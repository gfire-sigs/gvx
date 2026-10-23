// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package netbackend connects gVisor's pure-Go Netstack (pkg/tcpip) to either
// an L4 Go net NAT and port forwarder (-net=nat) or an L3 in-memory WireGuard
// endpoint (-net=wg).
package netbackend

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/icmp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

const (
	// ModeNAT selects Track A: L4 Go net NAT and port forwarding.
	ModeNAT = "nat"
	// ModeWireGuard selects Track B: L3 in-memory WireGuard tunnel.
	ModeWireGuard = "wg"

	// LoopbackNICID is the Netstack NIC ID for lo (127.0.0.1/8).
	LoopbackNICID tcpip.NICID = 1
	// Eth0NICID is the Netstack NIC ID for eth0 (10.0.2.15/24).
	Eth0NICID tcpip.NICID = 2

	// DefaultGuestIPv4 is the default guest IPv4 address assigned to eth0.
	DefaultGuestIPv4 = "10.0.2.15"
	// HostGatewayIPv4 is the virtual gateway IPv4 address (host.docker.internal)
	// that maps to host 127.0.0.1 in NAT mode.
	HostGatewayIPv4 = "10.0.2.2"
	// HostDNSIPv4 is the virtual DNS resolver IPv4 address that relays guest
	// DNS queries (UDP/53 and TCP/53) through the host OS resolver.
	HostDNSIPv4 = "10.0.2.3"

	defaultTCPReceiveWindow = 0
	defaultMaxInFlightSYNs  = 1024
	defaultDialTimeout      = 10 * time.Second

	// defaultUDPIdleTimeout is the time without a datagram in either
	// direction after which a UDP session ends.
	defaultUDPIdleTimeout = 30 * time.Second

	// maxUDPDatagram is the largest UDP payload that a relay reads.
	maxUDPDatagram = 65535

	// maxTransientUDPErrors is the count of consecutive read errors that ends a
	// UDP session. A connected host socket reports an ICMP error once per
	// refused datagram, and that error does not end the session.
	maxTransientUDPErrors = 8
)

// StreamInterceptor inspects or transforms an outbound L4 stream between the
// guest endpoint and the host connection (for example, to inject host-held API
// credentials).
type StreamInterceptor func(ctx context.Context, dstAddr string, guestConn, hostConn net.Conn) error

// NATConfig configures the Track A L4 NAT forwarder.
type NATConfig struct {
	// IsolateLAN blocks outbound connections to RFC1918 private networks,
	// link-local ranges, and host loopback addresses (including 10.0.2.2).
	IsolateLAN bool

	// DialContext dials outbound host connections. When nil, a default
	// net.Dialer is used.
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// LookupHost resolves A and AAAA queries for the virtual DNS relay at
	// 10.0.2.3:53. When nil, the relay forwards the raw query to the host DNS
	// servers that were discovered before lockdown.
	LookupHost func(ctx context.Context, host string) ([]netip.Addr, error)

	// DNSServers specifies upstream host DNS servers ("ip:port") for the
	// virtual DNS relay. When empty, the host resolver configuration is
	// discovered: /etc/resolv.conf on macOS and the adapter DNS servers on
	// Windows. When the host has none, the relay answers SERVFAIL.
	DNSServers []string

	// UDPIdleTimeout is the time without a datagram in either direction after
	// which a UDP session ends. When zero, it is 30 seconds.
	UDPIdleTimeout time.Duration

	// Logger receives forwarder diagnostics. When nil, the forwarder discards them.
	Logger *slog.Logger

	// StreamInterceptor optionally relays traffic between guestConn and hostConn.
	StreamInterceptor StreamInterceptor
}

// NATForwarder implements Track A (-net=nat) L4 TCP, UDP, DNS, and ICMP egress
// forwarding for a pure-Go Netstack instance.
type NATForwarder struct {
	stack       *stack.Stack
	cfg         NATConfig
	log         *slog.Logger
	upstreamDNS []string
	udpIdle     time.Duration
	ctx         context.Context
	cancel      context.CancelFunc

	// mu guards closed, which stops spawn from calling wg.Add during wg.Wait.
	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup
}

// discardLogger drops every record. Forwarders use it when the caller sets no Logger.
var discardLogger = slog.New(slog.DiscardHandler)

type natLinkEndpoint struct {
	stack.LinkEndpoint
	nf *NATForwarder
}

func (e *natLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.nf == nil {
		return e.LinkEndpoint.WritePackets(pkts)
	}
	var filtered stack.PacketBufferList
	dropped := 0
	dnsIP := netip.MustParseAddr(HostDNSIPv4)
	for _, pkt := range pkts.AsSlice() {
		if pkt.NetworkProtocolNumber == ipv4.ProtocolNumber {
			netHdr := pkt.NetworkHeader().Slice()
			if len(netHdr) >= header.IPv4MinimumSize {
				ipHdr := header.IPv4(netHdr)
				if ipHdr.TransportProtocol() == header.ICMPv4ProtocolNumber {
					dstAddr := ipHdr.DestinationAddress()
					dstIP, ok := netip.AddrFromSlice(dstAddr.AsSlice())
					if ok && dstIP != dnsIP {
						if _, err := e.nf.ResolveOutboundTarget(dstIP, 0); err != nil {
							dropped++
							continue
						}
					}
				}
			}
		}
		filtered.PushBack(pkt)
	}
	if filtered.Len() == 0 {
		return dropped, nil
	}
	n, err := e.LinkEndpoint.WritePackets(filtered)
	return n + dropped, err
}

// NewNATStack creates a pure-Go Netstack configured with lo (127.0.0.1/8) and
// eth0 (10.0.2.15/24) and attaches a Track A L4 NATForwarder.
func NewNATStack(cfg NATConfig) (*stack.Stack, *NATForwarder, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{
			ipv4.NewProtocol,
			ipv6.NewProtocol,
		},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})

	if err := configureLoopbackNIC(s, LoopbackNICID); err != nil {
		s.Close()
		return nil, nil, err
	}

	fwd := newNATForwarder(s, cfg)
	if err := configureNATNIC(s, Eth0NICID, fwd); err != nil {
		_ = fwd.Close()
		s.Close()
		return nil, nil, err
	}
	registerNATTransportHandlers(s, fwd)
	return s, fwd, nil
}

func configureLoopbackNIC(s *stack.Stack, nicID tcpip.NICID) error {
	if err := s.CreateNIC(nicID, loopback.New()); err != nil {
		return fmt.Errorf("netbackend: create lo NIC: %s", err)
	}
	loAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{127, 0, 0, 1}),
			PrefixLen: 8,
		},
	}
	if err := s.AddProtocolAddress(nicID, loAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("netbackend: add 127.0.0.1/8 to lo: %s", err)
	}
	return nil
}

func configureNATNIC(s *stack.Stack, nicID tcpip.NICID, nf *NATForwarder) error {
	linkEP := &natLinkEndpoint{
		LinkEndpoint: loopback.New(),
		nf:           nf,
	}
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return fmt.Errorf("netbackend: create eth0 NIC: %s", err)
	}
	ethAddr := tcpip.ProtocolAddress{
		Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
			PrefixLen: 24,
		},
	}
	if err := s.AddProtocolAddress(nicID, ethAddr, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("netbackend: add 10.0.2.15/24 to eth0: %s", err)
	}
	// Enable promiscuous and spoofing modes on eth0 so outbound packets to
	// external IPv4/IPv6 addresses enter the transport demuxer and trigger
	// the L4 TCP/UDP forwarders when no local listener matches.
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return fmt.Errorf("netbackend: set promiscuous mode on eth0: %s", err)
	}
	if err := s.SetSpoofing(nicID, true); err != nil {
		return fmt.Errorf("netbackend: set spoofing on eth0: %s", err)
	}

	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         LoopbackNICID,
		},
		{
			Destination: header.IPv4EmptySubnet,
			Gateway:     tcpip.AddrFrom4([4]byte{10, 0, 2, 2}),
			NIC:         nicID,
		},
	})
	return nil
}

func newNATForwarder(s *stack.Stack, cfg NATConfig) *NATForwarder {
	if cfg.DialContext == nil {
		dialer := &net.Dialer{Timeout: defaultDialTimeout}
		cfg.DialContext = dialer.DialContext
	}
	upstream := cfg.DNSServers
	if len(upstream) == 0 {
		upstream = discoverHostDNSServers()
	}
	idle := cfg.UDPIdleTimeout
	if idle <= 0 {
		idle = defaultUDPIdleTimeout
	}
	log := cfg.Logger
	if log == nil {
		log = discardLogger
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &NATForwarder{
		stack:       s,
		cfg:         cfg,
		log:         log,
		upstreamDNS: upstream,
		udpIdle:     idle,
		ctx:         ctx,
		cancel:      cancel,
	}
}

func registerNATTransportHandlers(s *stack.Stack, nf *NATForwarder) {
	tcpFwd := tcp.NewForwarder(s, defaultTCPReceiveWindow, defaultMaxInFlightSYNs, nf.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, nf.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

// AttachNATForwarder registers L4 TCP and UDP forwarders on s.
func AttachNATForwarder(s *stack.Stack, cfg NATConfig) *NATForwarder {
	nf := newNATForwarder(s, cfg)
	registerNATTransportHandlers(s, nf)
	return nf
}

// Close cancels active NAT relays and waits for goroutines to finish.
func (nf *NATForwarder) Close() error {
	nf.mu.Lock()
	nf.closed = true
	nf.mu.Unlock()
	nf.cancel()
	nf.wg.Wait()
	return nil
}

// spawn runs fn on a tracked goroutine. It returns false after Close, so that
// no goroutine starts while Close waits.
func (nf *NATForwarder) spawn(fn func()) bool {
	nf.mu.Lock()
	if nf.closed {
		nf.mu.Unlock()
		return false
	}
	nf.wg.Add(1)
	nf.mu.Unlock()
	go func() {
		defer nf.wg.Done()
		fn()
	}()
	return true
}

// ResolveOutboundTarget maps a guest destination IP and port to a host network
// address. An address of the guest itself (loopback, the guest IP, or the
// unspecified address) never leaves the guest: Netstack hands such a SYN to
// the TCP forwarder when no guest socket listens, and a dial would reach a
// host service on the same port. The method rejects those addresses. It also
// enforces the IsolateLAN policy when enabled.
func (nf *NATForwarder) ResolveOutboundTarget(dstIP netip.Addr, dstPort uint16) (string, error) {
	gatewayIP := netip.MustParseAddr(HostGatewayIPv4)
	guestIP := netip.MustParseAddr(DefaultGuestIPv4)

	if dstIP == gatewayIP {
		if nf.cfg.IsolateLAN {
			return "", fmt.Errorf("netbackend: outbound access to host gateway %s blocked by -isolate-lan", dstIP)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(dstPort))), nil
	}

	if dstIP == guestIP || dstIP.IsLoopback() || dstIP.IsUnspecified() {
		return "", fmt.Errorf("netbackend: %s is an address of the guest itself, and no guest socket listens on it; use the host gateway %s to reach the host", dstIP, gatewayIP)
	}

	if nf.cfg.IsolateLAN {
		if dstIP.IsPrivate() || dstIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalMulticast() {
			return "", fmt.Errorf("netbackend: outbound access to private/local address %s blocked by -isolate-lan", dstIP)
		}
	}

	return net.JoinHostPort(dstIP.String(), strconv.Itoa(int(dstPort))), nil
}

func (nf *NATForwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		r.Complete(true)
		return
	}

	// Intercept TCP DNS queries to the virtual DNS relay (10.0.2.3:53).
	if dstIP == netip.MustParseAddr(HostDNSIPv4) && id.LocalPort == 53 {
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			r.Complete(true)
			return
		}
		guestConn := gonet.NewTCPConn(&wq, ep)
		if !nf.spawn(func() { nf.serveTCPDNS(nf.ctx, guestConn) }) {
			_ = guestConn.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		return
	}

	targetAddr, err := nf.ResolveOutboundTarget(dstIP, id.LocalPort)
	if err != nil {
		nf.log.Debug("netbackend: reject guest TCP connection", "error", err)
		r.Complete(true)
		return
	}

	// Dial the outbound host target on a dedicated goroutine so that slow or
	// unreachable remote hosts never block the Netstack packet demuxer.
	if !nf.spawn(func() { nf.relayTCP(r, targetAddr) }) {
		r.Complete(true)
	}
}

// relayTCP dials targetAddr on the host and relays it to the guest connection
// that r requests. It completes r in every case.
func (nf *NATForwarder) relayTCP(r *tcp.ForwarderRequest, targetAddr string) {
	hostConn, err := nf.cfg.DialContext(nf.ctx, "tcp", targetAddr)
	if err != nil {
		nf.log.Debug("netbackend: dial host TCP target", "target", targetAddr, "error", err)
		r.Complete(true)
		return
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		_ = hostConn.Close()
		r.Complete(true)
		return
	}
	r.Complete(false)

	guestConn := gonet.NewTCPConn(&wq, ep)
	defer func() {
		_ = guestConn.Close()
		_ = hostConn.Close()
	}()
	if nf.cfg.StreamInterceptor != nil {
		if err := nf.cfg.StreamInterceptor(nf.ctx, targetAddr, guestConn, hostConn); err != nil {
			nf.log.Warn("netbackend: stream interceptor failed", "target", targetAddr, "error", err)
		}
		return
	}
	relayBidirectional(nf.ctx, guestConn, hostConn)
}

func (nf *NATForwarder) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		return false
	}

	// Intercept UDP DNS queries to the virtual DNS relay (10.0.2.3:53).
	if dstIP == netip.MustParseAddr(HostDNSIPv4) && id.LocalPort == 53 {
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			return false
		}
		guestConn := gonet.NewUDPConn(&wq, ep)
		if !nf.spawn(func() {
			defer func() { _ = guestConn.Close() }()
			nf.serveUDPDNS(nf.ctx, guestConn)
		}) {
			_ = guestConn.Close()
			return false
		}
		return true
	}

	targetAddr, err := nf.ResolveOutboundTarget(dstIP, id.LocalPort)
	if err != nil {
		nf.log.Debug("netbackend: reject guest UDP flow", "error", err)
		return false
	}

	hostConn, err := nf.cfg.DialContext(nf.ctx, "udp", targetAddr)
	if err != nil {
		nf.log.Debug("netbackend: dial host UDP target", "target", targetAddr, "error", err)
		return false
	}

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		_ = hostConn.Close()
		return false
	}

	guestConn := gonet.NewUDPConn(&wq, ep)
	if !nf.spawn(func() {
		relayDatagrams(nf.ctx, guestConn, hostConn, nf.udpIdle)
	}) {
		_ = guestConn.Close()
		_ = hostConn.Close()
		return false
	}
	return true
}

// relayBidirectional copies a to b and b to a until both directions end or ctx
// ends. It returns after both copy goroutines return, so callers can track
// the relay with a WaitGroup. EOF in one direction half-closes the other
// connection. A copy error closes both connections.
func relayBidirectional(ctx context.Context, a, b net.Conn) {
	stop := context.AfterFunc(ctx, func() {
		_ = a.Close()
		_ = b.Close()
	})
	defer stop()

	var wg sync.WaitGroup
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		_, err := io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			if cw.CloseWrite() == nil {
				return
			}
		}
		// A copy error, or a connection without half-close, ends both directions.
		_ = a.Close()
		_ = b.Close()
	}
	wg.Add(2)
	go pump(a, b)
	go pump(b, a)
	wg.Wait()
}

// activityClock records the last datagram time of a UDP session. Both
// directions of the session share one clock, so one active direction keeps
// the session alive.
type activityClock struct {
	start time.Time
	// last is the offset from start in nanoseconds. The offset uses the
	// monotonic clock, so wall clock changes do not expire a session.
	last atomic.Int64
}

func newActivityClock() *activityClock {
	return &activityClock{start: time.Now()}
}

// touch records activity now. It never moves the last time backward.
func (c *activityClock) touch() {
	now := int64(time.Since(c.start))
	for {
		old := c.last.Load()
		if now <= old || c.last.CompareAndSwap(old, now) {
			return
		}
	}
}

// deadline returns the time at which the session expires without more activity.
func (c *activityClock) deadline(idle time.Duration) time.Time {
	return c.start.Add(time.Duration(c.last.Load()) + idle)
}

func (c *activityClock) expired(idle time.Duration) bool {
	return time.Since(c.start)-time.Duration(c.last.Load()) >= idle
}

// isTimeout reports whether err is a deadline error. The gonet adapter returns
// its own timeout type, so the check uses net.Error instead of os.ErrDeadlineExceeded.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// pumpDatagrams reads datagrams from src and passes each one to send until the
// session expires or src closes. A timeout ends the loop only when the shared
// clock shows no activity in the other direction either. A read error from a
// connected UDP socket, such as ECONNREFUSED after an ICMP port unreachable
// message, does not end the loop. A send error drops one datagram, except that
// net.ErrClosed ends the loop.
func pumpDatagrams(src net.Conn, send func([]byte) error, clock *activityClock, idle time.Duration) {
	buf := make([]byte, maxUDPDatagram)
	transient := 0
	for {
		if err := src.SetReadDeadline(clock.deadline(idle)); err != nil {
			return
		}
		n, err := src.Read(buf)
		if err != nil {
			switch {
			case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF):
				return
			case isTimeout(err):
				if clock.expired(idle) {
					return
				}
			default:
				transient++
				if transient >= maxTransientUDPErrors {
					return
				}
			}
			continue
		}
		transient = 0
		clock.touch()
		if err := send(buf[:n]); errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// relayDatagrams relays datagrams between guestConn and hostConn until both
// directions stay idle for idle, either connection closes, or ctx ends. It
// closes both connections and returns after both pump goroutines return.
func relayDatagrams(ctx context.Context, guestConn, hostConn net.Conn, idle time.Duration) {
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			_ = guestConn.Close()
			_ = hostConn.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	clock := newActivityClock()
	var wg sync.WaitGroup
	pump := func(dst, src net.Conn) {
		defer wg.Done()
		defer closeBoth()
		pumpDatagrams(src, func(p []byte) error {
			_, err := dst.Write(p)
			return err
		}, clock, idle)
	}
	wg.Add(2)
	go pump(hostConn, guestConn)
	go pump(guestConn, hostConn)
	wg.Wait()
}
