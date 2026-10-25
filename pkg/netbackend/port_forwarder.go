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

package netbackend

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// guestDialWindow is the time that a forwarded TCP client waits for the
	// guest to start listening on the target port.
	guestDialWindow = 3 * time.Second

	// guestDialRetryInterval is the pause between guest dial attempts.
	guestDialRetryInterval = 15 * time.Millisecond

	// defaultMaxUDPForwardSessions is the number of concurrent client sessions
	// per UDP rule. The forwarder drops a new client while the rule is at the limit.
	defaultMaxUDPForwardSessions = 1024

	// acceptBackoffMin and acceptBackoffMax bound the pause after a failed Accept.
	acceptBackoffMin = 5 * time.Millisecond
	acceptBackoffMax = time.Second
)

// PortForwardRule defines a single host-to-guest port mapping (-p host:guest).
type PortForwardRule struct {
	Proto     string
	HostIP    string
	HostPort  uint16
	GuestIP   string
	GuestPort uint16
}

// ParsePortForwardRule parses a CLI port-forward specification such as
// "8080:80", "127.0.0.1:8080:80", "8080:80/tcp", or "5353:53/udp".
func ParsePortForwardRule(spec string) (PortForwardRule, error) {
	return ParsePortForwardSpec(spec, false, false)
}

// ParsePortForwardSpec parses a port-forward specification. When allowSinglePort
// is true, Docker forms such as "80", "ip::80", and "[ipv6]:8080:80" are
// accepted. When strictBindIP is true, an explicit bind address must parse as
// an IPv4 or bracketed IPv6 address.
func ParsePortForwardSpec(spec string, allowSinglePort, strictBindIP bool) (PortForwardRule, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return PortForwardRule{}, errors.New("netbackend: empty port forward specification")
	}

	proto := "tcp"
	if slashIdx := strings.LastIndexByte(spec, '/'); slashIdx != -1 {
		proto = strings.ToLower(strings.TrimSpace(spec[slashIdx+1:]))
		spec = spec[:slashIdx]
		if proto != "tcp" && proto != "udp" {
			return PortForwardRule{}, fmt.Errorf("netbackend: unsupported protocol %q in port forward spec", proto)
		}
	}

	hostIP := "127.0.0.1"
	rest := spec
	if strings.HasPrefix(rest, "[") {
		end := strings.IndexByte(rest, ']')
		if end < 0 || end+1 >= len(rest) || rest[end+1] != ':' {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward %q: an IPv6 address needs brackets and a port", spec)
		}
		hostIP, rest = rest[1:end], rest[end+2:]
		if ip, err := netip.ParseAddr(hostIP); err != nil || !ip.Is6() {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid IPv6 address %q in %q", hostIP, spec)
		}
	}

	parts := strings.Split(rest, ":")
	if hostIP == "127.0.0.1" && len(parts) == 3 {
		hostIP, parts = parts[0], parts[1:]
		if hostIP == "" && !strictBindIP {
			hostIP = "127.0.0.1"
		} else if strictBindIP {
			if ip, err := netip.ParseAddr(hostIP); err != nil || !ip.Is4() {
				return PortForwardRule{}, fmt.Errorf("netbackend: invalid bind address %q in %q (want an IPv4 address, or an IPv6 address in brackets)", hostIP, spec)
			}
		}
	}

	var hostPortStr, guestPortStr string
	switch {
	case len(parts) == 1 && allowSinglePort:
		guestPortStr = parts[0]
	case len(parts) == 2:
		hostPortStr, guestPortStr = parts[0], parts[1]
	default:
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid port forward format %q", spec)
	}

	var hostPort uint64
	hostPortStr = strings.TrimSpace(hostPortStr)
	if hostPortStr != "" || !allowSinglePort {
		var err error
		hostPort, err = strconv.ParseUint(hostPortStr, 10, 16)
		if err != nil {
			return PortForwardRule{}, fmt.Errorf("netbackend: invalid host port %q: %w", hostPortStr, err)
		}
	}
	guestPort, err := strconv.ParseUint(strings.TrimSpace(guestPortStr), 10, 16)
	if err != nil || guestPort == 0 {
		return PortForwardRule{}, fmt.Errorf("netbackend: invalid guest port %q", guestPortStr)
	}

	return PortForwardRule{
		Proto:     proto,
		HostIP:    hostIP,
		HostPort:  uint16(hostPort),
		GuestIP:   DefaultGuestIPv4,
		GuestPort: uint16(guestPort),
	}, nil
}

type boundTCPForward struct {
	rule     PortForwardRule
	listener net.Listener
}

type boundUDPForward struct {
	rule       PortForwardRule
	packetConn *net.UDPConn

	// sessions maps a client address to its session. PortForwarder.mu guards it.
	sessions map[netip.AddrPort]*udpForwardSession
}

// udpForwardSession carries the datagrams of one host client. It owns one
// guest UDP endpoint, so the guest sees one stable source port per client.
type udpForwardSession struct {
	client netip.AddrPort
	guest  *gonet.UDPConn
	clock  *activityClock
}

// PortForwarder binds host TCP listeners and UDP packet sockets prior to
// hostlockdown.Apply() and forwards inbound traffic into Netstack via gonet.
type PortForwarder struct {
	mu      sync.Mutex
	tcpList []*boundTCPForward
	udpList []*boundUDPForward
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// udpIdle is the time without a datagram after which a UDP session ends.
	udpIdle time.Duration
	// udpMaxSessions is the session limit of each UDP rule.
	udpMaxSessions int
	log            *slog.Logger
}

// NewPortForwarder constructs an empty PortForwarder ready for PreBind.
func NewPortForwarder() *PortForwarder {
	ctx, cancel := context.WithCancel(context.Background())
	return &PortForwarder{
		ctx:            ctx,
		cancel:         cancel,
		udpIdle:        defaultUDPIdleTimeout,
		udpMaxSessions: defaultMaxUDPForwardSessions,
		log:            discardLogger,
	}
}

// PreBind opens all host TCP listeners and UDP sockets for rules before
// hostlockdown.Apply() restricts new socket binds.
func (pf *PortForwarder) PreBind(rules []PortForwardRule) error {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.closed {
		return errors.New("netbackend: PortForwarder is closed")
	}

	for _, r := range rules {
		proto := strings.ToLower(r.Proto)
		if proto == "" {
			proto = "tcp"
		}
		hostIP := r.HostIP
		if hostIP == "" {
			hostIP = "127.0.0.1"
		}
		guestIP := r.GuestIP
		if guestIP == "" {
			guestIP = DefaultGuestIPv4
		}
		bindAddr := net.JoinHostPort(hostIP, strconv.Itoa(int(r.HostPort)))

		switch proto {
		case "tcp":
			ln, err := net.Listen("tcp", bindAddr)
			if err != nil {
				return fmt.Errorf("netbackend: bind tcp %s: %w", bindAddr, err)
			}
			actualPort := r.HostPort
			if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
				actualPort = uint16(tcpAddr.Port)
			}
			pf.tcpList = append(pf.tcpList, &boundTCPForward{
				rule: PortForwardRule{
					Proto:     "tcp",
					HostIP:    hostIP,
					HostPort:  actualPort,
					GuestIP:   guestIP,
					GuestPort: r.GuestPort,
				},
				listener: ln,
			})
		case "udp":
			pc, err := net.ListenPacket("udp", bindAddr)
			if err != nil {
				return fmt.Errorf("netbackend: bind udp %s: %w", bindAddr, err)
			}
			udpConn, ok := pc.(*net.UDPConn)
			if !ok {
				_ = pc.Close()
				return fmt.Errorf("netbackend: bind udp %s: socket is %T, want *net.UDPConn", bindAddr, pc)
			}
			actualPort := uint16(udpConn.LocalAddr().(*net.UDPAddr).Port)
			pf.udpList = append(pf.udpList, &boundUDPForward{
				rule: PortForwardRule{
					Proto:     "udp",
					HostIP:    hostIP,
					HostPort:  actualPort,
					GuestIP:   guestIP,
					GuestPort: r.GuestPort,
				},
				packetConn: udpConn,
				sessions:   make(map[netip.AddrPort]*udpForwardSession),
			})
		default:
			return fmt.Errorf("netbackend: unsupported protocol %q", proto)
		}
	}
	return nil
}

// BoundRules returns the active port forward rules with resolved host ports.
func (pf *PortForwarder) BoundRules() []PortForwardRule {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	out := make([]PortForwardRule, 0, len(pf.tcpList)+len(pf.udpList))
	for _, b := range pf.tcpList {
		out = append(out, b.rule)
	}
	for _, b := range pf.udpList {
		out = append(out, b.rule)
	}
	return out
}

// Start launches background relay workers for all pre-bound TCP and UDP ports
// targeting the given Netstack instance. It does nothing after Close and
// after the first call.
func (pf *PortForwarder) Start(s *stack.Stack) {
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if pf.closed || pf.started {
		return
	}
	pf.started = true
	for _, b := range pf.tcpList {
		pf.wg.Add(1)
		go pf.serveTCP(s, b)
	}
	for _, b := range pf.udpList {
		pf.wg.Add(1)
		go pf.serveUDP(s, b)
	}
}

// spawn runs fn on a tracked goroutine. It returns false after Close, so that
// no goroutine starts while Close waits.
func (pf *PortForwarder) spawn(fn func()) bool {
	return spawnTracked(&pf.mu, &pf.closed, &pf.wg, fn)
}

func (pf *PortForwarder) serveTCP(s *stack.Stack, b *boundTCPForward) {
	defer pf.wg.Done()
	guestAddr := parseGuestFullAddr(b.rule.GuestIP, b.rule.GuestPort)
	var backoff time.Duration
	for {
		hostConn, err := b.listener.Accept()
		if err != nil {
			if pf.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			// A transient error such as EMFILE must not end the listener.
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			pf.log.Warn("netbackend: accept on forwarded port failed", "port", b.rule.HostPort, "retry_in", backoff, "error", err)
			select {
			case <-pf.ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		if !pf.spawn(func() { pf.relayTCPClient(s, guestAddr, hostConn) }) {
			_ = hostConn.Close()
			return
		}
	}
}

// relayTCPClient connects hostConn to the guest endpoint and relays both
// streams. The guest may start listening after the host client connects, so
// the dial retries during guestDialWindow.
func (pf *PortForwarder) relayTCPClient(s *stack.Stack, guestAddr tcpip.FullAddress, hostConn net.Conn) {
	defer func() { _ = hostConn.Close() }()

	ctx, cancel := context.WithTimeout(pf.ctx, guestDialWindow)
	defer cancel()
	var guestConn *gonet.TCPConn
	for {
		var err error
		guestConn, err = gonet.DialContextTCP(ctx, s, guestAddr, ipv4.ProtocolNumber)
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			pf.log.Debug("netbackend: dial guest for forwarded connection", "guest", guestAddr.Addr, "port", guestAddr.Port, "error", err)
			return
		case <-time.After(guestDialRetryInterval):
		}
	}
	defer func() { _ = guestConn.Close() }()
	relayBidirectional(pf.ctx, hostConn, guestConn)
}

func (pf *PortForwarder) serveUDP(s *stack.Stack, b *boundUDPForward) {
	defer pf.wg.Done()
	guestAddr := parseGuestFullAddr(b.rule.GuestIP, b.rule.GuestPort)
	buf := make([]byte, maxUDPDatagram)
	var backoff time.Duration
	for {
		n, client, err := b.packetConn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if pf.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			backoff = min(max(2*backoff, acceptBackoffMin), acceptBackoffMax)
			pf.log.Warn("netbackend: read on forwarded UDP port failed", "port", b.rule.HostPort, "retry_in", backoff, "error", err)
			select {
			case <-pf.ctx.Done():
				return
			case <-time.After(backoff):
			}
			continue
		}
		backoff = 0
		sess := pf.udpSession(s, b, guestAddr, client)
		if sess == nil {
			continue
		}
		sess.clock.touch()
		if _, err := sess.guest.Write(buf[:n]); err != nil {
			pf.log.Debug("netbackend: write forwarded datagram to guest", "client", client, "error", err)
		}
	}
}

// udpSession returns the session of client. It creates the session and its
// reply goroutine on the first datagram. It returns nil when the forwarder is
// closed, the rule is at its session limit, or the guest endpoint fails.
func (pf *PortForwarder) udpSession(s *stack.Stack, b *boundUDPForward, guestAddr tcpip.FullAddress, client netip.AddrPort) *udpForwardSession {
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return nil
	}
	if sess, ok := b.sessions[client]; ok {
		pf.mu.Unlock()
		return sess
	}
	if len(b.sessions) >= pf.udpMaxSessions {
		pf.mu.Unlock()
		pf.log.Warn("netbackend: UDP forward session limit reached", "port", b.rule.HostPort, "client", client)
		return nil
	}
	pf.mu.Unlock()

	guest, err := gonet.DialUDP(s, nil, &guestAddr, ipv4.ProtocolNumber)
	if err != nil {
		pf.log.Debug("netbackend: open guest UDP endpoint", "client", client, "error", err)
		return nil
	}
	sess := &udpForwardSession{client: client, guest: guest, clock: newActivityClock()}

	// Only this rule's serveUDP goroutine inserts sessions, so the earlier
	// lookup cannot race with another insert for the same key.
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		_ = guest.Close()
		return nil
	}
	b.sessions[client] = sess
	pf.wg.Add(1)
	pf.mu.Unlock()
	go pf.runUDPSession(b, sess)
	return sess
}

// runUDPSession forwards every guest reply to the host client until the
// session is idle in both directions or its guest endpoint closes.
func (pf *PortForwarder) runUDPSession(b *boundUDPForward, sess *udpForwardSession) {
	defer pf.wg.Done()
	defer func() {
		pf.mu.Lock()
		if b.sessions[sess.client] == sess {
			delete(b.sessions, sess.client)
		}
		pf.mu.Unlock()
		_ = sess.guest.Close()
	}()
	pumpDatagrams(sess.guest, func(p []byte) error {
		_, err := b.packetConn.WriteToUDPAddrPort(p, sess.client)
		if err != nil && !errors.Is(err, net.ErrClosed) {
			pf.log.Debug("netbackend: write guest reply to host client", "client", sess.client, "error", err)
		}
		return err
	}, sess.clock, pf.udpIdle)
}

func parseGuestFullAddr(ipStr string, port uint16) tcpip.FullAddress {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil || !addr.Is4() {
		return tcpip.FullAddress{
			NIC:  Eth0NICID,
			Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}),
			Port: port,
		}
	}
	return tcpip.FullAddress{
		NIC:  Eth0NICID,
		Addr: tcpip.AddrFrom4(addr.As4()),
		Port: port,
	}
}

// Close stops all pre-bound host listeners, closes every UDP session, and
// waits for active relays. It closes the session endpoints before it waits,
// so a guest that never answers cannot block Close.
func (pf *PortForwarder) Close() error {
	pf.mu.Lock()
	if pf.closed {
		pf.mu.Unlock()
		return nil
	}
	pf.closed = true
	pf.cancel()
	var errs []error
	for _, b := range pf.tcpList {
		if err := b.listener.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	var guests []*gonet.UDPConn
	for _, b := range pf.udpList {
		if err := b.packetConn.Close(); err != nil {
			errs = append(errs, err)
		}
		for _, sess := range b.sessions {
			guests = append(guests, sess.guest)
		}
	}
	pf.mu.Unlock()
	for _, g := range guests {
		_ = g.Close()
	}
	pf.wg.Wait()
	return errors.Join(errs...)
}
