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
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
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

	// maxUDPDatagram is the largest UDP payload that a relay reads.
	maxUDPDatagram = 65535

	// maxTransientUDPErrors is the count of consecutive read errors that ends a
	// UDP session. A connected host socket reports an ICMP error once per
	// refused datagram, and that error does not end the session.
	maxTransientUDPErrors = 8

	// maxNATTCPRelays bounds the guest TCP connections that the NAT relays at
	// once, including the ones that still dial. Each relay holds one host
	// socket and two goroutines. The forwarder resets a connection beyond the
	// limit.
	maxNATTCPRelays = 4096

	// maxNATDNSFlows bounds the guest flows that the virtual resolver serves at
	// once: one for each UDP source port and one for each TCP connection. Each
	// flow holds a guest endpoint, a goroutine, and a read buffer until it
	// idles out. The forwarder drops a flow beyond the limit.
	maxNATDNSFlows = 256
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

	// DialContext supplies the trusted host socket provider. Protected NAT
	// only passes an authorized numeric peer and rechecks the returned peer.
	// The provider must dial only that peer and honor context cancellation.
	// When nil, a default net.Dialer is used.
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

	// Tuning sets the MTU of eth0, the UDP session limit and idle time, the
	// dial time, the SYN backlog, and the DNS time limits. The zero value
	// selects the defaults of the registry.
	Tuning tuning.Values

	// Logger receives forwarder diagnostics. When nil, the forwarder discards them.
	Logger *slog.Logger

	// StreamInterceptor optionally relays traffic between guestConn and hostConn.
	StreamInterceptor StreamInterceptor

	// Stack selects the optional features of the guest network stack.
	Stack StackOptions

	// Policy enables the sandbox's shared NAT firewall and bandwidth limits.
	// The caller owns the policy. Protected NAT does not accept DNS lookup
	// or stream callbacks.
	Policy *NATPolicy
}

// NATForwarder implements Track A (-net=nat) L4 TCP, UDP, DNS, and ICMP egress
// forwarding for a pure-Go Netstack instance.
type NATForwarder struct {
	// stack stands for the host network. Its forwarders relay the guest
	// connections. Close closes it.
	stack       *stack.Stack
	cfg         NATConfig
	log         *slog.Logger
	upstreamDNS []string
	dnsSearch   []string
	dnsOptions  []string
	dnsSem      chan struct{}
	// paused is true between QuiesceForSave and ResumeAfterSave. While it is
	// true, both ends of the eth0 link drop every packet.
	paused *atomic.Bool
	// tcpRelaySem and dnsFlowSem count the running TCP relays and DNS flows.
	// A nil channel means no limit.
	tcpRelaySem chan struct{}
	dnsFlowSem  chan struct{}
	udpIdle     time.Duration
	udpDialSem  chan struct{}
	udpSessions *udpSessionTable
	ctx         context.Context
	cancel      context.CancelFunc

	// mu guards closed, guestStack and packetLink. It also stops spawn from
	// calling wg.Add during wg.Wait.
	mu         sync.Mutex
	guestStack *stack.Stack
	packetLink *natPacketLinkState
	closed     bool
	wg         sync.WaitGroup
}

// discardLogger drops every record. Forwarders use it when the caller sets no Logger.
var discardLogger = slog.New(slog.DiscardHandler)

// hostGatewayAddr is the IPv4 address of the virtual NAT gateway (10.0.2.2).
var hostGatewayAddr = tcpip.AddrFrom4([4]byte{10, 0, 2, 2})

type natLinkEndpoint struct {
	stack.LinkEndpoint
	nf *NATForwarder

	// peer is the host end of the link. SetMTU gives it the MTU of eth0, as
	// the two ends of one cable share one MTU. Without that, the host stack
	// would announce the MSS of its own MTU, and every TCP stream would keep
	// to it.
	peer stack.LinkEndpoint
}

// SetMTU implements stack.LinkEndpoint.SetMTU. It sets the MTU of both ends of
// the link.
func (e *natLinkEndpoint) SetMTU(mtu uint32) {
	e.LinkEndpoint.SetMTU(mtu)
	if e.peer != nil {
		e.peer.SetMTU(mtu)
	}
}

func (e *natLinkEndpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.nf == nil {
		return e.LinkEndpoint.WritePackets(pkts)
	}
	if e.nf.paused != nil && e.nf.paused.Load() {
		return pkts.Len(), nil
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

// pausableLink drops every packet that the stack writes to it while paused is
// true, as if an unplugged cable carried them. TCP retransmits after the
// link comes back, so a pause shows to the guest as packet loss only.
type pausableLink struct {
	stack.LinkEndpoint
	paused *atomic.Bool
}

// WritePackets implements stack.LinkEndpoint.WritePackets.
func (e pausableLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if e.paused.Load() {
		return pkts.Len(), nil
	}
	return e.LinkEndpoint.WritePackets(pkts)
}

// QuiesceForSave stops the packet flow between the guest and the host relays.
// The guest Netstack then holds no new packet from a relay while the kernel
// saves its state. ResumeAfterSave restores the flow.
func (nf *NATForwarder) QuiesceForSave() {
	if nf.paused != nil {
		nf.paused.Store(true)
	}
	if nf.cfg.Policy != nil {
		nf.mu.Lock()
		link := nf.packetLink
		nf.mu.Unlock()
		link.invalidate(false)
	}
}

// ResumeAfterSave restores the packet flow that QuiesceForSave stopped.
func (nf *NATForwarder) ResumeAfterSave() error {
	if nf.paused != nil {
		nf.paused.Store(false)
	}
	return nil
}

// NewLoopbackStack creates a pure-Go Netstack configured with lo (127.0.0.1/8)
// and a loopback route table. A new network namespace of the guest also gets
// this stack, as a new namespace on Linux has only lo.
func NewLoopbackStack(opts StackOptions) (*stack.Stack, error) {
	s, err := newStack(opts)
	if err != nil {
		return nil, err
	}
	if err := configureLoopbackNIC(s, LoopbackNICID); err != nil {
		s.Close()
		return nil, err
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         LoopbackNICID,
		},
	})
	return s, nil
}

// AttachRestoredLoopbackStack reconfigures lo (127.0.0.1/8) and the loopback
// route table on a restored guest Netstack and restores saved guest transport
// endpoints.
func AttachRestoredLoopbackStack(restored *stack.Stack) error {
	if restored == nil {
		return errors.New("netbackend: restored stack is nil")
	}
	restored.ResetConfig()
	if err := configureLoopbackNIC(restored, LoopbackNICID); err != nil {
		return err
	}
	restored.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         LoopbackNICID,
		},
	})
	restored.Restore()
	return nil
}

// NewNATStack creates a pure-Go Netstack configured with lo (127.0.0.1/8) and
// eth0 (10.0.2.15/24) and attaches a Track A L4 NATForwarder.
//
// eth0 is one end of an in-memory link. The other end belongs to a second
// stack that stands for the host network. Its L4 forwarders relay connections
// to the host, subject to the optional host policy. The guest stack
// therefore routes as a Linux host does: it can forward the packets of a
// bridge or a network namespace to eth0 and translate them with iptables.
func NewNATStack(cfg NATConfig) (*stack.Stack, *NATForwarder, error) {
	if cfg.Policy != nil && (cfg.LookupHost != nil || cfg.StreamInterceptor != nil) {
		return nil, nil, errors.New("netbackend: protected NAT does not support custom DNS lookup or stream callbacks")
	}
	s, err := NewLoopbackStack(cfg.Stack)
	if err != nil {
		return nil, nil, err
	}
	// eth0 has the MTU of an Ethernet link by default, as on a Linux node and
	// in a Docker container. Software in the guest derives the MTU of its
	// tunnels from it: flannel uses the MTU of eth0 minus 50 for vxlan and
	// minus 80 for WireGuard. The loopback device keeps the MTU of 65536.
	guestEP, hostEP := pipe.New("", "", uint32(cfg.Tuning.Int(tuning.NATMTU)))
	paused := new(atomic.Bool)
	var packetLink *natPacketLinkState
	if cfg.Policy != nil {
		packetLink = &natPacketLinkState{paused: paused}
	}
	hostLink := wrapNATPolicyLink(pausableLink{checksumOffloadEndpoint{hostEP}, paused}, cfg.Policy, packetLink)
	hostStack, err := newNATHostStack(hostLink, cfg.Policy)
	if err != nil {
		s.Close()
		return nil, nil, err
	}
	fwd := newNATForwarder(hostStack, cfg)
	fwd.paused = paused
	fwd.guestStack = s
	fwd.packetLink = packetLink
	registerNATTransportHandlers(hostStack, fwd)
	if err := configureNATNIC(s, Eth0NICID, checksumOffloadEndpoint{guestEP}, checksumOffloadEndpoint{hostEP}, fwd); err != nil {
		_ = fwd.Close()
		s.Close()
		return nil, nil, err
	}
	return s, fwd, nil
}

// hostNICID is the NIC of the host stack that connects to the guest eth0.
const hostNICID tcpip.NICID = 1

// checksumOffloadEndpoint reports checksum offload for an in-memory link. A
// packet on that link cannot be corrupted, so neither stack computes or
// checks transport checksums for it, as on the loopback device.
type checksumOffloadEndpoint struct {
	stack.LinkEndpoint
}

// Capabilities implements stack.LinkEndpoint.Capabilities.
func (e checksumOffloadEndpoint) Capabilities() stack.LinkEndpointCapabilities {
	return e.LinkEndpoint.Capabilities() | stack.CapabilityRXChecksumOffload | stack.CapabilityTXChecksumOffload
}

// newNATHostStack creates the stack that stands for the host network. Its only
// NIC accepts packets to every address and sends packets from every address,
// so its forwarders can answer for any destination of the guest.
func newNATHostStack(ep stack.LinkEndpoint, policy *NATPolicy) (*stack.Stack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{
			tcp.NewProtocol,
			udp.NewProtocol,
			icmp.NewProtocol4,
			icmp.NewProtocol6,
		},
	})
	if policy != nil {
		s.SetNFTables(natPolicyHooks{policy: policy})
		s.SetNFTablesConfigured(true)
	}
	fail := func(what string, err tcpip.Error) (*stack.Stack, error) {
		s.Close()
		return nil, fmt.Errorf("netbackend: %s on the host stack: %s", what, err)
	}
	if err := s.CreateNIC(hostNICID, ep); err != nil {
		return fail("create the NIC", err)
	}
	if err := s.SetPromiscuousMode(hostNICID, true); err != nil {
		return fail("set promiscuous mode", err)
	}
	if err := s.SetSpoofing(hostNICID, true); err != nil {
		return fail("set spoofing", err)
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return fail("enable TCP SACK", err)
	}
	moderate := tcpip.TCPModerateReceiveBufferOption(true)
	if err := s.SetTransportProtocolOption(tcp.ProtocolNumber, &moderate); err != nil {
		return fail("enable TCP receive buffer tuning", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: hostNICID},
		{Destination: header.IPv6EmptySubnet, NIC: hostNICID},
	})
	return s, nil
}

func configureLoopbackNIC(s *stack.Stack, nicID tcpip.NICID) error {
	if err := createNamedNIC(s, nicID, LoopbackNICName, loopback.New()); err != nil {
		return err
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

func configureNATNIC(s *stack.Stack, nicID tcpip.NICID, ep, peer stack.LinkEndpoint, nf *NATForwarder) error {
	linkEP := &natLinkEndpoint{
		LinkEndpoint: ep,
		nf:           nf,
		peer:         peer,
	}
	if err := createNamedNICWithMTURange(s, nicID, Eth0NICName, linkEP, header.IPv4MinimumMTU, MaxLinkMTU); err != nil {
		return err
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
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4LoopbackSubnet,
			NIC:         LoopbackNICID,
		},
		{
			Destination: header.IPv4EmptySubnet,
			Gateway:     hostGatewayAddr,
			NIC:         nicID,
		},
	})
	return nil
}

func newNATForwarder(s *stack.Stack, cfg NATConfig) *NATForwarder {
	if cfg.DialContext == nil {
		dialer := &net.Dialer{Timeout: cfg.Tuning.Duration(tuning.NATDialTimeout)}
		cfg.DialContext = dialer.DialContext
	}
	upstream := dedupeStrings(cfg.DNSServers)
	var dnsSearch, dnsOptions []string
	if len(upstream) == 0 {
		hostCfg := discoverHostDNSConfig()
		upstream = hostCfg.servers
		dnsSearch = hostCfg.search
		dnsOptions = hostCfg.options
	}
	log := cfg.Logger
	if log == nil {
		log = discardLogger
	}
	var udpDialSem chan struct{}
	udpLimit := cfg.Tuning.Int(tuning.NATUDPSessions)
	if cfg.Policy != nil {
		udpDialSem = make(chan struct{}, udpLimit)
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &NATForwarder{
		stack:       s,
		cfg:         cfg,
		log:         log,
		upstreamDNS: upstream,
		dnsSearch:   dnsSearch,
		dnsOptions:  dnsOptions,
		dnsSem:      make(chan struct{}, maxConcurrentDNS),
		paused:      new(atomic.Bool),
		tcpRelaySem: make(chan struct{}, maxNATTCPRelays),
		dnsFlowSem:  make(chan struct{}, maxNATDNSFlows),
		udpIdle:     cfg.Tuning.Duration(tuning.UDPIdleTimeout),
		udpDialSem:  udpDialSem,
		udpSessions: newUDPSessionTable(udpLimit),
		ctx:         ctx,
		cancel:      cancel,
	}
}

func registerNATTransportHandlers(s *stack.Stack, nf *NATForwarder) {
	tcpFwd := tcp.NewForwarder(s, defaultTCPReceiveWindow, nf.cfg.Tuning.Int(tuning.NATSynBacklog), nf.handleTCP)
	udpFwd := udp.NewForwarder(s, nf.handleUDP)
	if nf.cfg.Policy != nil {
		s.SetTransportProtocolRelayHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
		s.SetTransportProtocolRelayHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
		return
	}
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
}

func (nf *NATForwarder) rebindHostNIC(ep stack.LinkEndpoint) error {
	_ = nf.stack.RemoveNIC(hostNICID)
	if err := nf.stack.CreateNIC(hostNICID, ep); err != nil {
		return fmt.Errorf("netbackend: create the NIC on the host stack: %s", err)
	}
	if err := nf.stack.SetPromiscuousMode(hostNICID, true); err != nil {
		return fmt.Errorf("netbackend: set promiscuous mode on the host stack: %s", err)
	}
	if err := nf.stack.SetSpoofing(hostNICID, true); err != nil {
		return fmt.Errorf("netbackend: set spoofing on the host stack: %s", err)
	}
	nf.stack.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: hostNICID},
		{Destination: header.IPv6EmptySubnet, NIC: hostNICID},
	})
	return nil
}

// Limits for Eth0Config. A checkpoint of a normal guest holds a few entries.
// The limits stop a corrupt manifest from forcing thousands of Netstack calls.
const (
	maxEth0Addresses = 64
	maxEth0Routes    = 1024
)

// Eth0Config holds the settings of eth0 that a guest changes at run time:
// its addresses, its MTU, and its routes. NewNATStack gives eth0 fixed
// values, and the state of a saved guest Netstack does not hold NIC settings,
// so a checkpoint records them with SnapshotEth0Config and a restore applies
// them again with AttachRestoredStackWithConfig.
type Eth0Config struct {
	// Addresses lists the addresses of eth0 in CIDR form.
	Addresses []string `json:"addresses,omitempty"`
	// MTU is the MTU of eth0 in bytes.
	MTU uint32 `json:"mtu,omitempty"`
	// Routes lists the main-table unicast routes that leave through eth0.
	Routes []Eth0Route `json:"routes,omitempty"`
}

// Eth0Route is one route of eth0.
type Eth0Route struct {
	// Destination is the prefix of the route in CIDR form.
	Destination string `json:"destination"`
	// Gateway is the next hop, or empty for an on-link route.
	Gateway string `json:"gateway,omitempty"`
	// MTU is the MTU of the route, or zero for the MTU of eth0.
	MTU uint32 `json:"mtu,omitempty"`
}

// SnapshotEth0Config reads the settings of eth0 from the guest stack s. It
// returns false when s has no eth0 with an IPv4 address.
func SnapshotEth0Config(s *stack.Stack) (Eth0Config, bool) {
	if s == nil {
		return Eth0Config{}, false
	}
	info, ok := s.NICInfo()[Eth0NICID]
	if !ok {
		return Eth0Config{}, false
	}
	var cfg Eth0Config
	hasIPv4 := false
	for _, pa := range info.ProtocolAddresses {
		addr := pa.AddressWithPrefix.Address
		if pa.Protocol == ipv4.ProtocolNumber {
			hasIPv4 = true
		} else if header.IsV6LinkLocalUnicastAddress(addr) {
			// Netstack derives the link-local address of eth0 itself.
			continue
		}
		ip, ok := netip.AddrFromSlice(addr.AsSlice())
		if !ok || len(cfg.Addresses) >= maxEth0Addresses {
			continue
		}
		cfg.Addresses = append(cfg.Addresses, netip.PrefixFrom(ip, pa.AddressWithPrefix.PrefixLen).String())
	}
	if !hasIPv4 {
		return Eth0Config{}, false
	}
	cfg.MTU = info.MTU
	for _, r := range s.GetRouteTable() {
		if r.NIC != Eth0NICID || r.TableID() != tcpip.RouteTableMain || r.RouteType() != tcpip.RouteTypeUnicast || len(cfg.Routes) >= maxEth0Routes {
			continue
		}
		er := Eth0Route{Destination: r.Destination.String(), MTU: r.MTU}
		if gw, ok := netip.AddrFromSlice(r.Gateway.AsSlice()); ok {
			er.Gateway = gw.String()
		}
		if _, err := netip.ParsePrefix(er.Destination); err != nil {
			continue
		}
		cfg.Routes = append(cfg.Routes, er)
	}
	return cfg, true
}

// apply sets cfg on s after configureNATNIC gave eth0 its defaults. Its error
// joins each setting that is invalid or that Netstack rejected. A setting
// that fails does not stop the others.
func (cfg Eth0Config) apply(s *stack.Stack) error {
	if len(cfg.Addresses) > maxEth0Addresses || len(cfg.Routes) > maxEth0Routes {
		return fmt.Errorf("netbackend: eth0 config has %d addresses and %d routes, above the limits %d and %d", len(cfg.Addresses), len(cfg.Routes), maxEth0Addresses, maxEth0Routes)
	}
	var errs []error
	defaultAddr := tcpip.AddrFrom4([4]byte{10, 0, 2, 15})
	haveDefault := false
	for _, text := range cfg.Addresses {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			errs = append(errs, fmt.Errorf("eth0 address %q: %w", text, err))
			continue
		}
		pa := tcpip.ProtocolAddress{
			Protocol:          ipv4.ProtocolNumber,
			AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(prefix.Addr().AsSlice()), PrefixLen: prefix.Bits()},
		}
		if prefix.Addr().Is6() {
			pa.Protocol = ipv6.ProtocolNumber
		}
		if pa.AddressWithPrefix.Address == defaultAddr {
			haveDefault = true
			continue
		}
		if err := s.AddProtocolAddress(Eth0NICID, pa, stack.AddressProperties{}); err != nil {
			errs = append(errs, fmt.Errorf("add %s to eth0: %s", prefix, err))
		}
	}
	if len(cfg.Addresses) > 0 && !haveDefault {
		if err := s.RemoveAddress(Eth0NICID, defaultAddr); err != nil {
			errs = append(errs, fmt.Errorf("remove %s from eth0: %s", defaultAddr, err))
		}
	}
	if cfg.MTU != 0 {
		if err := s.SetNICMTU(Eth0NICID, cfg.MTU); err != nil {
			errs = append(errs, fmt.Errorf("set the MTU of eth0 to %d: %s", cfg.MTU, err))
		}
	}
	if len(cfg.Routes) > 0 {
		table := slices.DeleteFunc(s.GetRouteTable(), func(r tcpip.Route) bool { return r.NIC == Eth0NICID })
		for _, er := range cfg.Routes {
			prefix, err := netip.ParsePrefix(er.Destination)
			if err != nil {
				errs = append(errs, fmt.Errorf("eth0 route %q: %w", er.Destination, err))
				continue
			}
			route := tcpip.Route{
				Destination: tcpip.AddressWithPrefix{Address: tcpip.AddrFromSlice(prefix.Masked().Addr().AsSlice()), PrefixLen: prefix.Bits()}.Subnet(),
				NIC:         Eth0NICID,
				MTU:         er.MTU,
			}
			if er.Gateway != "" {
				gw, err := netip.ParseAddr(er.Gateway)
				if err != nil {
					errs = append(errs, fmt.Errorf("eth0 route gateway %q: %w", er.Gateway, err))
					continue
				}
				route.Gateway = tcpip.AddrFromSlice(gw.AsSlice())
			}
			table = append(table, route)
		}
		s.SetRouteTable(table)
	}
	return errors.Join(errs...)
}

// AttachRestoredStack rebinds a restored guest Netstack to nf without opening
// new host sockets. It resets and reconfigures lo and eth0 on restored, wires
// a fresh in-memory pipe to the host forwarder stack, and restores saved guest
// transport endpoints.
func (nf *NATForwarder) AttachRestoredStack(restored *stack.Stack) error {
	return nf.AttachRestoredStackWithConfig(restored, nil)
}

// AttachRestoredStackWithConfig is AttachRestoredStack followed by the
// settings of eth0 in eth0 that the guest had set before the checkpoint. A nil
// eth0 keeps the defaults of NewNATStack. A setting that Netstack rejects is
// logged and skipped, so one bad entry never fails the restore.
func (nf *NATForwarder) AttachRestoredStackWithConfig(restored *stack.Stack, eth0 *Eth0Config) error {
	if restored == nil {
		return errors.New("netbackend: restored stack is nil")
	}
	nf.mu.Lock()
	if nf.closed {
		nf.mu.Unlock()
		return errors.New("netbackend: NATForwarder is closed")
	}
	oldPacketLink := nf.packetLink
	var packetLink *natPacketLinkState
	if nf.cfg.Policy != nil {
		packetLink = &natPacketLinkState{paused: nf.paused}
		nf.packetLink = packetLink
	}
	nf.mu.Unlock()
	oldPacketLink.invalidate(true)

	guestEP, hostEP := pipe.New("", "", uint32(nf.cfg.Tuning.Int(tuning.NATMTU)))
	hostLink := stack.LinkEndpoint(checksumOffloadEndpoint{hostEP})
	if nf.paused != nil {
		hostLink = pausableLink{hostLink, nf.paused}
	}
	hostLink = wrapNATPolicyLink(hostLink, nf.cfg.Policy, packetLink)
	if err := nf.rebindHostNIC(hostLink); err != nil {
		guestEP.Close()
		hostEP.Close()
		return err
	}
	restored.ResetConfig()
	if err := configureLoopbackNIC(restored, LoopbackNICID); err != nil {
		guestEP.Close()
		hostEP.Close()
		return err
	}
	if err := configureNATNIC(restored, Eth0NICID, checksumOffloadEndpoint{guestEP}, checksumOffloadEndpoint{hostEP}, nf); err != nil {
		guestEP.Close()
		hostEP.Close()
		return err
	}
	if eth0 != nil {
		if err := eth0.apply(restored); err != nil {
			nf.log.Warn("netbackend: reapply the saved eth0 settings", "error", err)
		}
	}
	nf.mu.Lock()
	if nf.closed {
		nf.mu.Unlock()
		guestEP.Close()
		hostEP.Close()
		return errors.New("netbackend: NATForwarder is closed")
	}
	nf.guestStack = restored
	nf.mu.Unlock()
	restored.Restore()
	return nil
}

// RebindRestore rebinds a restored guest Netstack to nf.
func (nf *NATForwarder) RebindRestore(restored *stack.Stack) error {
	return nf.AttachRestoredStack(restored)
}

// Close cancels active NAT relays and waits for goroutines to finish.
func (nf *NATForwarder) Close() error {
	nf.mu.Lock()
	wasClosed := nf.closed
	nf.closed = true
	link := nf.packetLink
	nf.mu.Unlock()
	nf.cancel()
	link.invalidate(true)
	nf.wg.Wait()
	if !wasClosed {
		nf.stack.Close()
	}
	return nil
}

// tryAcquire takes one slot of sem without waiting. It reports false when sem
// is full. A nil sem has no limit.
func tryAcquire(sem chan struct{}) bool {
	if sem == nil {
		return true
	}
	select {
	case sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseSlot returns the slot that tryAcquire took from sem.
func releaseSlot(sem chan struct{}) {
	if sem != nil {
		<-sem
	}
}

// spawnTracked runs fn on a tracked goroutine unless *closed is true.
func spawnTracked(mu *sync.Mutex, closed *bool, wg *sync.WaitGroup, fn func()) bool {
	mu.Lock()
	if *closed {
		mu.Unlock()
		return false
	}
	wg.Add(1)
	mu.Unlock()
	go func() {
		defer wg.Done()
		fn()
	}()
	return true
}

// spawn runs fn on a tracked goroutine. It returns false after Close, so that
// no goroutine starts while Close waits.
func (nf *NATForwarder) spawn(fn func()) bool {
	return spawnTracked(&nf.mu, &nf.closed, &nf.wg, fn)
}

// ResolveOutboundTarget maps a guest destination IP and port to a host network
// address. An address of the guest itself (loopback, the guest IP, or the
// unspecified address) never leaves the guest: Netstack hands such a SYN to
// the TCP forwarder when no guest socket listens, and a dial would reach a
// host service on the same port. The method rejects those addresses. It also
// enforces the IsolateLAN policy when enabled.
func (nf *NATForwarder) ResolveOutboundTarget(dstIP netip.Addr, dstPort uint16) (string, error) {
	target, err := nf.resolveOutboundTarget(dstIP, dstPort)
	if err != nil {
		return "", err
	}
	return target.String(), nil
}

func (nf *NATForwarder) resolveOutboundTarget(dstIP netip.Addr, dstPort uint16) (netip.AddrPort, error) {
	if nf.cfg.Policy != nil {
		dstIP = dstIP.Unmap()
	}
	gatewayIP := netip.MustParseAddr(HostGatewayIPv4)
	guestIP := netip.MustParseAddr(DefaultGuestIPv4)

	if dstIP == gatewayIP {
		if nf.cfg.IsolateLAN {
			return netip.AddrPort{}, fmt.Errorf("netbackend: outbound access to host gateway %s blocked by -isolate-lan", dstIP)
		}
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dstPort), nil
	}

	if dstIP == guestIP || dstIP.IsLoopback() || dstIP.IsUnspecified() {
		return netip.AddrPort{}, fmt.Errorf("netbackend: %s is an address of the guest itself, and no guest socket listens on it; use the host gateway %s to reach the host", dstIP, gatewayIP)
	}

	if nf.cfg.IsolateLAN {
		if dstIP.IsPrivate() || dstIP.IsLinkLocalUnicast() || dstIP.IsLinkLocalMulticast() {
			return netip.AddrPort{}, fmt.Errorf("netbackend: outbound access to private/local address %s blocked by -isolate-lan", dstIP)
		}
	}

	return netip.AddrPortFrom(dstIP, dstPort), nil
}

func (nf *NATForwarder) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dstIP, ok := netip.AddrFromSlice(id.LocalAddress.AsSlice())
	if !ok {
		r.Complete(true)
		return
	}

	// Intercept TCP DNS queries to the virtual DNS relay (10.0.2.3:53).
	const proto = uint8(header.TCPProtocolNumber)
	if dstIP == netip.MustParseAddr(HostDNSIPv4) && id.LocalPort == 53 {
		requestPolicy, allowed := nf.authorizeDNSFlow(proto, id, dstIP)
		if !allowed {
			r.Complete(true)
			return
		}
		if !tryAcquire(nf.dnsFlowSem) {
			nf.log.Debug("netbackend: reject guest DNS connection: too many DNS flows")
			r.Complete(true)
			return
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			releaseSlot(nf.dnsFlowSem)
			r.Complete(true)
			return
		}
		guestConn := gonet.NewTCPConn(&wq, ep)
		if !nf.spawn(func() {
			defer releaseSlot(nf.dnsFlowSem)
			nf.serveTCPDNS(nf.ctx, guestConn, requestPolicy)
		}) {
			releaseSlot(nf.dnsFlowSem)
			_ = guestConn.Close()
			r.Complete(true)
			return
		}
		r.Complete(false)
		return
	}

	targetAddr, err := nf.resolveOutboundTarget(dstIP, id.LocalPort)
	if err != nil {
		nf.log.Debug("netbackend: reject guest TCP connection", "error", err)
		r.Complete(true)
		return
	}

	if !tryAcquire(nf.tcpRelaySem) {
		nf.log.Debug("netbackend: reject guest TCP connection: too many relays", "target", targetAddr)
		r.Complete(true)
		return
	}
	// Dial the outbound host target on a dedicated goroutine so that slow or
	// unreachable remote hosts never block the Netstack packet demuxer.
	if !nf.spawn(func() {
		defer releaseSlot(nf.tcpRelaySem)
		nf.relayTCP(r, targetAddr, dstIP)
	}) {
		releaseSlot(nf.tcpRelaySem)
		r.Complete(true)
	}
}

// relayTCP dials targetAddr on the host and relays it to the guest connection
// that r requests. It completes r in every case.
func (nf *NATForwarder) relayTCP(r *tcp.ForwarderRequest, targetAddr netip.AddrPort, dstIP netip.Addr) {
	var guestTuple PolicyTuple
	if nf.cfg.Policy != nil {
		guestTuple = natGuestTuple(uint8(header.TCPProtocolNumber), r.ID(), dstIP)
	}
	hostConn, hostTuple, err := nf.dialNATTarget("tcp", targetAddr, guestTuple)
	if err != nil {
		nf.answerFailedDial(r, targetAddr.String(), err)
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
	if nf.cfg.Policy != nil {
		relayPolicyTCP(nf.ctx, nf.cfg.Policy, PolicyInput, hostConn, guestConn, guestTuple, hostTuple)
		return
	}
	if nf.cfg.StreamInterceptor != nil {
		if err := nf.cfg.StreamInterceptor(nf.ctx, targetAddr.String(), guestConn, hostConn); err != nil {
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
	const proto = uint8(header.UDPProtocolNumber)
	if dstIP == netip.MustParseAddr(HostDNSIPv4) && id.LocalPort == 53 {
		requestPolicy, allowed := nf.authorizeDNSFlow(proto, id, dstIP)
		if !allowed {
			return false
		}
		if !tryAcquire(nf.dnsFlowSem) {
			nf.log.Debug("netbackend: drop guest DNS flow: too many DNS flows")
			return false
		}
		var wq waiter.Queue
		ep, tcpErr := r.CreateEndpoint(&wq)
		if tcpErr != nil {
			releaseSlot(nf.dnsFlowSem)
			return false
		}
		guestConn := gonet.NewUDPConn(&wq, ep)
		if !nf.spawn(func() {
			defer releaseSlot(nf.dnsFlowSem)
			nf.serveUDPDNS(nf.ctx, guestConn, requestPolicy)
		}) {
			releaseSlot(nf.dnsFlowSem)
			_ = guestConn.Close()
			return false
		}
		return true
	}

	targetAddr, err := nf.resolveOutboundTarget(dstIP, id.LocalPort)
	if err != nil {
		nf.log.Debug("netbackend: reject guest UDP flow", "error", err)
		return false
	}

	if nf.cfg.Policy != nil {
		return nf.startProtectedUDP(r, targetAddr, natGuestTuple(proto, id, dstIP))
	}
	hostConn, err := nf.cfg.DialContext(nf.ctx, "udp", targetAddr.String())
	if err != nil {
		nf.log.Debug("netbackend: dial host UDP target", "target", targetAddr, "error", err)
		return false
	}
	widenUDPSend(hostConn)

	var wq waiter.Queue
	ep, tcpErr := r.CreateEndpoint(&wq)
	if tcpErr != nil {
		_ = hostConn.Close()
		return false
	}

	guestConn := gonet.NewUDPConn(&wq, ep)
	sess := &udpSession{guest: guestConn, host: hostConn, clock: newActivityClock()}
	nf.udpSessions.add(sess)
	if !nf.spawn(func() {
		defer nf.udpSessions.remove(sess)
		relayDatagramsWithClock(nf.ctx, guestConn, hostConn, nf.udpIdle, sess.clock)
	}) {
		nf.udpSessions.remove(sess)
		sess.close()
		return false
	}
	return true
}

// relayBidirectional copies a to b and b to a until both directions end or ctx
// ends. It returns after both copy goroutines return, so callers can track
// the relay with a WaitGroup. EOF in one direction half-closes the other
// connection. A copy error closes both connections.
func relayBidirectional(ctx context.Context, a, b net.Conn) {
	copyStream := func(dst, src net.Conn) error {
		_, err := io.Copy(dst, src)
		return err
	}
	relayStreamPair(ctx, a, b, copyStream, copyStream, nil)
}

func relayStreamPair(ctx context.Context, a, b net.Conn, copyToA, copyToB func(dst, src net.Conn) error, cancel context.CancelFunc) {
	closeBoth := func() {
		if cancel != nil {
			cancel()
		}
		_ = a.Close()
		_ = b.Close()
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()

	var wg sync.WaitGroup
	pump := func(dst, src net.Conn, copyStream func(dst, src net.Conn) error) {
		defer wg.Done()
		err := copyStream(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok && err == nil {
			if cw.CloseWrite() == nil {
				return
			}
		}
		// A copy error, or a connection without half-close, ends both directions.
		closeBoth()
	}
	wg.Add(2)
	go pump(a, b, copyToA)
	go pump(b, a, copyToB)
	wg.Wait()
}

// isTimeout reports whether err is a deadline error. The gonet adapter returns
// its own timeout type, so the check uses net.Error instead of os.ErrDeadlineExceeded.
func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// datagramBuffers holds the read buffers of the UDP relays. A pump takes one
// when it starts and returns it when it ends, so a session that ends leaves its
// buffer to the next session, and the buffers of idle table slots cost nothing.
var datagramBuffers = sync.Pool{New: func() any {
	b := make([]byte, maxUDPDatagram)
	return &b
}}

// pumpDatagrams reads until either connection closes. A send error drops one
// datagram; a connected UDP read error is tolerated unless it persists.
func pumpDatagrams(src net.Conn, send func([]byte) error) {
	bp := datagramBuffers.Get().(*[]byte)
	defer datagramBuffers.Put(bp)
	buf := *bp
	transient := 0
	for {
		n, err := src.Read(buf)
		if err != nil {
			switch {
			case errors.Is(err, net.ErrClosed), errors.Is(err, io.EOF):
				return
			default:
				transient++
				if transient >= maxTransientUDPErrors {
					return
				}
			}
			continue
		}
		transient = 0
		if err := send(buf[:n]); errors.Is(err, net.ErrClosed) {
			return
		}
	}
}

// relayDatagrams relays datagrams between guestConn and hostConn until both
// directions stay idle for idle, either connection closes, or ctx ends. It
// closes both connections and returns after both pump goroutines return.
func relayDatagrams(ctx context.Context, guestConn, hostConn net.Conn, idle time.Duration) {
	relayDatagramsWithClock(ctx, guestConn, hostConn, idle, newActivityClock())
}

// relayDatagramsWithClock is relayDatagrams with the activity clock of the
// session, which the session table reads to find the oldest session.
func relayDatagramsWithClock(ctx context.Context, guestConn, hostConn net.Conn, idle time.Duration, clock *activityClock) {
	relayDatagramPumps(ctx, guestConn, hostConn, idle, clock, nil, PolicyTuple{}, PolicyTuple{})
}

func relayDatagramPumps(ctx context.Context, guestConn, hostConn net.Conn, idle time.Duration, clock *activityClock, policy *NATPolicy, guest, host PolicyTuple) {
	var cancel context.CancelFunc
	if policy != nil {
		ctx, cancel = context.WithCancel(ctx)
	}
	var once sync.Once
	closeBoth := func() {
		once.Do(func() {
			clock.stop()
			_ = guestConn.Close()
			_ = hostConn.Close()
		})
	}
	stop := context.AfterFunc(ctx, closeBoth)
	defer stop()
	clock.startIdleTimer(idle, closeBoth, cancel)
	// A custom dialer can leave a deadline behind. The session timer now
	// owns idle expiry, so clear the socket deadline before the first read.
	if err := hostConn.SetReadDeadline(time.Time{}); err != nil {
		closeBoth()
		return
	}

	var wg sync.WaitGroup
	pump := func(dst, src net.Conn, chain PolicyChain, legs [2]PolicyTuple) {
		defer wg.Done()
		defer closeBoth()
		pumpDatagrams(src, func(p []byte) error {
			if policy != nil {
				return policy.sendDatagram(ctx, chain, len(p), clock, func() (int, error) {
					var n int
					err := policyWrite(dst, func() error {
						var err error
						if chain == PolicyOutput {
							n, err = writeNATRelayDatagram(policy, dst.(*gonet.UDPConn), p, legs[:]...)
						} else {
							n, err = dst.Write(p)
						}
						return err
					})
					return n, err
				}, legs[:]...)
			}
			if !clock.touch() {
				return net.ErrClosed
			}
			_, err := dst.Write(p)
			return err
		})
	}
	wg.Add(2)
	go pump(hostConn, guestConn, PolicyInput, [2]PolicyTuple{guest, host})
	go pump(guestConn, hostConn, PolicyOutput, [2]PolicyTuple{guest.Reverse(), host.Reverse()})
	wg.Wait()
}
