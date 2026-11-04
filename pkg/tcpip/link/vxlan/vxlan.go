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

// Package vxlan implements a VXLAN link endpoint (RFC 7348). The endpoint is
// an Ethernet device. It wraps each frame in a VXLAN header and a UDP datagram
// and sends it through the routes of its own network stack, so the outer
// packets follow the routes of the guest. It receives the datagrams on a UDP
// endpoint of that stack and demultiplexes them by VNI.
//
// The forwarding table follows the VXLAN driver of Linux. A frame goes to the
// remotes of the entry for its destination address. A frame with no entry goes
// to the remotes of the all-zeros entry. With learning on, the endpoint learns
// the source address of each received frame.
package vxlan

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/checksum"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// DefaultPort is the UDP port of a link with no destination port. It is the
	// port that Linux used before the IANA assigned 4789.
	DefaultPort = 8472

	// MaxVNI is the largest network identifier. The identifier has 24 bits.
	MaxVNI = 1<<24 - 1

	// DefaultAgeing is the time in seconds after which an unused learned entry
	// ends.
	DefaultAgeing = 300

	// DefaultTTL is the TTL of an outer packet when the link sets none.
	DefaultTTL = 64

	// Overhead4 and Overhead6 are the bytes that VXLAN, UDP, IP, and the inner
	// Ethernet header add to the MTU of the underlay link.
	Overhead4 = 50
	Overhead6 = 70

	// DefaultMTU is the MTU of a link with no underlay link and no MTU.
	DefaultMTU = 1500 - Overhead4

	headerLen = 8
	// flagVNI is the I flag: the VNI field is valid.
	flagVNI = 0x08
	// flagGBP is the G flag of the Group Based Policy extension.
	flagGBP = 0x80
	// gbpFlags2 holds the D and A bits in the second byte of a GBP header.
	gbpFlags2 = 0x48

	defaultPortLow  = 32768
	defaultPortHigh = 60999
)

// Config is the configuration of a link. The fields follow the IFLA_VXLAN
// attributes of include/uapi/linux/if_link.h. The endpoint stores every field.
type Config struct {
	// ID is the interface index of the link in the stack. A packet whose route
	// leaves through this index loops, so the endpoint drops it.
	ID tcpip.NICID

	// VNI is the network identifier of the link, from 0 to MaxVNI.
	VNI uint32

	// Port is the UDP port that the endpoint listens on and sends to, unless a
	// remote names another port. 0 selects DefaultPort.
	Port uint16

	// Local is the outer source address and the address of the UDP endpoint. The
	// unspecified address stands for any address.
	Local tcpip.Address

	// Group is the remote of the all-zeros entry at creation. The unspecified
	// address stands for no remote. A multicast group is not supported.
	Group tcpip.Address

	// Link is the interface index of the underlay link, or 0.
	Link tcpip.NICID

	// TTL and TOS are the fields of the outer IP header. A TTL of 0 selects
	// DefaultTTL.
	TTL, TOS uint8

	// TTLInherit and the three fields after it are stored and reported. The
	// transmit path does not read them.
	TTLInherit bool
	DF         uint8
	Label      uint32

	// Learning makes the link learn the source address of received frames.
	Learning bool

	// AgeingSeconds is the time that an unused learned entry lives. 0 keeps
	// every entry.
	AgeingSeconds uint32

	// Limit is the largest count of learned entries, or 0 for no limit.
	Limit uint32

	// PortLow and PortHigh are the range of outer source ports. The endpoint
	// stores them. It sends from a flow hash inside the range, as Linux does.
	// Both 0 select the default range.
	PortLow, PortHigh uint16

	// UDPCsum makes an IPv4 outer packet carry a UDP checksum. An IPv6 outer
	// packet always carries one unless UDPZeroCsum6Tx is set.
	UDPCsum          bool
	UDPZeroCsum6Tx   bool
	UDPZeroCsum6Rx   bool
	Proxy, RSC       bool
	L2Miss, L3Miss   bool
	RemcsumTx        bool
	RemcsumRx        bool
	RemcsumNoPartial bool

	// GBP accepts the Group Based Policy header bits on receive.
	GBP bool

	// MTU is the MTU of the link, or 0 to use the MTU of the underlay link
	// minus the overhead.
	MTU uint32

	// Address is the Ethernet address of the link, or empty for a random one.
	Address tcpip.LinkAddress
}

// IPv6 reports whether the outer packets use IPv6.
func (c *Config) IPv6() bool {
	return c.Local.Len() == header.IPv6AddressSize || c.Group.Len() == header.IPv6AddressSize
}

// anyAddress returns the unspecified address of the outer family.
func (c *Config) anyAddress() tcpip.Address {
	if c.IPv6() {
		return tcpip.AddrFrom16([16]byte{})
	}
	return tcpip.AddrFrom4([4]byte{})
}

// ErrDuplicate is the error of a link whose VNI and UDP port another link of
// the stack already uses.
var ErrDuplicate = errors.New("vxlan: another link has the same VNI and port")

// StackError carries an error of the network stack, for example from the bind
// of the UDP endpoint.
type StackError struct{ Err tcpip.Error }

func (e *StackError) Error() string { return "vxlan: " + e.Err.String() }

// Endpoint is a VXLAN link endpoint.
type Endpoint struct {
	stack *stack.Stack
	cfg   Config
	proto tcpip.NetworkProtocolNumber
	table fdb
	sock  *udpSocket

	mtu atomic.Uint32

	mu         sync.RWMutex
	dispatcher stack.NetworkDispatcher
	linkAddr   tcpip.LinkAddress
	onClose    func()

	closeOnce sync.Once
}

var _ stack.LinkEndpoint = (*Endpoint)(nil)

// New returns a link endpoint. It binds the UDP endpoint of the link, or joins
// the one of another link with the same address and port and another VNI.
func New(s *stack.Stack, cfg Config) (*Endpoint, error) {
	if cfg.VNI > MaxVNI {
		return nil, fmt.Errorf("vxlan: VNI %d is larger than %d", cfg.VNI, MaxVNI)
	}
	if cfg.Local.Len() != 0 && cfg.Group.Len() != 0 && cfg.Local.Len() != cfg.Group.Len() {
		return nil, ErrBadAddress
	}
	if cfg.Port == 0 {
		cfg.Port = DefaultPort
	}
	if cfg.Local.Len() == 0 || cfg.Group.Len() == 0 {
		// Normalize an empty address to the unspecified address of the family.
		unspecified := cfg.anyAddress()
		if cfg.Local.Len() == 0 {
			cfg.Local = unspecified
		}
		if cfg.Group.Len() == 0 {
			cfg.Group = unspecified
		}
	}
	e := &Endpoint{stack: s, cfg: cfg, proto: header.IPv4ProtocolNumber, linkAddr: cfg.Address}
	if cfg.IPv6() {
		e.proto = header.IPv6ProtocolNumber
	}
	if e.linkAddr == "" {
		e.linkAddr = tcpip.GetRandMacAddr()
	}
	e.cfg.Address = e.linkAddr
	e.mtu.Store(e.initialMTU())
	if !cfg.Group.Unspecified() {
		if header.IsV4MulticastAddress(cfg.Group) || header.IsV6MulticastAddress(cfg.Group) {
			return nil, ErrNotSupported
		}
		r := Remote{IP: cfg.Group, Port: cfg.Port, VNI: cfg.VNI, Link: cfg.Link}
		if err := e.table.update(zeroMAC, NUDReachable|NUDPermanent, NTFSelf, r, UpdateMode{Create: true, Excl: true}, time.Now()); err != nil {
			return nil, err
		}
	}
	sock, err := acquireSocket(e)
	if err != nil {
		return nil, err
	}
	e.sock = sock
	return e, nil
}

// initialMTU returns the MTU of a new link: the one in the configuration, or
// the MTU of the underlay link minus the overhead.
func (e *Endpoint) initialMTU() uint32 {
	if e.cfg.MTU != 0 {
		return e.cfg.MTU
	}
	overhead := uint32(Overhead4)
	if e.cfg.IPv6() {
		overhead = Overhead6
	}
	if e.cfg.Link != 0 {
		if info, ok := e.stack.SingleNICInfo(e.cfg.Link); ok && info.MTU > overhead {
			return info.MTU - overhead
		}
	}
	return 1500 - overhead
}

// Config returns the configuration of the link, with the defaults filled in.
func (e *Endpoint) Config() Config { return e.cfg }

// FDB returns a copy of the forwarding table.
func (e *Endpoint) FDB() []FDBEntry {
	return e.table.snapshot(time.Now(), e.ageing())
}

func (e *Endpoint) ageing() time.Duration {
	return time.Duration(e.cfg.AgeingSeconds) * time.Second
}

// normalizeRemote checks the family of the remote and turns an empty address
// into the unspecified address of the family of the link.
func (e *Endpoint) normalizeRemote(r Remote) (Remote, error) {
	switch r.IP.Len() {
	case 0:
		r.IP = e.cfg.anyAddress()
	case header.IPv4AddressSize, header.IPv6AddressSize:
		if r.IP.Len() != e.cfg.anyAddress().Len() {
			return r, ErrBadAddress
		}
	default:
		return r, ErrBadAddress
	}
	return r, nil
}

// FDBUpdate adds or changes the entry for mac, as RTM_NEWNEIGH of the family
// AF_BRIDGE does. The state must hold NUDPermanent or NUDReachable.
func (e *Endpoint) FDBUpdate(mac tcpip.LinkAddress, state uint16, flags uint8, r Remote, mode UpdateMode) error {
	if state&(NUDPermanent|NUDReachable) == 0 {
		return ErrBadState
	}
	r, err := e.normalizeRemote(r)
	if err != nil {
		return err
	}
	return e.table.update(mac, state, flags, r, mode, time.Now())
}

// FDBDelete removes the remote from the entry for mac, or the whole entry when
// the remote has no address, as RTM_DELNEIGH of the family AF_BRIDGE does.
func (e *Endpoint) FDBDelete(mac tcpip.LinkAddress, r Remote) error {
	r, err := e.normalizeRemote(r)
	if err != nil {
		return err
	}
	return e.table.remove(mac, r)
}

// transmit encapsulates one frame for each remote of its FDB entry and sends
// it. Linux does the same in vxlan_xmit: a failed send drops that copy.
func (e *Endpoint) transmit(pkt *stack.PacketBuffer) {
	frame := pkt.ToBuffer()
	defer frame.Release()
	var hdr [64]byte
	n, _ := frame.ReadAt(hdr[:], 0)
	if n < header.EthernetMinimumSize {
		return
	}
	var scratch [4]Remote
	remotes := e.table.lookup(tcpip.LinkAddress(hdr[:6]), time.Now(), e.ageing(), scratch[:0])
	if len(remotes) == 0 {
		return
	}
	sport := e.sourcePort(hdr[:n])
	for _, r := range remotes {
		e.send(&frame, r, sport)
	}
}

// send writes one encapsulated copy of the frame to the remote. It sends
// nothing for a remote with the unspecified address.
func (e *Endpoint) send(frame *buffer.Buffer, r Remote, sport uint16) {
	if r.IP.Unspecified() {
		return
	}
	var local tcpip.Address
	if !e.cfg.Local.Unspecified() {
		local = e.cfg.Local
	}
	route, err := e.stack.FindRoute(0, local, r.IP, e.proto, false /* multicastLoop */)
	if err != nil {
		return
	}
	defer route.Release()
	if route.OutgoingNIC() == e.cfg.ID {
		// The route loops through this link, as Linux reports in vxlan_xmit_one.
		return
	}
	payload := frame.Clone()
	var vh [headerLen]byte
	vh[0] = flagVNI
	vh[4], vh[5], vh[6] = byte(r.VNI>>16), byte(r.VNI>>8), byte(r.VNI)
	if err := payload.Prepend(buffer.NewViewWithData(vh[:])); err != nil {
		payload.Release()
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		ReserveHeaderBytes: int(route.MaxHeaderLength()) + header.UDPMinimumSize,
		Payload:            payload,
	})
	defer pkt.DecRef()
	if pkt.Size()+header.UDPMinimumSize > header.UDPMaximumPacketSize {
		return
	}
	udp := header.UDP(pkt.TransportHeader().Push(header.UDPMinimumSize))
	pkt.TransportProtocolNumber = header.UDPProtocolNumber
	length := uint16(pkt.Size())
	udp.Encode(&header.UDPFields{SrcPort: sport, DstPort: r.Port, Length: length})
	v6 := e.proto == header.IPv6ProtocolNumber
	if route.RequiresTXTransportChecksum() && (v6 && !e.cfg.UDPZeroCsum6Tx || !v6 && e.cfg.UDPCsum) {
		xsum := udp.CalculateChecksum(checksum.Combine(
			header.PseudoHeaderChecksum(header.UDPProtocolNumber, route.LocalAddress(), route.RemoteAddress(), length),
			pkt.Data().Checksum(),
		))
		// A computed zero goes out as all ones, because zero means "no checksum".
		if xsum != 0xffff {
			xsum = ^xsum
		}
		udp.SetChecksum(xsum)
	}
	ttl := e.cfg.TTL
	if ttl == 0 {
		ttl = DefaultTTL
	}
	route.WritePacket(stack.NetworkHeaderParams{
		Protocol: header.UDPProtocolNumber,
		TTL:      ttl,
		TOS:      e.cfg.TOS,
		DF:       e.cfg.DF == 1,
	}, pkt)
}

// sourcePort returns the outer UDP source port for a frame. The hash covers the
// Ethernet addresses and, for IPv4 and IPv6, the addresses, the protocol, and
// the ports, so one flow keeps one port and stays in order, as with
// udp_flow_src_port in Linux.
func (e *Endpoint) sourcePort(frame []byte) uint16 {
	low, high := uint32(e.cfg.PortLow), uint32(e.cfg.PortHigh)
	if low == 0 && high == 0 {
		low, high = defaultPortLow, defaultPortHigh
	}
	if high < low {
		low, high = high, low
	}
	const (
		offset = 14695981039346656037
		prime  = 1099511628211
	)
	h := uint64(offset)
	mix := func(b []byte) {
		for _, c := range b {
			h = (h ^ uint64(c)) * prime
		}
	}
	mix(frame[:12])
	if len(frame) >= 14 {
		proto := tcpip.NetworkProtocolNumber(uint16(frame[12])<<8 | uint16(frame[13]))
		rest := frame[14:]
		switch {
		case proto == header.IPv4ProtocolNumber && len(rest) >= header.IPv4MinimumSize:
			ihl := int(rest[0]&0x0f) * 4
			mix(rest[9:10])
			mix(rest[12:20])
			if (rest[9] == byte(header.TCPProtocolNumber) || rest[9] == byte(header.UDPProtocolNumber)) && ihl >= header.IPv4MinimumSize && len(rest) >= ihl+4 {
				mix(rest[ihl : ihl+4])
			}
		case proto == header.IPv6ProtocolNumber && len(rest) >= header.IPv6MinimumSize:
			mix(rest[6:7])
			mix(rest[8:40])
			if (rest[6] == byte(header.TCPProtocolNumber) || rest[6] == byte(header.UDPProtocolNumber)) && len(rest) >= header.IPv6MinimumSize+4 {
				mix(rest[header.IPv6MinimumSize : header.IPv6MinimumSize+4])
			}
		}
	}
	return uint16(low + uint32((h>>32)^h)%(high-low+1))
}

// receive injects the inner frame of one datagram. src is the outer source of
// the datagram.
func (e *Endpoint) receive(frame []byte, src tcpip.Address) {
	if len(frame) < header.EthernetMinimumSize {
		return
	}
	eth := header.Ethernet(frame)
	if e.cfg.Learning {
		mac := eth.SourceAddress()
		if mac != zeroMAC && !header.IsMulticastEthernetAddress(mac) {
			r := Remote{IP: src, Port: e.cfg.Port, VNI: e.cfg.VNI}
			if !e.table.learn(mac, r, e.cfg.Limit, time.Now()) {
				return
			}
		}
	}
	e.mu.RLock()
	d := e.dispatcher
	e.mu.RUnlock()
	if d == nil {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(frame)})
	defer pkt.DecRef()
	if !e.ParseHeader(pkt) {
		return
	}
	switch dst := eth.DestinationAddress(); {
	case dst == header.EthernetBroadcastAddress:
		pkt.PktType = tcpip.PacketBroadcast
	case header.IsMulticastEthernetAddress(dst):
		pkt.PktType = tcpip.PacketMulticast
	case dst == e.LinkAddress():
		pkt.PktType = tcpip.PacketHost
	default:
		pkt.PktType = tcpip.PacketOtherHost
	}
	d.DeliverNetworkPacket(eth.Type(), pkt)
}

// parseHeader checks the VXLAN header of a datagram payload and returns the VNI
// and the inner frame. It follows vxlan_rcv: the I flag must be set, and every
// other bit must be 0, except the bits that the Group Based Policy extension
// owns when the link enables it.
func parseHeader(b []byte, gbp bool) (vni uint32, frame []byte, ok bool) {
	if len(b) < headerLen {
		return 0, nil, false
	}
	flags, flags2 := b[0], b[1]
	if flags&flagVNI == 0 {
		return 0, nil, false
	}
	flags &^= flagVNI
	if gbp {
		flags &^= flagGBP
		flags2 &^= gbpFlags2
	} else if b[2] != 0 || b[3] != 0 {
		return 0, nil, false
	}
	if flags != 0 || flags2 != 0 || b[7] != 0 {
		return 0, nil, false
	}
	return uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6]), b[headerLen:], true
}

// MTU implements stack.LinkEndpoint.
func (e *Endpoint) MTU() uint32 { return e.mtu.Load() }

// SetMTU implements stack.LinkEndpoint.
func (e *Endpoint) SetMTU(mtu uint32) { e.mtu.Store(mtu) }

// MaxHeaderLength implements stack.LinkEndpoint.
func (*Endpoint) MaxHeaderLength() uint16 { return header.EthernetMinimumSize }

// LinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) LinkAddress() tcpip.LinkAddress {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.linkAddr
}

// SetLinkAddress implements stack.LinkEndpoint.
func (e *Endpoint) SetLinkAddress(addr tcpip.LinkAddress) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.linkAddr = addr
}

// Capabilities implements stack.LinkEndpoint. The link needs address
// resolution, and it computes no checksum, so the stack must fill in the
// checksums of the inner packets.
func (*Endpoint) Capabilities() stack.LinkEndpointCapabilities {
	return stack.CapabilityResolutionRequired
}

// Attach implements stack.LinkEndpoint.
func (e *Endpoint) Attach(dispatcher stack.NetworkDispatcher) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dispatcher = dispatcher
}

// IsAttached implements stack.LinkEndpoint.
func (e *Endpoint) IsAttached() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.dispatcher != nil
}

// WritePackets implements stack.LinkEndpoint. It encapsulates each frame and
// sends the copies on the calling goroutine. Like a device of Linux, the link
// never fails a write: it drops a frame that has no remote or no route.
func (e *Endpoint) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	n := 0
	for _, pkt := range pkts.AsSlice() {
		e.transmit(pkt)
		n++
	}
	return n, nil
}

// Wait implements stack.LinkEndpoint. Close already waits for the receive
// goroutine.
func (*Endpoint) Wait() {}

// ARPHardwareType implements stack.LinkEndpoint.
func (*Endpoint) ARPHardwareType() header.ARPHardwareType { return header.ARPHardwareEther }

// AddHeader implements stack.LinkEndpoint.
func (*Endpoint) AddHeader(pkt *stack.PacketBuffer) {
	eth := header.Ethernet(pkt.LinkHeader().Push(header.EthernetMinimumSize))
	eth.Encode(&header.EthernetFields{
		SrcAddr: pkt.EgressRoute.LocalLinkAddress,
		DstAddr: pkt.EgressRoute.RemoteLinkAddress,
		Type:    pkt.NetworkProtocolNumber,
	})
}

// ParseHeader implements stack.LinkEndpoint.
func (*Endpoint) ParseHeader(pkt *stack.PacketBuffer) bool {
	_, ok := pkt.LinkHeader().Consume(header.EthernetMinimumSize)
	return ok
}

// SetOnCloseAction implements stack.LinkEndpoint. The link never closes by
// itself, so the action never runs.
func (e *Endpoint) SetOnCloseAction(action func()) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.onClose = action
}

// Close implements stack.LinkEndpoint. It detaches the link from its UDP
// endpoint and closes that endpoint when no other link uses it. It waits until
// the receive goroutine of a closed UDP endpoint ends.
func (e *Endpoint) Close() {
	e.closeOnce.Do(func() {
		if e.sock != nil {
			e.sock.release(e)
		}
	})
}
