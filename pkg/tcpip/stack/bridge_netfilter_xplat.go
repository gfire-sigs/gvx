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

package stack

import (
	"z.gfire.dev/gvx/internal/weakmap"
	"z.gfire.dev/gvx/pkg/sync"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file implements the br_netfilter behavior of Linux. With
// bridge-nf-call-iptables or bridge-nf-call-ip6tables at 1, an IP frame that a
// bridge forwards between two ports passes the iptables hooks PREROUTING,
// FORWARD, and POSTROUTING. Both names of the bridged traffic in a rule
// (-i and -o) are the name of the bridge, as in Linux without the physdev match.
//
// Ref: net/bridge/br_netfilter_hooks.c.

// bridgeNetfilterDefault is the value of both switches in a network namespace
// that no write changed. It is the value that Linux has after "modprobe br_netfilter".
const bridgeNetfilterDefault = true

// bridgeNetfilterSwitches holds the switches of one Stack.
type bridgeNetfilterSwitches struct {
	ipv4 bool
	ipv6 bool
}

// bridgeNetfilterSwitchesMap holds the switches of stacks that differ from the
// default. When Len is 0, BridgeNetfilter takes no lock on the packet path.
// Checkpoint persistence lives on Stack.extState.
var bridgeNetfilterSwitchesMap weakmap.Map[Stack, bridgeNetfilterSwitches]

// BridgeNetfilter reports whether an IP frame of the protocol that a bridge of
// the stack forwards between two ports passes the iptables hooks.
func (s *Stack) BridgeNetfilter(protocol tcpip.NetworkProtocolNumber) bool {
	if bridgeNetfilterSwitchesMap.Len() == 0 {
		return bridgeNetfilterDefault
	}
	sw, ok := bridgeNetfilterSwitchesMap.Load(s)
	if !ok {
		return bridgeNetfilterDefault
	}
	if protocol == header.IPv6ProtocolNumber {
		return sw.ipv6
	}
	return sw.ipv4
}

// SetBridgeNetfilter sets bridge-nf-call-iptables for IPv4 or
// bridge-nf-call-ip6tables for IPv6 in the stack.
func (s *Stack) SetBridgeNetfilter(protocol tcpip.NetworkProtocolNumber, enable bool) {
	if s == nil {
		return
	}
	e := s.ensureExtState()
	var finalSw bridgeNetfilterSwitches
	var keep bool
	bridgeNetfilterSwitchesMap.Update(s, func(sw bridgeNetfilterSwitches, ok bool) (bridgeNetfilterSwitches, bool) {
		if !ok {
			sw = bridgeNetfilterSwitches{ipv4: bridgeNetfilterDefault, ipv6: bridgeNetfilterDefault}
		}
		if protocol == header.IPv6ProtocolNumber {
			sw.ipv6 = enable
		} else {
			sw.ipv4 = enable
		}
		finalSw = sw
		keep = sw.ipv4 != bridgeNetfilterDefault || sw.ipv6 != bridgeNetfilterDefault
		return sw, keep
	})
	e.mu.Lock()
	e.hasBridgeNetfilter = keep
	e.bridgeIPv4 = finalSw.ipv4
	e.bridgeIPv6 = finalSw.ipv6
	e.mu.Unlock()
}

// hasRules reports whether a write changed an iptables table. Until then the
// hooks accept every packet, and the bridge skips the parse of the frame.
func (it *IPTables) hasRules() bool {
	it.mu.RLock()
	defer it.mu.RUnlock()
	return it.modified
}

// netfilterForward runs the iptables hooks for an IP frame that the bridge
// forwards from port p to another port, and forwards the frame itself. It
// reports false when the frame does not take this path: another protocol, a
// switch at 0, a group frame, a frame for the bridge or for the port, a frame
// that does not parse, or an iptables table that no write changed. The caller
// then forwards the frame without the hooks.
//
// A frame that goes to the bridge, or to a host behind another route after a
// DNAT, enters the IP layer of the stack as it arrived. That layer runs its own
// hooks and reuses the connection that the bridge created.
func (p *bridgePort) netfilterForward(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) bool {
	if protocol != header.IPv4ProtocolNumber && protocol != header.IPv6ProtocolNumber {
		return false
	}
	stk := p.nic.stack
	if !stk.BridgeNetfilter(protocol) || !stk.IPTables().hasRules() {
		return false
	}

	eth := header.Ethernet(pkt.LinkHeader().Slice())
	if len(eth) < header.EthernetMinimumSize {
		return false
	}
	dstMAC := eth.DestinationAddress()
	if header.IsMulticastEthernetAddress(dstMAC) {
		return false
	}
	b := p.bridge
	b.mu.RLock()
	isLocal, dispatcher := b.isLocalAddressLocked(dstMAC), b.dispatcher
	b.mu.RUnlock()
	if isLocal {
		return false
	}
	bridgeNIC, ok := dispatcher.(*nic)
	if !ok {
		return false
	}
	addressEP, ok := bridgeNIC.getNetworkEndpoint(protocol).(AddressableEndpoint)
	if !ok {
		return false
	}

	work := p.parseForNetfilter(protocol, pkt)
	if work == nil {
		return false
	}
	// From here the bridge owns the frame. Every path ends with work.DecRef.
	work.InputNICID = bridgeNIC.id
	work.NICID = bridgeNIC.id
	// The physdev match sees the port of arrival from the PREROUTING hook on.
	work.Bridged = true
	work.BridgedFrom = p.nic.Name()
	oldDst := work.Network().DestinationAddress()
	name := bridgeNIC.Name()
	it := stk.IPTables()
	if !it.CheckPrerouting(work, addressEP, name) {
		work.DecRef()
		return true
	}
	newDst := work.Network().DestinationAddress()
	if newDst == oldDst {
		p.netfilterFinish(bridgeNIC, addressEP, work)
		return true
	}

	// A DNAT rule changed the destination. Linux looks up the route again.
	// A destination on the bridge gets a new Ethernet address from the neighbor
	// cache of the bridge. Any other destination goes up to the IP layer.
	if stk.CheckLocalAddress(0, protocol, newDst) != 0 {
		p.netfilterDeliverUp(dispatcher, protocol, pkt, work)
		return true
	}
	r, err := stk.FindRoute(bridgeNIC.id, tcpip.Address{}, newDst, protocol, false /* multicastLoop */)
	if err != nil {
		work.DecRef()
		return true
	}
	if r.OutgoingNIC() != bridgeNIC.id || (r.NextHop().BitLen() != 0 && r.NextHop() != newDst) {
		r.Release()
		p.netfilterDeliverUp(dispatcher, protocol, pkt, work)
		return true
	}

	// The neighbor cache may call back while it holds the lock of the entry, so
	// the callback never sends a frame. A callback that runs before
	// ResolvedFields returns stores the result. A later callback starts a
	// goroutine.
	var (
		mu       sync.Mutex
		returned bool
		called   bool
		resolved ResolvedFieldsResult
	)
	resolveErr := r.ResolvedFields(func(res ResolvedFieldsResult) {
		mu.Lock()
		if !returned {
			resolved, called = res, true
			mu.Unlock()
			return
		}
		mu.Unlock()
		go func() {
			defer r.Release()
			p.netfilterResolved(bridgeNIC, addressEP, work, res)
		}()
	})
	mu.Lock()
	returned = true
	ranInline := called
	mu.Unlock()
	if _, wouldBlock := resolveErr.(*tcpip.ErrWouldBlock); wouldBlock && !ranInline {
		// The callback owns the route and the frame.
		return true
	}
	defer r.Release()
	if resolveErr != nil && !ranInline {
		work.DecRef()
		return true
	}
	p.netfilterResolved(bridgeNIC, addressEP, work, resolved)
	return true
}

// parseForNetfilter returns a private copy of the frame with the link, network,
// and transport headers parsed. The caller owns the copy. It returns nil when
// the frame is not a valid IP packet.
func (p *bridgePort) parseForNetfilter(protocol tcpip.NetworkProtocolNumber, pkt *PacketBuffer) *PacketBuffer {
	frame := pkt.ToBuffer()
	defer frame.Release()
	work := NewPacketBuffer(PacketBufferOptions{Payload: frame.DeepClone()})
	work.NetworkProtocolNumber = protocol
	// The port is a NIC, but the frame skips nic.DeliverNetworkPacket, which sets this flag.
	work.RXChecksumValidated = p.nic.NetworkLinkEndpoint.Capabilities()&CapabilityRXChecksumOffload != 0
	if _, ok := work.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
		work.DecRef()
		return nil
	}
	stk := p.nic.stack
	netProto := stk.NetworkProtocolInstance(protocol)
	if netProto == nil {
		work.DecRef()
		return nil
	}
	transProto, hasTransport, ok := netProto.Parse(work)
	if !ok {
		work.DecRef()
		return nil
	}
	if protocol == header.IPv4ProtocolNumber {
		h := header.IPv4(work.NetworkHeader().Slice())
		if !h.IsValid(work.Size()-len(work.LinkHeader().Slice())) || (!work.RXChecksumValidated && !h.IsChecksumValid()) {
			work.DecRef()
			return nil
		}
	}
	if !hasTransport {
		return work
	}
	switch transProto {
	case header.ICMPv4ProtocolNumber:
		if _, ok := work.TransportHeader().Consume(header.ICMPv4MinimumSize); ok {
			work.TransportProtocolNumber = transProto
		}
	case header.ICMPv6ProtocolNumber:
		if _, ok := work.TransportHeader().Consume(header.ICMPv6EchoMinimumSize); ok {
			work.TransportProtocolNumber = transProto
		}
	default:
		// A transport header that does not parse leaves the packet without one.
		// Conntrack then skips it, as it does in the IP layer.
		_ = stk.ParsePacketBufferTransport(transProto, work)
	}
	return work
}

// netfilterResolved continues a frame after the DNAT rule changed its
// destination. It takes the ownership of work.
func (p *bridgePort) netfilterResolved(bridgeNIC *nic, addressEP AddressableEndpoint, work *PacketBuffer, res ResolvedFieldsResult) {
	if res.Err != nil || res.RouteInfo.RemoteLinkAddress == "" {
		work.DecRef()
		return
	}
	eth := header.Ethernet(work.LinkHeader().Slice())
	eth.Encode(&header.EthernetFields{
		SrcAddr: eth.SourceAddress(),
		DstAddr: res.RouteInfo.RemoteLinkAddress,
		Type:    eth.Type(),
	})
	p.netfilterFinish(bridgeNIC, addressEP, work)
}

// netfilterFinish runs the FORWARD and POSTROUTING hooks and sends the frame
// to the port that the forwarding database names for its destination. It takes
// the ownership of work.
func (p *bridgePort) netfilterFinish(bridgeNIC *nic, addressEP AddressableEndpoint, work *PacketBuffer) {
	defer work.DecRef()
	it := p.nic.stack.IPTables()
	name := bridgeNIC.Name()
	work.BridgedTo = p.egressPortName(work)
	if !it.CheckForward(work, name, name) {
		return
	}
	// The route of a bridged frame is the bridge. It tells the NAT code whether
	// to update the transport checksum, which a bridge does not offload.
	if !it.CheckPostrouting(work, &Route{outgoingNIC: bridgeNIC}, addressEP, name) {
		return
	}
	p.bridge.forwardFrame(p, work)
}

// egressPortName returns the name of the port that receives the frame, or an
// empty name when the frame goes to no port or to many ports. Linux decides the
// port before the FORWARD hook, so the physdev match of the hook can name it.
// A frame that goes to many ports has no single port for the match. Linux runs
// the hook once for each port.
func (p *bridgePort) egressPortName(work *PacketBuffer) string {
	dst := header.Ethernet(work.LinkHeader().Slice()).DestinationAddress()
	b := p.bridge
	b.mu.RLock()
	targets := b.forwardTargetsLocked(p, dst)
	b.mu.RUnlock()
	if len(targets) != 1 {
		return ""
	}
	return targets[0].nic.Name()
}

// netfilterDeliverUp gives the original frame to the IP layer of the bridge. It
// takes the ownership of work, the rewritten copy, and drops it.
//
// The IP layer must see the frame as it arrived. Its PREROUTING hook then
// finds the connection that the bridge created for the original tuple and
// applies the same DNAT. A frame with the rewritten destination would start a
// second connection with the new tuple, and the replies would miss the NAT.
func (p *bridgePort) netfilterDeliverUp(d NetworkDispatcher, protocol tcpip.NetworkProtocolNumber, orig, work *PacketBuffer) {
	work.DecRef()
	up := NewPacketBuffer(PacketBufferOptions{Payload: orig.ToBuffer()})
	defer up.DecRef()
	if _, ok := up.LinkHeader().Consume(header.EthernetMinimumSize); !ok {
		return
	}
	d.DeliverNetworkPacket(protocol, up)
}

// forwardFrame learns the source address of the frame and sends the frame to
// the port of its destination address. An unknown destination goes to every port
// except the port of arrival. The bridge keeps no lock while it writes. It
// returns whether the frame is addressed to the bridge or one of its ports.
func (b *BridgeEndpoint) forwardFrame(from *bridgePort, frame *PacketBuffer) bool {
	eth := header.Ethernet(frame.LinkHeader().Slice())
	src, dst := eth.SourceAddress(), eth.DestinationAddress()
	isMulticast := header.IsMulticastEthernetAddress(dst)

	b.mu.RLock()
	isLocal := !isMulticast && b.isLocalAddressLocked(dst)
	switch {
	case dst == header.EthernetBroadcastAddress:
		frame.PktType = tcpip.PacketBroadcast
	case isMulticast:
		frame.PktType = tcpip.PacketMulticast
	case dst == b.addr || dst == from.nic.LinkAddress():
		frame.PktType = tcpip.PacketHost
	default:
		frame.PktType = tcpip.PacketOtherHost
	}
	learn := b.needsLearningLocked(src, from)
	targets := b.forwardTargetsLocked(from, dst)
	b.mu.RUnlock()

	if learn {
		b.mu.Lock()
		// The port or the bridge's addresses may have changed while the frame
		// waited for the neighbor cache or while the lock was released.
		if b.needsLearningLocked(src, from) {
			b.addFDBEntryLocked(src, from, 0)
		}
		b.mu.Unlock()
	}
	for _, port := range targets {
		out := NewPacketBuffer(PacketBufferOptions{
			ReserveHeaderBytes: int(port.nic.MaxHeaderLength()),
			Payload:            frame.ToBuffer(),
		})
		port.nic.writeRawPacket(out)
		out.DecRef()
	}
	return isLocal
}
