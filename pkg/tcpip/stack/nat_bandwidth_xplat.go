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
	"sync"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// NATRelayOwner identifies packets and endpoints of one private NAT stack.
// The pipe does not copy Owner to the guest stack.
type NATRelayOwner struct{ _ byte }

func (*NATRelayOwner) KUID() uint32 { return 0 }
func (*NATRelayOwner) KGID() uint32 { return 0 }

// NATPacketMeter admits a packet on the private peer of a NAT pipe. Enqueue
// borrows pkt and must retain a reference if it defers deliver. It calls
// release, if non-nil, when it no longer needs deliver.
type NATPacketMeter interface {
	Enabled() bool
	Enqueue(pkt *PacketBuffer, bytes int, deliver func(*PacketBuffer), release func())
	Allows(*PacketBuffer) bool
	Run(deliver func()) bool
}

// NATPacketInput is transient metadata on packets received by the private peer.
// All packets on one attachment epoch share its initial value.
type NATPacketInput struct {
	scope     *natInputScope
	wireBytes int
}

type natInputScope struct {
	meter NATPacketMeter
	relay *NATRelayOwner

	fragmentsMu sync.Mutex
	fragments   [2]NATReassembler
	retired     bool
}

var natStaleReassembly NATPacketInput

// NewNATPacketInput starts a new attachment epoch. Only the private peer uses it.
func NewNATPacketInput(meter NATPacketMeter, relay *NATRelayOwner) *NATPacketInput {
	return &NATPacketInput{scope: &natInputScope{meter: meter, relay: relay}}
}

// NATReassembler owns one address family's fragment buffers for a pipe epoch.
type NATReassembler interface {
	Release()
}

// ReassembleNAT serializes fragment insertion through completion and release.
// Each family creates its reassembler on the first fragment of an epoch.
func ReassembleNAT[R NATReassembler](input *NATPacketInput, protocol tcpip.NetworkProtocolNumber, create func() R, process func(R) (*PacketBuffer, uint8, bool, error)) (*PacketBuffer, uint8, bool, error) {
	scope := input.scope
	if scope == nil {
		return nil, 0, false, nil
	}
	scope.fragmentsMu.Lock()
	defer scope.fragmentsMu.Unlock()
	if scope.retired {
		return nil, 0, false, nil
	}
	var index int
	if protocol == header.IPv6ProtocolNumber {
		index = 1
	}
	reassembler := scope.fragments[index]
	if reassembler == nil {
		r := create()
		scope.fragments[index] = r
		return process(r)
	}
	return process(reassembler.(R))
}

// RetireReassembly discards incomplete fragments and cancels their timers.
// Call after draining packet delivery for this epoch.
func (in *NATPacketInput) RetireReassembly() {
	scope := in.scope
	scope.fragmentsMu.Lock()
	defer scope.fragmentsMu.Unlock()
	scope.retired = true
	for index, reassembler := range scope.fragments {
		if reassembler != nil {
			reassembler.Release()
			scope.fragments[index] = nil
		}
	}
}

// NATReassemblyTimeout runs only against the epoch that received the packet.
type NATReassemblyTimeout func(*PacketBuffer)

func (h NATReassemblyTimeout) OnReassemblyTimeout(pkt *PacketBuffer) { h(pkt) }

// GuardReassemblyTimeout fences timeout effects with the epoch's drain.
func (in *NATPacketInput) GuardReassemblyTimeout(deliver func(*PacketBuffer)) NATReassemblyTimeout {
	return func(pkt *PacketBuffer) {
		if pkt != nil {
			in.scope.meter.Run(func() {
				if in.scope.meter.Allows(pkt) {
					deliver(pkt)
				}
			})
		}
	}
}

func (*NATPacketInput) KUID() uint32 { return 0 }
func (*NATPacketInput) KGID() uint32 { return 0 }

// NATInput returns the provenance set by the private pipe, if any.
func (pk *PacketBuffer) NATInput() *NATPacketInput {
	input, _ := pk.Owner.(*NATPacketInput)
	return input
}

// RelayOwner gives a TCP forwarder the owner of its first SYN-ACK.
func (in *NATPacketInput) RelayOwner() tcpip.PacketOwner {
	if in == nil || in.scope == nil {
		return nil
	}
	return in.scope.relay
}

func (in *NATPacketInput) relayed(ep TransportEndpoint) bool {
	relay, ok := ep.(interface{ NATRelayOwner() *NATRelayOwner })
	return ok && relay.NATRelayOwner() == in.scope.relay
}

// SetNATRelayTransportHandler sets an admitting relay as the default handler
// on a private NAT stack. Call this only during stack initialization.
func (s *Stack) SetNATRelayTransportHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	if state := s.transportProtocols[p]; state != nil {
		state.defaultHandler = h
		state.natRelay = h != nil
	}
}

// Stale reports a reassembly that spans more than one pipe attachment epoch.
func (in *NATPacketInput) Stale() bool { return in != nil && in.scope == nil }

// Metered reports whether packet-only effects need admission.
func (in *NATPacketInput) Metered() bool {
	return in != nil && (in.scope == nil || in.scope.meter.Enabled())
}

// Admit queues the original L3 byte count or drops a stale reassembly.
// Call this only if Metered reports true.
func (in *NATPacketInput) Admit(pkt *PacketBuffer, deliver func(*PacketBuffer)) {
	in.AdmitWithRelease(pkt, deliver, nil)
}

// AdmitWithRelease admits the packet and releases an additional reference at
// the end of delivery or on drop.
func (in *NATPacketInput) AdmitWithRelease(pkt *PacketBuffer, deliver func(*PacketBuffer), release func()) {
	if in.scope != nil {
		in.scope.meter.Enqueue(pkt, in.bytes(pkt), deliver, release)
	} else if release != nil {
		release()
	}
}

// Forwarded marks an egress copy of a packet already admitted in TX.
func (in *NATPacketInput) Forwarded(pkt *PacketBuffer) { pkt.Owner = in.scope.relay }

func (in *NATPacketInput) bytes(pkt *PacketBuffer) int {
	if in.wireBytes > 0 {
		return in.wireBytes
	}
	switch pkt.NetworkProtocolNumber {
	case header.IPv4ProtocolNumber:
		return int(header.IPv4(pkt.NetworkHeader().Slice()).TotalLength())
	case header.IPv6ProtocolNumber:
		return header.IPv6MinimumSize + int(header.IPv6(pkt.NetworkHeader().Slice()).PayloadLength())
	default:
		panic("unexpected NAT input network protocol")
	}
}

func mergeNATInput(dst, frag *PacketBuffer) {
	input, next := dst.NATInput(), frag.NATInput()
	if input == nil && next == nil {
		return
	}
	if input == nil || input.scope == nil || next == nil || input.scope != next.scope {
		dst.Owner = &natStaleReassembly
		return
	}
	switch input.wireBytes {
	case 0:
		// Only the reassembled packet owns this accumulator. Fragments retain
		// the shared epoch marker, including the copy held for timeout ICMP.
		dst.Owner = &NATPacketInput{scope: input.scope, wireBytes: input.bytes(dst) + next.bytes(frag)}
	default:
		input.wireBytes += next.bytes(frag)
	}
}

// DeliverNATLocalTransportPacket admits packet-only local effects but bypasses
// the packet meter for an admitted L4 relay. The callback runs with a borrowed
// packet and can run after this call returns.
func DeliverNATLocalTransportPacket(d TransportDispatcher, protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer, done func(*PacketBuffer, TransportPacketDisposition)) {
	if n, ok := d.(*nic); ok {
		n.deliverTransportPacket(protocol, pkt, done)
		return
	}
	pkt.NATInput().Admit(pkt, func(pkt *PacketBuffer) { done(pkt, d.DeliverTransportPacket(protocol, pkt)) })
}

func (d *transportDemuxer) deliverNATPacket(protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer, id TransportEndpointID, input *NATPacketInput) bool {
	protos := protocolIDs{pkt.NetworkProtocolNumber, protocol}
	if protocol == header.UDPProtocolNumber && isInboundMulticastOrBroadcast(pkt, id.LocalAddress) {
		return d.deliverNATMulticastUDP(protos, pkt, id, input)
	}
	if protocol == header.TCPProtocolNumber && (!isSpecified(id.LocalAddress) || !isSpecified(id.RemoteAddress) || isInboundMulticastOrBroadcast(pkt, id.LocalAddress)) {
		return d.deliverPacket(protocol, pkt, id)
	}
	ep := d.findTransportEndpoint(pkt.NetworkProtocolNumber, protocol, id, pkt.NICID)
	if ep == nil {
		if protocol == header.UDPProtocolNumber {
			d.stack.stats.UDP.UnknownPortErrors.Increment()
		}
		return false
	}
	// Keep the selected endpoint through admission. Retrying lookup after
	// the wait could deliver the packet to a newly published relay.
	if input.relayed(ep) {
		d.deliverNATPacketTo(ep, protos, id, pkt)
	} else {
		input.Admit(pkt, func(pkt *PacketBuffer) { d.deliverNATPacketTo(ep, protos, id, pkt) })
	}
	return true
}

func (d *transportDemuxer) deliverNATMulticastUDP(protos protocolIDs, pkt *PacketBuffer, id TransportEndpointID, input *NATPacketInput) bool {
	eps, ok := d.protocol[protos]
	if !ok {
		return false
	}
	var sockets []TransportEndpoint
	eps.mu.RLock()
	eps.iterEndpointsLocked(id, func(group *endpointsByNIC) bool {
		sockets = group.appendNATMulticastEndpoints(pkt.NICID, sockets)
		return true
	})
	eps.mu.RUnlock()
	if len(sockets) == 0 {
		d.stack.stats.UDP.UnknownPortErrors.Increment()
		return false
	}

	// Relay payloads keep their own accounting. Charge the IP packet once
	// only when one or more packet-only recipients also need delivery.
	packetOnly := sockets[:0]
	for index, endpoint := range sockets {
		if !input.relayed(endpoint) {
			packetOnly = append(packetOnly, endpoint)
			continue
		}
		if index == len(sockets)-1 && len(packetOnly) == 0 {
			endpoint.HandlePacket(id, pkt)
		} else {
			clone := pkt.Clone()
			endpoint.HandlePacket(id, clone)
			clone.DecRef()
		}
	}
	if len(packetOnly) != 0 {
		input.Admit(pkt, func(pkt *PacketBuffer) {
			for _, endpoint := range packetOnly[:len(packetOnly)-1] {
				clone := pkt.Clone()
				endpoint.HandlePacket(id, clone)
				clone.DecRef()
			}
			packetOnly[len(packetOnly)-1].HandlePacket(id, pkt)
		})
	}
	return true
}

func (group *endpointsByNIC) appendNATMulticastEndpoints(nic tcpip.NICID, sockets []TransportEndpoint) []TransportEndpoint {
	group.mu.RLock()
	defer group.mu.RUnlock()
	endpoints := group.endpoints[nic]
	if endpoints == nil {
		endpoints = group.endpoints[0]
	}
	if endpoints == nil {
		return sockets
	}
	endpoints.mu.RLock()
	defer endpoints.mu.RUnlock()
	return append(sockets, endpoints.endpoints...)
}

func (d *transportDemuxer) deliverNATPacketTo(ep TransportEndpoint, protos protocolIDs, id TransportEndpointID, pkt *PacketBuffer) {
	if queued := d.queuedProtocols[protos]; queued != nil {
		queued.QueuePacket(ep, id, pkt)
		return
	}
	ep.HandlePacket(id, pkt)
}
