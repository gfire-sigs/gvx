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

import "z.gfire.dev/gvx/pkg/tcpip"

// PacketPolicyIngress is set by a private attachment on freshly received
// packets. WireBytes counts the original IP lengths of contributing fragments;
// a negative value denotes reassembly across different attachments or epochs.
type PacketPolicyIngress struct {
	Attachment                                           any // an attachment's comparable identity
	Epoch                                                uint64
	Generation                                           uint64
	WireBytes                                            int
	Protocol                                             tcpip.TransportProtocolNumber
	SourcePort, DestinationPort                          uint16
	ProtocolKnown, SourcePortKnown, DestinationPortKnown bool
	Reassembled, Accounted                               bool
}

// AddFragment accumulates only wire lengths; selectors belong to the first
// fragment. Cross-revision or cross-attachment reassembly cannot be delivered.
func (p *PacketPolicyIngress) AddFragment(f PacketPolicyIngress) {
	if p.Attachment == nil && f.Attachment == nil {
		return
	}
	p.Reassembled = true
	if p.WireBytes < 0 || f.WireBytes < 0 || p.Attachment != f.Attachment ||
		p.Epoch != f.Epoch || p.Generation != f.Generation {
		p.WireBytes = -1
		return
	}
	p.WireBytes += f.WireBytes
}

// PacketPolicyOutput belongs to one locally generated write and its synchronous
// fragments. Provenance is independent of whether the payload was charged.
type PacketPolicyOutput struct {
	Provenance       any
	PayloadAccounted bool
	RelayTCP         bool
}

// PacketPolicyMetadata belongs to one in-process packet. It is not saved or
// carried across a link.
type PacketPolicyMetadata struct {
	Ingress PacketPolicyIngress
	Output  PacketPolicyOutput
}

// HasIngress reports whether an attachment supplied ingress metadata.
func (p *PacketPolicyMetadata) HasIngress() bool {
	return p != nil && p.Ingress.Attachment != nil
}

// AddIngressFragment accounts for a fragment, including a fragment with no
// ingress metadata when evaluating attachment and epoch consistency.
func (p *PacketPolicyMetadata) AddIngressFragment(fragment *PacketBuffer) {
	p.Ingress.AddFragment(fragment.policyIngress())
}

// RelayTransportEndpoint identifies an endpoint created by a relay forwarder.
type RelayTransportEndpoint interface {
	IsRelayTransportEndpoint() bool
}

// SetTransportProtocolRelayHandler sets an admitting relay as the default
// transport handler. Like SetTransportProtocolHandler, it is for initialization.
func (s *Stack) SetTransportProtocolRelayHandler(p tcpip.TransportProtocolNumber, h func(TransportEndpointID, *PacketBuffer) bool) {
	if state := s.transportProtocols[p]; state != nil {
		state.defaultHandler = h
		runtime := s.ensureRuntimeState()
		if runtime.relayProtocols == nil {
			runtime.relayProtocols = make(map[tcpip.TransportProtocolNumber]struct{})
		}
		runtime.relayProtocols[p] = struct{}{}
	}
}

// IsTransportRelayProtocol reports whether the default handler is a relay.
func (s *Stack) IsTransportRelayProtocol(p tcpip.TransportProtocolNumber) bool {
	if runtime := s.runtimeState(); runtime != nil {
		_, relay := runtime.relayProtocols[p]
		return relay
	}
	return false
}

// relaySocketStackHandler uses the same Stack without allocating a wrapper.
// SocketOptions does not save the stack handler, which is rebound on restore.
type relaySocketStackHandler Stack

func (s *relaySocketStackHandler) Option(option any) tcpip.Error {
	return (*Stack)(s).Option(option)
}

func (s *relaySocketStackHandler) TransportProtocolOption(p tcpip.TransportProtocolNumber, option tcpip.GettableTransportProtocolOption) tcpip.Error {
	return (*Stack)(s).TransportProtocolOption(p, option)
}

func (s *relaySocketStackHandler) TCPSendBufferLimits() tcpip.TCPSendBufferSizeRangeOption {
	return (*Stack)(s).TCPSendBufferLimits()
}

func (*relaySocketStackHandler) IsRelaySocketStackHandler() {}

// RelaySocketStackHandler returns the transient handler for relay sockets.
func (s *Stack) RelaySocketStackHandler() tcpip.StackHandler {
	return (*relaySocketStackHandler)(s)
}

// PacketDeliveryPolicy optionally accounts for packet-only local delivery on
// a private stack. A continuation borrows the packet when invoked, either
// synchronously or later with a reference owned by the policy.
type PacketDeliveryPolicy interface {
	DeliverPacketOnly(*PacketBuffer, func(*PacketBuffer))
	DeliverReassemblyTimeout(*PacketBuffer, func(*PacketBuffer))
	// ForwardPacket holds the forwarding route through release, including
	// when it drops the packet without invoking the continuation.
	ForwardPacket(*PacketBuffer, func(*PacketBuffer, PacketPolicyOutput), func())
}

// SynchronousPolicyLink identifies an attachment that never retains packet
// buffers; it must also be used with the default synchronous NIC discipline.
type SynchronousPolicyLink interface {
	SynchronousPolicyLink()
}

// PacketDeliveryPolicy returns the private packet-delivery hook, if configured.
func (s *Stack) PacketDeliveryPolicy() PacketDeliveryPolicy {
	hook, _ := s.NFTables().(PacketDeliveryPolicy)
	return hook
}

// DeliverLocalTransportPacket delivers a local packet, applying packet-only
// accounting before effects that are not part of a selected relay.
func (s *Stack) DeliverLocalTransportPacket(d TransportDispatcher, protocol tcpip.TransportProtocolNumber, pkt *PacketBuffer, onUnhandled func(*PacketBuffer, TransportPacketDisposition)) {
	if policy := s.PacketDeliveryPolicy(); policy != nil {
		if n, ok := d.(*nic); ok {
			n.deliverTransportPacket(protocol, pkt, policy, onUnhandled)
			return
		}
	}
	onUnhandled(pkt, d.DeliverTransportPacket(protocol, pkt))
}
