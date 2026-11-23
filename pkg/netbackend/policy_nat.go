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
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// natPolicyHooks binds the fixed filter program to the private peer's IP
// hooks. The adapter avoids enabling Netstack's unrelated connection tracker.
type natPolicyHooks struct {
	policy *NATPolicy
}

func (h natPolicyHooks) allows(chain PolicyChain, pkt *stack.PacketBuffer) bool {
	tuple, ok := policyPacketTuple(pkt)
	return ok && h.policy.Allow(chain, tuple)
}

func (h natPolicyHooks) CheckInput(pkt *stack.PacketBuffer, _ *stack.Route, _ stack.AddressFamily) bool {
	metadata := pkt.PacketPolicy()
	if !metadata.HasIngress() {
		return false
	}
	tuple, ipBytes, ok := policyPacketDetails(pkt)
	if !ok || !h.policy.active.allows(PolicyInput, []PolicyTuple{tuple}) {
		return false
	}
	input := &metadata.Ingress
	input.WireBytes = ipBytes
	input.Protocol, input.ProtocolKnown = tcpip.TransportProtocolNumber(tuple.Protocol), tuple.ProtocolKnown
	input.SourcePort, input.SourcePortKnown = tuple.SourcePort, tuple.SourcePortKnown
	input.DestinationPort, input.DestinationPortKnown = tuple.DestinationPort, tuple.DestinationPortKnown
	return true
}

func (h natPolicyHooks) CheckForward(pkt *stack.PacketBuffer, _ *stack.Route, _ tcpip.NICID, _ stack.AddressFamily) bool {
	return h.allows(PolicyForward, pkt)
}

func (h natPolicyHooks) CheckOutput(pkt *stack.PacketBuffer, _ *stack.Route, _ tcpip.NICID, _ stack.AddressFamily) bool {
	metadata := pkt.PacketPolicy()
	if metadata != nil {
		if output, ok := metadata.Output.Provenance.(*natRelayOutput); ok {
			// The pipe is the final handoff. It checks the original legs under
			// the snapshot pinned by the relay's synchronous write.
			return output.policy == h.policy
		}
	}
	return h.allows(PolicyOutput, pkt)
}

func (h natPolicyHooks) DeliverPacketOnly(pkt *stack.PacketBuffer, deliver func(*stack.PacketBuffer)) {
	h.deliverPacketOnly(pkt, deliver, false)
}

func (h natPolicyHooks) DeliverReassemblyTimeout(pkt *stack.PacketBuffer, deliver func(*stack.PacketBuffer)) {
	release := h.policy.tryRead()
	if release == nil {
		return
	}
	defer release()
	// Netstack calls the timeout handler under its reassembly lock. Do not
	// run a synchronous pipe write until that lock can be released.
	h.deliverPacketOnly(pkt, deliver, true)
}

func (h natPolicyHooks) deliverPacketOnly(pkt *stack.PacketBuffer, deliver func(*stack.PacketBuffer), forceQueue bool) {
	metadata := pkt.PacketPolicy()
	if metadata == nil {
		return
	}
	input := metadata.Ingress
	wire, ok := input.Attachment.(*natPacketLinkState)
	if !ok || input.WireBytes <= 0 || input.Generation != h.policy.generation {
		return
	}
	chargedDelivery := func(pkt *stack.PacketBuffer) {
		metadata.Ingress.Accounted = true
		deliver(pkt)
	}
	if !forceQueue && h.policy.active.config.TX.RateBPS == 0 {
		chargedDelivery(pkt)
		return
	}
	tuple := policyInputTuple(pkt)
	pkt.IncRef()
	h.policy.enqueue(PolicyInput, input.WireBytes, input.Generation, input.Reassembled, func() {
		wire.withActive(input.Epoch, func() { chargedDelivery(pkt) })
	}, pkt.DecRef, tuple)
}

func (h natPolicyHooks) ForwardPacket(pkt *stack.PacketBuffer, forward func(*stack.PacketBuffer, stack.PacketPolicyOutput), dispose func()) {
	metadata := pkt.PacketPolicy()
	if metadata == nil {
		dispose()
		return
	}
	input := metadata.Ingress
	wire, ok := input.Attachment.(*natPacketLinkState)
	if !ok {
		dispose()
		return
	}
	tuple, ipBytes, ok := policyPacketDetails(pkt)
	if !ok {
		dispose()
		return
	}
	// Never put forwarded fragments through reassembly. The unit is the
	// individual ingress packet, even when the outgoing MTU fragments it.
	pkt.IncRef()
	h.policy.Enqueue(PolicyForward, ipBytes, func() {
		wire.withActive(input.Epoch, func() {
			forward(pkt, stack.PacketPolicyOutput{Provenance: wire})
		})
	}, func() {
		pkt.DecRef()
		dispose()
	}, tuple)
}

func (natPolicyHooks) CheckPrerouting(*stack.PacketBuffer, *stack.Route, stack.AddressFamily) bool {
	return true
}

func (natPolicyHooks) CheckPostrouting(*stack.PacketBuffer, *stack.Route, tcpip.NICID, stack.AddressFamily) bool {
	return true
}

func (natPolicyHooks) CheckIngress(*stack.PacketBuffer, *stack.Route, stack.AddressFamily) bool {
	return true
}

func (natPolicyHooks) CheckEgress(*stack.PacketBuffer, *stack.Route, tcpip.NICID, stack.AddressFamily) bool {
	return true
}

// natPacketLinkState invalidates queued work when a wire is quiesced or
// replaced. The writer barrier drains active packet callbacks without holding
// NATForwarder.mu, which the synchronous pipe dispatch may acquire.
type natPacketLinkState struct {
	paused *atomic.Bool
	epoch  atomic.Uint64
	gate   sync.RWMutex
	closed atomic.Bool
}

func (s *natPacketLinkState) invalidate(closeLink bool) {
	if s == nil {
		return
	}
	s.gate.Lock()
	s.epoch.Add(1)
	if closeLink {
		s.closed.Store(true)
	}
	s.gate.Unlock()
}

func (s *natPacketLinkState) withActive(epoch uint64, send func()) {
	if !s.gate.TryRLock() {
		return
	}
	defer s.gate.RUnlock() // +checklocksforce: TryRLock succeeded.
	if !s.closed.Load() && !s.paused.Load() && s.epoch.Load() == epoch {
		send()
	}
}

type natPolicyDispatcher struct {
	stack.NetworkDispatcher
	policy *NATPolicy
	state  *natPacketLinkState
}

func (d natPolicyDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	epoch := d.state.epoch.Load()
	d.state.withActive(epoch, func() {
		release := d.policy.tryRead()
		if release == nil {
			return
		}
		defer release()
		if d.policy.active == nil {
			return
		}
		// The pipe allocates a fresh buffer containing only wire bytes.
		// This context is derived solely from the private receiving end.
		pkt.PacketPolicy().Ingress = stack.PacketPolicyIngress{
			Attachment: d.state,
			Epoch:      epoch,
			Generation: d.policy.generation,
		}
		d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
	})
}

type natPolicyLink struct {
	stack.LinkEndpoint
	policy *NATPolicy
	state  *natPacketLinkState
}

func wrapNATPolicyLink(ep stack.LinkEndpoint, policy *NATPolicy, state *natPacketLinkState) stack.LinkEndpoint {
	if policy == nil {
		return ep
	}
	return &natPolicyLink{LinkEndpoint: ep, policy: policy, state: state}
}

func (e *natPolicyLink) Attach(d stack.NetworkDispatcher) {
	if d != nil {
		d = natPolicyDispatcher{NetworkDispatcher: d, policy: e.policy, state: e.state}
	}
	e.LinkEndpoint.Attach(d)
}

func (*natPolicyLink) SynchronousPolicyLink() {}

func (e *natPolicyLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	if pkts.Len() == 1 {
		e.writePacket(pkts.AsSlice()[0], pkts)
		return 1, nil
	}
	for _, pkt := range pkts.AsSlice() {
		e.writePacket(pkt, stack.PacketBufferList{})
	}
	return pkts.Len(), nil
}

func (e *natPolicyLink) writePacket(pkt *stack.PacketBuffer, direct stack.PacketBufferList) {
	metadata := pkt.PacketPolicy()
	var policyOutput stack.PacketPolicyOutput
	if metadata != nil {
		policyOutput = metadata.Output
	}
	if wire, ok := policyOutput.Provenance.(*natPacketLinkState); ok {
		// The FORWARD continuation already owns the epoch and accounts
		// for the original packet. Do not filter/charge its egress again.
		if wire == e.state {
			e.deliverOne(pkt, direct)
		}
		return
	}
	epoch := e.state.epoch.Load()
	if e.state.closed.Load() || e.state.paused.Load() {
		return
	}
	if output, ok := policyOutput.Provenance.(*natRelayOutput); ok {
		if output.policy != e.policy || !output.snapshot.allows(PolicyOutput, output.tuples) {
			return
		}
		if policyOutput.PayloadAccounted {
			e.state.withActive(epoch, func() { e.deliverOne(pkt, direct) })
			return
		}
		_, ipBytes, valid := policyPacketDetails(pkt)
		if valid {
			metadata.Output.Provenance = nil
			e.queuePacket(pkt, epoch, ipBytes, output.tuples...)
		}
		return
	}
	tuple, ipBytes, ok := policyPacketDetails(pkt)
	if !ok {
		return
	}
	if policyOutput.RelayTCP {
		e.state.withActive(epoch, func() {
			release, allowed := e.policy.Begin(PolicyOutput, tuple)
			if allowed {
				defer release()
				e.deliverOne(pkt, direct)
			}
		})
		return
	}
	// Raw writes, including dial-failure ICMP, must still pass OUTPUT
	// even when Netstack skips its OUTPUT hook.
	e.queuePacket(pkt, epoch, ipBytes, tuple)
}

func (e *natPolicyLink) queuePacket(pkt *stack.PacketBuffer, epoch uint64, size int, tuples ...PolicyTuple) {
	pkt.IncRef()
	e.policy.Enqueue(PolicyOutput, size, func() {
		e.state.withActive(epoch, func() { e.deliverOne(pkt, stack.PacketBufferList{}) })
	}, pkt.DecRef, tuples...)
}

func (e *natPolicyLink) deliverOne(pkt *stack.PacketBuffer, direct stack.PacketBufferList) {
	if direct.Len() == 1 {
		_, _ = e.LinkEndpoint.WritePackets(direct)
		return
	}
	var one stack.PacketBufferList
	one.PushBack(pkt)
	_, _ = e.LinkEndpoint.WritePackets(one)
}

type natRelayOutput struct {
	policy   *NATPolicy
	snapshot *CompiledPolicy
	tuples   []PolicyTuple // borrowed for the synchronous private write
}

// writeNATRelayDatagram runs only inside an eligible policy scheduler
// callback. Its pinned snapshot remains active until the synchronous private
// pipe write, including all locally generated fragments, returns.
func writeNATRelayDatagram(policy *NATPolicy, dst *gonet.UDPConn, payload []byte, tuples ...PolicyTuple) (int, error) {
	if len(tuples) == 0 || len(tuples) > 2 {
		return 0, ErrPolicyDenied
	}
	output := &policy.relayOutput
	*output = natRelayOutput{policy: policy, snapshot: policy.active, tuples: tuples}
	defer func() { *output = natRelayOutput{} }()
	return dst.WriteWithPacketPolicy(payload, stack.PacketPolicyOutput{
		Provenance:       output,
		PayloadAccounted: true,
	})
}

func policySocketAddrPort(addr net.Addr) netip.AddrPort {
	var endpoint netip.AddrPort
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr != nil && addr.Port >= 0 && addr.Port <= 65535 {
			endpoint = addr.AddrPort()
		}
	case *net.UDPAddr:
		if addr != nil && addr.Port >= 0 && addr.Port <= 65535 {
			endpoint = addr.AddrPort()
		}
	}
	if !endpoint.IsValid() {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(endpoint.Addr().Unmap(), endpoint.Port())
}

func policySocketTuple(proto uint8, source, destination net.Addr) PolicyTuple {
	return policyAddrTuple(proto, policySocketAddrPort(source), policySocketAddrPort(destination))
}

func policyAddrTuple(proto uint8, source, destination netip.AddrPort) PolicyTuple {
	source = netip.AddrPortFrom(source.Addr().Unmap().WithZone(""), source.Port())
	destination = netip.AddrPortFrom(destination.Addr().Unmap().WithZone(""), destination.Port())
	return natTuple(proto, source, destination)
}

func natTuple(proto uint8, source, destination netip.AddrPort) PolicyTuple {
	return PolicyTuple{
		IPv6:                 destination.Addr().Is6() || (!destination.IsValid() && source.Addr().Is6()),
		Protocol:             proto,
		ProtocolKnown:        true,
		Source:               source.Addr(),
		Destination:          destination.Addr(),
		SourcePort:           source.Port(),
		DestinationPort:      destination.Port(),
		SourcePortKnown:      source.IsValid() && source.Port() != 0,
		DestinationPortKnown: destination.IsValid() && destination.Port() != 0,
	}
}

func natGuestTuple(proto uint8, id stack.TransportEndpointID, dst netip.Addr) PolicyTuple {
	src, _ := netip.AddrFromSlice(id.RemoteAddress.AsSlice())
	// These are wire addresses from the peer stack, not Go socket addresses.
	// In particular, an IPv4-mapped address in an IPv6 packet is still IPv6
	// on this leg. The actual host socket leg can use a different family.
	return natTuple(proto, netip.AddrPortFrom(src, id.RemotePort), netip.AddrPortFrom(dst, id.LocalPort))
}

func (nf *NATForwarder) authorizeDNSFlow(proto uint8, id stack.TransportEndpointID, dst netip.Addr) (*dnsRequestPolicy, bool) {
	policy := nf.cfg.Policy
	if policy == nil {
		return nil, true
	}
	guest := natGuestTuple(proto, id, dst)
	if !policy.Allow(PolicyInput, guest) {
		return nil, false
	}
	return &dnsRequestPolicy{policy: policy, guest: guest}, true
}

func (nf *NATForwarder) dialNATTarget(network string, target netip.AddrPort, guest PolicyTuple) (net.Conn, PolicyTuple, error) {
	policy := nf.cfg.Policy
	if policy == nil {
		conn, err := nf.cfg.DialContext(nf.ctx, network, target.String())
		return conn, PolicyTuple{}, err
	}
	if !target.IsValid() || target.Port() == 0 || (network == "tcp" && !policy.HostDialAllowed(target)) {
		return nil, PolicyTuple{}, ErrPolicyDenied
	}
	// The resolved destination is already numeric, including gateway aliases.
	// Pin its family so there is no resolver or Happy Eyeballs fallback.
	if target.Addr().Is4() {
		network += "4"
	} else {
		network += "6"
	}
	proposal := policyAddrTuple(guest.Protocol, netip.AddrPort{}, target)
	conn, err := policy.Dial(nf.ctx, PolicyInput, func(ctx context.Context) (net.Conn, error) {
		return nf.cfg.DialContext(ctx, network, target.String())
	}, guest, proposal)
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		return nil, PolicyTuple{}, err
	}
	source := policySocketAddrPort(conn.LocalAddr())
	actual := policySocketAddrPort(conn.RemoteAddr())
	host := policyAddrTuple(guest.Protocol, source, actual)
	if !source.IsValid() || source.Addr().IsUnspecified() || source.Port() == 0 || actual != target ||
		!policy.Allow(PolicyInput, guest, host) {
		_ = conn.Close()
		return nil, PolicyTuple{}, ErrPolicyDenied
	}
	return conn, host, nil
}

func (nf *NATForwarder) startProtectedUDP(r *udp.ForwarderRequest, target netip.AddrPort, guest PolicyTuple) bool {
	policy := nf.cfg.Policy
	proposal := policyAddrTuple(guest.Protocol, netip.AddrPort{}, target)
	if !policy.Allow(PolicyInput, guest, proposal) || !tryAcquire(nf.udpDialSem) {
		return false
	}
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		releaseSlot(nf.udpDialSem)
		return false
	}
	guestConn := gonet.NewUDPConn(&wq, ep)
	// Pipe dispatch is synchronous. Keep host dials off it, including when
	// the packet arrived through an in-flight policy callback.
	if !nf.spawn(func() {
		hostConn, host, err := nf.dialNATTarget("udp", target, guest)
		if err != nil {
			_ = guestConn.Close()
			releaseSlot(nf.udpDialSem)
			nf.log.Debug("netbackend: dial host UDP target", "target", target, "error", err)
			return
		}
		widenUDPSend(hostConn)
		sess := &udpSession{guest: guestConn, host: hostConn, clock: newActivityClock(), policy: policy}
		nf.udpSessions.add(sess)
		releaseSlot(nf.udpDialSem)
		defer nf.udpSessions.remove(sess)
		relayDatagramPumps(nf.ctx, guestConn, hostConn, nf.udpIdle, sess.clock, policy, guest, host)
	}) {
		releaseSlot(nf.udpDialSem)
		_ = guestConn.Close()
		return false
	}
	return true
}

func relayPolicyTCP(ctx context.Context, policy *NATPolicy, requestChain PolicyChain, requestDst, requestSrc net.Conn, requestTuples ...PolicyTuple) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	replyChain := PolicyOutput
	if requestChain == PolicyOutput {
		replyChain = PolicyInput
	}
	replyTuples := make([]PolicyTuple, len(requestTuples))
	for i, tuple := range requestTuples {
		replyTuples[i] = tuple.Reverse()
	}
	relayStreamPair(ctx, requestDst, requestSrc, func(dst, src net.Conn) error {
		return policy.CopyStream(ctx, requestChain, dst, src, requestTuples...)
	}, func(dst, src net.Conn) error {
		return policy.CopyStream(ctx, replyChain, dst, src, replyTuples...)
	}, cancel)
}
