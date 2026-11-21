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
	return h.allows(PolicyInput, pkt)
}

func (h natPolicyHooks) CheckForward(pkt *stack.PacketBuffer, _ *stack.Route, _ tcpip.NICID, _ stack.AddressFamily) bool {
	return h.allows(PolicyForward, pkt)
}

func (h natPolicyHooks) CheckOutput(pkt *stack.PacketBuffer, _ *stack.Route, _ tcpip.NICID, _ stack.AddressFamily) bool {
	return h.allows(PolicyOutput, pkt)
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

type natPolicyLink struct {
	stack.LinkEndpoint
	policy *NATPolicy
	state  *natPacketLinkState
	chain  PolicyChain
}

func wrapNATPolicyLink(ep stack.LinkEndpoint, policy *NATPolicy, chain PolicyChain, state *natPacketLinkState) stack.LinkEndpoint {
	if policy == nil {
		return ep
	}
	return &natPolicyLink{LinkEndpoint: ep, policy: policy, state: state, chain: chain}
}

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
	epoch := e.state.epoch.Load()
	if e.state.closed.Load() || e.state.paused.Load() {
		return
	}
	tuple, ipBytes, socketBacked, ok := policyPacketDetails(pkt)
	if !ok {
		return
	}
	if socketBacked || !tuple.ProtocolKnown {
		// Socket payload is charged at its relay. An unresolved fragment
		// could belong to either accounting path; pass it only if that
		// direction is unlimited. The peer hooks still filter its tuple.
		e.state.withActive(epoch, func() {
			var release func()
			var allowed bool
			if e.chain == PolicyInput {
				// Synchronous pipe delivery enters the peer INPUT matcher below.
				release, allowed = e.policy.beginUnshaped(e.chain, !tuple.ProtocolKnown)
			} else {
				release, allowed = e.policy.beginUnshaped(e.chain, !tuple.ProtocolKnown, tuple)
			}
			if !allowed {
				return
			}
			defer release()
			if direct.Len() == 1 {
				_, _ = e.LinkEndpoint.WritePackets(direct)
			} else {
				e.deliver(pkt)
			}
		})
		return
	}
	// The queue owns the reference on both acceptance and rejection. Its
	// callback writes directly to the pipe, not back into this wrapper. Raw
	// host writes (including dial-failure ICMP) also get checked here, even
	// when Netstack skips the OUTPUT hook.
	pkt.IncRef()
	e.policy.Enqueue(e.chain, ipBytes, func() {
		e.state.withActive(epoch, func() { e.deliver(pkt) })
	}, pkt.DecRef, tuple)
}

func (e *natPolicyLink) deliver(pkt *stack.PacketBuffer) {
	var one stack.PacketBufferList
	one.PushBack(pkt)
	_, _ = e.LinkEndpoint.WritePackets(one)
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
		sess := &udpSession{guest: guestConn, host: hostConn, clock: newActivityClock()}
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
