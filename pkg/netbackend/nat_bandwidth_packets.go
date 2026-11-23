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
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// natBandwidthLink wraps only the host end of the NAT pipe. It never writes
// to a native socket from a shaper callback.
type natBandwidthLink struct {
	stack.LinkEndpoint
	ctx    context.Context
	paused *atomic.Bool
	shaper *BandwidthShaper
	relay  *stack.NATRelayOwner
	nf     *NATForwarder

	// gate drains callbacks before pause, rebind, or close. It must not
	// nest inside the forwarder's mutex: pipe delivery can enter a relay.
	gate    sync.RWMutex
	retired bool
	current atomic.Pointer[natPacketEpoch]
}

type natPacketEpoch struct {
	link   *natBandwidthLink
	ctx    context.Context
	cancel context.CancelFunc
	input  *stack.NATPacketInput
}

func (l *natBandwidthLink) start() {
	l.gate.Lock()
	defer l.gate.Unlock()
	if l.retired || l.ctx.Err() != nil || l.current.Load() != nil {
		return
	}
	ctx, cancel := context.WithCancel(l.ctx)
	epoch := &natPacketEpoch{link: l, ctx: ctx, cancel: cancel}
	epoch.input = stack.NewNATPacketInput(epoch, l.relay)
	l.current.Store(epoch)
}

func (l *natBandwidthLink) stop(retire bool) {
	l.gate.Lock()
	defer l.gate.Unlock()
	if retire {
		l.retired = true
	}
	if epoch := l.current.Swap(nil); epoch != nil {
		epoch.cancel()
		epoch.input.RetireReassembly()
	}
}

func (g *natPacketEpoch) Run(deliver func()) bool {
	l := g.link
	// A synchronous pipe write can produce a second write on this link.
	// Drop it instead of waiting behind a pause or close on this same gate.
	if !l.gate.TryRLock() {
		return false
	}
	defer l.gate.RUnlock() // +checklocksforce: TryRLock succeeds on this path.
	if l.current.Load() != g || l.paused.Load() || g.ctx.Err() != nil {
		return false
	}
	deliver()
	return true
}

func (g *natPacketEpoch) Enabled() bool {
	return g.link.nf.cfg.Policy != nil || g.link.shaper.Enabled(BandwidthTX)
}

func (g *natPacketEpoch) Allows(pkt *stack.PacketBuffer) bool {
	return g.link.allowsPacket(pkt, BandwidthTX)
}

func (g *natPacketEpoch) Enqueue(pkt *stack.PacketBuffer, bytes int, deliver func(*stack.PacketBuffer), release func()) {
	g.enqueue(BandwidthTX, pkt, bytes, deliver, release)
}

func (g *natPacketEpoch) enqueue(dir BandwidthDirection, pkt *stack.PacketBuffer, bytes int, deliver func(*stack.PacketBuffer), release func()) {
	if !g.link.shaper.Enabled(dir) {
		g.Run(func() {
			if g.link.allowsPacket(pkt, dir) {
				deliver(pkt)
			}
		})
		if release != nil {
			release()
		}
		return
	}
	policy := g.link.nf.cfg.Policy
	ctx := g.ctx
	var untrack func()
	var flow NATPolicyFlow
	if policy != nil {
		var ok bool
		flow, ok = g.link.packetFlow(pkt, dir)
		if ok {
			// Track even before activation so the first policy can revoke queued work.
			ctx, untrack, ok = policy.Track(ctx, flow)
		}
		if !ok {
			if release != nil {
				release()
			}
			return
		}
	}
	pkt.IncRef()
	g.link.shaper.EnqueuePacket(ctx, dir, pkt.MemSize(), bytes, func() (int, error) {
		var handedOff bool
		g.Run(func() {
			// Test cancellation last so a later allow cannot revive this packet.
			if policy == nil || (policy.Allows(flow) && ctx.Err() == nil) {
				deliver(pkt)
				handedOff = true
			}
		})
		if handedOff {
			return bytes, nil
		}
		return 0, nil
	}, func() {
		if untrack != nil {
			untrack()
		}
		pkt.DecRef()
		if release != nil {
			release()
		}
	})
}

func (l *natBandwidthLink) packetFlow(pkt *stack.PacketBuffer, dir BandwidthDirection) (NATPolicyFlow, bool) {
	if dir == BandwidthRX {
		return natPacketPolicyFlow(pkt, NATPolicyIngress)
	}
	flow, ok := natPacketPolicyFlow(pkt, NATPolicyEgress)
	if !ok {
		return NATPolicyFlow{}, false
	}
	switch tcpip.TransportProtocolNumber(flow.Protocol) {
	case header.ICMPv4ProtocolNumber, header.ICMPv6ProtocolNumber:
		if flow.Remote.Unmap() != natVirtualDNSIP {
			_, err := l.nf.resolveOutboundTarget(0, flow.Remote, 0)
			return flow, err == nil
		}
	}
	return flow, true
}

func (l *natBandwidthLink) allowsPacket(pkt *stack.PacketBuffer, dir BandwidthDirection) bool {
	policy := l.nf.cfg.Policy
	if policy == nil {
		return true
	}
	flow, ok := l.packetFlow(pkt, dir)
	return ok && policy.Allows(flow)
}

func (l *natBandwidthLink) packetOnly(pkt *stack.PacketBuffer) bool {
	// The pipe strips guest metadata. Only the private stack marks output
	// from an admitted relay or traffic already admitted for forwarding.
	return pkt.Owner != l.relay && (pkt.NetworkProtocolNumber == header.IPv4ProtocolNumber ||
		pkt.NetworkProtocolNumber == header.IPv6ProtocolNumber)
}

type natBandwidthDispatcher struct {
	stack.NetworkDispatcher
	link *natBandwidthLink
}

func (d natBandwidthDispatcher) DeliverNetworkPacket(protocol tcpip.NetworkProtocolNumber, pkt *stack.PacketBuffer) {
	epoch := d.link.current.Load()
	if epoch == nil {
		return
	}
	epoch.Run(func() {
		if protocol == header.IPv4ProtocolNumber || protocol == header.IPv6ProtocolNumber {
			pkt.Owner = epoch.input
		}
		d.NetworkDispatcher.DeliverNetworkPacket(protocol, pkt)
	})
}

func (l *natBandwidthLink) Attach(d stack.NetworkDispatcher) {
	if d != nil {
		d = natBandwidthDispatcher{NetworkDispatcher: d, link: l}
	}
	l.LinkEndpoint.Attach(d)
}

func (l *natBandwidthLink) WritePackets(pkts stack.PacketBufferList) (int, tcpip.Error) {
	epoch := l.current.Load()
	if epoch == nil || l.paused.Load() {
		return pkts.Len(), nil
	}
	if !l.shaper.Enabled(BandwidthRX) {
		n, err := pkts.Len(), tcpip.Error(nil)
		epoch.Run(func() {
			if l.nf.cfg.Policy == nil {
				n, err = l.LinkEndpoint.WritePackets(pkts)
				return
			}
			var filtered stack.PacketBufferList
			dropped := 0
			for i, pkt := range pkts.AsSlice() {
				if l.packetOnly(pkt) && !l.allowsPacket(pkt, BandwidthRX) {
					if dropped == 0 {
						for _, prior := range pkts.AsSlice()[:i] {
							filtered.PushBack(prior)
						}
					}
					dropped++
				} else if dropped != 0 {
					filtered.PushBack(pkt)
				}
			}
			switch {
			case dropped == 0:
				n, err = l.LinkEndpoint.WritePackets(pkts)
			case filtered.Len() != 0:
				n, err = l.LinkEndpoint.WritePackets(filtered)
				n += dropped
			}
		})
		return n, err
	}
	for _, pkt := range pkts.AsSlice() {
		if !l.packetOnly(pkt) {
			epoch.Run(func() { l.writeOne(pkt) })
			continue
		}
		epoch.enqueue(BandwidthRX, pkt, pkt.Size(), l.writeOne, nil)
	}
	return pkts.Len(), nil
}

func (l *natBandwidthLink) writeOne(pkt *stack.PacketBuffer) {
	var one stack.PacketBufferList
	one.PushBack(pkt)
	// The in-memory pipe cannot return a write error.
	_, _ = l.LinkEndpoint.WritePackets(one)
}

func (nf *NATForwarder) hostLink(ep stack.LinkEndpoint) stack.LinkEndpoint {
	base := pausableLink{ep, nf.paused}
	if nf.cfg.Bandwidth == nil && nf.cfg.Policy == nil {
		return base
	}
	link := &natBandwidthLink{LinkEndpoint: base, ctx: nf.ctx, paused: nf.paused, shaper: nf.cfg.Bandwidth, relay: &nf.relayOwner, nf: nf}
	if !nf.paused.Load() {
		link.start()
	}
	if old := nf.packetLink.Swap(link); old != nil {
		old.stop(true)
	}
	return link
}
