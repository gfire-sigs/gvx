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

func (g *natPacketEpoch) Enabled() bool { return g.link.shaper.Enabled(BandwidthTX) }

func (g *natPacketEpoch) Enqueue(pkt *stack.PacketBuffer, bytes int, deliver func(*stack.PacketBuffer), release func()) {
	g.enqueue(BandwidthTX, pkt, bytes, deliver, release)
}

func (g *natPacketEpoch) enqueue(dir BandwidthDirection, pkt *stack.PacketBuffer, bytes int, deliver func(*stack.PacketBuffer), release func()) {
	pkt.IncRef()
	g.link.shaper.EnqueuePacket(g.ctx, dir, pkt.MemSize(), bytes, func() (int, error) {
		if g.Run(func() { deliver(pkt) }) {
			return bytes, nil
		}
		return 0, nil
	}, func() {
		pkt.DecRef()
		if release != nil {
			release()
		}
	})
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
		epoch.Run(func() { n, err = l.LinkEndpoint.WritePackets(pkts) })
		return n, err
	}
	for _, pkt := range pkts.AsSlice() {
		if pkt.Owner == l.relay || pkt.NetworkProtocolNumber != header.IPv4ProtocolNumber && pkt.NetworkProtocolNumber != header.IPv6ProtocolNumber {
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
	if nf.cfg.Bandwidth == nil {
		return base
	}
	link := &natBandwidthLink{LinkEndpoint: base, ctx: nf.ctx, paused: nf.paused, shaper: nf.cfg.Bandwidth, relay: &nf.relayOwner}
	if !nf.paused.Load() {
		link.start()
	}
	if old := nf.packetLink.Swap(link); old != nil {
		old.stop(true)
	}
	return link
}
