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
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	// wgTUNName is the interface name that channelTUN reports.
	wgTUNName = "gvx-wg0"

	// wgTUNBatchSize is the largest packet count that one Read call returns.
	// A batch lets the WireGuard encryption workers run in parallel.
	wgTUNBatchSize = 16
)

// errInvalidIPPacket reports a packet that is not a complete IPv4 or IPv6 packet.
var errInvalidIPPacket = errors.New("netbackend: packet is not IPv4 or IPv6")

// channelTUN implements tun.Device on top of a gVisor channel.Endpoint.
// It has no file descriptor, no OS interface, and no kernel driver.
//
// Packets flow in two directions. Netstack writes outbound IP packets into the
// channel queue, and Read returns them to wireguard-go for encryption.
// wireguard-go decrypts inbound packets and Write injects them into Netstack.
//
// channelTUN does not own the channel.Endpoint. The creator closes the
// endpoint after channelTUN.Close returns.
type channelTUN struct {
	ep *channel.Endpoint

	// ctx ends when Close runs. It unblocks a pending Read.
	ctx    context.Context
	cancel context.CancelFunc

	// events carries the MTU events. wireguard-go ranges over it, so Close
	// must close it to stop the event goroutine.
	events    chan tun.Event
	closeOnce sync.Once

	// mu orders notifyMTU and Close, so that notifyMTU never sends on the
	// closed events channel.
	mu     sync.Mutex
	closed bool
}

var _ tun.Device = (*channelTUN)(nil)

func newChannelTUN(ep *channel.Endpoint) *channelTUN {
	ctx, cancel := context.WithCancel(context.Background())
	return &channelTUN{
		ep:     ep,
		ctx:    ctx,
		cancel: cancel,
		events: make(chan tun.Event, 1),
	}
}

// notifyMTU queues one MTU event, so that wireguard-go reads the new MTU. A
// queued event already covers a second change.
func (t *channelTUN) notifyMTU() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return
	}
	select {
	case t.events <- tun.EventMTUUpdate:
	default:
	}
}

// File returns nil because the device has no file descriptor.
func (t *channelTUN) File() *os.File { return nil }

// Name returns the fixed interface name.
func (t *channelTUN) Name() (string, error) { return wgTUNName, nil }

// MTU returns the current MTU of the channel endpoint.
func (t *channelTUN) MTU() (int, error) { return int(t.ep.MTU()), nil }

// Events returns the channel of MTU events. Close closes it.
func (t *channelTUN) Events() <-chan tun.Event { return t.events }

// BatchSize returns the largest packet count of one Read or Write call.
func (t *channelTUN) BatchSize() int { return wgTUNBatchSize }

// Read blocks until Netstack emits at least one outbound packet. It copies up
// to len(bufs) packets into bufs[i][offset:] and records each length in sizes.
// A packet that does not fit in its buffer is dropped, as a kernel TUN device
// would drop it.
func (t *channelTUN) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, fmt.Errorf("netbackend: tun read needs sizes for %d buffers, got %d", len(bufs), len(sizes))
	}
	for {
		if t.ctx.Err() != nil {
			return 0, os.ErrClosed
		}
		pkt := t.ep.ReadContext(t.ctx)
		if pkt == nil {
			// The context ended or the channel queue closed.
			return 0, os.ErrClosed
		}
		n := 0
		for pkt != nil {
			if size, ok := copyPacket(pkt, bufs[n][offset:]); ok {
				sizes[n] = size
				n++
			}
			pkt.DecRef()
			if n == len(bufs) {
				break
			}
			pkt = t.ep.Read()
		}
		if n > 0 {
			return n, nil
		}
	}
}

// copyPacket copies the bytes of pkt into dst. It reports false when dst is too small.
func copyPacket(pkt *stack.PacketBuffer, dst []byte) (int, bool) {
	if pkt.Size() > len(dst) {
		return 0, false
	}
	n := 0
	for _, s := range pkt.AsSlices() {
		n += copy(dst[n:], s)
	}
	return n, true
}

// Write injects each packet bufs[i][offset:] into Netstack as an inbound
// packet. It selects the network protocol from the IP version nibble. Write
// skips an invalid packet, injects the valid ones, and reports the first
// invalid packet in the returned error.
func (t *channelTUN) Write(bufs [][]byte, offset int) (int, error) {
	var firstErr error
	n := 0
	for _, b := range bufs {
		if t.ctx.Err() != nil {
			return n, os.ErrClosed
		}
		if offset > len(b) {
			return n, fmt.Errorf("netbackend: tun write offset %d exceeds buffer length %d", offset, len(b))
		}
		packet := b[offset:]
		proto, err := ipPacketProtocol(packet)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		t.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
		n++
	}
	return n, firstErr
}

// ipPacketProtocol returns the Netstack protocol number of an IP packet.
func ipPacketProtocol(packet []byte) (tcpip.NetworkProtocolNumber, error) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return 0, fmt.Errorf("%w: IPv4 packet has %d bytes", errInvalidIPPacket, len(packet))
		}
		return ipv4.ProtocolNumber, nil
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return 0, fmt.Errorf("%w: IPv6 packet has %d bytes", errInvalidIPPacket, len(packet))
		}
		return ipv6.ProtocolNumber, nil
	default:
		return 0, fmt.Errorf("%w: IP version %d", errInvalidIPPacket, header.IPVersion(packet))
	}
}

// Close unblocks Read and closes the event channel. It is safe to call more
// than once. It does not close the channel endpoint.
func (t *channelTUN) Close() error {
	t.closeOnce.Do(func() {
		t.cancel()
		t.mu.Lock()
		t.closed = true
		close(t.events)
		t.mu.Unlock()
	})
	return nil
}
