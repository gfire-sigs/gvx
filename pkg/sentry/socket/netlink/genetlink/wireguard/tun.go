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

package wireguard

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
	// queueSize is the length of the outbound packet queue of a link.
	queueSize = 512

	// tunBatchSize is the largest packet count of one Read call. A batch lets
	// the encryption workers of wireguard-go run in parallel.
	tunBatchSize = 16
)

// errInvalidIPPacket reports a packet that is not a whole IPv4 or IPv6 packet.
var errInvalidIPPacket = errors.New("wireguard: packet is not IPv4 or IPv6")

// tunDevice implements tun.Device on top of a channel.Endpoint. It has no
// file descriptor. The channel endpoint belongs to the link endpoint.
type tunDevice struct {
	ep   *channel.Endpoint
	name string

	// ctx ends when Close runs. It unblocks a pending Read.
	ctx    context.Context
	cancel context.CancelFunc

	// events carries MTU changes. Close closes it, which stops the event
	// goroutine of wireguard-go.
	mu     sync.Mutex
	events chan tun.Event
	closed bool
}

var _ tun.Device = (*tunDevice)(nil)

func newTUN(ep *channel.Endpoint, name string) *tunDevice {
	ctx, cancel := context.WithCancel(context.Background())
	return &tunDevice{ep: ep, name: name, ctx: ctx, cancel: cancel, events: make(chan tun.Event, 1)}
}

// notifyMTU queues one MTU event. A queued event already covers a second change.
func (t *tunDevice) notifyMTU() {
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
func (t *tunDevice) File() *os.File { return nil }

// Name returns the name that the link had at creation.
func (t *tunDevice) Name() (string, error) { return t.name, nil }

// MTU returns the current MTU of the link.
func (t *tunDevice) MTU() (int, error) { return int(t.ep.MTU()), nil }

// Events returns the channel of MTU events.
func (t *tunDevice) Events() <-chan tun.Event { return t.events }

// BatchSize returns the largest packet count of one Read or Write call.
func (t *tunDevice) BatchSize() int { return tunBatchSize }

// Read blocks until the stack sends at least one packet to the link. It
// copies up to len(bufs) packets into bufs[i][offset:] and stores each length
// in sizes. A packet that does not fit its buffer is dropped.
func (t *tunDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, fmt.Errorf("wireguard: tun read needs sizes for %d buffers, got %d", len(bufs), len(sizes))
	}
	for {
		pkt := t.ep.ReadContext(t.ctx)
		if pkt == nil {
			// The context ended or the queue closed.
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

// copyPacket copies the bytes of pkt into dst. It reports false when dst is
// too small.
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

// Write injects each packet bufs[i][offset:] into the stack as an inbound
// packet of the link. It skips an invalid packet and reports the first one in
// the returned error.
func (t *tunDevice) Write(bufs [][]byte, offset int) (int, error) {
	var firstErr error
	n := 0
	for _, b := range bufs {
		if t.ctx.Err() != nil {
			return n, os.ErrClosed
		}
		if offset > len(b) {
			return n, fmt.Errorf("wireguard: tun write offset %d exceeds buffer length %d", offset, len(b))
		}
		packet := b[offset:]
		proto, err := ipPacketProtocol(packet)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
		t.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
		n++
	}
	return n, firstErr
}

// ipPacketProtocol returns the network protocol of an IP packet from its
// version nibble.
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
func (t *tunDevice) Close() error {
	t.cancel()
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.events)
	}
	return nil
}
