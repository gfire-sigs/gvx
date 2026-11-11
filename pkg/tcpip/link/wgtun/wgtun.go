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

// Package wgtun adapts a Netstack channel.Endpoint to the tun.Device interface
// of wireguard-go and provides endpoint and packet conversion helpers.
package wgtun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
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
	// DefaultQueueSize is the default outbound packet queue capacity of a link.
	DefaultQueueSize = 512

	// BatchSize is the maximum packet count of one Read or Write call.
	// A batch lets the encryption workers of wireguard-go run in parallel.
	BatchSize = 16
)

// ErrInvalidIPPacket reports a packet that is not a complete IPv4 or IPv6 packet.
var ErrInvalidIPPacket = errors.New("wgtun: packet is not IPv4 or IPv6")

// Device implements tun.Device on top of a Netstack channel.Endpoint.
// It has no file descriptor, no OS interface, and no kernel driver.
//
// Netstack writes outbound IP packets into the channel queue, and Read returns
// them to wireguard-go for encryption. wireguard-go decrypts inbound packets
// and Write injects them into Netstack. Device does not own the channel.Endpoint;
// the caller closes the endpoint after Device.Close returns.
type Device struct {
	ep   *channel.Endpoint
	name string

	// ctx ends when Close runs and unblocks a pending Read.
	ctx    context.Context
	cancel context.CancelFunc

	// events carries MTU updates. wireguard-go ranges over it, so Close
	// closes the channel to stop the event goroutine.
	events    chan tun.Event
	closeOnce sync.Once

	// mu orders NotifyMTU and Close so NotifyMTU never sends on a closed channel.
	mu     sync.Mutex
	closed bool
}

var _ tun.Device = (*Device)(nil)

// New creates a Device that reads and writes packets on ep and reports name.
func New(ep *channel.Endpoint, name string) *Device {
	ctx, cancel := context.WithCancel(context.Background())
	return &Device{
		ep:     ep,
		name:   name,
		ctx:    ctx,
		cancel: cancel,
		events: make(chan tun.Event, 1),
	}
}

// Endpoint returns the underlying Netstack channel.Endpoint.
func (d *Device) Endpoint() *channel.Endpoint { return d.ep }

// NotifyMTU queues one MTU update event so wireguard-go reads the new MTU.
// A queued event already covers a second change.
func (d *Device) NotifyMTU() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return
	}
	select {
	case d.events <- tun.EventMTUUpdate:
	default:
	}
}

// File returns nil because the device has no file descriptor.
func (d *Device) File() *os.File { return nil }

// Name returns the interface name configured at creation.
func (d *Device) Name() (string, error) { return d.name, nil }

// MTU returns the current MTU of the channel endpoint.
func (d *Device) MTU() (int, error) { return int(d.ep.MTU()), nil }

// Events returns the channel of MTU update events. Close closes it.
func (d *Device) Events() <-chan tun.Event { return d.events }

// BatchSize returns the maximum packet count of one Read or Write call.
func (d *Device) BatchSize() int { return BatchSize }

// Read blocks until Netstack emits at least one outbound packet. It copies up
// to len(bufs) packets into bufs[i][offset:] and records each length in sizes.
// Read drops any packet that exceeds its destination buffer.
func (d *Device) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) {
		return 0, fmt.Errorf("wgtun: tun read needs sizes for %d buffers, got %d", len(bufs), len(sizes))
	}
	for {
		if d.ctx.Err() != nil {
			return 0, os.ErrClosed
		}
		pkt := d.ep.ReadContext(d.ctx)
		if pkt == nil {
			return 0, os.ErrClosed
		}
		n := 0
		for pkt != nil {
			if offset <= len(bufs[n]) {
				if size, ok := CopyPacket(pkt, bufs[n][offset:]); ok {
					sizes[n] = size
					n++
				}
			}
			pkt.DecRef()
			if n == len(bufs) {
				break
			}
			pkt = d.ep.Read()
		}
		if n > 0 {
			return n, nil
		}
	}
}

// CopyPacket copies the bytes of pkt into dst. It returns false when dst is too small.
func CopyPacket(pkt *stack.PacketBuffer, dst []byte) (int, bool) {
	if pkt.Size() > len(dst) {
		return 0, false
	}
	n := 0
	for _, s := range pkt.AsSlices() {
		n += copy(dst[n:], s)
	}
	return n, true
}

// Write injects each packet bufs[i][offset:] into Netstack as an inbound packet.
// It selects the network protocol from the IP version nibble, skips invalid
// packets, and returns the first validation error.
func (d *Device) Write(bufs [][]byte, offset int) (int, error) {
	var firstErr error
	n := 0
	for _, b := range bufs {
		if d.ctx.Err() != nil {
			return n, os.ErrClosed
		}
		if offset > len(b) {
			return n, fmt.Errorf("wgtun: tun write offset %d exceeds buffer length %d", offset, len(b))
		}
		packet := b[offset:]
		proto, err := IPPacketProtocol(packet)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
			Payload: buffer.MakeWithData(packet),
		})
		d.ep.InjectInbound(proto, pkt)
		pkt.DecRef()
		n++
	}
	return n, firstErr
}

// IPPacketProtocol returns the Netstack protocol number of an IPv4 or IPv6 packet.
func IPPacketProtocol(packet []byte) (tcpip.NetworkProtocolNumber, error) {
	switch header.IPVersion(packet) {
	case header.IPv4Version:
		if len(packet) < header.IPv4MinimumSize {
			return 0, fmt.Errorf("%w: IPv4 packet has %d bytes", ErrInvalidIPPacket, len(packet))
		}
		return ipv4.ProtocolNumber, nil
	case header.IPv6Version:
		if len(packet) < header.IPv6MinimumSize {
			return 0, fmt.Errorf("%w: IPv6 packet has %d bytes", ErrInvalidIPPacket, len(packet))
		}
		return ipv6.ProtocolNumber, nil
	default:
		return 0, fmt.Errorf("%w: IP version %d", ErrInvalidIPPacket, header.IPVersion(packet))
	}
}

// Close unblocks Read and closes the event channel. It is safe to call more
// than once and does not close the underlying channel endpoint.
func (d *Device) Close() error {
	d.closeOnce.Do(func() {
		d.cancel()
		d.mu.Lock()
		d.closed = true
		close(d.events)
		d.mu.Unlock()
	})
	return nil
}

// NewEndpoint returns a WireGuard StdNetEndpoint with an unmapped IP address.
func NewEndpoint(ap netip.AddrPort) *conn.StdNetEndpoint {
	return &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}
}

// ParseEndpoint parses "ip:port" or "[ipv6]:port" into a WireGuard endpoint.
func ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("wgtun: parse endpoint %q: %w", s, err)
	}
	return NewEndpoint(ap), nil
}
