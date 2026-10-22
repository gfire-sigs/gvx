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
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// errMarkUnsupported reports a non-zero socket mark request. Only Linux
// supports SO_MARK, and the pre-bound socket runs on Windows and macOS.
var errMarkUnsupported = errors.New("netbackend: socket marks are not supported on the pre-bound WireGuard socket")

// pastDeadline is a read deadline that already expired. Setting it makes a
// blocked read return at once without closing the socket.
var pastDeadline = time.Unix(1, 0)

// preboundBind implements conn.Bind over one host UDP socket that the caller
// opened before hostlockdown.Apply. It never opens, rebinds, or duplicates a
// socket, because lockdown denies every new socket.
//
// Ownership: the caller of newPreboundBind owns the socket and closes it.
// Close stops the receive function by setting an expired read deadline. It
// leaves the socket open, so Open can run again on the same socket.
type preboundBind struct {
	sock DatagramSocket

	mu sync.Mutex
	// session is the active Open generation, or nil while the bind is closed.
	session *bindSession
}

// bindSession marks one Open generation. A receive function reads closed to
// tell a Close request from a socket error.
type bindSession struct {
	closed atomic.Bool
}

var _ conn.Bind = (*preboundBind)(nil)

// newPreboundBind returns a Bind over sock. The socket must stay open until
// the Device that uses the Bind is closed.
func newPreboundBind(sock net.PacketConn) (*preboundBind, error) {
	udp, ok := sock.(DatagramSocket)
	if !ok {
		return nil, fmt.Errorf("netbackend: WireGuard socket is %T, want DatagramSocket", sock)
	}
	return &preboundBind{sock: udp}, nil
}

// Open starts the receive function on the pre-bound socket. The port argument
// is only a request and the Bind ignores it: the returned port is the real
// local port of the pre-bound socket.
func (b *preboundBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	local, ok := b.sock.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("netbackend: WireGuard socket local address is %T, want *net.UDPAddr", b.sock.LocalAddr())
	}
	// Close left an expired deadline. Clear it before any reader starts.
	if err := b.sock.SetReadDeadline(time.Time{}); err != nil {
		return nil, 0, fmt.Errorf("netbackend: clear WireGuard socket read deadline: %w", err)
	}
	s := &bindSession{}
	b.session = s
	return []conn.ReceiveFunc{func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		return b.receive(s, bufs, sizes, eps)
	}}, uint16(local.Port), nil
}

// receive reads one datagram. It runs on the single goroutine that wireguard-go
// starts for the receive function.
func (b *preboundBind) receive(s *bindSession, bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	if len(bufs) == 0 || len(sizes) < len(bufs) || len(eps) < len(bufs) {
		return 0, fmt.Errorf("netbackend: receive needs %d sizes and endpoints, got %d and %d", len(bufs), len(sizes), len(eps))
	}
	n, from, err := b.sock.ReadFromUDPAddrPort(bufs[0])
	if err != nil {
		if s.closed.Load() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	sizes[0] = n
	if n == 0 {
		return 1, nil
	}
	// A dual-stack socket reports IPv4 peers as IPv4-mapped IPv6 addresses.
	// Unmap them so that the endpoint equals the configured peer address.
	eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
	return 1, nil
}

// Close stops the receive function and keeps the socket open. Every receive
// function returns net.ErrClosed afterward. Close succeeds when the Bind is
// already closed.
func (b *preboundBind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session == nil {
		return nil
	}
	b.session.closed.Store(true)
	b.session = nil
	if err := b.sock.SetReadDeadline(pastDeadline); err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("netbackend: stop WireGuard socket reader: %w", err)
	}
	return nil
}

// SetMark accepts only the zero mark. Linux alone supports SO_MARK.
func (b *preboundBind) SetMark(mark uint32) error {
	if mark != 0 {
		return errMarkUnsupported
	}
	return nil
}

// Send writes each buffer as one datagram to ep through the pre-bound socket.
func (b *preboundBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	open := b.session != nil
	b.mu.Unlock()
	if !open {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := b.sock.WriteToUDPAddrPort(buf, dst.AddrPort); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses "ip:port" or "[ipv6]:port". Host names are invalid
// because DNS lookups run before lockdown, in NewWireGuardEndpoint.
func (b *preboundBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("netbackend: parse WireGuard endpoint %q: %w", s, err)
	}
	return &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

// BatchSize returns 1. Windows and macOS have no batched UDP receive call.
func (b *preboundBind) BatchSize() int { return 1 }
