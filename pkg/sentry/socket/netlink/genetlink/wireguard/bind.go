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
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"

	"golang.zx2c4.com/wireguard/conn"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
	"z.gfire.dev/gvx/pkg/waiter"
)

// portRetries is the count of retries to find one free port for the IPv4 and
// the IPv6 UDP endpoint when the device asks for any port. It is the limit of
// wg_socket_init.
const portRetries = 100

// bindError carries the errno of a failed UDP bind, so the netlink handler
// answers with it, and the error of the stack, so a link-up request answers
// with it.
type bindError struct {
	err  *syserr.Error
	terr tcpip.Error
}

func (e *bindError) Error() string { return "wireguard: " + e.err.String() }

// newBindError returns the bindError of an error of the stack.
func newBindError(terr tcpip.Error) *bindError {
	return &bindError{err: syserr.TranslateNetstackError(terr), terr: terr}
}

// errBirthplaceEnded is the error of a device whose creating network
// namespace ended. Linux answers ENONET, because the device then has no
// namespace for its sockets.
var errBirthplaceEnded = &bindError{err: syserr.ErrNoNet, terr: &tcpip.ErrNoNet{}}

// netBind implements conn.Bind with UDP endpoints of a network stack. The
// stack is the network stack of the namespace where the link was created, so
// the encrypted packets leave through the routes of that namespace, also after
// the link moves to another namespace.
//
// The bind keeps the state that Linux keeps in struct wg_device for the
// sockets: the port (incoming_port) and the mark (fwmark). wireguard-go never
// chooses the port. It asks the bind to open, and the bind opens the stored
// port. The stored port survives a close, so a device that comes up again
// listens on the port that it had before, as in wg_open.
// +stateify savable
type netBind struct {
	stack *stack.Stack

	mu      sync.Mutex   `state:"nosave"`
	session *bindSession `state:"nosave"`
	// pending holds sockets that the next Open takes. A change of the port
	// opens them first, so that a busy port fails before the device closes
	// its sockets.
	pending *bindSession `state:"nosave"`
	// incoming is the port that the next Open binds. It is 0 for a random
	// port until the first Open. After an Open it is the port of that Open.
	incoming uint16
	// mark is the packet mark of the sockets.
	mark uint32
	// gone is true after the creating namespace ended. No socket opens then.
	gone bool
}

func (b *netBind) closePending() {
	b.mu.Lock()
	p := b.pending
	b.pending = nil
	b.mu.Unlock()
	if p != nil {
		p.close()
	}
}

// bindSession is one generation of UDP endpoints.
type bindSession struct {
	v4     *gonet.UDPConn
	v6     *gonet.UDPConn // nil when the stack has no IPv6
	eps    []tcpip.Endpoint
	port   uint16
	closed atomic.Bool
}

var _ conn.Bind = (*netBind)(nil)

func newBind(s *stack.Stack) *netBind {
	return &netBind{stack: s}
}

// Open takes the pending sockets, or binds one UDP endpoint for each IP family
// to the stored port, and returns one receive function for each endpoint. It
// ignores its argument, because the bind owns the port. A stored port of 0
// selects a free port. Open stores and returns the port.
func (b *netBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	if b.gone {
		return nil, 0, errBirthplaceEnded
	}
	s := b.pending
	b.pending = nil
	if s == nil {
		var err error
		if s, err = b.openLocked(b.incoming); err != nil {
			return nil, 0, err
		}
	}
	b.session = s
	b.incoming = s.port
	fns := []conn.ReceiveFunc{receive(s, s.v4)}
	if s.v6 != nil {
		fns = append(fns, receive(s, s.v6))
	}
	return fns, s.port, nil
}

// openLocked binds the sockets of a new generation to port, or to a free port
// when port is 0, and gives them the mark. With port 0, the IPv4 endpoint
// selects the port, and a retry runs when another socket owns the IPv6 side of
// it, as in wg_socket_init.
//
// Preconditions: b.mu is held.
func (b *netBind) openLocked(port uint16) (*bindSession, error) {
	hasV6 := b.stack.CheckNetworkProtocol(ipv6.ProtocolNumber)
	for try := 0; ; try++ {
		s := &bindSession{}
		v4, ep4, actual, err := b.listen(ipv4.ProtocolNumber, port)
		if err != nil {
			return nil, err
		}
		s.v4, s.port, s.eps = v4, actual, []tcpip.Endpoint{ep4}
		if hasV6 {
			v6, ep6, _, err := b.listen(ipv6.ProtocolNumber, actual)
			if err != nil {
				v4.Close()
				var be *bindError
				if port != 0 || try >= portRetries || !errors.As(err, &be) || be.err != syserr.ErrPortInUse {
					return nil, err
				}
				continue
			}
			s.v6 = v6
			s.eps = append(s.eps, ep6)
		}
		for _, ep := range s.eps {
			ep.SocketOptions().SetMark(b.mark)
		}
		return s, nil
	}
}

// incomingPort returns the stored port.
func (b *netBind) incomingPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.incoming
}

// setIncoming stores the port for the next Open. It changes no socket.
func (b *netBind) setIncoming(port uint16) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.incoming = port
}

// prepare binds the sockets of port, or of a free port for 0, and keeps them
// for the next Open. A failure leaves the open sockets and the stored port
// as they are, so a rebind never leaves the device without a socket.
func (b *netBind) prepare(port uint16) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.gone {
		return errBirthplaceEnded
	}
	s, err := b.openLocked(port)
	if err != nil {
		return err
	}
	if b.pending != nil {
		b.pending.close()
	}
	b.pending = s
	return nil
}

// setMark stores the mark and gives it to the open sockets. Every packet that
// the sockets send then carries it, and so a packet filter rule that matches
// the mark sees the encrypted packets, as it does on Linux.
func (b *netBind) setMark(mark uint32) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.mark = mark
	for _, s := range []*bindSession{b.session, b.pending} {
		if s == nil {
			continue
		}
		for _, ep := range s.eps {
			ep.SocketOptions().SetMark(mark)
		}
	}
}

// birthplaceEnded closes the sockets and refuses every later Open. The device
// keeps its configuration, as a Linux device does when its creating namespace
// exits.
func (b *netBind) birthplaceEnded() {
	b.mu.Lock()
	b.gone = true
	s, p := b.session, b.pending
	b.session, b.pending = nil, nil
	b.mu.Unlock()
	if s != nil {
		s.close()
	}
	if p != nil {
		p.close()
	}
}

// close closes the endpoints of the generation.
func (s *bindSession) close() {
	s.closed.Store(true)
	s.v4.Close()
	if s.v6 != nil {
		s.v6.Close()
	}
}

// listen opens a UDP endpoint of one IP family on the wildcard address.
func (b *netBind) listen(proto tcpip.NetworkProtocolNumber, port uint16) (*gonet.UDPConn, tcpip.Endpoint, uint16, error) {
	var wq waiter.Queue
	ep, terr := b.stack.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if terr != nil {
		return nil, nil, 0, newBindError(terr)
	}
	if proto == ipv6.ProtocolNumber {
		ep.SocketOptions().SetV6Only(true)
	}
	if terr := ep.Bind(tcpip.FullAddress{Port: port}); terr != nil {
		ep.Close()
		return nil, nil, 0, newBindError(terr)
	}
	local, terr := ep.GetLocalAddress()
	if terr != nil {
		ep.Close()
		return nil, nil, 0, newBindError(terr)
	}
	return gonet.NewUDPConn(&wq, ep), ep, local.Port, nil
}

// receive returns the receive function of one UDP endpoint.
func receive(s *bindSession, c *gonet.UDPConn) conn.ReceiveFunc {
	return func(bufs [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		if len(bufs) == 0 || len(sizes) < len(bufs) || len(eps) < len(bufs) {
			return 0, fmt.Errorf("wireguard: receive needs %d sizes and endpoints, got %d and %d", len(bufs), len(sizes), len(eps))
		}
		n, from, err := c.ReadFrom(bufs[0])
		if err != nil {
			// A closed endpoint reads as end of file.
			if s.closed.Load() || errors.Is(err, io.EOF) {
				return 0, net.ErrClosed
			}
			return 0, err
		}
		sizes[0] = n
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			return 0, fmt.Errorf("wireguard: sender address is %T, want *net.UDPAddr", from)
		}
		ip, ok := netip.AddrFromSlice(ua.IP)
		if !ok {
			return 0, fmt.Errorf("wireguard: invalid sender address %v", ua.IP)
		}
		eps[0] = &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port))}
		return 1, nil
	}
}

// Close closes the UDP endpoints. Every receive function of the generation
// returns net.ErrClosed afterward. The stored port stays. Close succeeds when
// the Bind is closed.
func (b *netBind) Close() error {
	b.mu.Lock()
	s := b.session
	b.session = nil
	b.mu.Unlock()
	if s != nil {
		s.close()
	}
	return nil
}

// SetMark implements conn.Bind.SetMark. The device owns the mark, so this
// stores the value that wireguard-go passes.
func (b *netBind) SetMark(mark uint32) error {
	b.setMark(mark)
	return nil
}

// Send writes each buffer as one datagram to ep from the UDP endpoint of the
// address family of ep.
func (b *netBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	dst, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	b.mu.Lock()
	s := b.session
	b.mu.Unlock()
	if s == nil {
		return net.ErrClosed
	}
	ip := dst.Addr().Unmap()
	c := s.v4
	if !ip.Is4() {
		c = s.v6
	}
	if c == nil {
		return syscall.EAFNOSUPPORT
	}
	to := &net.UDPAddr{IP: ip.AsSlice(), Port: int(dst.Port())}
	for _, buf := range bufs {
		if _, err := c.WriteTo(buf, to); err != nil {
			return err
		}
	}
	return nil
}

// ParseEndpoint parses "ip:port" or "[ipv6]:port".
func (b *netBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("wireguard: parse endpoint %q: %w", s, err)
	}
	return &conn.StdNetEndpoint{AddrPort: netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())}, nil
}

// BatchSize returns 1, because a UDP endpoint of the stack reads one datagram
// at a time.
func (b *netBind) BatchSize() int { return 1 }
