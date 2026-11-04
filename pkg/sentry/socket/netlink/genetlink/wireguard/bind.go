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

// portRetries is the count of attempts to find one free port for the IPv4 and
// the IPv6 UDP endpoint when the device asks for any port.
const portRetries = 8

// bindError carries the errno of a failed UDP bind, so the netlink handler
// answers with it.
type bindError struct{ err *syserr.Error }

func (e *bindError) Error() string { return "wireguard: " + e.err.String() }

// netBind implements conn.Bind with UDP endpoints of a network stack. The
// stack is the network stack of the namespace where the link was created, so
// the encrypted packets leave through the routes of that namespace.
type netBind struct {
	stack *stack.Stack

	mu      sync.Mutex
	session *bindSession
	// port is the port of the open generation, or 0 while the bind is closed.
	port uint16
}

// bindSession is one Open generation with its UDP endpoints.
type bindSession struct {
	v4     *gonet.UDPConn
	v6     *gonet.UDPConn // nil when the stack has no IPv6
	closed atomic.Bool
}

var _ conn.Bind = (*netBind)(nil)

func newBind(s *stack.Stack) *netBind {
	return &netBind{stack: s}
}

// Open binds one UDP endpoint for each IP family to the port and returns one
// receive function for each endpoint. Port 0 selects a free port, and Open
// returns it.
func (b *netBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.session != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	s := &bindSession{}
	hasV6 := b.stack.CheckNetworkProtocol(ipv6.ProtocolNumber)
	actual := port
	for try := 0; ; try++ {
		v4, p, err := b.listen(ipv4.ProtocolNumber, port)
		if err != nil {
			return nil, 0, err
		}
		actual = p
		s.v4 = v4
		if !hasV6 {
			break
		}
		v6, _, err := b.listen(ipv6.ProtocolNumber, actual)
		if err == nil {
			s.v6 = v6
			break
		}
		v4.Close()
		// With port 0, another socket can own the IPv6 side of the port that
		// was free for IPv4. A fixed port that is in use stays in use.
		var be *bindError
		if port != 0 || try+1 >= portRetries || !errors.As(err, &be) || be.err != syserr.ErrPortInUse {
			return nil, 0, err
		}
	}
	b.session = s
	b.port = actual
	fns := []conn.ReceiveFunc{receive(s, s.v4)}
	if s.v6 != nil {
		fns = append(fns, receive(s, s.v6))
	}
	return fns, actual, nil
}

// localPort returns the port of the open generation, or 0 while the bind is
// closed.
func (b *netBind) localPort() uint16 {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.port
}

// probe binds the port for both IP families and releases it at once. A caller
// uses it to find a busy port before it closes the open generation, because a
// failed rebind would leave the device without a socket.
func (b *netBind) probe(port uint16) error {
	v4, _, err := b.listen(ipv4.ProtocolNumber, port)
	if err != nil {
		return err
	}
	defer v4.Close()
	if !b.stack.CheckNetworkProtocol(ipv6.ProtocolNumber) {
		return nil
	}
	v6, _, err := b.listen(ipv6.ProtocolNumber, port)
	if err != nil {
		return err
	}
	return v6.Close()
}

// listen opens a UDP endpoint of one IP family on the wildcard address.
func (b *netBind) listen(proto tcpip.NetworkProtocolNumber, port uint16) (*gonet.UDPConn, uint16, error) {
	var wq waiter.Queue
	ep, terr := b.stack.NewEndpoint(udp.ProtocolNumber, proto, &wq)
	if terr != nil {
		return nil, 0, &bindError{syserr.TranslateNetstackError(terr)}
	}
	if proto == ipv6.ProtocolNumber {
		ep.SocketOptions().SetV6Only(true)
	}
	if terr := ep.Bind(tcpip.FullAddress{Port: port}); terr != nil {
		ep.Close()
		return nil, 0, &bindError{syserr.TranslateNetstackError(terr)}
	}
	local, terr := ep.GetLocalAddress()
	if terr != nil {
		ep.Close()
		return nil, 0, &bindError{syserr.TranslateNetstackError(terr)}
	}
	return gonet.NewUDPConn(&wq, ep), local.Port, nil
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
// returns net.ErrClosed afterward. Close succeeds when the Bind is closed.
func (b *netBind) Close() error {
	b.mu.Lock()
	s := b.session
	b.session = nil
	b.port = 0
	b.mu.Unlock()
	if s == nil {
		return nil
	}
	s.closed.Store(true)
	s.v4.Close()
	if s.v6 != nil {
		s.v6.Close()
	}
	return nil
}

// SetMark accepts every mark and changes nothing. Netstack has no socket
// marks. wireguard-go keeps the value, and WG_CMD_GET_DEVICE reports it.
func (b *netBind) SetMark(uint32) error { return nil }

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
