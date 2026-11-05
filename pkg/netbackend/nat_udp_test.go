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
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// udpEndpoint is a raw loopback UDP socket that stands for one side of a relay.
type udpEndpoint struct {
	t    *testing.T
	sock *net.UDPConn
}

func newUDPEndpoint(t *testing.T) *udpEndpoint {
	t.Helper()
	sock, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = sock.Close() })
	return &udpEndpoint{t: t, sock: sock}
}

func (e *udpEndpoint) addr() *net.UDPAddr { return e.sock.LocalAddr().(*net.UDPAddr) }

// connect returns a UDP connection from a new socket to this endpoint. The
// relay uses it as its side of the session.
func (e *udpEndpoint) connect() *net.UDPConn {
	e.t.Helper()
	c, err := net.DialUDP("udp", nil, e.addr())
	if err != nil {
		e.t.Fatalf("DialUDP: %v", err)
	}
	e.t.Cleanup(func() { _ = c.Close() })
	return c
}

// recv reads one datagram and returns it with its source.
func (e *udpEndpoint) recv() (string, *net.UDPAddr) {
	e.t.Helper()
	if err := e.sock.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		e.t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, from, err := e.sock.ReadFromUDP(buf)
	if err != nil {
		e.t.Fatalf("recv: %v", err)
	}
	return string(buf[:n]), from
}

func (e *udpEndpoint) send(payload string, to *net.UDPAddr) {
	e.t.Helper()
	if _, err := e.sock.WriteToUDP([]byte(payload), to); err != nil {
		e.t.Fatalf("send: %v", err)
	}
}

// startRelay runs relayDatagrams between two fresh connections. It returns the
// remote endpoints, the relay-side addresses, and a channel that closes when
// the relay returns.
func startRelay(t *testing.T, ctx context.Context, idle time.Duration) (guestPeer, hostPeer *udpEndpoint, guestSide, hostSide *net.UDPAddr, done <-chan struct{}) {
	t.Helper()
	guestPeer, hostPeer = newUDPEndpoint(t), newUDPEndpoint(t)
	guestConn, hostConn := guestPeer.connect(), hostPeer.connect()
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		relayDatagrams(ctx, guestConn, hostConn, idle)
	}()
	return guestPeer, hostPeer, guestConn.LocalAddr().(*net.UDPAddr), hostConn.LocalAddr().(*net.UDPAddr), ch
}

func TestRelayDatagramsForwardsBothDirections(t *testing.T) {
	guestPeer, hostPeer, guestSide, hostSide, done := startRelay(t, t.Context(), time.Minute)
	for _, msg := range []string{"g1", "g2", "g3"} {
		guestPeer.send(msg, guestSide)
		if got, _ := hostPeer.recv(); got != msg {
			t.Fatalf("host received %q, want %q", got, msg)
		}
	}
	// A guest datagram may produce several replies, and the relay forwards all of them.
	for _, msg := range []string{"h1", "h2", "h3"} {
		hostPeer.send(msg, hostSide)
	}
	for _, msg := range []string{"h1", "h2", "h3"} {
		if got, _ := guestPeer.recv(); got != msg {
			t.Fatalf("guest received %q, want %q", got, msg)
		}
	}
	select {
	case <-done:
		t.Fatal("relay ended while it carried traffic")
	default:
	}
}

func TestRelayDatagramsKeepsSessionWhileOneDirectionIsActive(t *testing.T) {
	const idle = 1500 * time.Millisecond
	guestPeer, hostPeer, guestSide, hostSide, done := startRelay(t, t.Context(), idle)

	// The guest sends once and then stays quiet. Its direction goes idle,
	// but the host keeps sending for longer than the idle timeout. The session
	// must survive because the two directions share one activity clock.
	guestPeer.send("request", guestSide)
	if got, _ := hostPeer.recv(); got != "request" {
		t.Fatalf("host received %q", got)
	}
	start := time.Now()
	tick := time.NewTicker(idle / 4)
	defer tick.Stop()
	for i := 0; time.Since(start) < idle+idle/2; i++ {
		<-tick.C
		hostPeer.send("reply", hostSide)
		if got, _ := guestPeer.recv(); got != "reply" {
			t.Fatalf("guest received %q, want reply", got)
		}
		select {
		case <-done:
			t.Fatalf("relay ended after %s although the host was active", time.Since(start))
		default:
		}
	}

	// With both directions quiet, the session expires and the relay returns.
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay stayed open after both directions went idle")
	}
}

func TestRelayDatagramsExpiresWhenIdle(t *testing.T) {
	_, _, _, _, done := startRelay(t, t.Context(), 200*time.Millisecond)
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay stayed open with no traffic")
	}
}

func TestRelayDatagramsStopsOnContextAndClosesConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	guestPeer, hostPeer := newUDPEndpoint(t), newUDPEndpoint(t)
	guestConn, hostConn := guestPeer.connect(), hostPeer.connect()
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayDatagrams(ctx, guestConn, hostConn, time.Hour)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay ignored the context")
	}
	for name, c := range map[string]*net.UDPConn{"guest": guestConn, "host": hostConn} {
		if _, err := c.Write([]byte("x")); !errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s connection after the relay ended: Write = %v, want net.ErrClosed", name, err)
		}
	}
}

// scriptConn is a net.Conn whose Read returns scripted results.
type scriptConn struct {
	net.Conn
	results chan scriptResult
	closed  chan struct{}
	once    sync.Once
}

type scriptResult struct {
	data string
	err  error
}

func newScriptConn() *scriptConn {
	return &scriptConn{results: make(chan scriptResult, 64), closed: make(chan struct{})}
}

func (c *scriptConn) Read(p []byte) (int, error) {
	select {
	case r := <-c.results:
		return copy(p, r.data), r.err
	case <-c.closed:
		return 0, net.ErrClosed
	}
}
func (c *scriptConn) SetReadDeadline(time.Time) error { return nil }
func (c *scriptConn) Close() error                    { c.once.Do(func() { close(c.closed) }); return nil }

func connRefused() error {
	return &net.OpError{Op: "read", Net: "udp", Err: os.NewSyscallError("recvfrom", syscall.ECONNREFUSED)}
}

func TestPumpDatagramsSurvivesReadErrorsOfConnectedSocket(t *testing.T) {
	src := newScriptConn()
	got := make(chan string, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpDatagrams(src, func(p []byte) error { got <- string(p); return nil }, newActivityClock(), time.Hour)
	}()
	// Two refusals, a datagram, then two more refusals and a second datagram.
	// The counter of consecutive errors resets after each datagram.
	for _, r := range []scriptResult{
		{err: connRefused()}, {err: connRefused()}, {data: "first"},
		{err: connRefused()}, {err: connRefused()}, {data: "second"},
	} {
		src.results <- r
	}
	for _, want := range []string{"first", "second"} {
		select {
		case g := <-got:
			if g != want {
				t.Fatalf("pump forwarded %q, want %q", g, want)
			}
		case <-time.After(testTimeout):
			t.Fatalf("pump stopped before %q after read errors", want)
		}
	}
	select {
	case <-done:
		t.Fatal("pump ended after isolated read errors")
	default:
	}
	_ = src.Close()
	<-done
}

func TestPumpDatagramsEndsOnPersistentReadErrors(t *testing.T) {
	src := newScriptConn()
	for range maxTransientUDPErrors {
		src.results <- scriptResult{err: connRefused()}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpDatagrams(src, func([]byte) error { return nil }, newActivityClock(), time.Hour)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("pump never gave up on a socket that fails every read")
	}
}

func TestPumpDatagramsDropsOnlyTheDatagramThatFailsToSend(t *testing.T) {
	src := newScriptConn()
	var mu sync.Mutex
	var sent []string
	delivered := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpDatagrams(src, func(p []byte) error {
			mu.Lock()
			defer mu.Unlock()
			if string(p) == "bad" {
				return errors.New("send failed")
			}
			sent = append(sent, string(p))
			close(delivered)
			return nil
		}, newActivityClock(), time.Hour)
	}()
	src.results <- scriptResult{data: "bad"}
	src.results <- scriptResult{data: "good"}
	select {
	case <-delivered:
	case <-time.After(testTimeout):
		t.Fatal("pump stopped after a send error")
	}
	_ = src.Close()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(sent) != 1 || sent[0] != "good" {
		t.Fatalf("delivered %v, want [good]", sent)
	}
}

func TestPumpDatagramsEndsWhenSendReportsClosed(t *testing.T) {
	src := newScriptConn()
	src.results <- scriptResult{data: "x"}
	done := make(chan struct{})
	go func() {
		defer close(done)
		pumpDatagrams(src, func([]byte) error { return net.ErrClosed }, newActivityClock(), time.Hour)
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("pump kept running after its destination closed")
	}
}

func TestIsTimeoutRecognizesGonetDeadlines(t *testing.T) {
	s, _ := newTestStack(t, DefaultWireGuardMTU)
	c, err := gonet.DialUDP(s, &tcpip.FullAddress{Port: 4000}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer c.Close()
	if err := c.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err = c.Read(make([]byte, 16))
	if !isTimeout(err) {
		t.Fatalf("isTimeout(%v) = false for a gonet deadline error", err)
	}
	// The gonet error does not wrap os.ErrDeadlineExceeded, which is why isTimeout exists.
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("gonet deadline error now wraps os.ErrDeadlineExceeded: %v", err)
	}
	if isTimeout(errors.New("other")) || isTimeout(net.ErrClosed) {
		t.Fatal("isTimeout reports a non-timeout error as a timeout")
	}
}

func TestActivityClock(t *testing.T) {
	c := newActivityClock()
	const idle = time.Hour
	if c.expired(idle) {
		t.Fatal("new clock is expired")
	}
	d1 := c.deadline(idle)
	c.touch()
	d2 := c.deadline(idle)
	if d2.Before(d1) {
		t.Fatalf("touch moved the deadline back from %v to %v", d1, d2)
	}
	if !c.expired(0) {
		t.Fatal("clock with zero idle time is not expired")
	}
	// touch never moves the last activity time backward.
	c.last.Store(int64(10 * time.Hour))
	c.touch()
	if got := time.Duration(c.last.Load()); got != 10*time.Hour {
		t.Fatalf("touch moved last activity back to %v", got)
	}
}

// recordedConn wraps a net.Conn and reports when it closes.
type recordedConn struct {
	net.Conn
	closed chan struct{}
	once   sync.Once
}

func (c *recordedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestNATUDPSessionCarriesMultipleRepliesAndExpires(t *testing.T) {
	host := newUDPEndpoint(t)
	var dialed sync.Once
	hostSide := make(chan *recordedConn, 1)
	tuned, err := tuning.Values{}.WithDuration(tuning.UDPIdleTimeout, 300*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	s, nf, err := NewNATStack(NATConfig{
		Tuning: tuned,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			rc := &recordedConn{Conn: c, closed: make(chan struct{})}
			dialed.Do(func() { hostSide <- rc })
			return rc, nil
		},
	})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		s.Close()
	}()

	// 10.0.2.2 maps to the host loopback, where the raw endpoint listens.
	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.addr().Port)}
	guest, err := gonet.DialUDP(s, nil, &gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer guest.Close()
	if _, err := guest.Write([]byte("hello")); err != nil {
		t.Fatalf("guest write: %v", err)
	}
	got, from := host.recv()
	if got != "hello" {
		t.Fatalf("host received %q, want hello", got)
	}
	// One request, three replies. The NAT must forward every reply.
	for _, r := range []string{"r1", "r2", "r3"} {
		host.send(r, from)
	}
	if err := guest.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	for _, want := range []string{"r1", "r2", "r3"} {
		n, err := guest.Read(buf)
		if err != nil || string(buf[:n]) != want {
			t.Fatalf("guest read = (%q, %v), want %q", buf[:n], err, want)
		}
	}

	// With no traffic in either direction, the host socket closes after the idle timeout.
	rc := <-hostSide
	select {
	case <-rc.closed:
	case <-time.After(testTimeout):
		t.Fatal("NAT session stayed open after the idle timeout")
	}
}

func TestNATForwarderCloseEndsActiveUDPSessionsPromptly(t *testing.T) {
	host := newUDPEndpoint(t)
	s, nf, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer s.Close()
	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.addr().Port)}
	guest, err := gonet.DialUDP(s, nil, &gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer guest.Close()
	if _, err := guest.Write([]byte("open-session")); err != nil {
		t.Fatal(err)
	}
	if got, _ := host.recv(); got != "open-session" {
		t.Fatalf("host received %q", got)
	}

	// The session has the default 30 second idle timeout. Close must not wait for it.
	closed := make(chan error, 1)
	go func() { closed <- nf.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("NATForwarder.Close did not return with an active UDP session")
	}
	if nf.spawn(func() {}) {
		t.Fatal("spawn accepted work after Close")
	}
}

func TestRelayBidirectionalHalfClosesAndReturnsAfterBothDirectionsEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverSide := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			serverSide <- c
		}
	}()
	a1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer a1.Close()
	a2 := <-serverSide
	defer a2.Close()

	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go func() {
		c, err := ln2.Accept()
		if err == nil {
			serverSide <- c
		}
	}()
	b1, err := net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer b1.Close()
	b2 := <-serverSide
	defer b2.Close()

	// a2 and b2 are the relay ends. a1 and b1 are the two remote peers.
	done := make(chan struct{})
	go func() {
		defer close(done)
		relayBidirectional(t.Context(), a2, b2)
	}()

	if _, err := a1.Write([]byte("to-b")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 16)
	if n, err := b1.Read(buf); err != nil || string(buf[:n]) != "to-b" {
		t.Fatalf("b1 read = (%q, %v)", buf[:n], err)
	}
	// a1 half-closes. The relay forwards the EOF to b1 but keeps b1 to a1 open.
	if err := a1.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := b1.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("b1 read after a1 half-close = %v, want EOF", err)
	}
	select {
	case <-done:
		t.Fatal("relay ended before the second direction finished")
	default:
	}
	if _, err := b1.Write([]byte("to-a")); err != nil {
		t.Fatal(err)
	}
	if n, err := a1.Read(buf); err != nil || string(buf[:n]) != "to-a" {
		t.Fatalf("a1 read = (%q, %v)", buf[:n], err)
	}
	if err := b1.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("relay did not return after both directions ended")
	}
}
