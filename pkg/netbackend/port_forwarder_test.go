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
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// newForwardStack returns the Track A Netstack for forwarder tests.
func newForwardStack(t *testing.T) *stack.Stack {
	t.Helper()
	s, nf, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() {
		_ = nf.Close()
		s.Close()
	})
	return s
}

func guestFullAddr(port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 15}), Port: port}
}

// preBoundUDPForward binds one UDP rule on a free loopback port.
func preBoundUDPForward(t *testing.T, guestPort uint16) (*PortForwarder, *net.UDPAddr) {
	t.Helper()
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	if err := pf.PreBind([]PortForwardRule{{Proto: "udp", HostIP: "127.0.0.1", GuestPort: guestPort}}); err != nil {
		t.Fatalf("PreBind: %v", err)
	}
	rules := pf.BoundRules()
	if len(rules) != 1 || rules[0].HostPort == 0 {
		t.Fatalf("BoundRules() = %+v, want one rule with a bound port", rules)
	}
	return pf, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(rules[0].HostPort)}
}

func newClientSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func recvFrom(t *testing.T, c *net.UDPConn) string {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	n, _, err := c.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	return string(buf[:n])
}

// guestSeen is one datagram that the guest UDP server received.
type guestSeen struct {
	payload string
	from    string
}

// startGuestUDPServer listens in the guest on port. For each datagram it
// reports the payload and the source, then sends replyCount copies of
// "<payload>#<i>" back.
func startGuestUDPServer(t *testing.T, s *stack.Stack, port uint16, replyCount int) <-chan guestSeen {
	t.Helper()
	addr := guestFullAddr(port)
	srv, err := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("guest UDP listen: %v", err)
	}
	seen := make(chan guestSeen, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFrom(buf)
			if err != nil {
				return
			}
			seen <- guestSeen{payload: string(buf[:n]), from: from.String()}
			for i := range replyCount {
				_, _ = srv.WriteTo(append(append([]byte(nil), buf[:n]...), '#', byte('0'+i)), from)
			}
		}
	}()
	t.Cleanup(func() {
		_ = srv.Close()
		<-done
	})
	return seen
}

func TestPortForwarderUDPSessionsForwardEveryReply(t *testing.T) {
	s := newForwardStack(t)
	seen := startGuestUDPServer(t, s, 5300, 3)
	pf, hostAddr := preBoundUDPForward(t, 5300)
	pf.Start(s)

	clientA, clientB := newClientSocket(t), newClientSocket(t)
	if _, err := clientA.WriteToUDP([]byte("a1"), hostAddr); err != nil {
		t.Fatal(err)
	}
	first := <-seen
	// One request produces three replies. The forwarder must deliver all of them.
	for i, want := range []string{"a1#0", "a1#1", "a1#2"} {
		if got := recvFrom(t, clientA); got != want {
			t.Fatalf("client A reply %d = %q, want %q", i, got, want)
		}
	}

	// A second datagram from the same client reuses its guest endpoint.
	if _, err := clientA.WriteToUDP([]byte("a2"), hostAddr); err != nil {
		t.Fatal(err)
	}
	second := <-seen
	if second.from != first.from {
		t.Fatalf("guest saw client A from %s then %s, want one stable source per client", first.from, second.from)
	}
	for range 3 {
		recvFrom(t, clientA)
	}

	// A different client gets its own guest endpoint and its own replies.
	if _, err := clientB.WriteToUDP([]byte("b1"), hostAddr); err != nil {
		t.Fatal(err)
	}
	other := <-seen
	if other.from == first.from {
		t.Fatalf("clients A and B share the guest source %s, want separate sessions", other.from)
	}
	for i, want := range []string{"b1#0", "b1#1", "b1#2"} {
		if got := recvFrom(t, clientB); got != want {
			t.Fatalf("client B reply %d = %q, want %q", i, got, want)
		}
	}
	pf.mu.Lock()
	sessions := len(pf.udpList[0].sessions)
	pf.mu.Unlock()
	if sessions != 2 {
		t.Fatalf("forwarder holds %d sessions, want 2", sessions)
	}
}

func TestPortForwarderUDPSessionExpiresWhenIdle(t *testing.T) {
	s := newForwardStack(t)
	seen := startGuestUDPServer(t, s, 5300, 1)
	pf, hostAddr := preBoundUDPForward(t, 5300)
	pf.udpIdle = 200 * time.Millisecond
	pf.Start(s)

	client := newClientSocket(t)
	if _, err := client.WriteToUDP([]byte("one"), hostAddr); err != nil {
		t.Fatal(err)
	}
	first := <-seen
	recvFrom(t, client)

	// The expired session releases its guest endpoint. The next datagram
	// opens a new one, so the guest sees a new source port.
	waitForSessions(t, pf, 0)
	if _, err := client.WriteToUDP([]byte("two"), hostAddr); err != nil {
		t.Fatal(err)
	}
	second := <-seen
	if second.from == first.from {
		t.Fatalf("guest saw source %s again after the session expired, want a new endpoint", first.from)
	}
	if got := recvFrom(t, client); got != "two#0" {
		t.Fatalf("reply after expiry = %q, want two#0", got)
	}
}

// waitForSessions blocks until the first UDP rule holds n sessions.
func waitForSessions(t *testing.T, pf *PortForwarder, n int) {
	t.Helper()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	deadline := time.After(testTimeout)
	for {
		pf.mu.Lock()
		got := len(pf.udpList[0].sessions)
		pf.mu.Unlock()
		if got == n {
			return
		}
		select {
		case <-tick.C:
		case <-deadline:
			t.Fatalf("forwarder holds %d sessions, want %d", got, n)
		}
	}
}

func TestPortForwarderCloseDoesNotWaitForUnansweredDatagrams(t *testing.T) {
	s := newForwardStack(t)
	// No guest server exists, so no datagram ever gets an answer.
	pf, hostAddr := preBoundUDPForward(t, 5300)
	pf.Start(s)

	const clients = 8
	for range clients {
		if _, err := newClientSocket(t).WriteToUDP([]byte("nobody-answers"), hostAddr); err != nil {
			t.Fatal(err)
		}
	}
	// The serve loop reads datagrams in order. A probe from a ninth client
	// that gets an answer proves that it also created the earlier sessions.
	seen := startGuestUDPServer(t, s, 5300, 1)
	probe := newClientSocket(t)
	if _, err := probe.WriteToUDP([]byte("probe"), hostAddr); err != nil {
		t.Fatal(err)
	}
	// The server may also see some of the earlier datagrams, so skip them.
	for got := range seen {
		if got.payload == "probe" {
			break
		}
	}
	waitForSessions(t, pf, clients+1)

	closed := make(chan error, 1)
	go func() { closed <- pf.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("PortForwarder.Close hangs while sessions wait for guest replies")
	}
	pf.mu.Lock()
	left := len(pf.udpList[0].sessions)
	pf.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d sessions remain after Close, want 0", left)
	}
	if err := waitNoGoroutines(testContext(t), "(*PortForwarder)"); err != nil {
		t.Fatalf("forwarder goroutines remain after Close: %v", err)
	}
}

func TestPortForwarderUDPSessionLimit(t *testing.T) {
	s := newForwardStack(t)
	seen := startGuestUDPServer(t, s, 5300, 1)
	pf, hostAddr := preBoundUDPForward(t, 5300)
	pf.udpMaxSessions = 2
	pf.Start(s)

	c1, c2, c3 := newClientSocket(t), newClientSocket(t), newClientSocket(t)
	for _, c := range []*net.UDPConn{c1, c2} {
		if _, err := c.WriteToUDP([]byte("in"), hostAddr); err != nil {
			t.Fatal(err)
		}
		<-seen
		recvFrom(t, c)
	}
	if _, err := c3.WriteToUDP([]byte("over-limit"), hostAddr); err != nil {
		t.Fatal(err)
	}
	// The serve loop reads datagrams in order, so the probe from client 1
	// reaches the guest after the over-limit datagram would have.
	if _, err := c1.WriteToUDP([]byte("probe"), hostAddr); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.payload != "probe" {
		t.Fatalf("guest received %q, want the probe only: the third client is over the limit", got.payload)
	}
}

func TestPortForwarderTCPRetriesAcceptErrors(t *testing.T) {
	s := newForwardStack(t)
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(8080), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("guest listen: %v", err)
	}
	tcpEchoServer(t, guestLn)

	clientEnd, relayEnd := net.Pipe()
	defer clientEnd.Close()
	ln := &scriptListener{accepts: make(chan acceptResult, 8), closed: make(chan struct{})}
	const failures = 3
	for range failures {
		ln.accepts <- acceptResult{err: errors.New("accept tcp: too many open files")}
	}
	ln.accepts <- acceptResult{conn: relayEnd}

	pf := NewPortForwarder(tuning.Values{})
	pf.tcpList = []*boundTCPForward{{rule: PortForwardRule{Proto: "tcp", GuestIP: DefaultGuestIPv4, GuestPort: 8080}, listener: ln}}
	pf.Start(s)

	// The listener survived three accept errors and still relays the next connection.
	if _, err := clientEnd.Write([]byte("after-accept-errors")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 19)
	if _, err := io.ReadFull(clientEnd, buf); err != nil || string(buf) != "after-accept-errors" {
		t.Fatalf("echo = (%q, %v), want the payload", buf, err)
	}
	if got := ln.calls(); got < failures+1 {
		t.Fatalf("Accept ran %d times, want at least %d", got, failures+1)
	}
	if err := pf.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Close: %v", err)
	}
}

type acceptResult struct {
	conn net.Conn
	err  error
}

// scriptListener is a net.Listener whose Accept returns scripted results.
type scriptListener struct {
	accepts chan acceptResult
	closed  chan struct{}
	once    sync.Once
	mu      sync.Mutex
	n       int
}

func (l *scriptListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	l.n++
	l.mu.Unlock()
	select {
	case r := <-l.accepts:
		return r.conn, r.err
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *scriptListener) calls() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.n
}

func (l *scriptListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return nil
}

func (l *scriptListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestPortForwarderTCPWaitsForGuestListener(t *testing.T) {
	s := newForwardStack(t)
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1", GuestPort: 8081}}); err != nil {
		t.Fatal(err)
	}
	pf.Start(s)
	hostPort := pf.BoundRules()[0].HostPort

	// The host client connects before the guest listens. The forwarder keeps
	// dialing the guest, so the connection works once the guest listens.
	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(hostPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(8081), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guestLn)
	roundTripTCP(t, client, []byte("late-guest"))
}

func TestPortForwarderCloseEndsActiveTCPRelays(t *testing.T) {
	s := newForwardStack(t)
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(8082), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guestLn)
	pf := NewPortForwarder(tuning.Values{})
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1", GuestPort: 8082}}); err != nil {
		t.Fatal(err)
	}
	pf.Start(s)
	client, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(pf.BoundRules()[0].HostPort))))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	roundTripTCP(t, client, []byte("open-relay"))

	closed := make(chan error, 1)
	go func() { closed <- pf.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("PortForwarder.Close hangs with an open relay")
	}
	// The relay closed the host connection, so the client sees EOF or a reset.
	if err := client.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("client read data after Close, want the connection closed")
	}
}

func TestPortForwarderLifecycleErrors(t *testing.T) {
	pf := NewPortForwarder(tuning.Values{})
	if err := pf.PreBind([]PortForwardRule{{Proto: "sctp", HostIP: "127.0.0.1"}}); err == nil {
		t.Fatal("PreBind accepted protocol sctp")
	}
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := uint16(busy.Addr().(*net.TCPAddr).Port)
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1", HostPort: port}}); err == nil {
		t.Fatal("PreBind succeeded on a port that is in use")
	}
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "192.0.2.77", HostPort: 1}}); err == nil {
		t.Fatal("PreBind succeeded with a host address that no interface owns")
	}
	if err := pf.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := pf.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1"}}); err == nil {
		t.Fatal("PreBind after Close succeeded")
	}
	// Start after Close must start no goroutine.
	s := newForwardStack(t)
	pf.Start(s)
	if err := waitNoGoroutines(testContext(t), "(*PortForwarder).serve"); err != nil {
		t.Fatalf("Start after Close started goroutines: %v", err)
	}
}

func TestPortForwarderStartRunsOnce(t *testing.T) {
	s := newForwardStack(t)
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1", GuestPort: 8083}}); err != nil {
		t.Fatal(err)
	}
	pf.Start(s)
	pf.Start(s)
	pf.mu.Lock()
	defer pf.mu.Unlock()
	if !pf.started {
		t.Fatal("Start did not mark the forwarder as started")
	}
}

func TestParsePortForwardRule(t *testing.T) {
	good := map[string]PortForwardRule{
		"8080:80":              {Proto: "tcp", HostIP: "127.0.0.1", HostPort: 8080, GuestIP: DefaultGuestIPv4, GuestPort: 80},
		"127.0.0.1:8080:80":    {Proto: "tcp", HostIP: "127.0.0.1", HostPort: 8080, GuestIP: DefaultGuestIPv4, GuestPort: 80},
		"0.0.0.0:8080:80/tcp":  {Proto: "tcp", HostIP: "0.0.0.0", HostPort: 8080, GuestIP: DefaultGuestIPv4, GuestPort: 80},
		"5353:53/UDP":          {Proto: "udp", HostIP: "127.0.0.1", HostPort: 5353, GuestIP: DefaultGuestIPv4, GuestPort: 53},
		":8080:80":             {Proto: "tcp", HostIP: "127.0.0.1", HostPort: 8080, GuestIP: DefaultGuestIPv4, GuestPort: 80},
		"0:80":                 {Proto: "tcp", HostIP: "127.0.0.1", HostPort: 0, GuestIP: DefaultGuestIPv4, GuestPort: 80},
		"  127.0.0.1:1:2/udp ": {Proto: "udp", HostIP: "127.0.0.1", HostPort: 1, GuestIP: DefaultGuestIPv4, GuestPort: 2},
	}
	for in, want := range good {
		got, err := ParsePortForwardRule(in)
		if err != nil || got != want {
			t.Fatalf("ParsePortForwardRule(%q) = (%+v, %v), want %+v", in, got, err, want)
		}
	}
	for _, in := range []string{"", "80", "a:b", "1:2:3:4", "8080:0", "70000:80", "8080:80/sctp", "8080:x"} {
		if _, err := ParsePortForwardRule(in); err == nil {
			t.Fatalf("ParsePortForwardRule(%q) succeeded, want an error", in)
		}
	}
}
