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
	"net"
	"net/netip"
	"sync"
	"testing"

	"golang.zx2c4.com/wireguard/conn"
)

// newBindSocket opens the wildcard socket that the endpoint pre-binds.
func newBindSocket(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", DefaultWireGuardListenAddr)
	if err != nil {
		t.Fatalf("ListenPacket: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.(*net.UDPConn)
}

func loopbackPort(sock *net.UDPConn) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(sock.LocalAddr().(*net.UDPAddr).Port))
}

func TestPreboundBindOpenReportsSocketPortAndNeverRebinds(t *testing.T) {
	sock := newBindSocket(t)
	b, err := newPreboundBind(sock)
	if err != nil {
		t.Fatalf("newPreboundBind: %v", err)
	}
	wantPort := uint16(sock.LocalAddr().(*net.UDPAddr).Port)

	// The requested port is a hint only. Keep freeProbe bound across Open so
	// any attempt to bind the requested port fails deterministically.
	freeProbe := newBindSocket(t)
	requested := uint16(freeProbe.LocalAddr().(*net.UDPAddr).Port)
	fns, got, err := b.Open(requested)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != wantPort {
		t.Fatalf("Open reported port %d, want the pre-bound port %d", got, wantPort)
	}
	if len(fns) != 1 {
		t.Fatalf("Open returned %d receive functions, want 1", len(fns))
	}
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open = %v, want conn.ErrBindAlreadyOpen", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestPreboundBindCloseUnblocksReceiveAndKeepsSocket(t *testing.T) {
	sock := newBindSocket(t)
	b, err := newPreboundBind(sock)
	if err != nil {
		t.Fatalf("newPreboundBind: %v", err)
	}
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	recvErr := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		bufs := [][]byte{make([]byte, 2048)}
		_, err := fns[0](bufs, make([]int, 1), make([]conn.Endpoint, 1))
		recvErr <- err
	}()
	<-started
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := <-recvErr; !errors.Is(err, net.ErrClosed) {
		t.Fatalf("receive after Close = %v, want net.ErrClosed", err)
	}
	// A receive function of a closed Bind keeps returning net.ErrClosed.
	if _, err := fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("second receive after Close = %v, want net.ErrClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	// The Bind does not own the socket, so the caller can still use it.
	peer := newBindSocket(t)
	if _, err := sock.WriteToUDPAddrPort([]byte("still-open"), loopbackPort(peer)); err != nil {
		t.Fatalf("socket closed by Bind.Close: %v", err)
	}
	// Open must work again on the same socket after Close.
	fns, _, err = b.Open(0)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := peer.WriteToUDPAddrPort([]byte("after-reopen"), loopbackPort(sock)); err != nil {
		t.Fatalf("write to reopened socket: %v", err)
	}
	bufs := [][]byte{make([]byte, 2048)}
	sizes := make([]int, 1)
	eps := make([]conn.Endpoint, 1)
	n, err := fns[0](bufs, sizes, eps)
	if err != nil || n != 1 || string(bufs[0][:sizes[0]]) != "after-reopen" {
		t.Fatalf("receive after reopen = (%d, %v, %q), want the datagram", n, err, bufs[0][:sizes[0]])
	}
	if err := b.Close(); err != nil {
		t.Fatalf("final Close: %v", err)
	}
}

func TestPreboundBindCloseWithoutOpenAndAfterSocketClosed(t *testing.T) {
	sock := newBindSocket(t)
	b, err := newPreboundBind(sock)
	if err != nil {
		t.Fatalf("newPreboundBind: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close without Open: %v", err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// The owner may close the socket first. Close must not fail because of it.
	_ = sock.Close()
	if err := b.Close(); err != nil {
		t.Fatalf("Close after the owner closed the socket: %v", err)
	}
	if _, _, err := b.Open(0); err == nil {
		t.Fatal("Open on a closed socket succeeded, want an error")
	}
}

func TestPreboundBindSendAndReceiveUnmapsIPv4(t *testing.T) {
	sockA, sockB := newBindSocket(t), newBindSocket(t)
	a, err := newPreboundBind(sockA)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newPreboundBind(sockB)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Open(0); err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	fnsB, _, err := b.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()

	dst, err := a.ParseEndpoint(loopbackPort(sockB).String())
	if err != nil {
		t.Fatalf("ParseEndpoint: %v", err)
	}
	if err := a.Send([][]byte{[]byte("one"), []byte("two")}, dst); err != nil {
		t.Fatalf("Send: %v", err)
	}
	for _, want := range []string{"one", "two"} {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fnsB[0](bufs, sizes, eps)
		if err != nil || n != 1 {
			t.Fatalf("receive = (%d, %v)", n, err)
		}
		if got := string(bufs[0][:sizes[0]]); got != want {
			t.Fatalf("received %q, want %q", got, want)
		}
		// The dual-stack socket reports 127.0.0.1 as an IPv4-mapped address.
		// The endpoint must hold the plain IPv4 address.
		if ip := eps[0].DstIP(); !ip.Is4() || ip != netip.MustParseAddr("127.0.0.1") {
			t.Fatalf("endpoint address = %s (Is4=%v), want 127.0.0.1", ip, ip.Is4())
		}
		if eps[0].DstToString() != loopbackPort(sockA).String() {
			t.Fatalf("endpoint = %s, want the sender %s", eps[0].DstToString(), loopbackPort(sockA))
		}
	}
}

func TestPreboundBindSendErrors(t *testing.T) {
	sock := newBindSocket(t)
	b, err := newPreboundBind(sock)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := b.ParseEndpoint("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send before Open = %v, want net.ErrClosed", err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, wrongEndpoint{}); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("Send with a foreign endpoint = %v, want conn.ErrWrongEndpointType", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v, want net.ErrClosed", err)
	}
}

type wrongEndpoint struct{}

func (wrongEndpoint) ClearSrc()           {}
func (wrongEndpoint) SrcToString() string { return "" }
func (wrongEndpoint) DstToString() string { return "" }
func (wrongEndpoint) DstToBytes() []byte  { return nil }
func (wrongEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (wrongEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

func TestPreboundBindParseEndpoint(t *testing.T) {
	b, err := newPreboundBind(newBindSocket(t))
	if err != nil {
		t.Fatal(err)
	}
	good := map[string]string{
		"192.0.2.1:51820":      "192.0.2.1:51820",
		"[2001:db8::1]:51820":  "[2001:db8::1]:51820",
		"[::ffff:192.0.2.1]:7": "192.0.2.1:7",
	}
	for in, want := range good {
		ep, err := b.ParseEndpoint(in)
		if err != nil {
			t.Fatalf("ParseEndpoint(%q): %v", in, err)
		}
		if got := ep.DstToString(); got != want {
			t.Fatalf("ParseEndpoint(%q).DstToString() = %q, want %q", in, got, want)
		}
	}
	for _, in := range []string{"", "example.com:51820", "192.0.2.1", "192.0.2.1:99999", "[::1]"} {
		if _, err := b.ParseEndpoint(in); err == nil {
			t.Fatalf("ParseEndpoint(%q) succeeded, want an error", in)
		}
	}
}

func TestPreboundBindMarkAndBatchSize(t *testing.T) {
	b, err := newPreboundBind(newBindSocket(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.SetMark(0); err != nil {
		t.Fatalf("SetMark(0) = %v, want nil", err)
	}
	if err := b.SetMark(7); !errors.Is(err, errMarkUnsupported) {
		t.Fatalf("SetMark(7) = %v, want errMarkUnsupported", err)
	}
	if b.BatchSize() != 1 {
		t.Fatalf("BatchSize() = %d, want 1", b.BatchSize())
	}
}

type notUDPConn struct{ net.PacketConn }

func TestNewPreboundBindRejectsNonUDPSocket(t *testing.T) {
	if _, err := newPreboundBind(notUDPConn{}); err == nil {
		t.Fatal("newPreboundBind accepted a PacketConn that is not *net.UDPConn")
	}
}

func TestPreboundBindOpenCloseRace(t *testing.T) {
	sock := newBindSocket(t)
	b, err := newPreboundBind(sock)
	if err != nil {
		t.Fatal(err)
	}
	for range 200 {
		fns, _, err := b.Open(0)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := fns[0]([][]byte{make([]byte, 64)}, make([]int, 1), make([]conn.Endpoint, 1))
			if !errors.Is(err, net.ErrClosed) {
				t.Errorf("receive = %v, want net.ErrClosed", err)
			}
		}()
		if err := b.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		wg.Wait()
	}
}
