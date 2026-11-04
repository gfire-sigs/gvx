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
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

// newLoopbackStack returns a stack whose only link is a loopback with the
// addresses 127.0.0.1 and ::1.
func newLoopbackStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	const nic tcpip.NICID = 1
	if err := s.CreateNIC(nic, loopback.New()); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	for _, a := range []tcpip.ProtocolAddress{
		{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{127, 0, 0, 1}), PrefixLen: 8}},
		{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: header.IPv6Loopback.WithPrefix()},
	} {
		if err := s.AddProtocolAddress(nic, a, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%v): %v", a, err)
		}
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: nic},
		{Destination: header.IPv6EmptySubnet, NIC: nic},
	})
	t.Cleanup(func() {
		s.Close()
		s.Wait()
	})
	return s
}

// receiveOne runs the receive function on its own goroutine and returns the
// result on a channel.
type received struct {
	data []byte
	from netip.AddrPort
	err  error
}

func receiveOne(fn conn.ReceiveFunc) <-chan received {
	ch := make(chan received, 1)
	go func() {
		bufs := [][]byte{make([]byte, 2048)}
		sizes := make([]int, 1)
		eps := make([]conn.Endpoint, 1)
		n, err := fn(bufs, sizes, eps)
		if err != nil || n != 1 {
			ch <- received{err: err}
			return
		}
		ch <- received{data: bufs[0][:sizes[0]], from: eps[0].(*conn.StdNetEndpoint).AddrPort}
	}()
	return ch
}

func TestBindOpenSelectsOnePortForBothFamilies(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open(0) = %v", err)
	}
	if port == 0 || len(fns) != 2 {
		t.Fatalf("Open(0) = %d functions and port %d, want 2 functions and a port", len(fns), port)
	}
	if _, _, err := b.Open(0); !errors.Is(err, conn.ErrBindAlreadyOpen) {
		t.Fatalf("second Open = %v, want ErrBindAlreadyOpen", err)
	}
	// Both families of the port are taken.
	other := newBind(b.stack)
	if _, _, err := other.Open(port); err == nil {
		t.Fatalf("Open(%d) succeeded while the first bind owns the port", port)
	} else {
		var be *bindError
		if !errors.As(err, &be) || be.err != syserr.ErrPortInUse {
			t.Fatalf("Open(%d) = %v, want a port in use error", port, err)
		}
	}
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, err := other.Open(port); err != nil {
		t.Fatalf("Open(%d) after Close = %v, want success", port, err)
	}
	other.Close()
}

func TestBindSendsAndReceivesDatagramsOfBothFamilies(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	fns, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	for i, dst := range []string{"127.0.0.1", "::1"} {
		ep, err := b.ParseEndpoint(netip.AddrPortFrom(netip.MustParseAddr(dst), port).String())
		if err != nil {
			t.Fatalf("ParseEndpoint(%s): %v", dst, err)
		}
		got := receiveOne(fns[i])
		if err := b.Send([][]byte{[]byte("one"), []byte("two")}, ep); err != nil {
			t.Fatalf("Send to %s: %v", dst, err)
		}
		select {
		case r := <-got:
			if r.err != nil || string(r.data) != "one" || r.from.Addr() != netip.MustParseAddr(dst) {
				t.Fatalf("receive on %s = %+v, want the datagram \"one\" from %s", dst, r, dst)
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("no datagram arrived on %s", dst)
		}
	}
}

func TestBindCloseUnblocksReceiveAndAllowsReopen(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := receiveOne(fns[0])
	if err := b.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case r := <-got:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("receive after Close = %v, want net.ErrClosed", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not unblock the receive function")
	}
	ep, _ := b.ParseEndpoint("127.0.0.1:9")
	if err := b.Send([][]byte{{1}}, ep); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Send after Close = %v, want net.ErrClosed", err)
	}
	if err := b.Close(); err != nil {
		t.Fatalf("second Close = %v, want success", err)
	}
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open after Close = %v, want success", err)
	}
	b.Close()
}

func TestBindSendRejectsForeignEndpoint(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	if err := b.Send([][]byte{{1}}, nil); !errors.Is(err, conn.ErrWrongEndpointType) {
		t.Fatalf("Send(nil endpoint) = %v, want ErrWrongEndpointType", err)
	}
}

func TestNewLinkConfiguresAndClosesTheDevice(t *testing.T) {
	st := newLoopbackStack(t)
	before := runtime.NumGoroutine()
	ep, sysErr := newLink(context.Background(), &netstack.NewLinkRequest{Stack: netstack.NewStack(st, 1), ID: 2, Name: "wg0"})
	if sysErr != nil {
		t.Fatalf("newLink = %v", sysErr)
	}
	link := ep.(*linkEndpoint)
	if link.MTU() != defaultMTU {
		t.Errorf("MTU = %d, want %d", link.MTU(), defaultMTU)
	}
	conf := "listen_port=0\nfwmark=7\nprivate_key=" + hexKey(1) + "\npublic_key=" + hexKey(2) + "\nallowed_ip=10.0.0.0/8\n"
	if err := link.dev.IpcSet(conf); err != nil {
		t.Fatalf("IpcSet: %v", err)
	}
	text, err := link.dev.IpcGet()
	if err != nil {
		t.Fatalf("IpcGet: %v", err)
	}
	info, err := parseIpcGet(text)
	if err != nil {
		t.Fatalf("parseIpcGet: %v", err)
	}
	if info.listenPort == 0 || info.fwmark != 7 || len(info.peers) != 1 || len(info.peers[0].allowedIPs) != 1 {
		t.Errorf("device state = %+v, want an assigned port, mark 7, and one peer with one prefix", info)
	}
	link.SetMTU(1380)
	if got, _ := link.tun.MTU(); got != 1380 {
		t.Errorf("tun MTU = %d after SetMTU(1380)", got)
	}

	link.Close()
	link.Close()
	deadline := time.Now().Add(10 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if after := runtime.NumGoroutine(); after > before {
		t.Errorf("%d goroutines remain after Close, started with %d", after, before)
	}
}

// hexKey returns the hexadecimal form of a 32-byte key with every byte b.
func hexKey(b byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b}, 32))
}
