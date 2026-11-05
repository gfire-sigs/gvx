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
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"z.gfire.dev/gvx/pkg/syserr"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
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
	other.setIncoming(port)
	if _, _, err := other.Open(0); err == nil {
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
	if _, _, err := other.Open(0); err != nil {
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

// hexKey returns the hexadecimal form of a 32-byte key with every byte b.
func hexKey(b byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestBindKeepsItsPortAcrossCloseAndOpen(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	_, port, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b.Close()
	if got := b.incomingPort(); got != port {
		t.Errorf("incomingPort after Close = %d, want the port %d of the closed sockets", got, port)
	}
	if _, again, err := b.Open(0); err != nil || again != port {
		t.Errorf("Open after Close = port %d and %v, want port %d", again, err, port)
	}
	b.Close()
}

func TestBindPrepareFailsOnABusyPortAndKeepsTheSockets(t *testing.T) {
	st := newLoopbackStack(t)
	owner := newBind(st)
	if _, _, err := owner.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer owner.Close()
	holder := newBind(st)
	_, busy, err := holder.Open(0)
	if err != nil {
		t.Fatalf("Open of the holder: %v", err)
	}
	defer holder.Close()
	before := owner.incomingPort()
	var be *bindError
	if err := owner.prepare(busy); !errors.As(err, &be) || be.err != syserr.ErrPortInUse {
		t.Fatalf("prepare(%d) = %v, want a port in use error", busy, err)
	}
	if got := owner.incomingPort(); got != before {
		t.Errorf("the port changed to %d after the failed prepare, want %d", got, before)
	}
	if owner.session == nil || owner.pending != nil {
		t.Errorf("session = %v and pending = %v after the failed prepare, want the open session and no pending one", owner.session, owner.pending)
	}
}

func TestBindOpenTakesThePreparedSockets(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := b.prepare(0); err != nil {
		t.Fatalf("prepare(0): %v", err)
	}
	prepared := b.pending.port
	b.Close()
	if _, port, err := b.Open(0); err != nil || port != prepared || b.incomingPort() != prepared {
		t.Fatalf("Open after prepare = port %d and %v, want the prepared port %d", port, err, prepared)
	}
	b.Close()
}

func TestBindMarksTheSocketsOfEveryGeneration(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	b.setMark(0x51)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	marks := func() []uint32 {
		var got []uint32
		for _, ep := range b.session.eps {
			got = append(got, ep.SocketOptions().GetMark())
		}
		return got
	}
	if got := marks(); len(got) != 2 || got[0] != 0x51 || got[1] != 0x51 {
		t.Errorf("marks of the sockets = %#x, want 0x51 on both families", got)
	}
	b.setMark(0x52)
	if got := marks(); got[0] != 0x52 || got[1] != 0x52 {
		t.Errorf("marks after setMark = %#x, want 0x52 on both families", got)
	}
	b.Close()
	b.setMark(0)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open after Close: %v", err)
	}
	if got := marks(); got[0] != 0 || got[1] != 0 {
		t.Errorf("marks of the new generation = %#x, want 0 after the mark was cleared while closed", got)
	}
	b.Close()
}

func TestBindOpenFailsAfterTheBirthplaceEnded(t *testing.T) {
	b := newBind(newLoopbackStack(t))
	fns, _, err := b.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	got := receiveOne(fns[0])
	b.birthplaceEnded()
	select {
	case r := <-got:
		if !errors.Is(r.err, net.ErrClosed) {
			t.Fatalf("receive after the end of the birthplace = %v, want net.ErrClosed", r.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the end of the birthplace did not close the sockets")
	}
	b.Close()
	if _, _, err := b.Open(0); !errors.As(err, new(*bindError)) || err.(*bindError).err != syserr.ErrNoNet {
		t.Fatalf("Open after the end of the birthplace = %v, want ENONET", err)
	}
}

// TestBindSendsEncryptedPacketsWithTheMark checks the effect that the mark has
// on the packets of the stack: a datagram that leaves through a link carries
// the mark, so a packet filter rule with "-m mark" sees it, and a datagram
// of a bind without a mark carries no mark.
func TestBindSendsEncryptedPacketsWithTheMark(t *testing.T) {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	t.Cleanup(func() { st.Close(); st.Wait() })
	out := channel.New(16, 1500, "")
	const nic tcpip.NICID = 1
	if err := st.CreateNIC(nic, out); err != nil {
		t.Fatalf("CreateNIC: %v", err)
	}
	local := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddrFrom4([4]byte{192, 0, 2, 1}).WithPrefix()}
	if err := st.AddProtocolAddress(nic, local, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress: %v", err)
	}
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: nic}})

	b := newBind(st)
	if _, _, err := b.Open(0); err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer b.Close()
	dst, _ := b.ParseEndpoint("198.51.100.7:51820")
	sendAndRead := func() uint32 {
		t.Helper()
		if err := b.Send([][]byte{[]byte("wireguard")}, dst); err != nil {
			t.Fatalf("Send: %v", err)
		}
		pkt := out.Read()
		if pkt == nil {
			t.Fatal("the link got no packet")
		}
		defer pkt.DecRef()
		return pkt.Mark
	}
	if got := sendAndRead(); got != 0 {
		t.Errorf("mark of a packet before SetMark = %#x, want 0", got)
	}
	b.setMark(0x51)
	if got := sendAndRead(); got != 0x51 {
		t.Errorf("mark of a packet after setMark(0x51) = %#x, want 0x51", got)
	}
	b.setMark(0)
	if got := sendAndRead(); got != 0 {
		t.Errorf("mark of a packet after setMark(0) = %#x, want 0", got)
	}
}
