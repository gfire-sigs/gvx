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
	"net"
	"strconv"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// quietPeriod is how long a test waits to prove that nothing arrives.
const quietPeriod = 300 * time.Millisecond

func TestNATQuiesceForSaveStopsTrafficBetweenGuestAndHost(t *testing.T) {
	host := newUDPEndpoint(t)
	s, nf, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		s.Close()
	}()
	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.addr().Port)}
	guest, err := gonet.DialUDP(s, nil, &gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	defer guest.Close()

	if _, err := guest.Write([]byte("before")); err != nil {
		t.Fatal(err)
	}
	if got, _ := host.recv(); got != "before" {
		t.Fatalf("host received %q, want before", got)
	}

	nf.QuiesceForSave()
	if _, err := guest.Write([]byte("during")); err != nil {
		t.Fatal(err)
	}
	if err := host.sock.SetReadDeadline(time.Now().Add(quietPeriod)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := host.sock.ReadFromUDP(make([]byte, 64)); err == nil {
		t.Fatalf("the host received %d bytes while the forwarder was quiesced", n)
	}

	if err := nf.ResumeAfterSave(); err != nil {
		t.Fatal(err)
	}
	if _, err := guest.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}
	if got, _ := host.recv(); got != "after" {
		t.Fatalf("host received %q after the resume, want after", got)
	}
}

func TestNATQuiesceForSaveRecoversTCPAfterResume(t *testing.T) {
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	received := make(chan string, 4)
	go func() {
		c, err := host.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		for {
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			received <- string(buf[:n])
		}
	}()

	s, nf, err := NewNATStack(NATConfig{})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		s.Close()
	}()
	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.Addr().(*net.TCPAddr).Port)}
	c, err := gonet.DialTCP(s, gw, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "one" {
		t.Fatalf("host received %q, want one", got)
	}

	nf.QuiesceForSave()
	if _, err := c.Write([]byte("two")); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-received:
		t.Fatalf("the host received %q while the forwarder was quiesced", got)
	case <-time.After(quietPeriod):
	}

	if err := nf.ResumeAfterSave(); err != nil {
		t.Fatal(err)
	}
	// TCP retransmits the held segment after the link comes back.
	select {
	case got := <-received:
		if got != "two" {
			t.Fatalf("host received %q after the resume, want two", got)
		}
	case <-time.After(testTimeout):
		t.Fatal("the held TCP segment never arrived after the resume")
	}
}

func TestPortForwarderQuiesceHoldsNewClientsUntilResume(t *testing.T) {
	s := newForwardStack(t)
	guestLn, err := gonet.ListenTCP(s, guestFullAddr(8090), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	tcpEchoServer(t, guestLn)
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	if err := pf.PreBind([]PortForwardRule{{Proto: "tcp", HostIP: "127.0.0.1", GuestPort: 8090}}); err != nil {
		t.Fatal(err)
	}
	pf.Start(s)
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(int(pf.BoundRules()[0].HostPort)))

	open := net.Conn(nil)
	if open, err = net.Dial("tcp", addr); err != nil {
		t.Fatal(err)
	}
	defer open.Close()
	roundTripTCP(t, open, []byte("running"))

	pf.QuiesceForSave()
	// An established relay holds its writes into the guest.
	if _, err := open.Write([]byte("held")); err != nil {
		t.Fatal(err)
	}
	// A new client connects but no relay starts.
	fresh, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if _, err := fresh.Write([]byte("fresh")); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]net.Conn{"established": open, "new": fresh} {
		_ = c.SetReadDeadline(time.Now().Add(quietPeriod))
		if n, err := c.Read(make([]byte, 16)); err == nil {
			t.Fatalf("the %s client got %d echoed bytes while the forwarder was quiesced", name, n)
		}
	}

	if err := pf.ResumeAfterSave(); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]net.Conn{"established": open, "new": fresh} {
		_ = c.SetReadDeadline(time.Now().Add(testTimeout))
		if n, err := c.Read(make([]byte, 16)); err != nil || n == 0 {
			t.Fatalf("the %s client got (%d, %v) after the resume, want an echo", name, n, err)
		}
	}
}
