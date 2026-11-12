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
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

var natDNSAddr = tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}), Port: 53}

// queryUDPDNS sends one query from a new guest source port and reports whether
// an answer arrives within wait. The connection stays open.
func queryUDPDNS(t *testing.T, s *stack.Stack, id uint16, wait time.Duration) (answered bool, closeConn func()) {
	t.Helper()
	u, err := gonet.DialUDP(s, nil, &natDNSAddr, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP: %v", err)
	}
	if _, err := u.Write(buildDNSQuery(id, "service.example.test", dnsTypeA)); err != nil {
		t.Fatalf("write query: %v", err)
	}
	_ = u.SetReadDeadline(time.Now().Add(wait))
	_, err = u.Read(make([]byte, 512))
	return err == nil, func() { _ = u.Close() }
}

func TestNATDNSFlowsAreBounded(t *testing.T) {
	srv := startFakeDNSServer(t, answerWith("198.51.100.42"))
	tuned, err := tuning.Values{}.WithDuration(tuning.DNSTimeout, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	s, nf, err := NewNATStack(NATConfig{DNSServers: []string{srv.addr}, Tuning: tuned})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	defer func() {
		_ = nf.Close()
		s.Close()
	}()
	const limit = 4
	nf.dnsFlowSem = make(chan struct{}, limit)

	// Each source port is one flow, and a flow holds its slot until it idles out.
	for i := range limit {
		ok, closeConn := queryUDPDNS(t, s, uint16(i), testTimeout)
		defer closeConn()
		if !ok {
			t.Fatalf("flow %d got no answer below the limit", i)
		}
	}
	if got := len(nf.dnsFlowSem); got != limit {
		t.Fatalf("DNS flow slots in use = %d, want %d", got, limit)
	}

	ok, closeConn := queryUDPDNS(t, s, 100, 300*time.Millisecond)
	defer closeConn()
	if ok {
		t.Fatal("a DNS flow beyond the limit got an answer, want it dropped")
	}
	if got := len(nf.dnsFlowSem); got > limit {
		t.Fatalf("DNS flow slots in use = %d, above the limit %d", got, limit)
	}

	// Idle flows free their slots after the DNS timeout.
	deadline := time.Now().Add(testTimeout)
	for len(nf.dnsFlowSem) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("DNS flow slots in use = %d after the idle timeout, want 0", len(nf.dnsFlowSem))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if ok, closeConn := queryUDPDNS(t, s, 200, testTimeout); !ok {
		t.Fatal("a DNS flow got no answer after the slots were freed")
	} else {
		closeConn()
	}
}

func TestNATTCPRelaysAreBounded(t *testing.T) {
	host, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer host.Close()
	go func() {
		for {
			c, err := host.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				buf := make([]byte, 1)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}()
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
	const limit = 2
	nf.tcpRelaySem = make(chan struct{}, limit)

	gw := tcpip.FullAddress{Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 2}), Port: uint16(host.Addr().(*net.TCPAddr).Port)}
	var conns []net.Conn
	for i := range limit {
		c, err := gonet.DialTCP(s, gw, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("dial %d below the limit: %v", i, err)
		}
		conns = append(conns, c)
	}
	if got := len(nf.tcpRelaySem); got != limit {
		t.Fatalf("TCP relay slots in use = %d, want %d", got, limit)
	}

	if c, err := gonet.DialTCP(s, gw, ipv4.ProtocolNumber); err == nil {
		_ = c.Close()
		t.Fatal("a TCP relay beyond the limit connected, want a reset")
	}

	// Closing one relay frees its slot for a new connection.
	_ = conns[0].Close()
	deadline := time.Now().Add(testTimeout)
	for {
		c, err := gonet.DialTCP(s, gw, ipv4.ProtocolNumber)
		if err == nil {
			conns = append(conns, c)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no TCP relay slot freed after a connection closed: %v", err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, c := range conns {
		_ = c.Close()
	}
}
