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
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

const dnsPolicyDefaultDrop = "*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n:OUTPUT DROP [0:0]\n"

func dnsPolicyGuestRules(network string) string {
	return fmt.Sprintf("-A INPUT -s 10.0.2.15 -d 10.0.2.3 -p %[1]s -m %[1]s --dport 53 -j ACCEPT\n"+
		"-A OUTPUT -s 10.0.2.3 -d 10.0.2.15 -p %[1]s -m %[1]s --sport 53 -j ACCEPT\n", network)
}

func dnsPolicyUpstreamInput(network, server string) string {
	return fmt.Sprintf("-A INPUT -d 127.0.0.1 -p %[1]s -m %[1]s --dport %[2]d -j ACCEPT\n",
		network, netip.MustParseAddrPort(server).Port())
}

func dnsPolicyUpstreamOutput(network, server string) string {
	return fmt.Sprintf("-A OUTPUT -s 127.0.0.1 -d 127.0.0.1 -p %[1]s -m %[1]s --sport %[2]d --dport 1:65535 -j ACCEPT\n",
		network, netip.MustParseAddrPort(server).Port())
}

func dialProtectedDNS(t *testing.T, network, rules string, control netip.AddrPort, cfg NATConfig) net.Conn {
	t.Helper()
	compiled, err := CompilePolicy(PolicyConfig{
		RulesV4: dnsPolicyDefaultDrop + rules + "COMMIT\n",
		RulesV6: dnsPolicyDefaultDrop + "COMMIT\n",
	})
	if err != nil {
		t.Fatalf("compile DNS policy: %v", err)
	}
	policy := NewNATPolicy(compiled, control)
	t.Cleanup(policy.Close)
	cfg.Policy = policy
	guestStack, nf, err := NewNATStack(cfg)
	if err != nil {
		t.Fatalf("start protected NAT: %v", err)
	}
	t.Cleanup(func() {
		_ = nf.Close()
		guestStack.Close()
	})
	dns := tcpip.FullAddress{NIC: Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}), Port: 53}
	ctx, cancel := context.WithTimeout(t.Context(), testTimeout)
	defer cancel()
	var conn net.Conn
	if network == "tcp" {
		conn, err = gonet.DialContextTCP(ctx, guestStack, dns, ipv4.ProtocolNumber)
	} else {
		conn, err = gonet.DialUDP(guestStack, nil, &dns, ipv4.ProtocolNumber)
	}
	if err != nil {
		t.Fatalf("dial virtual DNS over %s: %v", network, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return conn
}

func queryProtectedDNS(t *testing.T, network, name string, servers []string, rules string, control netip.AddrPort) []netip.Addr {
	t.Helper()
	conn := dialProtectedDNS(t, network, rules, control, NATConfig{DNSServers: servers})

	query := buildDNSQuery(0x7777, name, dnsTypeA)
	wire := query
	if network == "tcp" {
		wire = append(binary.BigEndian.AppendUint16(nil, uint16(len(query))), query...)
	}
	if _, err := conn.Write(wire); err != nil {
		t.Fatalf("send guest %s DNS query: %v", network, err)
	}
	var response []byte
	if network == "tcp" {
		var length [2]byte
		if _, err := io.ReadFull(conn, length[:]); err != nil {
			t.Fatalf("read guest TCP DNS length: %v", err)
		}
		response = make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(conn, response); err != nil {
			t.Fatalf("read guest TCP DNS reply: %v", err)
		}
	} else {
		var buf [512]byte
		n, err := conn.Read(buf[:])
		if err != nil {
			t.Fatalf("read guest UDP DNS reply: %v", err)
		}
		response = buf[:n]
	}
	return answerIPs(t, response)
}

func TestNATDNSPolicyRequiresBothUpstreamDirections(t *testing.T) {
	for _, network := range []string{"udp", "tcp"} {
		t.Run(network, func(t *testing.T) {
			blockedRequest := startFakeDNSServer(t, answerWith("192.0.2.10"))
			blockedReply := startFakeDNSServer(t, answerWith("192.0.2.20"))
			allowed := startFakeDNSServer(t, answerWith("192.0.2.30"))
			rules := dnsPolicyGuestRules(network) +
				dnsPolicyUpstreamInput(network, blockedReply.addr) +
				dnsPolicyUpstreamInput(network, allowed.addr) +
				dnsPolicyUpstreamOutput(network, allowed.addr)
			servers := []string{blockedRequest.addr, blockedReply.addr, allowed.addr}
			got := queryProtectedDNS(t, network, "service.example.test", servers, rules, netip.AddrPort{})
			if want := []netip.Addr{netip.MustParseAddr("192.0.2.30")}; !slices.Equal(got, want) {
				t.Errorf("guest answers = %v, want %v from the permitted upstream", got, want)
			}
			if got := blockedRequest.queries.Load(); got != 0 {
				t.Errorf("upstream with denied INPUT received %d queries, want 0", got)
			}
			if got := blockedReply.queries.Load(); got != 1 {
				t.Errorf("upstream with denied OUTPUT received %d queries, want 1", got)
			}
			if got := allowed.queries.Load(); got != 1 {
				t.Errorf("permitted upstream received %d queries, want 1", got)
			}
		})
	}
}

func TestNATDNSPolicyAuthorizesEachTCPRetry(t *testing.T) {
	t.Run("firewall", func(t *testing.T) { testNATDNSPolicyTCPRetry(t, false) })
	t.Run("management", func(t *testing.T) { testNATDNSPolicyTCPRetry(t, true) })
}

func testNATDNSPolicyTCPRetry(t *testing.T, permitFirstTCP bool) {
	t.Helper()
	truncatedAnswer := func(req []byte) []byte {
		resp := answerWith("192.0.2.1")(req, false)
		binary.BigEndian.PutUint16(resp[2:4], binary.BigEndian.Uint16(resp[2:4])|dnsFlagTC)
		return resp
	}
	udp, tcp, err := listenUDPAndTCP()
	if err != nil {
		t.Fatalf("listen with UDP and TCP on one port: %v", err)
	}
	blockedRetry := tcp.Addr().String()
	var upstreamErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		var buf [512]byte
		n, peer, err := udp.ReadFrom(buf[:])
		if err != nil {
			upstreamErr = err
			return
		}
		_, upstreamErr = udp.WriteTo(truncatedAnswer(buf[:n]), peer)
	}()
	t.Cleanup(func() {
		_ = udp.Close()
		_ = tcp.Close()
		<-done
	})
	allowed := startFakeDNSServer(t, func(req []byte, viaTCP bool) []byte {
		if !viaTCP {
			return truncatedAnswer(req)
		}
		return answerWith("192.0.2.200")(req, viaTCP)
	})
	rules := dnsPolicyGuestRules("udp") +
		dnsPolicyUpstreamInput("udp", blockedRetry) + dnsPolicyUpstreamOutput("udp", blockedRetry) +
		dnsPolicyUpstreamInput("udp", allowed.addr) + dnsPolicyUpstreamOutput("udp", allowed.addr) +
		dnsPolicyUpstreamInput("tcp", allowed.addr) + dnsPolicyUpstreamOutput("tcp", allowed.addr)
	var control netip.AddrPort
	if permitFirstTCP {
		rules += dnsPolicyUpstreamInput("tcp", blockedRetry) + dnsPolicyUpstreamOutput("tcp", blockedRetry)
		control = netip.MustParseAddrPort(blockedRetry)
	}
	got := queryProtectedDNS(t, "udp", "large.example.test", []string{blockedRetry, allowed.addr}, rules, control)
	if want := []netip.Addr{netip.MustParseAddr("192.0.2.200")}; !slices.Equal(got, want) {
		t.Errorf("guest answers = %v, want %v from the permitted TCP retry", got, want)
	}
	if got := allowed.queries.Load(); got != 2 {
		t.Errorf("permitted upstream received %d queries, want one UDP and one TCP query", got)
	}
	select {
	case <-done:
		if upstreamErr != nil {
			t.Fatalf("serve UDP answer for denied TCP retry: %v", upstreamErr)
		}
	case <-time.After(testTimeout):
		t.Fatal("first upstream did not receive the permitted UDP query")
	}

	listener := tcp.(*net.TCPListener)
	if err := listener.SetDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	conn, err := listener.AcceptTCP()
	if err == nil {
		_ = conn.Close()
		t.Fatal("first upstream accepted a TCP connection despite the denied retry")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("accept denied TCP connection: %v, want deadline expiry", err)
	}
}

func TestNATDNSPolicyAllowsLocalReplyWithOnlyGuestRules(t *testing.T) {
	upstream := startFakeDNSServer(t, answerWith("192.0.2.10"))
	got := queryProtectedDNS(t, "tcp", "localhost", []string{upstream.addr}, dnsPolicyGuestRules("tcp"), netip.AddrPort{})
	if want := []netip.Addr{netip.MustParseAddr("127.0.0.1")}; !slices.Equal(got, want) {
		t.Errorf("guest answers = %v, want local answer %v", got, want)
	}
	if got := upstream.queries.Load(); got != 0 {
		t.Errorf("upstream received %d queries for locally answered name, want 0", got)
	}
}

func TestNATDNSPolicyDropsOversizedGuestDatagram(t *testing.T) {
	tuned, err := tuning.Values{}.WithInt(tuning.NATMTU, 8192)
	if err != nil {
		t.Fatal(err)
	}
	upstream := startFakeDNSServer(t, answerWith("192.0.2.10"))
	conn := dialProtectedDNS(t, "udp", dnsPolicyGuestRules("udp"), netip.AddrPort{}, NATConfig{
		DNSServers: []string{upstream.addr},
		Tuning:     tuned,
	})
	oversized := make([]byte, 4097)
	copy(oversized, buildDNSQuery(0x1234, "localhost", dnsTypeA))
	if _, err := conn.Write(oversized); err != nil {
		t.Fatalf("send oversized DNS query: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var buf [512]byte
	var timeout net.Error
	if _, err := conn.Read(buf[:]); !errors.As(err, &timeout) || !timeout.Timeout() {
		t.Fatalf("read reply to oversized DNS query: %v, want deadline expiry", err)
	}

	if err := conn.SetReadDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(buildDNSQuery(0x4321, "localhost", dnsTypeA)); err != nil {
		t.Fatalf("send valid DNS query after oversized query: %v", err)
	}
	n, err := conn.Read(buf[:])
	if err != nil {
		t.Fatalf("read reply to valid DNS query: %v", err)
	}
	if n < 2 || binary.BigEndian.Uint16(buf[:2]) != 0x4321 {
		t.Fatalf("read reply %x, want transaction ID 0x4321", buf[:n])
	}
}
