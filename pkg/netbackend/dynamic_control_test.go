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
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func startTaggedTCPEchoServer(t *testing.T, s *stack.Stack, port uint16, tag string) {
	t.Helper()
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(:%d): %v", port, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil && !errors.Is(err, io.EOF) {
					return
				}
				_, _ = conn.Write([]byte(tag + ":" + string(buf[:n])))
			}(c)
		}
	}()
}

func startTaggedUDPEchoServer(t *testing.T, s *stack.Stack, port uint16, tag string) {
	t.Helper()
	addr := tcpip.FullAddress{Port: port}
	conn, err := gonet.DialUDP(s, &addr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP(:%d): %v", port, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo([]byte(tag+":"+string(buf[:n])), from)
		}
	}()
}

func dialAndReadTagTCP(t *testing.T, port uint16, msg string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), testTimeout)
	if err != nil {
		t.Fatalf("Dial 127.0.0.1:%d: %v", port, err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(testTimeout))
	if _, err := c.Write([]byte(msg)); err != nil {
		t.Fatalf("Write 127.0.0.1:%d: %v", port, err)
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		t.Fatalf("Read 127.0.0.1:%d: %v", port, err)
	}
	return string(buf[:n])
}

func TestDynamicControlAddReplaceLimitAndRemove(t *testing.T) {
	s := newForwardStack(t)
	startTaggedTCPEchoServer(t, s, 18081, "tcpA")
	startTaggedTCPEchoServer(t, s, 18082, "tcpB")
	startTaggedUDPEchoServer(t, s, 19091, "udpA")
	startTaggedUDPEchoServer(t, s, 19092, "udpB")

	tv, err := (tuning.Values{}).Set("net.forward.max_dynamic_ports", "2")
	if err != nil {
		t.Fatalf("tuning.Set(max_dynamic_ports): %v", err)
	}
	pf := NewPortForwarder(tv)
	t.Cleanup(func() { _ = pf.Close() })

	// Bind one static rule on an ephemeral host port targeting 18081.
	if err := pf.PreBind([]PortForwardRule{{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 18081,
	}}); err != nil {
		t.Fatalf("PreBind: %v", err)
	}
	staticPort := pf.BoundRules()[0].HostPort
	pf.Start(s)

	// Static rule conflict must fail even when replace is true.
	if _, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  staticPort,
		GuestPort: 18082,
	}, true, nil, nil); !errors.Is(err, ErrPortRuleExists) {
		t.Fatalf("AddDynamicRule colliding with static rule = %v, want ErrPortRuleExists", err)
	}

	// Add dynamic TCP rule #1 (slot 1 of 2).
	dynTCP, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 18081,
	}, false, nil, nil)
	if err != nil {
		t.Fatalf("AddDynamicRule(tcp #1): %v", err)
	}
	if got := dialAndReadTagTCP(t, dynTCP.HostPort, "hi"); got != "tcpA:hi" {
		t.Fatalf("tcp #1 reply = %q, want tcpA:hi", got)
	}

	// Duplicate dynamic binding with replace=false returns ErrPortRuleExists.
	if _, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  dynTCP.HostPort,
		GuestPort: 18082,
	}, false, nil, nil); !errors.Is(err, ErrPortRuleExists) {
		t.Fatalf("duplicate AddDynamicRule(replace=false) = %v, want ErrPortRuleExists", err)
	}

	// Replacing an existing dynamic TCP rule updates the guest target in place
	// without rebinding the host socket, so a failing listenTCP cannot drop it.
	failingTCP := func(network, address string) (net.Listener, error) {
		return nil, errors.New("unexpected rebind on in-place replace")
	}
	replacedTCP, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  dynTCP.HostPort,
		GuestPort: 18082,
	}, true, failingTCP, nil)
	if err != nil {
		t.Fatalf("AddDynamicRule(tcp replace=true): %v", err)
	}
	if replacedTCP.HostPort != dynTCP.HostPort || replacedTCP.GuestPort != 18082 {
		t.Fatalf("replacedTCP = %+v, want HostPort=%d GuestPort=18082", replacedTCP, dynTCP.HostPort)
	}
	if got := dialAndReadTagTCP(t, dynTCP.HostPort, "next"); got != "tcpB:next" {
		t.Fatalf("tcp #1 after in-place replace = %q, want tcpB:next", got)
	}

	// Failed bind for a brand-new host port leaves existing rules intact.
	newBindErr := errors.New("bind denied")
	if _, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 18081,
	}, true, func(string, string) (net.Listener, error) { return nil, newBindErr }, nil); !errors.Is(err, newBindErr) {
		t.Fatalf("AddDynamicRule new-port failure = %v, want %v", err, newBindErr)
	}
	if got := dialAndReadTagTCP(t, dynTCP.HostPort, "still-up"); got != "tcpB:still-up" {
		t.Fatalf("existing tcp rule after failed sibling bind = %q, want tcpB:still-up", got)
	}

	// Add dynamic UDP rule #2 (slot 2 of 2).
	dynUDP, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "udp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 19091,
	}, false, nil, nil)
	if err != nil {
		t.Fatalf("AddDynamicRule(udp #2): %v", err)
	}
	udpClient := newClientSocket(t)
	udpTarget := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(dynUDP.HostPort)}
	if _, err := udpClient.WriteToUDP([]byte("ping1"), udpTarget); err != nil {
		t.Fatalf("WriteToUDP(1): %v", err)
	}
	if got := recvFrom(t, udpClient); got != "udpA:ping1" {
		t.Fatalf("udp #2 reply = %q, want udpA:ping1", got)
	}

	// Slot limit (maxDynamicPorts=2) rejects a 3rd dynamic rule with ErrDynamicPortLimit.
	if _, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 18081,
	}, false, nil, nil); !errors.Is(err, ErrDynamicPortLimit) {
		t.Fatalf("3rd dynamic rule err = %v, want ErrDynamicPortLimit", err)
	}

	// Replacing UDP rule #2 at the slot limit succeeds in place and retargets
	// subsequent datagrams to udpB by evicting stale guest sessions.
	failingUDP := func(network, address string) (net.PacketConn, error) {
		return nil, errors.New("unexpected udp rebind on in-place replace")
	}
	if _, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "udp",
		HostIP:    "127.0.0.1",
		HostPort:  dynUDP.HostPort,
		GuestPort: 19092,
	}, true, nil, failingUDP); err != nil {
		t.Fatalf("AddDynamicRule(udp replace=true at limit): %v", err)
	}
	if _, err := udpClient.WriteToUDP([]byte("ping2"), udpTarget); err != nil {
		t.Fatalf("WriteToUDP(2): %v", err)
	}
	if got := recvFrom(t, udpClient); got != "udpB:ping2" {
		t.Fatalf("udp #2 after in-place replace = %q, want udpB:ping2", got)
	}

	// RemoveRule without force refuses to remove static rules; with force it succeeds.
	if _, err := pf.RemoveRule(PortForwardRule{Proto: "tcp", HostPort: staticPort}, false); !errors.Is(err, ErrStaticRuleRequiresForce) {
		t.Fatalf("RemoveRule(static, force=false) = %v, want ErrStaticRuleRequiresForce", err)
	}
	removedStatic, err := pf.RemoveRule(PortForwardRule{Proto: "tcp", HostPort: staticPort}, true)
	if err != nil || len(removedStatic) != 1 || removedStatic[0].Source != PortSourceStatic {
		t.Fatalf("RemoveRule(static, force=true) = (%+v, %v), want 1 static rule", removedStatic, err)
	}

	// RemoveRule on unknown port returns ErrPortRuleNotFound.
	if _, err := pf.RemoveRule(PortForwardRule{Proto: "tcp", HostPort: 65001}, false); !errors.Is(err, ErrPortRuleNotFound) {
		t.Fatalf("RemoveRule(unknown) = %v, want ErrPortRuleNotFound", err)
	}

	// RemoveAllDynamic removes both manual dynamic rules and leaves none.
	removedDyn := pf.RemoveAllDynamic()
	if len(removedDyn) != 2 {
		t.Fatalf("RemoveAllDynamic removed %d rules, want 2: %+v", len(removedDyn), removedDyn)
	}
	if rem := pf.BoundRulesWithSource(); len(rem) != 0 {
		t.Fatalf("BoundRulesWithSource after RemoveAllDynamic = %+v, want empty", rem)
	}
}

func TestDynamicControlPromotesAutoRuleInPlaceAndAttachStartsManualRules(t *testing.T) {
	s := newForwardStack(t)
	autoPort := reserveFreeLoopbackPort(t, "tcp")
	startTaggedTCPEchoServer(t, s, autoPort, "auto")

	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{PollInterval: time.Hour})
	pf.Start(s)

	// Wait for runDynamicLoop's initial reconcile so it is parked on the 1h
	// ticker before starting the secondary guest listener on 18083.
	waitUntil(t, testTimeout, "autoPort published as auto rule", func() bool {
		for _, br := range pf.BoundRulesWithSource() {
			if br.Rule.HostPort == autoPort && br.Source == PortSourceAuto {
				return true
			}
		}
		return false
	})
	startTaggedTCPEchoServer(t, s, 18083, "manual")

	if got := dialAndReadTagTCP(t, autoPort, "1"); got != "auto:1" {
		t.Fatalf("auto rule reply = %q, want auto:1", got)
	}

	// Explicit dynamic rule takes precedence over auto rule even with replace=false,
	// promoting the live listener in place without rebinding.
	promoted, err := pf.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  autoPort,
		GuestPort: 18083,
	}, false, func(string, string) (net.Listener, error) {
		return nil, errors.New("unexpected rebind during auto promotion")
	}, nil)
	if err != nil {
		t.Fatalf("AddDynamicRule promoting auto rule: %v", err)
	}
	if promoted.HostPort != autoPort || promoted.GuestPort != 18083 {
		t.Fatalf("promoted = %+v, want %d -> 18083", promoted, autoPort)
	}
	if got := dialAndReadTagTCP(t, autoPort, "2"); got != "manual:2" {
		t.Fatalf("promoted rule reply = %q, want manual:2", got)
	}
	rules := pf.BoundRulesWithSource()
	if len(rules) != 1 || rules[0].Source != PortSourceDynamic {
		t.Fatalf("BoundRulesWithSource after promotion = %+v, want 1 dynamic rule", rules)
	}

	// Verify AttachRestoredStack starts manual dynamic rules added before Start().
	pfPre := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pfPre.Close() })
	preRule, err := pfPre.AddDynamicRule(PortForwardRule{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: 18083,
	}, false, nil, nil)
	if err != nil {
		t.Fatalf("AddDynamicRule before start: %v", err)
	}
	if err := pfPre.AttachRestoredStack(s); err != nil {
		t.Fatalf("AttachRestoredStack: %v", err)
	}
	if got := dialAndReadTagTCP(t, preRule.HostPort, "restored"); got != "manual:restored" {
		t.Fatalf("pre-start dynamic rule after AttachRestoredStack = %q, want manual:restored", got)
	}
}

func TestRuntimeTuningSettersLiveAndRaceFree(t *testing.T) {
	s, nf, err := NewNATStack(NATConfig{
		IsolateLAN: false,
		DNSServers: []string{"127.0.0.1:1"},
	})
	if err != nil {
		t.Fatalf("NewNATStack: %v", err)
	}
	t.Cleanup(func() {
		_ = nf.Close()
		s.Close()
	})

	// Build a standard A query for host.docker.internal.
	qMsg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: 0x4242, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName("host.docker.internal."),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	rawQ, err := qMsg.Pack()
	if err != nil {
		t.Fatalf("pack DNS query: %v", err)
	}

	// Initially IsolateLAN is false: gateway resolves to 10.0.2.2 and 10.0.2.2 is routable.
	if nf.IsolateLAN() {
		t.Fatal("initial IsolateLAN() = true, want false")
	}
	if _, err := nf.ResolveOutboundTarget(netip.MustParseAddr(HostGatewayIPv4), 80); err != nil {
		t.Fatalf("ResolveOutboundTarget(gateway) with IsolateLAN=false: %v", err)
	}
	resp := nf.dnsRelay().answerQuery(t.Context(), rawQ, false)
	var parsed dnsmessage.Message
	if err := parsed.Unpack(resp); err != nil || parsed.RCode != dnsmessage.RCodeSuccess || len(parsed.Answers) != 1 {
		t.Fatalf("DNS host.docker.internal with IsolateLAN=false = (rcode=%v, answers=%d, err=%v)", parsed.RCode, len(parsed.Answers), err)
	}

	// Live toggle IsolateLAN=true: blocks outbound gateway and turns host.docker.internal into NXDOMAIN.
	nf.SetIsolateLAN(true)
	if !nf.IsolateLAN() {
		t.Fatal("IsolateLAN() after SetIsolateLAN(true) = false, want true")
	}
	if _, err := nf.ResolveOutboundTarget(netip.MustParseAddr(HostGatewayIPv4), 80); err == nil {
		t.Fatal("ResolveOutboundTarget(gateway) succeeded with IsolateLAN=true, want blocked")
	}
	respBlocked := nf.dnsRelay().answerQuery(t.Context(), rawQ, false)
	var parsedBlocked dnsmessage.Message
	if err := parsedBlocked.Unpack(respBlocked); err != nil || parsedBlocked.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("DNS host.docker.internal with IsolateLAN=true = (rcode=%v, err=%v), want NXDOMAIN", parsedBlocked.RCode, err)
	}

	// Live timeout setters update values and ignore non-positive values.
	nf.SetDialTimeout(3 * time.Second)
	nf.SetDialTimeout(0)
	if got := nf.dialTimeout(); got != 3*time.Second {
		t.Fatalf("dialTimeout = %v, want 3s", got)
	}
	nf.SetUDPIdleTimeout(12 * time.Second)
	nf.SetUDPIdleTimeout(-time.Second)
	if got := nf.udpIdleTimeout(); got != 12*time.Second {
		t.Fatalf("udpIdleTimeout = %v, want 12s", got)
	}
	nf.SetDNSTimeouts(4*time.Second, 2*time.Second)
	nf.SetDNSTimeouts(0, -1)
	if nf.dnsTimeout() != 4*time.Second || nf.dnsUpstreamTimeout() != 2*time.Second {
		t.Fatalf("dns timeouts = (%v, %v), want (4s, 2s)", nf.dnsTimeout(), nf.dnsUpstreamTimeout())
	}

	// Concurrent updates and reads across NATForwarder and PortForwarder under -race.
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{PollInterval: 500 * time.Millisecond})
	pf.Start(s)

	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := range 20 {
				nf.SetIsolateLAN((id+j)%2 == 0)
				_ = nf.IsolateLAN()
				nf.SetDialTimeout(time.Duration(j+1) * time.Millisecond)
				nf.SetUDPIdleTimeout(time.Duration(j+1) * time.Millisecond)
				nf.SetDNSTimeouts(time.Duration(j+1)*time.Millisecond, time.Duration(j+1)*time.Millisecond)
				_ = nf.dnsRelay()
				pf.SetGuestDialWindow(time.Duration(j+1) * time.Millisecond)
				pf.SetUDPIdleTimeout(time.Duration(j+1) * time.Millisecond)
				pf.SetDynamicPollInterval(time.Duration(j+50) * time.Millisecond)
			}
		}(i)
	}
	wg.Wait()
}
