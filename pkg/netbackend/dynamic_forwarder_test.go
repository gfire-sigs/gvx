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
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/tcp"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

func reserveFreeLoopbackPort(t *testing.T, proto string) uint16 {
	t.Helper()
	if proto == "udp" {
		pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("ListenPacket(udp4): %v", err)
		}
		port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		_ = pc.Close()
		return port
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(tcp4): %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}

type fakeDstPortMatcher struct {
	start    uint16
	end      uint16
	inverted bool
}

func (f fakeDstPortMatcher) Name() string { return "fake-dst-port" }

func (f fakeDstPortMatcher) Match(stack.Hook, *stack.PacketBuffer, string, string) (bool, bool) {
	return false, false
}

func (f fakeDstPortMatcher) DestinationPortRange() (uint16, uint16, bool) {
	return f.start, f.end, f.inverted
}

func TestDynamicLoopbackPublishAndUnpublish(t *testing.T) {
	s := newForwardStack(t)
	portAny := reserveFreeLoopbackPort(t, "tcp")
	portLo := reserveFreeLoopbackPort(t, "tcp")
	if portLo == portAny {
		portLo = reserveFreeLoopbackPort(t, "tcp")
	}

	var mu sync.Mutex
	var events []string
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		PollInterval: 20 * time.Millisecond,
		OnPublish: func(r PortForwardRule, added bool) {
			mu.Lock()
			defer mu.Unlock()
			action := "del"
			if added {
				action = "add"
			}
			events = append(events, action+":"+r.Proto+":"+strconv.Itoa(int(r.HostPort)))
		},
	})
	pf.Start(s)

	// Start both a wildcard listener and a loopback-only listener in the guest.
	lnAny, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: portAny}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(:%d): %v", portAny, err)
	}
	tcpEchoServer(t, lnAny)

	lnLo, err := gonet.ListenTCP(s, guestLoopbackAddr(portLo), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(127.0.0.1:%d): %v", portLo, err)
	}
	tcpEchoServer(t, lnLo)

	hasBound := func(port uint16) bool {
		for _, r := range pf.BoundRules() {
			if r.Proto == "tcp" && r.HostPort == port && r.GuestPort == port {
				return true
			}
		}
		return false
	}
	waitUntil(t, testTimeout, "both dynamic ports bound", func() bool {
		return hasBound(portAny) && hasBound(portLo)
	})

	for _, tc := range []struct {
		port uint16
		msg  string
	}{
		{portAny, "dyn-wildcard"},
		{portLo, "dyn-loopback"},
	} {
		c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(tc.port))))
		if err != nil {
			t.Fatalf("Dial 127.0.0.1:%d: %v", tc.port, err)
		}
		roundTripTCP(t, c, []byte(tc.msg))
		_ = c.Close()
	}

	// Closing the guest listener unpublishes the dynamic host socket.
	_ = lnLo.Close()
	waitUntil(t, testTimeout, "loopback listener unpublished", func() bool {
		return !hasBound(portLo)
	})
	if !hasBound(portAny) {
		t.Fatalf("wildcard port %d disappeared when only loopback port closed", portAny)
	}
}

func TestDynamicLoopbackSkipsStaticRules(t *testing.T) {
	s := newForwardStack(t)
	staticGuestPort := reserveFreeLoopbackPort(t, "tcp")

	guestLn, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: staticGuestPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(:%d): %v", staticGuestPort, err)
	}
	tcpEchoServer(t, guestLn)

	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	// Bind static rule on ephemeral host port targeting staticGuestPort.
	if err := pf.PreBind([]PortForwardRule{{
		Proto:     "tcp",
		HostIP:    "127.0.0.1",
		HostPort:  0,
		GuestPort: staticGuestPort,
	}}); err != nil {
		t.Fatalf("PreBind: %v", err)
	}

	var dynBound bool
	var mu sync.Mutex
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		PollInterval: 20 * time.Millisecond,
		OnPublish: func(r PortForwardRule, added bool) {
			mu.Lock()
			defer mu.Unlock()
			if added && r.GuestPort == staticGuestPort {
				dynBound = true
			}
		},
	})
	pf.Start(s)

	// Force several reconciliation cycles and confirm the static port is never shadowed.
	pf.reconcileDynamicPorts()
	pf.reconcileDynamicPorts()

	mu.Lock()
	gotDyn := dynBound
	mu.Unlock()
	if gotDyn {
		t.Fatalf("dynamic publish bound guest port %d despite static PreBind rule", staticGuestPort)
	}
	if got := len(pf.BoundRules()); got != 1 {
		t.Fatalf("BoundRules len = %d, want 1 (static only)", got)
	}
}

func TestDynamicLoopbackRespectsMaxPortsAndBindConflict(t *testing.T) {
	s := newForwardStack(t)

	// Reserve three distinct ports and sort ascending so reconcileDynamicPorts
	// always visits busyPort first, then middlePort, then highestPort.
	portSet := make(map[uint16]struct{}, 3)
	var ports []uint16
	for len(ports) < 3 {
		p := reserveFreeLoopbackPort(t, "tcp")
		if _, dup := portSet[p]; !dup {
			portSet[p] = struct{}{}
			ports = append(ports, p)
		}
	}
	slices.Sort(ports)
	busyPort, middlePort, highestPort := ports[0], ports[1], ports[2]

	busyLn, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(busyPort))))
	if err != nil {
		t.Fatalf("occupy 127.0.0.1:%d: %v", busyPort, err)
	}
	t.Cleanup(func() { _ = busyLn.Close() })

	for _, p := range ports {
		ln, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: p}, ipv4.ProtocolNumber)
		if err != nil {
			t.Fatalf("ListenTCP(:%d): %v", p, err)
		}
		t.Cleanup(func() { _ = ln.Close() })
	}

	var mu sync.Mutex
	errCalls := 0
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		MaxPorts:     1,
		PollInterval: time.Hour,
		OnBindError: func(proto string, port uint16, err error) {
			mu.Lock()
			defer mu.Unlock()
			if proto == "tcp" && port == busyPort && err != nil {
				errCalls++
			}
		},
	})
	pf.Start(s)

	// Reconcile 3 times:
	// - pass 1 attempts busyPort, records failure, and notifies OnBindError once;
	// - pass 2 skips busyPort and binds middlePort (hitting MaxPorts=1);
	// - pass 3 keeps middlePort bound and never re-notifies OnBindError or binds highestPort.
	pf.reconcileDynamicPorts()
	pf.reconcileDynamicPorts()
	pf.reconcileDynamicPorts()

	rules := pf.BoundRules()
	if len(rules) != 1 || rules[0].HostPort != middlePort {
		t.Fatalf("BoundRules = %+v, want single dynamic rule on port %d (not %d or %d)", rules, middlePort, busyPort, highestPort)
	}
	mu.Lock()
	gotErrs := errCalls
	mu.Unlock()
	if gotErrs != 1 {
		t.Fatalf("OnBindError fired %d times for busy port %d, want exactly 1", gotErrs, busyPort)
	}
}

// embeddedDNATTarget mirrors pkg/sentry/socket/netfilter.dnatTarget, which
// embeds stack.DNATTarget rather than using *stack.DNATTarget directly.
type embeddedDNATTarget struct {
	stack.DNATTarget
	revision uint8
}

func TestDiscoverGuestPublishedPortsIPTablesDNAT(t *testing.T) {
	s := newForwardStack(t)
	it := s.IPTables()
	nat := it.GetTable(stack.NATID, false)

	dnatTarget := &embeddedDNATTarget{
		DNATTarget: stack.DNATTarget{
			Addr:            tcpip.AddrFrom4([4]byte{172, 17, 0, 2}),
			Port:            80,
			NetworkProtocol: header.IPv4ProtocolNumber,
		},
		revision: 0,
	}

	// Wildcard TCP DNAT (matches 10.0.2.15), explicit 127.0.0.1 UDP DNAT,
	// and a cluster-CIDR DNAT rule (10.96.0.0/16) that must be ignored.
	nat.Rules = append(nat.Rules,
		stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
			},
			Matchers: []stack.Matcher{fakeDstPortMatcher{start: 8081, end: 8081}},
			Target:   dnatTarget,
		},
		stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.UDPProtocolNumber,
				CheckProtocol: true,
				Dst:           guestLoopbackIPv4,
				DstMask:       tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
			},
			Matchers: []stack.Matcher{fakeDstPortMatcher{start: 5353, end: 5353}},
			Target:   dnatTarget,
		},
		stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
				Dst:           tcpip.AddrFrom4([4]byte{10, 96, 0, 0}),
				DstMask:       tcpip.AddrFrom4([4]byte{255, 255, 0, 0}),
			},
			Matchers: []stack.Matcher{fakeDstPortMatcher{start: 9090, end: 9090}},
			Target:   dnatTarget,
		},
		stack.Rule{
			Filter: stack.IPHeaderFilter{
				Protocol:      header.TCPProtocolNumber,
				CheckProtocol: true,
				DstInvert:     true,
			},
			Matchers: []stack.Matcher{fakeDstPortMatcher{start: 9091, end: 9091}},
			Target:   dnatTarget,
		},
	)
	it.ForceReplaceTable(stack.NATID, nat, false)

	got := discoverGuestPublishedPorts(s)
	if ip, ok := got[dynPortKey{proto: "tcp", port: 8081}]; !ok || ip != DefaultGuestIPv4 {
		t.Fatalf("tcp/8081 = (%q, %v), want (%q, true)", ip, ok, DefaultGuestIPv4)
	}
	if ip, ok := got[dynPortKey{proto: "udp", port: 5353}]; !ok || ip != "127.0.0.1" {
		t.Fatalf("udp/5353 = (%q, %v), want (%q, true)", ip, ok, "127.0.0.1")
	}
	if _, ok := got[dynPortKey{proto: "tcp", port: 9090}]; ok {
		t.Fatal("cluster CIDR 10.96.0.0/16 DNAT rule was discovered, want ignored")
	}
	if _, ok := got[dynPortKey{proto: "tcp", port: 9091}]; ok {
		t.Fatal("inverted destination DNAT rule was discovered, want ignored")
	}
}

func TestDynamicLoopbackCustomListenError(t *testing.T) {
	s := newForwardStack(t)
	ln, err := gonet.ListenTCP(s, tcpip.FullAddress{Port: 25511}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	wantErr := errors.New("denied by policy")
	var gotErr error
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		PollInterval: time.Hour,
		ListenTCP: func(network, address string) (net.Listener, error) {
			return nil, wantErr
		},
		OnBindError: func(proto string, port uint16, err error) {
			gotErr = err
		},
	})
	pf.Start(s)
	pf.reconcileDynamicPorts()
	if !errors.Is(gotErr, wantErr) {
		t.Fatalf("OnBindError = %v, want %v", gotErr, wantErr)
	}
}

func TestDynamicUDPUnpublishAndCloseDoesNotBlock(t *testing.T) {
	s := newForwardStack(t)
	udpPort := reserveFreeLoopbackPort(t, "udp")

	loAddr := guestLoopbackAddr(udpPort)
	guestConn, err := gonet.DialUDP(s, &loAddr, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("DialUDP(127.0.0.1:%d): %v", udpPort, err)
	}
	guestDone := make(chan struct{})
	t.Cleanup(func() {
		_ = guestConn.Close()
		<-guestDone
	})
	go func() {
		defer close(guestDone)
		buf := make([]byte, 2048)
		for {
			n, from, err := guestConn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = guestConn.WriteTo(buf[:n], from)
		}
	}()

	it := s.IPTables()
	origNat := it.GetTable(stack.NATID, false)
	withRule := it.GetTable(stack.NATID, false)
	withRule.Rules = append(withRule.Rules, stack.Rule{
		Filter: stack.IPHeaderFilter{
			Protocol:      header.UDPProtocolNumber,
			CheckProtocol: true,
			Dst:           guestLoopbackIPv4,
			DstMask:       tcpip.AddrFrom4([4]byte{255, 255, 255, 255}),
		},
		Matchers: []stack.Matcher{fakeDstPortMatcher{start: udpPort, end: udpPort}},
		Target:   &embeddedDNATTarget{DNATTarget: stack.DNATTarget{NetworkProtocol: header.IPv4ProtocolNumber}},
	})
	it.ForceReplaceTable(stack.NATID, withRule, false)

	// Use a long UDP idle timeout so an orphaned session would stall Close().
	tv, err := (tuning.Values{}).Set("net.udp.idle_timeout", "30s")
	if err != nil {
		t.Fatal(err)
	}
	pf := NewPortForwarder(tv)
	pf.EnableDynamicLoopback(DynamicForwardOptions{PollInterval: time.Hour})
	pf.Start(s)
	pf.reconcileDynamicPorts()

	// Send one datagram so a runUDPSession goroutine is live.
	client := newClientSocket(t)
	target := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(udpPort)}
	if _, err := client.WriteToUDP([]byte("dyn-udp-ping"), target); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}
	if got := recvFrom(t, client); got != "dyn-udp-ping" {
		t.Fatalf("UDP reply = %q, want %q", got, "dyn-udp-ping")
	}

	// Remove the DNAT rule and reconcile to unpublish the dynamic UDP forward.
	it.ForceReplaceTable(stack.NATID, origNat, false)
	pf.reconcileDynamicPorts()

	closeDone := make(chan error, 1)
	go func() { closeDone <- pf.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close after dynamic UDP unpublish: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("PortForwarder.Close blocked after dynamic UDP unpublish (orphaned UDP session)")
	}
}

func TestDynamicLoopbackSkipsIPv6OnlyAndReconcilesGuestIPChange(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(LoopbackNICID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(lo): %s", err)
	}
	if err := s.CreateNIC(Eth0NICID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(eth0): %s", err)
	}
	if err := s.AddProtocolAddress(LoopbackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: guestLoopbackIPv4, PrefixLen: 8},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(lo v4): %s", err)
	}
	if err := s.AddProtocolAddress(LoopbackNICID, tcpip.ProtocolAddress{
		Protocol:          ipv6.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: header.IPv6Loopback, PrefixLen: 128},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(lo v6): %s", err)
	}
	if err := s.AddProtocolAddress(Eth0NICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: defaultGuestIPv4Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(eth0 v4): %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: header.IPv4EmptySubnet, NIC: Eth0NICID},
		{Destination: header.IPv6EmptySubnet, NIC: LoopbackNICID},
	})

	// 1. An IPv6-only [::1] listener must not be published as an IPv4 forward.
	v6Port := reserveFreeLoopbackPort(t, "tcp")
	v6Ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: LoopbackNICID, Addr: header.IPv6Loopback, Port: v6Port}, ipv6.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP([::1]:%d): %v", v6Port, err)
	}
	t.Cleanup(func() { _ = v6Ln.Close() })

	if got := discoverGuestPublishedPorts(s); len(got) != 0 {
		t.Fatalf("discoverGuestPublishedPorts for [::1]-only listener = %+v, want empty", got)
	}

	// 2. When a guest port moves from 127.0.0.1 to 10.0.2.15 between ticks,
	// reconcileDynamicPorts updates the active dynamic forward's GuestIP.
	port := reserveFreeLoopbackPort(t, "tcp")
	loLn, err := gonet.ListenTCP(s, guestLoopbackAddr(port), ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(127.0.0.1:%d): %v", port, err)
	}
	tcpEchoServer(t, loLn)

	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{PollInterval: time.Hour})
	pf.Start(s)
	pf.reconcileDynamicPorts()

	rules := pf.BoundRules()
	if len(rules) != 1 || rules[0].GuestIP != "127.0.0.1" {
		t.Fatalf("initial BoundRules = %+v, want GuestIP=127.0.0.1", rules)
	}

	_ = loLn.Close()
	eth0Ln, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: Eth0NICID, Addr: defaultGuestIPv4Addr, Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP(10.0.2.15:%d): %v", port, err)
	}
	tcpEchoServer(t, eth0Ln)

	pf.reconcileDynamicPorts()
	rules = pf.BoundRules()
	if len(rules) != 1 || rules[0].GuestIP != DefaultGuestIPv4 {
		t.Fatalf("updated BoundRules = %+v, want GuestIP=%s", rules, DefaultGuestIPv4)
	}
	c, err := net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
	if err != nil {
		t.Fatalf("Dial after GuestIP transition: %v", err)
	}
	roundTripTCP(t, c, []byte("after-ip-switch"))
	_ = c.Close()
}

func TestDynamicForwarderCustomBindIPAndBindError(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})
	t.Cleanup(s.Close)
	if err := s.CreateNIC(Eth0NICID, loopback.New()); err != nil {
		t.Fatalf("CreateNIC(eth0): %s", err)
	}
	if err := s.AddProtocolAddress(Eth0NICID, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: defaultGuestIPv4Addr, PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(eth0): %s", err)
	}
	s.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: Eth0NICID}})

	busyLn, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatalf("Listen busy: %v", err)
	}
	t.Cleanup(func() { _ = busyLn.Close() })
	busyPort := uint16(busyLn.Addr().(*net.TCPAddr).Port)
	freePort := reserveFreeLoopbackPort(t, "tcp")
	for freePort == busyPort {
		freePort = reserveFreeLoopbackPort(t, "tcp")
	}

	guestFreeLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: Eth0NICID, Addr: defaultGuestIPv4Addr, Port: freePort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP free: %v", err)
	}
	tcpEchoServer(t, guestFreeLn)

	guestBusyLn, err := gonet.ListenTCP(s, tcpip.FullAddress{NIC: Eth0NICID, Addr: defaultGuestIPv4Addr, Port: busyPort}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("ListenTCP busy: %v", err)
	}
	tcpEchoServer(t, guestBusyLn)

	var cbMu sync.Mutex
	var published []PortForwardRule
	var removed []PortForwardRule
	var bindErrs []uint16
	pf := NewPortForwarder(tuning.Values{})
	t.Cleanup(func() { _ = pf.Close() })
	pf.EnableDynamicLoopback(DynamicForwardOptions{
		BindIP:       "0.0.0.0",
		PollInterval: time.Hour,
		OnPublish: func(rule PortForwardRule, added bool) {
			cbMu.Lock()
			defer cbMu.Unlock()
			if added {
				published = append(published, rule)
			} else {
				removed = append(removed, rule)
			}
		},
		OnBindError: func(_ string, port uint16, _ error) {
			cbMu.Lock()
			defer cbMu.Unlock()
			bindErrs = append(bindErrs, port)
		},
	})
	pf.Start(s)
	pf.reconcileDynamicPorts()

	cbMu.Lock()
	gotPublished := slices.Clone(published)
	gotBindErrs := slices.Clone(bindErrs)
	cbMu.Unlock()
	if len(gotPublished) != 1 || gotPublished[0].HostIP != "0.0.0.0" || gotPublished[0].HostPort != freePort {
		t.Fatalf("published = %+v, want HostIP=0.0.0.0 HostPort=%d", gotPublished, freePort)
	}
	if len(gotBindErrs) != 1 || gotBindErrs[0] != busyPort {
		t.Fatalf("bindErrs = %v, want [%d]", gotBindErrs, busyPort)
	}
	c, err := net.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(freePort))))
	if err != nil {
		t.Fatalf("Dial 127.0.0.1:%d: %v", freePort, err)
	}
	roundTripTCP(t, c, []byte("custom-bind-ip"))
	_ = c.Close()

	_ = guestFreeLn.Close()
	pf.reconcileDynamicPorts()
	cbMu.Lock()
	gotRemoved := slices.Clone(removed)
	cbMu.Unlock()
	if len(gotRemoved) != 1 || gotRemoved[0].HostIP != "0.0.0.0" || gotRemoved[0].HostPort != freePort {
		t.Fatalf("removed = %+v, want HostIP=0.0.0.0 HostPort=%d", gotRemoved, freePort)
	}
}
