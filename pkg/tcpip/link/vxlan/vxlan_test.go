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

package vxlan

import (
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/ethernet"
	"z.gfire.dev/gvx/pkg/tcpip/link/pipe"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
	"z.gfire.dev/gvx/pkg/tcpip/transport/udp"
)

const (
	underlayNIC tcpip.NICID = 1
	overlayNIC  tcpip.NICID = 2
)

func ip4(a, b, c, d byte) tcpip.Address { return tcpip.AddrFrom4([4]byte{a, b, c, d}) }

// node is one network stack with an underlay link and a vxlan link.
type node struct {
	stack    *stack.Stack
	vxlan    *Endpoint
	underlay tcpip.Address
	overlay  tcpip.Address
}

// newNodes returns two stacks that a pipe links. The underlay addresses are
// 10.0.0.1 and 10.0.0.2. Each stack has a vxlan link with the overlay address
// 192.168.1.1 or 192.168.1.2.
func newNodes(t *testing.T, cfgA, cfgB Config) (a, b *node) {
	t.Helper()
	pa, pb := pipe.New("\x02\x00\x00\x00\x00\x01", "\x02\x00\x00\x00\x00\x02", 1514)
	mk := func(p *pipe.Endpoint, under, over tcpip.Address, cfg Config) *node {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		})
		if err := s.CreateNIC(underlayNIC, ethernet.New(p)); err != nil {
			t.Fatalf("CreateNIC(underlay): %v", err)
		}
		addAddress := func(nic tcpip.NICID, addr tcpip.Address) {
			pa := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr, PrefixLen: 24}}
			if err := s.AddProtocolAddress(nic, pa, stack.AddressProperties{}); err != nil {
				t.Fatalf("AddProtocolAddress(%d): %v", nic, err)
			}
		}
		addAddress(underlayNIC, under)
		cfg.ID = overlayNIC
		cfg.Local = under
		ep, err := New(s, cfg)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if err := s.CreateNIC(overlayNIC, ep); err != nil {
			t.Fatalf("CreateNIC(vxlan): %v", err)
		}
		addAddress(overlayNIC, over)
		s.SetRouteTable([]tcpip.Route{
			subnetRoute(under, underlayNIC),
			subnetRoute(over, overlayNIC),
		})
		t.Cleanup(func() {
			s.Close()
			s.Wait()
		})
		return &node{stack: s, vxlan: ep, underlay: under, overlay: over}
	}
	return mk(pa, ip4(10, 0, 0, 1), ip4(192, 168, 1, 1), cfgA), mk(pb, ip4(10, 0, 0, 2), ip4(192, 168, 1, 2), cfgB)
}

// subnetRoute returns the route of the /24 around addr.
func subnetRoute(addr tcpip.Address, nic tcpip.NICID) tcpip.Route {
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{addr.As4()[0], addr.As4()[1], addr.As4()[2], 0}), tcpip.MaskFromBytes([]byte{255, 255, 255, 0}))
	if err != nil {
		panic(err)
	}
	return tcpip.Route{Destination: subnet, NIC: nic}
}

// connect gives each node a permanent neighbor entry and an FDB entry for the
// other node, as flannel does.
func connect(t *testing.T, a, b *node) {
	t.Helper()
	for _, p := range []struct{ from, to *node }{{a, b}, {b, a}} {
		mac := p.to.vxlan.LinkAddress()
		if err := p.from.stack.AddStaticNeighbor(overlayNIC, ipv4.ProtocolNumber, p.to.overlay, mac); err != nil {
			t.Fatalf("AddStaticNeighbor: %v", err)
		}
		r := Remote{IP: p.to.underlay, Port: p.to.vxlan.Config().Port, VNI: p.to.vxlan.Config().VNI}
		if err := p.from.vxlan.FDBUpdate(mac, NUDPermanent, NTFSelf, r, UpdateMode{Create: true}); err != nil {
			t.Fatalf("FDBUpdate: %v", err)
		}
	}
}

// echo sends one datagram from a to b over the overlay and reports whether b
// receives it within the timeout.
func echo(t *testing.T, a, b *node, port uint16, payload string, timeout time.Duration) bool {
	t.Helper()
	l, err := gonet.DialUDP(b.stack, &tcpip.FullAddress{NIC: overlayNIC, Addr: b.overlay, Port: port}, nil, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	c, err := gonet.DialUDP(a.stack, &tcpip.FullAddress{Addr: a.overlay}, &tcpip.FullAddress{Addr: b.overlay, Port: port}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(payload)); err != nil {
		t.Fatalf("write: %v", err)
	}
	l.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 128)
	n, err := l.Read(buf)
	return err == nil && string(buf[:n]) == payload
}

func TestDatagramCrossesTheTunnel(t *testing.T) {
	a, b := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789})
	connect(t, a, b)
	if !echo(t, a, b, 9000, "hello", 5*time.Second) {
		t.Fatal("datagram from A did not reach B")
	}
	if !echo(t, b, a, 9001, "again", 5*time.Second) {
		t.Fatal("datagram from B did not reach A")
	}
}

func TestMTUDefaultsToTheUnderlayMTUMinusOverhead(t *testing.T) {
	a, _ := newNodes(t, Config{VNI: 1, Port: 4789, Link: underlayNIC}, Config{VNI: 1, Port: 4789})
	if got, want := a.vxlan.MTU(), uint32(1500-Overhead4); got != want {
		t.Errorf("MTU with an underlay link = %d, want %d", got, want)
	}
	_, b := newNodes(t, Config{VNI: 1, Port: 4789}, Config{VNI: 1, Port: 4789, MTU: 1400})
	if got := b.vxlan.MTU(); got != 1400 {
		t.Errorf("MTU = %d, want the configured 1400", got)
	}
}

func TestDeletingTheFDBEntryStopsTheTraffic(t *testing.T) {
	a, b := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789})
	connect(t, a, b)
	if !echo(t, a, b, 9000, "one", 5*time.Second) {
		t.Fatal("datagram did not cross before the removal")
	}
	if err := a.vxlan.FDBDelete(b.vxlan.LinkAddress(), Remote{}); err != nil {
		t.Fatalf("FDBDelete: %v", err)
	}
	if echo(t, a, b, 9000, "two", 500*time.Millisecond) {
		t.Fatal("datagram crossed after the FDB entry was removed")
	}
}

func TestFramesWithAnotherVNIAreDropped(t *testing.T) {
	a, b := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 8, Port: 4789})
	connect(t, a, b)
	// connect names the VNI of B in the remote, so the datagram arrives with the
	// VNI that B listens on. Change it to the VNI of A.
	if err := a.vxlan.FDBUpdate(b.vxlan.LinkAddress(), NUDPermanent, NTFSelf, Remote{IP: b.underlay, Port: 4789, VNI: 7}, UpdateMode{Replace: true}); err != nil {
		t.Fatalf("FDBUpdate: %v", err)
	}
	if echo(t, a, b, 9000, "x", 500*time.Millisecond) {
		t.Fatal("B delivered a frame of VNI 7 on a link with VNI 8")
	}
}

func TestLearningAddsTheSourceAddress(t *testing.T) {
	a, b := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789, Learning: true})
	connect(t, a, b)
	// B knows A only by the neighbor entry, so it has no FDB entry for A.
	if err := b.vxlan.FDBDelete(a.vxlan.LinkAddress(), Remote{}); err != nil {
		t.Fatalf("FDBDelete: %v", err)
	}
	if !echo(t, a, b, 9000, "learn", 5*time.Second) {
		t.Fatal("datagram did not cross")
	}
	var got *FDBEntry
	for _, e := range b.vxlan.FDB() {
		if e.MAC == a.vxlan.LinkAddress() {
			got = &e
		}
	}
	if got == nil || len(got.Remotes) != 1 || got.Remotes[0].IP != a.underlay || got.State != NUDReachable {
		t.Fatalf("B learned %+v, want a reachable entry for A with the remote %v", got, a.underlay)
	}
}

func TestDuplicateVNIOnOnePortFails(t *testing.T) {
	a, _ := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789})
	_, err := New(a.stack, Config{ID: 9, VNI: 7, Port: 4789, Local: a.underlay})
	if !errors.Is(err, ErrDuplicate) {
		t.Fatalf("New with the same VNI and port = %v, want ErrDuplicate", err)
	}
	other, err := New(a.stack, Config{ID: 9, VNI: 8, Port: 4789, Local: a.underlay})
	if err != nil {
		t.Fatalf("New with another VNI on the same port = %v, want success", err)
	}
	other.Close()
}

func TestClosingTheLastLinkFreesThePort(t *testing.T) {
	a, _ := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789})
	a.vxlan.Close()
	ep, err := New(a.stack, Config{ID: 9, VNI: 7, Port: 4789, Local: a.underlay})
	if err != nil {
		t.Fatalf("New after Close = %v, want success", err)
	}
	ep.Close()
}

func TestGroupCreatesTheDefaultEntry(t *testing.T) {
	a, _ := newNodes(t, Config{VNI: 7, Port: 4789, Group: ip4(10, 0, 0, 2)}, Config{VNI: 7, Port: 4789})
	fdb := a.vxlan.FDB()
	if len(fdb) != 1 || fdb[0].MAC != zeroMAC || len(fdb[0].Remotes) != 1 || fdb[0].Remotes[0].IP != ip4(10, 0, 0, 2) {
		t.Fatalf("FDB = %+v, want one all-zeros entry for 10.0.0.2", fdb)
	}
	if fdb[0].State != NUDReachable|NUDPermanent {
		t.Errorf("state = %#x, want permanent and reachable", fdb[0].State)
	}
}

func TestUnknownDestinationGoesToTheAllZerosEntry(t *testing.T) {
	a, b := newNodes(t, Config{VNI: 7, Port: 4789}, Config{VNI: 7, Port: 4789})
	// Only the neighbor entries exist, and the FDB holds the all-zeros entry.
	for _, p := range []struct{ from, to *node }{{a, b}, {b, a}} {
		if err := p.from.stack.AddStaticNeighbor(overlayNIC, ipv4.ProtocolNumber, p.to.overlay, p.to.vxlan.LinkAddress()); err != nil {
			t.Fatalf("AddStaticNeighbor: %v", err)
		}
		r := Remote{IP: p.to.underlay, Port: 4789, VNI: 7}
		if err := p.from.vxlan.FDBUpdate(zeroMAC, NUDPermanent, NTFSelf, r, UpdateMode{Create: true, Append: true}); err != nil {
			t.Fatalf("FDBUpdate: %v", err)
		}
	}
	if !echo(t, a, b, 9000, "flood", 5*time.Second) {
		t.Fatal("datagram did not reach B through the all-zeros entry")
	}
}

func TestParseHeader(t *testing.T) {
	good := []byte{0x08, 0, 0, 0, 0x01, 0x02, 0x03, 0, 0xde, 0xad}
	tests := []struct {
		name  string
		b     []byte
		gbp   bool
		vni   uint32
		frame int
		ok    bool
	}{
		{"valid", good, false, 0x010203, 2, true},
		{"short", good[:7], false, 0, 0, false},
		{"no I flag", []byte{0, 0, 0, 0, 1, 2, 3, 0, 0}, false, 0, 0, false},
		{"reserved flag", []byte{0x09, 0, 0, 0, 1, 2, 3, 0, 0}, false, 0, 0, false},
		{"reserved last byte", []byte{0x08, 0, 0, 0, 1, 2, 3, 1, 0}, false, 0, 0, false},
		{"GBP bits without GBP", []byte{0x88, 0, 0, 5, 1, 2, 3, 0, 0}, false, 0, 0, false},
		{"GBP bits with GBP", []byte{0x88, 0x48, 0, 5, 1, 2, 3, 0, 0}, true, 0x010203, 1, true},
	}
	for _, tc := range tests {
		vni, frame, ok := parseHeader(tc.b, tc.gbp)
		if ok != tc.ok || (ok && (vni != tc.vni || len(frame) != tc.frame)) {
			t.Errorf("%s: parseHeader = %#x, %d bytes, %v; want %#x, %d bytes, %v", tc.name, vni, len(frame), ok, tc.vni, tc.frame, tc.ok)
		}
	}
}

func TestSourcePortStaysInTheRangeAndKeepsTheFlow(t *testing.T) {
	a, _ := newNodes(t, Config{VNI: 7, Port: 4789, PortLow: 40000, PortHigh: 40009}, Config{VNI: 7, Port: 4789})
	frame := make([]byte, 60)
	frame[12], frame[13] = 0x08, 0x00
	frame[14] = 0x45
	frame[23] = byte(header.TCPProtocolNumber)
	first := a.vxlan.sourcePort(frame)
	if first < 40000 || first > 40009 {
		t.Fatalf("source port %d is outside 40000..40009", first)
	}
	if got := a.vxlan.sourcePort(frame); got != first {
		t.Errorf("one flow got ports %d and %d", first, got)
	}
	seen := map[uint16]bool{}
	for i := range 200 {
		frame[34], frame[35] = byte(i>>8), byte(i)
		seen[a.vxlan.sourcePort(frame)] = true
	}
	if len(seen) < 5 {
		t.Errorf("200 flows used %d ports, want a spread over the range", len(seen))
	}
}

// TestFDBUpdateSemantics checks the rules of vxlan_fdb_update for the flags of
// the request.
func TestFDBUpdateSemantics(t *testing.T) {
	var tb fdb
	now := time.Now()
	unicast := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
	r1 := Remote{IP: ip4(10, 0, 0, 1), Port: 4789, VNI: 1}
	r2 := Remote{IP: ip4(10, 0, 0, 2), Port: 4789, VNI: 1}
	check := func(name string, got, want error) {
		t.Helper()
		if !errors.Is(got, want) {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	check("update of a missing entry without create", tb.update(unicast, NUDPermanent, 0, r1, UpdateMode{}, now, 0, 0), ErrNotFound)
	check("create", tb.update(unicast, NUDPermanent, 0, r1, UpdateMode{Create: true, Excl: true}, now, 0, 0), nil)
	check("exclusive create of an existing entry", tb.update(unicast, NUDPermanent, 0, r1, UpdateMode{Create: true, Excl: true}, now, 0, 0), ErrExists)
	check("append to a unicast entry changes nothing", tb.update(unicast, NUDPermanent, 0, r2, UpdateMode{Create: true, Append: true}, now, 0, 0), nil)
	if got := tb.entries[unicast].remotes; len(got) != 1 || got[0] != r1 {
		t.Errorf("remotes after append to a unicast entry = %v, want only %v", got, r1)
	}
	check("replace", tb.update(unicast, NUDPermanent, 0, r2, UpdateMode{Create: true, Replace: true}, now, 0, 0), nil)
	if got := tb.entries[unicast].remotes; len(got) != 1 || got[0] != r2 {
		t.Errorf("remotes after replace = %v, want only %v", got, r2)
	}
	check("first append to the all-zeros entry", tb.update(zeroMAC, NUDPermanent, 0, r1, UpdateMode{Create: true, Append: true}, now, 0, 0), nil)
	check("second append", tb.update(zeroMAC, NUDPermanent, 0, r2, UpdateMode{Create: true, Append: true}, now, 0, 0), nil)
	check("repeated append", tb.update(zeroMAC, NUDPermanent, 0, r2, UpdateMode{Create: true, Append: true}, now, 0, 0), nil)
	if got := tb.entries[zeroMAC].remotes; len(got) != 2 {
		t.Errorf("all-zeros remotes = %v, want two", got)
	}
	check("replace of the all-zeros entry", tb.update(zeroMAC, NUDPermanent, 0, r1, UpdateMode{Create: true, Replace: true}, now, 0, 0), ErrNotSupported)
	check("delete one remote", tb.remove(zeroMAC, r1), nil)
	check("delete a missing remote", tb.remove(zeroMAC, r1), ErrNotFound)
	check("delete the last remote", tb.remove(zeroMAC, r2), nil)
	check("delete the removed entry", tb.remove(zeroMAC, Remote{IP: ip4(0, 0, 0, 0)}), ErrNotFound)
	check("delete without a remote", tb.remove(unicast, Remote{IP: ip4(0, 0, 0, 0)}), nil)
}

func TestLearningRules(t *testing.T) {
	var tb fdb
	now := time.Now()
	mac := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x09")
	src1 := Remote{IP: ip4(10, 0, 0, 1)}
	src2 := Remote{IP: ip4(10, 0, 0, 2)}
	if !tb.learn(mac, src1, 0, now, 0) || !tb.learn(mac, src2, 0, now, 0) {
		t.Fatal("learning dropped a frame of a dynamic entry")
	}
	if got := tb.entries[mac].remotes[0]; got != src2 {
		t.Errorf("a moved address learned %v, want %v", got, src2)
	}
	static := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0a")
	if err := tb.update(static, NUDPermanent, 0, src1, UpdateMode{Create: true}, now, 0, 0); err != nil {
		t.Fatal(err)
	}
	if tb.learn(static, src2, 0, now, 0) {
		t.Error("learning accepted a frame that moves a static entry")
	}
	if !tb.learn(static, src1, 0, now, 0) {
		t.Error("learning dropped a frame from the remote of a static entry")
	}
	if got := tb.entries[static].remotes[0]; got != src1 {
		t.Errorf("static entry moved to %v", got)
	}
	// With a limit of 1 and one dynamic entry, a new address is not learned.
	other := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x0b")
	tb.learn(other, src1, 1, now, 0)
	if _, ok := tb.entries[other]; ok {
		t.Error("learning exceeded the limit")
	}
}

func TestDynamicEntriesAge(t *testing.T) {
	var tb fdb
	now := time.Now()
	mac := tcpip.LinkAddress("\x02\x00\x00\x00\x00\x09")
	tb.learn(mac, Remote{IP: ip4(10, 0, 0, 1)}, 0, now, 300*time.Second)
	if got := tb.snapshot(now.Add(299*time.Second), 300*time.Second); len(got) != 1 {
		t.Fatalf("entries after 299 s = %d, want 1", len(got))
	}
	if got := tb.snapshot(now.Add(301*time.Second), 300*time.Second); len(got) != 0 {
		t.Fatalf("entries after 301 s = %d, want 0", len(got))
	}
}

func countGlobalVxlanEntriesForStacks(targets ...weak.Pointer[stack.Stack]) (nics, socks int) {
	targetSet := make(map[weak.Pointer[stack.Stack]]struct{}, len(targets))
	for _, w := range targets {
		targetSet[w] = struct{}{}
	}
	vxlanNICs.Range(func(k, _ any) bool {
		key := k.(nicKey)
		if _, ok := targetSet[key.stack]; ok {
			nics++
		}
		return true
	})
	sockets.Lock()
	for k := range sockets.m {
		if _, ok := targetSet[k.stack]; ok {
			socks++
		}
	}
	sockets.Unlock()
	return nics, socks
}

func TestTwoSandboxesCloseActionAndZeroGlobalMapLeaks(t *testing.T) {
	newSandboxStack := func() *stack.Stack {
		s := stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
		})
		p1, p2 := pipe.New("\x02\x00\x00\x00\x01\x01", "\x02\x00\x00\x00\x01\x02", 1514)
		_ = p2
		if err := s.CreateNIC(underlayNIC, ethernet.New(p1)); err != nil {
			t.Fatalf("CreateNIC(underlay): %v", err)
		}
		return s
	}

	var ws1, ws2 weak.Pointer[stack.Stack]
	collected1 := make(chan struct{})
	collected2 := make(chan struct{})
	func() {
		stk1 := newSandboxStack()
		stk2 := newSandboxStack()
		ws1 = weak.Make(stk1)
		ws2 = weak.Make(stk2)
		runtime.AddCleanup(stk1, func(ch chan struct{}) { close(ch) }, collected1)
		runtime.AddCleanup(stk2, func(ch chan struct{}) { close(ch) }, collected2)

		// Sandbox 1: NIC close via Endpoint.Close triggers stack's SetOnCloseAction
		// without re-entrant deadlock, and custom SetOnCloseAction runs once.
		ep1, err := New(stk1, Config{ID: overlayNIC, VNI: 101, Port: 4789})
		if err != nil {
			t.Fatalf("New(stk1, 101): %v", err)
		}
		if err := stk1.CreateNIC(overlayNIC, ep1); err != nil {
			t.Fatalf("stk1.CreateNIC: %v", err)
		}
		if !stk1.HasNIC(overlayNIC) {
			t.Fatal("stk1 missing overlayNIC before Close")
		}

		var customCalls atomic.Int32
		ep1Custom, err := New(stk1, Config{ID: 3, VNI: 102, Port: 4789})
		if err != nil {
			t.Fatalf("New(stk1, 102): %v", err)
		}
		ep1Custom.SetOnCloseAction(func() {
			customCalls.Add(1)
		})

		// Sandbox 2: open VXLAN endpoint on independent stack.
		ep2, err := New(stk2, Config{ID: overlayNIC, VNI: 201, Port: 4789})
		if err != nil {
			t.Fatalf("New(stk2, 201): %v", err)
		}
		if err := stk2.CreateNIC(overlayNIC, ep2); err != nil {
			t.Fatalf("stk2.CreateNIC: %v", err)
		}

		if nics, socks := countGlobalVxlanEntriesForStacks(ws1, ws2); nics != 3 || socks != 2 {
			t.Fatalf("active global entries = (%d nics, %d sockets), want (3, 2)", nics, socks)
		}

		// Closing ep1 directly must run stk1's SetOnCloseAction and remove overlayNIC.
		ep1.Close()
		if stk1.HasNIC(overlayNIC) {
			t.Fatal("ep1.Close() did not run stack SetOnCloseAction to remove overlayNIC")
		}

		ep1Custom.Close()
		ep1Custom.Close()
		if got := customCalls.Load(); got != 1 {
			t.Fatalf("SetOnCloseAction ran %d times, want 1", got)
		}

		// Closing stk2 without calling ep2.Close() first must also evict sockets and vxlanNICs.
		stk2.Close()
		CloseStack(stk2)
		ep2.Close()
		stk1.Close()

		if nics, socks := countGlobalVxlanEntriesForStacks(ws1, ws2); nics != 0 || socks != 0 {
			t.Fatalf("leaked global entries after close = (%d nics, %d sockets), want (0, 0)", nics, socks)
		}
	}()

	for range 8 {
		runtime.GC()
		runtime.Gosched()
		if ws1.Value() == nil && ws2.Value() == nil {
			break
		}
	}
	select {
	case <-collected1:
	case <-time.After(time.Second):
		t.Fatal("stk1 was not collected after GC")
	}
	select {
	case <-collected2:
	case <-time.After(time.Second):
		t.Fatal("stk2 was not collected after GC")
	}
	if ws1.Value() != nil || ws2.Value() != nil {
		t.Fatalf("closed stacks remained reachable after GC: stk1=%v stk2=%v", ws1.Value() != nil, ws2.Value() != nil)
	}
}
