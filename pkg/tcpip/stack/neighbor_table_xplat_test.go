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

package stack_test

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/buffer"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/arp"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// neighStack is a stack with Ethernet links that need address resolution.
type neighStack struct {
	*stack.Stack
	clock *faketime.ManualClock
	links map[tcpip.NICID]*channel.Endpoint
}

func newNeighStack(t *testing.T) *neighStack {
	t.Helper()
	clock := faketime.NewManualClock()
	nud := stack.DefaultNUDConfigurations()
	nud.BaseReachableTime = 10 * time.Second
	nud.MinRandomFactor, nud.MaxRandomFactor = 1, 1
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, arp.NewProtocol, ipv6.NewProtocol},
		Clock:            clock,
		NUDConfigs:       nud,
	})
	t.Cleanup(s.Close)
	return &neighStack{Stack: s, clock: clock, links: make(map[tcpip.NICID]*channel.Endpoint)}
}

// addLink creates an Ethernet link with the IPv4 address 10.<id>.0.1/16 and the
// IPv6 address fd00:<id>::1/64.
func (n *neighStack) addLink(t *testing.T, id tcpip.NICID) {
	t.Helper()
	ep := channel.New(4096, 1500, tcpip.LinkAddress([]byte{2, 0, 0, 0, 0, byte(id)}))
	ep.LinkEPCapabilities |= stack.CapabilityResolutionRequired
	n.links[id] = ep
	if err := n.CreateNIC(id, ep); err != nil {
		t.Fatalf("CreateNIC(%d): %v", id, err)
	}
	v4 := tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom4([4]byte{10, byte(id), 0, 1}), PrefixLen: 16}}
	v6 := tcpip.ProtocolAddress{Protocol: ipv6.ProtocolNumber, AddressWithPrefix: tcpip.AddressWithPrefix{Address: tcpip.AddrFrom16([16]byte{0xfd, 0, 0, byte(id), 15: 1}), PrefixLen: 64}}
	for _, a := range []tcpip.ProtocolAddress{v4, v6} {
		if err := n.AddProtocolAddress(id, a, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress(%d): %v", id, err)
		}
	}
}

func isNoBufferSpace(err tcpip.Error) bool {
	_, ok := err.(*tcpip.ErrNoBufferSpace)
	return ok
}

func peer4(id tcpip.NICID, i int) tcpip.Address {
	return tcpip.AddrFrom4([4]byte{10, byte(id), byte(i >> 8), byte(i + 2)})
}

func peer6(id tcpip.NICID, i int) tcpip.Address {
	return tcpip.AddrFrom16([16]byte{0xfd, 0, 0, byte(id), 12: byte(i >> 24), 13: byte(i >> 16), 14: byte(i >> 8), 15: byte(i + 2)})
}

// resolve starts the resolution of the IPv4 peer, which creates a dynamic entry.
func (n *neighStack) resolve(id tcpip.NICID, peer tcpip.Address) tcpip.Error {
	local := tcpip.AddrFrom4([4]byte{10, byte(id), 0, 1})
	err := n.GetLinkAddress(id, peer, local, ipv4.ProtocolNumber, func(stack.LinkResolutionResult) {})
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		return nil
	}
	return err
}

func (n *neighStack) resolve6(id tcpip.NICID, peer tcpip.Address) tcpip.Error {
	local := tcpip.AddrFrom16([16]byte{0xfd, 0, 0, byte(id), 15: 1})
	err := n.GetLinkAddress(id, peer, local, ipv6.ProtocolNumber, func(stack.LinkResolutionResult) {})
	if _, ok := err.(*tcpip.ErrWouldBlock); ok {
		return nil
	}
	return err
}

func (n *neighStack) count(t *testing.T, id tcpip.NICID, proto tcpip.NetworkProtocolNumber, state stack.NeighborState) int {
	t.Helper()
	entries, err := n.Neighbors(id, proto)
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	c := 0
	for _, e := range entries {
		if e.State == state {
			c++
		}
	}
	return c
}

func (n *neighStack) total(t *testing.T, id tcpip.NICID, proto tcpip.NetworkProtocolNumber) int {
	t.Helper()
	entries, err := n.Neighbors(id, proto)
	if err != nil {
		t.Fatalf("Neighbors: %v", err)
	}
	return len(entries)
}

// TestPermanentNeighborsHaveNoLimit adds more static entries than the old cap
// of 65,536 and checks that dynamic entries still fit. Linux keeps a
// NUD_PERMANENT entry off the garbage collection list.
func TestPermanentNeighborsHaveNoLimit(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	const count = 70000
	for i := range count {
		peer := tcpip.AddrFrom4([4]byte{172, byte(16 + i>>16), byte(i >> 8), byte(i)})
		if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, peer, tcpip.LinkAddress([]byte{2, 1, 0, 0, byte(i >> 8), byte(i)})); err != nil {
			t.Fatalf("static entry %d: %v", i, err)
		}
	}
	if got := s.count(t, 1, ipv4.ProtocolNumber, stack.Static); got != count {
		t.Fatalf("static entries = %d, want %d", got, count)
	}
	for i := range 100 {
		if err := s.resolve(1, peer4(1, i)); err != nil {
			t.Fatalf("dynamic entry %d after %d static entries: %v", i, count, err)
		}
	}
}

// TestDynamicNeighborsAreCountedForTheWholeTable creates more dynamic entries
// than the old limit of 512 for one link. gc_thresh3 is 1024 for the whole
// table, so all of them stay.
func TestDynamicNeighborsAreCountedForTheWholeTable(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	const count = 900
	for i := range count {
		if err := s.resolve(1, peer4(1, i)); err != nil {
			t.Fatalf("dynamic entry %d: %v", i, err)
		}
	}
	if got := s.total(t, 1, ipv4.ProtocolNumber); got != count {
		t.Errorf("entries = %d, want %d (the table keeps up to gc_thresh3 = 1024)", got, count)
	}
}

// TestNeighborTableOverflowAtDefaultThresholds fills the table with entries
// that run address resolution. A forced collection cannot remove them, so the
// 1025th entry fails as in Linux ("neighbor table overflow!", ENOBUFS).
func TestNeighborTableOverflowAtDefaultThresholds(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	s.addLink(t, 2)
	for i := range 1024 {
		id := tcpip.NICID(1 + i%2)
		if err := s.resolve(id, peer4(id, i)); err != nil {
			t.Fatalf("dynamic entry %d: %v", i, err)
		}
	}
	err := s.resolve(1, peer4(1, 5000))
	if !isNoBufferSpace(err) {
		t.Fatalf("entry 1025 error = %v, want ErrNoBufferSpace", err)
	}
	// The table counts both links, so the other link overflows as well.
	if err := s.resolve(2, peer4(2, 5000)); !isNoBufferSpace(err) {
		t.Errorf("entry 1025 on the second link error = %v, want ErrNoBufferSpace", err)
	}
	// The IPv6 table is separate.
	if err := s.resolve6(1, peer6(1, 0)); err != nil {
		t.Errorf("first IPv6 entry = %v, want success", err)
	}
	// A static entry needs no room.
	if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, peer4(1, 6000), "\x02\x01\x00\x00\x00\x01"); err != nil {
		t.Errorf("static entry in a full table = %v, want success", err)
	}
}

// TestForcedCollectionRemovesFailedEntries lets address resolution fail, so the
// entries become unreachable. A new entry in a full table then removes them.
func TestForcedCollectionRemovesFailedEntries(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	for i := range 1024 {
		if err := s.resolve(1, peer4(1, i)); err != nil {
			t.Fatalf("dynamic entry %d: %v", i, err)
		}
	}
	s.clock.Advance(time.Minute)
	if got := s.count(t, 1, ipv4.ProtocolNumber, stack.Unreachable); got != 1024 {
		t.Fatalf("unreachable entries = %d, want 1024", got)
	}
	if err := s.resolve(1, peer4(1, 5000)); err != nil {
		t.Fatalf("entry in a table of failed entries: %v", err)
	}
	// neigh_forced_gc removes gc_entries - gc_thresh2 entries: 1025 - 512.
	if got, want := s.total(t, 1, ipv4.ProtocolNumber), 1024-513+1; got != want {
		t.Errorf("entries after the collection = %d, want %d", got, want)
	}
}

// reply delivers an ARP reply from the IPv4 peer, which makes the entry of the
// peer reachable.
func (n *neighStack) reply(id tcpip.NICID, peer tcpip.Address, mac tcpip.LinkAddress) {
	pkt := make([]byte, header.ARPSize)
	a := header.ARP(pkt)
	a.SetIPv4OverEthernet()
	a.SetOp(header.ARPReply)
	copy(a.HardwareAddressSender(), mac)
	copy(a.ProtocolAddressSender(), peer.AsSlice())
	copy(a.HardwareAddressTarget(), "\x02\x00\x00\x00\x00"+string(rune(id)))
	copy(a.ProtocolAddressTarget(), []byte{10, byte(id), 0, 1})
	n.links[id].InjectInbound(arp.ProtocolNumber, stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(pkt),
	}))
}
