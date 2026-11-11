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

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestNeighborGCThresholdsStartAtTheLinuxDefaults(t *testing.T) {
	s := newNeighStack(t)
	for _, proto := range []tcpip.NetworkProtocolNumber{ipv4.ProtocolNumber, ipv6.ProtocolNumber} {
		got, err := s.NeighborGCThresholds(proto)
		if err != nil {
			t.Fatalf("NeighborGCThresholds(%d): %v", proto, err)
		}
		if want := (stack.NeighborGCThresholds{Thresh1: 128, Thresh2: 512, Thresh3: 1024}); got != want {
			t.Errorf("thresholds(%d) = %+v, want %+v", proto, got, want)
		}
	}
	if _, err := s.NeighborGCThresholds(tcpip.NetworkProtocolNumber(0x1234)); err == nil {
		t.Error("a protocol without a neighbor table has thresholds")
	}
}

func TestNeighborGCThresholdsBelongToTheStackAndTheProtocol(t *testing.T) {
	a, b := newNeighStack(t), newNeighStack(t)
	want := stack.NeighborGCThresholds{Thresh1: 9, Thresh2: 3, Thresh3: 1}
	if err := a.SetNeighborGCThresholds(ipv4.ProtocolNumber, want); err != nil {
		t.Fatal(err)
	}
	if got, _ := a.NeighborGCThresholds(ipv4.ProtocolNumber); got != want {
		t.Errorf("IPv4 thresholds = %+v, want %+v (Linux does not compare the thresholds)", got, want)
	}
	if got, _ := a.NeighborGCThresholds(ipv6.ProtocolNumber); got != stack.DefaultNeighborGCThresholds() {
		t.Errorf("IPv6 thresholds = %+v, want the defaults", got)
	}
	if got, _ := b.NeighborGCThresholds(ipv4.ProtocolNumber); got != stack.DefaultNeighborGCThresholds() {
		t.Errorf("thresholds of the other stack = %+v, want the defaults", got)
	}
}

func TestSmallerThresh3LimitsTheDynamicEntries(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	s.addLink(t, 2)
	if err := s.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh1: 1, Thresh2: 2, Thresh3: 4}); err != nil {
		t.Fatal(err)
	}
	// Static entries do not count.
	for i := range 20 {
		if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, peer4(1, 100+i), "\x02\x01\x00\x00\x00\x01"); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 4 {
		id := tcpip.NICID(1 + i%2)
		if err := s.resolve(id, peer4(id, i)); err != nil {
			t.Fatalf("dynamic entry %d: %v", i, err)
		}
	}
	if err := s.resolve(2, peer4(2, 50)); !isNoBufferSpace(err) {
		t.Fatalf("fifth dynamic entry error = %v, want ErrNoBufferSpace", err)
	}
	// Replacing a dynamic entry by a static entry takes it off the count.
	if err := s.AddStaticNeighbor(1, ipv4.ProtocolNumber, peer4(1, 0), "\x02\x01\x00\x00\x00\x02"); err != nil {
		t.Fatal(err)
	}
	if err := s.resolve(2, peer4(2, 50)); err != nil {
		t.Errorf("entry after a dynamic entry became static = %v, want success", err)
	}
	// Removing an entry frees its place.
	if err := s.RemoveNeighbor(2, ipv4.ProtocolNumber, peer4(2, 50)); err != nil {
		t.Fatal(err)
	}
	if err := s.resolve(2, peer4(2, 51)); err != nil {
		t.Errorf("entry after a removal = %v, want success", err)
	}
	// Removing a link frees the entries of the link. The first link keeps one
	// dynamic entry, so three more entries fit.
	if err := s.RemoveNIC(2); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := s.resolve(1, peer4(1, 52+i)); err != nil {
			t.Errorf("entry %d after the removal of a link = %v, want success", i, err)
		}
	}
	if err := s.resolve(1, peer4(1, 60)); !isNoBufferSpace(err) {
		t.Errorf("entry beyond the limit after the removal of a link = %v, want ErrNoBufferSpace", err)
	}
}

func TestThresh3OfZeroRefusesEveryDynamicEntry(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	if err := s.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh3: 0}); err != nil {
		t.Fatal(err)
	}
	if err := s.resolve(1, peer4(1, 0)); !isNoBufferSpace(err) {
		t.Errorf("dynamic entry with gc_thresh3 = 0: %v, want ErrNoBufferSpace", err)
	}
}

// TestThresh2StartsACollectionAfterFiveSeconds checks the soft threshold. At
// gc_thresh2 entries, a new entry starts a forced collection only when the last
// one ran more than five seconds ago.
func TestThresh2StartsACollectionAfterFiveSeconds(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	if err := s.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh1: 0, Thresh2: 4, Thresh3: 100}); err != nil {
		t.Fatal(err)
	}
	for i := range 4 {
		if err := s.resolve(1, peer4(1, i)); err != nil {
			t.Fatal(err)
		}
	}
	// Address resolution fails after about three seconds, and the entries
	// become unreachable.
	s.clock.Advance(10 * time.Second)
	if got := s.count(t, 1, ipv4.ProtocolNumber, stack.Unreachable); got != 4 {
		t.Fatalf("unreachable entries = %d, want 4", got)
	}
	if err := s.resolve(1, peer4(1, 10)); err != nil {
		t.Fatal(err)
	}
	// gc_entries is 5 with the new entry, so the collection removes one entry.
	if got := s.total(t, 1, ipv4.ProtocolNumber); got != 4 {
		t.Fatalf("entries after the first collection = %d, want 4", got)
	}
	// The next entries come less than five seconds after the collection.
	if err := s.resolve(1, peer4(1, 11)); err != nil {
		t.Fatal(err)
	}
	if got := s.total(t, 1, ipv4.ProtocolNumber); got != 5 {
		t.Errorf("entries within five seconds of a collection = %d, want 5", got)
	}
	s.clock.Advance(6 * time.Second)
	if err := s.resolve(1, peer4(1, 12)); err != nil {
		t.Fatal(err)
	}
	if got := s.total(t, 1, ipv4.ProtocolNumber); got >= 6 {
		t.Errorf("entries after five seconds = %d, want fewer than 6 after a collection", got)
	}
}

// TestForcedCollectionKeepsRecentStaleEntries makes two entries stale at
// different times and runs a collection. A stale entry younger than five
// seconds survives, as neigh_forced_gc keeps an entry that time_in_range
// accepts.
func TestForcedCollectionKeepsRecentStaleEntries(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	if err := s.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh2: 0, Thresh3: 100}); err != nil {
		t.Fatal(err)
	}
	mac := tcpip.LinkAddress("\x02\x09\x00\x00\x00\x01")
	older, younger := peer4(1, 0), peer4(1, 1)
	for _, p := range []tcpip.Address{older, younger} {
		if err := s.resolve(1, p); err != nil {
			t.Fatal(err)
		}
	}
	// The reachable time is 10 seconds. The older entry goes stale at 10
	// seconds, and the younger entry at 12 seconds. Resolution fails after 3
	// seconds, so the reply comes sooner. The collection runs at 16 seconds.
	s.reply(1, older, mac)
	s.clock.Advance(2 * time.Second)
	s.reply(1, younger, mac)
	s.clock.Advance(14 * time.Second)
	if got := s.count(t, 1, ipv4.ProtocolNumber, stack.Stale); got != 2 {
		es, _ := s.Neighbors(1, ipv4.ProtocolNumber)
		t.Fatalf("stale entries = %d, want 2: %v", got, es)
	}
	if err := s.resolve(1, peer4(1, 2)); err != nil {
		t.Fatal(err)
	}
	entries, _ := s.Neighbors(1, ipv4.ProtocolNumber)
	have := make(map[tcpip.Address]bool)
	for _, e := range entries {
		have[e.Addr] = true
	}
	if have[older] || !have[younger] || !have[peer4(1, 2)] || len(entries) != 2 {
		t.Errorf("entries after the collection = %v, want the younger stale entry and the new entry", entries)
	}
}

func TestDynamicNeighborCountsIsolateAcrossStacksAndNICDisable(t *testing.T) {
	a, b := newNeighStack(t), newNeighStack(t)
	a.addLink(t, 1)
	b.addLink(t, 1)
	if err := a.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh1: 1, Thresh2: 2, Thresh3: 2}); err != nil {
		t.Fatal(err)
	}
	if err := b.SetNeighborGCThresholds(ipv4.ProtocolNumber, stack.NeighborGCThresholds{Thresh1: 1, Thresh2: 2, Thresh3: 2}); err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if err := a.resolve(1, peer4(1, i)); err != nil {
			t.Fatalf("stack a entry %d: %v", i, err)
		}
	}
	if err := a.resolve(1, peer4(1, 10)); !isNoBufferSpace(err) {
		t.Fatalf("stack a third entry = %v, want ErrNoBufferSpace", err)
	}
	for i := range 2 {
		if err := b.resolve(1, peer4(1, i)); err != nil {
			t.Fatalf("stack b entry %d while stack a is full: %v", i, err)
		}
	}

	if err := a.DisableNIC(1); err != nil {
		t.Fatalf("DisableNIC: %v", err)
	}
	if err := a.EnableNIC(1); err != nil {
		t.Fatalf("EnableNIC: %v", err)
	}
	for i := range 2 {
		if err := a.resolve(1, peer4(1, 20+i)); err != nil {
			t.Fatalf("stack a entry %d after NIC reset: %v", i, err)
		}
	}
	if err := a.resolve(1, peer4(1, 30)); !isNoBufferSpace(err) {
		t.Fatalf("stack a third entry after NIC reset = %v, want ErrNoBufferSpace", err)
	}
}

func TestThresh3AboveUint16MaxEnforcesExactLimit(t *testing.T) {
	s := newNeighStack(t)
	s.addLink(t, 1)
	const limit = 65540
	if err := s.SetNeighborGCThresholds(ipv6.ProtocolNumber, stack.NeighborGCThresholds{
		Thresh1: limit,
		Thresh2: limit,
		Thresh3: limit,
	}); err != nil {
		t.Fatal(err)
	}
	for i := range limit {
		if err := s.resolve6(1, peer6(1, i)); err != nil {
			t.Fatalf("dynamic entry %d: %v", i, err)
		}
	}
	if err := s.resolve6(1, peer6(1, limit)); !isNoBufferSpace(err) {
		t.Fatalf("entry %d = %v, want ErrNoBufferSpace", limit+1, err)
	}

	if err := s.RemoveNeighbor(1, ipv6.ProtocolNumber, peer6(1, 0)); err != nil {
		t.Fatalf("RemoveNeighbor: %v", err)
	}
	if err := s.resolve6(1, peer6(1, limit)); err != nil {
		t.Fatalf("insert after RemoveNeighbor above MaxUint16: %v", err)
	}
	if err := s.DisableNIC(1); err != nil {
		t.Fatalf("DisableNIC: %v", err)
	}
	if err := s.EnableNIC(1); err != nil {
		t.Fatalf("EnableNIC: %v", err)
	}
	if err := s.resolve6(1, peer6(1, limit+1)); err != nil {
		t.Fatalf("insert after NIC reset above MaxUint16: %v", err)
	}
}
