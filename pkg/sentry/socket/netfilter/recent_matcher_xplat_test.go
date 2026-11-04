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

package netfilter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

type recentInfo struct {
	rev      uint8
	seconds  uint32
	hitCount uint32
	checkSet uint8
	invert   bool
	name     string
	side     uint8
	mask     []byte
}

func (i recentInfo) bytes() []byte {
	data := make([]byte, recentInfoSize(i.rev))
	binary.LittleEndian.PutUint32(data[recentOffSeconds:], i.seconds)
	binary.LittleEndian.PutUint32(data[recentOffHitCount:], i.hitCount)
	data[recentOffCheckSet] = i.checkSet
	if i.invert {
		data[recentOffInvert] = 1
	}
	copy(data[recentOffName:recentOffName+recentNameLen], i.name)
	data[recentOffSide] = i.side
	if i.rev == recentRevision1 {
		mask := i.mask
		if mask == nil {
			mask = bytes.Repeat([]byte{0xff}, 16)
		}
		copy(data[recentOffMask:], mask)
	}
	return data
}

func recentEntryBuf(info recentInfo) []byte {
	buf := marshalEntryMatch(matcherNameRecent, info.bytes())
	buf[revisionOffset] = info.rev
	return buf
}

// fakeClock is a manual monotonic clock for the lists of a test.
type fakeClock struct{ now time.Duration }

func (c *fakeClock) read() time.Duration { return c.now }

// parseRecent parses info and binds it to the lists of reg.
func parseRecent(t *testing.T, reg *recentRegistry, info recentInfo) *RecentMatcher {
	t.Helper()
	parsed, err := parseMatchers(nil, stack.EmptyFilter4(), recentEntryBuf(info))
	if err != nil {
		t.Fatalf("parseMatchers(%+v): %v", info, err)
	}
	m := parsed[0].(*RecentMatcher)
	m.table = reg.acquire(m.listName, m.mask, m.stampCount())
	return m
}

func newRecentRegistry(c *fakeClock) *recentRegistry {
	return &recentRegistry{tables: make(map[string]*recentTable), clock: c.read}
}

func matches(t *testing.T, m *RecentMatcher, src string) bool {
	t.Helper()
	ok, hotdrop := m.Match(stack.Prerouting, newIPv4Packet(t, src, "10.0.0.1"), "", "")
	if hotdrop {
		t.Fatalf("Match(%s) dropped the packet", src)
	}
	return ok
}

func TestRecentSetThenCheckMatchesTheSameSource(t *testing.T) {
	clock := &fakeClock{}
	reg := newRecentRegistry(clock)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "aff"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, seconds: 10, name: "aff"})

	if matches(t, check, "192.0.2.7") {
		t.Fatal("--rcheck matched an address that no rule recorded")
	}
	if !matches(t, set, "192.0.2.7") {
		t.Fatal("--set did not match")
	}
	if !matches(t, check, "192.0.2.7") {
		t.Fatal("--rcheck did not match the recorded address")
	}
	if matches(t, check, "192.0.2.8") {
		t.Fatal("--rcheck matched another address")
	}
	clock.now += 11 * time.Second
	if matches(t, check, "192.0.2.7") {
		t.Fatal("--rcheck --seconds 10 matched a stamp 11 s old")
	}
}

func TestRecentUpdateRefreshesTheStamp(t *testing.T) {
	clock := &fakeClock{}
	reg := newRecentRegistry(clock)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "u"})
	update := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentUpdate, seconds: 10, name: "u"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, seconds: 10, name: "u"})

	matches(t, set, "192.0.2.1")
	clock.now += 8 * time.Second
	if !matches(t, update, "192.0.2.1") {
		t.Fatal("--update did not match a fresh stamp")
	}
	clock.now += 8 * time.Second
	if !matches(t, check, "192.0.2.1") {
		t.Fatal("--update did not refresh the stamp")
	}
	clock.now += 11 * time.Second
	if matches(t, update, "192.0.2.1") {
		t.Fatal("--update matched a stale entry")
	}
}

func TestRecentHitCountNeedsThatManyStamps(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	set := parseRecent(t, reg, recentInfo{rev: 0, checkSet: recentSet, name: "hits"})
	check := parseRecent(t, reg, recentInfo{rev: 0, checkSet: recentCheck, hitCount: 3, name: "hits"})

	for i := 1; i <= 3; i++ {
		matches(t, set, "198.51.100.4")
		if got, want := matches(t, check, "198.51.100.4"), i >= 3; got != want {
			t.Fatalf("after %d stamps: --rcheck --hitcount 3 = %v, want %v", i, got, want)
		}
	}
}

func TestRecentRemoveDropsTheEntry(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "r"})
	remove := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentRemove, name: "r"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "r"})

	if matches(t, remove, "203.0.113.9") {
		t.Fatal("--remove matched an absent address")
	}
	matches(t, set, "203.0.113.9")
	if !matches(t, remove, "203.0.113.9") {
		t.Fatal("--remove did not match a recorded address")
	}
	if matches(t, check, "203.0.113.9") {
		t.Fatal("--rcheck matched after --remove")
	}
}

func TestRecentMaskGroupsAddresses(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	mask := append([]byte{255, 255, 255, 0}, make([]byte, 12)...)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "m", mask: mask})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "m", mask: mask})

	matches(t, set, "192.0.2.10")
	if !matches(t, check, "192.0.2.99") {
		t.Fatal("--mask 255.255.255.0 did not group 192.0.2.10 and 192.0.2.99")
	}
	if matches(t, check, "192.0.3.10") {
		t.Fatal("--mask 255.255.255.0 grouped another /24")
	}
}

func TestRecentInvertNegatesTheResult(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, invert: true, name: "i"})
	if !matches(t, check, "192.0.2.1") {
		t.Fatal("! --rcheck did not match an absent address")
	}
}

func TestRecentFullListDropsTheOldestEntry(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "full"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "full"})
	for i := 0; i <= recentListTotal; i++ {
		matches(t, set, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1))
	}
	if matches(t, check, "10.1.0.1") {
		t.Fatal("the oldest of 201 entries stayed in a list of 200")
	}
	if !matches(t, check, "10.1.0.2") {
		t.Fatal("the second oldest entry was dropped")
	}
}

func TestRecentMaskOfTheFirstRuleAppliesToTheList(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	mask := append([]byte{255, 255, 255, 0}, make([]byte, 12)...)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "first", mask: mask})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "first"})

	matches(t, set, "192.0.2.10")
	if !matches(t, check, "192.0.2.99") {
		t.Fatal("the second rule did not use the /24 mask of the list")
	}
}

func TestRecentRTTLTreatsTTLZeroAsAnyTTL(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "ttl"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck | recentTTL, name: "ttl"})

	matches(t, set, "192.0.2.1")
	pkt := newIPv4Packet(t, "192.0.2.1", "10.0.0.1")
	hdr := header.IPv4(pkt.NetworkHeader().Slice())
	hdr.SetTTL(9)
	if ok, _ := check.Match(stack.Prerouting, pkt, "", ""); ok {
		t.Fatal("--rttl matched TTL 9 against a stamp with TTL 64")
	}
	hdr.SetTTL(0)
	if ok, _ := check.Match(stack.Prerouting, pkt, "", ""); !ok {
		t.Fatal("--rttl did not match a packet with TTL 0")
	}
}

func TestRecentListGoesAwayWhenItsRulesAreReplaced(t *testing.T) {
	stk := stack.New(stack.Options{})
	t.Cleanup(stk.Destroy)
	parse := func(info recentInfo) *RecentMatcher {
		parsed, err := parseMatchers(nil, stack.EmptyFilter4(), recentEntryBuf(info))
		if err != nil {
			t.Fatalf("parseMatchers: %v", err)
		}
		rules := []stack.Rule{{Matchers: parsed}}
		bindMatcherStacks(stk, rules)
		return parsed[0].(*RecentMatcher)
	}
	set := parse(recentInfo{rev: 1, checkSet: recentSet, name: "life"})
	check := parse(recentInfo{rev: 1, checkSet: recentCheck, name: "life"})
	if set.table != check.table {
		t.Fatal("two rules of one stack that name one list got different lists")
	}
	matches(t, set, "192.0.2.5")

	// A replacement table that names the list binds before the old one is
	// released, so the list and its addresses stay.
	check2 := parse(recentInfo{rev: 1, checkSet: recentCheck, name: "life"})
	releaseMatcherStacks([]stack.Rule{{Matchers: []stack.Matcher{set, check}}})
	if !matches(t, check2, "192.0.2.5") {
		t.Fatal("the list lost its addresses while a new rule names it")
	}

	// With its last rule gone, a later rule gets an empty list.
	releaseMatcherStacks([]stack.Rule{{Matchers: []stack.Matcher{check2, check2}}})
	check3 := parse(recentInfo{rev: 1, checkSet: recentCheck, name: "life"})
	if matches(t, check3, "192.0.2.5") {
		t.Fatal("the list kept its addresses after its last rule went away")
	}

	other := stack.New(stack.Options{})
	t.Cleanup(other.Destroy)
	parsed, err := parseMatchers(nil, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentCheck, name: "life"}))
	if err != nil {
		t.Fatalf("parseMatchers: %v", err)
	}
	bindMatcherStacks(other, []stack.Rule{{Matchers: parsed}})
	if parsed[0].(*RecentMatcher).table == check3.table {
		t.Fatal("two stacks share one list")
	}
}

func TestRecentRejectsInvalidRules(t *testing.T) {
	for _, tc := range []struct {
		name string
		info recentInfo
	}{
		{"no operation", recentInfo{rev: 1, name: "x"}},
		{"two operations", recentInfo{rev: 1, checkSet: recentSet | recentCheck, name: "x"}},
		{"set with seconds", recentInfo{rev: 1, checkSet: recentSet, seconds: 5, name: "x"}},
		{"reap without seconds", recentInfo{rev: 1, checkSet: recentCheck | recentReap, name: "x"}},
		{"hitcount above the maximum", recentInfo{rev: 1, checkSet: recentCheck, hitCount: recentMaxStamps, name: "x"}},
		{"empty name", recentInfo{rev: 1, checkSet: recentSet}},
		{"dot dot name", recentInfo{rev: 1, checkSet: recentSet, name: ".."}},
		{"unknown flag", recentInfo{rev: 1, checkSet: recentSet | 0x40, name: "x"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMatchers(nil, stack.EmptyFilter4(), recentEntryBuf(tc.info)); err == nil {
				t.Errorf("parseMatchers(%+v) succeeded, want an error", tc.info)
			}
		})
	}
}

func TestRecentMarshalReturnsTheRule(t *testing.T) {
	for _, rev := range []uint8{recentRevision0, recentRevision1} {
		info := recentInfo{rev: rev, checkSet: recentCheck | recentReap, seconds: 10800, name: "KUBE-SEP-ABC"}
		parsed, err := parseMatchers(nil, stack.EmptyFilter4(), recentEntryBuf(info))
		if err != nil {
			t.Fatalf("revision %d: parseMatchers: %v", rev, err)
		}
		if got, want := marshalMatcher(parsed[0]), recentEntryBuf(info); !bytes.Equal(got, want) {
			t.Errorf("revision %d: marshal = %x, want %x", rev, got, want)
		}
	}
}

func TestRecentConcurrentRulesKeepEveryAddress(t *testing.T) {
	reg := newRecentRegistry(&fakeClock{})
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "par"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "par"})
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				src := fmt.Sprintf("10.2.%d.%d", g, i+1)
				matches(t, set, src)
				if !matches(t, check, src) {
					t.Errorf("--rcheck missed %s right after --set", src)
				}
			}
		}()
	}
	wg.Wait()
	if got := len(set.table.entries); got != 80 {
		t.Errorf("the list has %d addresses, want 80", got)
	}
}
