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
	"errors"
	"fmt"
	"math"
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
	parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(info))
	if err != nil {
		t.Fatalf("parseMatchers(%+v): %v", info, err)
	}
	m := parsed[0].(*RecentMatcher)
	m.table = reg.acquire(m.listName, m.mask, m.stampCount)
	return m
}

func newRecentRegistry(c *fakeClock) *recentRegistry {
	return &recentRegistry{tables: make(map[string]*recentTable), clock: c.read, module: new(RecentModule)}
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
	for i := 0; i <= RecentDefaultListTot; i++ {
		matches(t, set, fmt.Sprintf("10.1.%d.%d", i/250, i%250+1))
	}
	if matches(t, check, "10.1.0.1") {
		t.Fatal("the oldest of 101 entries stayed in a list of 100")
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
		parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(info))
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
	parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentCheck, name: "life"}))
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
			if _, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(tc.info)); err == nil {
				t.Errorf("parseMatchers(%+v) succeeded, want an error", tc.info)
			}
		})
	}
}

func TestRecentMarshalReturnsTheRule(t *testing.T) {
	for _, rev := range []uint8{recentRevision0, recentRevision1} {
		info := recentInfo{rev: rev, checkSet: recentCheck | recentReap, seconds: 10800, name: "KUBE-SEP-ABC"}
		parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(info))
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

// registryWithModule returns a registry that uses the module parameters.
func registryWithModule(m *RecentModule) *recentRegistry {
	r := newRecentRegistry(&fakeClock{})
	r.module = m
	return r
}

func TestRecentModuleStartsAtTheLinuxDefaults(t *testing.T) {
	var m RecentModule
	if m.ListTot() != 100 || m.PktListTot() != 0 {
		t.Errorf("defaults = ip_list_tot %d, ip_pkt_list_tot %d, want 100 and 0", m.ListTot(), m.PktListTot())
	}
}

// TestRecentModuleRefusesTheValuesOfRecentMtInit checks the conditions of
// recent_mt_init: ip_list_tot must not be 0, and ip_pkt_list_tot must stay
// below XT_RECENT_MAX_NSTAMPS.
func TestRecentModuleRefusesTheValuesOfRecentMtInit(t *testing.T) {
	var m RecentModule
	if err := m.SetListTot(0); !errors.Is(err, ErrRecentParam) {
		t.Errorf("SetListTot(0) = %v, want ErrRecentParam", err)
	}
	if err := m.SetPktListTot(65536); !errors.Is(err, ErrRecentParam) {
		t.Errorf("SetPktListTot(65536) = %v, want ErrRecentParam", err)
	}
	if err := m.SetPktListTot(65535); err != nil || m.PktListTot() != 65535 {
		t.Errorf("SetPktListTot(65535) = %v, value %d, want success", err, m.PktListTot())
	}
	if err := m.SetListTot(math.MaxUint32); err != nil || m.ListTot() != math.MaxUint32 {
		t.Errorf("SetListTot(MaxUint32) = %v, value %d, want success", err, m.ListTot())
	}
	if m.ListTot() == 100 {
		t.Error("the large value reads as the default")
	}
}

func TestRecentListTotSetsTheSizeOfTheList(t *testing.T) {
	var mod RecentModule
	if err := mod.SetListTot(2); err != nil {
		t.Fatal(err)
	}
	reg := registryWithModule(&mod)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "tiny"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "tiny"})
	for _, src := range []string{"10.1.0.1", "10.1.0.2", "10.1.0.3"} {
		matches(t, set, src)
	}
	if matches(t, check, "10.1.0.1") {
		t.Error("the oldest address stayed in a list of 2 entries")
	}
	for _, src := range []string{"10.1.0.2", "10.1.0.3"} {
		if !matches(t, check, src) {
			t.Errorf("%s left a list of 2 entries too early", src)
		}
	}
}

func TestRecentListTotAboveTheOldLimitKeepsEveryAddress(t *testing.T) {
	var mod RecentModule
	if err := mod.SetListTot(1000); err != nil {
		t.Fatal(err)
	}
	reg := registryWithModule(&mod)
	set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "big"})
	check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "big"})
	for i := range 1000 {
		matches(t, set, fmt.Sprintf("10.2.%d.%d", i/250, i%250+1))
	}
	if !matches(t, check, "10.2.0.1") {
		t.Error("the oldest of 1000 addresses left a list of 1000 entries")
	}
}

// TestRecentParametersAreFixedWhileAListExists checks that a write fails while a
// rule holds a list, and that it works again after the last rule went away.
func TestRecentParametersAreFixedWhileAListExists(t *testing.T) {
	var mod RecentModule
	reg := registryWithModule(&mod)
	m := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "pinned"})
	if err := mod.SetListTot(5); !errors.Is(err, ErrRecentModuleBusy) {
		t.Errorf("SetListTot with a list = %v, want ErrRecentModuleBusy", err)
	}
	if err := mod.SetPktListTot(5); !errors.Is(err, ErrRecentModuleBusy) {
		t.Errorf("SetPktListTot with a list = %v, want ErrRecentModuleBusy", err)
	}
	if mod.ListTot() != 100 || mod.PktListTot() != 0 {
		t.Errorf("a refused write changed the parameters to %d and %d", mod.ListTot(), mod.PktListTot())
	}
	// A second rule that names the same list keeps it.
	m2 := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "pinned"})
	m.table.owner.release(m.table)
	if err := mod.SetListTot(5); !errors.Is(err, ErrRecentModuleBusy) {
		t.Errorf("SetListTot with a rule left = %v, want ErrRecentModuleBusy", err)
	}
	m2.table.owner.release(m2.table)
	if err := mod.SetListTot(5); err != nil {
		t.Errorf("SetListTot after the last rule = %v, want success", err)
	}
}

// TestRecentPktListTotSetsTheStampCount follows the mask computation of
// recent_mt_check.
func TestRecentPktListTotSetsTheStampCount(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pktListTot uint32
		hitCount   uint32
		want       int
	}{
		{"default without a hit count", 0, 0, 32},
		{"default with a hit count", 0, 5, 8},
		{"hit count of one", 0, 1, 1},
		{"hit count that is a power of two", 0, 64, 64},
		{"ip_pkt_list_tot above the hit count", 100, 5, 128},
		{"ip_pkt_list_tot without a hit count", 100, 0, 128},
		{"hit count at ip_pkt_list_tot", 20, 20, 32},
		{"hit count above ip_pkt_list_tot", 20, 40, 64},
		{"ip_pkt_list_tot of one", 1, 0, 1},
	} {
		m := &RecentMatcher{hitCount: tc.hitCount}
		if got := m.stampCount(tc.pktListTot); got != tc.want {
			t.Errorf("%s: stampCount(%d) with hit count %d = %d, want %d", tc.name, tc.pktListTot, tc.hitCount, got, tc.want)
		}
	}
}

// TestRecentPktListTotKeepsTheListWhenARuleWithMoreHitsJoins checks the effect
// that a user sees. A rule that needs more stamps than the list has empties the
// list, as recent_mt_check does. ip_pkt_list_tot gives the list room for the
// later rule.
func TestRecentPktListTotKeepsTheListWhenARuleWithMoreHitsJoins(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pktListTot uint32
		wantKept   bool
	}{
		{"default", 0, false},
		{"ip_pkt_list_tot of 100", 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mod RecentModule
			if err := mod.SetPktListTot(tc.pktListTot); err != nil {
				t.Fatal(err)
			}
			reg := registryWithModule(&mod)
			set := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentSet, name: "grow"})
			check := parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "grow"})
			matches(t, set, "192.0.2.1")
			// The default list keeps 32 stamps for each address, and a rule with
			// 50 hits needs 64.
			parseRecent(t, reg, recentInfo{rev: 1, checkSet: recentCheck, name: "grow", hitCount: 50})
			if kept := matches(t, check, "192.0.2.1"); kept != tc.wantKept {
				t.Errorf("address kept after a rule with 50 hits joined = %v, want %v", kept, tc.wantKept)
			}
		})
	}
}

// TestRecentModuleIsSharedByTheStacksOfAKernel binds rules of a child stack and
// checks that the parameters of the parent stack apply, and that a write fails
// while a rule of either stack holds a list.
func TestRecentModuleIsSharedByTheStacksOfAKernel(t *testing.T) {
	parent, child, stranger := stack.New(stack.Options{}), stack.New(stack.Options{}), stack.New(stack.Options{})
	for _, s := range []*stack.Stack{parent, child, stranger} {
		t.Cleanup(s.Destroy)
	}
	ShareRecentModule(child, parent)
	if RecentModuleOf(child) != RecentModuleOf(parent) {
		t.Fatal("a child stack does not share the parameters of its parent")
	}
	if RecentModuleOf(stranger) == RecentModuleOf(parent) {
		t.Fatal("a stack that no call linked shares the parameters of another kernel")
	}
	if err := RecentModuleOf(parent).SetListTot(2); err != nil {
		t.Fatal(err)
	}
	parsed, err := parseMatchers(nil, nil, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentSet, name: "shared"}))
	if err != nil {
		t.Fatal(err)
	}
	bindMatcherStacks(child, []stack.Rule{{Matchers: parsed}})
	set := parsed[0].(*RecentMatcher)
	if err := RecentModuleOf(parent).SetListTot(7); !errors.Is(err, ErrRecentModuleBusy) {
		t.Errorf("write with a list in a child namespace = %v, want ErrRecentModuleBusy", err)
	}
	for _, src := range []string{"10.3.0.1", "10.3.0.2", "10.3.0.3"} {
		matches(t, set, src)
	}
	if got := len(set.table.entries); got != 2 {
		t.Errorf("entries of a list with ip_list_tot 2 = %d, want 2", got)
	}
	releaseMatcherStacks([]stack.Rule{{Matchers: parsed}})
	if err := RecentModuleOf(parent).SetListTot(7); err != nil {
		t.Errorf("write after the list went away = %v, want success", err)
	}
}
