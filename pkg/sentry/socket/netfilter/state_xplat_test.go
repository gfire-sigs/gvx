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
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/link/loopback"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func configureNICsForFilterStack(t *testing.T, s *stack.Stack) {
	t.Helper()
	if err := s.CreateNICWithOptions(1, loopback.New(), stack.NICOptions{Name: "lo"}); err != nil {
		t.Fatalf("CreateNIC(lo): %v", err)
	}
	if err := s.AddProtocolAddress(1, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr4("127.0.0.1"), PrefixLen: 8},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(lo): %v", err)
	}
	if err := s.CreateNICWithOptions(2, channel.New(4, 1500, ""), stack.NICOptions{Name: "eth0"}); err != nil {
		t.Fatalf("CreateNIC(eth0): %v", err)
	}
	if err := s.AddProtocolAddress(2, tcpip.ProtocolAddress{
		Protocol:          ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: addr4("10.0.2.15"), PrefixLen: 24},
	}, stack.AddressProperties{}); err != nil {
		t.Fatalf("AddProtocolAddress(eth0): %v", err)
	}
	sub, err := tcpip.NewSubnet(addr4("10.0.2.0"), tcpip.MaskFromBytes([]byte{255, 255, 255, 0}))
	if err != nil {
		t.Fatalf("NewSubnet: %v", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{Destination: sub, NIC: 2},
	})
}

func TestStateRoundTripAllTier2MatchersAndTargets(t *testing.T) {
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            clock,
	})
	t.Cleanup(stk.Destroy)
	configureNICsForFilterStack(t, stk)

	reg := ipset.ForStack(stk, nil)
	_, hipRev, err := ipset.FindType("hash:ip", ipset.FamilyIPv4)
	if err != nil {
		t.Fatalf("FindType(hash:ip): %v", err)
	}
	for _, name := range []string{"allowlist", "dynlist"} {
		if err := reg.Create(&ipset.CreateParams{
			Name:     name,
			TypeName: "hash:ip",
			Family:   ipset.FamilyIPv4,
			Revision: hipRev,
			Timeout:  30,
			Given:    ipset.GivenTimeout,
		}); err != nil {
			t.Fatalf("Create(%s): %v", name, err)
		}
	}
	allowID, _, ok := reg.Lookup("allowlist")
	if !ok {
		t.Fatal("Lookup(allowlist) failed")
	}
	dynID, _, ok := reg.Lookup("dynlist")
	if !ok {
		t.Fatal("Lookup(dynlist) failed")
	}
	allowElem := hostElement("203.0.113.5")
	if ret := reg.Uadt("allowlist", ipset.AdtAdd, &allowElem, 0); ret != 0 {
		t.Fatalf("Uadt(allowlist): code %d", ret)
	}

	addrtypeM := &AddrtypeMatcher{rev: 1, dest: linux.XT_ADDRTYPE_LOCAL}
	connmarkM := parseOneMatcher(t, stack.EmptyFilter4(), connmarkMatchEntry(0xca6c, 0xffff, false))
	connmarkT := parseConnmark(t, stack.EmptyFilter4(), connmarkSpec{rev: 1, ctmark: 0xca6c, ctmask: 0xffff, mode: connmarkModeSet})
	icmpM := parseOneMatcher(t, icmpFilter(false), icmpEntry("icmp", 8, 0, 0, 0))
	limitM := parseOneMatcher(t, stack.EmptyFilter4(), limitEntry(perSecond(1, 2)))
	logT, sysErr := parseTarget(stack.EmptyFilter4(), logEntry(4, []byte("cp-log: ")), false, filterTable)
	if sysErr != nil {
		t.Fatalf("parseTarget(LOG): %v", sysErr)
	}
	nflogT, sysErr := parseNFLog(t, stack.EmptyFilter4(), false, nflogInfo{group: 77, threshold: 4, prefix: "cp-nflog: "}.entry())
	if sysErr != nil {
		t.Fatalf("parseNFLog: %v", sysErr)
	}
	physdevM := parsePhysdev(t, stack.EmptyFilter4(), physdevInfo{in: "eth+", bitmask: physdevOpIn | physdevOpIsIn})
	recentSetM := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentSet, name: "state-recent"}))
	recentCheckM := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentCheck, seconds: 30, name: "state-recent"}))
	rpfilterM := parseOneMatcher(t, stack.EmptyFilter4(), marshalEntryMatch(matcherNameRPFilter, []byte{rpfilterLoose}))
	setM := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: setMatchRevision4, index: allowID, dim: 1, flags: testDimOneSrc})
	setT := parseSetTarget(t, stack.EmptyFilter4(), setTargetSpec{
		rev:     2,
		add:     setInfo{index: dynID, dim: 1, flags: testDimOneSrc},
		del:     noSet,
		timeout: 20,
		flags:   uint32(ipset.FlagExist),
	})
	statM := parseStatistic(t, nthInfo(3, 2, 0))

	rules := []stack.Rule{
		{Matchers: []stack.Matcher{addrtypeM, connmarkM, icmpM, limitM, physdevM, recentSetM, recentCheckM, rpfilterM, setM, statM}, Target: logT},
		{Target: connmarkT},
		{Target: nflogT},
		{Target: setT},
	}
	if err := bindMatcherStacks(stk, rules); err != nil {
		t.Fatalf("bindMatcherStacks: %v", err)
	}

	// Mutate stateful matchers before save so restore must preserve runtime counters.
	if ok, _ := limitM.Match(stack.Input, nil, "", ""); !ok {
		t.Fatal("first limitM packet did not match before save")
	}
	if ok, _ := recentSetM.Match(stack.Prerouting, newIPv4Packet(t, "198.51.100.9", "10.0.2.15"), "", ""); !ok {
		t.Fatal("recentSetM did not record 198.51.100.9 before save")
	}
	for i := range 2 {
		if ok, _ := statM.Match(stack.Input, nil, "", ""); ok {
			t.Fatalf("statM matched packet %d before save, want match on packet 3", i+1)
		}
	}

	wantMarshaledMatchers := make([][]byte, len(rules[0].Matchers))
	for i, m := range rules[0].Matchers {
		wantMarshaledMatchers[i] = marshalMatcher(m)
	}
	wantLogBytes := marshalTarget(logT)
	wantConnmarkBytes := marshalTarget(connmarkT)
	wantNFLogBytes := marshalTarget(nflogT)
	wantSetTargetBytes := marshalTarget(setT)

	stk.Pause()
	var buf bytes.Buffer
	saved := []any{stk, clock, rules}
	if _, err := state.Save(context.Background(), &buf, &saved); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	var loaded []any
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredStk := loaded[0].(*stack.Stack)
	restoredClock := loaded[1].(*faketime.ManualClock)
	restoredRules := loaded[2].([]stack.Rule)
	t.Cleanup(restoredStk.Destroy)

	cfgStk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            restoredClock,
	})
	configureNICsForFilterStack(t, cfgStk)
	restoredStk.ResetConfig()
	restoredStk.ReplaceConfig(cfgStk)
	restoredStk.Restore()

	for i, m := range restoredRules[0].Matchers {
		if got := marshalMatcher(m); !bytes.Equal(got, wantMarshaledMatchers[i]) {
			t.Errorf("restored matcher %d (%T) marshal = %x, want %x", i, m, got, wantMarshaledMatchers[i])
		}
	}
	if got := marshalTarget(restoredRules[0].Target); !bytes.Equal(got, wantLogBytes) {
		t.Errorf("restored logTarget marshal = %x, want %x", got, wantLogBytes)
	}
	if got := marshalTarget(restoredRules[1].Target); !bytes.Equal(got, wantConnmarkBytes) {
		t.Errorf("restored connmarkTarget marshal = %x, want %x", got, wantConnmarkBytes)
	}
	if got := marshalTarget(restoredRules[2].Target); !bytes.Equal(got, wantNFLogBytes) {
		t.Errorf("restored nflogTarget marshal = %x, want %x", got, wantNFLogBytes)
	}
	if got := marshalTarget(restoredRules[3].Target); !bytes.Equal(got, wantSetTargetBytes) {
		t.Errorf("restored setTarget marshal = %x, want %x", got, wantSetTargetBytes)
	}

	rAddrtype := restoredRules[0].Matchers[0]
	rConnmarkM := restoredRules[0].Matchers[1]
	rICMP := restoredRules[0].Matchers[2]
	rLimit := restoredRules[0].Matchers[3]
	rPhysdev := restoredRules[0].Matchers[4]
	rRecentCheck := restoredRules[0].Matchers[6]
	rRPFilter := restoredRules[0].Matchers[7]
	rSetM := restoredRules[0].Matchers[8]
	rStat := restoredRules[0].Matchers[9]
	rLogT := restoredRules[0].Target.(*logTarget)
	rConnmarkT := restoredRules[1].Target
	rNFLogT := restoredRules[2].Target
	rSetT := restoredRules[3].Target

	// AddrtypeMatcher bound to restoredStk classifies 10.0.2.15 as LOCAL.
	if ok, _ := rAddrtype.Match(stack.Prerouting, newIPv4Packet(t, "10.0.2.2", "10.0.2.15"), "eth0", ""); !ok {
		t.Error("restored AddrtypeMatcher failed to match local address")
	}
	if ok, _ := rAddrtype.Match(stack.Prerouting, newIPv4Packet(t, "10.0.2.2", "1.1.1.1"), "eth0", ""); ok {
		t.Error("restored AddrtypeMatcher matched remote address")
	}

	// ConnmarkTarget + ConnmarkMatcher on a tracked packet.
	it := restoredStk.IPTables()
	table := insertChainRules(it.GetTable(stack.MangleID, false), stack.Prerouting, []stack.Rule{{Filter: stack.EmptyFilter4(), Target: rConnmarkT}})
	it.ForceReplaceTable(stack.MangleID, table, false)
	trackedPkt := udpPacket(t, false)
	it.CheckPrerouting(trackedPkt, nil, "eth0")
	if ok, _ := rConnmarkM.Match(stack.Prerouting, trackedPkt, "eth0", ""); !ok {
		t.Errorf("restored ConnmarkMatcher did not match mark %#x set by connmarkTarget", trackedPkt.ConnMark())
	}

	// ICMPMatcher matches echo request (type 8) and rejects echo reply (type 0).
	if ok, _ := rICMP.Match(stack.Input, buildICMPPacket(t, icmpPacketSpec{protocol: uint8(header.ICMPv4ProtocolNumber), typ: 8}), "", ""); !ok {
		t.Error("restored ICMPMatcher rejected echo request")
	}
	if ok, _ := rICMP.Match(stack.Input, buildICMPPacket(t, icmpPacketSpec{protocol: uint8(header.ICMPv4ProtocolNumber), typ: 0}), "", ""); ok {
		t.Error("restored ICMPMatcher accepted echo reply")
	}

	// LimitMatcher had burst 2 and spent 1 token before save; 1 remains now.
	if ok, _ := rLimit.Match(stack.Input, nil, "", ""); !ok {
		t.Error("restored LimitMatcher rejected second burst packet")
	}
	if ok, _ := rLimit.Match(stack.Input, nil, "", ""); ok {
		t.Error("restored LimitMatcher accepted third packet without clock advance")
	}
	restoredClock.Advance(time.Second)
	if ok, _ := rLimit.Match(stack.Input, nil, "", ""); !ok {
		t.Error("restored LimitMatcher did not refill after advancing restored clock")
	}

	// PhysdevMatcher matches bridged eth0 ingress.
	if ok, _ := rPhysdev.Match(stack.Forward, markedPacket(t, bridgeMark{bridged: true, from: "eth0"}), "br0", "br0"); !ok {
		t.Error("restored PhysdevMatcher rejected bridged eth0 packet")
	}

	// RecentMatcher and SetMatcher both share restoredClock (30s timeout).
	if ok, _ := rRecentCheck.Match(stack.Prerouting, newIPv4Packet(t, "198.51.100.9", "10.0.2.15"), "", ""); !ok {
		t.Error("restored RecentMatcher lost pre-save address 198.51.100.9")
	}
	if ok, _ := rSetM.Match(stack.Input, newIPv4Packet(t, "203.0.113.5", "10.0.2.15"), "", ""); !ok {
		t.Error("restored SetMatcher failed to match 203.0.113.5 in allowlist")
	}
	restoredClock.Advance(31 * time.Second)
	if ok, _ := rRecentCheck.Match(stack.Prerouting, newIPv4Packet(t, "198.51.100.9", "10.0.2.15"), "", ""); ok {
		t.Error("restored RecentMatcher matched expired stamp after 31s")
	}
	if ok, _ := rSetM.Match(stack.Input, newIPv4Packet(t, "203.0.113.5", "10.0.2.15"), "", ""); ok {
		t.Error("restored SetMatcher matched expired allowlist entry after 31s")
	}

	// RPFilterMatcher validates routable subnet source on eth0.
	inPkt := newIPv4Packet(t, "10.0.2.77", "10.0.2.15")
	inPkt.InputNICID = 2
	if ok, _ := rRPFilter.Match(stack.Prerouting, inPkt, "eth0", ""); !ok {
		t.Error("restored RPFilterMatcher rejected routable source on eth0")
	}

	// setTarget operates on restoredStk's ipset.Registry.
	if v, _ := rSetT.Action(newIPv4Packet(t, "203.0.113.88", "10.0.2.15"), stack.Prerouting, nil, nil); v != stack.RuleContinue {
		t.Fatalf("restored setTarget verdict = %v, want RuleContinue", v)
	}
	restoredReg := ipset.ExistingForStack(restoredStk)
	dynProbe := hostElement("203.0.113.88")
	if ret := restoredReg.Uadt("dynlist", ipset.AdtTest, &dynProbe, 0); ret != 1 {
		t.Fatalf("restored dynlist test for 203.0.113.88 = %d, want 1", ret)
	}

	// StatisticMatcher spent 2 packets before save, so the next packet is #3 and matches.
	if ok, _ := rStat.Match(stack.Input, nil, "", ""); !ok {
		t.Error("restored StatisticMatcher did not match packet #3")
	}
	if ok, _ := rStat.Match(stack.Input, nil, "", ""); ok {
		t.Error("restored StatisticMatcher matched packet #4")
	}

	// logTarget and nflogTarget continue and deliver lines once SetStackLog binds restoredStk.
	var logRecords []logRecord
	SetStackLog(restoredStk, func(level int, line string) {
		logRecords = append(logRecords, logRecord{level: level, line: line})
	})
	t.Cleanup(func() { SetStackLog(restoredStk, nil) })
	if v, _ := rLogT.ActionOnInterfaces(newIPv4Packet(t, "10.1.1.1", "10.2.2.2"), stack.Input, nil, nil, "eth0", ""); v != stack.RuleContinue {
		t.Fatalf("restored logTarget verdict = %v, want RuleContinue", v)
	}
	if len(logRecords) != 1 || logRecords[0].level != 4 || !strings.HasPrefix(logRecords[0].line, "cp-log: IN=eth0 OUT= ") {
		t.Fatalf("restored logTarget records = %+v, want one level-4 cp-log record", logRecords)
	}
	if v, _ := rNFLogT.Action(newIPv4Packet(t, "10.1.1.1", "10.2.2.2"), stack.Input, nil, nil); v != stack.RuleContinue {
		t.Fatalf("restored nflogTarget verdict = %v, want RuleContinue", v)
	}
}

func TestTwoSandboxesIsolateStackAndKernelExtensionsAcrossSaveRestore(t *testing.T) {
	k1, k2 := &kernel.Kernel{}, &kernel.Kernel{}
	mod1 := ipset.ModuleFor(k1)
	mod2 := ipset.ModuleFor(k2)
	mod1.SetMaxSets(16)
	mod2.SetMaxSets(32)
	k1.SetReportedMemory(1 << 30)
	k2.SetReportedMemory(2 << 30)

	stk1 := stack.New(stack.Options{Clock: faketime.NewManualClock()})
	stk2 := stack.New(stack.Options{Clock: faketime.NewManualClock()})
	t.Cleanup(stk1.Destroy)
	t.Cleanup(stk2.Destroy)

	stk1.SetBridgeNetfilter(header.IPv4ProtocolNumber, false)
	stk1.SetBridgeNetfilter(header.IPv6ProtocolNumber, true)
	stk2.SetBridgeNetfilter(header.IPv4ProtocolNumber, true)
	stk2.SetBridgeNetfilter(header.IPv6ProtocolNumber, false)

	RecentModuleOf(stk1).SetListTot(11)
	RecentModuleOf(stk2).SetListTot(22)

	reg1 := ipset.ForStack(stk1, mod1)
	reg2 := ipset.ForStack(stk2, mod2)
	_, hipRev, err := ipset.FindType("hash:ip", ipset.FamilyIPv4)
	if err != nil {
		t.Fatalf("FindType: %v", err)
	}
	for _, r := range []*ipset.Registry{reg1, reg2} {
		if err := r.Create(&ipset.CreateParams{Name: "shared-name", TypeName: "hash:ip", Family: ipset.FamilyIPv4, Revision: hipRev}); err != nil {
			t.Fatalf("Create(shared-name): %v", err)
		}
	}
	el1 := hostElement("10.101.0.1")
	el2 := hostElement("10.202.0.2")
	if ret := reg1.Uadt("shared-name", ipset.AdtAdd, &el1, 0); ret != 0 {
		t.Fatalf("reg1 add: %d", ret)
	}
	if ret := reg2.Uadt("shared-name", ipset.AdtAdd, &el2, 0); ret != 0 {
		t.Fatalf("reg2 add: %d", ret)
	}

	rSet1 := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentSet, name: "aff"}))
	rCheck1 := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentCheck, name: "aff"}))
	rSet2 := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentSet, name: "aff"}))
	rCheck2 := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentCheck, name: "aff"}))

	if err := bindMatcherStacks(stk1, []stack.Rule{{Matchers: []stack.Matcher{rSet1, rCheck1}}}); err != nil {
		t.Fatalf("bindMatcherStacks(stk1): %v", err)
	}
	if err := bindMatcherStacks(stk2, []stack.Rule{{Matchers: []stack.Matcher{rSet2, rCheck2}}}); err != nil {
		t.Fatalf("bindMatcherStacks(stk2): %v", err)
	}
	rSet1.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.11", "10.0.0.1"), "", "")
	rSet2.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.22", "10.0.0.1"), "", "")

	verifyIsolation := func(phase string, s1, s2 *stack.Stack, ka, kb *kernel.Kernel, c1, c2 stack.Matcher) {
		t.Helper()
		if got := ipset.ModuleFor(ka).MaxSets(); got != 16 {
			t.Fatalf("%s: kernel 1 MaxSets = %d, want 16", phase, got)
		}
		if got := ipset.ModuleFor(kb).MaxSets(); got != 32 {
			t.Fatalf("%s: kernel 2 MaxSets = %d, want 32", phase, got)
		}
		if mem, ok := ka.ReportedMemory(); !ok || mem != 1<<30 {
			t.Fatalf("%s: kernel 1 ReportedMemory = (%d, %v), want (1GiB, true)", phase, mem, ok)
		}
		if mem, ok := kb.ReportedMemory(); !ok || mem != 2<<30 {
			t.Fatalf("%s: kernel 2 ReportedMemory = (%d, %v), want (2GiB, true)", phase, mem, ok)
		}
		if s1.BridgeNetfilter(header.IPv4ProtocolNumber) || !s1.BridgeNetfilter(header.IPv6ProtocolNumber) {
			t.Fatalf("%s: stack 1 BridgeNetfilter = (v4=%v, v6=%v), want (false, true)", phase, s1.BridgeNetfilter(header.IPv4ProtocolNumber), s1.BridgeNetfilter(header.IPv6ProtocolNumber))
		}
		if !s2.BridgeNetfilter(header.IPv4ProtocolNumber) || s2.BridgeNetfilter(header.IPv6ProtocolNumber) {
			t.Fatalf("%s: stack 2 BridgeNetfilter = (v4=%v, v6=%v), want (true, false)", phase, s2.BridgeNetfilter(header.IPv4ProtocolNumber), s2.BridgeNetfilter(header.IPv6ProtocolNumber))
		}
		if got := RecentModuleOf(s1).ListTot(); got != 11 {
			t.Fatalf("%s: stack 1 ListTot = %d, want 11", phase, got)
		}
		if got := RecentModuleOf(s2).ListTot(); got != 22 {
			t.Fatalf("%s: stack 2 ListTot = %d, want 22", phase, got)
		}
		ra := ipset.ExistingForStack(s1)
		rb := ipset.ExistingForStack(s2)
		p1, p2 := el1, el2
		if ra.Uadt("shared-name", ipset.AdtTest, &p1, 0) != 1 || ra.Uadt("shared-name", ipset.AdtTest, &p2, 0) != 0 {
			t.Fatalf("%s: stack 1 ipset leaked or lost membership", phase)
		}
		if rb.Uadt("shared-name", ipset.AdtTest, &p2, 0) != 1 || rb.Uadt("shared-name", ipset.AdtTest, &p1, 0) != 0 {
			t.Fatalf("%s: stack 2 ipset leaked or lost membership", phase)
		}
		if ok, _ := c1.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.11", "10.0.0.1"), "", ""); !ok {
			t.Fatalf("%s: stack 1 recent lost 192.0.2.11", phase)
		}
		if ok, _ := c1.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.22", "10.0.0.1"), "", ""); ok {
			t.Fatalf("%s: stack 1 recent leaked 192.0.2.22 from stack 2", phase)
		}
		if ok, _ := c2.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.22", "10.0.0.1"), "", ""); !ok {
			t.Fatalf("%s: stack 2 recent lost 192.0.2.22", phase)
		}
		if ok, _ := c2.Match(stack.Prerouting, newIPv4Packet(t, "192.0.2.11", "10.0.0.1"), "", ""); ok {
			t.Fatalf("%s: stack 2 recent leaked 192.0.2.11 from stack 1", phase)
		}
	}

	verifyIsolation("pre-save", stk1, stk2, k1, k2, rCheck1, rCheck2)

	stk1.Pause()
	stk2.Pause()
	var buf1, buf2 bytes.Buffer
	s1 := []any{stk1, k1, []stack.Rule{{Matchers: []stack.Matcher{rCheck1}}}}
	s2 := []any{stk2, k2, []stack.Rule{{Matchers: []stack.Matcher{rCheck2}}}}
	if _, err := state.Save(context.Background(), &buf1, &s1); err != nil {
		t.Fatalf("state.Save(sandbox 1): %v", err)
	}
	if _, err := state.Save(context.Background(), &buf2, &s2); err != nil {
		t.Fatalf("state.Save(sandbox 2): %v", err)
	}

	var l1, l2 []any
	if _, err := state.Load(context.Background(), bytes.NewReader(buf1.Bytes()), &l1); err != nil {
		t.Fatalf("state.Load(sandbox 1): %v", err)
	}
	if _, err := state.Load(context.Background(), bytes.NewReader(buf2.Bytes()), &l2); err != nil {
		t.Fatalf("state.Load(sandbox 2): %v", err)
	}
	rs1 := l1[0].(*stack.Stack)
	rs2 := l2[0].(*stack.Stack)
	rk1 := l1[1].(*kernel.Kernel)
	rk2 := l2[1].(*kernel.Kernel)
	rc1 := slices.Clone(l1[2].([]stack.Rule))[0].Matchers[0]
	rc2 := slices.Clone(l2[2].([]stack.Rule))[0].Matchers[0]
	t.Cleanup(rs1.Destroy)
	t.Cleanup(rs2.Destroy)
	rs1.ResetConfig()
	rs1.ReplaceConfig(stack.New(stack.Options{Clock: rs1.Clock()}))
	rs1.Restore()
	rs2.ResetConfig()
	rs2.ReplaceConfig(stack.New(stack.Options{Clock: rs2.Clock()}))
	rs2.Restore()

	verifyIsolation("post-load", rs1, rs2, rk1, rk2, rc1, rc2)
}

func TestStackSaveRestoreDropsUnsavedRuleAndDumpRefs(t *testing.T) {
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            clock,
	})
	t.Cleanup(stk.Destroy)

	reg := ipset.ForStack(stk, nil)
	_, hipRev, err := ipset.FindType("hash:ip", ipset.FamilyIPv4)
	if err != nil {
		t.Fatalf("FindType(hash:ip): %v", err)
	}
	_, lsetRev, err := ipset.FindType("list:set", ipset.FamilyUnspec)
	if err != nil {
		t.Fatalf("FindType(list:set): %v", err)
	}
	for _, name := range []string{"rule-pinned", "dump-pinned", "swap-peer", "list-member"} {
		if err := reg.Create(&ipset.CreateParams{
			Name:     name,
			TypeName: "hash:ip",
			Family:   ipset.FamilyIPv4,
			Revision: hipRev,
		}); err != nil {
			t.Fatalf("Create(%s): %v", name, err)
		}
	}
	if err := reg.Create(&ipset.CreateParams{
		Name:     "parent-list",
		TypeName: "list:set",
		Family:   ipset.FamilyUnspec,
		Revision: lsetRev,
	}); err != nil {
		t.Fatalf("Create(parent-list): %v", err)
	}
	memberElem := ipset.Element{Has: ipset.HasName, Name: "list-member"}
	if ret := reg.Uadt("parent-list", ipset.AdtAdd, &memberElem, 0); ret != 0 {
		t.Fatalf("Uadt(parent-list add list-member): %d", ret)
	}

	rulePinnedID, _, ok := reg.Lookup("rule-pinned")
	if !ok {
		t.Fatal("Lookup(rule-pinned) failed")
	}
	setM := parseSetMatch(t, stack.EmptyFilter4(), setMatchSpec{rev: setMatchRevision4, index: rulePinnedID, dim: 1, flags: testDimOneSrc})
	setT := parseSetTarget(t, stack.EmptyFilter4(), setTargetSpec{
		rev: 2,
		add: setInfo{index: rulePinnedID, dim: 1, flags: testDimOneSrc},
		del: noSet,
	})
	recentM := parseOneMatcher(t, stack.EmptyFilter4(), recentEntryBuf(recentInfo{rev: 1, checkSet: recentSet, name: "unsaved-ipt-recent"}))
	rules := []stack.Rule{
		{Matchers: []stack.Matcher{setM, recentM}, Target: setT},
	}
	if err := bindMatcherStacks(stk, rules); err != nil {
		t.Fatalf("bindMatcherStacks: %v", err)
	}

	// Start an unsaved netlink dump that pins dump-pinned with refNetlink > 0 and listings > 0.
	dump, err := reg.NewDump("dump-pinned", true)
	if err != nil {
		t.Fatalf("NewDump(dump-pinned): %v", err)
	}
	defer dump.Close()
	if _, _, more, err := dump.Next(); !more || err != nil {
		t.Fatalf("dump.Next: more=%v err=%v", more, err)
	}

	// Before checkpoint, rule-pinned, dump-pinned, list-member, and RecentModule are busy.
	if err := reg.Destroy("rule-pinned", false, false); err == nil {
		t.Fatal("Destroy(rule-pinned) succeeded while referenced by rules")
	}
	if err := reg.Destroy("dump-pinned", false, false); err == nil {
		t.Fatal("Destroy(dump-pinned) succeeded while pinned by an active dump")
	}
	if err := RecentModuleOf(stk).SetListTot(50); err != ErrRecentModuleBusy {
		t.Fatalf("pre-save SetListTot = %v, want ErrRecentModuleBusy", err)
	}

	stk.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &stk); err != nil {
		t.Fatalf("state.Save(stk): %v", err)
	}
	var restoredStk *stack.Stack
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &restoredStk); err != nil {
		t.Fatalf("state.Load(stk): %v", err)
	}
	t.Cleanup(restoredStk.Destroy)
	restoredStk.ResetConfig()
	restoredStk.ReplaceConfig(stack.New(stack.Options{Clock: clock}))
	restoredStk.Restore()

	restoredReg := ipset.ExistingForStack(restoredStk)
	if restoredReg == nil {
		t.Fatal("ExistingForStack(restoredStk) = nil")
	}
	// Unsaved IPTables rules and netlink dumps must not strand ref, refNetlink, or listings.
	if err := restoredReg.Rename("rule-pinned", "rule-unpinned"); err != nil {
		t.Fatalf("post-restore Rename(rule-pinned): %v", err)
	}
	if err := restoredReg.Destroy("rule-unpinned", false, false); err != nil {
		t.Fatalf("post-restore Destroy(rule-unpinned): %v", err)
	}
	if err := restoredReg.Swap("dump-pinned", "swap-peer"); err != nil {
		t.Fatalf("post-restore Swap(dump-pinned, swap-peer): %v", err)
	}
	if err := restoredReg.Destroy("dump-pinned", false, false); err != nil {
		t.Fatalf("post-restore Destroy(dump-pinned): %v", err)
	}
	if err := restoredReg.Destroy("swap-peer", false, false); err != nil {
		t.Fatalf("post-restore Destroy(swap-peer): %v", err)
	}

	// Saved list:set membership must still keep list-member referenced until parent-list is destroyed.
	if err := restoredReg.Destroy("list-member", false, false); err == nil {
		t.Fatal("post-restore Destroy(list-member) succeeded while still held by parent-list")
	}
	if err := restoredReg.Destroy("parent-list", false, false); err != nil {
		t.Fatalf("post-restore Destroy(parent-list): %v", err)
	}
	if err := restoredReg.Destroy("list-member", false, false); err != nil {
		t.Fatalf("post-restore Destroy(list-member) after parent-list removal: %v", err)
	}

	// Unsaved RecentMatcher rules must not strand RecentModule.lists > 0.
	if err := RecentModuleOf(restoredStk).SetListTot(50); err != nil {
		t.Fatalf("post-restore RecentModule.SetListTot(50): %v", err)
	}
	if err := RecentModuleOf(restoredStk).SetPktListTot(64); err != nil {
		t.Fatalf("post-restore RecentModule.SetPktListTot(64): %v", err)
	}
}
