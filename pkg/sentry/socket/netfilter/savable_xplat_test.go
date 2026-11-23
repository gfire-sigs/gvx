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
	"reflect"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/faketime"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv6"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// concatEntries joins marshalled xt_entry_match records, as userspace does.
func concatEntries(entries ...[]byte) []byte {
	return slices.Concat(entries...)
}

// conntrackEntry returns an xt_conntrack match of revision 2 for --ctstate.
func conntrackEntry(stateMask uint16) []byte {
	info := linux.XTConntrackMtinfo2{MatchFlags: linux.XT_CONNTRACK_STATE, StateMask: stateMask}
	buf := marshalEntryMatch(matcherNameConntrack, marshal.Marshal(&info))
	buf[revisionOffset] = 2
	return buf
}

// standardRules returns a TCP rule that ends in DNAT and a UDP rule that ends
// in SNAT. Each rule goes through the parsers that SetEntries uses.
func standardRules(t *testing.T) []stack.Rule {
	t.Helper()
	tcpFilter := stack.EmptyFilter4()
	tcpFilter.Protocol, tcpFilter.CheckProtocol = header.TCPProtocolNumber, true
	udpFilter := stack.EmptyFilter4()
	udpFilter.Protocol, udpFilter.CheckProtocol = header.UDPProtocolNumber, true

	tcpEntries := concatEntries(
		marshalMatcher(&TCPMatcher{destinationPortStart: 80, destinationPortEnd: 80, sourcePortEnd: 0xffff, flagMask: 0x12, flagCompare: 0x02}),
		marshalMatcher(&multiportMatcher{flags: linux.XT_MULTIPORT_DESTINATION, count: 2, ports: []uint16{8080, 8443}}),
		conntrackEntry(0x0e),
		marshalMatcher(&MarkMatcher{mark: 0x10, mask: 0xff, invert: true}),
		marshalMatcher(&commentMatcher{comment: "kube-proxy: service"}),
	)
	tcpMatchers, err := parseMatchers(nil, nil, tcpFilter, tcpEntries)
	if err != nil {
		t.Fatalf("parseMatchers(tcp): %v", err)
	}
	// The owner parsers need an ID mapper, which needs the auth package that
	// the test boundary does not allow. Build the owner matchers directly.
	tcpMatchers = append(tcpMatchers, &OwnerMatcher{uid: 1000, gid: 100, matchUID: true, matchGID: true, invertGID: true})
	dnat, sysErr := parseTarget(tcpFilter, marshalTarget(&dnatTarget{
		DNATTarget: stack.DNATTarget{
			NetworkProtocol: header.IPv4ProtocolNumber,
			Addr:            tcpip.AddrFrom4([4]byte{172, 17, 0, 2}),
			Port:            8080,
			ChangeAddress:   true,
			ChangePort:      true,
		},
		revision: 2,
	}), false, natTable)
	if sysErr != nil {
		t.Fatalf("parseTarget(DNAT): %v", sysErr)
	}

	udpEntries := concatEntries(
		marshalMatcher(&UDPMatcher{destinationPortStart: 53, destinationPortEnd: 53, sourcePortEnd: 0xffff}),
		marshalMatcher(&multiportMatcherV1{flags: linux.XT_MULTIPORT_SOURCE, count: 1, ports: []uint16{5353}, pflags: []uint8{0}}),
	)
	udpMatchers, err := parseMatchers(nil, nil, udpFilter, udpEntries)
	if err != nil {
		t.Fatalf("parseMatchers(udp): %v", err)
	}
	udpMatchers = append(udpMatchers, &OwnerMatcherV1{uid: 0, matchUID: true, invertUID: true})
	snat, sysErr := parseTarget(udpFilter, marshalTarget(&snatTarget{
		SNATTarget: stack.SNATTarget{
			NetworkProtocol: header.IPv4ProtocolNumber,
			Addr:            tcpip.AddrFrom4([4]byte{192, 0, 2, 1}),
			Port:            5353,
			ChangeAddress:   true,
			ChangePort:      true,
		},
		revision: 2,
	}), false, natTable)
	if sysErr != nil {
		t.Fatalf("parseTarget(SNAT): %v", sysErr)
	}
	return []stack.Rule{
		{Filter: tcpFilter, Matchers: tcpMatchers, Target: dnat},
		{Filter: udpFilter, Matchers: udpMatchers, Target: snat},
	}
}

func TestIPTablesWithStandardMatchersAndTargetsSurvivesSaveLoad(t *testing.T) {
	clock := faketime.NewManualClock()
	stk := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		Clock:            clock,
	})
	t.Cleanup(stk.Destroy)
	configureNICsForFilterStack(t, stk)
	stk.EnableIPTablesCheckpoint()

	rules := standardRules(t)
	wantTypes := []string{
		"*netfilter.TCPMatcher", "*netfilter.multiportMatcher", "*netfilter.conntrackMatcher",
		"*netfilter.MarkMatcher", "*netfilter.commentMatcher", "*netfilter.OwnerMatcher",
		"*netfilter.UDPMatcher", "*netfilter.multiportMatcherV1", "*netfilter.OwnerMatcherV1",
	}
	var gotTypes []string
	for _, r := range rules {
		for _, m := range r.Matchers {
			gotTypes = append(gotTypes, reflect.TypeOf(m).String())
		}
	}
	if !slices.Equal(gotTypes, wantTypes) {
		t.Fatalf("parsed matcher types = %v, want %v", gotTypes, wantTypes)
	}

	table := insertChainRules(stk.IPTables().GetTable(stack.NATID, false), stack.Prerouting, rules)
	stk.IPTables().ForceReplaceTable(stack.NATID, table, false)
	wantRules := stk.IPTables().GetTable(stack.NATID, false).Rules

	stk.Pause()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, &stk); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var restored *stack.Stack
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	t.Cleanup(restored.Destroy)
	install, err := restored.PrepareIPTablesCheckpoint(nil)
	if err != nil || install == nil {
		t.Fatalf("prepare saved guest rules: %v", err)
	}
	install()
	restoredTables := restored.IPTables()

	gotRules := restoredTables.GetTable(stack.NATID, false).Rules
	if len(gotRules) != len(wantRules) {
		t.Fatalf("restored NAT rules = %d, want %d", len(gotRules), len(wantRules))
	}
	for i := range rules {
		got, want := gotRules[i], wantRules[i]
		if !reflect.DeepEqual(got.Matchers, want.Matchers) {
			t.Errorf("rule %d: restored matchers = %+v, want %+v", i, got.Matchers, want.Matchers)
		}
		if !reflect.DeepEqual(got.Target, want.Target) {
			t.Errorf("rule %d: restored target = %+v, want %+v", i, got.Target, want.Target)
		}
		for j, m := range want.Matchers {
			if !bytes.Equal(marshalMatcher(got.Matchers[j]), marshalMatcher(m)) {
				t.Errorf("rule %d matcher %d (%T): restored ABI bytes differ", i, j, m)
			}
		}
		if !bytes.Equal(marshalTarget(got.Target), marshalTarget(want.Target)) {
			t.Errorf("rule %d target (%T): restored ABI bytes differ", i, want.Target)
		}
	}
}

func TestIPTablesCheckpointAcceptsRulesWrittenThroughSetEntries(t *testing.T) {
	original := stack.New(stack.Options{Clock: faketime.NewManualClock(), DefaultIPTables: DefaultLinuxTables})
	t.Cleanup(original.Destroy)
	original.EnableIPTablesCheckpoint()
	var name linux.TableName
	copy(name[:], filterTable)
	// The writer accepts alignment padding after a fixed-size comment.
	// The guest ABI dump does not preserve that padding when it emits rules.
	const padding = 8
	paddedComment := marshalEntryMatch(matcherNameComment, make([]byte, linux.SizeOfXTCommentInfo+padding))
	commentSize := len(paddedComment) - padding
	for _, ipv6 := range [...]bool{false, true} {
		table := original.IPTables().GetTable(stack.FilterID, ipv6)
		filter, entrySize := stack.EmptyFilter4(), linux.SizeOfIPTEntry
		if ipv6 {
			filter, entrySize = stack.EmptyFilter6(), linux.SizeOfIP6TEntry
		}
		proto := filter.NetworkProtocol()
		jump := &JumpTarget{NetworkProtocol: proto}
		table = insertChainRules(table, stack.Input, []stack.Rule{{
			Filter: filter, Matchers: []stack.Matcher{&commentMatcher{}}, Target: jump,
		}})
		last := len(table.Rules) - 1
		jump.Offset = uint32(last*(entrySize+linux.SizeOfXTStandardTarget) + entrySize + linux.SizeOfXTErrorTarget + len(paddedComment))
		table.Rules = append(table.Rules[:last:last],
			stack.Rule{Filter: filter, Target: &userChainTarget{stack.UserChainTarget{Name: "GUEST", NetworkProtocol: proto}}},
			stack.Rule{Filter: filter, Matchers: []stack.Matcher{&commentMatcher{comment: "guest policy"}}, Target: &dropTarget{stack.DropTarget{NetworkProtocol: proto}}},
			stack.Rule{Filter: filter, Target: &returnTarget{stack.ReturnTarget{NetworkProtocol: proto}}},
			table.Rules[last],
		)
		var entries []byte
		var info linux.IPTGetinfo
		if ipv6 {
			wire, metadata := getEntries6(table, name)
			info = metadata
			for i, entry := range wire.Entrytable {
				if i == 0 {
					entry.Elems = append(slices.Clone(paddedComment), entry.Elems[commentSize:]...)
					entry.Entry.TargetOffset += padding
					entry.Entry.NextOffset += padding
				}
				entries = append(entries, marshal.Marshal(&entry)...)
			}
		} else {
			wire, metadata := getEntries4(table, name)
			info = metadata
			for i, entry := range wire.Entrytable {
				if i == 0 {
					entry.Elems = append(slices.Clone(paddedComment), entry.Elems[commentSize:]...)
					entry.Entry.TargetOffset += padding
					entry.Entry.NextOffset += padding
				}
				entries = append(entries, marshal.Marshal(&entry)...)
			}
		}
		replace := linux.IPTReplace{
			Name: name, ValidHooks: info.ValidHooks, NumEntries: info.NumEntries,
			Size: info.Size, HookEntry: info.HookEntry, Underflow: info.Underflow,
		}
		replace.Size += padding
		for hook := range replace.HookEntry {
			if replace.HookEntry[hook] != 0 {
				replace.HookEntry[hook] += padding
			}
			if replace.Underflow[hook] != 0 {
				replace.Underflow[hook] += padding
			}
		}
		if err := SetEntries(nil, original, append(marshal.Marshal(&replace), entries...), ipv6); err != nil {
			t.Fatalf("SetEntries (ipv6=%t): %v", ipv6, err)
		}
	}

	var buf bytes.Buffer
	if _, err := state.Save(t.Context(), &buf, &original); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var restored *stack.Stack
	if _, err := state.Load(t.Context(), &buf, &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	t.Cleanup(restored.Destroy)
	install, err := restored.PrepareIPTablesCheckpoint(func(it *stack.IPTables, modified bool) error {
		return ValidateIPTablesCheckpoint(t.Context(), restored, it, modified)
	})
	if err != nil || install == nil {
		t.Fatalf("prepare rules written by SetEntries: %v", err)
	}
	if restored.IPTables() != nil {
		t.Fatal("validation installed iptables")
	}
	install()
	for _, ipv6 := range [...]bool{false, true} {
		table := restored.IPTables().GetTable(stack.FilterID, ipv6)
		jump := table.Rules[table.BuiltinChains[stack.Input]].Target.(*JumpTarget)
		wantOffset := uint32(0)
		if ipv6 {
			wire, _ := getEntries6(table, name)
			for _, entry := range wire.Entrytable[:jump.RuleNum] {
				wantOffset += uint32(entry.Entry.NextOffset)
			}
		} else {
			wire, _ := getEntries4(table, name)
			for _, entry := range wire.Entrytable[:jump.RuleNum] {
				wantOffset += uint32(entry.Entry.NextOffset)
			}
		}
		if jump.Offset != wantOffset {
			t.Errorf("restored jump offset (ipv6=%t) = %d, want %d from the guest ABI", ipv6, jump.Offset, wantOffset)
		}
		rule := table.Rules[jump.RuleNum]
		if got, ok := rule.Matchers[0].(*commentMatcher); !ok || got.comment != "guest policy" {
			t.Errorf("restored jump destination (ipv6=%t) lost its comment: %v", ipv6, rule.Matchers)
		}
		if verdict, _ := rule.Target.Action(nil, stack.Input, nil, nil); verdict != stack.RuleDrop {
			t.Errorf("restored guest target (ipv6=%t) = %v, want DROP", ipv6, verdict)
		}
	}
}

func TestIPTablesCheckpointRejectsNonDefaultInactiveRules(t *testing.T) {
	st := stack.New(stack.Options{Clock: faketime.NewManualClock(), DefaultIPTables: DefaultLinuxTables})
	t.Cleanup(st.Destroy)
	if err := ValidateIPTablesCheckpoint(t.Context(), st, st.IPTables(), false); err != nil {
		t.Fatalf("validate inactive defaults: %v", err)
	}
	table := st.IPTables().GetTable(stack.FilterID, true)
	table.Rules = slices.Clone(table.Rules)
	table.Rules[table.Underflows[stack.Input]].Target = &dropTarget{stack.DropTarget{NetworkProtocol: header.IPv6ProtocolNumber}}
	st.IPTables().ReplaceTable(stack.FilterID, table, true)
	if err := ValidateIPTablesCheckpoint(t.Context(), st, st.IPTables(), false); err == nil || !strings.Contains(err.Error(), "unmodified rules differ") {
		t.Fatalf("validate inactive IPv6 DROP policy = %v, want non-default rule error", err)
	}
}
