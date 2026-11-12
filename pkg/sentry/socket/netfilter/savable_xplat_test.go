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
	tcpMatchers, err := parseMatchers(nil, tcpFilter, tcpEntries)
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
	udpMatchers, err := parseMatchers(nil, udpFilter, udpEntries)
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
	// Stack.tables is nosave upstream, so save the IPTables object itself.
	saved := []any{stk.IPTables(), clock}
	if _, err := state.Save(context.Background(), &buf, &saved); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	var loaded []any
	if _, err := state.Load(context.Background(), bytes.NewReader(buf.Bytes()), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredTables := loaded[0].(*stack.IPTables)

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
