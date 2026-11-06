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
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/link/channel"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

const (
	fibEth0 = tcpip.NICID(1)
	fibWG0  = tcpip.NICID(2)
)

func fibAddr(a, b, c, d byte) tcpip.Address { return tcpip.AddrFrom4([4]byte{a, b, c, d}) }

func fibSubnet(t *testing.T, a, b, c, d byte, prefix int) tcpip.Subnet {
	t.Helper()
	return tcpip.AddressWithPrefix{Address: fibAddr(a, b, c, d), PrefixLen: prefix}.Subnet()
}

// newFibStack returns a stack with eth0 (10.0.0.2/24) and wg0 (10.9.0.2/32).
// The table main holds the route to 10.0.0.0/24 and a default route through
// 10.0.0.1 on eth0, as a host with one uplink has.
func newFibStack(t *testing.T) *stack.Stack {
	t.Helper()
	s := stack.New(stack.Options{NetworkProtocols: []stack.NetworkProtocolFactory{ipv4.NewProtocol}})
	t.Cleanup(func() { s.Close() })
	for _, n := range []struct {
		id   tcpip.NICID
		name string
		addr tcpip.AddressWithPrefix
	}{
		{fibEth0, "eth0", tcpip.AddressWithPrefix{Address: fibAddr(10, 0, 0, 2), PrefixLen: 24}},
		{fibWG0, "wg0", tcpip.AddressWithPrefix{Address: fibAddr(10, 9, 0, 2), PrefixLen: 32}},
	} {
		if err := s.CreateNICWithOptions(n.id, channel.New(8, 1500, ""), stack.NICOptions{Name: n.name}); err != nil {
			t.Fatalf("CreateNIC %s: %v", n.name, err)
		}
		if err := s.AddProtocolAddress(n.id, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber, AddressWithPrefix: n.addr}, stack.AddressProperties{}); err != nil {
			t.Fatalf("AddProtocolAddress %s: %v", n.name, err)
		}
	}
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 10, 0, 0, 0, 24), NIC: fibEth0})
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), Gateway: fibAddr(10, 0, 0, 1), NIC: fibEth0})
	return s
}

// outgoingNIC returns the NIC that FindRouteFlow picks, or the lookup error.
func outgoingNIC(t *testing.T, s *stack.Stack, flow stack.RouteFlow, dst tcpip.Address) (tcpip.NICID, tcpip.Error) {
	t.Helper()
	r, err := s.FindRouteFlow(flow, 0, tcpip.Address{}, dst, ipv4.ProtocolNumber, false)
	if err != nil {
		return 0, err
	}
	defer r.Release()
	return r.NICID(), nil
}

func TestFindRouteUsesTheTableMainWithTheDefaultRules(t *testing.T) {
	s := newFibStack(t)
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(8, 8, 8, 8)); err != nil || got != fibEth0 {
		t.Fatalf("lookup = (%d, %v), want NIC %d", got, err, fibEth0)
	}
	rules := s.Rules(ipv4.ProtocolNumber)
	var priorities []uint32
	for _, r := range rules {
		priorities = append(priorities, r.Priority)
	}
	if len(priorities) != 3 || priorities[0] != 0 || priorities[1] != 32766 || priorities[2] != 32767 {
		t.Errorf("default IPv4 rule priorities = %v, want [0 32766 32767]", priorities)
	}
	if n := len(s.Rules(header.IPv6ProtocolNumber)); n != 2 {
		t.Errorf("default IPv6 rule count = %d, want 2", n)
	}
}

func TestRouteTypesEndTheLookupWithTheirError(t *testing.T) {
	for _, tc := range []struct {
		name string
		typ  tcpip.RouteType
		want tcpip.Error
	}{
		{"blackhole", tcpip.RouteTypeBlackhole, &tcpip.ErrRouteBlackhole{}},
		{"unreachable", tcpip.RouteTypeUnreachable, &tcpip.ErrHostUnreachable{}},
		{"prohibit", tcpip.RouteTypeProhibit, &tcpip.ErrRouteProhibited{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newFibStack(t)
			rt := tcpip.Route{Destination: fibSubnet(t, 10, 42, 0, 0, 26), RouteAttrs: tcpip.RouteAttrs{Type: tc.typ}}
			if _, err := s.InsertRoute(rt, stack.RouteInsert{Create: true, Excl: true}); err != nil {
				t.Fatalf("InsertRoute: %v", err)
			}
			_, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 42, 0, 5))
			if err == nil || err.String() != tc.want.String() {
				t.Errorf("lookup inside the prefix = %v, want %v", err, tc.want)
			}
			if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 42, 0, 70)); err != nil || got != fibEth0 {
				t.Errorf("lookup outside the prefix = (%d, %v), want NIC %d", got, err, fibEth0)
			}
		})
	}
}

func TestMoreSpecificRouteBeatsBlackhole(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 10, 42, 0, 0, 26), RouteAttrs: tcpip.RouteAttrs{Type: tcpip.RouteTypeBlackhole}})
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 10, 42, 0, 7, 32), NIC: fibWG0})
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 42, 0, 7)); err != nil || got != fibWG0 {
		t.Errorf("lookup of the pod address = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if _, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 42, 0, 8)); err == nil {
		t.Errorf("lookup of another address in the block succeeded, want the blackhole error")
	}
}

func TestThrowRouteSendsTheLookupToTheNextRule(t *testing.T) {
	s := newFibStack(t)
	// Table 100 throws 8.8.8.0/24, so the table main answers with its default route.
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 8, 8, 8, 0, 24), RouteAttrs: tcpip.RouteAttrs{Table: 100, Type: tcpip.RouteTypeThrow}})
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100}})
	if err := s.AddRule(ipv4.ProtocolNumber, stack.PolicyRule{Priority: 100, Action: stack.RuleActionToTable, Table: 100, SuppressPrefixLen: -1}, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(8, 8, 8, 8)); err != nil || got != fibEth0 {
		t.Errorf("thrown destination = (%d, %v), want NIC %d", got, err, fibEth0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(1, 1, 1, 1)); err != nil || got != fibWG0 {
		t.Errorf("other destination = (%d, %v), want NIC %d", got, err, fibWG0)
	}
}

func TestFwmarkRuleSelectsAnotherTable(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100}})
	rule := stack.PolicyRule{Priority: 100, Action: stack.RuleActionToTable, Table: 100, Mark: 1, MarkMask: 0xffffffff, SuppressPrefixLen: -1}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	dst := fibAddr(8, 8, 8, 8)
	if got, err := outgoingNIC(t, s, stack.RouteFlow{Mark: 1}, dst); err != nil || got != fibWG0 {
		t.Errorf("marked lookup = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{Mark: 2}, dst); err != nil || got != fibEth0 {
		t.Errorf("other mark = (%d, %v), want NIC %d", got, err, fibEth0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, dst); err != nil || got != fibEth0 {
		t.Errorf("no mark = (%d, %v), want NIC %d", got, err, fibEth0)
	}
}

// TestWGQuickFullTunnelRules builds the rules and tables that wg-quick makes
// for AllowedIPs 0.0.0.0/0: every packet without the mark of the tunnel socket
// goes to wg0, and a more specific route of the table main still wins.
func TestWGQuickFullTunnelRules(t *testing.T) {
	s := newFibStack(t)
	const wgMark = 51820
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: wgMark}})
	notMark := stack.PolicyRule{Priority: 32765, Action: stack.RuleActionToTable, Table: wgMark, Mark: wgMark, MarkMask: 0xffffffff, Invert: true, SuppressPrefixLen: -1}
	suppress := stack.PolicyRule{Priority: 32764, Action: stack.RuleActionToTable, Table: tcpip.RouteTableMain, SuppressPrefixLen: 0}
	for _, r := range []stack.PolicyRule{notMark, suppress} {
		if err := s.AddRule(ipv4.ProtocolNumber, r, stack.RuleInsert{Excl: true}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
	}
	for _, tc := range []struct {
		name string
		mark uint32
		dst  tcpip.Address
		want tcpip.NICID
	}{
		{"internet without mark", 0, fibAddr(8, 8, 8, 8), fibWG0},
		{"tunnel socket", wgMark, fibAddr(8, 8, 8, 8), fibEth0},
		{"local subnet without mark", 0, fibAddr(10, 0, 0, 7), fibEth0},
		{"other mark", 7, fibAddr(8, 8, 8, 8), fibWG0},
	} {
		got, err := outgoingNIC(t, s, stack.RouteFlow{Mark: tc.mark}, tc.dst)
		if err != nil || got != tc.want {
			t.Errorf("%s = (%d, %v), want NIC %d", tc.name, got, err, tc.want)
		}
	}
}

func TestRuleSourceAndInterfaceMatches(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100}})
	from := fibAddr(192, 168, 7, 0)
	rules := []stack.PolicyRule{
		{Priority: 100, Action: stack.RuleActionToTable, Table: 100, Src: from, SrcLen: 24, SuppressPrefixLen: -1},
		{Priority: 200, Action: stack.RuleActionToTable, Table: 100, InputName: "eth0", SuppressPrefixLen: -1},
	}
	for _, r := range rules {
		if err := s.AddRule(ipv4.ProtocolNumber, r, stack.RuleInsert{Excl: true}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
	}
	dst := fibAddr(8, 8, 8, 8)
	if got, err := outgoingNIC(t, s, stack.RouteFlow{Source: fibAddr(192, 168, 7, 9)}, dst); err != nil || got != fibWG0 {
		t.Errorf("forwarded packet from the source prefix = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{Source: fibAddr(192, 168, 8, 9)}, dst); err != nil || got != fibEth0 {
		t.Errorf("forwarded packet from another source = (%d, %v), want NIC %d", got, err, fibEth0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{InputNIC: fibEth0}, dst); err != nil || got != fibWG0 {
		t.Errorf("packet from eth0 = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{InputNIC: fibWG0}, dst); err != nil || got != fibEth0 {
		t.Errorf("packet from wg0 = (%d, %v), want NIC %d", got, err, fibEth0)
	}
}

func TestRuleActionsBlackholeProhibitUnreachable(t *testing.T) {
	for _, tc := range []struct {
		action stack.RuleAction
		want   string
	}{
		{stack.RuleActionBlackhole, (&tcpip.ErrRouteBlackhole{}).String()},
		{stack.RuleActionProhibit, (&tcpip.ErrRouteProhibited{}).String()},
		{stack.RuleActionUnreachable, (&tcpip.ErrNetworkUnreachable{}).String()},
	} {
		s := newFibStack(t)
		rule := stack.PolicyRule{Priority: 100, Action: tc.action, Mark: 5, MarkMask: 0xffffffff, SuppressPrefixLen: -1}
		if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
			t.Fatalf("AddRule: %v", err)
		}
		_, err := outgoingNIC(t, s, stack.RouteFlow{Mark: 5}, fibAddr(8, 8, 8, 8))
		if err == nil || err.String() != tc.want {
			t.Errorf("action %d lookup = %v, want %q", tc.action, err, tc.want)
		}
		if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(8, 8, 8, 8)); err != nil || got != fibEth0 {
			t.Errorf("action %d unmarked lookup = (%d, %v), want NIC %d", tc.action, got, err, fibEth0)
		}
	}
}

func TestGotoRuleSkipsTheRulesInBetween(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100}})
	for _, r := range []stack.PolicyRule{
		{Priority: 100, Action: stack.RuleActionGoto, Goto: 300, SuppressPrefixLen: -1},
		{Priority: 200, Action: stack.RuleActionBlackhole, SuppressPrefixLen: -1},
		{Priority: 300, Action: stack.RuleActionToTable, Table: 100, SuppressPrefixLen: -1},
	} {
		if err := s.AddRule(ipv4.ProtocolNumber, r, stack.RuleInsert{Excl: true}); err != nil {
			t.Fatalf("AddRule %d: %v", r.Priority, err)
		}
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(8, 8, 8, 8)); err != nil || got != fibWG0 {
		t.Errorf("lookup = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	if err := s.AddRule(ipv4.ProtocolNumber, stack.PolicyRule{Priority: 500, Action: stack.RuleActionGoto, Goto: 400}, stack.RuleInsert{}); !errors.Is(err, stack.ErrRuleInvalid) {
		t.Errorf("goto to a lower priority = %v, want ErrRuleInvalid", err)
	}
}

func TestAddRuleOrdersRulesAndRejectsDuplicates(t *testing.T) {
	s := newFibStack(t)
	if got := s.DefaultRulePriority(ipv4.ProtocolNumber); got != 32765 {
		t.Fatalf("DefaultRulePriority = %d, want 32765", got)
	}
	rule := stack.PolicyRule{Priority: 32765, Action: stack.RuleActionToTable, Table: 100, SuppressPrefixLen: -1}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	// The second rule is now the rule at 32765, so the next rule gets 32764,
	// as the second "ip rule add" of wg-quick does.
	if got := s.DefaultRulePriority(ipv4.ProtocolNumber); got != 32764 {
		t.Errorf("DefaultRulePriority after the first rule = %d, want 32764", got)
	}
	// A request without a priority matches the rule at any priority, as
	// rule_find() of Linux does.
	exists := &stack.RuleMatch{Action: stack.RuleActionToTable, Table: 100, HasTable: true}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true, Exists: exists}); !errors.Is(err, stack.ErrRuleExists) {
		t.Errorf("duplicate rule with Excl = %v, want ErrRuleExists", err)
	}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{}); err != nil {
		t.Errorf("duplicate rule without Excl = %v, want success", err)
	}
	var got []uint32
	for _, r := range s.Rules(ipv4.ProtocolNumber) {
		got = append(got, r.Priority)
	}
	want := []uint32{0, 32765, 32765, 32766, 32767}
	if len(got) != len(want) {
		t.Fatalf("priorities = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("priorities = %v, want %v", got, want)
		}
	}
}

func TestDeleteRuleMatchesGivenFieldsOnly(t *testing.T) {
	s := newFibStack(t)
	rule := stack.PolicyRule{Priority: 100, Action: stack.RuleActionToTable, Table: 100, Mark: 3, MarkMask: 0xffffffff, SuppressPrefixLen: -1}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	if _, err := s.DeleteRule(ipv4.ProtocolNumber, stack.RuleMatch{HasPrio: true, Priority: 101}); !errors.Is(err, stack.ErrRuleNotFound) {
		t.Errorf("delete of a missing priority = %v, want ErrRuleNotFound", err)
	}
	if _, err := s.DeleteRule(ipv4.ProtocolNumber, stack.RuleMatch{HasPrio: true, Priority: 100}); err != nil {
		t.Errorf("delete by priority = %v", err)
	}
	if _, err := s.DeleteRule(ipv4.ProtocolNumber, stack.RuleMatch{HasPrio: true, Priority: 32766}); err != nil {
		t.Errorf("delete of the default rule main = %v", err)
	}
	if _, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(8, 8, 8, 8)); err == nil {
		t.Errorf("lookup without the rule main succeeded, want network unreachable")
	}
}

func TestInsertRouteFollowsNetlinkFlags(t *testing.T) {
	s := newFibStack(t)
	dst := fibSubnet(t, 10, 50, 0, 0, 24)
	first := tcpip.Route{Destination: dst, NIC: fibEth0, RouteAttrs: tcpip.RouteAttrs{Metric: 10}}
	if res, err := s.InsertRoute(first, stack.RouteInsert{Create: true, Excl: true}); err != nil || !res.Added {
		t.Fatalf("add = (%+v, %v)", res, err)
	}
	other := first
	other.NIC = fibWG0
	if _, err := s.InsertRoute(other, stack.RouteInsert{Create: true, Excl: true}); !errors.Is(err, stack.ErrRouteExists) {
		t.Errorf("add with the same key = %v, want ErrRouteExists", err)
	}
	if _, err := s.InsertRoute(first, stack.RouteInsert{Create: true, Append: true}); !errors.Is(err, stack.ErrRouteExists) {
		t.Errorf("append of an identical route = %v, want ErrRouteExists", err)
	}
	if res, err := s.InsertRoute(other, stack.RouteInsert{Create: true, Replace: true}); err != nil || !res.Replaced {
		t.Errorf("replace = (%+v, %v)", res, err)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 50, 0, 3)); err != nil || got != fibWG0 {
		t.Errorf("lookup after the replace = (%d, %v), want NIC %d", got, err, fibWG0)
	}
	missing := tcpip.Route{Destination: fibSubnet(t, 10, 51, 0, 0, 24), NIC: fibEth0}
	if _, err := s.InsertRoute(missing, stack.RouteInsert{Replace: true}); !errors.Is(err, stack.ErrRouteNotFound) {
		t.Errorf("replace without a route and without Create = %v, want ErrRouteNotFound", err)
	}
	// A lower metric wins, and a prepended route wins over an equal metric.
	low := tcpip.Route{Destination: dst, NIC: fibEth0, RouteAttrs: tcpip.RouteAttrs{Metric: 5}}
	if _, err := s.InsertRoute(low, stack.RouteInsert{Create: true, Excl: true}); err != nil {
		t.Fatalf("add of the lower metric: %v", err)
	}
	if got, err := outgoingNIC(t, s, stack.RouteFlow{}, fibAddr(10, 50, 0, 3)); err != nil || got != fibEth0 {
		t.Errorf("lookup with two metrics = (%d, %v), want NIC %d", got, err, fibEth0)
	}
}

func TestDeleteRouteMatchesGivenFieldsOnly(t *testing.T) {
	s := newFibStack(t)
	dst := fibSubnet(t, 10, 60, 0, 0, 24)
	rt := tcpip.Route{Destination: dst, NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100, Metric: 7, Protocol: 80, Scope: 253, ScopeSet: true, Type: tcpip.RouteTypeUnicast}}
	if _, err := s.InsertRoute(rt, stack.RouteInsert{Create: true, Excl: true}); err != nil {
		t.Fatalf("add: %v", err)
	}
	for _, tc := range []struct {
		name string
		m    stack.RouteMatch
		want bool
	}{
		{"other table", stack.RouteMatch{Table: 101, Destination: dst}, false},
		{"other metric", stack.RouteMatch{Table: 100, Destination: dst, Metric: 8}, false},
		{"other protocol", stack.RouteMatch{Table: 100, Destination: dst, Protocol: 3}, false},
		{"scope universe", stack.RouteMatch{Table: 100, Destination: dst, HasScope: true, Scope: 0}, false},
		{"other NIC", stack.RouteMatch{Table: 100, Destination: dst, NIC: fibEth0}, false},
		{"other type", stack.RouteMatch{Table: 100, Destination: dst, Type: tcpip.RouteTypeBlackhole}, false},
		{"all fields", stack.RouteMatch{Table: 100, Destination: dst, Metric: 7, Protocol: 80, HasScope: true, Scope: 253, NIC: fibWG0, Type: tcpip.RouteTypeUnicast}, true},
	} {
		if _, ok := s.DeleteRoute(tc.m); ok != tc.want {
			t.Errorf("%s: DeleteRoute = %v, want %v", tc.name, ok, tc.want)
		}
	}
	if _, ok := s.DeleteRoute(stack.RouteMatch{Table: 100, Destination: dst}); ok {
		t.Errorf("route still exists after the delete that named every field")
	}
	if _, err := s.InsertRoute(rt, stack.RouteInsert{Create: true, Excl: true}); err != nil {
		t.Fatalf("add again: %v", err)
	}
	if _, ok := s.DeleteRoute(stack.RouteMatch{Table: 100, Destination: dst}); !ok {
		t.Errorf("delete that names only the table and the destination found no route")
	}
}

func TestLookupRouteAnswersLikeRouteGet(t *testing.T) {
	s := newFibStack(t)
	s.AddRoute(tcpip.Route{Destination: fibSubnet(t, 0, 0, 0, 0, 0), NIC: fibWG0, RouteAttrs: tcpip.RouteAttrs{Table: 100}})
	rule := stack.PolicyRule{Priority: 100, Action: stack.RuleActionToTable, Table: 100, Mark: 9, MarkMask: 0xffffffff, SuppressPrefixLen: -1}
	if err := s.AddRule(ipv4.ProtocolNumber, rule, stack.RuleInsert{Excl: true}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	rt, err := s.LookupRoute(stack.RouteFlow{Mark: 9}, 0, tcpip.Address{}, fibAddr(8, 8, 8, 8), ipv4.ProtocolNumber)
	if err != nil || rt.NIC != fibWG0 || rt.TableID() != 100 {
		t.Errorf("marked LookupRoute = (%+v, %v), want NIC %d in table 100", rt, err, fibWG0)
	}
	rt, err = s.LookupRoute(stack.RouteFlow{}, 0, tcpip.Address{}, fibAddr(8, 8, 8, 8), ipv4.ProtocolNumber)
	if err != nil || rt.NIC != fibEth0 || rt.TableID() != tcpip.RouteTableMain {
		t.Errorf("unmarked LookupRoute = (%+v, %v), want NIC %d in the table main", rt, err, fibEth0)
	}
}
