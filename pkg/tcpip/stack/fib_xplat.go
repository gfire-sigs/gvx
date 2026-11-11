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

package stack

import (
	"errors"
	"iter"
	"slices"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
)

// This file holds the policy routing of a stack: the routing rules, the lookup
// that applies them, and the insert and delete operations of a netlink client.
// The routes of all tables share the list routeTable, sorted by prefix length
// (longest first) and then by metric. A rule selects the routes of one table.
// The rules and the lookup follow net/core/fib_rules.c and net/ipv4/fib_trie.c
// of Linux.

// RuleAction is the action of a routing rule. The values are the FR_ACT_*
// constants of Linux.
type RuleAction uint8

// PolicyRule actions.
const (
	// RuleActionToTable looks up the table of the rule.
	RuleActionToTable RuleAction = 1
	// RuleActionGoto continues the rule walk at the rule with the priority
	// PolicyRule.Goto.
	RuleActionGoto RuleAction = 2
	// RuleActionNop does nothing, so the next rule applies.
	RuleActionNop RuleAction = 3
	// RuleActionBlackhole ends the lookup like a blackhole route.
	RuleActionBlackhole RuleAction = 6
	// RuleActionUnreachable ends the lookup with "network unreachable".
	RuleActionUnreachable RuleAction = 7
	// RuleActionProhibit ends the lookup like a prohibit route.
	RuleActionProhibit RuleAction = 8
)

// PolicyRule is one routing rule of an IP family. The fields hold the values that
// "ip rule" prints. An unset match field matches every lookup.
//
// +stateify savable
type PolicyRule struct {
	// Priority orders the rules. The rule with the lowest value applies first.
	Priority uint32
	Action   RuleAction
	// Table is the table of RuleActionToTable.
	Table uint32
	// Goto is the priority that RuleActionGoto jumps to.
	Goto uint32
	// Invert makes the rule match when its conditions do not match.
	Invert bool

	// Src and Dst match the source and the destination address of a lookup
	// with their first SrcLen and DstLen bits. A length of 0 matches all.
	Src, Dst       tcpip.Address
	SrcLen, DstLen uint8

	// InputName and OutputName match the name of the input and the output
	// device. Local traffic enters through the loopback device.
	InputName, OutputName string

	// Mark and MarkMask match the firewall mark: a lookup matches when
	// (mark ^ Mark) & MarkMask is 0. A MarkMask of 0 matches every mark.
	Mark, MarkMask uint32

	// SuppressPrefixLen makes the rule ignore a route of the table whose
	// prefix length is not longer than the value. -1 turns the check off.
	SuppressPrefixLen int32

	// Protocol is the origin of the rule, as RTPROT_* of Linux.
	Protocol uint8
	// TOS is the type of service that a lookup must have. A lookup has 0.
	TOS uint8
	// Flags keeps the FIB_RULE_* flags that the stack does not interpret.
	Flags uint32

	src, dst tcpip.Subnet
}

var (
	// ErrRuleExists reports a rule that the table already holds.
	ErrRuleExists = errors.New("routing rule exists")
	// ErrRuleNotFound reports a delete request that matches no rule.
	ErrRuleNotFound = errors.New("routing rule not found")
	// ErrRuleInvalid reports a rule with inconsistent fields.
	ErrRuleInvalid = errors.New("invalid routing rule")
	// ErrRouteExists reports a route that the table already holds.
	ErrRouteExists = errors.New("route exists")
	// ErrRouteNotFound reports a replace request without a route to replace.
	ErrRouteNotFound = errors.New("route not found")
)

// fibRules holds the routing rules of a stack. A nil slice stands for the
// default rules, so a stack needs no setup code. Both slices are sorted by
// priority, and Stack.routeMu guards them.
//
// +stateify savable
type fibRules struct {
	rules4, rules6 []PolicyRule
}

// fibState holds the policies, the counters, and the snapshots of a stack that
// a reader uses without routeMu. Every field is atomic.
//
// +stateify savable
type fibState struct {
	// proxyARP is the policy for proxy ARP. See proxyarp_xplat.go.
	proxyARP atomic.Pointer[ProxyARPPolicy] `state:"nosave"`
	// rpFilter is the policy for the reverse path check of received IPv4
	// packets. See rpfilter_xplat.go.
	rpFilter atomic.Pointer[RPFilterPolicy] `state:"nosave"`

	// hostAddrGen and hostAddrs hold the snapshot of the IPv4 addresses of the
	// NICs. See hostaddr_xplat.go.
	hostAddrGen atomicbitops.Uint64
	hostAddrs   atomic.Pointer[hostAddrSnapshot] `state:"nosave"`

	// routeGen counts the changes of the route list, and routeTables holds the
	// count of routes in each table at one generation. See tablehas_xplat.go.
	routeGen    atomicbitops.Uint64
	routeTables atomic.Pointer[routeTableCounts] `state:"nosave"`

	// nicGen counts the NICs that join or leave, and nicOrder holds the NICs in
	// the order of the source address choice. See route_xplat.go.
	nicGen   atomicbitops.Uint64
	nicOrder atomic.Pointer[nicOrderSnapshot] `state:"nosave"`

	// protocolsStarted tracks whether protocol background workers are active.
	protocolsStarted atomic.Bool `state:"nosave"`
	// restoredNICs tracks preserved NICs already restored since load.
	restoredNICs map[tcpip.NICID]*nic `state:"nosave"`
	// childPause, childResume, and childRestore propagate lifecycle actions to
	// child network namespace stacks.
	childPause   func() `state:"nosave"`
	childResume  func() `state:"nosave"`
	childRestore func() `state:"nosave"`
}

var (
	defaultRules4 = []PolicyRule{
		{Priority: 0, Action: RuleActionToTable, Table: tcpip.RouteTableLocal, SuppressPrefixLen: -1},
		{Priority: 32766, Action: RuleActionToTable, Table: tcpip.RouteTableMain, SuppressPrefixLen: -1},
		{Priority: 32767, Action: RuleActionToTable, Table: tcpip.RouteTableDefault, SuppressPrefixLen: -1},
	}
	defaultRules6 = defaultRules4[:2]
)

func (f *fibRules) rulesOf(v6 bool) []PolicyRule {
	switch {
	case v6 && f.rules6 != nil:
		return f.rules6
	case v6:
		return defaultRules6
	case f.rules4 != nil:
		return f.rules4
	}
	return defaultRules4
}

func (f *fibRules) setRules(v6 bool, rules []PolicyRule) {
	if rules == nil {
		rules = []PolicyRule{}
	}
	if v6 {
		f.rules6 = rules
	} else {
		f.rules4 = rules
	}
}

func isV6Protocol(proto tcpip.NetworkProtocolNumber) bool {
	return proto == header.IPv6ProtocolNumber
}

// Rules returns the routing rules of the IP family, in lookup order.
func (s *Stack) Rules(proto tcpip.NetworkProtocolNumber) []PolicyRule {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	return slices.Clone(s.fibRules.rulesOf(isV6Protocol(proto)))
}

// RuleInsert tells AddRule how to treat an equal rule.
type RuleInsert struct {
	// Excl fails with ErrRuleExists when the table holds a rule that
	// rule_exists() of Linux calls the same: the action, the table, the
	// priority, the device names, the mark and its mask, the suppress length,
	// the protocol, the inversion, and the goto target must be equal. The
	// source, the destination, and the type of service count only when the new
	// rule sets them.
	Excl bool
}

// DefaultRulePriority returns the priority that a rule without a priority
// gets. Linux takes the priority of the second rule, minus 1.
func (s *Stack) DefaultRulePriority(proto tcpip.NetworkProtocolNumber) uint32 {
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()
	rules := s.fibRules.rulesOf(isV6Protocol(proto))
	if len(rules) > 1 && rules[1].Priority > 0 {
		return rules[1].Priority - 1
	}
	return 0
}

// AddRule inserts the rule after the rules with the same or a lower priority.
func (s *Stack) AddRule(proto tcpip.NetworkProtocolNumber, r PolicyRule, mode RuleInsert) error {
	v6 := isV6Protocol(proto)
	if err := r.prepare(v6); err != nil {
		return err
	}
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	rules := s.fibRules.rulesOf(v6)
	if mode.Excl && slices.ContainsFunc(rules, func(have PolicyRule) bool { return have.sameAs(&r) }) {
		return ErrRuleExists
	}
	at := len(rules)
	for i := range rules {
		if rules[i].Priority > r.Priority {
			at = i
			break
		}
	}
	s.fibRules.setRules(v6, slices.Insert(slices.Clone(rules), at, r))
	return nil
}

// sameAs reports whether the rule is the same as n in the sense of
// rule_exists() and fib4_rule_compare() of Linux.
func (r *PolicyRule) sameAs(n *PolicyRule) bool {
	switch {
	case r.Action != n.Action,
		r.Table != n.Table,
		r.Priority != n.Priority,
		r.InputName != n.InputName,
		r.OutputName != n.OutputName,
		r.Mark != n.Mark,
		r.MarkMask != n.MarkMask,
		r.SuppressPrefixLen != n.SuppressPrefixLen,
		r.Protocol != n.Protocol,
		r.Invert != n.Invert,
		n.Action == RuleActionGoto && r.Goto != n.Goto,
		n.SrcLen != 0 && (r.SrcLen != n.SrcLen || !r.Src.Equal(n.Src)),
		n.DstLen != 0 && (r.DstLen != n.DstLen || !r.Dst.Equal(n.Dst)),
		n.TOS != 0 && r.TOS != n.TOS:
		return false
	}
	return true
}

// RuleMatch selects the rule that DeleteRule removes. A field that the client
// left out matches every rule, as in rule_find() of Linux.
type RuleMatch struct {
	Action    RuleAction
	Table     uint32
	HasTable  bool
	Priority  uint32
	HasPrio   bool
	InputName *string
	OutName   *string
	Mark      *uint32
	MarkMask  *uint32
	Goto      *uint32
	Protocol  *uint8
	Suppress  *int32
	Src, Dst  *tcpip.Address
	SrcLen    uint8
	DstLen    uint8
	TOS       uint8
}

// DeleteRule removes the first rule that matches and returns it.
func (s *Stack) DeleteRule(proto tcpip.NetworkProtocolNumber, m RuleMatch) (PolicyRule, error) {
	v6 := isV6Protocol(proto)
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	rules := s.fibRules.rulesOf(v6)
	i := slices.IndexFunc(rules, func(r PolicyRule) bool { return m.matches(&r) })
	if i < 0 {
		return PolicyRule{}, ErrRuleNotFound
	}
	removed := rules[i]
	s.fibRules.setRules(v6, slices.Delete(slices.Clone(rules), i, i+1))
	return removed, nil
}

func (m *RuleMatch) matches(r *PolicyRule) bool {
	switch {
	case m.Action != 0 && m.Action != r.Action,
		m.HasTable && m.Table != r.Table,
		m.HasPrio && m.Priority != r.Priority,
		m.InputName != nil && *m.InputName != r.InputName,
		m.OutName != nil && *m.OutName != r.OutputName,
		m.Mark != nil && *m.Mark != r.Mark,
		m.MarkMask != nil && *m.MarkMask != r.MarkMask,
		m.Goto != nil && *m.Goto != r.Goto,
		m.Protocol != nil && *m.Protocol != r.Protocol,
		m.Suppress != nil && *m.Suppress != r.SuppressPrefixLen,
		m.SrcLen != 0 && m.SrcLen != r.SrcLen,
		m.DstLen != 0 && m.DstLen != r.DstLen,
		m.SrcLen != 0 && m.Src != nil && !m.Src.Equal(r.Src),
		m.DstLen != 0 && m.Dst != nil && !m.Dst.Equal(r.Dst),
		m.TOS != 0 && m.TOS != r.TOS:
		return false
	}
	return true
}

// prepare validates the rule and fills the fields that the lookup uses.
func (r *PolicyRule) prepare(v6 bool) error {
	bits := uint8(header.IPv4AddressSizeBits)
	size := header.IPv4AddressSize
	if v6 {
		bits, size = header.IPv6AddressSizeBits, header.IPv6AddressSize
	}
	if r.SrcLen > bits || r.DstLen > bits {
		return ErrRuleInvalid
	}
	switch r.Action {
	case RuleActionToTable:
		if r.Table == 0 {
			return ErrRuleInvalid
		}
	case RuleActionGoto:
		if r.Goto <= r.Priority {
			return ErrRuleInvalid
		}
	case RuleActionNop, RuleActionBlackhole, RuleActionUnreachable, RuleActionProhibit:
	default:
		return ErrRuleInvalid
	}
	zero := make([]byte, size)
	var err error
	if r.src, err = ruleSubnet(r.Src, r.SrcLen, zero); err != nil {
		return err
	}
	if r.dst, err = ruleSubnet(r.Dst, r.DstLen, zero); err != nil {
		return err
	}
	return nil
}

func ruleSubnet(addr tcpip.Address, length uint8, zero []byte) (tcpip.Subnet, error) {
	if length == 0 {
		return tcpip.Subnet{}, nil
	}
	if addr.Len() != len(zero) {
		return tcpip.Subnet{}, ErrRuleInvalid
	}
	return tcpip.AddressWithPrefix{Address: addr, PrefixLen: int(length)}.Subnet(), nil
}

// RouteFlow carries the inputs of a lookup that the routing rules can match.
type RouteFlow struct {
	// Mark is the firewall mark of the packet or the socket.
	Mark uint32
	// InputNIC is the NIC where a forwarded packet arrived. It is 0 for a
	// packet that a local socket sends.
	InputNIC tcpip.NICID
	// Source is the source address of a forwarded packet. A rule that matches
	// the source address uses it when the lookup has no local address.
	Source tcpip.Address
}

// routeLookup is the state of one lookup through the rules.
type routeLookup struct {
	flow     RouteFlow
	outputID tcpip.NICID
	src, dst tcpip.Address
	v6       bool
	// err is set when a reject route or rule ends the lookup.
	err tcpip.Error
}

func newRouteLookup(flow RouteFlow, outputID tcpip.NICID, src, dst tcpip.Address, proto tcpip.NetworkProtocolNumber) routeLookup {
	if src.BitLen() == 0 {
		src = flow.Source
	}
	return routeLookup{flow: flow, outputID: outputID, src: src, dst: dst, v6: isV6Protocol(proto)}
}

// ruleMatches reports whether the rule applies to the lookup.
//
// +checklocksread:s.mu
func (s *Stack) ruleMatches(r *PolicyRule, l *routeLookup) bool {
	return s.ruleConditionsHold(r, l) != r.Invert
}

// +checklocksread:s.mu
func (s *Stack) ruleConditionsHold(r *PolicyRule, l *routeLookup) bool {
	if r.InputName != "" {
		id := l.flow.InputNIC
		if id == 0 && s.loopbackNIC != nil {
			id = s.loopbackNIC.id
		}
		if n, ok := s.nics[id]; !ok || n.name != r.InputName {
			return false
		}
	}
	if r.OutputName != "" {
		if n, ok := s.nics[l.outputID]; !ok || n.name != r.OutputName {
			return false
		}
	}
	if r.MarkMask != 0 && (l.flow.Mark^r.Mark)&r.MarkMask != 0 {
		return false
	}
	if r.TOS != 0 {
		return false
	}
	if r.SrcLen != 0 && (l.src.BitLen() == 0 || !r.src.Contains(l.src)) {
		return false
	}
	if r.DstLen != 0 && (l.dst.BitLen() == 0 || !r.dst.Contains(l.dst)) {
		return false
	}
	return true
}

// rejectError returns the error that a lookup returns for a route type.
func rejectError(t tcpip.RouteType) tcpip.Error {
	switch t {
	case tcpip.RouteTypeBlackhole:
		return &tcpip.ErrRouteBlackhole{}
	case tcpip.RouteTypeUnreachable:
		return &tcpip.ErrHostUnreachable{}
	case tcpip.RouteTypeProhibit:
		return &tcpip.ErrRouteProhibited{}
	}
	return &tcpip.ErrNetworkUnreachable{}
}

// fibRoutes yields the routes that a lookup may use, in the order of Linux: the
// rules in priority order and, for each rule that applies, the routes of its
// table that contain the destination, longest prefix first. A route that is
// not a unicast route ends the walk of its table. A reject route also stops
// the lookup and leaves its error in l.err.
//
// The caller holds s.mu for reading and s.routeMu for reading.
//
// +checklocksread:s.mu
// +checklocksread:s.routeMu
func (s *Stack) fibRoutes(l *routeLookup) iter.Seq[*tcpip.Route] {
	return func(yield func(*tcpip.Route) bool) {
		rules := s.fibRules.rulesOf(l.v6) // +checklocksforce: the caller of fibRoutes holds s.routeMu
		for i := 0; i < len(rules); i++ {
			r := &rules[i]
			if !s.ruleMatches(r, l) { // +checklocksforce: the caller of fibRoutes holds s.mu
				continue
			}
			switch r.Action {
			case RuleActionToTable:
				// A rule for a table without routes changes nothing. The
				// table local, which the default rule 0 names, has none, and
				// the scan of the list for it would cost as much as the
				// whole list.
				if !s.tableHasRoutes(r.Table) { // +checklocksforce: the caller of fibRoutes holds s.routeMu
					continue
				}
				if !s.walkTable(r.Table, r.SuppressPrefixLen, l, yield) { // +checklocksforce: the caller of fibRoutes holds s.routeMu
					return
				}
			case RuleActionGoto:
				j := slices.IndexFunc(rules[i+1:], func(t PolicyRule) bool { return t.Priority == r.Goto })
				if j >= 0 {
					i += j // The loop adds 1 to land on the target.
				}
			case RuleActionBlackhole:
				l.err = rejectError(tcpip.RouteTypeBlackhole)
				return
			case RuleActionUnreachable:
				l.err = &tcpip.ErrNetworkUnreachable{}
				return
			case RuleActionProhibit:
				l.err = rejectError(tcpip.RouteTypeProhibit)
				return
			}
		}
	}
}

// walkTable yields the matching routes of one table. It returns false when the
// lookup is over.
//
// +checklocksread:s.routeMu
func (s *Stack) walkTable(table uint32, suppress int32, l *routeLookup, yield func(*tcpip.Route) bool) bool {
	for route := s.routeTable.Front(); route != nil; route = route.Next() {
		if route.TableID() != table || route.TOS != 0 {
			continue
		}
		if l.dst.BitLen() != 0 && !route.Destination.Contains(l.dst) {
			continue
		}
		switch t := route.RouteType(); {
		case t == tcpip.RouteTypeThrow:
			if l.dst.BitLen() == 0 {
				continue
			}
			return true
		case t.IsReject():
			if l.dst.BitLen() == 0 {
				continue
			}
			l.err = rejectError(t)
			return false
		}
		if suppress >= 0 && int32(route.Destination.Prefix()) <= suppress {
			continue
		}
		if !yield(route) {
			return false
		}
	}
	return true
}

// FindRoute creates a route to the destination address. FindRouteFlow
// describes it.
func (s *Stack) FindRoute(id tcpip.NICID, localAddr, remoteAddr tcpip.Address, netProto tcpip.NetworkProtocolNumber, multicastLoop bool) (*Route, tcpip.Error) {
	return s.FindRouteFlow(RouteFlow{}, id, localAddr, remoteAddr, netProto, multicastLoop)
}

// RouteInsert describes how InsertRoute treats an existing route.
type RouteInsert struct {
	// Create allows the call to add a route.
	Create bool
	// Excl fails when a route with the same key exists.
	Excl bool
	// Replace overwrites the first route with the same key.
	Replace bool
	// Append puts a new route after the routes with the same key. Without it
	// the new route goes before them.
	Append bool
}

// RouteInsertResult tells what InsertRoute did.
type RouteInsertResult struct {
	// Added is set when the route is new, Replaced when it overwrote another.
	Added, Replaced bool
	// SameDestination is set when another route to the same destination
	// existed before the call.
	SameDestination bool
}

// sameRouteKey reports whether two routes have the same table, destination,
// type of service, and metric. Linux keeps one route for each key unless the
// client appends.
func sameRouteKey(a, b *tcpip.Route) bool {
	return a.TableID() == b.TableID() && a.Destination.Equal(b.Destination) && a.TOS == b.TOS && a.Metric == b.Metric
}

// InsertRoute adds the route like fib_table_insert() of Linux. It returns
// ErrRouteExists for a route that mode.Excl rejects, and ErrRouteNotFound when
// the route is new and mode.Create is not set.
func (s *Stack) InsertRoute(route tcpip.Route, mode RouteInsert) (RouteInsertResult, error) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()

	var res RouteInsertResult
	var first *tcpip.Route
	for r := s.routeTable.Front(); r != nil; r = r.Next() {
		if r.TableID() != route.TableID() || !r.Destination.Equal(route.Destination) {
			continue
		}
		res.SameDestination = true
		if first == nil && sameRouteKey(r, &route) {
			first = r
		}
	}
	if first != nil {
		if mode.Excl {
			return res, ErrRouteExists
		}
		if mode.Replace {
			route.RouteEntry = first.RouteEntry
			*first = route
			res.Replaced = true
			return res, nil
		}
		if sameRouteNextHop(first, &route) {
			return res, ErrRouteExists
		}
	}
	if !mode.Create {
		return res, ErrRouteNotFound
	}
	s.insertRouteLocked(&route, !mode.Append)
	res.Added = true
	return res, nil
}

// sameRouteNextHop reports whether two routes with the same key also send
// packets the same way, so that adding the second one changes nothing.
func sameRouteNextHop(a, b *tcpip.Route) bool {
	return a.RouteType() == b.RouteType() && a.NIC == b.NIC && a.Gateway == b.Gateway &&
		a.SourceHint == b.SourceHint && a.Protocol == b.Protocol && a.EffectiveScope(a.Gateway.BitLen() != 0) == b.EffectiveScope(b.Gateway.BitLen() != 0) &&
		a.MTU == b.MTU && a.Flags == b.Flags
}

// insertRouteLocked adds the route in the order of prefix length and metric.
// A route that goes first lands before the routes with the same key.
//
// +checklocks:s.routeMu
func (s *Stack) insertRouteLocked(route *tcpip.Route, first bool) {
	s.fib.routesChanged()
	prefix := route.Destination.Prefix()
	for n := s.routeTable.Front(); n != nil; n = n.Next() {
		np := n.Destination.Prefix()
		if np < prefix || (np == prefix && (n.Metric > route.Metric || (first && n.Metric == route.Metric))) {
			s.routeTable.InsertBefore(n, route)
			return
		}
	}
	s.routeTable.PushBack(route)
}

// RouteMatch selects the route that DeleteRoute removes. A field that the
// client left out matches every route, as in fib_table_delete() of Linux.
type RouteMatch struct {
	Table       uint32
	Destination tcpip.Subnet
	TOS         uint8
	Metric      uint32
	Type        tcpip.RouteType
	// Scope is matched unless HasScope is false.
	Scope    uint8
	HasScope bool
	Protocol uint8
	// Gateway and NIC are matched when set.
	Gateway tcpip.Address
	NIC     tcpip.NICID
	// PrefSrc is matched when set.
	PrefSrc tcpip.Address
}

// DeleteRoute removes the first route that matches and returns it.
func (s *Stack) DeleteRoute(m RouteMatch) (tcpip.Route, bool) {
	s.routeMu.Lock()
	defer s.routeMu.Unlock()
	s.fib.routesChanged()
	for r := s.routeTable.Front(); r != nil; r = r.Next() {
		if !m.matches(r) {
			continue
		}
		removed := *r
		s.routeTable.Remove(r)
		return removed, true
	}
	return tcpip.Route{}, false
}

func (m *RouteMatch) matches(r *tcpip.Route) bool {
	switch {
	case r.TableID() != m.Table,
		!r.Destination.Equal(m.Destination),
		r.TOS != m.TOS,
		m.Metric != 0 && r.Metric != m.Metric,
		m.Type != 0 && r.RouteType() != m.Type,
		m.HasScope && r.EffectiveScope(r.Gateway.BitLen() != 0) != m.Scope,
		m.Protocol != 0 && r.Protocol != m.Protocol,
		m.Gateway.BitLen() != 0 && !m.Gateway.Equal(r.Gateway),
		m.NIC != 0 && m.NIC != r.NIC,
		m.PrefSrc.BitLen() != 0 && !m.PrefSrc.Equal(r.SourceHint):
		return false
	}
	return true
}

// LookupRoute returns the route that the rules and the tables select for the
// flow, without a NIC or an address check. It returns the error of a reject
// route or rule when one ends the lookup, and a network unreachable error when
// no route matches. outputNIC and src stay unset when the caller has no values.
func (s *Stack) LookupRoute(flow RouteFlow, outputNIC tcpip.NICID, src, dst tcpip.Address, proto tcpip.NetworkProtocolNumber) (tcpip.Route, tcpip.Error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()

	l := newRouteLookup(flow, outputNIC, src, dst, proto)
	for route := range s.fibRoutes(&l) {
		if outputNIC != 0 && route.NIC != outputNIC {
			continue
		}
		if nic, ok := s.nics[route.NIC]; !ok || !nic.Enabled() { // +checklocksforce: the loop body runs with s.mu held
			continue
		}
		return *route, nil
	}
	if l.err != nil {
		return tcpip.Route{}, l.err
	}
	return tcpip.Route{}, &tcpip.ErrNetworkUnreachable{}
}

// ReversePathMode selects how ReversePathValid compares the interface.
type ReversePathMode int

// Reverse path modes.
const (
	// ReversePathStrict needs the best route to the source address to leave
	// through the interface that received the packet.
	ReversePathStrict ReversePathMode = iota
	// ReversePathLoose needs any route to the source address.
	ReversePathLoose
)

// ReversePathValid reports whether a packet that arrived on inNIC with the
// source address src and the destination address dst has a valid source, as
// the xt_rpfilter match and fib_validate_source() of Linux decide it. It looks
// up the route to src with the rules and the mark. It fails when no route
// matches, when a reject route or rule matches, or, in the strict mode, when
// the route leaves through another interface. A source address of the host is
// valid only when acceptLocal is set. A link-local IPv6 source is valid only
// for its own interface.
func (s *Stack) ReversePathValid(inNIC tcpip.NICID, src, dst tcpip.Address, mark uint32, proto tcpip.NetworkProtocolNumber, mode ReversePathMode, acceptLocal bool) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.hostAddress(src, proto) {
		return acceptLocal
	}
	s.routeMu.RLock()
	defer s.routeMu.RUnlock()

	// The flow is the reply: it goes to the source and leaves from the
	// destination, as it enters through the loopback device.
	var from tcpip.Address
	if !header.IsV4MulticastAddress(dst) && !header.IsV6MulticastAddress(dst) && dst != header.IPv4Broadcast {
		from = dst
	}
	l := newRouteLookup(RouteFlow{Mark: mark}, 0, from, src, proto)
	linkLocal := header.IsV6LinkLocalUnicastAddress(src)
	for route := range s.fibRoutes(&l) {
		if _, ok := s.nics[route.NIC]; !ok { // +checklocksforce: the loop body runs with s.mu held
			continue
		}
		if linkLocal && route.NIC != inNIC {
			continue
		}
		return mode == ReversePathLoose || route.NIC == inNIC
	}
	return false
}
