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
	"context"
	"fmt"
	"math/rand"
	"reflect"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/bits"
	"z.gfire.dev/gvx/pkg/ipset"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// Only the rules are used, never its clock or RNG.
var checkpointDefaultTables = DefaultLinuxTables(nil, rand.New(rand.NewSource(0)))

var checkpointTableNames = [stack.NumTables]string{
	stack.NATID: natTable, stack.MangleID: mangleTable,
	stack.FilterID: filterTable, stack.RawID: rawTable,
}

type checkpointValidator struct {
	owner  *stack.Stack
	ctx    context.Context
	sets   *ipset.Registry
	recent map[string]*recentTable
}

// ValidateIPTablesCheckpoint checks both address families before the tables
// become reachable by packets or by guest getsockopt. In particular, an
// unmodified snapshot must match the rules that the fast path skips.
// A nil tables value validates registries for a legacy import without rules.
func ValidateIPTablesCheckpoint(ctx context.Context, owner *stack.Stack, tables *stack.IPTables, modified bool) error {
	sets, err := ipset.CheckpointRegistry(owner)
	if err != nil {
		return err
	}
	if raw, ok := owner.ExtensionState(stackRecentRegistryKey); ok {
		registry, typed := raw.(*recentRegistry)
		module, _ := owner.ExtensionState(stackRecentModuleKey)
		if !typed || registry == nil || registry.stk != owner || registry.module == nil || registry.module != module ||
			registry.module.PktListTot() >= recentModuleStampLimit {
			return fmt.Errorf("invalid recent registry owner, type or parameters")
		}
		stack.AuthorizeCheckpointActivation(ctx, registry)
	}
	if tables == nil {
		return nil
	}
	// Wrapping only changes the representation of bare targets written by
	// the stack. Check typed nils first, since wrappers dereference them.
	for _, ipv6 := range [...]bool{false, true} {
		for id := range stack.NumTables {
			for i, rule := range tables.GetTable(id, ipv6).Rules {
				if !nonNilExtension(rule.Target) {
					return fmt.Errorf("iptables (ipv6=%t) table %d rule %d: invalid target %T", ipv6, id, i, rule.Target)
				}
			}
		}
	}
	WrapLinuxTableTargets(tables)
	validate := checkpointValidator{ctx: ctx, owner: owner, sets: sets}

	for _, ipv6 := range [...]bool{false, true} {
		for id, name := range checkpointTableNames {
			table, defaults := tables.GetTable(stack.TableID(id), ipv6), checkpointDefaultTables.GetTable(stack.TableID(id), ipv6)
			var err error
			if modified {
				err = validate.table(table, defaults.ValidHooks(), name, ipv6)
			} else if !reflect.DeepEqual(table, defaults) {
				err = fmt.Errorf("unmodified rules differ from the Linux defaults")
			}
			if err != nil {
				return fmt.Errorf("iptables (ipv6=%t) %s: %w", ipv6, name, err)
			}
		}
	}
	return nil
}

func nonNilExtension(v any) bool {
	p := reflect.ValueOf(v)
	return p.Kind() == reflect.Pointer && !p.IsNil()
}

func (v *checkpointValidator) table(table stack.Table, hooks uint32, name string, ipv6 bool) error {
	for hook, entry := range table.BuiltinChains {
		underflow := table.Underflows[hook]
		if hooks&(1<<hook) == 0 {
			if entry != stack.HookUnset || underflow != stack.HookUnset {
				return fmt.Errorf("unexpected builtin hook %d", hook)
			}
			continue
		}
		if entry < 0 || entry >= len(table.Rules) || underflow < entry || underflow >= len(table.Rules) {
			return fmt.Errorf("invalid hook %d entry or underflow", hook)
		}
		if isUserChainTarget(table.Rules[entry].Target) || isErrorTarget(table.Rules[entry].Target) {
			return fmt.Errorf("builtin hook %d starts at a chain marker", hook)
		}
		if !validUnderflow(table.Rules[underflow], ipv6) {
			return fmt.Errorf("hook %d underflow is not unconditional ACCEPT or DROP", hook)
		}
	}

	for i, rule := range table.Rules {
		if err := v.rule(table, i, rule, name, ipv6); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	if err := canonicalizeCheckpointJumps(table, ipv6); err != nil {
		return err
	}
	if err := checkLoopsAndChains(table, ipv6); err != nil {
		return fmt.Errorf("invalid chain graph: %s", err)
	}
	return validateCheckpointHooks(table, ipv6)
}

func (v *checkpointValidator) rule(table stack.Table, i int, rule stack.Rule, name string, ipv6 bool) error {
	filter := rule.Filter
	addrSize := header.IPv4AddressSize
	if ipv6 {
		addrSize = header.IPv6AddressSize
	}
	for _, addr := range [...]tcpip.Address{filter.Src, filter.SrcMask, filter.Dst, filter.DstMask} {
		if addr.Len() != addrSize {
			return fmt.Errorf("address or mask has wrong family")
		}
	}
	if filter.Protocol > 0xffff || (!ipv6 && filter.CheckProtocol != (filter.Protocol != 0)) {
		return fmt.Errorf("invalid transport protocol filter")
	}
	for _, iface := range [...]string{filter.InputInterface, filter.InputInterfaceMask, filter.OutputInterface, filter.OutputInterfaceMask} {
		if len(iface) > linux.IFNAMSIZ || strings.IndexByte(iface, 0) >= 0 {
			return fmt.Errorf("invalid interface filter")
		}
	}

	if err := v.target(rule.Target, filter, name); err != nil {
		return err
	}
	switch t := rule.Target.(type) {
	case *JumpTarget:
		if t.RuleNum <= 0 || t.RuleNum >= len(table.Rules) ||
			(t.RuleNum != i+1 && !isUserChainTarget(table.Rules[t.RuleNum-1].Target)) {
			return fmt.Errorf("invalid jump destination")
		}
	case *userChainTarget:
		if i+1 == len(table.Rules) || len(rule.Matchers) != 0 || t.Name == "" || t.Name == ErrorTargetName ||
			len(t.Name) > linux.XT_FUNCTION_MAXNAMELEN || strings.IndexByte(t.Name, 0) >= 0 {
			return fmt.Errorf("invalid user chain marker")
		}
	}

	for j, m := range rule.Matchers {
		if err := v.matcher(m, filter, ipv6); err != nil {
			return fmt.Errorf("matcher %d: %w", j, err)
		}
	}
	return nil
}

// Use the guest ABI's own marshallers: a writer may have supplied extra
// padding that is not present in a subsequent IPT_SO_GET_ENTRIES response.
func canonicalizeCheckpointJumps(table stack.Table, ipv6 bool) error {
	hasJump := false
	for _, rule := range table.Rules {
		if _, ok := rule.Target.(*JumpTarget); ok {
			hasJump = true
			break
		}
	}
	if !hasJump {
		return nil
	}
	entrySize := linux.SizeOfIPTEntry
	if ipv6 {
		entrySize = linux.SizeOfIP6TEntry
	}
	offsets := make([]uint32, len(table.Rules))
	var offset uint64
	for i, rule := range table.Rules {
		size := entrySize
		for _, m := range rule.Matchers {
			size += len(marshalMatcher(m))
			if size > 1<<16-1 {
				return fmt.Errorf("rule %d matches cannot be represented by the guest ABI", i)
			}
		}
		size += len(marshalTarget(rule.Target))
		if size > 1<<16-1 || offset+uint64(size) > 1<<31-1 {
			return fmt.Errorf("rule %d cannot be represented by the guest ABI", i)
		}
		offsets[i] = uint32(offset)
		offset += uint64(size)
	}
	for i, rule := range table.Rules {
		if jump, ok := rule.Target.(*JumpTarget); ok && jump.Offset != offsets[jump.RuleNum] {
			canonical := *jump
			canonical.Offset = offsets[jump.RuleNum]
			table.Rules[i].Target = &canonical
		}
	}
	return nil
}

// Build the set of hooks that can reach each rule, checking targets as we
// visit. The worklist avoids recursion proportional to the checkpoint size.
func validateCheckpointHooks(table stack.Table, ipv6 bool) error {
	masks := make([]uint32, len(table.Rules))
	var pending []int
	for hook, first := range table.BuiltinChains {
		if first == stack.HookUnset {
			continue
		}
		bit := uint32(1) << hook
		pending = append(pending, first)
		for len(pending) != 0 {
			i := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			for ; i < len(table.Rules) && masks[i]&bit == 0; i++ {
				masks[i] |= bit
				rule := table.Rules[i]
				if !targetSupportsHook(rule.Target, stack.Hook(hook)) {
					return fmt.Errorf("rule %d target %T cannot run in hook %d", i, rule.Target, hook)
				}
				if jump, ok := rule.Target.(*JumpTarget); ok && jump.RuleNum != i+1 {
					pending = append(pending, jump.RuleNum)
				}
				if isUnconditionalFinalRule(rule, ipv6) {
					break
				}
			}
		}
	}
	for i, rule := range table.Rules {
		for _, m := range rule.Matchers {
			if checker, ok := m.(hookChecker); ok {
				if err := checker.checkHooks(masks[i]); err != nil {
					return fmt.Errorf("rule %d matcher %T: %s", i, m, err)
				}
			}
		}
	}
	return nil
}

func (v *checkpointValidator) target(tgt stack.Target, filter stack.IPHeaderFilter, table string) error {
	owner := v.owner
	switch t := tgt.(type) {
	case *acceptTarget, *dropTarget, *returnTarget, *errorTarget, *userChainTarget,
		*JumpTarget, *ctTarget, *markTarget:
	case *connmarkTarget:
		if t.shiftDir > connmarkShiftRight || t.shiftBits >= 32 ||
			(t.rev == connmarkTargetRevision1 && (t.shiftDir != 0 || t.shiftBits != 0)) {
			return fmt.Errorf("invalid CONNMARK shift")
		}
	case *dnatTarget:
		if t.Addr.Len() != filter.Src.Len() || !portProtocol(filter.Protocol) || (t.revision == 0 && t.Port == 0) {
			return fmt.Errorf("invalid DNAT address or transport")
		}
	case *snatTarget:
		if t.Addr.Len() != filter.Src.Len() || !portProtocol(filter.Protocol) {
			return fmt.Errorf("invalid SNAT address or transport")
		}
	case *redirectTarget:
		if (t.addr.Len() != 0 && t.addr.Len() != filter.Src.Len()) || !portProtocol(filter.Protocol) {
			return fmt.Errorf("invalid REDIRECT address or transport")
		}
	case *masqueradeTarget:
		parsed, err := (&masqueradeTargetMaker{}).unmarshal(t.raw, filter)
		if err != nil || parsed.(*masqueradeTarget).Ports != t.Ports {
			return fmt.Errorf("invalid MASQUERADE port range")
		}
	case *rejectIPv4Target:
		handler, ok := owner.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler)
		if !ok || !nonNilExtension(handler) || t.Handler != handler ||
			(t.RejectWith != stack.RejectIPv4WithICMPPortUnreachable &&
				(t.RejectWith != stack.RejectIPv4WithTCPReset || filter.Protocol != header.TCPProtocolNumber)) {
			return fmt.Errorf("invalid IPv4 REJECT method or handler")
		}
	case *rejectIPv6Target:
		handler, ok := owner.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler)
		if !ok || !nonNilExtension(handler) || t.Handler != handler ||
			(t.RejectWith != stack.RejectIPv6WithICMPPortUnreachable &&
				(t.RejectWith != stack.RejectIPv6WithTCPReset || filter.Protocol != header.TCPProtocolNumber)) {
			return fmt.Errorf("invalid IPv6 REJECT method or handler")
		}
	case *logTarget:
		if t.stk != owner {
			return fmt.Errorf("LOG is bound to a different network stack")
		}
		if _, err := (&logTargetMaker{}).unmarshal(t.raw, filter); err != nil {
			return fmt.Errorf("invalid LOG options")
		}
	case *nflogTarget:
		if _, err := (&nflogTargetMaker{}).unmarshal(t.raw, filter); err != nil {
			return fmt.Errorf("invalid NFLOG options")
		}
	case *setTarget:
		if err := v.setTarget(t, filter); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported target %T", tgt)
	}
	id := tgt.(target).id()
	if id.networkProtocol != filter.NetworkProtocol() || targetMakers[id] == nil {
		return fmt.Errorf("target %T has invalid family or revision", tgt)
	}
	if required := targetTable(id.name); required != "" && required != table {
		return fmt.Errorf("target %q requires the %s table", id.name, required)
	}
	return nil
}

func portProtocol(proto tcpip.TransportProtocolNumber) bool {
	return proto == header.TCPProtocolNumber || proto == header.UDPProtocolNumber
}

func (v *checkpointValidator) matcher(m stack.Matcher, filter stack.IPHeaderFilter, ipv6 bool) error {
	if !nonNilExtension(m) {
		return fmt.Errorf("invalid matcher %T", m)
	}
	owner := v.owner
	switch m := m.(type) {
	case *commentMatcher, *MarkMatcher, *OwnerMatcher, *OwnerMatcherV1, *ConnmarkMatcher:
	case *TCPMatcher:
		if filter.Protocol != header.TCPProtocolNumber || m.inverseFlags > 2 {
			return fmt.Errorf("invalid TCP protocol or flags")
		}
	case *UDPMatcher:
		if filter.Protocol != header.UDPProtocolNumber {
			return fmt.Errorf("invalid UDP protocol")
		}
	case *multiportMatcher:
		if m.count == 0 || m.count > linux.XT_MULTI_PORTS || int(m.count) != len(m.ports) || m.flags > linux.XT_MULTIPORT_EITHER {
			return fmt.Errorf("invalid multiport match")
		}
	case *multiportMatcherV1:
		if m.count == 0 || m.count > linux.XT_MULTI_PORTS || int(m.count) != len(m.ports) || len(m.ports) != len(m.pflags) || m.flags > linux.XT_MULTIPORT_EITHER {
			return fmt.Errorf("invalid multiport match")
		}
	case *conntrackMatcher:
		raw, err := (conntrackMarshaler{rev: m.rev}).unmarshal(nil, nil, m.raw, filter)
		if err != nil {
			return err
		}
		parsed := raw.(*conntrackMatcher)
		if parsed.matchFlags != m.matchFlags || parsed.invertFlags != m.invertFlags || parsed.stateMask != m.stateMask || len(parsed.raw) != len(m.raw) {
			return fmt.Errorf("conntrack options do not match saved state")
		}
	case *AddrtypeMatcher:
		if m.stk != owner || (m.limitIfaceIn && m.limitIfaceOut) ||
			(m.rev == addrtypeRevision0 && (ipv6 || m.limitIfaceIn || m.limitIfaceOut)) ||
			(ipv6 && (m.source|m.dest)&addrtypeIPv6Unsupported != 0) {
			return fmt.Errorf("invalid addrtype flags, family or stack")
		}
	case *ICMPMatcher:
		proto := header.ICMPv4ProtocolNumber
		if ipv6 {
			proto = header.ICMPv6ProtocolNumber
		}
		if m.ipv6 != ipv6 || !filter.CheckProtocol || filter.Protocol != proto || m.invflags&^icmpInvert != 0 {
			return fmt.Errorf("invalid ICMP family, protocol or flags")
		}
	case *LimitMatcher:
		raw, err := (limitMarshaler{}).unmarshal(nil, nil, m.raw, filter)
		if err != nil {
			return err
		}
		parsed := raw.(*LimitMatcher)
		if m.stk != owner || m.cost != parsed.cost || m.creditCap != parsed.creditCap {
			return fmt.Errorf("invalid limit settings or stack")
		}
		stack.AuthorizeCheckpointActivation(v.ctx, m)
	case *RecentMatcher:
		if err := v.recentMatch(m); err != nil {
			return err
		}
	case *RPFilterMatcher:
		if m.stack != owner || m.flags&^rpfilterFlagMask != 0 {
			return fmt.Errorf("invalid rpfilter flags or stack")
		}
	case *SetMatcher:
		if err := v.setMatcher(m, filter); err != nil {
			return err
		}
	case *StatisticMatcher:
		if m.mode > statisticModeNth || m.flags&^statisticFlagInvert != 0 {
			return fmt.Errorf("invalid statistic flags or mode")
		}
	case *PhysdevMatcher:
		if m.bitmask == 0 || m.bitmask&^physdevOpMask != 0 {
			return fmt.Errorf("invalid physdev flags")
		}
		if m.bitmask&physdevOpIn != 0 {
			if err := checkPhysdevName("physdev-in", m.inDev); err != nil {
				return err
			}
		}
		if m.bitmask&physdevOpOut != 0 {
			if err := checkPhysdevName("physdev-out", m.outDev); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported matcher %T", m)
	}
	xm := m.(matcher)
	if matchMakers[matchKey{name: xm.name(), revision: xm.revision()}] == nil {
		return fmt.Errorf("matcher %T has invalid revision", m)
	}
	return nil
}

func (v *checkpointValidator) setMatcher(m *SetMatcher, filter stack.IPHeaderFilter) error {
	raw, err := (setMarshaler{rev: m.rev}).unmarshal(nil, nil, m.raw, filter)
	if err != nil {
		return err
	}
	parsed := raw.(*SetMatcher)
	if parsed.info != m.info || parsed.packetsOp != m.packetsOp || parsed.bytesOp != m.bytesOp ||
		parsed.packetsValue != m.packetsValue || parsed.bytesValue != m.bytesValue || parsed.cmdFlags != m.cmdFlags {
		return fmt.Errorf("set options do not match saved state")
	}
	return v.setRefs(&m.refs, []setInfo{m.info}, false)
}

func (v *checkpointValidator) setTarget(t *setTarget, filter stack.IPHeaderFilter) error {
	raw, err := (&setTargetMaker{rev: t.rev}).unmarshal(t.raw, filter)
	if err != nil {
		return fmt.Errorf("invalid SET options")
	}
	parsed := raw.(*setTarget)
	if parsed.add != t.add || parsed.del != t.del || parsed.mapSet != t.mapSet || parsed.flags != t.flags || parsed.timeout != t.timeout {
		return fmt.Errorf("SET options do not match saved state")
	}
	return v.setRefs(&t.refs, []setInfo{t.add, t.del, t.mapSet}, true)
}

func (v *checkpointValidator) setRefs(refs *setRefs, infos []setInfo, optional bool) error {
	ids := refs.ids
	if refs.released.Load() || (refs.reg != v.sets && (!optional || refs.reg != nil)) {
		return fmt.Errorf("invalid ipset registry binding")
	}
	for _, info := range infos {
		if info.dim > ipset.DimMax {
			return fmt.Errorf("invalid ipset dimension")
		}
		if optional && info.index == ipset.InvalidID {
			continue
		}
		if len(ids) == 0 || ids[0] != info.index || refs.reg == nil {
			return fmt.Errorf("missing ipset reference")
		}
		if _, ok := refs.reg.NameByIndex(info.index); !ok {
			return fmt.Errorf("unknown ipset index")
		}
		ids = ids[1:]
	}
	if len(ids) != 0 {
		return fmt.Errorf("unexpected ipset references")
	}
	stack.AuthorizeCheckpointActivation(v.ctx, refs)
	return nil
}

func (v *checkpointValidator) recentMatch(m *RecentMatcher) error {
	if m.rev != recentRevision0 && m.rev != recentRevision1 {
		return fmt.Errorf("invalid recent revision")
	}
	size := recentInfoSize(m.rev)
	if len(m.raw) != size {
		return fmt.Errorf("invalid recent options")
	}
	// The writer stores the unpadded ABI payload and its decoded fields.
	var buf [recentOffMask + 16 + 7]byte
	copy(buf[:], m.raw)
	raw, err := (recentMarshaler{rev: m.rev}).unmarshal(nil, nil, buf[:bits.AlignUp(size, 8)], stack.IPHeaderFilter{})
	if err != nil {
		return err
	}
	parsed := raw.(*RecentMatcher)
	if parsed.listName != m.listName || parsed.seconds != m.seconds || parsed.hitCount != m.hitCount ||
		parsed.checkSet != m.checkSet || parsed.invert != m.invert || parsed.side != m.side || parsed.mask != m.mask {
		return fmt.Errorf("recent options do not match saved state")
	}
	t := m.table
	owner := v.owner
	registry, _ := owner.ExtensionState(stackRecentRegistryKey)
	if t == nil || t.name != m.listName || t.owner == nil || t.owner != registry || t.owner.stk != owner || t.owner.module == nil ||
		m.release == nil || m.release.table != t || m.release.released.Load() {
		return fmt.Errorf("invalid recent list binding")
	}
	stack.AuthorizeCheckpointActivation(v.ctx, m)
	if prior := v.recent[t.name]; prior != nil {
		if prior != t {
			return fmt.Errorf("recent name has distinct saved lists")
		}
		return nil
	}
	if t.stamps <= 0 || t.stamps > recentMaxStamps || t.stamps&(t.stamps-1) != 0 ||
		t.entries == nil || len(t.entries) != len(t.savedOrder) || uint64(len(t.entries)) > uint64(t.owner.module.ListTot()) {
		return fmt.Errorf("invalid recent list dimensions")
	}
	seen := make(map[recentKey]struct{}, len(t.savedOrder))
	for _, entry := range t.savedOrder {
		if entry == nil || t.entries[entry.key] != entry || len(entry.stamps) != t.stamps ||
			entry.nstamps <= 0 || entry.nstamps > t.stamps || entry.index <= 0 || entry.index > entry.nstamps {
			return fmt.Errorf("invalid recent list entry")
		}
		if _, exists := seen[entry.key]; exists {
			return fmt.Errorf("duplicate recent list entry")
		}
		seen[entry.key] = struct{}{}
	}
	if v.recent == nil {
		v.recent = make(map[string]*recentTable)
	}
	v.recent[t.name] = t
	stack.AuthorizeCheckpointActivation(v.ctx, t)
	return nil
}
