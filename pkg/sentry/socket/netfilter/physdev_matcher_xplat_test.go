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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// physdevInfo is the user space view of struct xt_physdev_info.
type physdevInfo struct {
	in, out         string
	invert, bitmask uint8
	// rawIn replaces the in name when set, so that a test can fill all 16 bytes.
	rawIn []byte
}

// maskFor returns the mask that iptables builds for an interface name. A name
// with a trailing "+" compares the characters before the plus sign. Any other
// name compares the characters and the NUL byte.
func maskFor(name string) []byte {
	mask := make([]byte, physdevNameLen)
	if n := len(name); n > 0 && name[n-1] == '+' {
		for i := range n - 1 {
			mask[i] = 0xff
		}
		return mask
	}
	for i := 0; i <= len(name) && i < physdevNameLen; i++ {
		mask[i] = 0xff
	}
	return mask
}

func (i physdevInfo) bytes() []byte {
	data := make([]byte, physdevInfoSize)
	if i.rawIn != nil {
		copy(data[physdevOffInDev:physdevOffInMask], i.rawIn)
	} else {
		copy(data[physdevOffInDev:physdevOffInMask], i.in)
	}
	copy(data[physdevOffInMask:], maskFor(i.in))
	copy(data[physdevOffOutDev:physdevOffOutMask], i.out)
	copy(data[physdevOffOutMask:], maskFor(i.out))
	data[physdevOffInvert] = i.invert
	data[physdevOffBitmask] = i.bitmask
	return data
}

func physdevEntry(info physdevInfo) []byte {
	return marshalEntryMatch(matcherNamePhysdev, info.bytes())
}

func parsePhysdev(t *testing.T, filter stack.IPHeaderFilter, info physdevInfo) *PhysdevMatcher {
	t.Helper()
	m, ok := parseOneMatcher(t, filter, physdevEntry(info)).(*PhysdevMatcher)
	if !ok {
		t.Fatalf("parseMatchers did not return a *PhysdevMatcher")
	}
	return m
}

// bridgeMark is the bridge information of a packet.
type bridgeMark struct {
	bridged  bool
	from, to string
}

func markedPacket(t *testing.T, mark bridgeMark) *stack.PacketBuffer {
	t.Helper()
	pkt := buildICMPPacket(t, icmpPacketSpec{protocol: uint8(header.ICMPv4ProtocolNumber), typ: 8})
	pkt.Bridged, pkt.BridgedFrom, pkt.BridgedTo = mark.bridged, mark.from, mark.to
	return pkt
}

func TestPhysdevMatch(t *testing.T) {
	const (
		in, out, bridged, isIn, isOut = physdevOpIn, physdevOpOut, physdevOpBridged, physdevOpIsIn, physdevOpIsOut
	)
	routed := bridgeMark{}
	prerouting := bridgeMark{bridged: true, from: "veth1"}
	forward := bridgeMark{bridged: true, from: "veth1", to: "veth2"}

	tests := []struct {
		name string
		info physdevInfo
		mark bridgeMark
		want bool
	}{
		// A packet that no bridge switches matches only when every used option is inverted.
		{"routed is-bridged", physdevInfo{bitmask: bridged}, routed, false},
		{"routed not is-bridged", physdevInfo{bitmask: bridged, invert: bridged}, routed, true},
		{"routed is-in", physdevInfo{bitmask: isIn}, routed, false},
		{"routed is-out", physdevInfo{bitmask: isOut}, routed, false},
		{"routed physdev-in", physdevInfo{in: "veth1", bitmask: in}, routed, false},
		{"routed not physdev-in", physdevInfo{in: "veth1", bitmask: in, invert: in}, routed, true},
		{"routed physdev-out", physdevInfo{out: "veth2", bitmask: out}, routed, false},
		{"routed not physdev-out", physdevInfo{out: "veth2", bitmask: out, invert: out}, routed, true},
		{"routed one option inverted and one not", physdevInfo{in: "veth1", bitmask: in | bridged, invert: in}, routed, false},
		{"routed all options inverted", physdevInfo{in: "veth1", out: "veth2", bitmask: in | out | bridged | isIn | isOut, invert: in | out | bridged | isIn | isOut}, routed, true},

		// A frame in the FORWARD or POSTROUTING hook knows both ports.
		{"forward is-bridged", physdevInfo{bitmask: bridged}, forward, true},
		{"forward not is-bridged", physdevInfo{bitmask: bridged, invert: bridged}, forward, false},
		{"forward is-in", physdevInfo{bitmask: isIn}, forward, true},
		{"forward not is-in", physdevInfo{bitmask: isIn, invert: isIn}, forward, false},
		{"forward is-out", physdevInfo{bitmask: isOut}, forward, true},
		{"forward not is-out", physdevInfo{bitmask: isOut, invert: isOut}, forward, false},
		{"forward physdev-in hit", physdevInfo{in: "veth1", bitmask: in}, forward, true},
		{"forward physdev-in miss", physdevInfo{in: "veth2", bitmask: in}, forward, false},
		{"forward not physdev-in miss", physdevInfo{in: "veth2", bitmask: in, invert: in}, forward, true},
		{"forward not physdev-in hit", physdevInfo{in: "veth1", bitmask: in, invert: in}, forward, false},
		{"forward physdev-out hit", physdevInfo{out: "veth2", bitmask: out}, forward, true},
		{"forward physdev-out miss", physdevInfo{out: "veth1", bitmask: out}, forward, false},
		{"forward not physdev-out miss", physdevInfo{out: "veth1", bitmask: out, invert: out}, forward, true},
		{"forward physdev-out prefix of the name is no match", physdevInfo{out: "veth", bitmask: out}, forward, false},
		{"forward physdev-in with a plus sign", physdevInfo{in: "veth+", bitmask: in}, forward, true},
		{"forward physdev-in with a plus sign and another prefix", physdevInfo{in: "tap+", bitmask: in}, forward, false},
		{"forward physdev-out with a plus sign", physdevInfo{out: "veth+", bitmask: out}, forward, true},
		{"forward in and out hit", physdevInfo{in: "veth1", out: "veth2", bitmask: in | out | bridged}, forward, true},
		{"forward in hit and out miss", physdevInfo{in: "veth1", out: "veth3", bitmask: in | out | bridged}, forward, false},

		// The PREROUTING hook knows the port of arrival only.
		{"prerouting is-bridged", physdevInfo{bitmask: bridged}, prerouting, false},
		{"prerouting not is-bridged", physdevInfo{bitmask: bridged, invert: bridged}, prerouting, true},
		{"prerouting is-in", physdevInfo{bitmask: isIn}, prerouting, true},
		{"prerouting is-out", physdevInfo{bitmask: isOut}, prerouting, false},
		{"prerouting not is-out", physdevInfo{bitmask: isOut, invert: isOut}, prerouting, true},
		{"prerouting physdev-in hit", physdevInfo{in: "veth1", bitmask: in}, prerouting, true},
		{"prerouting physdev-out fails even when inverted", physdevInfo{out: "veth2", bitmask: out, invert: out}, prerouting, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m := parsePhysdev(t, stack.EmptyFilter4(), tc.info)
			pkt := markedPacket(t, tc.mark)
			got, hotdrop := m.Match(stack.Forward, pkt, "br0", "br0")
			if hotdrop {
				t.Errorf("Match returned hotdrop")
			}
			if got != tc.want {
				t.Errorf("Match = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestPhysdevMarshalRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		info physdevInfo
	}{
		{"is-bridged", physdevInfo{bitmask: physdevOpBridged}},
		{"not is-bridged", physdevInfo{bitmask: physdevOpBridged, invert: physdevOpBridged}},
		{"in and out", physdevInfo{in: "veth1", out: "veth+", bitmask: physdevOpIn | physdevOpOut, invert: physdevOpOut}},
		{"is-in and is-out", physdevInfo{bitmask: physdevOpIsIn | physdevOpIsOut}},
		{"longest name", physdevInfo{in: "abcdefghijklmno", bitmask: physdevOpIn}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			entry := physdevEntry(tc.info)
			m := parsePhysdev(t, stack.EmptyFilter4(), tc.info)
			got := marshalMatcher(m)
			if !bytes.Equal(got, entry) {
				t.Errorf("marshalMatcher = %x, want %x", got, entry)
			}
			var hdr linux.XTEntryMatch
			hdr.UnmarshalBytes(got)
			if hdr.Name.String() != matcherNamePhysdev || int(hdr.MatchSize) != len(got) || len(got) != 72+linux.SizeOfXTEntryMatch {
				t.Errorf("header = name %q size %d for %d bytes", hdr.Name.String(), hdr.MatchSize, len(got))
			}
		})
	}
}

func TestPhysdevUnmarshalRejects(t *testing.T) {
	tests := []struct {
		name  string
		entry []byte
	}{
		{"no option", physdevEntry(physdevInfo{})},
		{"unknown option bit", physdevEntry(physdevInfo{bitmask: 0x20})},
		{"physdev-in without a name", physdevEntry(physdevInfo{bitmask: physdevOpIn})},
		{"physdev-out without a name", physdevEntry(physdevInfo{bitmask: physdevOpOut})},
		{"physdev-in name without a NUL byte", physdevEntry(physdevInfo{rawIn: bytes.Repeat([]byte{'a'}, physdevNameLen), bitmask: physdevOpIn})},
		{"too short", marshalEntryMatch(matcherNamePhysdev, make([]byte, 40))},
		{"too long", marshalEntryMatch(matcherNamePhysdev, make([]byte, 80))},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseMatchers(nil, stack.EmptyFilter4(), tc.entry); err == nil {
				t.Errorf("parseMatchers accepted the match")
			}
		})
	}
}

func TestPhysdevMatchRevisionIsReported(t *testing.T) {
	if rev, ok := matchMakerRevision(matcherNamePhysdev, 0); !ok || rev != 0 {
		t.Errorf("matchMakerRevision(physdev) = (%d, %v), want (0, true)", rev, ok)
	}
}

// hookRule is a rule of the hook tests: it holds the matcher of info, or no
// matcher for a policy rule.
func hookRule(t *testing.T, info *physdevInfo, tgt stack.Target) stack.Rule {
	t.Helper()
	rule := stack.Rule{Filter: stack.EmptyFilter4(), Target: tgt}
	if info != nil {
		rule.Matchers = []stack.Matcher{parsePhysdev(t, rule.Filter, *info)}
	}
	return rule
}

func TestPhysdevHookCheck(t *testing.T) {
	accept := &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: header.IPv4ProtocolNumber}}
	isOut := physdevInfo{bitmask: physdevOpIsOut}
	out := physdevInfo{out: "veth1", bitmask: physdevOpOut}
	in := physdevInfo{in: "veth1", bitmask: physdevOpIn}
	isOutBridged := physdevInfo{bitmask: physdevOpIsOut | physdevOpBridged}
	isOutNotBridged := physdevInfo{bitmask: physdevOpIsOut | physdevOpBridged, invert: physdevOpBridged}
	isIn := physdevInfo{bitmask: physdevOpIsIn}

	// chain builds a table with one rule of info and a policy in the chain of each hook of hooks.
	chain := func(t *testing.T, info physdevInfo, hooks ...stack.Hook) stack.Table {
		table := stack.EmptyMangleTable()
		for h := range table.BuiltinChains {
			table.BuiltinChains[h], table.Underflows[h] = stack.HookUnset, stack.HookUnset
		}
		for _, h := range hooks {
			table.BuiltinChains[h] = len(table.Rules)
			table.Rules = append(table.Rules, hookRule(t, &info, accept))
			table.Underflows[h] = len(table.Rules)
			table.Rules = append(table.Rules, hookRule(t, nil, accept))
		}
		return table
	}
	// userChain builds a table whose user chain holds the rule of info. The
	// chains of hooks jump to it.
	userChain := func(t *testing.T, info physdevInfo, hooks ...stack.Hook) stack.Table {
		const chainStart = 6
		table := stack.EmptyMangleTable()
		for h := range table.BuiltinChains {
			table.BuiltinChains[h], table.Underflows[h] = stack.HookUnset, stack.HookUnset
		}
		// The user chain is last, so the builtin chains of the hooks come first.
		for _, h := range hooks {
			table.BuiltinChains[h] = len(table.Rules)
			table.Rules = append(table.Rules, hookRule(t, nil, &JumpTarget{RuleNum: chainStart, NetworkProtocol: header.IPv4ProtocolNumber}))
			table.Underflows[h] = len(table.Rules)
			table.Rules = append(table.Rules, hookRule(t, nil, accept))
		}
		// Pad so that the user chain starts at chainStart, whatever the count of hooks.
		for len(table.Rules) < chainStart-1 {
			table.Rules = append(table.Rules, hookRule(t, nil, accept))
		}
		table.Rules = append(table.Rules,
			hookRule(t, nil, &userChainTarget{}),
			hookRule(t, &info, accept),
			hookRule(t, nil, &returnTarget{}),
		)
		return table
	}

	tests := []struct {
		name    string
		table   stack.Table
		wantErr bool
	}{
		{"is-out in OUTPUT", chain(t, isOut, stack.Output), true},
		{"physdev-out in OUTPUT", chain(t, out, stack.Output), true},
		{"is-out and not is-bridged in OUTPUT", chain(t, isOutNotBridged, stack.Output), true},
		{"is-out and is-bridged in OUTPUT", chain(t, isOutBridged, stack.Output), false},
		{"is-out in FORWARD", chain(t, isOut, stack.Forward), false},
		{"is-out in POSTROUTING", chain(t, isOut, stack.Postrouting), false},
		{"physdev-out in FORWARD and POSTROUTING", chain(t, out, stack.Forward, stack.Postrouting), false},
		{"is-out in FORWARD and OUTPUT", chain(t, isOut, stack.Forward, stack.Output), true},
		{"physdev-in in OUTPUT", chain(t, in, stack.Output), false},
		{"is-in in OUTPUT", chain(t, isIn, stack.Output), false},
		{"is-out in a user chain of FORWARD", userChain(t, isOut, stack.Forward), false},
		{"is-out in a user chain of OUTPUT", userChain(t, isOut, stack.Output), true},
		{"is-out in a user chain of FORWARD and OUTPUT", userChain(t, isOut, stack.Forward, stack.Output), true},
		{"is-out in a user chain that no chain reaches", userChain(t, isOut), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := checkMatcherHooks(tc.table, false)
			if (err != nil) != tc.wantErr {
				t.Errorf("checkMatcherHooks = %v, want error %v", err, tc.wantErr)
			}
		})
	}
}

// filterTableBlob returns the argument of the IPT_SO_SET_REPLACE call for the
// filter table that userspace writes. Each builtin chain has an ACCEPT policy.
// The chain of hook also has one rule with the matcher entries and an ACCEPT
// target, in front of the policy.
func filterTableBlob(hook stack.Hook, matchers []byte) []byte {
	standardAccept := linux.XTStandardTarget{Target: linux.XTEntryTarget{TargetSize: linux.SizeOfXTStandardTarget}, Verdict: -linux.NF_ACCEPT - 1}
	errorTarget := linux.XTErrorTarget{Target: linux.XTEntryTarget{TargetSize: linux.SizeOfXTErrorTarget}}
	copy(errorTarget.Target.Name[:], ErrorTargetName)
	copy(errorTarget.Name[:], ErrorTargetName)

	entry := func(matchers []byte, target marshal.Marshallable) []byte {
		targetBytes := make([]byte, target.SizeBytes())
		target.MarshalUnsafe(targetBytes)
		e := linux.IPTEntry{
			TargetOffset: uint16(linux.SizeOfIPTEntry + len(matchers)),
			NextOffset:   uint16(linux.SizeOfIPTEntry + len(matchers) + len(targetBytes)),
		}
		buf := make([]byte, linux.SizeOfIPTEntry)
		e.MarshalUnsafe(buf)
		return append(append(buf, matchers...), targetBytes...)
	}

	replace := linux.IPTReplace{ValidHooks: 1<<linux.NF_INET_LOCAL_IN | 1<<linux.NF_INET_FORWARD | 1<<linux.NF_INET_LOCAL_OUT}
	copy(replace.Name[:], filterTable)
	var entries []byte
	for _, h := range []struct {
		hook  stack.Hook
		index int
	}{{stack.Input, linux.NF_INET_LOCAL_IN}, {stack.Forward, linux.NF_INET_FORWARD}, {stack.Output, linux.NF_INET_LOCAL_OUT}} {
		replace.HookEntry[h.index] = uint32(len(entries))
		replace.NumEntries++
		if h.hook == hook {
			entries = append(entries, entry(matchers, &standardAccept)...)
			replace.NumEntries++
		}
		replace.Underflow[h.index] = uint32(len(entries))
		entries = append(entries, entry(nil, &standardAccept)...)
	}
	replace.NumEntries++
	entries = append(entries, entry(nil, &errorTarget)...)
	replace.Size = uint32(len(entries))

	blob := make([]byte, linux.SizeOfIPTReplace)
	replace.MarshalUnsafe(blob)
	return append(blob, entries...)
}

// TestSetEntriesChecksTheHooksOfPhysdev replaces the filter table of a stack
// with the writes that iptables makes.
func TestSetEntriesChecksTheHooksOfPhysdev(t *testing.T) {
	isOut := physdevEntry(physdevInfo{bitmask: physdevOpIsOut})
	isOutBridged := physdevEntry(physdevInfo{bitmask: physdevOpIsOut | physdevOpBridged})
	tests := []struct {
		name     string
		hook     stack.Hook
		matchers []byte
		wantErr  bool
	}{
		{"is-out in FORWARD", stack.Forward, isOut, false},
		{"is-out in OUTPUT", stack.Output, isOut, true},
		{"is-out and is-bridged in OUTPUT", stack.Output, isOutBridged, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ms := newMatchStack(t)
			err := SetEntries(nil, ms.stack, filterTableBlob(tc.hook, tc.matchers), false)
			if (err != nil) != tc.wantErr {
				t.Fatalf("SetEntries = %v, want error %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			var found bool
			for _, rule := range ms.stack.IPTables().GetTable(stack.FilterID, false).Rules {
				for _, m := range rule.Matchers {
					_, ok := m.(*PhysdevMatcher)
					found = found || ok
				}
			}
			if !found {
				t.Errorf("the filter table has no physdev matcher after SetEntries")
			}
		})
	}
}
