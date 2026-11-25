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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/marshal"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/tcpip/header"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

func TestJumpTargetGotoStateRoundTrip(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			filter := stack.EmptyFilter4()
			gotoFlag := uint8(iptFGoto)
			if ipv6 {
				filter = stack.EmptyFilter6()
				gotoFlag = linux.IP6T_F_GOTO
			}

			raw := linux.XTStandardTarget{
				Target: linux.XTEntryTarget{
					TargetSize: linux.SizeOfXTStandardTarget,
				},
				Verdict: 264,
			}
			targetBytes := make([]byte, linux.SizeOfXTStandardTarget)
			raw.MarshalUnsafe(targetBytes)

			parsed, err := parseTarget(filter, targetBytes, ipv6, "filter")
			if err != nil {
				t.Fatalf("parseTarget: %v", err)
			}
			applied := applyGoto(parsed, gotoFlag, gotoFlag)

			orig, ok := applied.(*GotoTarget)
			if !ok {
				t.Fatalf("applyGoto type = %T, want *GotoTarget", applied)
			}
			orig.RuleNum = 4

			var buf bytes.Buffer
			ctx := context.Background()
			if _, err := state.Save(ctx, &buf, orig); err != nil {
				t.Fatalf("state.Save: %v", err)
			}

			var restored GotoTarget
			if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
				t.Fatalf("state.Load: %v", err)
			}

			if restored.Offset != orig.Offset || restored.RuleNum != orig.RuleNum || restored.NetworkProtocol != orig.NetworkProtocol {
				t.Fatalf("restored = %+v, want %+v", restored, *orig)
			}
			if jt, ok := asJumpTarget(&restored); !ok || jt.RuleNum != orig.RuleNum || jt.Offset != orig.Offset {
				t.Fatalf("asJumpTarget(&restored) = (%+v, %v), want rule %d offset %d", jt, ok, orig.RuleNum, orig.Offset)
			}

			verdict, ruleNum := restored.Action(nil, stack.Output, nil, nil)
			if verdict != stack.RuleGoto || ruleNum != orig.RuleNum {
				t.Fatalf("Action() = (%v, %d), want (%v, %d)", verdict, ruleNum, stack.RuleGoto, orig.RuleNum)
			}

			table := stack.EmptyNATTable()
			table.Rules = []stack.Rule{{
				Filter: filter,
				Target: &restored,
			}}
			if ipv6 {
				entries, _ := getEntries6(table, linux.TableName{'f', 'i', 'l', 't', 'e', 'r'})
				if got := entries.Entrytable[0].Entry.IPv6.Flags & linux.IP6T_F_GOTO; got != linux.IP6T_F_GOTO {
					t.Fatalf("IPv6 entry Flags goto bit = 0x%x, want 0x%x", got, linux.IP6T_F_GOTO)
				}
				return
			}
			entries, _ := getEntries4(table, linux.TableName{'f', 'i', 'l', 't', 'e', 'r'})
			if got := entries.Entrytable[0].Entry.IP.Flags & iptFGoto; got != iptFGoto {
				t.Fatalf("IPv4 entry Flags goto bit = 0x%x, want 0x%x", got, iptFGoto)
			}
		})
	}
}

// TestSetEntriesGotoPreservedAcrossSaveRestore installs a real "-g" user-chain
// rule through SetEntries (both IPv4 and IPv6), verifies the installed rule
// stays a *GotoTarget, round-trips the stack via state.Save/Load (exercising
// stack.Rule.Target interface serialization), and verifies GetEntries emits
// the goto flag and target offset.
func TestSetEntriesGotoPreservedAcrossSaveRestore(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		proto := header.IPv4ProtocolNumber
		filter := stack.EmptyFilter4()
		gotoFlag := uint8(iptFGoto)
		entrySize := uint32(linux.SizeOfIPTEntry + linux.SizeOfXTStandardTarget)
		errEntrySize := uint32(linux.SizeOfIPTEntry + linux.SizeOfXTErrorTarget)
		if ipv6 {
			name = "ipv6"
			proto = header.IPv6ProtocolNumber
			filter = stack.EmptyFilter6()
			gotoFlag = linux.IP6T_F_GOTO
			entrySize = uint32(linux.SizeOfIP6TEntry + linux.SizeOfXTStandardTarget)
			errEntrySize = uint32(linux.SizeOfIP6TEntry + linux.SizeOfXTErrorTarget)
		}

		t.Run(name, func(t *testing.T) {
			// Rules layout in filter table:
			//   0: INPUT policy (ACCEPT)
			//   1: FORWARD policy (ACCEPT)
			//   2: OUTPUT rule (-g MYCHAIN -> rule 5)
			//   3: OUTPUT policy (ACCEPT)
			//   4: user chain header ("MYCHAIN")
			//   5: MYCHAIN body (RETURN)
			//   6: table end error target
			chainBodyOffset := 4*entrySize + errEntrySize
			srcTable := stack.Table{
				Rules: []stack.Rule{
					{Filter: filter, Target: &acceptTarget{NetworkProtocol: proto}},
					{Filter: filter, Target: &acceptTarget{NetworkProtocol: proto}},
					{Filter: filter, Target: &GotoTarget{JumpTarget: JumpTarget{Offset: chainBodyOffset, RuleNum: 5, NetworkProtocol: proto}}},
					{Filter: filter, Target: &acceptTarget{NetworkProtocol: proto}},
					{Filter: filter, Target: &userChainTarget{Name: "MYCHAIN", NetworkProtocol: proto}},
					{Filter: filter, Target: &returnTarget{NetworkProtocol: proto}},
					{Filter: filter, Target: &errorTarget{NetworkProtocol: proto}},
				},
				BuiltinChains: [stack.NumHooks]int{
					stack.Prerouting:  stack.HookUnset,
					stack.Input:       0,
					stack.Forward:     1,
					stack.Output:      2,
					stack.Postrouting: stack.HookUnset,
				},
				Underflows: [stack.NumHooks]int{
					stack.Prerouting:  stack.HookUnset,
					stack.Input:       0,
					stack.Forward:     1,
					stack.Output:      3,
					stack.Postrouting: stack.HookUnset,
				},
			}

			var tableName linux.TableName
			copy(tableName[:], "filter")
			var blob []byte
			if ipv6 {
				entries, info := getEntries6(srcTable, tableName)
				replace := linux.IP6TReplace{
					Name:        tableName,
					ValidHooks:  info.ValidHooks,
					NumEntries:  info.NumEntries,
					Size:        info.Size,
					HookEntry:   info.HookEntry,
					Underflow:   info.Underflow,
					NumCounters: info.NumEntries,
				}
				blob = marshal.Marshal(&replace)
				for i := range entries.Entrytable {
					blob = append(blob, marshal.Marshal(&entries.Entrytable[i].Entry)...)
					blob = append(blob, entries.Entrytable[i].Elems...)
				}
			} else {
				entries, info := getEntries4(srcTable, tableName)
				replace := linux.IPTReplace{
					Name:        tableName,
					ValidHooks:  info.ValidHooks,
					NumEntries:  info.NumEntries,
					Size:        info.Size,
					HookEntry:   info.HookEntry,
					Underflow:   info.Underflow,
					NumCounters: info.NumEntries,
				}
				blob = marshal.Marshal(&replace)
				for i := range entries.Entrytable {
					blob = append(blob, marshal.Marshal(&entries.Entrytable[i].Entry)...)
					blob = append(blob, entries.Entrytable[i].Elems...)
				}
			}

			s := stack.New(stack.Options{})
			defer s.Close()
			if err := SetEntries(nil, s, blob, ipv6); err != nil {
				t.Fatalf("SetEntries: %v", err)
			}

			verifyGoto := func(phase string, ipt *stack.IPTables) {
				t.Helper()
				tbl := ipt.GetTable(stack.FilterID, ipv6)
				gotTarget := tbl.Rules[2].Target
				gt, ok := gotTarget.(*GotoTarget)
				if !ok {
					t.Fatalf("%s: rule 2 target type = %T, want *GotoTarget", phase, gotTarget)
				}
				verdict, ruleNum := gt.Action(nil, stack.Output, nil, nil)
				if verdict != stack.RuleGoto || ruleNum != 5 {
					t.Fatalf("%s: Action() = (%v, %d), want (%v, 5)", phase, verdict, ruleNum, stack.RuleGoto)
				}
				if ipv6 {
					entries, _ := getEntries6(tbl, tableName)
					if got := entries.Entrytable[2].Entry.IPv6.Flags & gotoFlag; got != gotoFlag {
						t.Fatalf("%s: getEntries6 rule 2 goto bit = 0x%x, want 0x%x", phase, got, gotoFlag)
					}
					return
				}
				entries, _ := getEntries4(tbl, tableName)
				if got := entries.Entrytable[2].Entry.IP.Flags & gotoFlag; got != gotoFlag {
					t.Fatalf("%s: getEntries4 rule 2 goto bit = 0x%x, want 0x%x", phase, got, gotoFlag)
				}
			}

			verifyGoto("installed", s.IPTables())

			ipt := s.IPTables()
			var buf bytes.Buffer
			ctx := context.Background()
			if _, err := state.Save(ctx, &buf, ipt); err != nil {
				t.Fatalf("state.Save: %v", err)
			}
			var restored stack.IPTables
			if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
				t.Fatalf("state.Load: %v", err)
			}

			verifyGoto("restored", &restored)
		})
	}
}
