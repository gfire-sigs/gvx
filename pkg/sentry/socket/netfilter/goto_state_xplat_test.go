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
	"z.gfire.dev/gvx/pkg/state"
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
			markGoto(parsed, gotoFlag, gotoFlag)

			orig, ok := parsed.(*JumpTarget)
			if !ok {
				t.Fatalf("parseTarget type = %T, want *JumpTarget", parsed)
			}
			orig.RuleNum = 4

			var buf bytes.Buffer
			ctx := context.Background()
			if _, err := state.Save(ctx, &buf, orig); err != nil {
				t.Fatalf("state.Save: %v", err)
			}

			var restored JumpTarget
			if _, err := state.Load(ctx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
				t.Fatalf("state.Load: %v", err)
			}

			if !restored.Goto {
				t.Fatalf("restored.Goto = false, want true")
			}
			if restored.Offset != orig.Offset || restored.RuleNum != orig.RuleNum || restored.NetworkProtocol != orig.NetworkProtocol {
				t.Fatalf("restored = %+v, want %+v", restored, *orig)
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
