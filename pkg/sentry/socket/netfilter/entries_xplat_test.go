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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// TestGetEntriesReportsInterfaceInversion verifies that the table that the
// getsockopt path returns keeps the "!" of "-i" and "-o". Without the flag,
// "iptables -C" and "iptables -D" do not find a rule such as
// "! -i docker0 -j DNAT", and dockerd leaves stale rules behind.
func TestGetEntriesReportsInterfaceInversion(t *testing.T) {
	for _, ipv6 := range []bool{false, true} {
		name := "ipv4"
		if ipv6 {
			name = "ipv6"
		}
		t.Run(name, func(t *testing.T) {
			filter := stack.EmptyFilter4()
			if ipv6 {
				filter = stack.EmptyFilter6()
			}
			filter.InputInterface, filter.InputInterfaceMask = "docker0", "\xff\xff\xff\xff\xff\xff\xff"
			filter.InputInterfaceInvert = true
			filter.OutputInterface, filter.OutputInterfaceMask = "eth0", "\xff\xff\xff\xff"
			filter.OutputInterfaceInvert = true

			table := stack.EmptyNATTable()
			table.Rules = []stack.Rule{{
				Filter: filter,
				Target: &acceptTarget{AcceptTarget: stack.AcceptTarget{NetworkProtocol: filter.NetworkProtocol()}},
			}}

			var inverseFlags uint8
			if ipv6 {
				entries, _ := getEntries6(table, linux.TableName{'n', 'a', 't'})
				inverseFlags = uint8(entries.Entrytable[0].Entry.IPv6.InverseFlags)
				want := uint8(linux.IP6T_INV_VIA_IN | linux.IP6T_INV_VIA_OUT)
				if inverseFlags != want {
					t.Errorf("InverseFlags = 0x%x, want 0x%x", inverseFlags, want)
				}
				return
			}
			entries, _ := getEntries4(table, linux.TableName{'n', 'a', 't'})
			inverseFlags = entries.Entrytable[0].Entry.IP.InverseFlags
			want := uint8(linux.IPT_INV_VIA_IN | linux.IPT_INV_VIA_OUT)
			if inverseFlags != want {
				t.Errorf("InverseFlags = 0x%x, want 0x%x", inverseFlags, want)
			}
		})
	}
}
