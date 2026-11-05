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

	"z.gfire.dev/gvx/pkg/tcpip/stack"
)

// TestMarshaledMatchersCarryTheirRevision checks the revision byte of the match
// entries that GET_ENTRIES returns. iptables reads the revision back to find
// the extension that prints the rule. A rule with the match mark at revision 0
// prints as "unsupported revision", and the next "iptables -I" on the table
// fails with "Incompatible with this kernel".
func TestMarshaledMatchersCarryTheirRevision(t *testing.T) {
	tests := []struct {
		name string
		m    stack.Matcher
		want uint8
	}{
		{"mark", NewMarkMatcher(0x10000, 0x10000, false), markRevision},
		{"multiport v0", &multiportMatcher{flags: 1, count: 1, ports: []uint16{80}}, matcherRevMultiport},
		{"multiport v1", &multiportMatcherV1{flags: 1, count: 1, ports: []uint16{80}, pflags: []uint8{0}}, matcherRevMultiportV1},
		{"owner", &OwnerMatcher{matchUID: true}, 0},
		{"tcp", &TCPMatcher{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := marshalMatcher(tt.m)
			if got := buf[revisionOffset]; got != tt.want {
				t.Errorf("revision byte = %d, want %d", got, tt.want)
			}
		})
	}
}
