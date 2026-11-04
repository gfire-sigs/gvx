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

package memdev

import "testing"

func TestKmsgTextDropsThePriorityPrefix(t *testing.T) {
	tests := []struct{ record, want string }{
		{"<6>started\n", "started"},
		{"<30>two words", "two words"},
		{"plain\n\n", "plain"},
		{"<x>not a priority", "<x>not a priority"},
		{"<>empty prefix", "<>empty prefix"},
		{"<6", "<6"},
	}
	for _, tc := range tests {
		if got := kmsgText(tc.record); got != tc.want {
			t.Errorf("kmsgText(%q) = %q, want %q", tc.record, got, tc.want)
		}
	}
}
