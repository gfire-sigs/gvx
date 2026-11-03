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

package proc

import (
	"slices"
	"testing"
)

func TestDiffLinkDirsFollowsLinkLifecycle(t *testing.T) {
	tests := []struct {
		name      string
		have      map[string]int32
		live      map[int32]string
		wantStale []string
		wantAdd   map[string]int32
	}{
		{name: "new link", have: map[string]int32{"lo": 1}, live: map[int32]string{1: "lo", 2: "docker0"},
			wantAdd: map[string]int32{"docker0": 2}},
		{name: "deleted link", have: map[string]int32{"lo": 1, "docker0": 2}, live: map[int32]string{1: "lo"},
			wantStale: []string{"docker0"}, wantAdd: map[string]int32{}},
		{name: "renamed link", have: map[string]int32{"veth0": 5}, live: map[int32]string{5: "eth1"},
			wantStale: []string{"veth0"}, wantAdd: map[string]int32{"eth1": 5}},
		{name: "link recreated under the same name", have: map[string]int32{"docker0": 2}, live: map[int32]string{7: "docker0"},
			wantStale: []string{"docker0"}, wantAdd: map[string]int32{"docker0": 7}},
		{name: "no change", have: map[string]int32{"lo": 1}, live: map[int32]string{1: "lo"}, wantAdd: map[string]int32{}},
		{name: "unusable names are skipped", have: map[string]int32{}, live: map[int32]string{3: "", 4: "a/b"}, wantAdd: map[string]int32{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stale, add := diffLinkDirs(tc.have, tc.live)
			if !slices.Equal(stale, tc.wantStale) {
				t.Errorf("stale = %v, want %v", stale, tc.wantStale)
			}
			if len(add) != len(tc.wantAdd) {
				t.Fatalf("add = %v, want %v", add, tc.wantAdd)
			}
			for name, id := range tc.wantAdd {
				if add[name] != id {
					t.Errorf("add[%q] = %d, want %d", name, add[name], id)
				}
			}
		})
	}
}

func TestLinkDirValidComparesTheLinkIndex(t *testing.T) {
	live := map[int32]string{1: "lo", 7: "docker0"}
	tests := []struct {
		name string
		id   int32
		link string
		want bool
	}{
		{"same link", 7, "docker0", true},
		{"link deleted", 2, "docker0", false},
		{"link recreated with a new index", 2, "docker0", false},
		{"link renamed", 7, "br0", false},
		{"name taken by another index", 1, "docker0", false},
	}
	for _, tc := range tests {
		if got := linkDirValid(live, tc.id, tc.link); got != tc.want {
			t.Errorf("%s: linkDirValid(id=%d, %q) = %t, want %t", tc.name, tc.id, tc.link, got, tc.want)
		}
	}
}
