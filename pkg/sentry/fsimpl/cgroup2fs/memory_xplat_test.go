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

package cgroup2fs

import (
	"bytes"
	"strconv"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func parseMemoryStat(t *testing.T, text string) map[string]uint64 {
	t.Helper()
	fields := make(map[string]uint64)
	for _, line := range strings.Split(strings.TrimSuffix(text, "\n"), "\n") {
		key, value, ok := strings.Cut(line, " ")
		if !ok {
			t.Fatalf("memory.stat line %q has no value", line)
		}
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			t.Fatalf("memory.stat line %q: %v", line, err)
		}
		if _, dup := fields[key]; dup {
			t.Fatalf("memory.stat lists %s twice", key)
		}
		fields[key] = n
	}
	return fields
}

func TestMemoryStatSumsToMemoryCurrent(t *testing.T) {
	// Each kind has its own power of two, so a kind that the stat omits or
	// counts twice changes the sum.
	s := usage.MemoryStats{System: 1, Anonymous: 2, PageCache: 4, Tmpfs: 8, Mapped: 16, Ramdiskfs: 32}
	const current = 1 + 2 + 4 + 8 + 16 + 32

	var buf bytes.Buffer
	memoryStatFor(s).writeTo(&buf)
	got := parseMemoryStat(t, buf.String())

	if sum := got["anon"] + got["file"] + got["kernel"]; sum != current {
		t.Errorf("anon + file + kernel = %d, want memory.current %d", sum, current)
	}
	if got["shmem"] != s.Tmpfs {
		t.Errorf("shmem = %d, want the tmpfs usage %d", got["shmem"], s.Tmpfs)
	}
	if got["file_mapped"] != s.Mapped {
		t.Errorf("file_mapped = %d, want the mapped usage %d", got["file_mapped"], s.Mapped)
	}
	if want := s.Anonymous + s.Tmpfs; got["inactive_anon"]+got["active_anon"] != want {
		t.Errorf("inactive_anon + active_anon = %d, want anon + shmem %d", got["inactive_anon"]+got["active_anon"], want)
	}
}

func TestMemoryStatListsTheFieldsThatContainerRuntimesRead(t *testing.T) {
	var buf bytes.Buffer
	memoryStatFor(usage.MemoryStats{}).writeTo(&buf)
	got := parseMemoryStat(t, buf.String())

	// containerd and runc read these keys from memory.stat. docker stats
	// subtracts inactive_file from memory.current.
	for _, key := range []string{
		"anon", "file", "kernel", "kernel_stack", "sock", "shmem", "file_mapped", "file_dirty",
		"file_writeback", "inactive_anon", "active_anon", "inactive_file", "active_file", "unevictable",
	} {
		if _, ok := got[key]; !ok {
			t.Errorf("memory.stat lacks %s", key)
		}
	}
}

func TestOOMVictims(t *testing.T) {
	groups := []*kernel.ThreadGroup{new(kernel.ThreadGroup), new(kernel.ThreadGroup), new(kernel.ThreadGroup)}
	const limit = 1000
	byID := func(cs ...oomCandidate) []oomCandidate { return cs }

	tests := []struct {
		name       string
		candidates []oomCandidate
		group      bool
		want       []int
	}{
		{name: "largest process only", candidates: byID(
			oomCandidate{group: groups[0], id: 1, rss: 10},
			oomCandidate{group: groups[1], id: 2, rss: 90},
			oomCandidate{group: groups[2], id: 3, rss: 50}), want: []int{1}},
		{name: "equal scores go to the lower ID whatever the input order", candidates: byID(
			oomCandidate{group: groups[2], id: 7, rss: 90},
			oomCandidate{group: groups[1], id: 4, rss: 90},
			oomCandidate{group: groups[0], id: 9, rss: 10}), want: []int{1}},
		{name: "a negative oom_score_adj protects the largest process", candidates: byID(
			oomCandidate{group: groups[0], id: 1, rss: 500, adj: -900},
			oomCandidate{group: groups[1], id: 2, rss: 200}), want: []int{1}},
		{name: "a positive oom_score_adj attracts the kill", candidates: byID(
			oomCandidate{group: groups[0], id: 1, rss: 500},
			oomCandidate{group: groups[1], id: 2, rss: 200, adj: 500}), want: []int{1}},
		{name: "every process with oom.group in ID order", candidates: byID(
			oomCandidate{group: groups[1], id: 2, rss: 5},
			oomCandidate{group: groups[0], id: 1, rss: 90}), group: true, want: []int{0, 1}},
		{name: "single process", candidates: byID(oomCandidate{group: groups[0], id: 1}), want: []int{0}},
		{name: "no process", want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []*kernel.ThreadGroup
			for _, v := range oomVictims(tc.candidates, tc.group, limit) {
				got = append(got, v.group)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("oomVictims = %d processes, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != groups[tc.want[i]] {
					t.Errorf("victim %d is group %d, want group %d", i, indexOf(groups, got[i]), tc.want[i])
				}
			}
		})
	}
}

func indexOf(groups []*kernel.ThreadGroup, g *kernel.ThreadGroup) int {
	for i := range groups {
		if groups[i] == g {
			return i
		}
	}
	return -1
}

func TestOOMGateKillsOnceUntilTheUsageDrops(t *testing.T) {
	var g oomGate
	steps := []struct {
		name    string
		over    bool
		pending int
		want    bool
	}{
		{"first overrun kills", true, 0, true},
		{"the victim still runs", true, 1, false},
		{"the victim left and the pages are not free yet", true, 0, false},
		{"usage drops under the limit", false, 0, false},
		{"a new overrun kills again", true, 0, true},
		{"tmpfs data keeps the usage over the limit, first check", true, 0, false},
		{"tmpfs data keeps the usage over the limit, second check", true, 0, true},
	}
	for _, st := range steps {
		if got := g.shouldKill(st.over, st.pending); got != st.want {
			t.Errorf("%s: shouldKill(over=%t, pending=%d) = %t, want %t", st.name, st.over, st.pending, got, st.want)
		}
	}
}

func TestUnreclaimableUsageIgnoresReclaimableAndFreedMemory(t *testing.T) {
	s := usage.MemoryStats{System: 1 << 20, Anonymous: 2, PageCache: 4 << 20, Tmpfs: 8, Mapped: 16 << 20, Ramdiskfs: 32}
	if got, want := unreclaimableUsage(s), uint64(2+8+32); got != want {
		t.Errorf("unreclaimableUsage = %d, want anonymous plus tmpfs plus ramdisk %d", got, want)
	}
}

func TestEnforcerSupported(t *testing.T) {
	tests := []struct {
		goos, platform string
		want           bool
	}{
		{"linux", "*systrap.Systrap", true},
		{"darwin", "*hvf.HVF", true},
		{"windows", "*whpx.WHPX", true},
		{"windows", "*systrap.Systrap", false},
	}
	for _, tc := range tests {
		if got := enforcerSupported(tc.goos, tc.platform); got != tc.want {
			t.Errorf("enforcerSupported(%q, %q) = %t, want %t", tc.goos, tc.platform, got, tc.want)
		}
	}
}

func TestCountOOMEventsCountsInEveryAncestor(t *testing.T) {
	root := &memory{}
	mid := &memory{parent: root}
	leaf := &memory{parent: mid}

	leaf.countOOMEvents(context.Background(), 2, false)
	leaf.countOOMEvents(context.Background(), 1, true)
	leaf.countOOMEvents(context.Background(), 0, true)

	for name, m := range map[string]*memory{"leaf": leaf, "mid": mid, "root": root} {
		if got := m.oom.oom.Load(); got != 2 {
			t.Errorf("%s oom = %d, want 2 events", name, got)
		}
		if got := m.oom.oomKill.Load(); got != 3 {
			t.Errorf("%s oom_kill = %d, want 3 kills", name, got)
		}
		if got := m.oom.oomGroupKill.Load(); got != 1 {
			t.Errorf("%s oom_group_kill = %d, want 1", name, got)
		}
	}
}
