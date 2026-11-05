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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
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

type countingPlatform bool

func (c countingPlatform) CountsCgroupMemory() bool { return bool(c) }

func TestEnforcerSupported(t *testing.T) {
	tests := []struct {
		name     string
		platform any
		want     bool
	}{
		{"a platform without the method counts memory", struct{}{}, true},
		{"a platform that counts memory", countingPlatform(true), true},
		{"a platform that cannot count memory", countingPlatform(false), false},
	}
	for _, tc := range tests {
		if got := enforcerSupported(tc.platform); got != tc.want {
			t.Errorf("%s: enforcerSupported = %t, want %t", tc.name, got, tc.want)
		}
	}
}

func TestOOMKillCountsInTheCgroupOfTheVictim(t *testing.T) {
	root := &memory{}
	pod := &memory{parent: root}
	victim := &memory{parent: pod}
	sibling := &memory{parent: pod}
	ctx := context.Background()

	// The pod passed its limit, and the kill ended a process of one child.
	pod.countOOMEvent(ctx)
	victim.countOOMKill(ctx)
	pod.countOOMGroupKill(ctx)

	for _, tc := range []struct {
		name                string
		m                   *memory
		oom, kill, groupOOM uint64
	}{
		{"root", root, 1, 1, 1},
		{"pod", pod, 1, 1, 1},
		{"victim", victim, 0, 1, 0},
		{"sibling", sibling, 0, 0, 0},
	} {
		if got := tc.m.oom.oom.Load(); got != tc.oom {
			t.Errorf("%s oom = %d, want %d", tc.name, got, tc.oom)
		}
		if got := tc.m.oom.oomKill.Load(); got != tc.kill {
			t.Errorf("%s oom_kill = %d, want %d", tc.name, got, tc.kill)
		}
		if got := tc.m.oom.oomGroupKill.Load(); got != tc.groupOOM {
			t.Errorf("%s oom_group_kill = %d, want %d", tc.name, got, tc.groupOOM)
		}
	}
}

func TestOOMGroupIsTheHighestGroupBelowTheLimitedCgroup(t *testing.T) {
	root := &memory{}
	pod := &memory{parent: root}
	ctrA := &memory{parent: pod}
	ctrB := &memory{parent: pod}
	nested := &memory{parent: ctrA}
	ctrA.oomGroup.Store(true)
	nested.oomGroup.Store(true)
	root.oomGroup.Store(true)

	if got := oomGroupOf(nested, pod); got != ctrA {
		t.Errorf("oomGroupOf(nested, pod) = %p, want the container %p", got, ctrA)
	}
	if got := oomGroupOf(ctrB, pod); got != nil {
		t.Errorf("oomGroupOf(ctrB, pod) = %p, want nil: a group above the limited cgroup does not count", got)
	}
	candidates := []oomCandidate{{id: 1, mem: nested}, {id: 2, mem: ctrA}, {id: 3, mem: ctrB}}
	var ids []kernel.ThreadID
	for _, c := range oomGroupMembers(candidates, ctrA) {
		ids = append(ids, c.id)
	}
	if !slices.Equal(ids, []kernel.ThreadID{1, 2}) {
		t.Errorf("members of the container group = %v, want [1 2]", ids)
	}
}

func TestMemoryEnforcerOptionsKeepSetFieldsAndFillTheRest(t *testing.T) {
	def := DefaultMemoryEnforcerOptions()
	if def.PollInterval != oomPollInterval || def.IdlePollInterval != oomIdlePollInterval || def.ScanRatio != oomScanRatio {
		t.Errorf("defaults = %+v, want the built-in constants", def)
	}
	got := MemoryEnforcerOptions{PollInterval: 50 * time.Millisecond, ScanRatio: 9}.withDefaults()
	if got.PollInterval != 50*time.Millisecond || got.ScanRatio != 9 || got.IdlePollInterval != oomIdlePollInterval {
		t.Errorf("options = %+v, want the set fields and the default idle interval", got)
	}
}

type fixedClock struct{}

func (fixedClock) Now() ktime.Time                     { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedClock) NewTimer(ktime.Listener) ktime.Timer { panic("fixedClock has no timers") }

func newTestFilesystem(t *testing.T, opts MemoryEnforcerOptions) *filesystem {
	t.Helper()
	ctx := context.WithValues(context.Background(), map[any]any{ktime.CtxRealtimeClock: fixedClock{}})
	k := &kernel.Kernel{}
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	vfsfs, err := NewFilesystemWithMemoryOptions(opts)(ctx, k, vfsObj)
	if err != nil {
		t.Fatalf("NewFilesystemWithMemoryOptions: %v", err)
	}
	return vfsfs.Impl().(*filesystem)
}

func TestNewFilesystemKeepsTheOptionsOnTheFilesystem(t *testing.T) {
	want := MemoryEnforcerOptions{PollInterval: 3 * time.Millisecond, IdlePollInterval: 7 * time.Millisecond, ScanRatio: 2}
	if got := newTestFilesystem(t, want).memEnforcer.opts; got != want {
		t.Errorf("enforcer options = %+v, want %+v", got, want)
	}
	if got := newTestFilesystem(t, MemoryEnforcerOptions{}).memEnforcer.opts.withDefaults(); got != DefaultMemoryEnforcerOptions() {
		t.Errorf("enforcer options of a zero value = %+v, want the defaults", got)
	}
}

// TestFilesystemsAreFreeAfterTheLastReference creates many filesystems, as
// many sandboxes do, and drops them. No package-level value may keep one, or a
// host that creates sandboxes in a loop would hold the memory of every kernel.
func TestFilesystemsAreFreeAfterTheLastReference(t *testing.T) {
	const count = 64
	var refs []weak.Pointer[filesystem]
	for range count {
		refs = append(refs, weak.Make(newTestFilesystem(t, MemoryEnforcerOptions{PollInterval: time.Millisecond})))
	}
	for range 5 {
		runtime.GC()
	}
	leaked := 0
	for _, r := range refs {
		if r.Value() != nil {
			leaked++
		}
	}
	if leaked != 0 {
		t.Errorf("%d of %d filesystems stay reachable after the last reference is gone", leaked, count)
	}
}
