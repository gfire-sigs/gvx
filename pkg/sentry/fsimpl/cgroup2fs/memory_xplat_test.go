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
	small, large, equalToLarge := new(kernel.ThreadGroup), new(kernel.ThreadGroup), new(kernel.ThreadGroup)
	candidates := []oomCandidate{
		{group: small, rss: 10},
		{group: large, rss: 90},
		{group: equalToLarge, rss: 90},
	}

	tests := []struct {
		name       string
		candidates []oomCandidate
		group      bool
		want       []*kernel.ThreadGroup
	}{
		{name: "largest process only", candidates: candidates, want: []*kernel.ThreadGroup{large}},
		{name: "every process with oom.group", candidates: candidates, group: true, want: []*kernel.ThreadGroup{small, large, equalToLarge}},
		{name: "single process", candidates: candidates[:1], want: []*kernel.ThreadGroup{small}},
		{name: "no process", candidates: nil, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got []*kernel.ThreadGroup
			for _, v := range oomVictims(tc.candidates, tc.group) {
				got = append(got, v.group)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("oomVictims = %d processes, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("victim %d is not the expected process", i)
				}
			}
		})
	}
}
