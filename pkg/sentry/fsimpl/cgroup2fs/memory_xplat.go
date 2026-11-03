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
	"fmt"
	"math"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// This file adds two parts of the memory controller that runc, containerd, and
// docker read: the file memory.stat, and the enforcement of memory.max.

// memoryStatFields is the content of memory.stat. The Sentry counts memory by
// kind and not by LRU list, so the lists follow from the kinds as in
// Linux: shmem lives on the anonymous lists, and cached file data is inactive.
// Fields that the Sentry cannot count per cgroup stay zero.
type memoryStatFields struct {
	anon, file, kernel, shmem, fileMapped  uint64
	inactiveAnon, inactiveFile, activeFile uint64
}

// memoryStatFor derives the fields of memory.stat from the per-kind usage of a
// cgroup subtree. Their sum anon + file + kernel is the value of memory.current.
func memoryStatFor(s usage.MemoryStats) memoryStatFields {
	return memoryStatFields{
		anon:         s.Anonymous,
		file:         s.PageCache + s.Mapped + s.Tmpfs + s.Ramdiskfs,
		kernel:       s.System,
		shmem:        s.Tmpfs,
		fileMapped:   s.Mapped,
		inactiveAnon: s.Anonymous + s.Tmpfs,
		inactiveFile: s.PageCache + s.Ramdiskfs,
		activeFile:   s.Mapped,
	}
}

// writeTo writes the fields in the order and the format of Linux.
func (f memoryStatFields) writeTo(buf *bytes.Buffer) {
	for _, kv := range []struct {
		key string
		val uint64
	}{
		{"anon", f.anon},
		{"file", f.file},
		{"kernel", f.kernel},
		{"kernel_stack", 0},
		{"pagetables", 0},
		{"sock", 0},
		{"shmem", f.shmem},
		{"file_mapped", f.fileMapped},
		{"file_dirty", 0},
		{"file_writeback", 0},
		{"anon_thp", 0},
		{"inactive_anon", f.inactiveAnon},
		{"active_anon", 0},
		{"inactive_file", f.inactiveFile},
		{"active_file", f.activeFile},
		{"unevictable", 0},
		{"slab_reclaimable", 0},
		{"slab_unreclaimable", 0},
		{"slab", 0},
	} {
		fmt.Fprintf(buf, "%s %d\n", kv.key, kv.val)
	}
}

// memoryStat implements vfs.DynamicBytesSource for memory.stat.
type memoryStat struct {
	m *memory
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (ms *memoryStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	memCgIDs := make(map[uint32]struct{})
	ms.m.c.fs.treeMu.RLock()
	collectMemCgIDs(ms.m.c, memCgIDs)
	ms.m.c.fs.treeMu.RUnlock()

	memoryStatFor(getUsageStats(k, memCgIDs)).writeTo(buf)
	return nil
}

// getUsageStats returns the usage by kind for all cgroup IDs in memCgIDs.
func getUsageStats(k *kernel.Kernel, memCgIDs map[uint32]struct{}) usage.MemoryStats {
	_ = k.MemoryFile().UpdateUsage(memCgIDs)
	return sumUsageStats(memCgIDs)
}

// sumUsageStats adds the accounted usage of the cgroup IDs in memCgIDs.
func sumUsageStats(memCgIDs map[uint32]struct{}) usage.MemoryStats {
	var sum usage.MemoryStats
	for id := range memCgIDs {
		s, _ := usage.MemoryAccounting.CopyPerCg(id)
		sum.System += s.System
		sum.Anonymous += s.Anonymous
		sum.PageCache += s.PageCache
		sum.Tmpfs += s.Tmpfs
		sum.Mapped += s.Mapped
		sum.Ramdiskfs += s.Ramdiskfs
	}
	return sum
}

// oomState is the OOM bookkeeping of one memory controller.
type oomState struct {
	// The counters of memory.events. As in Linux, a cgroup counts the events
	// of its own subtree.
	hitMax       atomicbitops.Uint64
	oom          atomicbitops.Uint64
	oomKill      atomicbitops.Uint64
	oomGroupKill atomicbitops.Uint64

	// eventsFile is the memory.events file. The cgroup creation sets it under
	// the tree lock, before any reader can find the controller.
	eventsFile *eventFile

	// pending holds the thread groups that the enforcer killed and that are
	// still in the cgroup. Only the enforcer goroutine uses it.
	pending map[*kernel.ThreadGroup]struct{}
}

// memoryEnforcer is the state of the goroutine that enforces memory.max.
type memoryEnforcer struct {
	// running is true while the goroutine runs or starts.
	running atomic.Bool
}

const (
	// oomPollInterval is the shortest time between two checks of the limits.
	oomPollInterval = 5 * time.Millisecond
	// oomScanRatio limits the checks to 1/oomScanRatio of a CPU, as pgalloc
	// limits its own scans of the memory file.
	oomScanRatio = 4
)

// armMemoryEnforcer starts the goroutine that enforces memory.max if it does
// not run. The goroutine ends when no cgroup has a limit or the guest has no
// task. A later write of a limit starts it again.
func (fs *filesystem) armMemoryEnforcer(k *kernel.Kernel) {
	if fs.memEnforcer.running.CompareAndSwap(false, true) {
		go fs.enforceMemoryLimits(k)
	}
}

// enforceMemoryLimits checks the limits every oomPollInterval. Linux checks at
// each charge of a page. The Sentry sees a committed page only when it scans
// the memory file, so a task can pass its limit by what it allocates between
// two checks.
func (fs *filesystem) enforceMemoryLimits(k *kernel.Kernel) {
	ctx := k.SupervisorContext()
	delay := oomPollInterval
	for {
		time.Sleep(delay)
		if k.RootPIDNamespace().NumTasks() == 0 {
			fs.memEnforcer.running.Store(false)
			return
		}
		limited := fs.limitedMemory()
		if len(limited) == 0 {
			fs.memEnforcer.running.Store(false)
			// A write of a limit can see running == true just before the store
			// above and then not start a goroutine.
			if len(fs.limitedMemory()) == 0 || !fs.memEnforcer.running.CompareAndSwap(false, true) {
				return
			}
			continue
		}
		start := time.Now()
		fs.checkMemoryLimits(ctx, k, limited)
		delay = max(oomPollInterval, oomScanRatio*time.Since(start))
	}
}

// limitedMemory returns the active memory controllers that have a finite
// memory.max.
func (fs *filesystem) limitedMemory() []*memory {
	fs.treeMu.RLock()
	defer fs.treeMu.RUnlock()
	var limited []*memory
	visit := func(c *cgroup) {
		if m, ok := c.ctrls[kernel.Cgroup2Memory].(*memory); ok && m.isActive() && m.maxBytes.Load() != math.MaxInt64 {
			limited = append(limited, m)
		}
	}
	root := fs.root.Inode().(*cgroup)
	visit(root)
	root.walkSubtreeLocked(func(c *cgroup) bool {
		visit(c)
		return true
	})
	return limited
}

// checkMemoryLimits kills in each cgroup of limited whose usage passes its
// limit.
func (fs *filesystem) checkMemoryLimits(ctx context.Context, k *kernel.Kernel, limited []*memory) {
	subtrees := make([]map[uint32]struct{}, len(limited))
	all := make(map[uint32]struct{})
	fs.treeMu.RLock()
	for i, m := range limited {
		subtrees[i] = make(map[uint32]struct{})
		collectMemCgIDs(m.c, subtrees[i])
		collectMemCgIDs(m.c, all)
	}
	fs.treeMu.RUnlock()

	// One scan covers every limited subtree.
	_ = k.MemoryFile().UpdateUsage(all)
	for i, m := range limited {
		s := sumUsageStats(subtrees[i])
		total := s.System + s.Anonymous + s.PageCache + s.Tmpfs + s.Mapped + s.Ramdiskfs
		if limit := m.maxBytes.Load(); limit != math.MaxInt64 && total > uint64(limit) {
			m.oomKill(ctx, k)
		}
	}
}

// oomCandidate is a process that the OOM killer can end.
type oomCandidate struct {
	group *kernel.ThreadGroup
	// rss is the resident set size of the process in bytes.
	rss uint64
}

// oomVictims returns the candidates that the OOM killer ends. With group set
// it returns all of them. Otherwise it returns the candidate with the largest
// resident set, and the first of several equal ones.
func oomVictims(candidates []oomCandidate, group bool) []oomCandidate {
	if group || len(candidates) <= 1 {
		return candidates
	}
	largest := candidates[0]
	for _, c := range candidates[1:] {
		if c.rss > largest.rss {
			largest = c
		}
	}
	return []oomCandidate{largest}
}

// oomKill ends tasks of the subtree of m, as the OOM killer of Linux does for a
// cgroup that passed memory.max. With memory.oom.group set, it kills every
// process. Otherwise it kills the process with the largest resident set. It
// does nothing while an earlier victim still leaves the cgroup, because the
// memory of that victim is not free yet.
func (m *memory) oomKill(ctx context.Context, k *kernel.Kernel) {
	fs := m.c.fs
	var tasks []*kernel.Task
	fs.treeMu.RLock()
	fs.tasksMu.RLock()
	for t := range m.c.tasks {
		tasks = append(tasks, t)
	}
	m.c.walkSubtreeLocked(func(c *cgroup) bool {
		for t := range c.tasks { // +checklocksforce: fs.tasksMu is locked
			tasks = append(tasks, t)
		}
		return true
	})
	fs.tasksMu.RUnlock()
	fs.treeMu.RUnlock()

	rss := make(map[*kernel.ThreadGroup]uint64)
	present := make(map[*kernel.ThreadGroup]struct{})
	for _, t := range tasks {
		tg := t.ThreadGroup()
		present[tg] = struct{}{}
		if t.ExitState() != kernel.TaskExitNone {
			continue
		}
		var size uint64
		if mm := t.MemoryManager(); mm != nil {
			size = mm.ResidentSetSize()
		}
		rss[tg] = max(rss[tg], size)
	}

	for tg := range m.oom.pending {
		if _, ok := present[tg]; !ok {
			delete(m.oom.pending, tg)
		}
	}
	if len(m.oom.pending) > 0 || len(rss) == 0 {
		return
	}

	candidates := make([]oomCandidate, 0, len(rss))
	for tg, size := range rss {
		candidates = append(candidates, oomCandidate{group: tg, rss: size})
	}
	group := m.oomGroup.Load()
	victims := oomVictims(candidates, group)

	if m.oom.pending == nil {
		m.oom.pending = make(map[*kernel.ThreadGroup]struct{})
	}
	for _, v := range victims {
		if err := k.SendExternalSignalThreadGroup(v.group, &linux.SignalInfo{Signo: int32(linux.SIGKILL)}); err != nil {
			continue
		}
		m.oom.pending[v.group] = struct{}{}
	}
	m.countOOMEvents(ctx, uint64(len(m.oom.pending)), group)
}

// countOOMEvents records one OOM event that killed n processes in m and in each
// ancestor memory controller, and wakes the readers of memory.events.
func (m *memory) countOOMEvents(ctx context.Context, n uint64, group bool) {
	if n == 0 {
		return
	}
	for cur := m; cur != nil; cur = cur.parent {
		cur.oom.hitMax.Add(1)
		cur.oom.oom.Add(1)
		cur.oom.oomKill.Add(n)
		if group {
			cur.oom.oomGroupKill.Add(1)
		}
		if cur.oom.eventsFile != nil {
			cur.oom.eventsFile.Notify(ctx)
		}
	}
}
