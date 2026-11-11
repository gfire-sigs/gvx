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
	goContext "context"
	"fmt"
	"maps"
	"math"
	"slices"
	"sync"
	"sync/atomic"
	"time"
	"weak"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
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

// cgroupRootXplatState holds filesystem-wide Tier 2 state saved on the root
// memoryStat node so Tier 3 autogen files stay untouched.
//
// +stateify savable
type cgroupRootXplatState struct {
	klog           *kernel.KernelLog
	klogBufLen     int
	reportedMemory uint64
	enforcerOpts   MemoryEnforcerOptions
	cpuBandwidths  map[*cpu]*kernel.CPUBandwidth
	taskCPUMeters  map[*kernel.Task]int64
}

// memoryStat implements vfs.DynamicBytesSource for memory.stat.
//
// +stateify savable
type memoryStat struct {
	m    *memory
	oom  oomState
	root *cgroupRootXplatState
}

func copyOOMState(dst, src *oomState) {
	dst.hitMax.Store(src.hitMax.Load())
	dst.oom.Store(src.oom.Load())
	dst.oomKill.Store(src.oomKill.Load())
	dst.oomGroupKill.Store(src.oomGroupKill.Load())
	dst.eventsFile = src.eventsFile
	dst.pending = maps.Clone(src.pending)
	dst.gate = src.gate
}

func applyRestoredKernelProps(k *kernel.Kernel, st *cgroupRootXplatState) {
	if k == nil || st == nil {
		return
	}
	if st.reportedMemory > 0 {
		k.SetReportedMemory(st.reportedMemory)
	}
	if st.klog != nil {
		k.AttachKernelLog(st.klog)
	} else if st.klogBufLen > 0 {
		k.SetKernelLogBufLen(st.klogBufLen)
	}
}

// beforeSave is invoked by stateify.
func (ms *memoryStat) beforeSave() {
	if ms.m == nil {
		return
	}
	copyOOMState(&ms.oom, &ms.m.oom)
	if ms.m.parent != nil {
		ms.root = nil
		return
	}
	fs := ms.m.c.fs
	bwMap := make(map[*cpu]*kernel.CPUBandwidth)
	var taskMeters map[*kernel.Task]int64
	k := fs.memEnforcer.saveKernel.Value()
	fs.treeMu.RLock()
	fs.tasksMu.RLock()
	visit := func(c *cgroup) {
		if cc, ok := c.ctrls[kernel.Cgroup2CPU].(*cpu); ok { // +checklocksforce: fs.treeMu is held
			if node := cc.bandwidth.node.Load(); node != nil {
				bwMap[cc] = node
			}
		}
		for t := range c.tasks { // +checklocksforce: fs.tasksMu is held
			if k == nil {
				k = t.Kernel()
			}
			if ns := t.CPUTimeMeasured().Nanoseconds(); ns > 0 {
				if taskMeters == nil {
					taskMeters = make(map[*kernel.Task]int64)
				}
				taskMeters[t] = ns
			}
		}
	}
	visit(ms.m.c)
	ms.m.c.walkSubtreeLocked(func(c *cgroup) bool { // +checklocksforce: ms.m.c.fs is fs
		visit(c)
		return true
	})
	fs.tasksMu.RUnlock()
	fs.treeMu.RUnlock()

	var (
		klog        *kernel.KernelLog
		klogBufLen  int
		reportedMem uint64
	)
	if k != nil {
		klog = k.LookupKernelLog()
		klogBufLen = k.KernelLogBufLen()
		if total, ok := k.ReportedMemory(); ok {
			reportedMem = total
		}
		for t, ns := range k.SaveTaskCPUMeters() {
			if taskMeters == nil {
				taskMeters = make(map[*kernel.Task]int64)
			}
			taskMeters[t] = ns
		}
	}
	ms.root = &cgroupRootXplatState{
		klog:           klog,
		klogBufLen:     klogBufLen,
		reportedMemory: reportedMem,
		enforcerOpts:   fs.memEnforcer.opts,
		cpuBandwidths:  bwMap,
		taskCPUMeters:  taskMeters,
	}
}

// afterLoad is invoked by stateify.
func (ms *memoryStat) afterLoad(ctx goContext.Context) {
	if ms.m == nil {
		return
	}
	copyOOMState(&ms.m.oom, &ms.oom)
	if ms.root == nil {
		return
	}
	fs := ms.m.c.fs
	fs.memEnforcer.opts = ms.root.enforcerOpts
	fs.memEnforcer.pendingRestore = ms.root
	for cc, node := range ms.root.cpuBandwidths {
		cc.bandwidth.node.Store(node)
	}
	var nilKernel *kernel.Kernel
	nilKernel.LoadTaskCPUMeters(ms.root.taskCPUMeters)

	var k *kernel.Kernel
	if ctx != nil {
		k, _ = ctx.Value(kernel.CtxKernel).(*kernel.Kernel)
	}
	if k == nil {
		for t := range ms.root.taskCPUMeters {
			if t != nil && t.Kernel() != nil {
				k = t.Kernel()
				break
			}
		}
	}
	if k != nil {
		fs.memEnforcer.saveKernel = weak.Make(k)
		applyRestoredKernelProps(k, ms.root)
	}
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (ms *memoryStat) Generate(ctx context.Context, buf *bytes.Buffer) error {
	k := kernel.KernelFromContext(ctx)
	memCgIDs := make(map[uint32]struct{})
	ms.m.c.fs.treeMu.RLock()
	collectMemCgIDs(ms.m.c, memCgIDs)
	ms.m.c.fs.treeMu.RUnlock()

	var stats usage.MemoryStats
	if k != nil && k.MemoryFile() != nil {
		stats = getUsageStats(k, memCgIDs)
		if ms.m.c.parent == nil {
			// The root cgroup accounts all memory of the sandbox, also the memory of
			// tasks that no memory cgroup owns. Linux has memory.stat at the root for
			// this, and the cAdvisor of the kubelet reads it for the memory of the node.
			stats, _ = k.MemoryFile().Accounting().CopyPerCg(0)
		}
	}
	memoryStatFor(stats).writeTo(buf)
	return nil
}

// getUsageStats returns the usage by kind for all cgroup IDs in memCgIDs.
func getUsageStats(k *kernel.Kernel, memCgIDs map[uint32]struct{}) usage.MemoryStats {
	_ = k.MemoryFile().UpdateUsage(memCgIDs)
	return sumUsageStats(k, memCgIDs)
}

// sumUsageStats adds the usage of the cgroup IDs in memCgIDs that the memory
// file of k accounted. The cgroup IDs of two kernels overlap, so the sum must
// read the accounting of k and not the global one.
func sumUsageStats(k *kernel.Kernel, memCgIDs map[uint32]struct{}) usage.MemoryStats {
	var sum usage.MemoryStats
	for id := range memCgIDs {
		s, _ := k.MemoryFile().Accounting().CopyPerCg(id)
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
//
// +stateify savable
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

	// The fields below belong to the enforcer goroutine.

	// pending holds the thread groups that the enforcer killed and that are
	// still in the cgroup.
	pending map[*kernel.ThreadGroup]struct{}
	gate    oomGate
}

// oomGate decides when the enforcer may kill again. After a kill, the memory of
// the victim is not free until the Sentry released its pages. The gate waits
// until a check sees the usage at or below the limit. If the usage stays above
// the limit because the cgroup still holds tmpfs data, the gate lets the next
// kill pass after two more checks above the limit.
//
// +stateify savable
type oomGate struct {
	disarmed   bool
	overChecks int
}

// shouldKill reports whether the enforcer kills at a check. over is true when
// the usage passes the limit, and pending counts the victims that still run.
func (g *oomGate) shouldKill(over bool, pending int) bool {
	if !over {
		*g = oomGate{}
		return false
	}
	if pending > 0 {
		return false
	}
	if g.disarmed {
		g.overChecks++
		if g.overChecks < 2 {
			return false
		}
	}
	*g = oomGate{disarmed: true}
	return true
}

// memoryEnforcer is the state of the goroutine that enforces memory.max.
//
// +stateify savable
type memoryEnforcer struct {
	// running is true while the goroutine runs or starts.
	running atomic.Bool `state:"nosave"`

	// saveKernel weakly tracks the owning Kernel so root memoryStat can
	// snapshot KernelLog even when no task is attached to a cgroup.
	saveKernel weak.Pointer[kernel.Kernel] `state:"nosave"`

	// pendingRestore holds restored root state until CompleteRestore
	// activates bandwidth nodes and applies restored kernel properties.
	pendingRestore *cgroupRootXplatState `state:"nosave"`

	mu      sync.Mutex     `state:"nosave"`
	paused  bool           `state:"nosave"`
	stopped bool           `state:"nosave"`
	stopCh  chan struct{}  `state:"nosave"`
	wg      sync.WaitGroup `state:"nosave"`

	// opts holds the time limits of the checks. A zero field selects the
	// default.
	opts MemoryEnforcerOptions
}

// MemoryEnforcerOptions sets the time limits of the checks of memory.max. A
// zero field selects the default.
//
// +stateify savable
type MemoryEnforcerOptions struct {
	// PollInterval is the shortest time between two checks while a cgroup uses
	// at least half of its limit. The default is 5 ms.
	PollInterval time.Duration
	// IdlePollInterval is the time between two checks while every limited
	// cgroup uses less than half of its limit. The default is 25 ms.
	IdlePollInterval time.Duration
	// ScanRatio limits the checks to 1/ScanRatio of a CPU. The default is 4.
	ScanRatio int
}

// DefaultMemoryEnforcerOptions returns the values that a zero field selects.
func DefaultMemoryEnforcerOptions() MemoryEnforcerOptions {
	return MemoryEnforcerOptions{}.withDefaults()
}

func (o MemoryEnforcerOptions) withDefaults() MemoryEnforcerOptions {
	if o.PollInterval <= 0 {
		o.PollInterval = oomPollInterval
	}
	if o.IdlePollInterval <= 0 {
		o.IdlePollInterval = oomIdlePollInterval
	}
	if o.ScanRatio <= 0 {
		o.ScanRatio = oomScanRatio
	}
	return o
}

// NewFilesystemWithMemoryOptions is NewFilesystem with the time limits of the
// checks of memory.max. The enforcer of the new filesystem reads them.
func NewFilesystemWithMemoryOptions(opts MemoryEnforcerOptions) func(context.Context, *kernel.Kernel, *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
	return func(ctx context.Context, k *kernel.Kernel, vfsObj *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
		vfsfs, err := NewFilesystem(ctx, k, vfsObj)
		if err != nil {
			return nil, err
		}
		fs := vfsfs.Impl().(*filesystem)
		fs.memEnforcer.opts = opts
		if k != nil {
			fs.memEnforcer.saveKernel = weak.Make(k)
		}
		return vfsfs, nil
	}
}

var _ vfs.FilesystemImplSaveRestoreExtension = (*filesystem)(nil)

// PrepareSave implements vfs.FilesystemImplSaveRestoreExtension.PrepareSave.
func (fs *filesystem) PrepareSave(ctx context.Context, _ vfs.PrepareSaveOptions) error {
	if k := kernel.KernelFromContext(ctx); k != nil {
		fs.memEnforcer.saveKernel = weak.Make(k)
	}
	fs.pauseMemoryEnforcer()
	return nil
}

// BeforeResume implements vfs.FilesystemImplSaveRestoreExtension.BeforeResume.
func (fs *filesystem) BeforeResume(ctx context.Context) {
	fs.memEnforcer.mu.Lock()
	fs.memEnforcer.paused = false
	fs.memEnforcer.mu.Unlock()
	if k := fs.resolveKernel(ctx); k != nil && len(fs.limitedMemory()) > 0 {
		fs.armMemoryEnforcer(k)
	}
}

func (fs *filesystem) resolveKernel(ctx context.Context) *kernel.Kernel {
	if ctx != nil {
		if k := kernel.KernelFromContext(ctx); k != nil {
			return k
		}
	}
	if k := fs.memEnforcer.saveKernel.Value(); k != nil {
		return k
	}
	if fs.root != nil {
		var found *kernel.Kernel
		fs.treeMu.RLock()
		fs.tasksMu.RLock()
		visit := func(c *cgroup) bool {
			for t := range c.tasks { // +checklocksforce: fs.tasksMu is held
				if t != nil && t.Kernel() != nil {
					found = t.Kernel()
					return false
				}
			}
			return true
		}
		root := fs.root.Inode().(*cgroup)
		if visit(root) {
			root.walkSubtreeLocked(visit) // +checklocksforce: root.fs is fs
		}
		fs.tasksMu.RUnlock()
		fs.treeMu.RUnlock()
		if found != nil {
			return found
		}
	}
	if pr := fs.memEnforcer.pendingRestore; pr != nil {
		for t := range pr.taskCPUMeters {
			if t != nil && t.Kernel() != nil {
				return t.Kernel()
			}
		}
	}
	return nil
}

// CompleteRestore implements vfs.FilesystemImplSaveRestoreExtension.CompleteRestore.
func (fs *filesystem) CompleteRestore(ctx context.Context, _ vfs.CompleteRestoreOptions) error {
	k := fs.resolveKernel(ctx)
	pr := fs.memEnforcer.pendingRestore
	fs.memEnforcer.pendingRestore = nil
	now := kernel.BandwidthNow()
	if pr != nil {
		k.LoadTaskCPUMeters(pr.taskCPUMeters)
		applyRestoredKernelProps(k, pr)
		for _, node := range pr.cpuBandwidths {
			if node != nil {
				node.ActivateRestored(now)
			}
		}
	}
	if fs.root != nil {
		var limitedCPU []*cpu
		fs.treeMu.RLock()
		visit := func(c *cgroup) {
			if cc, ok := c.ctrls[kernel.Cgroup2CPU].(*cpu); ok && cc.isActive() && cc.maxUSec.Load() != cpuMaxUnlimited { // +checklocksforce: fs.treeMu is held
				limitedCPU = append(limitedCPU, cc)
			}
		}
		root := fs.root.Inode().(*cgroup)
		visit(root)
		root.walkSubtreeLocked(func(c *cgroup) bool { // +checklocksforce: root.fs is fs
			visit(c)
			return true
		})
		fs.treeMu.RUnlock()
		for _, cc := range limitedCPU {
			cc.bandwidthNode().ActivateRestored(now)
		}
	}
	if k != nil {
		fs.memEnforcer.saveKernel = weak.Make(k)
		if len(fs.limitedMemory()) > 0 {
			fs.armMemoryEnforcer(k)
		}
	}
	return nil
}

// releaseXplat stops the memory enforcer goroutine and removes active CPU
// bandwidth limits when the filesystem releases its root tree.
func (fs *filesystem) releaseXplat() {
	fs.stopMemoryEnforcer()
	var ctrls []*cpu
	seen := make(map[*cpu]struct{})
	add := func(cc *cpu) {
		if cc == nil {
			return
		}
		if _, ok := seen[cc]; !ok {
			seen[cc] = struct{}{}
			ctrls = append(ctrls, cc)
		}
	}
	if pr := fs.memEnforcer.pendingRestore; pr != nil {
		fs.memEnforcer.pendingRestore = nil
		for cc := range pr.cpuBandwidths {
			add(cc)
		}
	}
	if fs.root != nil {
		fs.treeMu.RLock()
		visit := func(c *cgroup) {
			if cc, ok := c.ctrls[kernel.Cgroup2CPU].(*cpu); ok { // +checklocksforce: fs.treeMu is held
				add(cc)
			}
		}
		root := fs.root.Inode().(*cgroup)
		visit(root)
		root.walkSubtreeLocked(func(c *cgroup) bool { // +checklocksforce: root.fs is fs
			visit(c)
			return true
		})
		fs.treeMu.RUnlock()
	}
	for _, cc := range ctrls {
		cc.releaseBandwidth()
	}
}

const (
	// oomPollInterval is the shortest time between two checks while a cgroup
	// uses at least half of its limit.
	oomPollInterval = 5 * time.Millisecond
	// oomIdlePollInterval is the time between two checks while every limited
	// cgroup uses less than half of its limit. It makes 40 wakeups a second.
	oomIdlePollInterval = 25 * time.Millisecond
	// oomScanRatio is the default of ScanRatio: it limits the checks to
	// 1/oomScanRatio of a CPU, as pgalloc limits its own scans of the memory
	// file.
	oomScanRatio = 4
	// oomImmune is the oom_score_adj value that exempts a process, as in Linux.
	oomImmune = -1000
)

// cgroupMemoryCounter is implemented by a platform that knows whether the
// Sentry can count the pages of guest memory for a memory cgroup. A platform
// without the method counts them. The Windows systrap engine runs guest code
// in stub processes, and the Sentry finds committed pages through the working
// set of its own process, so pages that only a stub wrote stay uncounted. The
// systrap tests check that this engine implements the method.
type cgroupMemoryCounter interface {
	CountsCgroupMemory() bool
}

// enforcerSupported reports whether the platform counts memory for a memory
// cgroup well enough to enforce a limit.
func enforcerSupported(p any) bool {
	c, ok := p.(cgroupMemoryCounter)
	return !ok || c.CountsCgroupMemory()
}

// armMemoryEnforcer starts the goroutine that enforces memory.max if it does
// not run. The goroutine ends when no cgroup has a limit, the filesystem stops,
// or the guest has no task. A later write of a limit starts it again.
func (fs *filesystem) armMemoryEnforcer(k *kernel.Kernel) {
	if k == nil {
		return
	}
	fs.memEnforcer.saveKernel = weak.Make(k)
	if !enforcerSupported(k.Platform) {
		return
	}
	fs.memEnforcer.mu.Lock()
	if fs.memEnforcer.stopped || fs.memEnforcer.paused || !fs.memEnforcer.running.CompareAndSwap(false, true) {
		fs.memEnforcer.mu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	fs.memEnforcer.stopCh = stopCh
	fs.memEnforcer.wg.Add(1)
	fs.memEnforcer.mu.Unlock()
	go func() {
		defer fs.memEnforcer.wg.Done()
		fs.enforceMemoryLimits(k, &fs.memEnforcer, stopCh)
	}()
}

// pauseMemoryEnforcer quiesces the memory.max goroutine before state.Save reads
// oomState fields owned by the goroutine. BeforeResume restarts it.
func (fs *filesystem) pauseMemoryEnforcer() {
	fs.memEnforcer.mu.Lock()
	fs.memEnforcer.paused = true
	if fs.memEnforcer.stopCh != nil {
		close(fs.memEnforcer.stopCh)
		fs.memEnforcer.stopCh = nil
	}
	fs.memEnforcer.mu.Unlock()
	fs.memEnforcer.wg.Wait()
}

// stopMemoryEnforcer stops the memory.max goroutine and waits for any active
// scan to finish before the caller releases backing memory files.
func (fs *filesystem) stopMemoryEnforcer() {
	fs.memEnforcer.mu.Lock()
	fs.memEnforcer.stopped = true
	if fs.memEnforcer.stopCh != nil {
		close(fs.memEnforcer.stopCh)
		fs.memEnforcer.stopCh = nil
	}
	fs.memEnforcer.mu.Unlock()
	fs.memEnforcer.wg.Wait()
}

// enforceMemoryLimits checks the limits at intervals. Linux checks at each
// charge of a page. The Sentry sees a committed page only when it scans the
// memory file, so a task can pass its limit by what it allocates between two
// checks.
func (fs *filesystem) enforceMemoryLimits(k *kernel.Kernel, e *memoryEnforcer, stopCh <-chan struct{}) {
	ctx := k.SupervisorContext()
	opts := e.opts.withDefaults()
	delay := opts.IdlePollInterval
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-stopCh:
			e.running.Store(false)
			return
		case <-timer.C:
		}
		if k.TaskSet() == nil || k.RootPIDNamespace() == nil || k.RootPIDNamespace().NumTasks() == 0 {
			e.running.Store(false)
			return
		}
		limited := fs.limitedMemory()
		if len(limited) == 0 {
			e.running.Store(false)
			// A write of a limit can see running == true just before the store
			// above and then not start a goroutine.
			e.mu.Lock()
			inactive := e.stopped || e.paused
			e.mu.Unlock()
			if inactive || len(fs.limitedMemory()) == 0 || !e.running.CompareAndSwap(false, true) {
				return
			}
			timer.Reset(delay)
			continue
		}
		start := time.Now()
		near := fs.checkMemoryLimits(ctx, k, limited)
		// The scan of a large anonymous range that no task touched costs time on
		// hosts that cannot ask for the committed pages cheaply, so the delay
		// grows with the duration of the check in both cases.
		delay = opts.IdlePollInterval
		if near {
			delay = opts.PollInterval
		}
		delay = max(delay, time.Duration(opts.ScanRatio)*time.Since(start))
		timer.Reset(delay)
	}
}

// limitedMemory returns the active memory controllers that have a finite
// memory.max.
func (fs *filesystem) limitedMemory() []*memory {
	fs.treeMu.RLock()
	defer fs.treeMu.RUnlock()
	var limited []*memory
	visit := func(c *cgroup) {
		if m, ok := c.ctrls[kernel.Cgroup2Memory].(*memory); ok && m.isActive() && m.maxBytes.Load() != math.MaxInt64 { // +checklocksforce: limitedMemory holds fs.treeMu while it walks
			limited = append(limited, m)
		}
	}
	root := fs.root.Inode().(*cgroup)
	visit(root)
	root.walkSubtreeLocked(func(c *cgroup) bool { // +checklocksforce: root.fs is fs
		visit(c)
		return true
	})
	return limited
}

// unreclaimableUsage returns the memory that the enforcer compares with
// memory.max: anonymous memory and tmpfs data. Page cache and mapped file
// pages are reclaimable in Linux. System memory of a cgroup is memory that
// the Sentry freed and that it has not decommitted yet.
func unreclaimableUsage(s usage.MemoryStats) uint64 {
	return s.Anonymous + s.Tmpfs + s.Ramdiskfs
}

// checkMemoryLimits kills in each cgroup of limited whose usage passes its
// limit. It returns true when a cgroup uses at least half of its limit.
func (fs *filesystem) checkMemoryLimits(ctx context.Context, k *kernel.Kernel, limited []*memory) bool {
	subtrees := make([]map[uint32]struct{}, len(limited))
	all := make(map[uint32]struct{})
	fs.treeMu.RLock()
	for i, m := range limited {
		subtrees[i] = make(map[uint32]struct{})
		collectMemCgIDs(m.c, subtrees[i]) // +checklocksforce: m.c.fs is fs
		collectMemCgIDs(m.c, all)         // +checklocksforce: m.c.fs is fs
	}
	fs.treeMu.RUnlock()

	// One scan covers every limited subtree.
	_ = k.MemoryFile().UpdateUsage(all)
	near := false
	// Linux charges a page from the cgroup of the task upward and fails at
	// the first cgroup over its limit. limited lists a parent before its
	// children, so the loop runs backward and checks a child first. A process
	// that a check of this pass killed frees its memory for the checks of
	// its ancestors too.
	killed := make(map[*kernel.ThreadGroup]struct{})
	for i := len(limited) - 1; i >= 0; i-- {
		m := limited[i]
		used := unreclaimableUsage(sumUsageStats(k, subtrees[i]))
		limit := uint64(m.maxBytes.Load())
		near = near || used >= limit/2
		m.oomCheck(ctx, k, used, limit, killed)
	}
	return near
}

// oomCandidate is a process that the OOM killer can end.
type oomCandidate struct {
	group *kernel.ThreadGroup
	// id is the ID of the process in the root PID namespace. It orders
	// candidates of equal score.
	id kernel.ThreadID
	// rss is the resident set size of the process in bytes.
	rss uint64
	// adj is the oom_score_adj of the process.
	adj int32
	// mem is the memory controller of the cgroup of the process. The kill
	// counts in its memory.events, as Linux counts it in the cgroup of the
	// victim.
	mem *memory
	// The fields below only feed the lines that the kill writes to the kernel
	// log.

	// comm is the name of the process.
	comm string
	// uid is the real user ID of the process in the root user namespace.
	uid uint32
	// vm is the size of the address space of the process in bytes.
	vm uint64
	// cgroup is the path of the cgroup of the process.
	cgroup string
}

// oomVictims returns the candidates that the OOM killer ends. With group set
// it returns all of them. Otherwise it returns the candidate with the highest
// score. The score is the resident set plus oom_score_adj per mille of limit,
// as in Linux. Equal scores go to the lower ID.
func oomVictims(candidates []oomCandidate, group bool, limit uint64) []oomCandidate {
	sorted := slices.Clone(candidates)
	slices.SortFunc(sorted, func(a, b oomCandidate) int { return int(int64(a.id) - int64(b.id)) })
	if group || len(sorted) <= 1 {
		return sorted
	}
	score := func(c oomCandidate) int64 { return int64(c.rss) + int64(c.adj)*int64(limit)/1000 }
	largest := sorted[0]
	for _, c := range sorted[1:] {
		if score(c) > score(largest) {
			largest = c
		}
	}
	return []oomCandidate{largest}
}

// oomCheck compares one controller with its limit and ends processes of the
// subtree as the OOM killer of Linux does for a cgroup that passed memory.max.
// It never ends the init process of the guest or a process with
// oom_score_adj of -1000. killed holds the processes that the checks of the
// current pass ended. A subtree with such a process waits for the next pass.
func (m *memory) oomCheck(ctx context.Context, k *kernel.Kernel, used, limit uint64, killed map[*kernel.ThreadGroup]struct{}) {
	over := used > limit
	if !over {
		m.oom.pending = nil
		m.oom.gate.shouldKill(false, 0)
		return
	}
	fs := m.c.fs
	type taskInCgroup struct {
		t   *kernel.Task
		mem *memory
		cg  *cgroup
	}
	var tasks []taskInCgroup
	closestMemory := func(c *cgroup) *memory {
		if mem, ok := c.closestCtrls.Load()[kernel.Cgroup2Memory].(*memory); ok {
			return mem
		}
		return m
	}
	fs.treeMu.RLock()
	fs.tasksMu.RLock()
	for t := range m.c.tasks {
		tasks = append(tasks, taskInCgroup{t, m, m.c})
	}
	m.c.walkSubtreeLocked(func(c *cgroup) bool {
		mem := closestMemory(c)
		for t := range c.tasks { // +checklocksforce: fs.tasksMu is locked
			tasks = append(tasks, taskInCgroup{t, mem, c})
		}
		return true
	})
	fs.tasksMu.RUnlock()
	fs.treeMu.RUnlock()

	rootNS := k.RootPIDNamespace()
	candidates := make(map[*kernel.ThreadGroup]*oomCandidate)
	present := make(map[*kernel.ThreadGroup]struct{})
	for _, tc := range tasks {
		t := tc.t
		tg := t.ThreadGroup()
		present[tg] = struct{}{}
		if t.ExitState() != kernel.TaskExitNone || tg.IsInitIn(rootNS) {
			continue
		}
		c, ok := candidates[tg]
		if !ok {
			c = &oomCandidate{group: tg, id: rootNS.IDOfThreadGroup(tg), mem: tc.mem, cgroup: tc.cg.Path()}
			if leader := tg.Leader(); leader != nil {
				c.adj = leader.OOMScoreAdj()
				c.comm = leader.Name()
				c.uid = uint32(leader.Credentials().RealKUID)
			}
			candidates[tg] = c
		}
		if mm := t.MemoryManager(); mm != nil {
			c.rss = max(c.rss, mm.ResidentSetSize())
			c.vm = max(c.vm, mm.VirtualMemorySize())
		}
	}
	for tg := range m.oom.pending {
		if _, ok := present[tg]; !ok {
			delete(m.oom.pending, tg)
		}
	}
	for tg := range candidates {
		if _, ok := killed[tg]; ok {
			return
		}
	}
	if !m.oom.gate.shouldKill(true, len(m.oom.pending)) {
		return
	}
	var eligible []oomCandidate
	for _, c := range candidates {
		if c.adj > oomImmune {
			eligible = append(eligible, *c)
		}
	}
	// Linux records the OOM event in the cgroup that passed its limit before
	// it kills. The event counts also when no process can be killed.
	m.countOOMEvent(ctx)
	victims := oomVictims(eligible, m.oomGroup.Load(), limit)
	if len(victims) == 0 {
		return
	}
	// As mem_cgroup_get_oom_group does, the highest cgroup with
	// memory.oom.group between the victim and m loses all its processes. The
	// kubelet sets memory.oom.group in each container cgroup.
	selected := victims[0]
	groupMem := oomGroupOf(selected.mem, m)
	if groupMem != nil {
		victims = oomGroupMembers(eligible, groupMem)
	}
	klog := k.KernelLog()
	logOOMContext(klog, m.c.Path(), selected)
	if m.oom.pending == nil {
		m.oom.pending = make(map[*kernel.ThreadGroup]struct{})
	}
	sent := false
	for _, v := range orderVictims(victims, selected) {
		// Each kill counts in the cgroup of the victim and its ancestors
		// before the signal, as in __oom_kill_process. The OOM monitor of
		// containerd reads the cgroup of the container, which can lie below
		// the cgroup that passed its limit.
		logOOMKill(klog, v)
		if v.group == selected.group && groupMem != nil {
			logOOMGroup(klog, groupMem.c.Path())
		}
		v.mem.countOOMKill(ctx)
		if err := k.SendExternalSignalThreadGroup(v.group, &linux.SignalInfo{Signo: int32(linux.SIGKILL)}); err != nil {
			continue
		}
		m.oom.pending[v.group] = struct{}{}
		killed[v.group] = struct{}{}
		sent = true
	}
	if groupMem != nil && sent {
		groupMem.countOOMGroupKill(ctx)
	}
}

// oomGroupOf returns the highest memory controller with memory.oom.group set
// on the path from mem up to top, or nil.
func oomGroupOf(mem, top *memory) *memory {
	var group *memory
	for cur := mem; cur != nil; cur = cur.parent {
		if cur.oomGroup.Load() {
			group = cur
		}
		if cur == top {
			break
		}
	}
	return group
}

// oomGroupMembers returns the candidates in the subtree of group.
func oomGroupMembers(candidates []oomCandidate, group *memory) []oomCandidate {
	var members []oomCandidate
	for _, c := range candidates {
		for cur := c.mem; cur != nil; cur = cur.parent {
			if cur == group {
				members = append(members, c)
				break
			}
		}
	}
	return members
}

// countOOMEvent records one OOM event in oom and max of m and of each ancestor
// memory controller, and wakes the readers of memory.events.
func (m *memory) countOOMEvent(ctx context.Context) {
	for cur := m; cur != nil; cur = cur.parent {
		cur.oom.hitMax.Add(1)
		cur.oom.oom.Add(1)
		cur.notifyEvents(ctx)
	}
}

// countOOMKill records one killed process in oom_kill of m and of each
// ancestor memory controller, and wakes the readers of memory.events.
func (m *memory) countOOMKill(ctx context.Context) {
	for cur := m; cur != nil; cur = cur.parent {
		cur.oom.oomKill.Add(1)
		cur.notifyEvents(ctx)
	}
}

// countOOMGroupKill records one kill of a whole group in oom_group_kill of m
// and of each ancestor memory controller.
func (m *memory) countOOMGroupKill(ctx context.Context) {
	for cur := m; cur != nil; cur = cur.parent {
		cur.oom.oomGroupKill.Add(1)
		cur.notifyEvents(ctx)
	}
}

func (m *memory) notifyEvents(ctx context.Context) {
	if m.oom.eventsFile != nil {
		m.oom.eventsFile.Notify(ctx)
	}
}
