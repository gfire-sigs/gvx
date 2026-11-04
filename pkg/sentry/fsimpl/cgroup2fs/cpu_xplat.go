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
	"math"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// This file enforces cpu.max and reports the throttle counters of cpu.stat. The
// budget and the throttle of tasks live in kernel.CPUBandwidth. Here each cpu
// controller owns one budget, and the budget of a child points to the budget of
// the parent controller.

// The limits of cpu.max that Linux accepts (kernel/sched/core.c,
// tg_set_cfs_bandwidth).
const (
	minCPUPeriodUSec = 1000
	maxCPUPeriodUSec = 1000000
	minCPUQuotaUSec  = 1000
	maxCPUQuotaUSec  = 1<<44 - 1
)

// cpuMaxUnlimited is the stored quota of the value "max".
const cpuMaxUnlimited = math.MaxInt64

// validateCPUMax returns EINVAL when Linux rejects the quota or the period of a
// write to cpu.max. Both values are in microseconds.
func validateCPUMax(quotaUSec, periodUSec int64) error {
	if periodUSec < minCPUPeriodUSec || periodUSec > maxCPUPeriodUSec {
		return linuxerr.EINVAL
	}
	if quotaUSec != cpuMaxUnlimited && (quotaUSec < minCPUQuotaUSec || quotaUSec > maxCPUQuotaUSec) {
		return linuxerr.EINVAL
	}
	return nil
}

// bandwidthLimits converts the values of cpu.max to the arguments of
// kernel.CPUBandwidth.SetLimits. A quota of "max" becomes a negative quota.
func bandwidthLimits(quotaUSec, periodUSec int64) (quota, period time.Duration) {
	period = time.Duration(periodUSec) * time.Microsecond
	if quotaUSec == cpuMaxUnlimited {
		return -1, period
	}
	return time.Duration(quotaUSec) * time.Microsecond, period
}

// cpuBandwidth is the CPU budget state of one cpu controller.
type cpuBandwidth struct {
	// node is the budget. The first use creates it. Reads need no lock.
	node atomic.Pointer[kernel.CPUBandwidth]

	// mu protects the creation of node and the writes of cpu.max.
	mu sync.Mutex
}

// bandwidthNode returns the budget of cc.
func (cc *cpu) bandwidthNode() *kernel.CPUBandwidth {
	if node := cc.bandwidth.node.Load(); node != nil {
		return node
	}
	cc.bandwidth.mu.Lock()
	defer cc.bandwidth.mu.Unlock()
	return cc.bandwidthNodeLocked()
}

// bandwidthNodeLocked creates the budget on first use. The new budget takes
// the limits that cc already stores.
//
// Preconditions: cc.bandwidth.mu is locked.
func (cc *cpu) bandwidthNodeLocked() *kernel.CPUBandwidth {
	if node := cc.bandwidth.node.Load(); node != nil {
		return node
	}
	var parent *kernel.CPUBandwidth
	if cc.parent != nil {
		parent = cc.parent.bandwidthNode()
	}
	node := kernel.NewCPUBandwidth(parent)
	if quotaUSec := cc.maxUSec.Load(); quotaUSec != cpuMaxUnlimited && cc.isActive() {
		node.SetLimits(bandwidthLimits(quotaUSec, cc.periodUSec.Load()))
	}
	cc.bandwidth.node.Store(node)
	return node
}

// setMax stores a new value of cpu.max and applies it to the budget. Both
// values are in microseconds, and a quota of cpuMaxUnlimited removes the limit.
func (cc *cpu) setMax(quotaUSec, periodUSec int64) error {
	if err := validateCPUMax(quotaUSec, periodUSec); err != nil {
		return err
	}
	cc.bandwidth.mu.Lock()
	defer cc.bandwidth.mu.Unlock()
	cc.maxUSec.Store(quotaUSec)
	cc.periodUSec.Store(periodUSec)
	if !cc.isActive() || cc.c.deleted.Load() {
		// A removed controller has no tasks. A new limit would only make the
		// Sentry account CPU time for a budget that nothing reads.
		return nil
	}
	cc.bandwidthNodeLocked().SetLimits(bandwidthLimits(quotaUSec, periodUSec))
	return nil
}

// releaseBandwidth removes the limit of a controller that leaves the tree, and
// it frees the tasks that the limit holds back.
func (cc *cpu) releaseBandwidth() {
	cc.bandwidth.mu.Lock()
	defer cc.bandwidth.mu.Unlock()
	if node := cc.bandwidth.node.Load(); node != nil {
		node.SetLimits(bandwidthLimits(cpuMaxUnlimited, cc.periodUSec.Load()))
	}
}

// CPUBandwidth implements kernel.CPUBandwidthProvider. It returns the budget of
// the nearest controller at or above c.
func (c *cgroup) CPUBandwidth() *kernel.CPUBandwidth {
	cc, ok := c.closestCtrls.Load()[kernel.Cgroup2CPU].(*cpu)
	if !ok {
		return nil
	}
	return cc.bandwidthNode()
}

// releaseCPUBandwidth removes the CPU limit of a cgroup that the user removes.
// It also adds the CPU time that the cgroup counted to the nearest cpu controller
// above it, as Linux does: the usage of a parent includes the usage of the
// cgroups that it had.
//
// +checklocksread:c.fs.treeMu
func (c *cgroup) releaseCPUBandwidth() {
	cc, ok := c.ctrls[kernel.Cgroup2CPU].(*cpu) // +checklocksforce: caller holds the tree lock
	if !ok {
		return
	}
	cc.releaseBandwidth()
	if c.parent == nil {
		return
	}
	newCPU, ok := c.parent.closestCtrls.Load()[kernel.Cgroup2CPU].(*cpu)
	if !ok {
		return
	}
	cc.mu.Lock()
	removed := cc.usage
	cc.usage = usage.CPUStats{}
	cc.mu.Unlock()
	newCPU.mu.Lock()
	newCPU.usage.Accumulate(removed)
	newCPU.mu.Unlock()
}

// taskCPUStats returns the CPU time of t for the accounting of cpu.stat. The
// total is the wall time that the task goroutine ran. The CPU clocks of the task
// count whole ticks of sampled tasks, so a thread that runs little can read
// a full tick, and a Go program with an idle second thread reads above one CPU.
// The Sentry cannot measure the split between user and system time exactly, so
// the system time is the tick count of the clocks, capped at the total.
func taskCPUStats(t *kernel.Task) usage.CPUStats {
	s := t.CPUStats()
	total := t.CPUTimeMeasured()
	sys := min(s.SysTime, total)
	s.SysTime = sys
	s.UserTime = total - sys
	return s
}

// cpuStatUSec returns the usage, user, and system time of cpu.stat in
// microseconds. The split of a sum over tasks can drift by a tick, so each part
// stays above 0 and the usage stays the sum of the measured times.
func cpuStatUSec(cs usage.CPUStats) (usageUSec, userUSec, sysUSec int64) {
	usageUSec = (cs.UserTime + cs.SysTime).Microseconds()
	sysUSec = min(max(cs.SysTime.Microseconds(), 0), usageUSec)
	return usageUSec, usageUSec - sysUSec, sysUSec
}

// wakeMigratedTask makes a task that left a throttled cgroup read the budget of
// its new cgroup now. Without it the task waits for the end of the old period.
func wakeMigratedTask(t *kernel.Task, oldCPU *cpu) {
	if oldCPU != nil && oldCPU.bandwidthNode().Throttled() {
		t.WakeCPUBandwidth()
	}
}
