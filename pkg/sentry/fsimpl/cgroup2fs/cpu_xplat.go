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
//
// +checklocksread:c.fs.treeMu
func (c *cgroup) releaseCPUBandwidth() {
	if cc, ok := c.ctrls[kernel.Cgroup2CPU].(*cpu); ok { // +checklocksforce: caller holds the tree lock
		cc.releaseBandwidth()
	}
}
