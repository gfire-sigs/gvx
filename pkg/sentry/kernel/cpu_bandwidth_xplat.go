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

package kernel

import (
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/sync"
)

// This file holds the budget of the CPU bandwidth control of cgroup v2
// (cpu.max). It follows the CFS bandwidth model of Linux: a node has a quota
// of CPU time for each period. The tasks of the node, and of its descendants,
// use the quota together on all CPUs. A node whose quota is spent throttles
// its tasks until the next period starts. A child node obeys the quota of
// every ancestor.
//
// A node reads time and arms timers only through a bandwidthClock, so the
// budget logic runs in tests without a Kernel and without real time.

var (
	// cpuBandwidthLimited counts the nodes with a finite quota. While it is
	// zero, the CPU clock ticker skips the accounting of CPU bandwidth.
	cpuBandwidthLimited atomic.Int32

	// cpuBandwidthThrottled counts the nodes that throttle their tasks now.
	// While it is zero, the task run loop skips the throttle check, so a
	// Sentry without a spent quota pays one load for each return to the
	// application.
	cpuBandwidthThrottled atomic.Int32
)

// bandwidthClock is the source of time and of timers for a CPUBandwidth.
type bandwidthClock struct {
	// now returns a monotonic time in nanoseconds.
	now func() int64

	// after calls f once after d. The returned function stops the call.
	after func(d time.Duration, f func()) (stop func())
}

// newHostBandwidthClock returns a clock on the host monotonic time.
func newHostBandwidthClock() bandwidthClock {
	epoch := time.Now()
	return bandwidthClock{
		now: func() int64 { return time.Since(epoch).Nanoseconds() },
		after: func(d time.Duration, f func()) func() {
			timer := time.AfterFunc(d, f)
			return func() { timer.Stop() }
		},
	}
}

// hostBandwidthClock is the shared clock of the nodes that the Sentry creates.
var hostBandwidthClock = newHostBandwidthClock()

// CPUBandwidth is the CPU budget of one cgroup. Each cgroup that has the cpu
// controller owns one node, and the node of a child points to the node of the
// nearest ancestor with the controller.
type CPUBandwidth struct {
	// parent is the node of the nearest ancestor. It is nil at the root.
	parent *CPUBandwidth

	clock bandwidthClock

	// quotaNS is the CPU time for each period in nanoseconds. A negative
	// value means no limit. Writers hold mu. Readers use the atomic.
	quotaNS atomic.Int64

	// throttled is true while the node holds its tasks back. Writers hold mu.
	throttled atomic.Bool

	mu sync.Mutex

	// periodNS is the length of one period.
	periodNS int64

	// periodEnd is the time at which the next period starts.
	periodEnd int64

	// remainingNS is the CPU time left in the current period. It goes
	// negative when tasks run past the quota. The next period repays that debt.
	remainingNS int64

	// charged is true when the node took a charge since the last refill.
	charged bool

	// throttleStart is the time at which the current throttle began.
	throttleStart int64

	// stopRefill cancels the refill timer of the current throttle.
	stopRefill func()

	// wake closes when a throttle ends, and then a new channel replaces it.
	wake chan struct{}

	nrPeriods   uint64
	nrThrottled uint64
	throttledNS int64
}

// CPUBandwidthStats are the counters that cpu.stat reports.
type CPUBandwidthStats struct {
	// Periods counts the periods in which the node took a charge.
	Periods uint64

	// Throttled counts the throttles of the node.
	Throttled uint64

	// ThrottledTime is the total time that the node held its tasks back.
	ThrottledTime time.Duration
}

// NewCPUBandwidth returns a node without a limit. The parent is the node of the
// nearest ancestor, or nil at the root.
func NewCPUBandwidth(parent *CPUBandwidth) *CPUBandwidth {
	return newCPUBandwidth(parent, hostBandwidthClock)
}

func newCPUBandwidth(parent *CPUBandwidth, clock bandwidthClock) *CPUBandwidth {
	b := &CPUBandwidth{parent: parent, clock: clock, wake: make(chan struct{})}
	b.quotaNS.Store(-1)
	return b
}

// SetLimits sets the quota and the period of the node. A negative quota
// removes the limit. As in Linux, a new limit starts a fresh period with a
// full quota and ends a throttle at once.
func (b *CPUBandwidth) SetLimits(quota, period time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.clock.now()
	quotaNS := quota.Nanoseconds()
	wasLimited := b.quotaNS.Load() >= 0
	if quotaNS < 0 {
		quotaNS = -1
	}
	b.periodNS = period.Nanoseconds()
	b.quotaNS.Store(quotaNS)
	b.remainingNS = max(quotaNS, 0)
	b.periodEnd = now + b.periodNS
	b.charged = false
	switch isLimited := quotaNS >= 0; {
	case isLimited && !wasLimited:
		cpuBandwidthLimited.Add(1)
	case !isLimited && wasLimited:
		cpuBandwidthLimited.Add(-1)
	}
	if b.throttled.Load() {
		b.endThrottleLocked(now)
	}
}

// Stats returns the counters of the node. A throttle in progress counts as
// throttled time up to now.
func (b *CPUBandwidth) Stats() CPUBandwidthStats {
	b.mu.Lock()
	defer b.mu.Unlock()
	throttledNS := b.throttledNS
	if b.throttled.Load() {
		throttledNS += b.clock.now() - b.throttleStart
	}
	return CPUBandwidthStats{
		Periods:       b.nrPeriods,
		Throttled:     b.nrThrottled,
		ThrottledTime: time.Duration(throttledNS),
	}
}

// charge takes ns nanoseconds of CPU time from the node and from every
// ancestor with a limit. A node that runs out of quota starts to throttle.
func (b *CPUBandwidth) charge(ns int64) {
	for n := b; n != nil; n = n.parent {
		if n.quotaNS.Load() >= 0 {
			n.chargeOne(ns)
		}
	}
}

func (b *CPUBandwidth) chargeOne(ns int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.quotaNS.Load() < 0 {
		return
	}
	now := b.clock.now()
	b.refillLocked(now)
	b.charged = true
	b.remainingNS -= ns
	if b.remainingNS <= 0 && !b.throttled.Load() {
		b.throttled.Store(true)
		b.throttleStart = now
		b.nrThrottled++
		cpuBandwidthThrottled.Add(1)
		b.armRefillLocked(now)
	}
}

// Throttled returns true if the node or an ancestor holds its tasks back.
func (b *CPUBandwidth) Throttled() bool {
	for n := b; n != nil; n = n.parent {
		if n.throttled.Load() {
			return true
		}
	}
	return false
}

// throttleWake returns the channel that closes when the first throttled node
// of the chain releases its tasks. It returns nil if no node throttles.
func (b *CPUBandwidth) throttleWake() chan struct{} {
	for n := b; n != nil; n = n.parent {
		if !n.throttled.Load() {
			continue
		}
		n.mu.Lock()
		wake := n.wake
		throttled := n.throttled.Load()
		n.mu.Unlock()
		if throttled {
			return wake
		}
	}
	return nil
}

// armRefillLocked starts the timer that begins the next period. The timer
// runs while the node throttles, so a node whose tasks all sleep or exited
// still leaves the throttle.
//
// Preconditions: b.mu is locked and b throttles.
func (b *CPUBandwidth) armRefillLocked(now int64) {
	b.stopRefill = b.clock.after(time.Duration(max(b.periodEnd-now, 0)), b.refillTimer)
}

// refillTimer is the callback of the refill timer.
func (b *CPUBandwidth) refillTimer() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.throttled.Load() {
		return
	}
	now := b.clock.now()
	b.refillLocked(now)
	if b.throttled.Load() {
		b.armRefillLocked(now)
	}
}

// refillLocked starts the next period when the current one ended. The
// quota of the new period is the full quota less any debt of the last period.
// After an idle gap of more than one period, the debt is zero and the new
// period starts now.
//
// Preconditions: b.mu is locked and b has a limit.
func (b *CPUBandwidth) refillLocked(now int64) {
	if now < b.periodEnd {
		return
	}
	quotaNS := b.quotaNS.Load()
	elapsed := (now-b.periodEnd)/b.periodNS + 1
	active := b.charged || b.throttled.Load()
	if active {
		b.nrPeriods++
	}
	if active && elapsed == 1 {
		b.periodEnd += b.periodNS
	} else {
		b.periodEnd = now + b.periodNS
	}
	if b.remainingNS > 0 || elapsed > 1 {
		b.remainingNS = quotaNS
	} else {
		b.remainingNS = min(b.remainingNS+quotaNS, quotaNS)
	}
	b.charged = false
	if b.throttled.Load() && b.remainingNS > 0 {
		b.endThrottleLocked(now)
	}
}

// endThrottleLocked releases the tasks of a throttled node and wakes them.
//
// Preconditions: b.mu is locked and b throttles.
func (b *CPUBandwidth) endThrottleLocked(now int64) {
	b.throttled.Store(false)
	b.throttledNS += now - b.throttleStart
	cpuBandwidthThrottled.Add(-1)
	if b.stopRefill != nil {
		b.stopRefill()
		b.stopRefill = nil
	}
	close(b.wake)
	b.wake = make(chan struct{})
}
