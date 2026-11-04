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
	"math"
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

	// cpuBillingGeneration changes each time the first finite quota appears.
	// A task that last ran under an older generation starts a new account, so
	// the time before the first quota is never charged.
	cpuBillingGeneration atomic.Int32
)

// bandwidthSlackNS is the debt that a node tolerates before it throttles. The
// CPU clock ticker charges each task once for each tick, and the threads of a
// program together can run a little more than one CPU. A debt carries into the
// next period, so the slack does not change the average.
const bandwidthSlackNS = 10 * int64(time.Millisecond)

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
	// Periods counts the periods that ended while the node was active, as
	// nr_periods does in Linux. A node is active from its first charge until
	// one period without a charge.
	Periods uint64

	// Throttled counts the periods that ended while the node throttled, as
	// nr_throttled does in Linux.
	Throttled uint64

	// ThrottledTime is the time in which the node held its tasks back. It is
	// one wall-clock interval for the whole node. Linux sums the time of every
	// CPU run queue of the cgroup, so it reports more on a cgroup with tasks on
	// several CPUs.
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
		if cpuBandwidthLimited.Add(1) == 1 {
			cpuBillingGeneration.Add(1)
		}
	case !isLimited && wasLimited:
		cpuBandwidthLimited.Add(-1)
	}
	if b.throttled.Load() {
		b.endThrottleLocked(now)
	}
}

// Parent returns the node of the nearest ancestor, or nil at the root.
func (b *CPUBandwidth) Parent() *CPUBandwidth { return b.parent }

// Limit returns the quota and the period of the node. Limited is false when the
// node has no quota.
func (b *CPUBandwidth) Limit() (quota, period time.Duration, limited bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	q := b.quotaNS.Load()
	return time.Duration(q), time.Duration(b.periodNS), q >= 0
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

// bandwidthMaxCoveredPeriods bounds the periods that one charge can cover. A
// run that started earlier counts only for these periods.
const bandwidthMaxCoveredPeriods = 1024

// charge takes ns nanoseconds of CPU time from the node and from every
// ancestor with a limit. The time ran in the interval that ends at end. A node
// that runs out of quota starts to throttle.
func (b *CPUBandwidth) charge(end, ns int64) {
	for n := b; n != nil; n = n.parent {
		if n.limited() {
			n.chargeRuns(end, []int64{ns})
		}
	}
}

// limited returns true if the node has a finite quota.
func (b *CPUBandwidth) limited() bool { return b.quotaNS.Load() >= 0 }

// bandwidthRun is the CPU time of one task that a node takes at one tick.
type bandwidthRun struct {
	node *CPUBandwidth
	ns   int64
}

// chargeBandwidthRuns takes the CPU time of the runs from their nodes. Each run
// is the time that one task ran in the interval that ends at end. The function
// takes all runs of one node together, so that the runs of many tasks that a
// stall delayed count for the same periods. It reorders runs.
func chargeBandwidthRuns(end int64, runs []bandwidthRun) {
	for len(runs) > 0 {
		node := runs[0].node
		var buf [16]int64
		nss := buf[:0]
		rest := runs[:0]
		for _, r := range runs {
			if r.node == node {
				nss = append(nss, r.ns)
			} else {
				rest = append(rest, r)
			}
		}
		node.chargeRuns(end, nss)
		runs = rest
	}
}

// chargeRuns takes the CPU time of the runs from the node. Each run is the time
// that one task ran without a pause in the interval that ends at end. A charge
// that comes late covers many periods. The node takes the part of each run that
// lies in each period, and it refills the quota between the periods, as if the
// charge had come on time in small parts. A debt only comes from a period in
// which the tasks used more than its quota. A node that runs out of quota starts
// to throttle.
func (b *CPUBandwidth) chargeRuns(end int64, runs []int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.quotaNS.Load() < 0 || b.periodNS <= 0 {
		return
	}
	now := end
	maxRun := bandwidthMaxCoveredPeriods * b.periodNS
	// firstStart is the start of the earliest run.
	firstStart := now
	for _, ns := range runs {
		if ns > 0 {
			firstStart = min(firstStart, now-min(ns, maxRun))
		}
	}
	// inRange returns the time of the runs that lies in [from, to).
	inRange := func(from, to int64) (used int64) {
		for _, ns := range runs {
			if start := now - min(ns, maxRun); ns > 0 && start < to {
				used += to - max(start, from)
			}
		}
		return used
	}
	// The first period takes the time of a run that started before it, because
	// no earlier period has seen that time.
	from := int64(math.MinInt64)
	for now >= b.periodEnd {
		if firstStart >= b.periodEnd {
			// No run reaches this period. Skip every period that ends before
			// the first run starts.
			b.advancePeriodsLocked((firstStart-b.periodEnd)/b.periodNS+1, now)
			continue
		}
		b.remainingNS -= inRange(from, b.periodEnd)
		b.charged = true
		from = b.periodEnd
		b.advancePeriodsLocked(1, now)
	}
	if used := inRange(from, now); used > 0 {
		b.charged = true
		b.remainingNS -= used
	}
	if b.remainingNS < -bandwidthSlackNS && !b.throttled.Load() {
		b.throttled.Store(true)
		b.throttleStart = now
		cpuBandwidthThrottled.Add(1)
		b.armRefillLocked(b.clock.now())
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

// refillLocked starts the next period when the current one ended. A timer calls
// it, so it can find many periods that ended. The periods follow each other on
// the grid of the first period.
//
// Preconditions: b.mu is locked and b has a limit.
func (b *CPUBandwidth) refillLocked(now int64) {
	if now < b.periodEnd {
		return
	}
	b.advancePeriodsLocked((now-b.periodEnd)/b.periodNS+1, now)
}

// advancePeriodsLocked ends the next n periods and starts the one after them.
// The quota of the new period is the full quota less any debt. Each period that
// ended repays one quota of the debt, as a refill on time does.
//
// Preconditions: b.mu is locked, b has a limit, and n is at least 1.
func (b *CPUBandwidth) advancePeriodsLocked(n, now int64) {
	quotaNS := b.quotaNS.Load()
	active := b.charged || b.throttled.Load()
	if b.throttled.Load() {
		// Every period that ended in the gap ended while throttled.
		b.nrPeriods += uint64(n)
		b.nrThrottled += uint64(n)
	} else if active {
		// A node that went idle stops counting after one more period.
		b.nrPeriods += uint64(min(n, 2))
	}
	b.periodEnd += n * b.periodNS
	if b.remainingNS >= 0 || quotaNS <= 0 || n >= (quotaNS-b.remainingNS+quotaNS-1)/quotaNS {
		b.remainingNS = quotaNS
	} else {
		b.remainingNS += n * quotaNS
	}
	b.charged = false
	if b.throttled.Load() && b.remainingNS >= -bandwidthSlackNS {
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
