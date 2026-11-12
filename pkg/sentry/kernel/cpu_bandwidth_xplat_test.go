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
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"
	"weak"
)

const (
	ms     = int64(time.Millisecond)
	period = 100 * time.Millisecond
)

// fakeBandwidthClock is a clock that tests advance by hand. A timer fires when
// advance moves the time to or past its deadline.
type fakeBandwidthClock struct {
	now    int64
	timers []*fakeTimer
}

type fakeTimer struct {
	at      int64
	f       func()
	stopped bool
}

func (c *fakeBandwidthClock) clock() bandwidthClock {
	return bandwidthClock{
		now: func() int64 { return c.now },
		after: func(d time.Duration, f func()) func() {
			t := &fakeTimer{at: c.now + d.Nanoseconds(), f: f}
			c.timers = append(c.timers, t)
			return func() { t.stopped = true }
		},
	}
}

// advance moves the time by d and runs the timers that came due, in order.
// A timer callback runs without a held lock, as the real timer goroutine does.
func (c *fakeBandwidthClock) advance(d time.Duration) {
	target := c.now + d.Nanoseconds()
	for {
		var next *fakeTimer
		for _, t := range c.timers {
			if !t.stopped && t.at <= target && (next == nil || t.at < next.at) {
				next = t
			}
		}
		if next == nil {
			break
		}
		c.now = max(c.now, next.at)
		next.stopped = true
		next.f()
	}
	c.now = target
	c.timers = slices.DeleteFunc(c.timers, func(t *fakeTimer) bool { return t.stopped })
}

var testKernels sync.Map

// testKernel returns the Kernel of a test. Each test owns one Kernel, so the
// bandwidth counters of two tests never meet. The Kernel has no tasks.
func testKernel(t *testing.T) *Kernel {
	t.Helper()
	k, _ := testKernels.LoadOrStore(t, &Kernel{})
	t.Cleanup(func() { testKernels.Delete(t) })
	return k.(*Kernel)
}

// newTestBandwidth returns a node with a quota of 50 ms for each period of
// 100 ms, and it removes the limit at the end of the test so that the global
// counters return to their old values.
func newTestBandwidth(t *testing.T, c *fakeBandwidthClock, parent *CPUBandwidth, quota time.Duration) *CPUBandwidth {
	t.Helper()
	b := newCPUBandwidth(parent, c.clock())
	k := testKernel(t)
	b.SetLimits(k, quota, period)
	t.Cleanup(func() { b.SetLimits(k, -1, period) })
	return b
}

// ran charges the node with a task that ran ns nanoseconds without a pause up to
// now. It uses the path of the CPU clock ticker, including the ancestors.
func ran(c *fakeBandwidthClock, node *CPUBandwidth, ns int64) {
	chargeBandwidthRuns(c.now, appendBandwidthRuns(nil, node, c.now-ns, ns))
}

// ranWithPauses charges the node with a task that ran ns nanoseconds in the
// interval that starts at from and ends now. The task paused in that interval.
func ranWithPauses(c *fakeBandwidthClock, node *CPUBandwidth, from, ns int64) {
	chargeBandwidthRuns(c.now, appendBandwidthRuns(nil, node, from, ns))
}

func TestCPUBandwidthThrottlesWhenQuotaIsSpent(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	ran(&clock, b, 40*ms)
	if b.Throttled() {
		t.Fatal("throttled after 40 ms of a 50 ms quota")
	}
	ran(&clock, b, 10*ms)
	if b.Throttled() {
		t.Fatal("throttled at the quota, inside the slack of one tick")
	}
	ran(&clock, b, 11*ms)
	if !b.Throttled() {
		t.Fatal("not throttled after 56 ms of a 50 ms quota")
	}
	if got := b.Stats().Throttled; got != 0 {
		t.Errorf("Throttled = %d before the period end, want 0", got)
	}
	clock.advance(100 * time.Millisecond)
	if got := b.Stats().Throttled; got != 1 {
		t.Errorf("Throttled = %d after the period end, want 1", got)
	}
}

func TestCPUBandwidthRefillEndsThrottleAtPeriodEnd(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	ran(&clock, b, 61*ms)
	wake := b.throttleWake()
	if wake == nil {
		t.Fatal("throttleWake returned nil for a throttled node")
	}

	clock.advance(99 * time.Millisecond)
	if !b.Throttled() {
		t.Fatal("released 1 ms before the period end")
	}
	select {
	case <-wake:
		t.Fatal("waiters woke before the period end")
	default:
	}

	clock.advance(1 * time.Millisecond)
	if b.Throttled() {
		t.Fatal("still throttled at the period end")
	}
	select {
	case <-wake:
	default:
		t.Fatal("waiters did not wake at the period end")
	}
	stats := b.Stats()
	if stats.ThrottledTime != 100*time.Millisecond || stats.Periods != 1 {
		t.Errorf("Stats = %+v, want 100 ms throttled over 1 period", stats)
	}

	// The new period holds 39 ms: 50 ms of quota less the 11 ms debt.
	ran(&clock, b, 50*ms)
	if !b.Throttled() {
		t.Error("the new period did not take the debt of the old one")
	}
	clock.advance(100 * time.Millisecond)
	if got := b.Stats().Throttled; got != 2 {
		t.Errorf("Throttled = %d, want 2", got)
	}
}

func TestCPUBandwidthDebtCarriesIntoNextPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	// Tasks on several CPUs charge 120 ms: 70 ms more than the quota.
	ran(&clock, b, 120*ms)
	clock.advance(100 * time.Millisecond)
	if !b.Throttled() {
		t.Fatal("released after one period with a debt of 70 ms and a quota of 50 ms")
	}
	clock.advance(100 * time.Millisecond)
	if b.Throttled() {
		t.Fatal("still throttled after the second period repaid the debt")
	}

	// The first period repaid 50 ms of the debt and the second period repaid
	// the last 20 ms. It left 30 ms of its quota.
	ran(&clock, b, 30*ms)
	if b.Throttled() {
		t.Fatal("throttled before the debt-adjusted quota was spent")
	}
	ran(&clock, b, 11*ms)
	if !b.Throttled() {
		t.Fatal("not throttled after the debt-adjusted quota was spent")
	}
}

func TestCPUBandwidthIdleNodeStartsFreshPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	ran(&clock, b, 30*ms)
	clock.advance(10*time.Second + 50*time.Millisecond)

	ran(&clock, b, 40*ms)
	if b.Throttled() {
		t.Fatal("throttled although the idle time restored the full quota")
	}
	if got := b.Stats().Periods; got != 2 {
		t.Errorf("Periods = %d, want 2: the period with the charge and one idle period", got)
	}
	// The 40 ms ran inside the period that began at 10.0 s, so 10 ms are left.
	ran(&clock, b, 10*ms)
	if b.Throttled() {
		t.Fatal("throttled before the quota of the new period was spent")
	}
	ran(&clock, b, 11*ms)
	if !b.Throttled() {
		t.Error("not throttled after 61 ms of charges in one period")
	}
}

func TestCPUBandwidthLateChargeOverManyPeriodsDoesNotThrottle(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 110*time.Millisecond)

	// A stall of the ticker holds back all charges for one second. Then it
	// bills the 1000 ms that one thread ran. Ten periods ended in that time, and
	// the thread used less than its quota in each of them. The charge must not
	// make a debt in the current period for the time of the periods before.
	clock.advance(time.Second)
	ran(&clock, b, 1000*ms)
	if b.Throttled() {
		t.Fatal("throttled by a charge that lies in periods that ended")
	}
	if got := b.Stats().Throttled; got != 0 {
		t.Errorf("Throttled = %d, want 0", got)
	}
	if got := b.Stats().Periods; got != 10 {
		t.Errorf("Periods = %d, want 10: the thread was active in every period", got)
	}
	ran(&clock, b, 100*ms)
	if b.Throttled() {
		t.Error("throttled although the current period used 100 ms of 110 ms")
	}
}

func TestCPUBandwidthLateChargeSpreadsTheTimeOfAPausedTask(t *testing.T) {
	cases := []struct {
		name string
		// ranNS is the time that the thread ran in the stall of 1000 ms.
		ranNS int64
	}{
		{"duty cycle of 30 percent", 300 * ms},
		{"exactly the quota", 500 * ms},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var clock fakeBandwidthClock
			b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

			// A stall of the ticker holds back the charge for one second. The
			// thread ran in short bursts with pauses, and it never used more
			// than its quota in any period. The charge must not bill the
			// time of the bursts as one run at the end of the stall.
			clock.advance(time.Second)
			ranWithPauses(&clock, b, 0, tc.ranNS)
			if b.Throttled() {
				t.Error("throttled although the thread stayed within its quota in every period")
			}
			if got := b.Stats(); got.Throttled != 0 || got.ThrottledTime != 0 {
				t.Errorf("Stats = %+v, want no throttle", got)
			}
			// The current period starts at 1000 ms and has used none of it.
			ran(&clock, b, 59*ms)
			if b.Throttled() {
				t.Error("the stall left a debt: 59 ms is inside the slack over a quota of 50 ms")
			}
		})
	}
}

func TestCPUBandwidthLateChargeCountsOnlyTimeInCurrentPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 110*time.Millisecond)

	// The charge at 250 ms covers 200 ms of running. The periods end at 100 ms
	// and at 200 ms, so 50 ms of the charge lie in the period that began at
	// 200 ms. That period then has 60 ms left.
	clock.advance(250 * time.Millisecond)
	ran(&clock, b, 200*ms)
	ran(&clock, b, 59*ms)
	if b.Throttled() {
		t.Fatal("throttled with 109 ms charged in a period of 110 ms")
	}
	ran(&clock, b, 12*ms)
	if !b.Throttled() {
		t.Error("not throttled with 121 ms charged in a period of 110 ms")
	}
}

func TestCPUBandwidthLateChargeRepaysTheDebtOfEveryPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	// A thread ran 350 ms without a pause, because a stall held back both the
	// charge and the throttle. Each period gave it 50 ms, and it ran 100 ms in
	// each of the three periods that ended. It used 150 ms more than the quota
	// gave. The debt stays, as it would after charges on time.
	clock.advance(350 * time.Millisecond)
	ran(&clock, b, 350*ms)
	if !b.Throttled() {
		t.Fatal("not throttled after the thread used 150 ms more than its quota")
	}
	// The refills at 400 ms, 500 ms, and 600 ms repay 50 ms each.
	clock.advance(249 * time.Millisecond)
	if !b.Throttled() {
		t.Fatal("released before the periods repaid the debt")
	}
	clock.advance(time.Millisecond)
	if b.Throttled() {
		t.Error("still throttled after three refills repaid the debt of 150 ms")
	}
}

func TestCPUBandwidthLateChargeCountsThrottledPeriods(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	// A thread ran 1000 ms without a pause at a quota of 50 ms for each
	// period. It would have used the quota and stopped in each of the ten
	// periods. The charge on time makes ten throttled periods, and so must the
	// late charge.
	clock.advance(time.Second)
	ran(&clock, b, 1000*ms)
	stats := b.Stats()
	if stats.Periods != 10 || stats.Throttled != 10 {
		t.Errorf("Periods = %d and Throttled = %d, want 10 and 10", stats.Periods, stats.Throttled)
	}
	// The thread used the quota in the first half of the first period, so it
	// stopped for the second half. Debt makes it stop for the whole period in
	// each later period.
	if want := 950 * time.Millisecond; stats.ThrottledTime != want {
		t.Errorf("ThrottledTime = %v, want %v", stats.ThrottledTime, want)
	}
}

func TestCPUBandwidthLateChargesOfManyTasksCountTogether(t *testing.T) {
	var clock fakeBandwidthClock
	one := newTestBandwidth(t, &clock, nil, 110*time.Millisecond)
	two := newTestBandwidth(t, &clock, nil, 110*time.Millisecond)

	// A stall holds back the charges for one second. A single thread that ran
	// all the time used 100 ms in each period, and two such threads used 200 ms.
	clock.advance(time.Second)
	runs := appendBandwidthRuns(nil, one, 0, 1000*ms)
	runs = appendBandwidthRuns(runs, two, 0, 1000*ms)
	runs = appendBandwidthRuns(runs, two, 0, 1000*ms)
	chargeBandwidthRuns(clock.now, runs)
	if one.Throttled() {
		t.Error("a node throttled with one thread below its quota in each period")
	}
	if !two.Throttled() {
		t.Error("a node did not throttle with two threads above its quota in each period")
	}
}

func TestCPUBandwidthUnlimitedNodeNeverThrottles(t *testing.T) {
	var clock fakeBandwidthClock
	b := newCPUBandwidth(nil, clock.clock())
	ran(&clock, b, 10*int64(time.Second))
	if b.Throttled() {
		t.Error("an unlimited node throttled")
	}
	if got := b.Stats(); got != (CPUBandwidthStats{}) {
		t.Errorf("Stats = %+v, want zero", got)
	}
}

func TestCPUBandwidthChildObeysLimitOfAncestor(t *testing.T) {
	var clock fakeBandwidthClock
	parent := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	child := newCPUBandwidth(parent, clock.clock())

	ran(&clock, child, 30*ms)
	if child.Throttled() {
		t.Fatal("child throttled before the parent quota ran out")
	}
	// A sibling shares the quota of the parent.
	sibling := newCPUBandwidth(parent, clock.clock())
	ran(&clock, sibling, 31*ms)
	if !child.Throttled() || !sibling.Throttled() {
		t.Fatal("children keep running although they spent the quota of the parent together")
	}
	if got := child.Stats().Throttled; got != 0 {
		t.Errorf("child Throttled = %d, want 0 because only the parent has a limit", got)
	}

	clock.advance(100 * time.Millisecond)
	if child.Throttled() || sibling.Throttled() {
		t.Error("children stay throttled after the parent period ended")
	}
	if got := parent.Stats().Throttled; got != 1 {
		t.Errorf("parent Throttled = %d, want 1", got)
	}
}

func TestCPUBandwidthTighterChildLimitsBeforeParent(t *testing.T) {
	var clock fakeBandwidthClock
	parent := newTestBandwidth(t, &clock, nil, 80*time.Millisecond)
	child := newTestBandwidth(t, &clock, parent, 20*time.Millisecond)

	ran(&clock, child, 31*ms)
	if !child.Throttled() {
		t.Fatal("child not throttled at its own quota")
	}
	if parent.Throttled() {
		t.Error("parent throttled with 20 ms of 80 ms spent")
	}
}

func TestCPUBandwidthSetLimitsReleasesThrottle(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	ran(&clock, b, 61*ms)
	wake := b.throttleWake()
	counters := bandwidthCountersOf(testKernel(t))
	before := counters.throttled.Load()

	b.SetLimits(nil, -1, period)
	if b.Throttled() {
		t.Error("still throttled after the limit was removed")
	}
	select {
	case <-wake:
	default:
		t.Error("waiters did not wake when the limit was removed")
	}
	if got := counters.throttled.Load(); got != before-1 {
		t.Errorf("throttled node count = %d, want %d", got, before-1)
	}
}

func TestCPUBandwidthRaisedQuotaStartsFullPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	ran(&clock, b, 61*ms)

	b.SetLimits(testKernel(t), 80*time.Millisecond, period)
	if b.Throttled() {
		t.Fatal("still throttled after the quota grew")
	}
	ran(&clock, b, 79*ms)
	if b.Throttled() {
		t.Error("throttled before the new quota of 80 ms ran out")
	}
	ran(&clock, b, 12*ms)
	if !b.Throttled() {
		t.Error("not throttled after the new quota of 80 ms ran out")
	}
}

func TestCPUBandwidthLimitCountTracksFiniteQuotas(t *testing.T) {
	var clock fakeBandwidthClock
	k := testKernel(t)
	counters := bandwidthCountersOf(k)
	before := counters.limited.Load()
	b := newCPUBandwidth(nil, clock.clock())

	b.SetLimits(k, 50*time.Millisecond, period)
	b.SetLimits(k, 60*time.Millisecond, period)
	if got := counters.limited.Load(); got != before+1 {
		t.Errorf("limited node count = %d with one finite node, want %d", got, before+1)
	}
	b.SetLimits(k, -1, period)
	if got := counters.limited.Load(); got != before {
		t.Errorf("limited node count = %d after the limit was removed, want %d", got, before)
	}
}

func TestCPUBandwidthStatsIncludeThrottleInProgress(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	ran(&clock, b, 61*ms)
	clock.advance(30 * time.Millisecond)
	if got := b.Stats().ThrottledTime; got != 30*time.Millisecond {
		t.Errorf("ThrottledTime = %v during a throttle, want 30ms", got)
	}
}

func TestCPUBandwidthChargeSpansPeriodEnd(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	// The ticker charges at 110 ms the 50 ms that ran since 60 ms. The first
	// 40 ms belong to the old period, which has 50 ms. The last 10 ms start the
	// new period.
	clock.advance(110 * time.Millisecond)
	ran(&clock, b, 50*ms)
	if b.Throttled() {
		t.Fatal("throttled although 40 ms fell in the old period and 10 ms in the new one")
	}
	ran(&clock, b, 39*ms)
	if b.Throttled() {
		t.Error("throttled with 49 ms charged in the new period of 50 ms")
	}
}

func TestCPUBandwidthFullSpeedThreadAtQuotaEqualsPeriodNeverThrottles(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, period)

	// One thread runs all the time, and the ticker charges it every 10.4 ms.
	step := 10400 * time.Microsecond
	for range 400 {
		clock.advance(step)
		ran(&clock, b, step.Nanoseconds())
		if b.Throttled() {
			t.Fatalf("a thread that runs without a pause throttled at %v", time.Duration(clock.now))
		}
	}
	if got := b.Stats().Throttled; got != 0 {
		t.Errorf("Throttled = %d for a thread that never used more than its quota", got)
	}
}

func TestCPUBandwidthLimitReportsQuotaAndPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newCPUBandwidth(nil, clock.clock())
	if _, _, limited := b.Limit(); limited {
		t.Error("a new node reports a limit")
	}
	k := testKernel(t)
	b.SetLimits(k, 20*time.Millisecond, 200*time.Millisecond)
	t.Cleanup(func() { b.SetLimits(k, -1, period) })
	quota, per, limited := b.Limit()
	if !limited || quota != 20*time.Millisecond || per != 200*time.Millisecond {
		t.Errorf("Limit = (%v, %v, %v), want (20ms, 200ms, true)", quota, per, limited)
	}
}

func TestCPUMeterCountsTheRunsOfATask(t *testing.T) {
	var m cpuMeter
	m.start(100)
	if got := m.measured(150, true); got != 50 {
		t.Errorf("measured while running = %d, want 50", got)
	}
	m.stop(180)
	if got := m.measured(500, false); got != 80 {
		t.Errorf("measured while blocked = %d, want 80", got)
	}
	m.start(600)
	m.stop(630)
	if got := m.measured(900, false); got != 110 {
		t.Errorf("measured after two runs = %d, want 110", got)
	}
}

func TestCPUMeterStartsAtTheFirstReadingOfAnUnstampedTask(t *testing.T) {
	var m cpuMeter
	if got := m.measured(1000, true); got != 0 {
		t.Errorf("first reading = %d, want 0", got)
	}
	if got := m.measured(1400, true); got != 400 {
		t.Errorf("second reading = %d, want 400", got)
	}
}

// TestCPUBandwidthCountersAreIsolatedBetweenKernels runs two Kernels in one
// process. A limit and a throttle in one Kernel must not change the counters
// that the CPU clock ticker and the run loop of the other Kernel read.
func TestCPUBandwidthCountersAreIsolatedBetweenKernels(t *testing.T) {
	var clock fakeBandwidthClock
	kA, kB := &Kernel{}, &Kernel{}
	cA, cB := bandwidthCountersOf(kA), bandwidthCountersOf(kB)
	if cA == cB {
		t.Fatal("two Kernels share one set of bandwidth counters")
	}
	taskA, taskB := &Task{k: kA}, &Task{k: kB}
	if taskA.bandwidthCounters() != cA || taskB.bandwidthCounters() != cB {
		t.Fatal("a task does not read the counters of its own Kernel")
	}

	genB := cB.generation.Load()
	a := newCPUBandwidth(nil, clock.clock())
	a.SetLimits(kA, 50*time.Millisecond, period)
	t.Cleanup(func() { a.SetLimits(kA, -1, period) })

	if !kA.cpuBandwidthLimited() {
		t.Error("Kernel A has a finite quota, but cpuBandwidthLimited is false")
	}
	if kB.cpuBandwidthLimited() {
		t.Error("a limit in Kernel A makes Kernel B account CPU bandwidth")
	}
	if got := cB.generation.Load(); got != genB {
		t.Errorf("billing generation of Kernel B = %d after a limit in Kernel A, want %d", got, genB)
	}

	ran(&clock, a, 61*ms)
	if !a.Throttled() {
		t.Fatal("node A is not throttled after it spent its quota")
	}
	if !taskA.cpuBandwidthThrottled() {
		t.Error("a task of Kernel A does not see the throttle of its Kernel")
	}
	if taskB.cpuBandwidthThrottled() {
		t.Error("a throttle in Kernel A makes a task of Kernel B look for a throttle")
	}

	b := newCPUBandwidth(nil, clock.clock())
	b.SetLimits(kB, 50*time.Millisecond, period)
	t.Cleanup(func() { b.SetLimits(kB, -1, period) })
	a.SetLimits(kA, -1, period)
	if kA.cpuBandwidthLimited() {
		t.Error("Kernel A still counts a limit after it removed its only limit")
	}
	if !kB.cpuBandwidthLimited() {
		t.Error("removing the limit of Kernel A removed the limit count of Kernel B")
	}
}

// TestCPUBandwidthRefillTimerDoesNotKeepNodeAlive checks the leak of a node
// that a failed restore drops while it throttles. The refill timer must not
// keep the node reachable.
func TestCPUBandwidthRefillTimerDoesNotKeepNodeAlive(t *testing.T) {
	var clock fakeBandwidthClock
	k := &Kernel{}
	node := newCPUBandwidth(nil, clock.clock())
	node.SetLimits(k, 50*time.Millisecond, period)
	ran(&clock, node, 61*ms)
	if !node.Throttled() || len(clock.timers) != 1 {
		t.Fatalf("throttled = %t, timers = %d, want a throttled node with one timer", node.Throttled(), len(clock.timers))
	}
	// Keep the timer callback, as the host timer does, and drop the node.
	refill := clock.timers[0].f
	clock.timers = nil
	ref := weak.Make(node)
	node = nil
	for range 5 {
		runtime.GC()
		if ref.Value() == nil {
			break
		}
	}
	if ref.Value() != nil {
		t.Fatal("the refill timer keeps a dropped node alive")
	}
	clock.advance(period)
	refill()
	if len(clock.timers) != 0 {
		t.Errorf("the refill timer of a dropped node armed %d new timers, want 0", len(clock.timers))
	}
}
