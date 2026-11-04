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
	"slices"
	"testing"
	"time"
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

// newTestBandwidth returns a node with a quota of 50 ms for each period of
// 100 ms, and it removes the limit at the end of the test so that the global
// counters return to their old values.
func newTestBandwidth(t *testing.T, c *fakeBandwidthClock, parent *CPUBandwidth, quota time.Duration) *CPUBandwidth {
	t.Helper()
	b := newCPUBandwidth(parent, c.clock())
	b.SetLimits(quota, period)
	t.Cleanup(func() { b.SetLimits(-1, period) })
	return b
}

func TestCPUBandwidthThrottlesWhenQuotaIsSpent(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	b.charge(clock.now, 40*ms)
	if b.Throttled() {
		t.Fatal("throttled after 40 ms of a 50 ms quota")
	}
	b.charge(clock.now, 10*ms)
	if b.Throttled() {
		t.Fatal("throttled at the quota, inside the slack of one tick")
	}
	b.charge(clock.now, 11*ms)
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
	b.charge(clock.now, 61*ms)
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
	b.charge(clock.now, 50*ms)
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
	b.charge(clock.now, 120*ms)
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
	b.charge(clock.now, 30*ms)
	if b.Throttled() {
		t.Fatal("throttled before the debt-adjusted quota was spent")
	}
	b.charge(clock.now, 11*ms)
	if !b.Throttled() {
		t.Fatal("not throttled after the debt-adjusted quota was spent")
	}
}

func TestCPUBandwidthIdleNodeStartsFreshPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	b.charge(clock.now, 30*ms)
	clock.advance(10 * time.Second)

	b.charge(clock.now, 40*ms)
	if b.Throttled() {
		t.Fatal("throttled although the idle time restored the full quota")
	}
	if got := b.Stats().Periods; got != 2 {
		t.Errorf("Periods = %d, want 2: the period with the charge and one idle period", got)
	}
	// The period of the new charge started at the charge. It ends 100 ms later.
	clock.advance(60 * time.Millisecond)
	b.charge(clock.now, 21*ms)
	if !b.Throttled() {
		t.Error("not throttled after 56 ms of charges in one period")
	}
}

func TestCPUBandwidthUnlimitedNodeNeverThrottles(t *testing.T) {
	var clock fakeBandwidthClock
	b := newCPUBandwidth(nil, clock.clock())
	b.charge(clock.now, 10*int64(time.Second))
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

	child.charge(clock.now, 30*ms)
	if child.Throttled() {
		t.Fatal("child throttled before the parent quota ran out")
	}
	// A sibling shares the quota of the parent.
	sibling := newCPUBandwidth(parent, clock.clock())
	sibling.charge(clock.now, 31*ms)
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

	child.charge(clock.now, 31*ms)
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
	b.charge(clock.now, 61*ms)
	wake := b.throttleWake()
	before := cpuBandwidthThrottled.Load()

	b.SetLimits(-1, period)
	if b.Throttled() {
		t.Error("still throttled after the limit was removed")
	}
	select {
	case <-wake:
	default:
		t.Error("waiters did not wake when the limit was removed")
	}
	if got := cpuBandwidthThrottled.Load(); got != before-1 {
		t.Errorf("throttled node count = %d, want %d", got, before-1)
	}
}

func TestCPUBandwidthRaisedQuotaStartsFullPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	b.charge(clock.now, 61*ms)

	b.SetLimits(80*time.Millisecond, period)
	if b.Throttled() {
		t.Fatal("still throttled after the quota grew")
	}
	b.charge(clock.now, 79*ms)
	if b.Throttled() {
		t.Error("throttled before the new quota of 80 ms ran out")
	}
	b.charge(clock.now, 12*ms)
	if !b.Throttled() {
		t.Error("not throttled after the new quota of 80 ms ran out")
	}
}

func TestCPUBandwidthLimitCountTracksFiniteQuotas(t *testing.T) {
	var clock fakeBandwidthClock
	before := cpuBandwidthLimited.Load()
	b := newCPUBandwidth(nil, clock.clock())

	b.SetLimits(50*time.Millisecond, period)
	b.SetLimits(60*time.Millisecond, period)
	if got := cpuBandwidthLimited.Load(); got != before+1 {
		t.Errorf("limited node count = %d with one finite node, want %d", got, before+1)
	}
	b.SetLimits(-1, period)
	if got := cpuBandwidthLimited.Load(); got != before {
		t.Errorf("limited node count = %d after the limit was removed, want %d", got, before)
	}
}

func TestCPUBandwidthStatsIncludeThrottleInProgress(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	b.charge(clock.now, 61*ms)
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
	b.charge(clock.now, 50*ms)
	if b.Throttled() {
		t.Fatal("throttled although 40 ms fell in the old period and 10 ms in the new one")
	}
	b.charge(clock.now, 39*ms)
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
		b.charge(clock.now, step.Nanoseconds())
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
	b.SetLimits(20*time.Millisecond, 200*time.Millisecond)
	t.Cleanup(func() { b.SetLimits(-1, period) })
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
