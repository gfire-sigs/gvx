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

	b.charge(40 * ms)
	if b.Throttled() {
		t.Fatal("throttled after 40 ms of a 50 ms quota")
	}
	b.charge(10 * ms)
	if !b.Throttled() {
		t.Fatal("not throttled after 50 ms of a 50 ms quota")
	}
	if got := b.Stats().Throttled; got != 1 {
		t.Errorf("Throttled = %d, want 1", got)
	}
}

func TestCPUBandwidthRefillEndsThrottleAtPeriodEnd(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	b.charge(50 * ms)
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

	b.charge(50 * ms)
	if !b.Throttled() {
		t.Error("the new period did not grant a full quota of 50 ms")
	}
	if got := b.Stats().Throttled; got != 2 {
		t.Errorf("Throttled = %d, want 2", got)
	}
}

func TestCPUBandwidthDebtCarriesIntoNextPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)

	// Tasks on several CPUs charge 120 ms: 70 ms more than the quota.
	b.charge(120 * ms)
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
	b.charge(29 * ms)
	if b.Throttled() {
		t.Fatal("throttled before the debt-adjusted quota was spent")
	}
	b.charge(1 * ms)
	if !b.Throttled() {
		t.Fatal("not throttled after the debt-adjusted quota was spent")
	}
}

func TestCPUBandwidthIdleNodeStartsFreshPeriod(t *testing.T) {
	var clock fakeBandwidthClock
	b := newTestBandwidth(t, &clock, nil, 50*time.Millisecond)
	b.charge(30 * ms)
	clock.advance(10 * time.Second)

	b.charge(40 * ms)
	if b.Throttled() {
		t.Fatal("throttled although the idle time restored the full quota")
	}
	if got := b.Stats().Periods; got != 1 {
		t.Errorf("Periods = %d, want 1 for the one period that had a charge", got)
	}
	// The period of the new charge started at the charge. It ends 100 ms later.
	clock.advance(60 * time.Millisecond)
	b.charge(10 * ms)
	if !b.Throttled() {
		t.Error("not throttled after 50 ms of charges in one period")
	}
}

func TestCPUBandwidthUnlimitedNodeNeverThrottles(t *testing.T) {
	var clock fakeBandwidthClock
	b := newCPUBandwidth(nil, clock.clock())
	b.charge(10 * int64(time.Second))
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

	child.charge(30 * ms)
	if child.Throttled() {
		t.Fatal("child throttled before the parent quota ran out")
	}
	// A sibling shares the quota of the parent.
	sibling := newCPUBandwidth(parent, clock.clock())
	sibling.charge(20 * ms)
	if !child.Throttled() || !sibling.Throttled() {
		t.Fatal("children keep running although they spent the quota of the parent together")
	}
	if got := child.Stats().Throttled; got != 0 {
		t.Errorf("child Throttled = %d, want 0 because only the parent has a limit", got)
	}
	if got := parent.Stats().Throttled; got != 1 {
		t.Errorf("parent Throttled = %d, want 1", got)
	}

	clock.advance(100 * time.Millisecond)
	if child.Throttled() || sibling.Throttled() {
		t.Error("children stay throttled after the parent period ended")
	}
}

func TestCPUBandwidthTighterChildLimitsBeforeParent(t *testing.T) {
	var clock fakeBandwidthClock
	parent := newTestBandwidth(t, &clock, nil, 80*time.Millisecond)
	child := newTestBandwidth(t, &clock, parent, 20*time.Millisecond)

	child.charge(20 * ms)
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
	b.charge(50 * ms)
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
	b.charge(50 * ms)

	b.SetLimits(80*time.Millisecond, period)
	if b.Throttled() {
		t.Fatal("still throttled after the quota grew")
	}
	b.charge(79 * ms)
	if b.Throttled() {
		t.Error("throttled before the new quota of 80 ms ran out")
	}
	b.charge(1 * ms)
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
	b.charge(50 * ms)
	clock.advance(30 * time.Millisecond)
	if got := b.Stats().ThrottledTime; got != 30*time.Millisecond {
		t.Errorf("ThrottledTime = %v during a throttle, want 30ms", got)
	}
}
