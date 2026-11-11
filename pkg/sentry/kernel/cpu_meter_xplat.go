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
	"context"
	"sync/atomic"
	"time"
)

// cpuMeter measures the wall time in which a task goroutine runs, in the state
// RunningApp or RunningSys. The CPU clock ticker samples a few tasks and bills a
// whole tick to each, so its numbers are exact only on average. The meter reads
// the clock when the task blocks and when it resumes, so a system call that does
// not block costs nothing.
//
// +stateify savable
type cpuMeter struct {
	// total is the time of the finished runs in nanoseconds.
	total atomic.Int64 `state:".(int64)"`

	// runStart is the start of the current run. It is 0 while the task is
	// blocked, and before the first reading of a task that never blocked.
	runStart atomic.Int64 `state:"nosave"`

	// billed is the measured time that the budget already took. Only the CPU
	// clock ticker uses it.
	billed int64 `state:"nosave"`

	// billedAt is the time of the last reading of the ticker. The next charge
	// spreads the unbilled time over the interval since then. Only the CPU
	// clock ticker uses it.
	billedAt int64 `state:"nosave"`

	// skipToApp is true after a throttled task woke. The time up to its next
	// entry into application code is the cost of the wake, and it is not billed.
	// Only the task goroutine uses it.
	skipToApp bool `state:"nosave"`

	// billedGen is the value of cpuBillingGeneration when billed was set.
	billedGen int32 `state:"nosave"`
}

// saveTotal is invoked by stateify.
func (m *cpuMeter) saveTotal() int64 {
	return m.total.Load()
}

// loadTotal is invoked by stateify.
func (m *cpuMeter) loadTotal(_ context.Context, v int64) {
	m.total.Store(v)
}

// meterNow returns the monotonic time in nanoseconds. It is never 0.
func meterNow() int64 { return hostBandwidthClock.now() + 1 }

// start marks the start of a run.
func (m *cpuMeter) start(now int64) { m.runStart.Store(now) }

// stop ends the current run.
func (m *cpuMeter) stop(now int64) {
	if s := m.runStart.Swap(0); s != 0 {
		m.total.Add(max(now-s, 0))
	}
}

// restart drops the unbilled time since the wake of a throttled task and starts
// a new run.
func (m *cpuMeter) restart(now int64) {
	m.skipToApp = false
	m.runStart.Store(now)
}

// measured returns the running time up to now. The argument running tells
// whether the task goroutine runs now. A running task without a start time
// starts its run at now.
func (m *cpuMeter) measured(now int64, running bool) int64 {
	// The total comes first. A task that stops between the two reads then
	// adds its last run one reading late, and never twice.
	total := m.total.Load()
	if !running {
		return total
	}
	s := m.runStart.Load()
	if s == 0 {
		m.runStart.CompareAndSwap(0, now)
		return total
	}
	return total + max(now-s, 0)
}

// CPUTimeMeasured returns the wall time that the task goroutine of t ran in
// application and Sentry code. It is exact to the clock, unlike the clocks of
// CPUClock, which count whole ticks of sampled tasks.
func (t *Task) CPUTimeMeasured() time.Duration {
	return time.Duration(t.cpuMeter.measured(meterNow(), t.running()))
}

// SetCPUTimeMeasured sets the finished run time of t to d and resets any active
// run start or unbilled delta.
func (t *Task) SetCPUTimeMeasured(d time.Duration) {
	ns := max(d.Nanoseconds(), 0)
	t.cpuMeter.runStart.Store(0)
	t.cpuMeter.total.Store(ns)
	t.cpuMeter.billed = ns
}

// SaveTaskCPUMeters returns the non-zero measured CPU time in nanoseconds for
// every task in k.
//
// +checklocksexclude:k.tasks.mu
func (k *Kernel) SaveTaskCPUMeters() map[*Task]int64 {
	if k == nil || k.tasks == nil || k.tasks.Root == nil {
		return nil
	}
	k.tasks.mu.RLock()
	defer k.tasks.mu.RUnlock()
	now := meterNow()
	var out map[*Task]int64
	for t := range k.tasks.Root.tids {
		if ns := t.cpuMeter.measured(now, t.running()); ns > 0 {
			if out == nil {
				out = make(map[*Task]int64)
			}
			out[t] = ns
		}
	}
	return out
}

// LoadTaskCPUMeters restores the saved CPU time in nanoseconds onto each task
// in meters without re-billing pre-checkpoint time to CPU bandwidth budgets.
func (k *Kernel) LoadTaskCPUMeters(meters map[*Task]int64) {
	_ = k
	for t, ns := range meters {
		if t == nil || ns <= 0 {
			continue
		}
		t.cpuMeter.runStart.Store(0)
		t.cpuMeter.total.Store(ns)
		t.cpuMeter.billed = ns
	}
}

// running returns true if the task goroutine runs application or Sentry code.
func (t *Task) running() bool {
	s := t.TaskGoroutineState()
	return s == TaskGoroutineRunningApp || s == TaskGoroutineRunningSys
}
