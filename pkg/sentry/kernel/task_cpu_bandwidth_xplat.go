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

// CPUBandwidthProvider is the optional interface of a Cgroup2 node that has
// a CPU budget. The node returns the budget of its nearest ancestor with the
// cpu controller, or nil when it has none.
type CPUBandwidthProvider interface {
	CPUBandwidth() *CPUBandwidth
}

// cpuBandwidth returns the CPU budget that limits t, or nil if none exists.
func (t *Task) cpuBandwidth() *CPUBandwidth {
	node := t.Cgroup2()
	if node == nil {
		return nil
	}
	p, ok := node.(CPUBandwidthProvider)
	if !ok {
		return nil
	}
	return p.CPUBandwidth()
}

// accountCPUBandwidth runs once for each CPU clock tick while a cgroup has a
// quota. It charges the time that each task ran since its last charge to the
// budget of the cgroup of the task, and to the budget of every ancestor with a
// limit. A task can pause between two charges, so the budgets spread its time
// over the interval since the last charge. The function gives all charges of
// one tick to the budgets together, so that a stall of the ticker is split over
// the periods that it covers.
//
// The function then interrupts the tasks that run application code in a
// throttled cgroup. The interrupted task returns to its run loop, which blocks
// it in throttleCPUBandwidth.
//
// A task in a system call is not interrupted. It stops when it returns to the
// application, as in Linux, so system time counts toward the quota.
//
// Preconditions: The caller must be the CPU clock ticker.
func (k *Kernel) accountCPUBandwidth(all []*Task) {
	now := meterNow()
	gen := cpuBillingGeneration.Load()
	var stack [32]bandwidthRun
	runs := stack[:0]
	for _, t := range all {
		m := &t.cpuMeter
		running := t.running()
		if !running && m.total.Load() == m.billed {
			m.billedAt = now
			continue
		}
		cur := m.measured(now, running)
		if m.billedGen != gen {
			// The first limit appeared after the task last ran under a limit.
			// The time before then belongs to no budget.
			m.billed, m.billedGen, m.billedAt = cur, gen, now
			continue
		}
		if cur <= m.billed {
			m.billedAt = now
			continue
		}
		runs = appendBandwidthRuns(runs, t.cpuBandwidth(), m.billedAt, cur-m.billed)
		m.billed, m.billedAt = cur, now
	}
	chargeBandwidthRuns(now, runs)
	if cpuBandwidthThrottled.Load() == 0 {
		return
	}
	for _, t := range all {
		if t.TaskGoroutineState() != TaskGoroutineRunningApp {
			continue
		}
		if bw := t.cpuBandwidth(); bw != nil && bw.Throttled() {
			t.interrupt()
		}
	}
}

// WakeCPUBandwidth makes t read the CPU budget of its cgroup again. A task that
// moves to another cgroup calls it, so that the task does not wait for the
// period end of the budget that it left.
func (t *Task) WakeCPUBandwidth() {
	t.interrupt()
}

// throttleCPUBandwidth blocks t while its cgroup has no CPU quota left. It
// returns true if it blocked. The caller must then run the interrupt checks of
// the run loop again, because a signal or a stop can end the block, and
// because the budget can still be empty.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) throttleCPUBandwidth() bool {
	bw := t.cpuBandwidth()
	if bw == nil {
		return false
	}
	wake := bw.throttleWake()
	if wake == nil {
		return false
	}
	t.Block(wake)
	t.cpuMeter.skipToApp = true
	return true
}
