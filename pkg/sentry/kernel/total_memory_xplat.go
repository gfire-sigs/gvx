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
	"weak"

	"z.gfire.dev/gvx/pkg/sync"
)

// reportedTotals holds the total memory that a kernel reports. The map holds
// the kernels weakly, so a kernel that a test drops frees its entry. A struct
// field would need a change in kernel.go.
var reportedTotals struct {
	mu     sync.Mutex
	totals map[weak.Pointer[Kernel]]uint64
}

// SetReportedMemory sets the total memory that /proc/meminfo and sysinfo(2) of
// the kernel report. A value of 0 removes the setting. Call it before the
// kernel starts a task.
func (k *Kernel) SetReportedMemory(total uint64) {
	key := weak.Make(k)
	reportedTotals.mu.Lock()
	defer reportedTotals.mu.Unlock()
	if total == 0 {
		delete(reportedTotals.totals, key)
		return
	}
	if reportedTotals.totals == nil {
		reportedTotals.totals = make(map[weak.Pointer[Kernel]]uint64)
	}
	if _, ok := reportedTotals.totals[key]; !ok {
		runtime.AddCleanup(k, func(key weak.Pointer[Kernel]) {
			reportedTotals.mu.Lock()
			defer reportedTotals.mu.Unlock()
			delete(reportedTotals.totals, key)
		}, key)
	}
	reportedTotals.totals[key] = total
}

// ReportedMemory returns the total memory that SetReportedMemory set for the
// kernel. It reports false when no value is set, and the caller then uses
// usage.TotalMemory.
func (k *Kernel) ReportedMemory() (uint64, bool) {
	reportedTotals.mu.Lock()
	defer reportedTotals.mu.Unlock()
	total, ok := reportedTotals.totals[weak.Make(k)]
	return total, ok
}
