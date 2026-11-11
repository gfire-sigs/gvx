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

import "z.gfire.dev/gvx/internal/weakmap"

// reportedTotals caches the total memory that each Kernel reports without
// retaining dropped Kernels strongly. Checkpoint persistence lives on
// kernelExtState inside Kernel.additionalCheckpointState.
var reportedTotals weakmap.Map[Kernel, uint64]

// SetReportedMemory sets the total memory that /proc/meminfo and sysinfo(2) of
// the kernel report. A value of 0 removes the setting. Call it before the
// kernel starts a task.
//
// +checklocksexclude:k.checkpointMu
// +checklocksexclude:k.CheckpointWait.mu
func (k *Kernel) SetReportedMemory(total uint64) {
	if k == nil {
		return
	}
	e := k.ensureExtState()
	e.mu.Lock()
	if total == 0 {
		e.hasReportedMemory = false
		e.reportedMemory = 0
		e.mu.Unlock()
		reportedTotals.Delete(k)
		return
	}
	e.hasReportedMemory = true
	e.reportedMemory = total
	e.mu.Unlock()
	reportedTotals.Store(k, total)
}

// ReportedMemory returns the total memory that SetReportedMemory set for the
// kernel. It reports false when no value is set, and the caller then uses
// usage.TotalMemory.
func (k *Kernel) ReportedMemory() (uint64, bool) {
	return reportedTotals.Load(k)
}
