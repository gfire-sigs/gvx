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

package linux

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// sysinfoXplat implements Linux syscall sysinfo(2) using the per-sandbox
// MemoryFile accounting and configured memory limit of t.Kernel().
func sysinfoXplat(t *kernel.Task, sysno uintptr, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	mf := t.Kernel().MemoryFile()
	mfUsage, err := mf.TotalUsage()
	if err != nil {
		return 0, nil, err
	}
	memStats, _ := mf.Accounting().Copy()
	totalUsage := mfUsage + memStats.Mapped
	totalSize := usage.TotalMemory(mf.TotalSize(), totalUsage)
	if reported, ok := t.Kernel().ReportedMemory(); ok {
		totalSize = reported
	}
	memFree := totalSize - totalUsage
	if memFree > totalSize {
		memFree = 0
	}

	boottime := t.Kernel().BoottimeClock().Now()
	uptime := boottime.Seconds()
	if boottime.Nanoseconds()%1e9 != 0 {
		uptime++
	}

	si := linux.Sysinfo{
		Procs:    uint16(t.Kernel().TaskSet().Root.NumTasks()),
		Uptime:   uptime,
		TotalRAM: totalSize,
		FreeRAM:  memFree,
		Unit:     1,
	}
	_, err = si.CopyOut(t, addr)
	return 0, nil, err
}
