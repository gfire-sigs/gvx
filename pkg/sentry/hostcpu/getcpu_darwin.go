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

//go:build darwin

package hostcpu

import (
	"errors"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

//go:linkname darwinRawSyscall6 syscall.rawSyscall6
func darwinRawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func pthreadCPUNumberTrampoline()
func addrOfPthreadCPUNumber() uintptr

// libSystem exports int pthread_cpu_number_np(size_t *cpu_number_out) since macOS 11.
// It returns 0 on success or an errno value. The CPU number lies in [0, hw.ncpu).
//
//go:cgo_import_dynamic libc_pthread_cpu_number_np pthread_cpu_number_np "/usr/lib/libSystem.B.dylib"

var pthreadCPUNumberAddr = addrOfPthreadCPUNumber()

// errCPUOutOfRange reports a CPU number outside [0, MaxPossibleCPU()].
var errCPUOutOfRange = errors.New("host reported a CPU number above the CPU count")

// currentCPU returns the number of the CPU that the calling thread runs on.
// The thread can move to another CPU before the caller uses the result.
func currentCPU() (uint32, error) {
	var cpu uintptr
	// The call only reads a thread-local CPU number, so it never blocks and
	// it skips the runtime syscall bookkeeping.
	rc, _, _ := darwinRawSyscall6(pthreadCPUNumberAddr, uintptr(unsafe.Pointer(&cpu)), 0, 0, 0, 0, 0)
	if rc != 0 {
		return 0, fmt.Errorf("pthread_cpu_number_np: %w", syscall.Errno(rc))
	}
	maxCPU, err := MaxPossibleCPU()
	if err != nil {
		return 0, err
	}
	if cpu > uintptr(maxCPU) {
		return 0, fmt.Errorf("%w: cpu=%d max=%d", errCPUOutOfRange, cpu, maxCPU)
	}
	return uint32(cpu), nil
}

// GetCPU returns the caller's current CPU number from pthread_cpu_number_np.
// It panics if the host cannot report a CPU number. Callers index per-CPU
// state with the result, and a made-up number would hide the fault.
func GetCPU() uint32 {
	cpu, err := currentCPU()
	if err != nil {
		panic(fmt.Sprintf("hostcpu: cannot read the current CPU: %v", err))
	}
	return cpu
}

var (
	maxCPUOnce sync.Once
	maxCPU     uint32
	maxCPUErr  error
)

// MaxPossibleCPU returns the highest CPU number that pthread_cpu_number_np can
// report. The header documents the interval [0, hw.ncpu).
func MaxPossibleCPU() (uint32, error) {
	maxCPUOnce.Do(func() {
		n, err := unix.SysctlUint32("hw.ncpu")
		switch {
		case err != nil:
			maxCPUErr = fmt.Errorf("sysctl hw.ncpu: %w", err)
		case n == 0:
			maxCPUErr = errors.New("sysctl hw.ncpu returned 0")
		default:
			maxCPU = n - 1
		}
	})
	return maxCPU, maxCPUErr
}
