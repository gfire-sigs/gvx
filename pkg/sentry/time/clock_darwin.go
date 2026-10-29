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

package time

import (
	"syscall"
	stdtime "time"
	_ "unsafe" // for go:linkname

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// clockUptimeRaw is CLOCK_UPTIME_RAW from <time.h>. It counts mach_absolute_time
// ticks in nanoseconds and pauses while the host sleeps, as Linux CLOCK_MONOTONIC does.
const clockUptimeRaw = 8

//go:linkname darwinRawSyscall6 syscall.rawSyscall6
func darwinRawSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func clockGettimeNsecNpTrampoline()
func addrOfClockGettimeNsecNp() uintptr

// libSystem exports uint64_t clock_gettime_nsec_np(clockid_t). It returns zero on failure.
//
//go:cgo_import_dynamic libc_clock_gettime_nsec_np clock_gettime_nsec_np "/usr/lib/libSystem.B.dylib"

var clockGettimeNsecNpAddr = addrOfClockGettimeNsecNp()

// MonotonicNanoseconds returns the host monotonic clock in nanoseconds.
// It reads clock_gettime_nsec_np(CLOCK_UPTIME_RAW), the same mach_absolute_time
// domain that the CPU counter behind Rdtsc advances in. The call is a short
// non-blocking libSystem function, so it skips the runtime syscall bookkeeping.
func MonotonicNanoseconds() int64 {
	ns, _, _ := darwinRawSyscall6(clockGettimeNsecNpAddr, clockUptimeRaw, 0, 0, 0, 0, 0)
	if ns == 0 {
		// The kernel rejects only unknown clock IDs, and CLOCK_UPTIME_RAW is known.
		panic("clock_gettime_nsec_np(CLOCK_UPTIME_RAW) failed")
	}
	return int64(ns)
}

// RealtimeNanoseconds returns the host wall clock in nanoseconds since the Unix epoch.
func RealtimeNanoseconds() int64 {
	return stdtime.Now().UnixNano()
}

func vdsoClockGettime(clockid ClockID, ts *unix.Timespec) int {
	var ns int64
	switch clockid {
	case Realtime:
		ns = RealtimeNanoseconds()
	case Monotonic, MonotonicRaw:
		ns = MonotonicNanoseconds()
	default:
		return int(unix.EINVAL)
	}
	ts.Sec = ns / 1_000_000_000
	ts.Nsec = ns % 1_000_000_000
	return 0
}
