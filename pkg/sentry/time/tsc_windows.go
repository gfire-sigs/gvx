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

//go:build windows

package time

import (
	"fmt"
	"math/bits"
	"sync"
	stdtime "time"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

var (
	modKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = modKernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modKernel32.NewProc("QueryPerformanceFrequency")
)

// qpcFrequency returns the QueryPerformanceCounter frequency in Hz.
// The frequency is fixed at boot. Windows XP and later never fail the call,
// so a failure means the host breaks the documented contract and the clock cannot work.
var qpcFrequency = sync.OnceValue(func() uint64 {
	var freq int64
	r0, _, err := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	if r0 == 0 || freq <= 0 {
		panic(fmt.Sprintf("QueryPerformanceFrequency failed: freq=%d: %v", freq, err))
	}
	return uint64(freq)
})

// ReadCounterTicks returns the QueryPerformanceCounter value. It advances at
// CounterFrequencyHz, the same domain MonotonicNanoseconds converts from.
func ReadCounterTicks() uint64 {
	var counter int64
	r0, _, err := procQueryPerformanceCounter.Call(uintptr(unsafe.Pointer(&counter)))
	if r0 == 0 || counter < 0 {
		panic(fmt.Sprintf("QueryPerformanceCounter failed: counter=%d: %v", counter, err))
	}
	return uint64(counter)
}

// CounterFrequencyHz returns the frequency of ReadCounterTicks.
func CounterFrequencyHz() uint64 {
	return qpcFrequency()
}

// MonotonicNanoseconds converts the QueryPerformanceCounter to nanoseconds.
func MonotonicNanoseconds() int64 {
	// The 128-bit product keeps ticks*1e9 exact for counters that run for years.
	hi, lo := bits.Mul64(ReadCounterTicks(), 1_000_000_000)
	ns, _ := bits.Div64(hi, lo, qpcFrequency())
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
