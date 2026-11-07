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

package tcpip

import (
	"fmt"
	"math/bits"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                   = windows.NewLazySystemDLL("kernel32.dll")
	procQueryPerformanceCounter   = modKernel32.NewProc("QueryPerformanceCounter")
	procQueryPerformanceFrequency = modKernel32.NewProc("QueryPerformanceFrequency")
)

// qpcFrequency returns the frequency of QueryPerformanceCounter in Hz. The
// frequency is fixed at boot, and the call never fails on Windows XP and
// later. A failure means that the host breaks that contract.
var qpcFrequency = sync.OnceValue(func() uint64 {
	var freq int64
	r0, _, err := procQueryPerformanceFrequency.Call(uintptr(unsafe.Pointer(&freq)))
	if r0 == 0 || freq <= 0 {
		panic(fmt.Sprintf("tcpip: QueryPerformanceFrequency failed: freq=%d: %v", freq, err))
	}
	return uint64(freq)
})

// hostTicks returns the value of QueryPerformanceCounter.
//
// The monotonic clock of the time package on Windows is the interrupt time.
// It changes once for each timer interrupt, which is 2 ms on a hosted Windows
// ARM runner and 15.6 ms at most. TCP loss detection compares the send time
// of a segment with the receive time of an acknowledgement. Two events in
// one interrupt period then have equal timestamps, and RACK marks segments as
// lost again and again. QueryPerformanceCounter changes every 100 ns.
func hostTicks() int64 {
	var counter int64
	// SyscallN does not move counter to the heap, and LazyProc.Call does.
	r0, _, err := syscall.SyscallN(procQueryPerformanceCounter.Addr(), uintptr(unsafe.Pointer(&counter)))
	if r0 == 0 || counter < 0 {
		panic(fmt.Sprintf("tcpip: QueryPerformanceCounter failed: counter=%d: %v", counter, err))
	}
	return counter
}

// hostSince returns the monotonic time that passed since the clock read
// baseTicks.
func hostSince(_ time.Time, baseTicks int64) time.Duration {
	delta := hostTicks() - baseTicks
	if delta < 0 {
		delta = 0
	}
	// The 128-bit product keeps delta*1e9 exact for counters that run for years.
	hi, lo := bits.Mul64(uint64(delta), uint64(time.Second))
	ns, _ := bits.Div64(hi, lo, qpcFrequency())
	return time.Duration(ns)
}
