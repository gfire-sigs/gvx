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

//go:build darwin || windows

package time

import (
	"runtime"
	"testing"
	stdtime "time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// spinFor busy-waits until the Go runtime clock has advanced by d.
// The host clocks under test have no readiness signal to wait on.
func spinFor(d stdtime.Duration) {
	start := stdtime.Now()
	for stdtime.Since(start) < d {
	}
}

func TestMonotonicNanosecondsNeverGoesBackwards(t *testing.T) {
	prev := MonotonicNanoseconds()
	for i := 0; i < 200_000; i++ {
		now := MonotonicNanoseconds()
		if now < prev {
			t.Fatalf("MonotonicNanoseconds went backwards: %d -> %d", prev, now)
		}
		prev = now
	}
}

// runtimeClockTolerance bounds the difference between the host clock and the
// Go runtime clock. On macOS both read the same counter. On Windows the Go
// runtime reads the interrupt time, which advances in timer ticks of up to
// 15.6ms, while the host clock reads the performance counter.
func runtimeClockTolerance() stdtime.Duration {
	if runtime.GOOS == "windows" {
		return 20 * stdtime.Millisecond
	}
	return stdtime.Millisecond
}

// TestMonotonicNanosecondsTracksRuntimeClock compares deltas with the Go runtime
// monotonic clock. A wrong unit or a wrong clock source shows up as a large
// mismatch.
func TestMonotonicNanosecondsTracksRuntimeClock(t *testing.T) {
	tol := runtimeClockTolerance()
	hostStart := MonotonicNanoseconds()
	goStart := stdtime.Now()
	spinFor(20 * stdtime.Millisecond)
	hostElapsed := stdtime.Duration(MonotonicNanoseconds() - hostStart)
	goElapsed := stdtime.Since(goStart)
	if hostElapsed < 20*stdtime.Millisecond-tol {
		t.Fatalf("host clock advanced %v while the runtime clock advanced %v", hostElapsed, goElapsed)
	}
	if diff := hostElapsed - goElapsed; diff < -tol || diff > tol {
		t.Fatalf("host clock advanced %v, runtime clock advanced %v, want a difference below %v", hostElapsed, goElapsed, tol)
	}
}

// TestCounterTicksMatchFrequency verifies that ReadCounterTicks and CounterFrequencyHz share one domain.
func TestCounterTicksMatchFrequency(t *testing.T) {
	freq := CounterFrequencyHz()
	if freq == 0 {
		t.Fatal("CounterFrequencyHz returned 0")
	}
	ticksStart, nsStart := ReadCounterTicks(), MonotonicNanoseconds()
	spinFor(20 * stdtime.Millisecond)
	ticksEnd, nsEnd := ReadCounterTicks(), MonotonicNanoseconds()
	if ticksEnd <= ticksStart {
		t.Fatalf("counter ticks did not advance: %d -> %d", ticksStart, ticksEnd)
	}
	fromTicks := float64(ticksEnd-ticksStart) / float64(freq) * 1e9
	fromClock := float64(nsEnd - nsStart)
	if ratio := fromTicks / fromClock; ratio < 0.95 || ratio > 1.05 {
		t.Fatalf("counter delta is %.0fns at %dHz, clock delta is %.0fns, ratio %.3f outside 0.95..1.05", fromTicks, freq, fromClock, ratio)
	}
}

func TestRealtimeNanosecondsFollowsWallClock(t *testing.T) {
	before := stdtime.Now().UnixNano()
	got := RealtimeNanoseconds()
	after := stdtime.Now().UnixNano()
	if got < before || got > after {
		t.Fatalf("RealtimeNanoseconds = %d, want within [%d, %d]", got, before, after)
	}
}

func TestVDSOClockGettimeSupportsHostClocks(t *testing.T) {
	var ts unix.Timespec
	if rc := vdsoClockGettime(Monotonic, &ts); rc != 0 {
		t.Fatalf("vdsoClockGettime(Monotonic) = %d, want 0", rc)
	}
	first := ts.Sec*1_000_000_000 + ts.Nsec
	spinFor(stdtime.Millisecond)
	if rc := vdsoClockGettime(MonotonicRaw, &ts); rc != 0 {
		t.Fatalf("vdsoClockGettime(MonotonicRaw) = %d, want 0", rc)
	}
	if second := ts.Sec*1_000_000_000 + ts.Nsec; second <= first {
		t.Fatalf("monotonic clock did not advance: %d -> %d", first, second)
	}
	if ts.Nsec < 0 || ts.Nsec >= 1_000_000_000 {
		t.Fatalf("Timespec.Nsec = %d, want a value below one second", ts.Nsec)
	}
	if rc := vdsoClockGettime(Realtime, &ts); rc != 0 || ts.Sec < 1_700_000_000 {
		t.Fatalf("vdsoClockGettime(Realtime) = (%d, %d s), want success with a current epoch time", rc, ts.Sec)
	}
	if rc := vdsoClockGettime(ClockID(0x7fff), &ts); rc != int(unix.EINVAL) {
		t.Fatalf("vdsoClockGettime(unknown) = %d, want EINVAL", rc)
	}
}

func TestCalibratedClocksOnHostClock(t *testing.T) {
	clocks := NewCalibratedClocks(true)
	clocks.Update(false)
	spinFor(2 * stdtime.Millisecond)
	res := clocks.Update(false)
	if !res.MonotonicOk || !res.RealtimeOk {
		t.Fatalf("CalibratedClocks failed to calibrate: %+v", res)
	}
	got, err := clocks.GetTime(Monotonic)
	if err != nil || got <= 0 {
		t.Fatalf("GetTime(Monotonic) = %d, %v", got, err)
	}
}
