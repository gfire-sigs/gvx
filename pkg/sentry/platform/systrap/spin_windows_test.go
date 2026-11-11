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

package systrap

import (
	"math"
	"testing"
	"time"

	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
)

func TestParseSpinEnv(t *testing.T) {
	for _, c := range []struct {
		in           string
		stub, sentry float64
		ok           bool
	}{
		{"16,1", 16, 1, true},
		{" 0 , 0 ", 0, 0, true},
		{"2.5,0.5", 2.5, 0.5, true},
		{"16", 0, 0, false},
		{"16,1,2", 0, 0, false},
		{"a,1", 0, 0, false},
		{"-1,1", 0, 0, false},
		{"", 0, 0, false},
	} {
		stub, sentry, err := parseSpinEnv(c.in)
		if (err == nil) != c.ok || (c.ok && (stub != c.stub || sentry != c.sentry)) {
			t.Errorf("parseSpinEnv(%q) = %v, %v, %v; want %v, %v, ok %v", c.in, stub, sentry, err, c.stub, c.sentry, c.ok)
		}
	}
}

func TestNewSpinWindowsUsesTheEnvironment(t *testing.T) {
	const perUs = 2500.0 // a 2.5 GHz counter
	t.Setenv(spinEnv, "")
	w, err := newSpinWindows(perUs)
	if err != nil {
		t.Fatal(err)
	}
	if want := uint64(defaultStubSpinNs / 1000 * perUs); w.stub != want {
		t.Errorf("default stub window = %d ticks, want %d", w.stub, want)
	}
	if want := uint64(defaultSentrySpinNs / 1000 * perUs); w.sentry != want {
		t.Errorf("default Sentry window = %d ticks, want %d", w.sentry, want)
	}
	t.Setenv(spinEnv, "4,0")
	w, err = newSpinWindows(perUs)
	if err != nil {
		t.Fatal(err)
	}
	if w.stub != 10000 || w.sentry != 0 {
		t.Errorf("windows = %+v, want 10000 and 0 ticks", w)
	}
	t.Setenv(spinEnv, "nonsense")
	if _, err := newSpinWindows(perUs); err == nil {
		t.Error("an invalid setting was accepted")
	}
}

// TestSpinTicksPerUsTracksTheClock checks the calibration against the Go clock
// over a longer span. Each counter reading sits between two readings of the Go
// clock, so thread preemption widens the bound instead of failing the sample.
func TestSpinTicksPerUsTracksTheClock(t *testing.T) {
	rate := spinTicksPerUs()
	if rate < 1 || math.IsNaN(rate) {
		t.Fatalf("spinTicksPerUs = %v", rate)
	}
	// The Go clock on Windows reads interrupt time, which can step by up to
	// 15.6 ms when timer resolution is coarse.
	const goClockStepUs = 20_000.0
	t0a := time.Now()
	c0 := spinNow()
	t0b := time.Now()
	for time.Since(t0b) < 100*time.Millisecond {
	}
	t1a := time.Now()
	c1 := spinNow()
	t1b := time.Now()

	minUs := max(0.0, float64(t1a.Sub(t0b))/1e3-goClockStepUs)
	maxUs := float64(t1b.Sub(t0a))/1e3 + goClockStepUs
	ticks := float64(c1 - c0)
	if ticks < minUs*rate*0.9 || ticks > maxUs*rate*1.1 {
		t.Errorf("counter advanced %.0f ticks in [%.0f, %.0f] us, outside 10%% of calibrated %.1f ticks/us",
			ticks, minUs, maxUs, rate)
	}
}

// TestAwaitSpinWindowLastsItsTime checks that the Sentry polls across its spin
// window and skips polling when the window has zero ticks.
func TestAwaitSpinWindowLastsItsTime(t *testing.T) {
	// Verify deterministic poll counts with a synthetic clock first.
	var zeroCalls int
	var hZero winSysmsgHeader
	_, _ = hZero.await(winSpin{ticks: 0, now: func() uint64 {
		zeroCalls++
		return 0
	}}, errSignaler{}, func() bool { return false })
	if zeroCalls != 0 {
		t.Errorf("zero-tick window read the clock %d times, want 0", zeroCalls)
	}

	var fakeTicks uint64
	var windowCalls int
	var hWin winSysmsgHeader
	_, _ = hWin.await(winSpin{ticks: 1000, now: func() uint64 {
		windowCalls++
		v := fakeTicks
		fakeTicks += 250
		return v
	}}, errSignaler{}, func() bool { return false })
	if windowCalls != 5 {
		t.Errorf("1000-tick window with 250-tick steps read the clock %d times, want 5", windowCalls)
	}

	// Verify that a real spin window waits at least its calibrated duration.
	const windowUs = 2000
	freq := float64(sentrytime.CounterFrequencyHz())
	var h winSysmsgHeader
	start := sentrytime.ReadCounterTicks()
	_, _ = h.await(winSpin{ticks: uint64(windowUs * spinTicksPerUs()), now: spinNow}, errSignaler{}, func() bool { return false })
	got := float64(sentrytime.ReadCounterTicks()-start) * 1e6 / freq
	if got < windowUs*0.9 {
		t.Errorf("await polled for %.0f us, want at least %.0f us", got, windowUs*0.9)
	}
}

// TestNewRejectsABadSpinSetting checks that a bad setting is an error in every
// mode. In the auto mode it must not look like a host without the fast path.
func TestNewRejectsABadSpinSetting(t *testing.T) {
	t.Setenv(spinEnv, "nonsense")
	for _, mode := range []fastPathSetting{fastPathAuto, fastPathRequired, fastPathOff} {
		prev := fastPathMode
		fastPathMode = mode
		p, err := New()
		fastPathMode = prev
		if err == nil {
			_ = p.Close()
			t.Errorf("mode %d: New accepted the setting", mode)
		}
	}
}
