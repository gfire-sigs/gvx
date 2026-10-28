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
// over a longer span. The counter that the stub reads must advance at the rate
// that the Sentry used to convert the windows.
func TestSpinTicksPerUsTracksTheClock(t *testing.T) {
	rate := spinTicksPerUs()
	if rate < 1 || math.IsNaN(rate) {
		t.Fatalf("spinTicksPerUs = %v", rate)
	}
	start, c0 := time.Now(), spinNow()
	for time.Since(start) < 20*time.Millisecond {
	}
	elapsedUs := float64(time.Since(start)) / 1e3
	got := float64(spinNow()-c0) / elapsedUs
	if got < rate*0.9 || got > rate*1.1 {
		t.Errorf("the counter ran at %.1f ticks per microsecond, the calibration says %.1f", got, rate)
	}
}

// TestAwaitSpinWindowLastsItsTime checks that the Sentry polls for the time of
// its window, and not for a number of loop iterations. The test reads the
// performance counter, because the Go clock of Windows ticks every half
// millisecond.
func TestAwaitSpinWindowLastsItsTime(t *testing.T) {
	const windowUs = 2000
	freq := float64(sentrytime.CounterFrequencyHz())
	measure := func(spin winSpin) float64 {
		var h winSysmsgHeader
		start := sentrytime.ReadCounterTicks()
		_, _ = h.await(spin, errSignaler{}, func() bool { return false })
		return float64(sentrytime.ReadCounterTicks()-start) * 1e6 / freq
	}
	got := measure(winSpin{ticks: uint64(windowUs * spinTicksPerUs()), now: spinNow})
	if got < windowUs {
		t.Errorf("await polled for %.0f us, want at least %d us", got, windowUs)
	}
	if got > 50*windowUs {
		t.Errorf("await polled for %.0f us, far more than %d us", got, windowUs)
	}
	// A window of zero ticks sleeps at once.
	if got := measure(winSpin{now: spinNow}); got > 1000 {
		t.Errorf("a window of 0 ticks polled for %.0f us", got)
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
