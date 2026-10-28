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
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
)

// The two sides of the handoff poll the handoff word for a while before they
// sleep on an event. A sleep costs a kernel call and a wake-up of a thread, which
// takes 10 to 30 microseconds. A window in time keeps that choice the same on
// every host. A window in loop counts did not: one poll of the stub took 18 ns
// on amd64 with a pause instruction and 0.15 ns on arm64 with a yield
// instruction, so the arm64 stub gave up after 0.2 microseconds and nearly every
// round trip used the events (docs/systrap-windows.md, 3.9).

const (
	// defaultStubSpinNs and defaultSentrySpinNs are the windows in nanoseconds.
	// They equal the time that the loop counts of the first version took on
	// amd64.
	defaultStubSpinNs   = 16_000
	defaultSentrySpinNs = 1_000

	// spinEnv sets both windows in microseconds, as "stub,sentry". A window of
	// 0 means that the side never polls. Tests and the spin sweep use it.
	spinEnv = "GVX_SYSTRAP_SPIN_US"
)

// spinWindows holds the windows in ticks of the cycle counter.
type spinWindows struct {
	stub, sentry uint64
}

// spinTicksPerUs returns the ticks of the cycle counter in one microsecond. The
// stub reads the same counter: the TSC on amd64, and CNTVCT_EL0 on arm64. The
// value comes from three samples of one millisecond against the performance
// counter. The first call takes about three milliseconds.
var spinTicksPerUs = sync.OnceValue(func() float64 {
	freq := float64(sentrytime.CounterFrequencyHz())
	window := uint64(freq / 1000)
	var rates [3]float64
	for i := range rates {
		q0 := sentrytime.ReadCounterTicks()
		c0 := uint64(sentrytime.Rdtsc())
		var q1 uint64
		for q1 = sentrytime.ReadCounterTicks(); q1-q0 < window; q1 = sentrytime.ReadCounterTicks() {
		}
		c1 := uint64(sentrytime.Rdtsc())
		us := float64(q1-q0) * 1e6 / freq
		rates[i] = float64(c1-c0) / us
	}
	slices.Sort(rates[:])
	return rates[1]
})

// spinNow reads the counter that the Sentry window uses.
func spinNow() uint64 { return uint64(sentrytime.Rdtsc()) }

// parseSpinEnv parses "stub,sentry" in microseconds.
func parseSpinEnv(v string) (stubUs, sentryUs float64, err error) {
	parts := strings.Split(v, ",")
	if len(parts) != 2 {
		return 0, 0, fmt.Errorf("%s=%q is not \"stub,sentry\" in microseconds", spinEnv, v)
	}
	var out [2]float64
	for i, part := range parts {
		out[i], err = strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil || out[i] < 0 {
			return 0, 0, fmt.Errorf("%s=%q: %q is not a non-negative number", spinEnv, v, part)
		}
	}
	return out[0], out[1], nil
}

// newSpinWindows returns the windows in ticks. perUs is the tick rate.
func newSpinWindows(perUs float64) (spinWindows, error) {
	stubUs, sentryUs := float64(defaultStubSpinNs)/1000, float64(defaultSentrySpinNs)/1000
	if v := os.Getenv(spinEnv); v != "" {
		var err error
		if stubUs, sentryUs, err = parseSpinEnv(v); err != nil {
			return spinWindows{}, err
		}
	}
	return spinWindows{stub: uint64(stubUs * perUs), sentry: uint64(sentryUs * perUs)}, nil
}
