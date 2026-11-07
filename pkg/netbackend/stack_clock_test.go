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

package netbackend

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/tcpip"
)

// maxStdClockStep is the largest step that NowMonotonic may take between two
// readings that differ. A host timer interrupt makes a step of 0.3 ms to 15.6 ms,
// which is too coarse for TCP loss detection.
const maxStdClockStep = 100 * time.Microsecond

// TestStdClockMonotonicStepIsFine checks that NowMonotonic changes in steps
// that are finer than one timer interrupt. A Windows host that returns the
// interrupt time lets two events of one burst share one timestamp, and RACK
// then marks every outstanding segment as lost for each acknowledgement.
func TestStdClockMonotonicStepIsFine(t *testing.T) {
	clock := tcpip.NewStdClock()
	const wantSteps = 50
	deadline := time.Now().Add(5 * time.Second)
	prev := clock.NowMonotonic()
	smallest := time.Duration(-1)
	steps := 0
	for steps < wantSteps && time.Now().Before(deadline) {
		cur := clock.NowMonotonic()
		if cur.Before(prev) {
			t.Fatalf("NowMonotonic went back from %v to %v", prev, cur)
		}
		if cur != prev {
			steps++
			if step := cur.Sub(prev); smallest < 0 || step < smallest {
				smallest = step
			}
			prev = cur
		}
	}
	if steps < wantSteps {
		t.Fatalf("NowMonotonic changed %d times in 5s, want %d", steps, wantSteps)
	}
	if smallest > maxStdClockStep {
		t.Fatalf("smallest step of NowMonotonic = %v, want at most %v", smallest, maxStdClockStep)
	}
}

// TestStdClockMonotonicRate checks that NowMonotonic advances at the rate of
// the time package. A wrong scale of the host tick counter fails it.
func TestStdClockMonotonicRate(t *testing.T) {
	clock := tcpip.NewStdClock()
	startClock, startTime := clock.NowMonotonic(), time.Now()
	time.Sleep(100 * time.Millisecond)
	gotClock, gotTime := clock.NowMonotonic().Sub(startClock), time.Since(startTime)
	if gotClock < gotTime-20*time.Millisecond || gotClock > gotTime+20*time.Millisecond {
		t.Fatalf("NowMonotonic advanced %v while the time package advanced %v", gotClock, gotTime)
	}
}
