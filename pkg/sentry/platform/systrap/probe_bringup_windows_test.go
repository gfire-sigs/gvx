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
	"strconv"
	"testing"
	"time"
)

// TestProbeBringUp brings up many stubs through the production path and
// prints the attempts that each request needed and the time of each phase.
// It is a measurement: it fails only when a request runs out of attempts.
func TestProbeBringUp(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("GVX_PROBE_BRINGUP"))
	if n <= 0 {
		t.Skip("set GVX_PROBE_BRINGUP=<count> to run the probe")
	}
	p := newPlatform(t)
	stopPoolForTest(p)
	hist := map[uint64]int{}
	var worst uint64
	var total, slowest time.Duration
	a0, d0 := bringUpStats.attempts.Load(), bringUpStats.discarded.Load()
	h0, w0 := bringUpStats.hostNs.Load(), bringUpStats.windowNs.Load()
	for range n {
		before := bringUpStats.attempts.Load()
		t0 := time.Now()
		sp, err := p.newStubProcFresh()
		d := time.Since(t0)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		total += d
		slowest = max(slowest, d)
		a := bringUpStats.attempts.Load() - before
		hist[a]++
		worst = max(worst, a)
		sp.destroy()
	}
	attempts := bringUpStats.attempts.Load() - a0
	fmt.Printf("PROBEBRINGUP windows=%d requests=%d attempts=%d discarded=%d avgAttempts=%.4f maxAttempts=%d hist=%v avgRequest=%v maxRequest=%v avgHostPerAttempt=%v avgReservePerAttempt=%v\n",
		len(p.layout), n, attempts, bringUpStats.discarded.Load()-d0, float64(attempts)/float64(n), worst, hist,
		total/time.Duration(n), slowest,
		time.Duration((bringUpStats.hostNs.Load()-h0)/attempts), time.Duration((bringUpStats.windowNs.Load()-w0)/attempts))
}
