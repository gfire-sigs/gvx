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

//go:build darwin && arm64

package hvf

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

func TestPlatformReportsGlobalMemoryBarrier(t *testing.T) {
	plat := newTestPlatform(t)
	if !plat.HaveGlobalMemoryBarrier() {
		t.Fatal("HaveGlobalMemoryBarrier() = false, want true")
	}
}

func TestGlobalMemoryBarrierReturnsWhenNoGuestRuns(t *testing.T) {
	plat := newTestPlatform(t)
	if err := plat.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier before any vCPU exists = %v", err)
	}
	g := newGuest(t, plat, insnSVC0)
	if sig, _, err := g.switchOnce(); sig != nil || err != nil {
		t.Fatalf("warm-up Switch = (%v, %v)", sig, err)
	}
	if err := plat.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier with an idle vCPU = %v", err)
	}
}

func TestGlobalMemoryBarrierForcesARunningVCPUThroughAnExit(t *testing.T) {
	plat := newTestPlatform(t)
	// The guest never traps by itself, so only a kick makes its vCPU exit.
	g := newGuest(t, plat, insnBSelf)
	res := g.switchAsync()
	waitInGuest(t, g.ctx)
	g.ctx.hw.mu.Lock()
	w := g.ctx.hw.worker
	g.ctx.hw.mu.Unlock()

	// A barrier that finds the vCPU in the guest returns only after an exit. A
	// later barrier can find the vCPU between two entries, so only the first
	// call has a fixed expectation.
	before := w.exits.Load()
	if err := plat.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier = %v", err)
	}
	if after := w.exits.Load(); after == before {
		t.Fatalf("GlobalMemoryBarrier returned while the vCPU still ran the same guest entry (exits stayed at %d)", after)
	}
	for i := range 20 {
		if err := plat.GlobalMemoryBarrier(); err != nil {
			t.Fatalf("barrier %d: %v", i, err)
		}
	}

	g.ctx.Interrupt()
	if got := receive(t, res); !errors.Is(got.err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch = (%v, %v), want ErrContextInterrupt: the barrier must not end the guest run by itself", got.sig, got.err)
	}
	if g.ac.IP() != uintptr(guestCodeAddr) {
		t.Fatalf("IP = %#x, want the loop at %#x", g.ac.IP(), guestCodeAddr)
	}
}

func TestGlobalMemoryBarrierCompletesUnderConcurrentSystemCalls(t *testing.T) {
	const (
		guests    = 4
		callers   = 3
		perCaller = 150
	)
	plat := newTestPlatform(t)
	var stop atomic.Bool
	var runners sync.WaitGroup
	for range guests {
		g := newGuest(t, plat, insnAddX1One, insnSVC0, 0x17fffffe) // ADD X1,X1,#1; SVC #0; B .-8
		runners.Add(1)
		go func() {
			defer runners.Done()
			for !stop.Load() {
				if sig, _, err := g.switchOnce(); sig != nil || err != nil {
					t.Errorf("Switch = (%v, %v), want a system call", sig, err)
					return
				}
			}
		}()
	}
	var barriers sync.WaitGroup
	for range callers {
		barriers.Add(1)
		go func() {
			defer barriers.Done()
			for range perCaller {
				if err := plat.GlobalMemoryBarrier(); err != nil {
					t.Errorf("GlobalMemoryBarrier = %v", err)
					return
				}
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		barriers.Wait()
		stop.Store(true)
		runners.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("barriers or guests did not finish: a barrier call stalled")
	}
}
