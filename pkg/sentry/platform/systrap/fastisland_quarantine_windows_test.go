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

package systrap

import (
	"errors"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// TestQuarantineStaysBoundedWhileAThreadRunsGuestCode runs a thread that never
// traps, so it never passes a quiescent point. Each drop of a block then adds
// slots that nothing can reclaim. The quarantine must stop at its limit, the
// block must then keep its trap sites and still serve every system call, and
// the slots must come back after the thread stops.
func TestQuarantineStaysBoundedWhileAThreadRunsGuestCode(t *testing.T) {
	const (
		spinVA = 0x5555_2000_0000
		sites  = 16
	)
	r := newRig(t, newFastPlatform(t))
	r.program(gJump(dataVA))
	var blockProg []byte
	for range sites {
		blockProg = append(blockProg, gSyscall(11)...)
	}
	r.mapPage(dataVA, rwxAccess, blockProg)
	r.mapPage(spinVA, execAccess, gCountSpin())

	spin := r.newThread()
	spin.ac.SetIP(spinVA)
	spin.ac.SetStack(stackVA + blockSize/2)
	spinDone := make(chan error, 1)
	go func() {
		_, _, err := spin.run()
		spinDone <- err
	}()
	// Wait until the thread runs, so that its reader is online.
	waitOnline := time.Now().Add(10 * time.Second)
	for {
		if th := spin.ctx.th.Load(); th != nil {
			if f := th.fast.Load(); f != nil && f.slot.reader.epoch.Load() != readerOffline {
				break
			}
		}
		if time.Now().After(waitOnline) {
			t.Fatal("the spinning thread never went online")
		}
		runtime.Gosched()
	}

	fastTraps := func() uint64 { return fastStats(t, r).traps.Load() }
	round := func() {
		t.Helper()
		si, _, err := r.run()
		mustSyscall(t, si, err, 11, r.ac)
	}
	round()
	quarantine := func() (units, islands int) {
		r.as.mu.Lock()
		defer r.as.mu.Unlock()
		return r.as.quarantineUnitsLocked(), len(r.as.islands)
	}

	var stalled int
	for i := 0; i < 400 && stalled < 3; i++ {
		if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
			t.Fatalf("round %d: restoreData = (%v, %v), want (true, nil)", i, ok, err)
		}
		r.ac.SetIP(dataVA)
		before := fastTraps()
		round()
		if fastTraps() == before {
			stalled++
		} else {
			stalled = 0
		}
	}
	if stalled < 3 {
		t.Fatal("the quarantine never filled, so the test did not reach the limit")
	}
	held, islands := quarantine()
	if limit := winQuarantineLimit + 2*winIslandUnits; held > limit {
		t.Errorf("the quarantine holds %d units, want at most %d", held, limit)
	}
	if limit := winQuarantineLimit/winIslandUnits + 3; islands > limit {
		t.Errorf("the address space has %d islands, want at most %d", islands, limit)
	}

	// The thread stops, which parks it, so it holds no slot.
	spin.ctx.Interrupt()
	select {
	case err := <-spinDone:
		if !errors.Is(err, platform.ErrContextInterrupt) {
			t.Fatalf("the spinning thread returned %v, want an interrupt", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the interrupt did not stop the spinning thread")
	}
	if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
		t.Fatalf("restoreData = (%v, %v), want (true, nil)", ok, err)
	}
	r.ac.SetIP(dataVA)
	before := fastTraps()
	round()
	if fastTraps() == before {
		t.Error("the block still has no slots after every thread passed a quiescent point")
	}
	if after, _ := quarantine(); after >= held {
		t.Errorf("the quarantine holds %d units after the thread stopped, was %d", after, held)
	}
}

// TestHotResumeRunsTheTailOfAQuarantinedSlot publishes a trap in a slot and
// lets another thread drop the block and patch the same code again before the
// Sentry reads the trap. The slot is Quarantined then. The thread must resume
// hot through the intact tail of the old slot, return to the code behind its
// site, and trap again at the next call.
func TestHotResumeRunsTheTailOfAQuarantinedSlot(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSyscall(1), gJump(dataVA))
	code := append(gSyscall(11), gSyscall(12)...)
	r.mapPage(dataVA, rwxAccess, code)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	th := r.ctx.th.Load()
	waitTrap := func() {
		t.Helper()
		for {
			ev, trapped, err := th.waitNext()
			if err != nil {
				t.Fatal(err)
			}
			if trapped {
				return
			}
			if out := r.ctx.handleEvent(r.rctx, r.mm, r.as, th, r.ac, ev); out.done {
				t.Fatalf("the thread stopped before its trap: %+v", out)
			}
		}
	}
	if err := th.start(r.ac, false); err != nil {
		t.Fatal(err)
	}
	if err := th.run(); err != nil {
		t.Fatal(err)
	}
	waitTrap()

	if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
		t.Fatalf("restoreData = (%v, %v), want (true, nil)", ok, err)
	}
	second := r.newThread()
	second.ac.SetIP(dataVA)
	second.ac.SetStack(stackVA + blockSize/2)
	si, _, err = second.run()
	mustSyscall(t, si, err, 11, second.ac)

	if out := r.ctx.fastTrap(r.as, th, r.ac); !out.done || out.err != nil {
		t.Fatalf("decode of the trap = %+v, want a system call", out)
	}
	mustSyscall(t, nil, nil, 11, r.ac)
	colds := fastStats(t, r).colds.Load()
	if err := th.start(r.ac, false); err != nil {
		t.Fatal(err)
	}
	if got := fastStats(t, r).resume; got != winStateRunHot {
		t.Fatalf("resume state = %d, want the hot state %d", got, winStateRunHot)
	}
	if err := th.run(); err != nil {
		t.Fatal(err)
	}
	waitTrap()
	if out := r.ctx.fastTrap(r.as, th, r.ac); !out.done || out.err != nil {
		t.Fatalf("decode of the second trap = %+v, want a system call", out)
	}
	mustSyscall(t, nil, nil, 12, r.ac)
	if got := fastStats(t, r).colds.Load(); got != colds {
		t.Errorf("the thread resumed cold %d times, want none", got-colds)
	}
}
