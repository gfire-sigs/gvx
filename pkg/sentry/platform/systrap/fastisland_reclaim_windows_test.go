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
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These tests drive real stub threads through trampoline slots that another
// thread frees and patches again. The contract is in fastisland_windows.go.

// TestTrapFromADroppedSlotDecodesAfterThePageIsPatchedAgain starts a thread
// that publishes a trap in a slot. Before the Sentry decodes the trap, another
// thread drops the block of the slot, changes the code of the page, and patches
// it again. The new patch must not reuse the bytes or the record of the first
// slot, and the first thread must still return to its own site.
//
// The old allocator reused the freed bytes at once and deleted the retired
// record, so the decode found the slot of the new code.
func TestTrapFromADroppedSlotDecodesAfterThePageIsPatchedAgain(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	r.program(gSyscall(1), gJump(dataVA))
	oldCode, newCode := gSyscall(11), gSyscall(12, 1)
	frame := r.mapPage(dataVA, rwxAccess, oldCode)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	// Resume the first thread by hand. It runs the jump, faults once for the
	// patch, and publishes the trap of system call 11. The test does not read
	// the trap yet.
	th := r.ctx.th.Load()
	if err := th.start(r.ac, false); err != nil {
		t.Fatal(err)
	}
	if err := th.run(); err != nil {
		t.Fatal(err)
	}
	for {
		ev, trapped, err := th.waitNext()
		if err != nil {
			t.Fatal(err)
		}
		if trapped {
			break
		}
		if out := r.ctx.handleEvent(r.rctx, r.mm, r.as, th, r.ac, ev); out.done {
			t.Fatalf("the first thread stopped before the trap: %+v", out)
		}
	}

	if ok, err := r.as.restoreData(dataVA); !ok || err != nil {
		t.Fatalf("restoreData = (%v, %v), want (true, nil)", ok, err)
	}
	clear(frame)
	copy(frame, newCode)
	second := r.newThread()
	second.ac.SetIP(dataVA)
	second.ac.SetStack(stackVA + blockSize/2)
	si, _, err = second.run()
	mustSyscall(t, si, err, 12, second.ac)

	if out := r.ctx.fastTrap(r.as, th, r.ac); !out.done || out.err != nil {
		t.Fatalf("decode of the trap = %+v, want a system call", out)
	}
	if got := regNr(r.ac); got != 11 {
		t.Errorf("system call number = %d, want 11", got)
	}
	if got, want := regPC(r.ac), uint64(dataVA)+uint64(len(oldCode)); got != want {
		t.Errorf("the thread returns to %#x, want %#x behind its own system call", got, want)
	}
}

// guestLoop returns the code of a page that issues sites system calls with
// numbers base, base+1, and so on, in a loop that never ends. It also returns
// the guest address that each call returns to, relative to the start of the page.
func guestLoop(base uint64, sites int) (code []byte, returns []uint64) {
	for i := 0; i < sites; i++ {
		code = append(code, gSyscall(base+uint64(i), uint64(i))...)
		returns = append(returns, uint64(len(code)))
	}
	code = append(code, gJump(dataVA)...)
	return code, returns
}

// stressDuration is the time that the stress test runs. Set
// GVX_SLOT_STRESS_SECONDS to run it longer when you look for a rare failure.
func stressDuration() time.Duration {
	if v, err := strconv.Atoi(os.Getenv("GVX_SLOT_STRESS_SECONDS")); err == nil && v > 0 {
		return time.Duration(v) * time.Second
	}
	return 3 * time.Second
}

// TestDropAndPatchAgainWhileThreadsTrapThroughTheSlots runs threads that trap
// in a loop through the slots of one block while another goroutine drops the
// block over and over. Each drop makes the next fetch patch the page again, and
// the new slots take the place of the old ones. A thread that runs reused bytes
// or decodes a reused record returns to a wrong address or with a wrong
// register, so every trap must show the expected call, argument, and address.
//
// The patch of the same code writes the same slot bytes when the allocator
// hands out the same offsets, and such a rewrite does no harm. So the dropper
// also drops and patches a second page of a changing size in front of the block.
// The new slots of the block then take other offsets, and a slot that a thread
// still runs gets the bytes of another site.
func TestDropAndPatchAgainWhileThreadsTrapThroughTheSlots(t *testing.T) {
	const (
		sites   = 8
		threads = 6
		base    = 400
		shiftVA = dataVA + 0x4000
	)
	r := newRig(t, newFastPlatform(t))
	code, returns := guestLoop(base, sites)
	r.program(gJump(dataVA))
	r.mapPage(dataVA, rwxAccess, code)
	shiftFrame := r.mapPage(shiftVA, rwxAccess)
	shifter := r.newThread()
	shifter.ac.SetStack(stackVA + blockSize/2)

	var stop atomic.Bool
	var traps, drops atomic.Uint64
	errs := make(chan error, threads)
	var wg sync.WaitGroup
	// A Fatal call in the dropper loop must not leave the workers running.
	defer func() {
		stop.Store(true)
		wg.Wait()
	}()
	for k := 0; k < threads; k++ {
		th := r.newThread()
		th.ac.SetIP(dataVA)
		th.ac.SetStack(uintptr(stackVA + 0x800 + uint64(k)*0x100))
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; !stop.Load(); i = (i + 1) % sites {
				si, _, err := th.run()
				if si != nil || err != nil {
					errs <- fmt.Errorf("Switch returned (%s, %v) at call %d", describe(si), err, i)
					return
				}
				if got := regNr(th.ac); got != uint64(base+i) {
					errs <- fmt.Errorf("system call %d, want %d", got, base+i)
					return
				}
				if got := regArg(th.ac, 0); got != uint64(i) {
					errs <- fmt.Errorf("call %d has argument %d", i, got)
					return
				}
				if got, want := regPC(th.ac), uint64(dataVA)+returns[i]; got != want {
					errs <- fmt.Errorf("call %d returns to %#x, want %#x", i, got, want)
					return
				}
				traps.Add(1)
			}
		}()
	}
	deadline := time.Now().Add(stressDuration())
	for iter := 0; time.Now().Before(deadline) && len(errs) == 0; iter++ {
		if ok, err := r.as.restoreData(dataVA); err != nil {
			t.Fatalf("restoreData: %v", err)
		} else if ok {
			drops.Add(1)
		}
		if n := iter % 5; n != 0 {
			if _, err := r.as.restoreData(shiftVA); err != nil {
				t.Fatalf("restoreData of the second page: %v", err)
			}
			clear(shiftFrame)
			var shiftCode []byte
			for range n {
				shiftCode = append(shiftCode, gSyscall(77)...)
			}
			copy(shiftFrame, shiftCode)
			shifter.ac.SetIP(shiftVA)
			si, _, err := shifter.run()
			mustSyscall(t, si, err, 77, shifter.ac)
		}
		before := traps.Load()
		for traps.Load() == before && time.Now().Before(deadline) && len(errs) == 0 {
			runtime.Gosched()
		}
	}
	stop.Store(true)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	t.Logf("%d traps, %d drops", traps.Load(), drops.Load())
	if drops.Load() < 5 {
		t.Errorf("the block dropped %d times, want at least 5", drops.Load())
	}
}
