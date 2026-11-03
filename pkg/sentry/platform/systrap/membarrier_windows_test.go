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
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

func TestPlatformReportsGlobalMemoryBarrier(t *testing.T) {
	p := newPlatform(t)
	if !p.HaveGlobalMemoryBarrier() {
		t.Fatal("HaveGlobalMemoryBarrier() = false, want true")
	}
	if err := p.GlobalMemoryBarrier(); err != nil {
		t.Fatalf("GlobalMemoryBarrier with no guest thread = %v", err)
	}
}

// waitRunning returns when the thread of c runs guest code: the engine resumed
// it and no stop parked it.
func waitRunning(t testing.TB, c *Context) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if th := c.th.Load(); th != nil {
			th.mu.Lock()
			running := !th.parked
			th.mu.Unlock()
			if running {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the guest thread never started to run")
		}
		runtime.Gosched()
	}
}

type spinResult struct {
	si  *linux.SignalInfo
	err error
}

// startSpin runs the guest of r in the background and returns when its thread
// runs guest code.
func startSpin(t testing.TB, r *rig) <-chan spinResult {
	t.Helper()
	done := make(chan spinResult, 1)
	go func() {
		si, _, err := r.run()
		done <- spinResult{si, err}
	}()
	waitRunning(t, r.ctx)
	return done
}

// stopSpin interrupts a spinning guest and checks that the run ends. A thread
// that a barrier left suspended never raises the single-step stop, so the
// interrupt would not end its run.
func stopSpin(t testing.TB, r *rig, done <-chan spinResult) {
	t.Helper()
	r.ctx.Interrupt()
	select {
	case res := <-done:
		if !errors.Is(res.err, platform.ErrContextInterrupt) || res.si != nil {
			t.Fatalf("Switch = (%s, %v), want an interrupt", describe(res.si), res.err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("an interrupt did not stop the guest after the barriers: a barrier left the thread suspended")
	}
}

func barrierStops(r *rig) uint64 { return r.ctx.th.Load().barrierStops.Load() }

func TestGlobalMemoryBarrierStopsARunningThreadOncePerCall(t *testing.T) {
	const barriers = 50
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(gCountSpin())
	done := startSpin(t, r)
	before := barrierStops(r)
	for i := range barriers {
		if err := p.GlobalMemoryBarrier(); err != nil {
			t.Fatalf("barrier %d: %v", i, err)
		}
	}
	if got := barrierStops(r) - before; got != barriers {
		t.Fatalf("%d stops of the spinning thread for %d barriers, want one for each", got, barriers)
	}
	select {
	case res := <-done:
		t.Fatalf("Switch returned (%s, %v) after the barriers: a barrier must not stop the guest", describe(res.si), res.err)
	default:
	}
	stopSpin(t, r, done)
}

func TestGlobalMemoryBarrierStopsOnlyThreadsThatRunGuestCode(t *testing.T) {
	const barriers = 10
	p := newPlatform(t)
	a := newRig(t, p)
	a.program(gCountSpin())
	b := a.newThread()
	b.ac.SetIP(codeVA)
	b.ac.SetStack(stackVA + blockSize/2)
	c := a.newThread()
	a.mapPage(dataVA, execAccess, gSyscall(7))
	c.ac.SetIP(dataVA)
	c.ac.SetStack(stackVA + blockSize/4)

	doneA := startSpin(t, a)
	doneB := startSpin(t, b)
	// The thread of c waits in the Sentry for the result of its call.
	si, _, err := c.run()
	mustSyscall(t, si, err, 7, c.ac)

	before := [3]uint64{barrierStops(a), barrierStops(b), barrierStops(c)}
	for i := range barriers {
		if err := p.GlobalMemoryBarrier(); err != nil {
			t.Fatalf("barrier %d: %v", i, err)
		}
	}
	got := [3]uint64{barrierStops(a) - before[0], barrierStops(b) - before[1], barrierStops(c) - before[2]}
	if want := [3]uint64{barriers, barriers, 0}; got != want {
		t.Fatalf("stops of the two spinning threads and of the thread in a system call = %v, want %v", got, want)
	}
	stopSpin(t, a, doneA)
	stopSpin(t, b, doneB)
}

func TestGlobalMemoryBarrierResumesAThreadInASystemCall(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(gSyscall(41), gSyscall(42))
	si, _, err := r.run()
	mustSyscall(t, si, err, 41, r.ac)
	for i := range 10 {
		if err := p.GlobalMemoryBarrier(); err != nil {
			t.Fatalf("barrier %d: %v", i, err)
		}
	}
	si, _, err = r.run()
	mustSyscall(t, si, err, 42, r.ac)
}

func TestGlobalMemoryBarrierCompletesUnderConcurrentSystemCalls(t *testing.T) {
	const (
		threads = 4
		calls   = 200
	)
	p := newPlatform(t)
	r := newRig(t, p)
	var prog []byte
	for i := range calls {
		prog = append(prog, gSyscall(uint64(300+i))...)
	}
	r.program(prog)

	var stop atomic.Bool
	var barriers sync.WaitGroup
	for range 2 {
		barriers.Add(1)
		go func() {
			defer barriers.Done()
			for !stop.Load() {
				if err := p.GlobalMemoryBarrier(); err != nil {
					t.Errorf("GlobalMemoryBarrier = %v", err)
					return
				}
			}
		}()
	}
	var guests sync.WaitGroup
	for k := range threads {
		th := r
		if k > 0 {
			th = r.newThread()
			th.ac.SetIP(codeVA)
			th.ac.SetStack(uintptr(stackVA + blockSize/2 + k*0x100))
		}
		guests.Add(1)
		go func() {
			defer guests.Done()
			for i := range calls {
				si, _, err := th.run()
				if si != nil || err != nil || regNr(th.ac) != uint64(300+i) {
					t.Errorf("thread %d call %d: Switch = (%s, %v), number %d", k, i, describe(si), err, regNr(th.ac))
					return
				}
			}
		}()
	}
	finished := make(chan struct{})
	go func() {
		guests.Wait()
		stop.Store(true)
		barriers.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Minute):
		t.Fatal("the guest threads or the barriers did not finish")
	}
}
