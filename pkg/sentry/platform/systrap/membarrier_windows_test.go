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

func TestGlobalMemoryBarrierLeavesASpinningThreadRunning(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(gCountSpin())
	type result struct {
		si  *linux.SignalInfo
		err error
	}
	done := make(chan result, 1)
	go func() {
		si, _, err := r.run()
		done <- result{si, err}
	}()
	waitRunning(t, r.ctx)
	for i := range 50 {
		if err := p.GlobalMemoryBarrier(); err != nil {
			t.Fatalf("barrier %d: %v", i, err)
		}
	}
	select {
	case res := <-done:
		t.Fatalf("Switch returned (%s, %v) after the barriers: a barrier must not stop the guest", describe(res.si), res.err)
	default:
	}
	// A thread that a barrier left suspended never raises the single-step stop,
	// so this interrupt would not end the run.
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

func TestGlobalMemoryBarrierWithAThreadInASystemCall(t *testing.T) {
	p := newPlatform(t)
	r := newRig(t, p)
	r.program(gSyscall(41), gSyscall(42))
	si, _, err := r.run()
	mustSyscall(t, si, err, 41, r.ac)
	// The thread waits in the Sentry for the result of the first call.
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
