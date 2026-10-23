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
	"sync"
	"time"

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// thread is one guest thread: a thread of a stub process.
//
// A thread is parked or running. A parked thread has a suspend count of one,
// and its registers live in the Sentry. A running thread has a count of zero.
// The thread stops by raising an exception that the debugger delivers to
// events. The Sentry parks the thread before it replies to the event, so the
// rest of the stub process runs while the Sentry serves a long system call.
type thread struct {
	sp  *stubProc
	h   windows.Handle
	tid uint32

	// events receives the exceptions that the debugger routes to this thread.
	events chan debugEvent

	// mu serializes every operation on the registers and the suspend count of
	// the thread. Switch holds it while it owns the thread, and a forced stop
	// holds it for the whole stop.
	mu sync.Mutex
	// ctx is the scratch CONTEXT record of the thread. Callers hold mu.
	ctx *hostContext
	// parked is true while the thread is suspended and no exception waits for
	// a reply. Callers hold mu.
	parked bool
	// stepping is true while the thread runs with the single-step flag that a
	// forced stop set. Callers hold mu.
	stepping bool

	// lastExecPC and execRepeats count the execute faults at one pc that the
	// engine retried without a patch. Callers hold mu.
	lastExecPC  uint64
	execRepeats int

	// closeOnce makes sure that the handle closes once. The stub process and
	// the context can both release the thread, and a second CloseHandle could
	// close a new object that reuses the handle value.
	closeOnce sync.Once

	archThread
}

func newThread(sp *stubProc, h windows.Handle, tid uint32) *thread {
	th := &thread{
		sp:     sp,
		h:      h,
		tid:    tid,
		events: make(chan debugEvent, eventSlots),
		ctx:    newHostContext(),
	}
	th.initArch()
	return th
}

// waitEvent blocks until the debugger delivers an exception, the stub dies, or
// limit passes. A zero limit waits without a time limit.
func (th *thread) waitEvent(limit time.Duration) (debugEvent, error) {
	var timeout <-chan time.Time
	if limit > 0 {
		t := time.NewTimer(limit)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case ev := <-th.events:
		return ev, nil
	case <-th.sp.deadCh:
		select {
		case ev := <-th.events:
			// Prefer an exception that arrived before the death.
			return ev, nil
		default:
		}
		return debugEvent{}, th.sp.deathError()
	case <-timeout:
		return debugEvent{}, fmt.Errorf("no stop within %v", limit)
	}
}

// getContext reads the registers of the thread into th.ctx. Callers hold mu.
func (th *thread) getContext(flags uint32) error {
	th.ctx.setFlags(flags)
	th.ctx.prepareGet()
	r, _, e := procGetThreadContext.Call(uintptr(th.h), th.ctx.ptr())
	if r == 0 {
		return th.ctxErr("GetThreadContext", e)
	}
	return nil
}

// setContext writes th.ctx to the thread. Callers hold mu.
func (th *thread) setContext() error {
	r, _, e := procSetThreadContext.Call(uintptr(th.h), th.ctx.ptr())
	if r == 0 {
		return th.ctxErr("SetThreadContext", e)
	}
	if traceEvents {
		want := th.ctx.pc()
		flags := th.ctx.u32(ctxOffFlags)
		if err := th.getContext(flags); err == nil && th.ctx.pc() != want {
			tracef("thread %d: SetThreadContext wrote pc %#x but the thread reads back %#x", th.tid, want, th.ctx.pc())
		}
	}
	return nil
}

func (th *thread) ctxErr(op string, err error) error {
	if th.sp.dead.Load() {
		return th.sp.deathError()
	}
	return fmt.Errorf("%s of thread %d: %w", op, th.tid, err)
}

// park suspends a thread that stopped at an exception and replies to the
// exception. The thread stays suspended afterwards. Callers hold mu.
func (th *thread) park(ev debugEvent) error {
	if err := ntSuspendThread(th.h); err != nil {
		return th.ctxErr("NtSuspendThread", err)
	}
	th.parked = true
	if err := th.sp.p.dbg.reply(ev); err != nil {
		return th.ctxErr("NtDebugContinue", err)
	}
	return nil
}

// resumeParked starts a parked thread with the registers in th.ctx. Callers
// hold mu.
func (th *thread) resumeParked() error {
	if err := th.setContext(); err != nil {
		return err
	}
	th.parked = false
	if err := ntResumeThread(th.h); err != nil {
		return th.ctxErr("NtResumeThread", err)
	}
	return nil
}

// continueEvent applies th.ctx to a thread that waits at an exception and
// lets it run on. Callers hold mu.
func (th *thread) continueEvent(ev debugEvent) error {
	if err := th.setContext(); err != nil {
		return err
	}
	if err := th.sp.p.dbg.reply(ev); err != nil {
		return th.ctxErr("NtDebugContinue", err)
	}
	return nil
}

// closeHandle closes the thread handle. It is safe to call more than once.
func (th *thread) closeHandle() {
	th.closeOnce.Do(func() { _ = windows.CloseHandle(th.h) })
}

// destroy terminates the thread and forgets it.
func (th *thread) destroy() {
	sp := th.sp
	sp.mu.Lock()
	if _, ok := sp.threads[th.tid]; !ok {
		sp.mu.Unlock()
		return
	}
	delete(sp.threads, th.tid)
	sp.mu.Unlock()
	th.releaseArch()
	if !sp.dead.Load() {
		_ = ntTerminateThread(th.h)
	}
	th.closeHandle()
}

// start loads the guest registers of ac into the scratch record of a parked
// thread. It loads the vector state only when loadFP is true, because the
// thread keeps its own vector registers while it is parked. The arch code adds
// the state that CONTEXT cannot carry.
func (th *thread) start(ac *arch.Context64, loadFP bool) error {
	th.mu.Lock()
	defer th.mu.Unlock()
	th.ctx.loadFrom(ac, loadFP)
	th.stepping = false
	th.lastExecPC, th.execRepeats = 0, 0
	return th.archStart(ac)
}

// run starts the parked thread with the registers that start loaded.
func (th *thread) run() error {
	th.mu.Lock()
	defer th.mu.Unlock()
	return th.resumeParked()
}

// forceStop makes a running thread stop at the next instruction boundary. It
// sets the single-step flag, so the thread raises a single-step exception
// after one more instruction.
//
// WHY: a thread that runs a tight loop raises no exception by itself. Windows
// has no signal to interrupt it. The step exception also reaches the Sentry
// through the same event path as every other stop, so no stop can overtake an
// exception that the thread raised before the Sentry suspended it.
func (th *thread) forceStop() {
	th.mu.Lock()
	defer th.mu.Unlock()
	if th.parked || th.stepping || th.sp.dead.Load() {
		return
	}
	if err := ntSuspendThread(th.h); err != nil {
		return
	}
	defer func() { _ = ntResumeThread(th.h) }()
	if err := th.getContext(ctxFlagControl); err != nil {
		return
	}
	th.ctx.setSingleStep(true)
	if err := th.setContext(); err != nil {
		return
	}
	th.stepping = true
}
