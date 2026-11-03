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

	"golang.org/x/sys/windows"

	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/log"
)

// NT statuses of a call on a thread or a process that is ending.
const (
	statusThreadIsTerminating  = 0xC000004B
	statusProcessIsTerminating = 0xC000010A
)

// HaveGlobalMemoryBarrier implements platform.Platform.HaveGlobalMemoryBarrier.
func (*Platform) HaveGlobalMemoryBarrier() bool { return true }

// GlobalMemoryBarrier implements platform.Platform.GlobalMemoryBarrier. It
// returns after every guest thread that ran guest code at the call has stopped
// once, and after every Sentry thread passed a barrier. A guest thread that
// waits in the spill routine or that the engine parked runs no guest code and
// needs no stop.
//
// WHY: guest threads run in stub processes, so FlushProcessWriteBuffers in the
// Sentry misses them, and the call cannot reach into a stub. The call stops a
// running thread with NtSuspendThread and GetThreadContext, then resumes it.
// The context call returns after the thread left user mode: the kernel runs
// the context request as an APC on the thread itself, and the thread then
// blocks in the suspension. The guest accesses of the thread before the stop
// precede the Sentry through that APC, and the guest accesses after the resume
// follow the Sentry through the resume call. Windows documents none of this
// ordering. The design relies on the barriers that the kernel executes in an
// interrupt, an APC, and a thread switch, so a regression on a Windows build
// shows up only in the stress test.
//
// A helper thread inside each stub that calls FlushProcessWriteBuffers has the
// documented guarantee. It needs the normal thread exit path of Windows, and
// the engine starts every stub thread without loader initialization, because
// the initial thread of the stub stays parked at the loader breakpoint. No
// test covers that exit path. The suspension needs no new thread, so the host
// lockdown and the one-process job limit do not matter. It adds no debug
// event, so it never waits for the pump.
//
// The call holds th.mu of every thread from before the first suspension until
// after the last resume, like every other operation on a suspend count, so it
// cannot leave a thread with the wrong count. barrierMu serializes the calls.
// The call locks every thread before it suspends any, so a suspended guest
// thread never waits for a lock that another operation holds.
//
// Suspending all threads first and reading the contexts afterwards overlaps
// the time that each thread needs to leave user mode.
func (p *Platform) GlobalMemoryBarrier() error {
	// The full barrier orders the stores of the calling task before the reads
	// of the thread states below.
	p.barrierFence.Add(1)
	// Threads of the Sentry pass a barrier here. The guest threads need the
	// stops below.
	procFlushProcessWriteBuffers.Call()

	p.barrierMu.Lock()
	defer p.barrierMu.Unlock()

	held := lockAllThreads(p.dbg.stubs())
	defer func() {
		for _, th := range held {
			th.mu.Unlock()
		}
	}()

	var errs []error
	var stopped []*thread
	for _, th := range held {
		if !th.mayRunGuest() {
			continue
		}
		if err := ntSuspendThread(th.h); err != nil {
			errs = append(errs, th.stopErr(err))
			continue
		}
		stopped = append(stopped, th)
	}
	// The thread context request waits until the thread is off the processor.
	for _, th := range stopped {
		errs = append(errs, th.stopErr(th.getContext(ctxFlagControl)))
	}
	for _, th := range stopped {
		th.barrierStops.Add(1)
		errs = append(errs, th.stopErr(ntResumeThread(th.h)))
	}
	if err := errors.Join(errs...); err != nil {
		log.Warningf("systrap: memory barrier: %v", err)
		return unix.EAGAIN
	}
	return nil
}

// lockAllThreads locks th.mu of every thread of the stubs. It never waits for
// one lock while it holds another: a thread that waits for an event of the
// debug pump while it holds its lock needs the Switch of another thread to
// reply, and that Switch needs its own lock. When a lock is busy, the call
// releases every lock it holds, waits until the busy lock is free, and starts
// again.
func lockAllThreads(stubs []*stubProc) []*thread {
	var all []*thread
	for _, sp := range stubs {
		sp.mu.Lock()
		for _, th := range sp.threads {
			all = append(all, th)
		}
		sp.mu.Unlock()
	}
	held := make([]*thread, 0, len(all))
	for {
		held = held[:0]
		var busy *thread
		for _, th := range all {
			if !th.mu.TryLock() {
				busy = th
				break
			}
			held = append(held, th)
		}
		if busy == nil {
			return held
		}
		for _, th := range held {
			th.mu.Unlock()
		}
		busy.mu.Lock()
		busy.mu.Unlock()
	}
}

// mayRunGuest reports whether the thread can run guest code. A parked thread,
// a thread that waits in the spill routine, the initial thread of the stub, a
// thread of a dead stub, and a thread that destroy removed need no stop.
// Callers hold th.mu.
func (th *thread) mayRunGuest() bool {
	if th.ctx == nil || th.parked || th.sp.dead.Load() {
		return false
	}
	if f := th.fast.Load(); f != nil && f.inSpill {
		return false
	}
	// destroy removes the thread before it closes the handle.
	return th.sp.thread(th.tid) == th
}

// stopErr drops an error that the end of the thread or of its stub caused. The
// thread runs no guest code then.
func (th *thread) stopErr(err error) error {
	if err == nil || th.sp.dead.Load() {
		return nil
	}
	var nt *ntError
	if errors.As(err, &nt) && (nt.Status == statusThreadIsTerminating || nt.Status == statusProcessIsTerminating) {
		return nil
	}
	// GetThreadContext reports a Win32 error that names no cause. A thread
	// object in the signaled state has exited.
	if ev, werr := windows.WaitForSingleObject(th.h, 0); werr == nil && ev == windows.WAIT_OBJECT_0 {
		return nil
	}
	return err
}
