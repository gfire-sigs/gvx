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
	"maps"
	"slices"

	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/log"
)

// HaveGlobalMemoryBarrier implements platform.Platform.HaveGlobalMemoryBarrier.
func (*Platform) HaveGlobalMemoryBarrier() bool { return true }

// GlobalMemoryBarrier implements platform.Platform.GlobalMemoryBarrier. It
// returns after every guest thread that ran guest code at the call has stopped
// once. A thread that waits in the spill routine or that the engine parked
// runs no guest code and needs no stop.
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
// event, so it never waits for the pump. It holds th.mu like every other
// operation on a suspend count, so it cannot leave a thread with the wrong
// count.
func (p *Platform) GlobalMemoryBarrier() error {
	// The full barrier orders the stores of the calling task before the reads
	// of the thread states below.
	p.barrierFence.Add(1)
	var errs []error
	for _, sp := range p.dbg.stubs() {
		errs = append(errs, sp.memoryBarrier())
	}
	if err := errors.Join(errs...); err != nil {
		log.Warningf("systrap: memory barrier: %v", err)
		return unix.EAGAIN
	}
	return nil
}

// memoryBarrier stops every running thread of the stub once.
func (sp *stubProc) memoryBarrier() error {
	sp.mu.Lock()
	threads := slices.Collect(maps.Values(sp.threads))
	sp.mu.Unlock()
	var errs []error
	for _, th := range threads {
		errs = append(errs, th.memoryBarrier())
	}
	return errors.Join(errs...)
}

// memoryBarrier stops the thread once when it can run guest code. A thread that
// died with its stub needs no stop.
func (th *thread) memoryBarrier() error {
	th.mu.Lock()
	defer th.mu.Unlock()
	if th.ctx == nil || th.parked || th.sp.dead.Load() {
		return nil
	}
	if f := th.fast.Load(); f != nil && f.inSpill {
		return nil
	}
	if th.sp.thread(th.tid) != th {
		// destroy removed the thread before it closed the handle.
		return nil
	}
	if err := ntSuspendThread(th.h); err != nil {
		return th.stopErr(err)
	}
	// The thread context request waits until the thread is off the processor.
	err := th.getContext(ctxFlagControl)
	if rerr := ntResumeThread(th.h); rerr != nil {
		err = errors.Join(err, rerr)
	}
	return th.stopErr(err)
}

// stopErr drops an error that the death of the stub caused.
func (th *thread) stopErr(err error) error {
	if err != nil && th.sp.dead.Load() {
		return nil
	}
	return err
}
