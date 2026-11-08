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

//go:build linux

package systrap

import (
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/log"
)

// idleStubLimit returns the maximum number of idle stubs that globalPool
// keeps. The value is a constant of the build (see defaultIdleStubLimit). A
// test replaces the function to force another bound, and restores it before
// it ends.
var idleStubLimit = defaultIdleStubLimit

// requestStop asks the request loop of a stub to return. The loop closes done
// just before it returns.
type requestStop struct {
	done chan struct{}
}

// destroyIdle ends a live stub that globalPool refused to keep. It frees every
// host resource of the stub, so that nothing of the stub outlives the call.
//
// Preconditions:
//   - The reference count of s is zero, so no shared context uses s.
//   - s is not in globalPool.available.
//   - s is not the source stub of globalPool.
//   - The caller holds no lock of s and no lock of globalPool.
//
// Lock order: destroyIdle never holds two locks at the same time. It takes
// s.aliveMu inside killIdle, s.sysmsgThreadsMu inside freeSysmsgThreads, and
// the lock of memoryFile inside DecRef. createSysmsgThreadLocked takes
// s.aliveMu before s.sysmsgThreadsMu, so no cycle exists.
func (s *subprocess) destroyIdle() {
	if s == globalPool.source {
		panic("systrap: destroyIdle called on the source stub")
	}
	s.killIdle()
	s.stopRequestLoop()
	s.reapStub()
	s.freeSyscallThread()
	s.freeSysmsgThreads()
	s.freeSharedRegions()
}

// killIdle marks s dead and sends SIGKILL to the stub process.
//
// It does what kill does, but it does not call wakeAllContexts. No context
// sleeps on an idle stub, and wakeAllContexts writes one page for each of the
// maxGuestContexts slots, which commits all of the thread context region.
func (s *subprocess) killIdle() {
	s.dead.Store(true)
	// Wait for a createSysmsgThread that is still in flight, as kill does.
	s.aliveMu.Lock()
	defer s.aliveMu.Unlock()
	s.syscallThread.thread.kill()
}

// stopRequestLoop returns when the request loop of s has returned.
//
// The loop answers each request that is in flight with a failure, because s is
// dead. No new sender exists, because every sender checks s.dead first.
func (s *subprocess) stopRequestLoop() {
	stop := requestStop{done: make(chan struct{})}
	s.requests <- stop
	<-stop.done
}

// reapStub collects the exit status of the stub process.
func (s *subprocess) reapStub() {
	reapChild(int(s.syscallThread.thread.tgid))
}

// reapChild collects the exit status of the process pid with wait4, and
// waits until the process exits. It returns at once when the Sentry is not the
// parent of pid.
//
// The sysmsg threads of a stub are processes without CLONE_THREAD and without
// CLONE_PARENT. They are children of the stub, and they carry
// PR_SET_PDEATHSIG with SIGKILL, so the kernel kills them when the stub exits.
// The init process of the host reaps them. Only when the Sentry is the init
// process of a PID namespace, or a child subreaper, does the Sentry own them,
// and reapChild then collects them.
//
// The blocking wait follows a successful non-blocking wait4. Only the Sentry
// reaps its own children, so the process of pid cannot be gone and replaced.
func reapChild(pid int) {
	var status unix.WaitStatus
	options := unix.WALL | unix.WNOHANG
	for {
		reaped, err := unix.Wait4(pid, &status, options, nil)
		switch {
		case err == unix.EINTR:
		case err == unix.ECHILD:
			return
		case err != nil:
			log.Warningf("systrap: wait4 of process %d failed: %v", pid, err)
			return
		case reaped == 0:
			// The process is a child that has not exited yet. Wait for it.
			options = unix.WALL
		default:
			return
		}
	}
}

// freeSyscallThread closes the seccomp listener of the stub and releases the
// message area of its syscall thread.
//
// Closing the listener closes a descriptor of the Sentry. The stubs share the
// descriptor table of the Sentry (CLONE_FILES), so the listener lives there.
func (s *subprocess) freeSyscallThread() {
	t := s.syscallThread
	if t.seccompNotify != nil {
		if err := t.seccompNotify.Close(); err != nil {
			log.Warningf("systrap: close of seccomp listener failed: %v", err)
		}
	}
	if t.sentryAddr != 0 {
		unmapFromSentry(t.sentryAddr, syscallThreadMessageSize)
		t.sentryAddr = 0
	}
	s.memoryFile.DecRef(t.stackRange)
}

// freeSysmsgThreads waits for each sysmsg thread that the Sentry owns, then
// unmaps its stack from the Sentry and releases it.
func (s *subprocess) freeSysmsgThreads() {
	s.sysmsgThreadsMu.Lock()
	defer s.sysmsgThreadsMu.Unlock()
	for _, t := range s.sysmsgThreads {
		reapChild(int(t.thread.tid))
		t.unmapStackFromSentry()
		s.memoryFile.DecRef(t.stackRange)
	}
	clear(s.sysmsgThreads)
}

// freeSharedRegions unmaps the context queue and the thread context region
// from the Sentry and releases them.
func (s *subprocess) freeSharedRegions() {
	unmapFromSentry(uintptr(unsafe.Pointer(s.contextQueue)), uintptr(s.contextQueueRange.Length()))
	s.memoryFile.DecRef(s.contextQueueRange)
	s.contextQueue = nil

	unmapFromSentry(s.threadContextRegion, uintptr(s.threadContextRange.Length()))
	s.memoryFile.DecRef(s.threadContextRange)
	s.threadContextRegion = 0
}

// unmapFromSentry removes a mapping of the memory file from the Sentry address
// space. A failure means that the Sentry lost track of its own mappings, so it
// panics, as the other unmap paths of the engine do.
func unmapFromSentry(addr, length uintptr) {
	if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, addr, length, 0); errno != 0 {
		panic(fmt.Sprintf("systrap: munmap(%#x, %#x) of a stub region failed: %v", addr, length, errno))
	}
}
