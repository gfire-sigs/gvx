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
	"runtime"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// ptraceWorker pins every Linux ptrace operation in systrap to one OS thread.
// On Linux kernels older than 6.17, per-thread Landlock calls allocate distinct
// landlock_hierarchy nodes. Linux domain_scope_le compares pointer identity on
// those nodes during PTRACE_ATTACH, rejecting sibling threads with EPERM.
// Forking globalPool.source and running all ptrace calls on the same locked OS
// thread preserves pointer identity across every stub. Keeping that OS thread
// alive also prevents premature PR_SET_PDEATHSIG termination of source and
// CLONE_PARENT stubs.
//
// Concurrency invariants:
//   - Every runOnPtraceThread callback attaches and detaches within one call and
//     never re-enters runOnPtraceThread.
//   - Channel waits on source.requests (requestStub) and s.requests
//     (requestThread) stay outside runOnPtraceThread.
//   - Callers acquire s.aliveMu before runOnPtraceThread; leaf locks
//     (s.syscallThreadMu, s.sysmsgThreadsMu, memoryFile) stay inside.
//   - Extra runtime.LockOSThread calls balance syscallThread.detach so the
//     worker never unlocks its OS thread.
//   - RefreshSourceForLockdown reaps oldSource before stopping the prior worker
//     so PR_SET_PDEATHSIG never fires on a live stub.
type ptraceWorker struct {
	work chan ptraceWork
	stop chan struct{}
	done chan struct{}
}

type ptraceWork struct {
	fn   func()
	done chan struct{}
}

var (
	ptraceWorkerMu     sync.Mutex
	activePtraceWorker atomic.Pointer[ptraceWorker]
)

func startPtraceWorker(initFn func() error) (*ptraceWorker, error) {
	w := &ptraceWorker{
		work: make(chan ptraceWork),
		stop: make(chan struct{}),
		done: make(chan struct{}),
	}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Never unlock this OS thread on exit so the Go runtime retires it
		// instead of returning a Landlock-confined thread to the general pool.
		defer close(w.done)

		workerTID := unix.Gettid()
		if initFn != nil {
			if err := initFn(); err != nil {
				ready <- err
				return
			}
		}
		ready <- nil

		for {
			select {
			case <-w.stop:
				return
			case req := <-w.work:
				req.fn()
				if got := unix.Gettid(); got != workerTID {
					panic(fmt.Sprintf("systrap: ptrace worker migrated from tid %d to %d", workerTID, got))
				}
				close(req.done)
			}
		}
	}()
	if err := <-ready; err != nil {
		<-w.done
		return nil, err
	}
	return w, nil
}

func (w *ptraceWorker) run(fn func()) {
	done := make(chan struct{})
	select {
	case w.work <- ptraceWork{fn: fn, done: done}:
		<-done
	case <-w.stop:
		panic("systrap: ptrace worker stopped while dispatching work")
	}
}

func (w *ptraceWorker) close() {
	close(w.stop)
	<-w.done
}

func currentPtraceWorker() *ptraceWorker {
	if w := activePtraceWorker.Load(); w != nil {
		return w
	}
	ptraceWorkerMu.Lock()
	defer ptraceWorkerMu.Unlock()
	if w := activePtraceWorker.Load(); w != nil {
		return w
	}
	w, err := startPtraceWorker(nil)
	if err != nil {
		panic(fmt.Sprintf("systrap: start initial ptrace worker: %v", err))
	}
	activePtraceWorker.Store(w)
	return w
}

func runOnPtraceThread(fn func()) {
	currentPtraceWorker().run(fn)
}

func (s *subprocess) requestUntracedStub() (*thread, error) {
	req := requestStub{done: make(chan *thread, 1)}
	s.requests <- req
	childT := <-req.done
	if childT == nil {
		return nil, fmt.Errorf("createStub: failed to get clone")
	}
	return childT, nil
}

func (s *subprocess) initSyscallThreadOnWorker(ptraceThread *thread, seccompNotify bool) error {
	// syscallThread.detach calls runtime.UnlockOSThread on success; lock once
	// beforehand so the ptrace worker stays pinned to its OS thread.
	runtime.LockOSThread()
	if err := s.initSyscallThread(ptraceThread, seccompNotify); err != nil {
		runtime.UnlockOSThread()
		return err
	}
	return nil
}

func (s *subprocess) initPtraceSyscallThread(create func() (*thread, error), seccompNotify bool) error {
	if seccompNotify {
		childT, err := globalPool.source.requestUntracedStub()
		if err != nil {
			return err
		}
		var initErr error
		runOnPtraceThread(func() {
			if err := childT.attach(); err != nil {
				childT.kill()
				reapChild(int(childT.tgid))
				initErr = err
				return
			}
			childT.grabInitRegs()
			s.sysmsgInitRegs = childT.initRegs
			if err := s.initSyscallThreadOnWorker(childT, true); err != nil {
				childT.kill()
				reapChild(int(childT.tgid))
				initErr = err
			}
		})
		return initErr
	}

	var initErr error
	runOnPtraceThread(func() {
		ptraceThread, err := create()
		if err != nil {
			initErr = err
			return
		}
		s.sysmsgInitRegs = ptraceThread.initRegs
		if err := s.initSyscallThreadOnWorker(ptraceThread, false); err != nil {
			ptraceThread.kill()
			reapChild(int(ptraceThread.tgid))
			initErr = err
		}
	})
	return initErr
}

func (s *subprocess) runPtraceSyscallRequest(req any) {
	runOnPtraceThread(func() {
		// handlePtraceSyscallRequest unlocks once on defer and once inside
		// syscallThread.detach when attach succeeds; add one lock here.
		runtime.LockOSThread()
		s.handlePtraceSyscallRequest(req)
	})
}

func (s *subprocess) runSysmsgThreadInit(p *thread) error {
	var err error
	runOnPtraceThread(func() {
		err = s.initSysmsgThread(p)
		if err != nil {
			unix.RawSyscall6(unix.SYS_PTRACE, unix.PTRACE_DETACH, uintptr(p.tid), 0, uintptr(unix.SIGSTOP), 0, 0)
		}
	})
	return err
}

// RefreshSourceForLockdown spawns a Landlock-confined ptrace worker and forks a
// replacement globalPool.source on that OS thread before seccomp blocks clone.
func (p *Systrap) RefreshSourceForLockdown() error {
	return p.refreshSourceForLockdown(nil)
}

func (p *Systrap) refreshSourceForLockdown(initWorker func() error) error {
	for sp := globalPool.fetchAvailable(); sp != nil; sp = globalPool.fetchAvailable() {
		sp.destroyIdle()
	}
	if globalPool.source == nil {
		return nil
	}

	newWorker, err := startPtraceWorker(initWorker)
	if err != nil {
		return fmt.Errorf("systrap: refresh source stub for lockdown: %w", err)
	}

	ptraceWorkerMu.Lock()
	oldWorker := activePtraceWorker.Swap(newWorker)
	ptraceWorkerMu.Unlock()

	newSource, err := newSubprocess(createStubWithoutRseq, globalPool.source.memoryFile, false, disableSyscallPatching)
	if err != nil {
		ptraceWorkerMu.Lock()
		activePtraceWorker.Store(oldWorker)
		ptraceWorkerMu.Unlock()
		newWorker.close()
		return fmt.Errorf("systrap: refresh source stub for lockdown: %w", err)
	}
	newSource.DecRef(nil)

	oldSource := globalPool.source
	globalPool.source = newSource
	oldSource.destroyIdle()
	if oldWorker != nil {
		oldWorker.close()
	}
	return nil
}
