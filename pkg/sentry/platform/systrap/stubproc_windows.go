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
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
)

const (
	// winBase and winLimit bound the guest window of a stub process. The window
	// is one placeholder that the Sentry reserves before the loader runs, so
	// the loader and the kernel place the stack, the heaps, and the system DLLs
	// elsewhere. The range sat free in every one of the stub processes that the
	// probes created on windows-latest and windows-11-arm (docs/systrap-windows.md).
	winBase  = uint64(0x100000000000) // 16 TiB
	winLimit = uint64(0x7EE000000000)

	// internalSize is the part of the window that the engine keeps for itself,
	// at the top: the engine pages, then one area for each fast thread. The
	// guest never sees it, because MaxUserAddress lies below it.
	internalSize = uint64(winArenaSize)
	internalBase = winLimit - internalSize

	// lowBase and lowLimit bound the low guest window. A non-PIE executable
	// runs at the address that it links to. Go links an arm64 program at
	// 0x10000, and most linkers use 0x400000. lowBase is the lowest address of a
	// Windows process. lowLimit is the address of KUSER_SHARED_DATA, which every
	// process maps. The range was free in every suspended stub that the probes
	// created on windows-latest and windows-11-arm. A placeholder over the range
	// kept the loader out of it. The Sentry reserves it before the loader runs.
	lowBase  = uint64(0x10000)
	lowLimit = uint64(0x7FFE0000)

	// codeSize is the size of the executable part of the engine pages. The
	// data pages follow it.
	codeSize = winCodeSize

	// startTimeout bounds the wait for a new stub process or thread to reach its
	// first stop.
	startTimeout = 20 * time.Second
)

var (
	errStubDead     = errors.New("the stub process died")
	errWindowTaken  = errors.New("the guest window is not free in the new stub process")
	errStubReleased = errors.New("the stub process is released")
)

// stubProc is one stub process. A stub holds the guest address space of one
// Linux process and one thread for each guest thread.
type stubProc struct {
	p     *Platform
	pid   uint32
	proc  windows.Handle
	main  windows.Handle
	level confinement

	mu      sync.Mutex
	threads map[uint32]*thread
	closed  bool

	dead    atomic.Bool
	deadCh  chan struct{}
	deadErr atomic.Pointer[error]

	// unknownThread and droppedEvents count events that the debugger could not
	// route. Both stay zero unless guest code runs NT services directly.
	unknownThread atomic.Uint64
	droppedEvents atomic.Uint64

	// internal is the section behind the engine pages of the window.
	internal *anonSection

	// owner is the address space of the stub. The thread code reads the
	// trampoline islands through it.
	owner atomic.Pointer[addressSpace]

	// fast holds the fast slots of the stub. Callers hold mu.
	fast fastSlots

	archProc
}

// thread returns the guest thread with the given ID.
func (sp *stubProc) thread(tid uint32) *thread {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.threads[tid]
}

// markDead records the death of the stub and wakes every waiter, including a
// Sentry thread that sleeps on the event of a fast thread.
func (sp *stubProc) markDead(err error) {
	if sp.dead.Swap(true) {
		return
	}
	sp.deadErr.Store(&err)
	close(sp.deadCh)
	sp.wakeFastThreads()
}

func (sp *stubProc) deathError() error {
	if e := sp.deadErr.Load(); e != nil {
		return fmt.Errorf("%w: %v", errStubDead, *e)
	}
	return errStubDead
}

// bringUpStub creates a stub process that is ready to run guest threads: it
// has the guest window reserved, the loader finished, and its initial thread
// parked for good.
func (p *Platform) bringUpStub() (*stubProc, error) {
	t0 := time.Now()
	sh, err := p.host.newStub()
	if err != nil {
		return nil, err
	}
	bringUpStats.hostNs.Add(uint64(time.Since(t0)))
	sp := &stubProc{
		p: p, pid: sh.pid, proc: sh.proc, main: sh.thread, level: sh.level,
		threads: make(map[uint32]*thread),
		deadCh:  make(chan struct{}),
	}
	fail := func(err error) (*stubProc, error) {
		sp.destroy()
		return nil, err
	}
	// The initial thread has not run. Registering it first lets the debugger
	// route its initial breakpoint.
	th0 := newThread(sp, sh.thread, sh.tid)
	th0.ctx = nil // The initial thread never runs guest code.
	sp.threads[sh.tid] = th0
	p.dbg.register(sp)
	t1 := time.Now()
	if err := virtualAllocPlaceholder(sp.proc, uintptr(winBase), uintptr(winLimit-winBase)); err != nil {
		return fail(fmt.Errorf("%w: %v", errWindowTaken, err))
	}
	if p.lowWindow {
		if err := virtualAllocPlaceholder(sp.proc, uintptr(lowBase), uintptr(lowLimit-lowBase)); err != nil {
			return fail(fmt.Errorf("%w: low window: %v", errWindowTaken, err))
		}
	}
	bringUpStats.windowNs.Add(uint64(time.Since(t1)))
	t2 := time.Now()
	if err := ntResumeThread(sp.main); err != nil {
		return fail(err)
	}
	// The loader finishes and raises the initial breakpoint of a debuggee. The
	// stub is then fully initialized, and nothing else of its image ever runs.
	ev, err := th0.waitEvent(startTimeout)
	if err != nil {
		return fail(fmt.Errorf("wait for the loader of the stub: %w", err))
	}
	if err := ntSuspendThread(sp.main); err != nil {
		return fail(err)
	}
	if err := p.dbg.reply(ev); err != nil {
		return fail(err)
	}
	bringUpStats.loaderNs.Add(uint64(time.Since(t2)))
	bringUpStats.stubs.Add(1)
	return sp, nil
}

// poolDepth is the number of ready stubs that the platform keeps. A stub takes
// 10 to 20 ms to start, and each fork and each exec of a guest needs one.
const poolDepth = 6

// stubPool keeps ready stubs, so that a fork or an exec does not wait for the
// loader of a new process. One goroutine fills the pool while the guests run.
type stubPool struct {
	ready chan *stubProc
	stop  chan struct{}
	done  chan struct{}
}

// startPool starts the goroutine that fills the pool.
func (p *Platform) startPool() {
	p.pool = &stubPool{
		ready: make(chan *stubProc, poolDepth),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}
	go p.fillPool()
}

func (p *Platform) fillPool() {
	pool := p.pool
	defer close(pool.done)
	for {
		select {
		case <-pool.stop:
			return
		default:
		}
		sp, err := p.newStubProcFresh()
		if err != nil {
			// The next call of NewAddressSpace reports the failure. Wait
			// before the next try, so that a failing host does not make a busy loop.
			select {
			case <-pool.stop:
				return
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		select {
		case pool.ready <- sp:
		case <-pool.stop:
			sp.destroy()
			return
		}
	}
}

// stopPool stops the goroutine and terminates the stubs that no guest took.
func (p *Platform) stopPool() {
	if p.pool == nil {
		return
	}
	close(p.pool.stop)
	<-p.pool.done
	for {
		select {
		case sp := <-p.pool.ready:
			sp.destroy()
		default:
			return
		}
	}
}

// newStubProc returns a ready stub from the pool, or creates one when the pool
// is empty.
func (p *Platform) newStubProc() (*stubProc, error) {
	if p.pool != nil {
		for {
			select {
			case sp := <-p.pool.ready:
				if sp.dead.Load() {
					sp.destroy()
					continue
				}
				return sp, nil
			default:
			}
			break
		}
	}
	return p.newStubProcFresh()
}

// newStubProcFresh creates a stub. The reservation of the guest window can fail
// when the loader placed something there, so the call retries with a new stub.
func (p *Platform) newStubProcFresh() (*stubProc, error) {
	var err error
	for attempt := 0; attempt < 4; attempt++ {
		var sp *stubProc
		if sp, err = p.bringUpStub(); err == nil {
			return sp, nil
		}
		if !errors.Is(err, errWindowTaken) {
			break
		}
	}
	return nil, err
}

// destroy terminates the stub process and releases every handle. It is
// idempotent.
func (sp *stubProc) destroy() {
	sp.mu.Lock()
	if sp.closed {
		sp.mu.Unlock()
		return
	}
	sp.closed = true
	threads := make([]*thread, 0, len(sp.threads))
	for _, th := range sp.threads {
		threads = append(threads, th)
	}
	sp.mu.Unlock()

	_ = ntTerminateProcess(sp.proc)
	// A terminating thread can still run user code for a short time. The Sentry
	// reuses the memory of the stub only after the process is gone.
	_, _ = windows.WaitForSingleObject(sp.proc, 10_000)
	sp.markDead(errStubReleased)
	sp.p.dbg.unregister(sp.pid)
	for _, th := range threads {
		th.closeHandle()
	}
	_ = windows.CloseHandle(sp.proc)
	sp.p.host.release(sp.pid)
}

// newGuestThread creates a thread that runs no code yet. The thread starts at
// ntdll!DbgBreakPoint, stops there, and stays parked until a Switch call
// loads its registers.
//
// WHY: Windows lets the Sentry change a thread context only after the thread
// ran once, on ARM64 at least. The first stop also proves that the thread and
// the debug object work before any guest code exists.
func (sp *stubProc) newGuestThread() (*thread, error) {
	if sp.dead.Load() {
		return nil, sp.deathError()
	}
	start := time.Now()
	defer func() { bringUpStats.threadNs.Add(uint64(time.Since(start))) }()
	h, err := ntCreateThreadEx(sp.proc, sp.p.breakAddr, true)
	if err != nil {
		return nil, err
	}
	tid, err := getThreadID(h)
	if err != nil {
		_ = windows.CloseHandle(h)
		return nil, err
	}
	th := newThread(sp, h, tid)
	sp.mu.Lock()
	if sp.closed {
		sp.mu.Unlock()
		th.closeHandle()
		return nil, errStubReleased
	}
	sp.threads[tid] = th
	sp.mu.Unlock()
	fail := func(err error) (*thread, error) {
		th.destroy()
		return nil, err
	}
	if err := ntResumeThread(h); err != nil {
		return fail(err)
	}
	ev, err := th.waitEvent(startTimeout)
	if err != nil {
		return fail(fmt.Errorf("wait for the start stop of a guest thread: %w", err))
	}
	if err := ntSuspendThread(h); err != nil {
		return fail(err)
	}
	if err := sp.p.dbg.reply(ev); err != nil {
		return fail(err)
	}
	th.parked = true
	return th, nil
}
