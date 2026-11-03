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

//go:build darwin

package hvf

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Hypervisor.framework binds a vCPU to the OS thread that creates it. Only
// that thread may run, read, write, or destroy the vCPU, and hv_vm_destroy
// fails while any vCPU exists. Go moves goroutines between threads freely, so
// this backend gives every vCPU a dedicated goroutine that holds
// runtime.LockOSThread for its whole life. That goroutine is a vCPU worker.
// A Switch call borrows an idle worker, hands it the request, and waits.
//
// The hand-off spins briefly before it parks. A guest system call costs a few
// microseconds, so a channel hand-off, which wakes a parked locked thread in
// about 15 microseconds, would dominate the round trip. A worker that served
// a request a moment ago still spins and takes the next request in well under
// a microsecond. Spinning ends after a bounded budget, so an idle backend
// burns no CPU.

const (
	// workerSpin bounds how long an idle worker polls for a request.
	workerSpin = 40 * time.Microsecond
	// callerSpin bounds how long Switch polls for the result before it parks.
	callerSpin = 40 * time.Microsecond
)

// spinWait polls done until it returns true or the budget ends. It yields the
// processor periodically so a spinning goroutine cannot starve the goroutine
// it waits for when GOMAXPROCS is small.
func spinWait(budget time.Duration, done func() bool) bool {
	start := time.Now()
	for i := 1; ; i++ {
		if done() {
			return true
		}
		if i&63 == 0 {
			if time.Since(start) >= budget {
				return false
			}
			if i&1023 == 0 {
				runtime.Gosched()
			}
		}
	}
}

// switchReq carries one Switch call to a worker and the result back. A
// Context owns one and reuses it: its Switch calls never overlap.
type switchReq struct {
	ctx context.Context
	mm  platform.MemoryManager
	c   *Context
	as  *AddressSpace
	ac  *arch.Context64

	info *linux.SignalInfo
	at   hostarch.AccessType
	err  error

	done   atomic.Uint32
	parked atomic.Uint32
	wake   chan struct{}
}

// contextHW is the per-Context backend state.
type contextHW struct {
	mu     sync.Mutex
	worker *vcpuWorker // The worker that runs this Context, if any.
	// waitIntr wakes a Switch that waits for a free worker.
	waitIntr chan struct{}
	req      switchReq
}

func (h *contextHW) init() {
	h.waitIntr = make(chan struct{}, 1)
	h.req.wake = make(chan struct{}, 1)
}

// cancel forces the worker that runs the Context out of the guest and wakes a
// Switch that still waits for a worker.
func (h *contextHW) cancel() {
	h.mu.Lock()
	w := h.worker
	h.mu.Unlock()
	if w != nil {
		w.cancel()
	}
	select {
	case h.waitIntr <- struct{}{}:
	default:
	}
}

// vcpuWorker owns one vCPU and its thread.
type vcpuWorker struct {
	vm   *vmState
	slot int
	comm *kernelComm

	// id and exit are set by the worker thread before it reports ready, and
	// never change.
	id   uint64
	exit *hvVCPUExit

	// Request hand-off.
	req    atomic.Pointer[switchReq]
	asleep atomic.Bool
	wake   chan struct{}
	quit   atomic.Bool
	// exited is set when the worker thread stops reading requests.
	exited atomic.Bool

	// State that other goroutines read to stop a vCPU that runs a table.
	curPT   atomic.Pointer[stage1Tables]
	inGuest atomic.Bool
	// exits counts the returns of hv_vcpu_run. memoryBarrier waits on it.
	exits      atomic.Uint64
	enterTLB   atomic.Uint64
	cancelErr  atomic.Pointer[error]
	destroyed  atomic.Bool
	archWorker // Fields that only the worker thread touches.
}

// cancel makes a running vCPU exit. When the vCPU does not run, the next
// hv_vcpu_run returns at once without entering the guest.
func (w *vcpuWorker) cancel() {
	if err := hvVCPUsExit(w.id); err != nil && !w.destroyed.Load() {
		log.Warningf("hvf: cancel vCPU %d: %v", w.id, err)
		w.cancelErr.CompareAndSwap(nil, &err)
	}
}

// quiesce returns when the vCPU no longer runs guest code that entered before
// the table generation reached target.
func (w *vcpuWorker) quiesce(pt *stage1Tables, target uint64) {
	cancelled := false
	for i := 1; ; i++ {
		if w.curPT.Load() != pt || !w.inGuest.Load() || w.enterTLB.Load() >= target {
			return
		}
		if !cancelled || i&0x3ff == 0 {
			w.cancel()
			cancelled = true
		}
		runtime.Gosched()
	}
}

// awaitExit returns when the vCPU leaves the guest. The caller read exits
// while the vCPU ran guest code. awaitExit sends the cancel again at
// intervals, because a cancel that arrives between two entries ends only the
// next run.
func (w *vcpuWorker) awaitExit(exits uint64) {
	for i := 1; w.inGuest.Load() && w.exits.Load() == exits; i++ {
		if i&0x3ff == 0 {
			w.cancel()
		}
		runtime.Gosched()
	}
}

// submit hands a request to an idle worker. A worker that already stopped
// fails the request, so Switch never waits for a thread that is gone.
func (w *vcpuWorker) submit(r *switchReq) {
	w.req.Store(r)
	if w.exited.Load() {
		w.failPending()
		return
	}
	if w.asleep.Load() {
		w.poke()
	}
}

// failPending completes a request that no worker thread will run. The worker
// thread and submit both call it; the swap gives the request to one of them.
func (w *vcpuWorker) failPending() {
	if r := w.req.Swap(nil); r != nil {
		r.err = errPlatformClosed
		r.finish()
	}
}

func (w *vcpuWorker) poke() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// nextRequest waits for a request. It returns nil when the worker must exit.
func (w *vcpuWorker) nextRequest() *switchReq {
	for {
		if r := w.req.Swap(nil); r != nil {
			return r
		}
		if w.quit.Load() {
			return nil
		}
		ready := func() bool { return w.req.Load() != nil || w.quit.Load() }
		if spinWait(workerSpin, ready) {
			continue
		}
		w.asleep.Store(true)
		if !ready() {
			<-w.wake
		}
		w.asleep.Store(false)
	}
}

// await waits for the worker to finish a request.
func (r *switchReq) await() {
	finished := func() bool { return r.done.Load() != 0 }
	if spinWait(callerSpin, finished) {
		return
	}
	r.parked.Store(1)
	for !finished() {
		<-r.wake
	}
	r.parked.Store(0)
}

// finish publishes the result of a request.
func (r *switchReq) finish() {
	r.done.Store(1)
	if r.parked.Load() != 0 {
		select {
		case r.wake <- struct{}{}:
		default:
		}
	}
}

// run is the worker goroutine.
func (w *vcpuWorker) run(ready chan<- error, wg *sync.WaitGroup, record func(error)) {
	defer wg.Done()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err := w.initVCPU(); err != nil {
		ready <- err
		return
	}
	ready <- nil
	for {
		r := w.nextRequest()
		if r == nil {
			break
		}
		r.info, r.at, r.err = w.runSwitch(r)
		r.finish()
	}
	w.exited.Store(true)
	w.failPending()
	w.destroyed.Store(true)
	if err := hvVCPUDestroy(w.id); err != nil {
		record(fmt.Errorf("hvf: destroy vCPU %d: %w", w.id, err))
	}
}

// errInterruptedWait reports that an interrupt ended a wait for a worker.
var errInterruptedWait = errors.New("hvf: interrupted while waiting for a vCPU")

// workerPool owns the vCPU workers of a VM.
type workerPool struct {
	vm  *vmState
	max int
	// slots[i] is the worker with CommPage i. Readers need no lock.
	slots [kernelCommPages]atomic.Pointer[vcpuWorker]

	// fence is the target of the full barrier that memoryBarrier runs first.
	fence atomic.Uint64

	mu        sync.Mutex
	stopping  bool
	freeSlots []int
	started   int           // Workers that run.
	limit     int           // vCPU limit that ConcurrencyCount reports.
	idle      []*vcpuWorker // Most recently used last.
	waiters   []chan *vcpuWorker
	errs      []error
	wg        sync.WaitGroup
}

func (p *workerPool) init(vm *vmState, max int) {
	p.vm = vm
	p.max = max
	p.limit = max
	for i := max - 1; i >= 0; i-- {
		p.freeSlots = append(p.freeSlots, i)
	}
}

func (p *workerPool) record(err error) {
	p.mu.Lock()
	p.errs = append(p.errs, err)
	p.mu.Unlock()
}

// acquire returns an idle worker, starts one while slots remain, or waits for a
// release. An interrupt ends the wait with errInterruptedWait.
func (p *workerPool) acquire(c *Context) (*vcpuWorker, error) {
	for {
		p.mu.Lock()
		if p.stopping {
			p.mu.Unlock()
			return nil, errPlatformClosed
		}
		if n := len(p.idle); n > 0 {
			w := p.idle[n-1]
			p.idle = p.idle[:n-1]
			p.mu.Unlock()
			return w, nil
		}
		if n := len(p.freeSlots); n > 0 {
			slot := p.freeSlots[n-1]
			p.freeSlots = p.freeSlots[:n-1]
			// Register the worker before the lock ends: stop waits for it, so
			// the VM cannot disappear under hv_vcpu_create.
			p.wg.Add(1)
			p.mu.Unlock()
			w, err := p.start(slot)
			if err == nil {
				return w, nil
			}
			p.mu.Lock()
			code, isHV := hvCode(err)
			if !isHV || code != hvErrNoRes || p.started == 0 {
				p.freeSlots = append(p.freeSlots, slot)
				p.mu.Unlock()
				return nil, err
			}
			// The framework refused another vCPU: the process already holds as
			// many as it may. Stop creating workers and wait for a release.
			p.freeSlots = nil
			p.limit = p.started
			p.mu.Unlock()
			continue
		}
		ch := make(chan *vcpuWorker, 1)
		p.waiters = append(p.waiters, ch)
		p.mu.Unlock()

		select {
		case w := <-ch:
			if w == nil {
				return nil, errPlatformClosed
			}
			return w, nil
		case <-c.hw.waitIntr:
			if p.cancelWait(ch) {
				if c.interrupted.CompareAndSwap(true, false) {
					return nil, errInterruptedWait
				}
				continue // A stale wake token: wait again.
			}
			// A worker was handed over before the cancellation: take it.
			if w := <-ch; w != nil {
				return w, nil
			}
			return nil, errPlatformClosed
		}
	}
}

// cancelWait removes ch from the waiter list. It reports false when release
// already removed it.
func (p *workerPool) cancelWait(ch chan *vcpuWorker) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, w := range p.waiters {
		if w == ch {
			p.waiters = append(p.waiters[:i], p.waiters[i+1:]...)
			return true
		}
	}
	return false
}

// release returns a worker, preferring the longest-waiting Switch.
func (p *workerPool) release(w *vcpuWorker) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.waiters) > 0 && !p.stopping {
		ch := p.waiters[0]
		p.waiters = p.waiters[1:]
		ch <- w
		return
	}
	p.idle = append(p.idle, w)
}

// start creates a worker and its vCPU on a new locked thread. The caller has
// added the worker to the wait group.
func (p *workerPool) start(slot int) (*vcpuWorker, error) {
	w := &vcpuWorker{
		vm:   p.vm,
		slot: slot,
		comm: &p.vm.kernel.comm[slot],
		wake: make(chan struct{}, 1),
	}
	ready := make(chan error, 1)
	go w.run(ready, &p.wg, p.record)
	if err := <-ready; err != nil {
		return nil, err
	}
	p.slots[slot].Store(w)
	p.mu.Lock()
	p.started++
	stopping := p.stopping
	p.mu.Unlock()
	if stopping {
		// stop scanned the slots before this worker appeared.
		w.quit.Store(true)
		w.poke()
		return nil, errPlatformClosed
	}
	return w, nil
}

// stop ends every worker and waits until each destroyed its vCPU.
func (p *workerPool) stop() error {
	p.mu.Lock()
	p.stopping = true
	for _, ch := range p.waiters {
		ch <- nil
	}
	p.waiters = nil
	p.mu.Unlock()

	for i := range p.slots[:p.max] {
		if w := p.slots[i].Load(); w != nil {
			w.quit.Store(true)
			w.cancel()
			w.poke()
		}
	}
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	return errors.Join(p.errs...)
}

// quiesce stops every vCPU that runs pt with a translation older than the
// current generation.
func (p *workerPool) quiesce(pt *stage1Tables) {
	target := pt.tlbGen.Load()
	for i := range p.slots[:p.max] {
		if w := p.slots[i].Load(); w != nil {
			w.quiesce(pt, target)
		}
	}
}

// memoryBarrier returns after every vCPU that runs guest code has left the
// guest at least once. A vCPU outside the guest needs no kick: its next entry
// comes after the call began.
//
// WHY: Hypervisor.framework documents no memory ordering for hv_vcpus_exit, so
// the ordering comes from the atomics around hv_vcpu_run. A vCPU that exits
// runs exits.Add after hv_vcpu_run returned, and the program order of that
// thread covers its guest accesses. A vCPU that enters runs inGuest.Swap before
// hv_vcpu_run, and a read-modify-write with acquire and release ordering keeps
// the guest accesses after it. The caller runs a full barrier before it reads
// any vCPU state. Per vCPU, either the caller reads inGuest as false before the
// entry swap, so the entry orders the guest after the call began, or it reads
// true and waits for an exit that follows its barrier.
func (p *workerPool) memoryBarrier() {
	p.fence.Add(1)
	type pending struct {
		w     *vcpuWorker
		exits uint64
	}
	var buf [kernelCommPages]pending
	waits := buf[:0]
	for i := range p.slots[:p.max] {
		w := p.slots[i].Load()
		if w == nil {
			continue
		}
		exits := w.exits.Load()
		if !w.inGuest.Load() {
			continue
		}
		w.cancel()
		waits = append(waits, pending{w, exits})
	}
	for _, c := range waits {
		c.w.awaitExit(c.exits)
	}
}

// memoryBarrier implements Platform.GlobalMemoryBarrier.
func (v *vmState) memoryBarrier() {
	v.pool.memoryBarrier()
}

// quiesce implements the Unmap guarantee: after it returns, no vCPU
// translates through a descriptor that was valid before the call.
func (v *vmState) quiesce(pt *stage1Tables) {
	v.pool.quiesce(pt)
}

// retire frees a page table after no vCPU can run it.
func (v *vmState) retire(pt *stage1Tables) {
	pt.markDead()
	v.pool.quiesce(pt)
	pt.release()
}

// concurrency returns the vCPU limit.
func (v *vmState) concurrency() int {
	v.pool.mu.Lock()
	defer v.pool.mu.Unlock()
	return v.pool.limit
}

// switchContext runs one guest slice of c on a pooled vCPU.
func (v *vmState) switchContext(ctx context.Context, mm platform.MemoryManager, c *Context, as *AddressSpace, ac *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	w, err := v.pool.acquire(c)
	if err != nil {
		if errors.Is(err, errInterruptedWait) {
			return nil, hostarch.NoAccess, platform.ErrContextInterrupt
		}
		return nil, hostarch.NoAccess, err
	}
	// Publish the worker before the request. Interrupt then either cancels this
	// worker or sets the flag that the worker tests before it enters the guest.
	c.hw.mu.Lock()
	c.hw.worker = w
	c.hw.mu.Unlock()

	r := &c.hw.req
	r.ctx, r.mm, r.c, r.as, r.ac = ctx, mm, c, as, ac
	r.done.Store(0)
	w.submit(r)
	r.await()

	c.hw.mu.Lock()
	c.hw.worker = nil
	c.hw.mu.Unlock()
	v.pool.release(w)

	info, at, err := r.info, r.at, r.err
	r.ctx, r.mm, r.c, r.as, r.ac, r.info, r.err = nil, nil, nil, nil, nil, nil, nil
	return info, at, err
}
