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

//go:build darwin && arm64

package systrap

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

const (
	// nzcvMask selects the condition flags in PSTATE.
	nzcvMask = 0xf0000000

	// startTimeout bounds the wait for a new stub thread to reach its first park.
	startTimeout = 20 * time.Second

	// waitSliceMicros is how long a wait on the handoff word lasts before
	// the Sentry re-checks whether the stub task died.
	waitSliceMicros = 100_000

	// ESR_EL1 exception classes of aborts from a lower exception level.
	ecInstructionAbort = 0x20
	ecDataAbort        = 0x24
	esrWnR             = 1 << 6
)

// Darwin signal numbers that the stub reports.
const (
	darwinSIGILL  = 4
	darwinSIGTRAP = 5
	darwinSIGFPE  = 8
	darwinSIGBUS  = 10
	darwinSIGSEGV = 11
	darwinSIGSYS  = 12
	darwinSIGEMT  = 7
)

var (
	errNoAddressSpace = &platform.ContextError{Err: errors.New("no stub address space"), Errno: unix.EFAULT}
	errDeadContext    = &platform.ContextError{Err: errDeadStub, Errno: unix.ECHILD}
)

// thread is one guest thread: a Mach thread of a stub task.
type thread struct {
	as *addressSpace
	// block is the Sentry address of the sysmsg block and stubVA its address
	// in the stub task.
	block  uint64
	stubVA uint64
	idx    int
	sm     *sysmsg
	port   machPort

	// stopMu serializes forced stops.
	stopMu sync.Mutex

	// The fields below belong to the task goroutine.

	// lastKind is the reason of the stop that the Sentry last reported.
	lastKind uint32
	// lastPC is the resume address of a syscall stop.
	lastPC uint64
	// fresh is true until the thread ran once.
	fresh bool
}

// Context implements platform.Context with one stub thread per stub task.
type Context struct {
	platform.NoCPUNumbers

	p         *Platform
	interrupt interrupt.Forwarder
	// kicked records an Interrupt call that Switch has not consumed.
	kicked atomic.Bool
	th     atomic.Pointer[thread]

	// needRestoreFP is true when the Sentry changed the vector state and the
	// next resume must load it.
	needRestoreFP bool
	// fpInStub is true while the vector registers exist in the sysmsg only.
	fpInStub bool
}

// newThread creates a guest thread in the stub task and waits until it parks.
func (as *addressSpace) newThread() (*thread, error) {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return nil, errAddressSpaceReleased
	}
	var idx int
	if n := len(as.freeIdx); n > 0 {
		idx = as.freeIdx[n-1]
		as.freeIdx = as.freeIdx[:n-1]
	} else if as.nextIdx < maxThreadBlocks {
		idx = as.nextIdx
		as.nextIdx++
	} else {
		as.mu.Unlock()
		return nil, fmt.Errorf("the stub task already has %d threads", maxThreadBlocks)
	}
	as.mu.Unlock()

	fail := func(err error) (*thread, error) {
		as.mu.Lock()
		as.freeIdx = append(as.freeIdx, idx)
		as.mu.Unlock()
		return nil, err
	}
	block, err := as.p.pool.allocSpan(threadSpan / blockSize)
	if err != nil {
		return fail(err)
	}
	stubVA := uint64(sysBase) + uint64(idx)*threadSpan
	if err := as.mapPages(stubVA, threadSpan, block, vmProtRead|vmProtWrite); err != nil {
		as.p.pool.releaseSpan(block, threadSpan/blockSize)
		return fail(fmt.Errorf("map a sysmsg block: %w", err))
	}
	th := &thread{as: as, block: block, stubVA: stubVA, idx: idx, sm: (*sysmsg)(addrPtr(block)), fresh: true}
	th.sm.Magic = sysmsgMagic
	th.sm.Stack = stubVA + stubStackTop
	th.sm.Alt = [3]uint64{stubVA + altStackBase, altStackSize, 0}
	st := armThreadState{PC: as.p.host.hello.ThreadEntry, SP: th.sm.Stack}
	st.X[16] = stubVA
	port, err := threadCreateRunning(as.proc.task, &st)
	if err != nil {
		_ = vmDeallocate(as.proc.task, stubVA, threadSpan)
		as.p.pool.releaseSpan(block, threadSpan/blockSize)
		return fail(as.taskErr(err))
	}
	th.port = port
	as.mu.Lock()
	as.threads[th] = struct{}{}
	as.mu.Unlock()
	if err := th.waitTrapped(startTimeout); err != nil {
		th.destroy()
		return nil, fmt.Errorf("start a stub thread: %w", err)
	}
	if th.sm.Kind != kindStart {
		th.destroy()
		return nil, fmt.Errorf("a new stub thread reported kind %d (signal %d, esr %#x, far %#x, pc %#x)", th.sm.Kind, th.sm.Sig, th.sm.MC.ES.ESR, th.sm.MC.ES.FAR, th.sm.MC.SS.PC)
	}
	return th, nil
}

// destroy terminates the thread and returns its block.
func (th *thread) destroy() {
	as := th.as
	as.mu.Lock()
	if _, ok := as.threads[th]; !ok {
		as.mu.Unlock()
		return
	}
	delete(as.threads, th)
	released := as.released
	as.mu.Unlock()
	if released {
		// Release returned the block already.
		return
	}
	if !as.dead.Load() {
		_ = threadTerminate(th.port)
		th.waitTerminated()
		_ = vmDeallocate(as.proc.task, th.stubVA, threadSpan)
	}
	_ = portDeallocate(as.p.host.self, th.port)
	as.p.pool.releaseSpan(th.block, threadSpan/blockSize)
	as.mu.Lock()
	as.freeIdx = append(as.freeIdx, th.idx)
	as.mu.Unlock()
}

// waitTerminated returns once the kernel confirms that the thread can no
// longer run user code. The Sentry unmaps the thread's pages only after that,
// because a thread that still runs would fault on them and take the task down.
func (th *thread) waitTerminated() {
	var ss armThreadState
	for i := 0; i < 2000; i++ {
		err := threadGetState(th.port, armThreadState64, unsafe.Pointer(&ss), armThreadState64Count)
		var me *MachError
		if err != nil && (!errors.As(err, &me) || me.Code != kernSuccess) {
			// The call fails with KERN_TERMINATED, or the task is gone.
			return
		}
		time.Sleep(50 * time.Microsecond)
	}
}

// waitTrapped blocks until the stub thread hands the thread to the Sentry.
//
// A guest system call often returns to the stub within a few microseconds, so
// the Sentry spins on the state word before it sleeps. A sleeping Sentry sets
// waiterSentry first and reads the state again. The stub calls ulock_wake only
// when it sees that bit, so a system call that the Sentry answers inside the
// spin needs no kernel call on this side.
func (th *thread) waitTrapped(limit time.Duration) error {
	for i := 0; i < sentrySpinRounds; i++ {
		if th.sm.loadState() == stateTrapped {
			return nil
		}
		procyield(sentrySpinYields)
	}
	var deadline time.Time
	if limit > 0 {
		deadline = time.Now().Add(limit)
	}
	for {
		st := th.sm.loadState()
		if st == stateTrapped {
			return nil
		}
		if th.as.dead.Load() {
			return errDeadStub
		}
		if limit > 0 && time.Now().After(deadline) {
			return fmt.Errorf("the stub thread did not park within %v (state %d)", limit, st)
		}
		atomic.OrUint32(&th.sm.Waiter, waiterSentry)
		if st = th.sm.loadState(); st != stateTrapped {
			ulockWait(&th.sm.State, st, waitSliceMicros)
		}
		atomic.AndUint32(&th.sm.Waiter, ^uint32(waiterSentry))
	}
}

// resume hands the thread back to the stub. The stub sets waiterStub before it
// sleeps and reads the state again, so the Sentry calls ulock_wake only when
// it sees that bit.
func (th *thread) resume(state uint32) {
	th.sm.storeState(state)
	if atomic.LoadUint32(&th.sm.Waiter)&waiterStub != 0 {
		ulockWakeAll(&th.sm.State)
	}
}

// forceStop makes a running thread trap, at the next instruction boundary of
// guest code. A thread inside stub or trampoline code reaches its own trap
// within nanoseconds, so the loop only retries.
func (th *thread) forceStop() {
	th.stopMu.Lock()
	defer th.stopMu.Unlock()
	for i := 0; i < 100000; i++ {
		if th.sm.loadState() == stateTrapped || th.as.dead.Load() {
			return
		}
		if th.tryCapture() {
			return
		}
		if i < 64 {
			runtime.Gosched()
		} else {
			time.Sleep(20 * time.Microsecond)
		}
	}
}

// tryCapture suspends the thread, and if it executes patched guest code it
// copies the registers to the sysmsg and redirects the thread to the park
// routine. It resumes the thread untouched otherwise.
func (th *thread) tryCapture() bool {
	if err := threadSuspend(th.port); err != nil {
		return th.as.dead.Load() || isDeadTaskError(err)
	}
	resumeOnly := func() { _ = threadResume(th.port) }
	var ss armThreadState
	if err := threadGetState(th.port, armThreadState64, unsafe.Pointer(&ss), armThreadState64Count); err != nil {
		resumeOnly()
		return th.as.dead.Load()
	}
	if !th.as.inPatchedCode(ss.PC) {
		resumeOnly()
		return false
	}
	var ns armNeonState
	if err := threadGetState(th.port, armNeonState64, unsafe.Pointer(&ns), armNeonState64Count); err != nil {
		resumeOnly()
		return th.as.dead.Load()
	}
	th.sm.MC.ES = armExceptionState{}
	th.sm.MC.SS = ss
	th.sm.MC.NS = ns
	redirect := armThreadState{PC: th.as.p.host.hello.InterruptEntry, SP: th.sm.Stack}
	redirect.X[16] = th.stubVA
	if err := threadSetState(th.port, armThreadState64, unsafe.Pointer(&redirect), armThreadState64Count); err != nil {
		resumeOnly()
		return th.as.dead.Load()
	}
	resumeOnly()
	return true
}

// inPatchedCode reports whether pc lies in a patched copy that the stub runs.
func (as *addressSpace) inPatchedCode(pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[blockRound(pc)]
	return blk != nil && blk.state == blockExec
}

// threadIn returns the thread of c in as. It creates the thread on first use
// and replaces a thread of an earlier address space.
func (c *Context) threadIn(as *addressSpace) (*thread, error) {
	th := c.th.Load()
	if th != nil && th.as == as {
		return th, nil
	}
	if th != nil {
		c.th.Store(nil)
		th.destroy()
	}
	th, err := as.newThread()
	if err != nil {
		return nil, err
	}
	c.needRestoreFP = true
	c.fpInStub = false
	c.th.Store(th)
	return th, nil
}

// Switch implements platform.Context.Switch.
//
// WHY: the spec asks for runtime.LockOSThread here because the trampoline
// would run on the calling thread. The guest here runs in another task, and
// the calling thread only waits on a futex word, so it needs no pinning.
func (c *Context) Switch(ctx context.Context, mm platform.MemoryManager, ac *arch.Context64, _ int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	var as *addressSpace
	if mm != nil {
		as, _ = mm.AddressSpace().(*addressSpace)
	}
	if as == nil {
		return nil, hostarch.NoAccess, errNoAddressSpace
	}
	if as.dead.Load() {
		return nil, hostarch.NoAccess, errDeadContext
	}
	th, err := c.threadIn(as)
	if err != nil {
		return nil, hostarch.NoAccess, &platform.ContextError{Err: err, Errno: unix.ENOMEM}
	}
	if !c.interrupt.Enable() {
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	defer c.interrupt.Disable()
	c.kicked.Store(false)

	state := c.prepareResume(th, ac)
	// stopPC and stopKind describe the last stop that Switch resumed
	// internally, so that an interrupt reports the state of that stop.
	var stopPC uint64
	var stopKind uint32
	for {
		if c.kicked.Load() {
			// The thread is parked. Before an internal stop ac already holds its
			// state. After one, ac still holds the state of the previous return.
			if stopKind != 0 {
				c.pull(th, ac, stopPC, stopKind)
			}
			return nil, hostarch.NoAccess, platform.ErrContextInterrupt
		}
		th.resume(state)
		if c.kicked.Load() {
			th.forceStop()
		}
		if err := th.waitTrapped(0); err != nil {
			return nil, hostarch.NoAccess, errDeadContext
		}
		sm := th.sm
		switch sm.Kind {
		case kindInterrupt:
			c.pull(th, ac, sm.MC.SS.PC, kindInterrupt)
			return nil, hostarch.NoAccess, platform.ErrContextInterrupt
		case kindSyscall:
			meta, ok := as.slotAt(sm.Tail, true)
			if !ok {
				return nil, hostarch.NoAccess, &platform.ContextError{Err: fmt.Errorf("the stub trapped from unknown slot %#x", sm.Tail), Errno: unix.EFAULT}
			}
			if meta.kind == siteMSR {
				sm.TLS = msrValue(sm, meta.reg)
				th.lastKind, th.lastPC = kindSyscall, meta.site+4
				stopPC, stopKind = meta.site+4, kindSyscall
				state = stateRunHot
				continue
			}
			if meta.kind == siteX18Jump {
				// The guest jumps through x18, whose value only the sysmsg holds.
				// The cold resume loads the new PC from the context.
				if meta.reg == 1 {
					sm.MC.SS.LR = meta.site + 4
				}
				sm.MC.SS.PC = sm.X18
				th.lastKind = kindSignal
				stopPC, stopKind = sm.X18, kindSignal
				state = stateRunCold
				continue
			}
			c.pull(th, ac, meta.site+4, kindSyscall)
			ac.StateData().OrigR0 = sm.MC.SS.X[0]
			return nil, hostarch.NoAccess, nil
		case kindSignal:
			act := c.handleSignal(ctx, mm, as, th, ac)
			if act.resume {
				th.lastKind = kindSignal
				stopPC, stopKind = sm.MC.SS.PC, kindSignal
				state = stateRunCold
				continue
			}
			return act.si, act.at, act.err
		default:
			return nil, hostarch.NoAccess, &platform.ContextError{Err: fmt.Errorf("the stub reported kind %d", sm.Kind), Errno: unix.EFAULT}
		}
	}
}

// msrValue returns the value that a trapped `msr tpidr_el0, xN` writes.
func msrValue(sm *sysmsg, reg uint8) uint64 {
	switch {
	case reg == 31:
		return 0
	case reg == x18Reg:
		return sm.X18
	case reg < 29:
		return sm.MC.SS.X[reg]
	case reg == 29:
		return sm.MC.SS.FP
	default:
		return sm.MC.SS.LR
	}
}

// prepareResume writes the state of ac into the sysmsg and returns the resume
// state. A hot resume needs only X0, because the stub still holds every other
// register of the trampoline stop.
func (c *Context) prepareResume(th *thread, ac *arch.Context64) uint32 {
	st := ac.StateData()
	regs := &st.Regs
	ss := &th.sm.MC.SS
	th.sm.TLS = regs.TPIDR_EL0
	// The real x18 of the thread holds no guest value. See patcher_arm64_x18.go.
	th.sm.X18 = regs.Regs[x18Reg]
	th.sm.Scratch[0] = regs.Regs[16]
	th.sm.Scratch[1] = regs.Regs[17]
	hot := th.lastKind == kindSyscall && !th.fresh && !c.needRestoreFP &&
		regs.Pc == th.lastPC && regs.Sp == ss.SP && regs.Regs[29] == ss.FP && regs.Regs[30] == ss.LR &&
		regs.Pstate&nzcvMask == uint64(ss.CPSR)&nzcvMask
	if hot {
		for i := 1; i < 29 && hot; i++ {
			hot = i == x18Reg || regs.Regs[i] == ss.X[i]
		}
	}
	if hot {
		ss.X[0] = regs.Regs[0]
		return stateRunHot
	}
	for i := 0; i < 29; i++ {
		ss.X[i] = regs.Regs[i]
	}
	ss.FP, ss.LR, ss.SP, ss.PC = regs.Regs[29], regs.Regs[30], regs.Sp, regs.Pc
	ss.CPSR = uint32(regs.Pstate & nzcvMask)
	ss.Flags = 0
	if c.needRestoreFP || th.fresh {
		storeFP(&th.sm.MC.NS, ac)
		c.needRestoreFP = false
		c.fpInStub = false
	}
	th.fresh = false
	return stateRunCold
}

// pull copies the thread state from the sysmsg into ac. The vector state
// stays in the sysmsg until PullFullState.
func (c *Context) pull(th *thread, ac *arch.Context64, pc uint64, kind uint32) {
	st := ac.StateData()
	regs := &st.Regs
	ss := &th.sm.MC.SS
	for i := 0; i < 29; i++ {
		regs.Regs[i] = ss.X[i]
	}
	regs.Regs[x18Reg] = th.sm.X18
	regs.Regs[29], regs.Regs[30] = ss.FP, ss.LR
	regs.Sp = ss.SP
	regs.Pc = pc
	regs.Pstate = uint64(ss.CPSR) & nzcvMask
	regs.TPIDR_EL0 = th.sm.TLS
	th.lastKind, th.lastPC = kind, pc
	if kind != kindSyscall {
		// A signal stop restores the whole context, so ss.PC must carry the resume address.
		ss.PC = pc
	}
	c.fpInStub = true
}

// fpHeaderSize is the size of the fpsimd_context header that precedes the
// FPSR, FPCR and vector registers in the Sentry's floating point state.
const (
	fpsrOffset  = 8
	fpcrOffset  = 12
	vregsOffset = 16
)

// loadFP copies the vector state of the sysmsg into the Sentry's state.
func loadFP(dst *arch.Context64, ns *armNeonState) {
	fp := *dst.FloatingPointData()
	putUint32(fp[fpsrOffset:], ns.FPSR)
	putUint32(fp[fpcrOffset:], ns.FPCR)
	for i := range ns.V {
		copy(fp[vregsOffset+16*i:], ns.V[i][:])
	}
}

// storeFP copies the Sentry's vector state into the sysmsg.
func storeFP(ns *armNeonState, ac *arch.Context64) {
	fp := *ac.FloatingPointData()
	ns.FPSR = getUint32(fp[fpsrOffset:])
	ns.FPCR = getUint32(fp[fpcrOffset:])
	for i := range ns.V {
		copy(ns.V[i][:], fp[vregsOffset+16*i:vregsOffset+16*i+16])
	}
}

func putUint32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func getUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

// PullFullState implements platform.Context.PullFullState.
func (c *Context) PullFullState(as platform.AddressSpace, ac *arch.Context64) error {
	if !c.fpInStub {
		return nil
	}
	th := c.th.Load()
	if th == nil {
		return nil
	}
	loadFP(ac, &th.sm.MC.NS)
	c.fpInStub = false
	return nil
}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *Context) FullStateChanged() {
	c.needRestoreFP = true
	c.fpInStub = false
}

// signalAction is the outcome of a signal stop.
type signalAction struct {
	// resume means Switch continues the thread without returning.
	resume bool
	si     *linux.SignalInfo
	at     hostarch.AccessType
	err    error
}

func contextErr(err error, errno unix.Errno) signalAction {
	return signalAction{err: &platform.ContextError{Err: err, Errno: errno}}
}

// handleSignal classifies a signal that the stub reported.
func (c *Context) handleSignal(ctx context.Context, mm platform.MemoryManager, as *addressSpace, th *thread, ac *arch.Context64) signalAction {
	sm := th.sm
	sm.MC = sm.FMC
	if act, done := c.recoverTrapSlot(as, sm); done {
		return act
	}
	if as.p.zone {
		if act, done := c.zoneBodyFault(ctx, mm, as, sm.Sig, sm.MC.ES.ESR>>26, sm.MC.ES.FAR, sm.MC.SS.PC); done {
			return act
		}
	}
	if act, done := c.recoverX18Slot(as, sm); done {
		return act
	}
	sig := sm.Sig
	esr := sm.MC.ES.ESR
	far := sm.MC.ES.FAR
	pc := sm.MC.SS.PC
	ec := esr >> 26

	if as.p.zone {
		if act, done := c.zoneFault(ctx, mm, as, th, ac, sig, ec, esr, far, pc); done {
			return act
		}
	}

	switch sig {
	case darwinSIGSEGV, darwinSIGBUS:
		switch ec {
		case ecInstructionAbort:
			if st, _, ok := as.blockStateOf(blockRound(pc)); ok {
				if st == blockData {
					if err := as.patchBlock(ctx, mm, pc); err != nil {
						return contextErr(fmt.Errorf("patch the code page at %#x: %w", blockRound(pc), err), unix.ENOMEM)
					}
				}
				// A block that is already executable means that another thread
				// patched it after this thread faulted. Either way the thread retries.
				return signalAction{resume: true}
			}
		case ecDataAbort:
			if esr&esrWnR != 0 {
				if act, done := c.storeToExecBlock(as, sm, pc, far); done {
					return act
				}
			}
		}
		return c.reportFault(th, ac, sig, ec, esr, far, pc)
	case darwinSIGILL:
		if emulateARM64MRS(as, sm, pc) {
			return signalAction{resume: true}
		}
		return c.reportSignal(th, ac, linux.SIGILL, 1, pc, pc)
	case darwinSIGTRAP:
		return c.reportSignal(th, ac, linux.SIGTRAP, linux.TRAP_BRKPT, pc, pc)
	case darwinSIGFPE:
		return c.reportSignal(th, ac, linux.SIGFPE, linuxFPECode(int32(sm.Code)), pc, pc)
	default:
		return contextErr(fmt.Errorf("the stub task received host signal %d at %#x", sig, pc), unix.EFAULT)
	}
}

// recoverTrapSlot repairs a fault inside a trap slot when an interrupt zeroed
// the real x18 before a scratch load or store. Each four-word phase is
// idempotent, so the thread restarts at the first instruction of the phase.
func (c *Context) recoverTrapSlot(as *addressSpace, sm *sysmsg) (signalAction, bool) {
	if sm.Sig != darwinSIGSEGV && sm.Sig != darwinSIGBUS {
		return signalAction{}, false
	}
	if sm.MC.ES.FAR >= faultLowLimit {
		return signalAction{}, false
	}
	pc := sm.MC.SS.PC
	meta, start, ok := as.slotWithin(pc)
	if !ok || !meta.kind.isTrap() {
		return signalAction{}, false
	}
	off := pc - start
	switch {
	case off < 16:
		sm.MC.SS.PC = start
		return signalAction{resume: true}, true
	case off >= trapSlotTailOffset && off < trapSlotTailOffset+16:
		sm.MC.SS.PC = start + trapSlotTailOffset
		return signalAction{resume: true}, true
	}
	return signalAction{}, false
}

// recoverX18Slot repairs a fault inside the slot of an instruction that names
// x18. A fault at an address below faultLowLimit inside a phase that uses the
// real x18 means that an interrupt zeroed the sysmsg pointer, and the thread
// restarts the phase. A fault inside the guest instruction of the slot is a
// fault of the guest. The context then returns to the guest site with the
// borrowed scratch register restored, as if the slot did not exist.
func (c *Context) recoverX18Slot(as *addressSpace, sm *sysmsg) (signalAction, bool) {
	if sm.Sig != darwinSIGSEGV && sm.Sig != darwinSIGBUS {
		return signalAction{}, false
	}
	pc := sm.MC.SS.PC
	meta, start, ok := as.slotWithin(pc)
	if !ok || (meta.kind != siteX18 && meta.kind != siteX18Cond) {
		return signalAction{}, false
	}
	restart, body, ok := x18Restart(meta.kind, int(meta.body), uint32(pc-start))
	switch {
	case !ok:
		return contextErr(fmt.Errorf("an x18 slot at %#x faulted at %#x outside its phases", start, pc), unix.EFAULT), true
	case body:
		sm.MC.SS.X[meta.scratch] = sm.Spill
		sm.MC.SS.PC = meta.site
		return signalAction{}, false
	case sm.MC.ES.FAR >= faultLowLimit:
		return contextErr(fmt.Errorf("an x18 slot at %#x faulted at address %#x", start, sm.MC.ES.FAR), unix.EFAULT), true
	}
	sm.MC.SS.PC = start + uint64(restart)
	return signalAction{resume: true}, true
}

// faultSignal classifies a hardware fault. The kernel reports an access to an
// unmapped address as SIGSEGV and every other EXC_BAD_ACCESS as SIGBUS. Linux
// reports both as SIGSEGV, with SEGV_MAPERR and SEGV_ACCERR. Only a data
// alignment fault stays SIGBUS.
func faultSignal(darwinSig uint64, esr uint32) (linux.Signal, int32) {
	const (
		dfscMask      = 0x3f
		dfscAlignment = 0x21
		segvMapErr    = 1
		segvAccErr    = 2
		busAdrAln     = 1
	)
	if esr&dfscMask == dfscAlignment {
		return linux.SIGBUS, busAdrAln
	}
	if darwinSig == darwinSIGSEGV {
		return linux.SIGSEGV, segvMapErr
	}
	return linux.SIGSEGV, segvAccErr
}

func linuxFPECode(darwin int32) int32 {
	switch darwin {
	case 1:
		return 3 // FPE_FLTDIV
	case 2:
		return 4 // FPE_FLTOVF
	case 3:
		return 5 // FPE_FLTUND
	case 4:
		return 6 // FPE_FLTRES
	case 5:
		return 7 // FPE_FLTINV
	case 6:
		return 8 // FPE_FLTSUB
	case 7:
		return 1 // FPE_INTDIV
	case 8:
		return 2 // FPE_INTOVF
	}
	return 0
}

func (c *Context) reportSignal(th *thread, ac *arch.Context64, sig linux.Signal, code int32, addr, pc uint64) signalAction {
	c.pull(th, ac, pc, kindSignal)
	si := &linux.SignalInfo{Signo: int32(sig), Code: code}
	si.SetAddr(addr)
	return signalAction{si: si, err: platform.ErrContextSignal}
}

// emulateARM64MRS emulates an EL0 read of an AArch64 ID register, CTR_EL0, or
// DCZID_EL0 when macOS raises SIGILL at pc.
func emulateARM64MRS(as *addressSpace, sm *sysmsg, pc uint64) bool {
	insn, ok := as.codeWord(pc)
	if !ok {
		return false
	}
	rt, val, ok := decodeARM64SysRegMRS(insn)
	if !ok {
		return false
	}
	switch {
	case rt == 31:
	case rt == x18Reg:
		sm.X18 = val
	case rt < 29:
		sm.MC.SS.X[rt] = val
	case rt == 29:
		sm.MC.SS.FP = val
	case rt == 30:
		sm.MC.SS.LR = val
	}
	sm.MC.SS.PC = pc + 4
	return true
}

// reportFault converts a memory fault into SIGSEGV or SIGBUS for the guest.
func (c *Context) reportFault(th *thread, ac *arch.Context64, sig uint64, ec uint32, esr uint32, far uint64, pc uint64) signalAction {
	c.pull(th, ac, pc, kindSignal)
	var at hostarch.AccessType
	switch {
	case ec == ecInstructionAbort:
		at = hostarch.Execute
		far = pc
	case esr&esrWnR != 0:
		at = hostarch.Write
	default:
		at = hostarch.Read
	}
	linuxSig, linuxCode := faultSignal(sig, esr)
	si := &linux.SignalInfo{Signo: int32(linuxSig), Code: linuxCode}
	si.SetAddr(c.p.guestAddr(far))
	return signalAction{si: si, at: at, err: platform.ErrContextSignal}
}

// Interrupt implements platform.Context.Interrupt.
func (c *Context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt. The flag is
// set before the state check, and Switch tests the flag after it resumes the
// thread, so one of the two sides always sees the other.
func (c *Context) NotifyInterrupt() {
	c.kicked.Store(true)
	if th := c.th.Load(); th != nil && th.sm.loadState() != stateTrapped {
		th.forceStop()
	}
}

// Preempt implements platform.Context.Preempt. Switch never waits for a free
// slot, so there is nothing to preempt.
func (*Context) Preempt() {}

// Release implements platform.Context.Release.
func (c *Context) Release() {
	if th := c.th.Swap(nil); th != nil {
		th.destroy()
	}
}

// PrepareSleep implements platform.Context.PrepareSleep.
func (*Context) PrepareSleep() {}

// PrepareUninterruptibleSleep implements platform.Context.PrepareUninterruptibleSleep.
func (*Context) PrepareUninterruptibleSleep() {}

// PrepareStop implements platform.Context.PrepareStop.
func (*Context) PrepareStop() {}

// PrepareExecve implements platform.Context.PrepareExecve.
func (*Context) PrepareExecve() {}

// PrepareExit implements platform.Context.PrepareExit.
func (*Context) PrepareExit() {}
