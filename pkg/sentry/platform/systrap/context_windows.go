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
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

var errDeadContext = &platform.ContextError{Err: errStubDead, Errno: unix.ECHILD}

// Context implements platform.Context with one stub thread for each context.
type Context struct {
	platform.NoCPUNumbers

	p         *Platform
	interrupt interrupt.Forwarder
	// kicked records an Interrupt call that Switch has not consumed.
	kicked atomic.Bool
	th     atomic.Pointer[thread]

	// needRestoreFP is true when the thread must load the vector state of ac at
	// the next start: the Sentry changed it, or the thread is new.
	needRestoreFP bool
	// fpInThread is true while the vector state of the guest lives in the
	// thread only, and ac holds an older copy. PullFullState reads it.
	fpInThread bool
}

// threadIn returns the thread of c in as. It creates the thread on first use
// and replaces a thread of an earlier address space.
func (c *Context) threadIn(as *addressSpace) (*thread, error) {
	th := c.th.Load()
	if th != nil && th.sp == as.sp {
		return th, nil
	}
	if th != nil {
		c.th.Store(nil)
		th.destroy()
	}
	th, err := as.sp.newGuestThread()
	if err != nil {
		return nil, err
	}
	c.th.Store(th)
	c.needRestoreFP = true
	c.fpInThread = false
	return th, nil
}

// outcome is the result of one stop of a guest thread.
type outcome struct {
	// done is true when Switch returns. A thread that is not done runs on, and
	// Switch waits for its next stop.
	done bool
	si   *linux.SignalInfo
	at   hostarch.AccessType
	err  error
}

var running = outcome{}

func fatal(err error, errno unix.Errno) outcome {
	return outcome{done: true, err: &platform.ContextError{Err: err, Errno: errno}}
}

// Switch implements platform.Context.Switch.
func (c *Context) Switch(ctx context.Context, mm platform.MemoryManager, ac *arch.Context64, _ int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	var as *addressSpace
	if mm != nil {
		as, _ = mm.AddressSpace().(*addressSpace)
	}
	if as == nil {
		return nil, hostarch.NoAccess, errNoAddressSpace
	}
	if as.sp.dead.Load() {
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

	loadFP := c.needRestoreFP
	c.needRestoreFP = false
	c.fpInThread = false
	if err := th.start(ac, loadFP); err != nil {
		return nil, hostarch.NoAccess, c.runErr(as, err)
	}
	for {
		if c.kicked.Load() {
			// The thread is parked and ac still holds its state.
			return nil, hostarch.NoAccess, platform.ErrContextInterrupt
		}
		if err := th.run(); err != nil {
			return nil, hostarch.NoAccess, c.runErr(as, err)
		}
		// Switch tests the flag after it starts the thread, and a kick tests the
		// state of the thread after it sets the flag, so one of the two sees the other.
		if c.kicked.Load() {
			th.forceStop()
		}
		for {
			var waited time.Time
			if traceEvents {
				waited = time.Now()
			}
			ev, err := th.waitEvent(0)
			if err != nil {
				return nil, hostarch.NoAccess, errDeadContext
			}
			if traceEvents {
				stopStats.waitNs[kindOf(ev)].Add(uint64(time.Since(waited)))
			}
			out := c.handleEvent(ctx, mm, as, th, ac, ev)
			if out.done {
				if traceAll && !traceMuted.Load() {
					tracef("pid %d thread %d: switch returns, signal %v, error %v", th.sp.pid, th.tid, out.si != nil, out.err)
				}
				// The stop copied the general-purpose registers. The vector
				// registers stay in the parked thread until PullFullState.
				c.fpInThread = true
				return out.si, out.at, out.err
			}
		}
	}
}

func (c *Context) runErr(as *addressSpace, err error) error {
	if as.sp.dead.Load() {
		return errDeadContext
	}
	return &platform.ContextError{Err: err, Errno: unix.EFAULT}
}

// handleEvent serves one exception of the thread.
func (c *Context) handleEvent(ctx context.Context, mm platform.MemoryManager, as *addressSpace, th *thread, ac *arch.Context64, ev debugEvent) outcome {
	th.mu.Lock()
	defer th.mu.Unlock()
	if err := th.getContext(th.ctx.gprFlags()); err != nil {
		return fatal(err, unix.EFAULT)
	}
	if traceEvents {
		kind := kindOf(ev)
		stopStats.count[kind].Add(1)
		start := time.Now()
		defer func() { stopStats.handleNs[kind].Add(uint64(time.Since(start))) }()
	}
	if traceAll && !traceMuted.Load() {
		th.traceStop(as, ev)
	}
	if out, ok := th.archEvent(as, ac, ev); ok {
		return out
	}
	switch ev.State {
	case dbgStateSingleStep:
		return c.stepStop(th, ac, ev)
	}
	switch ev.Code {
	case statusAccessViol, statusInPageError:
		return c.faultStop(ctx, mm, as, th, ac, ev)
	case statusIllegalInsn, statusPrivInsn:
		sig, code := th.illegalSignal(as, th.ctx.pc())
		return c.signalStop(as, th, ac, ev, linux.Signal(sig), code, th.ctx.pc())
	case statusBreakpoint:
		return c.signalStop(as, th, ac, ev, linux.SIGTRAP, linux.TRAP_BRKPT, th.ctx.pc())
	case statusSingleStep:
		return c.stepStop(th, ac, ev)
	case statusDatatypeMis:
		return c.signalStop(as, th, ac, ev, linux.SIGBUS, busAdrAln, th.ctx.pc())
	case statusIntDivZero:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeIntDiv, th.ctx.pc())
	case statusIntOverflow:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeIntOvf, th.ctx.pc())
	case statusFltDivZero:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeFltDiv, th.ctx.pc())
	case statusFltOverflow:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeFltOvf, th.ctx.pc())
	case statusFltUnderflow:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeFltUnd, th.ctx.pc())
	case statusFltInexact:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeFltRes, th.ctx.pc())
	case statusFltInvalid, statusFltDenormal, statusFltStack:
		return c.signalStop(as, th, ac, ev, linux.SIGFPE, fpeFltInv, th.ctx.pc())
	}
	return fatal(fmt.Errorf("the stub reported exception %#x at %#x (pc %#x)", ev.Code, ev.Addr, th.ctx.pc()), unix.EFAULT)
}

// traceStop prints one stop for GVX_SYSTRAP_TRACE.
func (th *thread) traceStop(as *addressSpace, ev debugEvent) {
	tracef("pid %d thread %d: state %d code %#x addr %#x info %#x first %d, pc %#x sp %#x code bytes % x",
		th.sp.pid, th.tid, ev.State, ev.Code, ev.Addr, ev.Info, ev.FirstChance, th.ctx.pc(), th.ctx.sp(), as.codeBytes(th.ctx.pc(), 16))
}

// stopAndPull parks the thread at an exception and copies its registers into
// ac. Callers hold th.mu and have read the full context.
func (th *thread) stopAndPull(ac *arch.Context64, ev debugEvent) error {
	if th.stepping {
		// The forced stop set the flag. The guest never sees it.
		th.ctx.setSingleStep(false)
	}
	if err := th.park(ev); err != nil {
		return err
	}
	th.stepping = false
	th.ctx.storeTo(ac)
	th.pullArch(ac)
	return nil
}

// stepStop serves a single-step stop. The stop belongs to a forced stop of the
// thread, so the Sentry reports an interrupt.
func (c *Context) stepStop(th *thread, ac *arch.Context64, ev debugEvent) outcome {
	if th.stepping && th.inEngineCode(th.ctx.pc()) {
		// The thread runs engine code that the Sentry planted. Step on until
		// it reaches guest code, where its registers are the guest registers.
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT)
		}
		return running
	}
	if err := th.stopAndPull(ac, ev); err != nil {
		return fatal(err, unix.EFAULT)
	}
	return outcome{done: true, err: platform.ErrContextInterrupt}
}

// signalStop reports a signal of the guest at pc.
func (c *Context) signalStop(as *addressSpace, th *thread, ac *arch.Context64, ev debugEvent, sig linux.Signal, code int32, addr uint64) outcome {
	if traceEvents && !traceMuted.Load() {
		tracef("signal %d code %d to the guest", sig, code)
		th.traceStop(as, ev)
	}
	if err := th.stopAndPull(ac, ev); err != nil {
		return fatal(err, unix.EFAULT)
	}
	si := &linux.SignalInfo{Signo: int32(sig), Code: code}
	si.SetAddr(addr)
	return outcome{done: true, si: si, err: platform.ErrContextSignal}
}

// linuxSig is a Linux signal number that the engine reports.
type linuxSig = linux.Signal

const (
	sigILL  = linux.SIGILL
	sigTRAP = linux.SIGTRAP
)

// Linux siginfo codes that the engine reports. The values are the Linux ABI.
const (
	illIllOpc  = 1
	trapBrkpt  = 1
	busAdrAln  = 1
	busAdrErr  = 2
	segvMapErr = 1
	segvAccErr = 2
	fpeIntDiv  = 1
	fpeIntOvf  = 2
	fpeFltDiv  = 3
	fpeFltOvf  = 4
	fpeFltUnd  = 5
	fpeFltRes  = 6
	fpeFltInv  = 7
)

// Access kinds of ExceptionInformation[0] of an access violation.
const (
	avRead    = 0
	avWrite   = 1
	avExecute = 8
)

// execRetryLimit is the number of faults at one pc that the engine retries
// without a patch before it reports SIGSEGV.
const execRetryLimit = 3

// faultStop serves an access violation. The engine repairs a fault that its
// own page state caused and reports every other fault as SIGSEGV.
func (c *Context) faultStop(ctx context.Context, mm platform.MemoryManager, as *addressSpace, th *thread, ac *arch.Context64, ev debugEvent) outcome {
	kind, addr := ev.Info[0], ev.Info[1]
	pc := th.ctx.pc()
	switch kind {
	case avExecute:
		addr = pc
		if _, _, ok := as.blockStateOf(blockRound(pc)); ok {
			// An instruction can cross into the next block. The fault then
			// names an address in the next block, and pc stays in the block
			// that is already executable. The loop patches every block that
			// the fetch window of the instruction touches.
			patched := false
			for base := blockRound(pc); base < pc+fetchWindow; base += blockSize {
				if st, _, ok := as.blockStateOf(base); !ok || st != blockData {
					continue
				}
				if err := as.patchBlock(ctx, mm, base); err != nil {
					return fatal(fmt.Errorf("patch the code page at %#x: %w", base, err), unix.ENOMEM)
				}
				patched = true
			}
			if patched {
				th.execRepeats = 0
			} else if th.lastExecPC == pc {
				th.execRepeats++
			} else {
				th.lastExecPC, th.execRepeats = pc, 1
			}
			// Without a patch, the fault can come from another thread that
			// patched the block after this thread faulted, so the thread retries.
			// A fault that repeats means that the fetch reaches a block that
			// the guest did not map for execution.
			if patched || th.execRepeats <= execRetryLimit {
				if err := th.continueEvent(ev); err != nil {
					return fatal(err, unix.EFAULT)
				}
				return running
			}
			if a := ev.Info[1]; a >= pc && a-pc < fetchWindow {
				addr = a
			}
		}
	case avWrite:
		base := blockRound(addr)
		if blockRound(pc) == base {
			// The guest writes to the page that it executes. Restoring the
			// original frame removes the execute permission under the
			// instruction, and the next fetch maps the patched copy that
			// removes the write permission again. The thread would loop, so the
			// engine reports the fault instead.
			break
		}
		if ok, err := as.restoreData(base); err != nil {
			return fatal(err, unix.ENOMEM)
		} else if ok {
			if err := th.continueEvent(ev); err != nil {
				return fatal(err, unix.EFAULT)
			}
			return running
		}
		// A writable data state means that another thread restored the block
		// after this thread faulted, so the write retries.
		if st, at, ok := as.blockStateOf(base); ok && st == blockData && at.Write {
			if err := th.continueEvent(ev); err != nil {
				return fatal(err, unix.EFAULT)
			}
			return running
		}
	}
	if th.archFault(as, ac, ev) {
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT)
		}
		return running
	}
	return c.reportFault(th, ac, ev, kind, addr, as)
}

// reportFault converts a memory fault into SIGSEGV or SIGBUS for the guest.
func (c *Context) reportFault(th *thread, ac *arch.Context64, ev debugEvent, kind, addr uint64, as *addressSpace) outcome {
	var at hostarch.AccessType
	switch kind {
	case avExecute:
		at = hostarch.Execute
	case avWrite:
		at = hostarch.Write
	default:
		at = hostarch.Read
	}
	sig, code := linux.Signal(linux.SIGSEGV), int32(segvMapErr)
	if ev.Code == statusInPageError {
		sig, code = linux.SIGBUS, busAdrErr
	} else if as.mapped(addr) {
		code = segvAccErr
	}
	if err := th.stopAndPull(ac, ev); err != nil {
		return fatal(err, unix.EFAULT)
	}
	si := &linux.SignalInfo{Signo: int32(sig), Code: code}
	si.SetAddr(addr)
	return outcome{done: true, si: si, at: at, err: platform.ErrContextSignal}
}

// mapped reports whether addr lies in a view of the window.
func (as *addressSpace) mapped(addr uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, _, ok := as.win.Lookup(addr)
	return ok
}

// Interrupt implements platform.Context.Interrupt.
func (c *Context) Interrupt() {
	c.interrupt.NotifyInterrupt()
}

// NotifyInterrupt implements interrupt.Receiver.NotifyInterrupt. The flag is
// set before the state check, and Switch tests the flag after it starts the
// thread, so one of the two sides always sees the other.
func (c *Context) NotifyInterrupt() {
	c.kicked.Store(true)
	if th := c.th.Load(); th != nil {
		th.forceStop()
	}
}

// PullFullState implements platform.Context.PullFullState. A stop copies only
// the general-purpose registers, so this call reads the vector state from the
// parked thread.
func (c *Context) PullFullState(_ platform.AddressSpace, ac *arch.Context64) error {
	if !c.fpInThread {
		return nil
	}
	th := c.th.Load()
	if th == nil {
		return nil
	}
	th.mu.Lock()
	defer th.mu.Unlock()
	if err := th.getContext(th.ctx.fpFlags()); err != nil {
		return err
	}
	th.ctx.storeFP(ac)
	c.fpInThread = false
	return nil
}

// FullStateChanged implements platform.Context.FullStateChanged. The next
// start loads the vector state from ac into the thread.
func (c *Context) FullStateChanged() {
	c.needRestoreFP = true
	c.fpInThread = false
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
