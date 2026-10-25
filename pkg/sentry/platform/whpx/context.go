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

package whpx

import (
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	pkgcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/interrupt"
)

// fpImageSize is the size of a saved floating-point image. It covers an
// FXSAVE area with an XSAVE header on amd64 and the arm64 image.
const fpImageSize = 576

// fpWhere tells where the current floating-point state of a Context lives.
type fpWhere uint8

const (
	// fpInAC means the arch.Context64 holds the state. A new Context and a
	// Context after FullStateChanged start here.
	fpInAC fpWhere = iota

	// fpOnVP means the registers of a virtual processor hold the state.
	fpOnVP

	// fpSaved means the Context saved the state in its own buffer after
	// another Context took over its virtual processor.
	fpSaved
)

// runResult is what a Switch returns to the Sentry.
type runResult struct {
	sig *linux.SignalInfo
	at  hostarch.AccessType
	err error
}

// cancelAction tells the run loop what to do after a cancelled run.
type cancelAction uint8

const (
	// cancelContinue runs the virtual processor again.
	cancelContinue cancelAction = iota

	// cancelInterrupt returns ErrContextInterrupt to the Sentry.
	cancelInterrupt
)

// rootStale reports whether the processor may hold a translation root other
// than the current one of as. prepareRun writes the root register of the
// processor on the host when it returns true.
func rootStale(st *vpState, as *AddressSpace, gen uint64) bool {
	return !st.valid || st.asID != as.id || st.asGen != gen
}

// Context implements platform.Context for one application thread.
type Context struct {
	platform.NoCPUNumbers

	p         *Platform
	interrupt interrupt.Forwarder

	// vp is the virtual processor that runs this Context, or nil.
	vp atomic.Pointer[vcpu]

	// kicked records an interrupt that arrived while the Context prepared to
	// enter the guest.
	kicked atomic.Bool

	// lastVP is the virtual processor of the last Switch. Only the task
	// goroutine and acquire (under Platform.mu) read it.
	lastVP *vcpu

	// parkDirty tells the next Switch that the Sentry changed register state
	// that lives inside the virtual processor.
	parkDirty bool

	// fpMu guards the floating-point residency below. A goroutine that
	// holds Platform.mu may take fpMu. The reverse order never happens.
	fpMu      sync.Mutex
	fpWhere   fpWhere
	fpVP      *vcpu
	fpSaved   []byte
	fpACFresh bool
	fpErr     error
}

func newContext(p *Platform) *Context {
	c := &Context{p: p, fpACFresh: true}
	c.interrupt.Dst = c
	return c
}

// NotifyInterrupt implements interrupt.Receiver. It stops the virtual
// processor of a running Switch or wakes a Context waiting for a free vCPU.
func (c *Context) NotifyInterrupt() {
	c.kicked.Store(true)
	if v := c.vp.Load(); v != nil {
		v.kickRunning()
		return
	}
	c.p.mu.Lock()
	if c.p.waiters > 0 {
		c.p.cond.Broadcast()
	}
	c.p.mu.Unlock()
}

// affinityVP returns the virtual processor that Switch must use, or the one
// it prefers. The caller holds Platform.mu.
func (c *Context) affinityVP() *vcpu {
	if c.fpWhere == fpOnVP {
		return c.fpVP
	}
	return c.lastVP
}

// evict moves the floating-point state of c out of v. The caller holds
// Platform.mu and has marked v busy, so no guest code runs on v.
func (c *Context) evict(v *vcpu) {
	c.fpMu.Lock()
	defer c.fpMu.Unlock()
	if c.fpWhere == fpOnVP && c.fpVP == v {
		if c.fpSaved == nil {
			c.fpSaved = make([]byte, fpImageSize)
		}
		if err := v.readFP(c.fpSaved); err != nil {
			c.fpErr = fmt.Errorf("whpx: save floating-point state: %w", err)
		} else {
			c.fpWhere = fpSaved
		}
		c.fpVP = nil
	}
	v.fpOwner = nil
}

// Switch implements platform.Context.Switch.
func (c *Context) Switch(_ pkgcontext.Context, mm platform.MemoryManager, ac *arch.Context64, _ int32) (sig *linux.SignalInfo, at hostarch.AccessType, retErr error) {
	as, ok := mm.AddressSpace().(*AddressSpace)
	if !ok || as == nil || as.p != c.p {
		return nil, hostarch.NoAccess, fmt.Errorf("whpx: address space does not belong to this platform")
	}
	if as.dead.Load() {
		return nil, hostarch.NoAccess, fmt.Errorf("whpx: address space is released")
	}
	// Clear the flag before Enable, so that an interrupt after Enable keeps it.
	c.kicked.Store(false)
	if !c.interrupt.Enable() {
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	defer func() {
		c.interrupt.Disable()
		if retErr != platform.ErrContextInterrupt && c.kicked.Swap(false) {
			c.interrupt.NotifyInterrupt()
		}
	}()

	// The hypervisor runs a virtual processor on the calling thread, and the
	// restricted token binds to that thread.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if init := c.p.opts.ThreadInit; init != nil {
		if err := init(); err != nil {
			return nil, hostarch.NoAccess, fmt.Errorf("whpx: initialize vCPU thread: %w", err)
		}
	}

	v, err := c.p.acquire(c)
	if err != nil {
		return nil, hostarch.NoAccess, err
	}
	defer c.p.release(v)
	c.lastVP = v
	c.vp.Store(v)
	defer c.vp.Store(nil)

	r := c.run(v, as, ac)
	return r.sig, r.at, r.err
}

// run enters the guest on v and returns when the guest needs the Sentry.
func (c *Context) run(v *vcpu, as *AddressSpace, ac *arch.Context64) runResult {
	// Register with the address space before reading its generation. An
	// invalidation then either kicks this processor or finds the new
	// generation on entry.
	as.addActive(v)
	defer as.removeActive(v)
	v.enter()
	defer v.leave()
	if v.p.closing.Load() {
		return runResult{err: errClosed}
	}

	if r, done := c.prepareRun(v, as, ac); done {
		return r
	}
	if c.kicked.Swap(false) {
		// The run did not happen, so the processor never executed the
		// reload path that prepareRun set up. Forget the state, so that the
		// next entry writes the root register again.
		v.st.invalidate()
		return runResult{err: platform.ErrContextInterrupt}
	}
	for {
		if err := v.p.be.run(v.index, v.exit); err != nil {
			v.st.invalidate()
			return runResult{err: fmt.Errorf("whpx: run virtual processor %d: %w", v.index, err)}
		}
		ex, err := v.decodeExit()
		if err != nil {
			v.st.invalidate()
			return runResult{err: err}
		}
		switch ex.kind {
		case exitStub:
			r, resume := c.onStubExit(v, ex, ac)
			if resume {
				continue
			}
			return r
		case exitCanceled:
			if ExitReason(atomic.LoadUint32(&v.comm.ExitReason)) != ExitNone {
				// The stub finished spilling guest state into the CommPage
				// right as WHvCancelRunVirtualProcessor stopped the vCPU at
				// HLT/HVC. Serve the completed stub exit instead of treating
				// the post-HLT/HVC PC as a mid-stub cancellation.
				r, resume := c.onStubExit(v, ex, ac)
				if resume {
					continue
				}
				return r
			}
			action, err := c.onCancel(v, ex, ac)
			if err != nil {
				v.st.invalidate()
				return runResult{err: err}
			}
			if action == cancelContinue {
				continue
			}
			return runResult{err: platform.ErrContextInterrupt}
		case exitMemory:
			return c.onMemoryFault(v, ex, ac)
		default:
			v.st.invalidate()
			return runResult{err: fmt.Errorf("whpx: virtual processor %d stopped unexpectedly: %v", v.index, ex)}
		}
	}
}

// decodeExit decodes the exit context of the last run.
func (v *vcpu) decodeExit() (exitInfo, error) {
	if v.p.arm64 {
		return decodeExitA64(v.exit)
	}
	return decodeExitX64(v.exit)
}

// acImage returns the floating-point image of ac.
func acImage(ac *arch.Context64) []byte {
	return []byte(*ac.FloatingPointData())
}

// PullFullState implements platform.Context.PullFullState. It copies the
// floating-point state out of the virtual processor into ac.
func (c *Context) PullFullState(_ platform.AddressSpace, ac *arch.Context64) error {
	c.fpMu.Lock()
	defer c.fpMu.Unlock()
	if c.fpErr != nil {
		return c.fpErr
	}
	if c.fpWhere == fpInAC || c.fpACFresh {
		return nil
	}
	image := acImage(ac)
	switch c.fpWhere {
	case fpOnVP:
		if err := c.fpVP.readFP(image); err != nil {
			return fmt.Errorf("whpx: pull floating-point state: %w", err)
		}
	case fpSaved:
		copy(image, c.fpSaved)
	}
	c.fpACFresh = true
	return nil
}

// FullStateChanged implements platform.Context.FullStateChanged.
func (c *Context) FullStateChanged() {
	c.fpMu.Lock()
	c.fpWhere = fpInAC
	c.fpVP = nil
	c.fpACFresh = true
	c.fpErr = nil
	c.fpMu.Unlock()
	c.parkDirty = true
}

// ensureFP loads the floating-point state of c into v when v does not hold it.
func (c *Context) ensureFP(v *vcpu, ac *arch.Context64) error {
	claimed, err := c.loadFP(v, ac)
	if claimed {
		// Platform.mu guards fpOwner. v is busy, so no other Context takes it.
		c.p.mu.Lock()
		v.fpOwner = c
		c.p.mu.Unlock()
	}
	return err
}

// loadFP does the work of ensureFP under fpMu. It reports whether the state
// moved onto v.
func (c *Context) loadFP(v *vcpu, ac *arch.Context64) (claimed bool, err error) {
	c.fpMu.Lock()
	defer c.fpMu.Unlock()
	if c.fpErr != nil {
		return false, c.fpErr
	}
	switch {
	case c.fpWhere == fpOnVP && c.fpVP == v:
		c.fpACFresh = false
		return false, nil
	case c.fpWhere == fpOnVP:
		return false, fmt.Errorf("whpx: floating-point state is on virtual processor %d, not %d", c.fpVP.index, v.index)
	}
	image := acImage(ac)
	if c.fpWhere == fpSaved {
		image = c.fpSaved
	}
	if err := v.writeFP(image); err != nil {
		return false, fmt.Errorf("whpx: load floating-point state: %w", err)
	}
	c.fpWhere = fpOnVP
	c.fpVP = v
	c.fpACFresh = false
	return true, nil
}

// Interrupt implements platform.Context.Interrupt.
func (c *Context) Interrupt() { c.interrupt.NotifyInterrupt() }

// Preempt implements platform.Context.Preempt.
func (c *Context) Preempt() { c.interrupt.Preempt() }

// Release implements platform.Context.Release.
func (c *Context) Release() {
	c.fpMu.Lock()
	v := c.fpVP
	c.fpWhere = fpInAC
	c.fpVP = nil
	c.fpSaved = nil
	c.fpMu.Unlock()
	c.p.mu.Lock()
	if v != nil && v.fpOwner == c {
		v.fpOwner = nil
	}
	c.lastVP = nil
	c.p.mu.Unlock()
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
