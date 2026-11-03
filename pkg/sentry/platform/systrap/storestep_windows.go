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

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// A guest can store into the page that holds the instruction that it runs.
// The stub never executes the original frame, so the engine cannot give that
// page write and execute access at once without running unpatched code. The
// engine serves such a store with a store step:
//
//  1. The write fault names a page that the thread also fetches from. The
//     engine maps the patched copy of that page as read, write, and execute,
//     and it keeps the bytes that the copy had.
//  2. The engine sets the single-step flag and lets the thread repeat the
//     store. The store changes the copy and the trap follows at once.
//  3. At the trap, the engine makes the copy read-only again, and it writes
//     every byte that differs from the kept bytes to the original frame. Then
//     it drops the copy of the page and the copies of the same frame in other
//     blocks. The next fetch patches the new bytes.
//
// A store through a second view of the executing frame works the same way. The
// engine makes the lowered view writable for the step, and at the trap it
// drops every copy of the frame.
//
// Other threads of the stub run while the window is open. They can run the
// copy with the new bytes before the engine patches it. That is a race of the
// guest, which has no promise about code that it changes while another thread
// runs it. The window is one instruction long.

// storeFaultLimit is the number of write faults of one thread that open a
// window without a completed step between them. The faults repeat when another
// thread keeps lowering the view or dropping the copy during the step.
const storeFaultLimit = 16

// storeRepeatLimit is the number of single steps that the engine spends on one
// instruction that does not retire, such as a REP store. Then it closes the
// window and lets the instruction run. The next store into the page opens a
// new window, so the instruction still makes progress.
const storeRepeatLimit = 64

// storeWindow is the extra access that one store step granted.
type storeWindow struct {
	// blk is the block whose copy maps read, write, and execute. It is nil for
	// the window of a lowered view.
	blk *execBlock
	// view is the page of the lowered view that the window made writable, and
	// key names the frame that it maps. They are set when blk is nil.
	view uint64
	key  frameKey
}

// storeStep records the windows that one thread opened for one store.
type storeStep struct {
	windows []storeWindow
	// pc is the program counter of the store.
	pc uint64
	// steps counts the single steps since the first fault.
	steps int
}

func (st *storeStep) has(w storeWindow) bool {
	for _, o := range st.windows {
		if o == w {
			return true
		}
	}
	return false
}

type windowResult uint8

const (
	// windowNone means that the fault does not belong to a store step.
	windowNone windowResult = iota
	// windowRetry means that the page changed state after the fault. The
	// thread repeats the store.
	windowRetry
	// windowOpen means that the page accepts the store now.
	windowOpen
)

// fetchesFrameLocked reports whether a block that the instruction at pc
// fetches from copies the frame key. Callers hold as.mu.
func (as *addressSpace) fetchesFrameLocked(pc uint64, key frameKey) bool {
	for base := blockRound(pc); base < pc+fetchWindow; base += blockSize {
		if blk := as.blocks[base]; blk != nil {
			if k, ok := blk.frameID(); ok && k == key {
				return true
			}
		}
	}
	return false
}

// openStoreWindow gives the instruction at pc the access that a store to addr
// needs, when that store belongs to a store step.
func (as *addressSpace) openStoreWindow(addr, pc uint64) (storeWindow, windowResult, error) {
	page := blockRound(addr)
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return storeWindow{}, windowNone, nil
	}
	if key, ok := as.aliasProt[page]; ok && as.fetchesFrameLocked(pc, key) {
		if !as.aliasStillLoweredLocked(page, key) {
			// Another thread restored the view after this thread faulted.
			delete(as.aliasProt, page)
			return storeWindow{}, windowRetry, nil
		}
		if err := as.win.Protect(page, blockSize, viewReadWrite); err != nil {
			return storeWindow{}, windowNone, as.mapErr(fmt.Errorf("make the view at %#x writable: %w", page, err))
		}
		delete(as.aliasProt, page)
		return storeWindow{view: page, key: key}, windowOpen, nil
	}
	if page < blockRound(pc) || page >= pc+fetchWindow {
		return storeWindow{}, windowNone, nil
	}
	blk := as.blocks[page]
	switch {
	case blk == nil:
		return storeWindow{}, windowNone, nil
	case blk.state != blockExec:
		// Another thread dropped the copy after this thread faulted. The
		// repeated store fetches the page again and faults on a new copy.
		if blk.at.Write {
			return storeWindow{}, windowRetry, nil
		}
		return storeWindow{}, windowNone, nil
	case !blk.at.Write || !blk.hasPriv || blk.src == 0:
		return storeWindow{}, windowNone, nil
	}
	if blk.stepSnap == nil {
		snap := make([]byte, blockSize)
		copy(snap, blk.priv.bytes())
		// A view can only lose access after it is mapped, so the window maps
		// the copy again. A store that another thread makes before the new
		// view appears faults, and a store after it lands in the copy.
		if err := as.win.Map(page, blockSize, &blk.priv.chunk.ref, blk.priv.off, viewReadWriteExec); err != nil {
			return storeWindow{}, windowNone, as.mapErr(fmt.Errorf("make the copy at %#x writable: %w", page, err))
		}
		blk.stepSnap = snap
	}
	return storeWindow{blk: blk}, windowOpen, nil
}

// storeWindowOpen reports whether a store step holds the block at base open
// for writes.
func (as *addressSpace) storeWindowOpen(base uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[base]
	return blk != nil && blk.stepSnap != nil
}

// closeStoreWindowLocked makes the copy of blk read-only again, writes the
// bytes that the window changed to the original frame, and drops the copy. It
// returns the key of the frame and true when the frame changed, because the
// other copies of the frame are stale then. A window that another call
// already closed, or that the block lost, has nothing to do. Callers hold
// as.mu.
func (as *addressSpace) closeStoreWindowLocked(blk *execBlock) (frameKey, bool, error) {
	if as.released || as.blocks[blk.base] != blk || blk.stepSnap == nil || blk.state != blockExec {
		return frameKey{}, false, nil
	}
	snap := blk.stepSnap
	blk.stepSnap = nil
	// Stores that land after this call fault, and the next step reopens a
	// window. So every store that the diff misses faults again.
	if err := as.win.Map(blk.base, blockSize, &blk.priv.chunk.ref, blk.priv.off, viewReadExec); err != nil {
		return frameKey{}, false, as.mapErr(fmt.Errorf("close the window at %#x: %w", blk.base, err))
	}
	cur, orig := blk.priv.bytes(), blk.frame()
	changed := false
	for i := range cur {
		if cur[i] != snap[i] {
			orig[i] = cur[i]
			changed = true
		}
	}
	if !changed {
		return frameKey{}, false, nil
	}
	key, _ := blk.frameID()
	return key, true, as.returnToDataLocked(blk)
}

// closeStoreStep closes the windows of st and drops the copies that the
// stores made stale.
func (as *addressSpace) closeStoreStep(st *storeStep) error {
	var drops []frameKey
	var first error
	keep := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	as.mu.Lock()
	for _, w := range st.windows {
		if w.blk == nil {
			drops = append(drops, w.key)
			continue
		}
		key, changed, err := as.closeStoreWindowLocked(w.blk)
		keep(err)
		if changed {
			drops = append(drops, key)
		}
	}
	as.mu.Unlock()
	for _, key := range drops {
		keep(as.p.alias.dropAll(key))
	}
	// A view stays writable only while no copy of its frame exists.
	as.mu.Lock()
	for _, w := range st.windows {
		if w.blk == nil {
			keep(as.relowerLocked(w.view, w.key))
		}
	}
	as.mu.Unlock()
	return first
}

// closeStoreStepLocked closes the store step of the thread. Callers hold th.mu.
func (th *thread) closeStoreStepLocked() error {
	st := th.storeStep
	if st == nil {
		return nil
	}
	th.storeStep = nil
	as := th.sp.owner.Load()
	if as == nil {
		return nil
	}
	return as.closeStoreStep(st)
}

// abortStoreStep closes the store step of a thread that goes away.
func (th *thread) abortStoreStep() {
	th.mu.Lock()
	defer th.mu.Unlock()
	if err := th.closeStoreStepLocked(); err != nil {
		tracef("pid %d thread %d: close the store step: %v", th.sp.pid, th.tid, err)
	}
}

// serveStoreFault serves a write fault of a thread that fetches from the page
// it writes, or from a page that maps the frame it writes. It reports false
// when the fault is not such a store.
func (th *thread) serveStoreFault(as *addressSpace, ev debugEvent, addr uint64) (outcome, bool) {
	pc := th.ctx.pc()
	if th.inEngineCode(pc) || th.archNoStoreStep(as, pc) || th.storeFaults >= storeFaultLimit {
		return outcome{}, false
	}
	w, res, err := as.openStoreWindow(addr, pc)
	if err != nil {
		return fatal(err, unix.ENOMEM), true
	}
	switch res {
	case windowNone:
		return outcome{}, false
	case windowRetry:
		if err := th.continueUnchanged(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	}
	th.storeFaults++
	if th.storeStep == nil {
		th.storeStep = &storeStep{pc: pc}
	}
	if !th.storeStep.has(w) {
		th.storeStep.windows = append(th.storeStep.windows, w)
	}
	if err := th.continueEvent(ev); err != nil {
		return fatal(err, unix.EFAULT), true
	}
	return running, true
}

// storeStepStop serves the single step that follows a store. It reports false
// when the thread has no store step.
func (th *thread) storeStepStop(ev debugEvent) (outcome, bool) {
	st := th.storeStep
	if st == nil {
		return outcome{}, false
	}
	st.steps++
	if th.ctx.pc() == st.pc && st.steps < storeRepeatLimit {
		// The instruction did not retire, as a REP store does after one
		// iteration. The next iteration needs the window too.
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	}
	th.storeFaults = 0
	if err := th.closeStoreStepLocked(); err != nil {
		return fatal(err, unix.ENOMEM), true
	}
	if th.stepping {
		// A forced stop waits for this thread. The normal path parks it.
		return outcome{}, false
	}
	th.ctx.setSingleStep(false)
	if err := th.continueEvent(ev); err != nil {
		return fatal(err, unix.EFAULT), true
	}
	return running, true
}
