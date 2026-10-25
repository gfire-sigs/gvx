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

//go:build windows && amd64

package systrap

import (
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"sync/atomic"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// FS base on Windows amd64.
//
// A Linux guest keeps its thread pointer in the FS base. Windows resets the
// FS base of a thread to zero when it switches the thread out, and CONTEXT has
// no field for it. The engine plants a trampoline in front of the guest code
// each time it starts a thread:
//
//	wrfsbase rax        ; rax holds the guest FS base
//	mov rax, [rip+d1]   ; load the guest rax from the slot of the thread
//	jmp [rip+d2]        ; jump to the guest rip from the slot
//
// The Sentry also repairs the FS base when a guest access through %fs faults
// after Windows reset the base during a run (docs/systrap-windows.md, 3.4).

const (
	// maxSlots is the number of guest threads that one stub can hold. Each
	// thread owns one trampoline and one data slot.
	maxSlots = 512

	// trampStride is the distance between two trampolines in the code pages.
	trampStride = 32
	// fsRepairLimit is the number of consecutive repairs at one pc with the
	// same registers that the engine allows. A repair that works changes the
	// registers when the instruction runs, so identical registers mean that
	// the repair brought no progress.
	fsRepairLimit = 8

	// slotBase is the offset of the data slots, and slotStride is the size of
	// one slot: the guest rax, then the guest rip. The data pages follow the
	// code pages.
	slotBase   = codeSize
	slotStride = 16
)

// The trampolines end where the spill routine starts, and the data slots fit in
// the data pages of the engine.
var (
	_ = [winSpillOffset - maxSlots*trampStride]struct{}{}
	_ = [winEnginePagesSize - slotBase - maxSlots*slotStride]struct{}{}
)

// fetchWindow is the longest instruction in bytes. A fetch of one instruction
// touches at most this many bytes from pc.
const fetchWindow = amd64MaxInsnLen

// archProc is the amd64 state of a stub process.
type archProc struct {
	slots [maxSlots]bool
	// fsRepairs counts the guest accesses through %fs that faulted because
	// Windows reset the FS base, and that the engine repaired.
	fsRepairs atomic.Uint64
}

// archThread is the amd64 state of a guest thread.
type archThread struct {
	// slot is the trampoline slot plus one. Zero means that the thread has none.
	slot int
	// fsFix tracks the last FS base repair. Windows resets the base at every
	// context switch, so a loop can fault at the same pc many times. A loop
	// that waits in the kernel on each pass, for example on a page of a file
	// view, faults at the same pc after each pass. Several repairs at one pc
	// with identical registers mean that the fault is not a lost FS base.
	fsFix struct {
		pc  uint64
		sum uint64
		n   int
	}
}

func configureArch() {}

func (th *thread) initArch() {}

func (th *thread) releaseArch() {
	if th.slot != 0 {
		th.sp.mu.Lock()
		th.sp.slots[th.slot-1] = false
		th.sp.mu.Unlock()
		th.slot = 0
	}
}

// ensureSlot allocates the trampoline slot of the thread.
func (th *thread) ensureSlot() (int, error) {
	if th.slot != 0 {
		return th.slot - 1, nil
	}
	th.sp.mu.Lock()
	defer th.sp.mu.Unlock()
	for i := range th.sp.slots {
		if !th.sp.slots[i] {
			th.sp.slots[i] = true
			th.slot = i + 1
			return i, nil
		}
	}
	return 0, fmt.Errorf("the stub process already has %d threads", maxSlots)
}

func trampAddr(slot int) uint64 { return internalBase + uint64(slot)*trampStride }

// writeInternalCode fills the code pages of the window with one trampoline for
// each slot. The rest holds INT3, so a stray jump traps.
func writeInternalCode(page []byte) {
	for i := range page {
		page[i] = 0xCC
	}
	for i := 0; i < maxSlots; i++ {
		off := i * trampStride
		code := page[off : off+trampStride]
		copy(code, []byte{0xF3, 0x48, 0x0F, 0xAE, 0xD0}) // wrfsbase rax
		code[5], code[6], code[7] = 0x48, 0x8B, 0x05     // mov rax, [rip+disp32]
		binary.LittleEndian.PutUint32(code[8:], uint32(int32(slotBase+slotStride*i-(off+12))))
		code[12], code[13] = 0xFF, 0x25 // jmp [rip+disp32]
		binary.LittleEndian.PutUint32(code[14:], uint32(int32(slotBase+slotStride*i+8-(off+18))))
		for j := 18; j < trampStride; j++ {
			code[j] = 0xCC
		}
	}
}

// goThroughTrampoline arranges that the thread loads the guest FS base before
// it runs the guest instruction at th.ctx pc. th.ctx holds the guest state.
func (th *thread) goThroughTrampoline(fsBase uint64) error {
	slot, err := th.ensureSlot()
	if err != nil {
		return err
	}
	data := th.sp.internal.local[slotBase+slotStride*slot:]
	binary.LittleEndian.PutUint64(data[0:], th.ctx.u64(ctxOffRax))
	binary.LittleEndian.PutUint64(data[8:], th.ctx.pc())
	th.ctx.put64(ctxOffRax, fsBase)
	th.ctx.setPC(trampAddr(slot))
	return nil
}

// archStart adds the FS base to the state that start loaded. A thread that
// continues at the return address of a patched SYSCALL continues in the slot
// tail, because the JMP overwrote the bytes at that address.
func (th *thread) archStart(ac *arch.Context64) error {
	th.fsFix.n = 0
	th.ctx.setPC(th.resumePC(th.ctx.pc()))
	fs := ac.StateData().Regs.Fs_base
	if fs == 0 {
		return nil
	}
	return th.goThroughTrampoline(fs)
}

// resumePC returns the address where a thread continues for the guest program
// counter pc. The return address of a SYSCALL that became a JMP lies inside the
// JMP. A new thread of clone, and a sigreturn to an interrupted system call,
// continue there. The slot tail runs the relocated instructions and jumps back
// to the code behind them, which is where the guest continues.
func (th *thread) resumePC(pc uint64) uint64 {
	as := th.sp.owner.Load()
	if as == nil {
		return pc
	}
	if tail, ok := as.jumpTail(pc); ok {
		return tail
	}
	return pc
}

// jumpTail returns the slot tail for the return address pc of a SYSCALL that
// became a JMP. The JMP overwrote the bytes at pc, so the thread must continue
// in the slot instead.
func (as *addressSpace) jumpTail(pc uint64) (uint64, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[blockRound(pc)]
	if blk == nil || blk.state != blockExec || pc-blk.base < winSiteLen {
		return 0, false
	}
	s, ok := blk.sites[uint16(pc-blk.base-winSiteLen)]
	if !ok || s.kind != winSiteJump {
		return 0, false
	}
	return s.tail, true
}

// pullArch completes the copy of the registers into ac.
func (th *thread) pullArch(*arch.Context64) {}

// inEngineCode reports whether pc lies in the engine pages or in a trampoline
// island.
func (th *thread) inEngineCode(pc uint64) bool { return inInternal(pc) || th.inIslandPC(pc) }

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. Windows uses
// the GS base for the TEB, so a guest cannot set it.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return fmt.Errorf("the GS base of a guest thread is not available on Windows")
}

// archEvent serves the stops that only amd64 has: the traps of patched sites.
func (th *thread) archEvent(as *addressSpace, ac *arch.Context64, ev debugEvent) (outcome, bool) {
	if ev.Code != statusBreakpoint || ev.State == dbgStateSingleStep {
		return outcome{}, false
	}
	if th.isFastExit(ev) {
		return th.fastExit(ac, ev), true
	}
	site, ok := as.siteAt(ev.Addr)
	if !ok {
		return outcome{}, false
	}
	th.fsFix.n = 0
	switch site.kind {
	case amd64SiteSyscall:
		th.ctx.setPC(ev.Addr + 2)
		if err := th.stopAndPull(ac, ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		r := &ac.StateData().Regs
		// The SYSCALL instruction leaves the return address in RCX and the
		// flags in R11.
		r.Rcx = r.Rip
		r.R11 = r.Eflags
		r.Orig_rax = r.Rax
		return outcome{done: true}, true
	case amd64SiteRDFSBASE:
		v := ac.StateData().Regs.Fs_base
		if !site.wide {
			v &= 0xFFFFFFFF
		}
		th.ctx.put64(120+8*int(site.reg), v)
		th.ctx.setPC(ev.Addr + uint64(site.length))
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	}
	return outcome{}, false
}

// illegalSignal classifies an illegal-instruction exception.
func (th *thread) illegalSignal(*addressSpace, uint64) (linuxSig, int32) { return sigILL, illIllOpc }

// archFault repairs a guest access through %fs that faulted because Windows
// reset the FS base. It returns true when it changed th.ctx so that the thread
// loads the base and runs the instruction again.
func (th *thread) archFault(as *addressSpace, ac *arch.Context64, ev debugEvent) bool {
	fs := ac.StateData().Regs.Fs_base
	pc := th.ctx.pc()
	if fs != 0 && ev.Info[0] != avExecute && !nearZeroBase(ev.Info[1], as.p.userMin) {
		// A thread with a valid base faults at the real address, not near
		// zero. The fault is a page of the guest that the Sentry has to map.
		return false
	}
	if fs == 0 || ev.Info[0] == avExecute {
		if traceEvents && ev.Info[0] != avExecute && ev.Info[1] < 0x10000 {
			tracef("pid %d thread %d: no FS repair, the guest FS base is zero, fault at %#x, pc %#x", th.sp.pid, th.tid, ev.Info[1], pc)
		}
		return false
	}
	sum := th.ctx.registerSum()
	if th.fsFix.pc == pc && th.fsFix.sum == sum && th.fsFix.n >= fsRepairLimit {
		tracef("pid %d thread %d: no FS repair, %d repairs at pc %#x without progress", th.sp.pid, th.tid, th.fsFix.n, pc)
		return false
	}
	code := as.codeBytes(pc, 15)
	if !hasFSPrefix(code) {
		if traceEvents && ev.Info[1] < 0x10000 {
			tracef("pid %d thread %d: no FS repair, no FS prefix at pc %#x, fault at %#x, code % x", th.sp.pid, th.tid, pc, ev.Info[1], code)
		}
		return false
	}
	if err := th.goThroughTrampoline(fs); err != nil {
		tracef("pid %d thread %d: no FS repair, trampoline: %v", th.sp.pid, th.tid, err)
		return false
	}
	if traceAll {
		tracef("pid %d thread %d: FS repair at pc %#x, fault at %#x, access %d", th.sp.pid, th.tid, pc, ev.Info[1], ev.Info[0])
	}
	if th.fsFix.pc == pc && th.fsFix.sum == sum {
		th.fsFix.n++
	} else {
		th.fsFix.n = 1
	}
	th.fsFix.pc, th.fsFix.sum = pc, sum
	th.sp.fsRepairs.Add(1)
	return true
}

// fsBaseReach is the distance from zero, in both directions, that an access
// through a lost FS base can reach.
const fsBaseReach = 1 << 24

// nearZeroBase reports whether an access at addr is at an offset from a zero
// base: a small positive offset, or a small negative one that wraps. Guest
// memory starts at guestMin, so a positive offset never reaches it. With the
// low window guestMin is 0x10000, and an access above it is a real guest
// access, for example to the TLS block of a static executable.
func nearZeroBase(addr, guestMin uint64) bool {
	return addr < min(fsBaseReach, guestMin) || addr > ^uint64(0)-fsBaseReach
}

// registerSum returns a hash of the flags and the general-purpose registers in
// the record. Two stops with the same pc and the same hash made no progress
// between them.
func (c *hostContext) registerSum() uint64 {
	h := fnv.New64a()
	h.Write(c.buf[ctxOffEFlags:ctxOffRip])
	return h.Sum64()
}

// hasFSPrefix reports whether the instruction at the start of code carries an
// FS segment override prefix.
func hasFSPrefix(code []byte) bool {
	for _, b := range code {
		switch {
		case b == 0x64:
			return true
		case b == 0x65, b == 0x2E, b == 0x36, b == 0x3E, b == 0x26, b == 0x66, b == 0x67, b == 0xF0, b == 0xF2, b == 0xF3:
		case b >= 0x40 && b <= 0x4F:
		default:
			return false
		}
	}
	return false
}

// siteInfo describes one patched instruction.
type siteInfo struct {
	kind   amd64SiteKind
	reg    uint8
	wide   bool
	length uint8
	// tail is the address of the slot tail of a winSiteJump.
	tail uint64
}

// winSiteJump marks the SYSCALL that became a JMP to a slot. The debugger
// never sees a trap there, so the kind only serves resumePC.
const winSiteJump amd64SiteKind = 0x80

// patchPage replaces the SYSCALL and RDFSBASE instructions of one page with
// traps. page is a copy of the original frame. With the fast path, a SYSCALL
// whose following instructions can move becomes a JMP to a trampoline slot,
// and every other SYSCALL keeps the trap.
func (as *addressSpace) patchPage(ctx context.Context, mm platform.MemoryManager, base uint64, page []byte) (map[uint16]siteInfo, []winSlotRef, error) {
	before := as.neighborBytes(base, true, amd64MaxInsnLen)
	after := as.neighborBytes(base, false, amd64MaxInsnLen)
	found := scanAMD64(before, page, after)
	scope := as.p.scopeOf(ctx, mm, base)
	var plan *jmpPlanner
	if as.p.fast {
		// The plan reads the original bytes, because an earlier patch changes
		// the page. A wider neighbor window catches branches that start more
		// than one instruction before or after the page boundary.
		jmpBefore := as.neighborBytes(base, true, winJmpNeighborLen)
		jmpAfter := as.neighborBytes(base, false, winJmpNeighborLen)
		plan = newJmpPlanner(jmpBefore, append([]byte(nil), page...), jmpAfter)
	}
	var keep []amd64Site
	var slots []winSlotRef
	sites := make(map[uint16]siteInfo, len(found))
	// jumpEnd is the end of the bytes that the last JMP patch owns.
	jumpEnd := 0
	for _, s := range found {
		// A file image proves which bytes are code. Anonymous memory and files
		// without section headers give no proof, and the decoder alone decides.
		if scope.proven() && !scope.containsRange(base+uint64(max(s.Offset, 0)), uint64(s.Len)) {
			continue
		}
		if jumpEnd > 0 && s.Offset < jumpEnd {
			// The bytes of this site belong to the previous slot.
			continue
		}
		if as.p.fast && s.Kind == amd64SiteSyscall && s.Offset >= 0 {
			if end, tail, ref, ok := as.patchJump(ctx, mm, base, plan, page, s.Offset); ok {
				jumpEnd = end
				sites[uint16(s.Offset)] = siteInfo{kind: winSiteJump, tail: tail}
				slots = append(slots, ref)
				continue
			}
		}
		keep = append(keep, s)
		if s.Offset >= 0 {
			sites[uint16(s.Offset)] = siteInfo{kind: s.Kind, reg: s.Reg, wide: s.Wide, length: uint8(s.Len)}
		}
	}
	if _, err := patchAMD64(page, keep); err != nil {
		as.mu.Lock()
		freeSlotRefsLocked(slots)
		as.mu.Unlock()
		return nil, nil, err
	}
	return sites, slots, nil
}

// patchJump replaces the SYSCALL at offset off of page with a JMP to a new
// slot. It returns the end of the bytes that the patch owns, the address of
// the slot tail, and the slot reference, or false when the site keeps its trap.
func (as *addressSpace) patchJump(ctx context.Context, mm platform.MemoryManager, base uint64, plan *jmpPlanner, page []byte, off int) (int, uint64, winSlotRef, bool) {
	if hasPrefixBefore(plan.before, plan.page, off) {
		// A prefix would apply to the JMP.
		return 0, 0, winSlotRef{}, false
	}
	reloc, ok := plan.plan(off)
	if !ok {
		return 0, 0, winSlotRef{}, false
	}
	site := base + uint64(off)
	slotVA, ref, err := as.installSlot(ctx, mm, site, winSlotSize, func(buf []byte, slotVA uint64) error {
		return encodeWinSlot(buf, slotVA, site, as.p.spillVA(), reloc)
	})
	if err == nil {
		if err = patchJmp(page, off, site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.free(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		if traceEvents {
			tracef("no trampoline slot for the SYSCALL at %#x: %v", site, err)
		}
		return 0, 0, winSlotRef{}, false
	}
	return off + winSiteLen + len(reloc), slotVA + winSlotTailOffset, ref, true
}

// hasPrefixBefore reports whether the byte in front of page[off] is an
// instruction prefix, a legacy prefix or REX.
func hasPrefixBefore(before, page []byte, off int) bool {
	var b byte
	switch {
	case off > 0:
		b = page[off-1]
	case len(before) > 0:
		b = before[len(before)-1]
	default:
		return false
	}
	switch {
	case b >= 0x40 && b <= 0x4F:
		return true
	}
	switch b {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
		return true
	}
	return false
}

// newWinTrap describes the trap of the SYSCALL at site.
func newWinTrap(site uint64, _ *winRegs) winTrap {
	return winTrap{site: site, ret: winSiteReturn(site)}
}

// archFastTrap adds the amd64 state to the registers of a fast trap.
func (th *thread) archFastTrap(*arch.Context64) { th.fsFix.n = 0 }

// archFastHot reports whether the thread can resume without a debug stop. The
// stub loads the FS base on every return.
func (th *thread) archFastHot(*arch.Context64) bool { return true }

// archPC returns the program counter of ac.
func archPC(ac *arch.Context64) uint64 { return ac.StateData().Regs.Rip }

// archAttachFast names the winSysmsg to the spill routine through the TEB.
func (th *thread) archAttachFast(slot *fastSlot) error { return th.writeTEBSysmsg(slot.va) }

// archFastSetFP writes the vector state of ac into the sysmsg of a thread that
// waits in the spill routine. The routine loads the image with XRSTOR on the
// next resume, because the calls of the routine clobber the live registers.
// Callers hold mu.
func (th *thread) archFastSetFP(f *fastThread, ac *arch.Context64) error {
	f.slot.sm.loadVector(ac, xstateMask())
	return nil
}

// archFastGetFP reads the vector state that the spill routine saved in the
// sysmsg of a thread that waits in it into ac. Callers hold mu.
func (th *thread) archFastGetFP(f *fastThread, ac *arch.Context64) error {
	f.slot.sm.storeVector(ac)
	return nil
}

// probeProgram returns the guest code of Probe: calls system calls with
// number 5, then one with number 6.
func probeProgram(calls int) []byte {
	n := uint32(calls)
	return []byte{
		0x41, 0xBC, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24), // mov r12d, calls
		0xB8, 5, 0, 0, 0, // loop: mov eax, 5
		0x0F, 0x05, // syscall
		0x41, 0xFF, 0xCC, // dec r12d
		0x75, 0xF4, // jnz loop
		0xB8, 6, 0, 0, 0, // mov eax, 6
		0x0F, 0x05, // syscall
	}
}

// probeSyscallNumber returns the number of the system call that stopped the guest.
func probeSyscallNumber(ac *arch.Context64) uint64 { return ac.StateData().Regs.Orig_rax }
