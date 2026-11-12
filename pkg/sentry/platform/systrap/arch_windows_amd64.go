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
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"unsafe"

	"golang.org/x/arch/x86/x86asm"
	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
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

	// guardCodeBase and guardDataBase locate the per-thread scratch slots that
	// execute sanitized non-GPR instructions covered by amd64SiteGuardedInsn.
	guardCodeBase   = winGuardCodeOffset
	guardCodeStride = 28
	guardDataBase   = slotBase + maxSlots*slotStride
	guardDataStride = 16
)

// The trampolines end where the spill routine starts, the guarded-site code
// slots fit behind the spill region, and the data slots fit in the data pages
// of the engine.
var (
	_ = [winSpillOffset - maxSlots*trampStride]struct{}{}
	_ = [winCodeSize - guardCodeBase - maxSlots*guardCodeStride]struct{}{}
	_ = [winEnginePagesSize - guardDataBase - maxSlots*guardDataStride]struct{}{}
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
	// fsNonZero is true when the thread loaded a non-zero FS base since its
	// last start with zero. A recycled parked thread uses it to clear a stale
	// FS base when the next guest starts with Fs_base == 0.
	fsNonZero bool
	// restartPC is the guest address where the Sentry continued the thread in
	// place. The thread fetches its bytes later, from the block that is current
	// then. A patch of the block must not cover a byte behind the first byte of
	// this address with a JMP. It is zero when the thread continued in a slot,
	// and after the thread stops. continueAt writes it under as.mu.
	restartPC atomic.Uint64
	// guardSite records the active amd64SiteGuardedInsn address while the thread
	// runs a sanitized instruction in its per-thread scratch slot.
	guardSite        uint64
	guardResume      uint64
	guardSavedVal    uint64
	guardInsnLen     uint8
	guardScratchReg  uint8
	guardScratchUsed bool
}

func configureArch() {}

func (th *thread) initArch() {}

func (th *thread) resetArch() {
	th.fsFix = struct {
		pc  uint64
		sum uint64
		n   int
	}{}
	th.guardSite = 0
	th.guardResume = 0
	th.guardSavedVal = 0
	th.guardInsnLen = 0
	th.guardScratchReg = 0
	th.guardScratchUsed = false
}

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

func guardCodeAddr(slot int) uint64 {
	return internalBase + guardCodeBase + uint64(slot)*guardCodeStride
}

func inGuardCode(pc uint64) bool {
	return pc >= internalBase+guardCodeBase && pc < internalBase+guardCodeBase+maxSlots*guardCodeStride
}

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
	th.ctx.setPC(th.startPC(th.ctx.pc()))
	if f := th.fast.Load(); f != nil {
		f.slot.sm.Regs.loadTLSFrom(ac)
	}
	fs := ac.StateData().Regs.Fs_base
	if fs == 0 {
		if !th.fsNonZero {
			return nil
		}
		th.fsNonZero = false
		return th.goThroughTrampoline(0)
	}
	th.fsNonZero = true
	return th.goThroughTrampoline(fs)
}

// startPC returns the address where a thread continues when the Sentry starts
// it at the guest program counter pc. A thread that starts at the SYSCALL of a
// pre-window continues in the entry code of the slot. The Sentry sets that
// program counter to restart a system call, after the relocated instructions
// ran. The slot keeps a restart on the fast path.
func (th *thread) startPC(pc uint64) uint64 { return th.continueAt(pc, true) }

// resumePC returns the address where a thread continues for the guest program
// counter pc. The return address of a SYSCALL that became a JMP lies inside the
// JMP. A new thread of clone, and a sigreturn to an interrupted system call,
// continue there. The slot tail runs the relocated instructions and jumps back
// to the code behind them, which is where the guest continues. The relocated
// instructions of a pre-window lie inside the JMP too. A thread that starts at
// one of them, for example after a fault in it, continues at the same
// instruction in the slot.
func (th *thread) resumePC(pc uint64) uint64 { return th.continueAt(pc, false) }

// continueAt returns the address where the thread continues for the guest
// program counter pc. With syscall set, a thread at the SYSCALL of a pre-window
// continues in the entry code of the slot.
//
// A thread that continues at pc itself fetches the bytes of pc later, from the
// block that is current then. The block can have no patched copy now, and
// another thread can patch it before the fetch. A JMP of that patch can cover
// pc, and the thread would run the bytes of the JMP as code. continueAt
// therefore records pc in the same critical section that decides the
// translation, and the install of a patch reads the records under the same
// lock (see restartInsideLocked).
func (th *thread) continueAt(pc uint64, syscall bool) uint64 {
	as := th.sp.owner.Load()
	if as == nil {
		return pc
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	reader := th.slotReader()
	if entry, ok := as.relocatedEntryLocked(pc, syscall, reader); ok {
		th.restartPC.Store(0)
		return entry
	}
	if tail, ok := as.jumpTailLocked(pc, reader); ok {
		th.restartPC.Store(0)
		return tail
	}
	// A thread that continues at an address inside a slot holds the slot until
	// it stops again. The Sentry sends a thread there after a fault in a
	// relocated instruction of a post-window slot.
	as.pinSlotLocked(reader, pc)
	th.restartPC.Store(pc)
	return pc
}

// continuationsIn returns the addresses in the block at base where a thread
// continues in place, or where the tail of a slot that a thread can still run
// continues. A patch of the block must not cover a byte behind the first byte
// of such an address with a JMP. The list is empty in almost every call.
func (as *addressSpace) continuationsIn(base uint64) []uint64 {
	var out []uint64
	as.sp.mu.Lock()
	for _, th := range as.sp.threads {
		if pc := th.restartPC.Load(); pc-base < blockSize {
			out = append(out, pc)
		}
	}
	as.sp.mu.Unlock()
	as.mu.Lock()
	defer as.mu.Unlock()
	for _, isl := range as.islands {
		isl.resumes(func(pc uint64) {
			if pc-base < blockSize {
				out = append(out, pc)
			}
		})
	}
	return out
}

// clearRestart ends the record of continueAt for a thread that does not run.
func (th *thread) clearRestart() {
	th.restartPC.Store(0)
	if f := th.fast.Load(); f != nil {
		f.slot.reader.goOffline(0)
	}
}

// restartInsideLocked reports whether a thread continues at an address inside
// one of the spans of a patch for the block at base. Callers hold as.mu, which
// also orders the records that continueAt writes.
func (as *addressSpace) restartInsideLocked(base uint64, spans []patchSpan) bool {
	if len(spans) == 0 {
		return false
	}
	as.sp.mu.Lock()
	defer as.sp.mu.Unlock()
	for _, th := range as.sp.threads {
		pc := th.restartPC.Load()
		if pc-base >= blockSize {
			continue
		}
		if slices.ContainsFunc(spans, func(s patchSpan) bool { return int(pc-base) >= s.lo && int(pc-base) < s.hi }) {
			return true
		}
	}
	return false
}

// relocatedEntryLocked returns the address in a pre-window slot where a thread
// continues when it starts at the guest address pc. It returns false when pc is
// not a relocated instruction of a pre-window. With syscall set, it also
// returns the entry code of the slot for the SYSCALL of a pre-window. The
// thread that starts at the entry holds the slot as its pin (reader), because a
// drop and a reuse of the slot can follow before the thread runs. Callers hold
// as.mu.
func (as *addressSpace) relocatedEntryLocked(pc uint64, syscall bool, reader *epochReader) (uint64, bool) {
	blk := as.blocks[blockRound(pc)]
	if blk == nil || blk.state != blockExec {
		return 0, false
	}
	s, ok := blk.sites[uint16(pc-blk.base)]
	if !ok || s.entry == 0 || (s.kind == amd64SiteSyscall && !syscall) {
		return 0, false
	}
	as.pinSlotLocked(reader, s.entry)
	return s.entry, true
}

// guestPC returns the program counter that the guest has for a thread that
// stopped at pc. A thread that faults in a relocated instruction of a
// pre-window stops in the slot. The guest, a signal frame, and the musl
// cancellation check must see the address that the instruction has in the
// original code.
func (th *thread) guestPC(pc uint64) uint64 {
	if inGuardCode(pc) && th.guardSite != 0 && th.slot != 0 {
		slotAddr := guardCodeAddr(th.slot - 1)
		if pc == slotAddr {
			return th.guardSite
		}
		if pc > slotAddr && pc < slotAddr+guardCodeStride {
			return th.guardResume
		}
	}
	as := th.sp.owner.Load()
	if as == nil {
		return pc
	}
	slot, slotVA, ok := as.slotContaining(pc)
	if !ok {
		return pc
	}
	if gpc, ok := slot.guestPC(slotVA, pc); ok {
		return gpc
	}
	return pc
}

// jumpTailLocked returns the slot tail for the return address pc of a SYSCALL
// that became a JMP. The JMP overwrote the bytes at pc, so the thread must
// continue in the slot instead. The thread that starts at the tail holds the
// slot as its pin (reader), as relocatedEntryLocked explains. Callers hold
// as.mu.
func (as *addressSpace) jumpTailLocked(pc uint64, reader *epochReader) (uint64, bool) {
	blk := as.blocks[blockRound(pc)]
	if blk == nil || blk.state != blockExec || pc-blk.base < winSiteLen {
		return 0, false
	}
	s, ok := blk.sites[uint16(pc-blk.base-winSiteLen)]
	if !ok || s.kind != winSiteJump {
		return 0, false
	}
	as.pinSlotLocked(reader, s.tail)
	return s.tail, true
}

// pullArch completes the copy of the registers into ac.
func (th *thread) pullArch(ac *arch.Context64) {
	r := &ac.StateData().Regs
	rawPC := r.Rip
	if inGuardCode(rawPC) && th.guardSite != 0 && th.slot != 0 {
		slotAddr := guardCodeAddr(th.slot - 1)
		if rawPC >= slotAddr && rawPC < slotAddr+guardCodeStride {
			if th.guardScratchUsed && rawPC <= slotAddr+uint64(th.guardInsnLen) {
				putArchGPR(&r.PtraceRegs, th.guardScratchReg, th.guardSavedVal)
			}
			r.Rip = th.guestPC(rawPC)
			th.guardSite = 0
			th.guardScratchUsed = false
			return
		}
	}
	r.Rip = th.guestPC(rawPC)
}

func putArchGPR(r *linux.PtraceRegs, reg uint8, val uint64) {
	switch reg {
	case 0:
		r.Rax = val
	case 1:
		r.Rcx = val
	case 2:
		r.Rdx = val
	case 3:
		r.Rbx = val
	case 4:
		r.Rsp = val
	case 5:
		r.Rbp = val
	case 6:
		r.Rsi = val
	case 7:
		r.Rdi = val
	case 8:
		r.R8 = val
	case 9:
		r.R9 = val
	case 10:
		r.R10 = val
	case 11:
		r.R11 = val
	case 12:
		r.R12 = val
	case 13:
		r.R13 = val
	case 14:
		r.R14 = val
	case 15:
		r.R15 = val
	}
}

// inEngineCode reports whether pc lies in the engine pages or in a trampoline
// island.
func (th *thread) inEngineCode(pc uint64) bool { return inInternal(pc) || th.inIslandPC(pc) }

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. patchPage
// always patches GS-segment memory instructions on Windows amd64, so setting a
// custom GS base requires no address space state change.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return nil
}

// archEvent serves the stops that only amd64 has: the traps of patched sites.
func (th *thread) archEvent(as *addressSpace, ac *arch.Context64, ev debugEvent) (outcome, bool) {
	// The thread stopped, so it no longer runs at the address of its last
	// start. A stop that continues the thread records the next address again.
	th.restartPC.Store(0)
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
	case amd64SiteRDFSBASE, amd64SiteRDGSBASE:
		v := ac.StateData().Regs.Fs_base
		if site.kind == amd64SiteRDGSBASE {
			v = ac.StateData().Regs.Gs_base
		}
		if !site.wide {
			v &= 0xFFFFFFFF
		}
		th.ctx.put64(ctxOffRax+8*int(site.reg), v)
		th.ctx.setPC(ev.Addr + uint64(site.length))
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	case amd64SiteWRFSBASE, amd64SiteWRGSBASE:
		v := th.ctx.u64(ctxOffRax + 8*int(site.reg))
		if !site.wide {
			v &= 0xFFFFFFFF
		}
		if v >= as.p.userMax {
			th.ctx.setPC(ev.Addr)
			if err := th.stopAndPull(ac, ev); err != nil {
				return fatal(err, unix.EFAULT), true
			}
			si := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: linux.SI_KERNEL}
			return outcome{done: true, si: si, err: platform.ErrContextSignal}, true
		}
		th.ctx.setPC(ev.Addr + uint64(site.length))
		if site.kind == amd64SiteWRFSBASE {
			ac.StateData().Regs.Fs_base = v
			// A zero base must still reach the hardware when the thread
			// loaded a non-zero base before, or the old base stays live.
			if v != 0 || th.fsNonZero {
				th.fsNonZero = v != 0
				if err := th.goThroughTrampoline(v); err != nil {
					return fatal(err, unix.EFAULT), true
				}
			}
		} else {
			ac.StateData().Regs.Gs_base = v
		}
		if f := th.fast.Load(); f != nil {
			f.slot.sm.Regs.loadTLSFrom(ac)
		}
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	case amd64SiteGSMem:
		return th.emulateGSMemSite(as, ac, ev, site)
	case amd64SiteInt2E:
		th.ctx.setPC(ev.Addr)
		if err := th.stopAndPull(ac, ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		si := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: linux.SI_KERNEL}
		return outcome{done: true, si: si, err: platform.ErrContextSignal}, true
	case amd64SiteSysenter:
		th.ctx.setPC(ev.Addr)
		if err := th.stopAndPull(ac, ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		si := &linux.SignalInfo{Signo: int32(linux.SIGILL), Code: illIllOpc}
		si.SetAddr(ev.Addr)
		return outcome{done: true, si: si, err: platform.ErrContextSignal}, true
	case amd64SiteGuardedInsn:
		return th.emulateGuardedSite(as, ac, ev, site)
	}
	return outcome{}, false
}

// emulateGuardedSite executes the unmodified outer instruction at ev.Addr that
// covers an embedded raw kernel-entry byte pair without exposing the raw bytes
// to direct branches.
func (th *thread) emulateGuardedSite(as *addressSpace, ac *arch.Context64, ev debugEvent, site siteInfo) (outcome, bool) {
	code := as.codeBytes(ev.Addr, int(site.length))
	if len(code) < int(site.length) {
		return outcome{}, false
	}
	var regs [16]uint64
	for i := range regs {
		regs[i] = th.ctx.u64(ctxOffRax + 8*i)
	}
	eflags := th.ctx.u32(ctxOffEFlags)
	var preciseFaultAddr uint64
	readMem := func(addr uint64, buf []byte) bool {
		if as.readGuest(addr, buf) {
			return true
		}
		preciseFaultAddr = addr
		if len(buf) > 1 && as.inGuestRange(addr, len(buf)) {
			nextPage := blockRound(addr) + blockSize
			if nextPage > addr && nextPage < addr+uint64(len(buf)) {
				var probe [8]byte
				firstLen := int(nextPage - addr)
				if as.readGuest(addr, probe[:firstLen]) {
					preciseFaultAddr = nextPage
				}
			}
		}
		return false
	}
	writeMem := func(addr uint64, buf []byte) bool {
		if !as.inGuestRange(addr, len(buf)) {
			preciseFaultAddr = addr
			return false
		}
		end := addr + uint64(len(buf))
		for pg := blockRound(addr); pg <= blockRound(end-1); pg += blockSize {
			if pg != blockRound(ev.Addr) {
				_, _ = as.aliasWriteFault(max(addr, pg))
				_, _ = as.restoreData(pg)
			}
		}
		ok, badAddr := as.writeGuestSpanWritable(addr, buf)
		if !ok {
			preciseFaultAddr = badAddr
		}
		return ok
	}
	fsBase := ac.StateData().Regs.Fs_base
	gsBase := ac.StateData().Regs.Gs_base
	var nextPC uint64
	res := emulateGuardedX86Insn(code, ev.Addr, fsBase, gsBase, &regs, &eflags, &nextPC, readMem, writeMem)
	if res.fault {
		fAddr := res.faultAddr
		if preciseFaultAddr != 0 {
			fAddr = preciseFaultAddr
		}
		return th.guardedFaultStop(as, ac, ev, fAddr, res.faultWrite), true
	}
	if res.ok {
		for i := range regs {
			th.ctx.put64(ctxOffRax+8*i, regs[i])
		}
		th.ctx.put32(ctxOffEFlags, eflags)
		th.ctx.setPC(th.resumePC(nextPC))
		if err := th.continueEvent(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	}
	return th.runGuardedScratch(as, ac, ev, site, code, fsBase, gsBase, &regs)
}

func (th *thread) guardedFaultStop(as *addressSpace, ac *arch.Context64, ev debugEvent, faultAddr uint64, write bool) outcome {
	th.ctx.setPC(ev.Addr)
	if err := th.stopAndPull(ac, ev); err != nil {
		return fatal(err, unix.EFAULT)
	}
	at := hostarch.Read
	if write {
		at = hostarch.Write
	}
	sigCode := int32(segvMapErr)
	if as.mapped(faultAddr) {
		sigCode = segvAccErr
	}
	si := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: sigCode}
	si.SetAddr(faultAddr)
	return outcome{done: true, si: si, at: at, err: platform.ErrContextSignal}
}

// runGuardedScratch executes a sanitized instruction (such as an SSE, AVX, FPU,
// or LOCK instruction whose displacement or immediate held raw kernel-entry
// bytes, or a non-memory non-GPR instruction on a cross-instruction seam)
// inside the thread's engine-page scratch slot.
func (th *thread) runGuardedScratch(as *addressSpace, ac *arch.Context64, ev debugEvent, site siteInfo, code []byte, fsBase, gsBase uint64, regs *[16]uint64) (outcome, bool) {
	plan, ok := planGuardedScratchInsn(code, ev.Addr, fsBase, gsBase, regs)
	if !ok || len(plan.insn) == 0 || len(plan.insn) > amd64MaxInsnLen {
		return outcome{}, false
	}
	var savedVal uint64
	if plan.useScratch {
		accessLen := 1
		if inst, err := decodeX86(code); err == nil && inst.MemBytes > 0 {
			accessLen = inst.MemBytes
		}
		if !as.inGuestRange(plan.effAddr, accessLen) {
			return th.guardedFaultStop(as, ac, ev, plan.effAddr, false), true
		}
		savedVal = regs[plan.scratchReg]
	}
	slot, err := th.ensureSlot()
	if err != nil {
		return fatal(err, unix.EFAULT), true
	}
	resumeAddr := th.resumePC(ev.Addr + uint64(site.length))

	codeOff := guardCodeBase + slot*guardCodeStride
	dataOff := guardDataBase + slot*guardDataStride
	dataBuf := th.sp.internal.local[dataOff : dataOff+guardDataStride]
	binary.LittleEndian.PutUint64(dataBuf[0:], savedVal)
	binary.LittleEndian.PutUint64(dataBuf[8:], resumeAddr)

	codeBuf := th.sp.internal.local[codeOff : codeOff+guardCodeStride]
	L := copy(codeBuf, plan.insn)
	pos := L
	if plan.useScratch {
		// mov <scratchReg64>, [rip + disp1]
		rex := byte(0x48)
		if plan.scratchReg >= 8 {
			rex = 0x4C
		}
		codeBuf[pos] = rex
		codeBuf[pos+1] = 0x8B
		codeBuf[pos+2] = ((plan.scratchReg & 7) << 3) | 0x05
		disp1 := int32(dataOff - (codeOff + pos + 7))
		binary.LittleEndian.PutUint32(codeBuf[pos+3:], uint32(disp1))
		pos += 7
	}
	// jmp qword ptr [rip + disp2]
	codeBuf[pos] = 0xFF
	codeBuf[pos+1] = 0x25
	disp2 := int32((dataOff + 8) - (codeOff + pos + 6))
	binary.LittleEndian.PutUint32(codeBuf[pos+2:], uint32(disp2))
	pos += 6
	for i := pos; i < guardCodeStride; i++ {
		codeBuf[i] = amd64INT3
	}
	if hasRawKernelExit(codeBuf[:guardCodeStride]) {
		for i := 0; i < guardCodeStride; i++ {
			codeBuf[i] = amd64INT3
		}
		return outcome{}, false
	}
	slotAddr := guardCodeAddr(slot)
	if err := flushInstructionCache(th.sp.proc, uintptr(slotAddr), guardCodeStride); err != nil {
		return fatal(err, unix.EFAULT), true
	}

	th.guardSite = ev.Addr
	th.guardResume = resumeAddr
	th.guardSavedVal = savedVal
	th.guardInsnLen = uint8(L)
	th.guardScratchReg = plan.scratchReg
	th.guardScratchUsed = plan.useScratch
	if plan.useScratch {
		th.ctx.put64(ctxOffRax+8*int(plan.scratchReg), plan.effAddr)
	}
	th.ctx.setPC(slotAddr)
	if err := th.continueEvent(ev); err != nil {
		th.guardSite = 0
		th.guardScratchUsed = false
		return fatal(err, unix.EFAULT), true
	}
	return running, true
}

// emulateGSMemSite emulates a trapped GS-segment memory instruction in the stub
// process. A store goes through writeGuestSpanWritable, so a read-only or
// copy-on-write view faults and the memory manager resolves it. A direct
// WriteProcessMemory would write the shared frame without that fault.
func (th *thread) emulateGSMemSite(as *addressSpace, ac *arch.Context64, ev debugEvent, site siteInfo) (outcome, bool) {
	code := as.codeBytes(ev.Addr, int(site.length))
	if len(code) < int(site.length) {
		return outcome{}, false
	}
	var regs [16]uint64
	for i := range regs {
		regs[i] = th.ctx.u64(ctxOffRax + 8*i)
	}
	eflags := th.ctx.u32(ctxOffEFlags)
	var preciseFaultAddr uint64
	writeMem := func(addr uint64, buf []byte) bool {
		if !as.inGuestRange(addr, len(buf)) {
			preciseFaultAddr = addr
			return false
		}
		end := addr + uint64(len(buf))
		for pg := blockRound(addr); pg <= blockRound(end-1); pg += blockSize {
			if pg != blockRound(ev.Addr) {
				_, _ = as.aliasWriteFault(max(addr, pg))
				_, _ = as.restoreData(pg)
			}
		}
		ok, badAddr := as.writeGuestSpanWritable(addr, buf)
		if !ok {
			preciseFaultAddr = badAddr
		}
		return ok
	}
	res := emulateSegMemInsn(code, x86asm.GS, ac.StateData().Regs.Gs_base, &regs, &eflags, as.readGuest, writeMem)
	if res.fault {
		fAddr := res.faultAddr
		if res.faultWrite && preciseFaultAddr != 0 {
			fAddr = preciseFaultAddr
		}
		return th.guardedFaultStop(as, ac, ev, fAddr, res.faultWrite), true
	}
	if !res.ok {
		return outcome{}, false
	}
	for i := range regs {
		th.ctx.put64(ctxOffRax+8*i, regs[i])
	}
	th.ctx.put32(ctxOffEFlags, eflags)
	th.ctx.setPC(ev.Addr + uint64(site.length))
	if err := th.continueEvent(ev); err != nil {
		return fatal(err, unix.EFAULT), true
	}
	return running, true
}

// inGuestRange reports whether the n bytes at addr lie in the guest range.
func (as *addressSpace) inGuestRange(addr uint64, n int) bool {
	return n > 0 && addr >= as.p.userMin && addr+uint64(n) <= as.p.userMax
}

// readGuest reads the guest memory at addr into buf through the stub process.
func (as *addressSpace) readGuest(addr uint64, buf []byte) bool {
	if !as.inGuestRange(addr, len(buf)) {
		return false
	}
	var n uintptr
	err := windows.ReadProcessMemory(as.sp.proc, uintptr(addr), &buf[0], uintptr(len(buf)), &n)
	return err == nil && n == uintptr(len(buf))
}

// writeGuestWritable writes buf to the guest memory at addr when the stub view
// of every byte allows writes. It reports false and writes nothing for any
// other view. WriteProcessMemory makes a read-only page writable for the write.
// That would skip the write fault that the memory manager needs for copy on
// write, and the restore of a patched code block. as.mu keeps the views stable
// between the query and the write.
func (as *addressSpace) writeGuestWritable(addr uint64, buf []byte) bool {
	if !as.inGuestRange(addr, len(buf)) {
		return false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return false
	}
	var mbi windows.MemoryBasicInformation
	if err := windows.VirtualQueryEx(as.sp.proc, uintptr(addr), &mbi, unsafe.Sizeof(mbi)); err != nil {
		return false
	}
	if mbi.State != windows.MEM_COMMIT || (mbi.Protect != windows.PAGE_READWRITE && mbi.Protect != windows.PAGE_EXECUTE_READWRITE) {
		return false
	}
	if uint64(mbi.BaseAddress)+uint64(mbi.RegionSize) < addr+uint64(len(buf)) {
		return false
	}
	var n uintptr
	err := windows.WriteProcessMemory(as.sp.proc, uintptr(addr), &buf[0], uintptr(len(buf)), &n)
	return err == nil && n == uintptr(len(buf))
}

// writeGuestSpanWritable writes buf to guest memory at addr when every region
// covering [addr, addr+len(buf)) is committed and writable in the stub view.
// When a region is unmapped or read-only, it returns false and the first
// faulting address without modifying memory.
func (as *addressSpace) writeGuestSpanWritable(addr uint64, buf []byte) (bool, uint64) {
	if !as.inGuestRange(addr, len(buf)) {
		return false, addr
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return false, addr
	}
	end := addr + uint64(len(buf))
	for cur := addr; cur < end; {
		var mbi windows.MemoryBasicInformation
		if err := windows.VirtualQueryEx(as.sp.proc, uintptr(cur), &mbi, unsafe.Sizeof(mbi)); err != nil {
			return false, cur
		}
		if mbi.State != windows.MEM_COMMIT || (mbi.Protect != windows.PAGE_READWRITE && mbi.Protect != windows.PAGE_EXECUTE_READWRITE) {
			return false, cur
		}
		regionEnd := uint64(mbi.BaseAddress) + uint64(mbi.RegionSize)
		if regionEnd <= cur {
			return false, cur
		}
		cur = regionEnd
	}
	var n uintptr
	err := windows.WriteProcessMemory(as.sp.proc, uintptr(addr), &buf[0], uintptr(len(buf)), &n)
	if err != nil || n != uintptr(len(buf)) {
		return false, addr + uint64(n)
	}
	return true, 0
}

// emulateFSAccess runs the memory instruction at pc, which addresses memory
// through %fs, in the Sentry with the guest FS base fs. On success, it updates
// th.ctx and moves the program counter past the instruction. It reports false
// and leaves th.ctx unchanged for an instruction that it cannot emulate, an
// atomic one, or an access that the stub views do not allow. The thread then
// runs the instruction itself.
func (th *thread) emulateFSAccess(as *addressSpace, pc, fs uint64, code []byte) bool {
	inst, err := decodeX86(code)
	if err != nil || inst.Len == 0 || isAtomicMemInsn(inst) {
		return false
	}
	var regs [16]uint64
	for i := range regs {
		regs[i] = th.ctx.u64(ctxOffRax + 8*i)
	}
	eflags := th.ctx.u32(ctxOffEFlags)
	if res := emulateSegMemInsn(code, x86asm.FS, fs, &regs, &eflags, as.readGuest, as.writeGuestWritable); !res.ok {
		return false
	}
	for i := range regs {
		th.ctx.put64(ctxOffRax+8*i, regs[i])
	}
	th.ctx.put32(ctxOffEFlags, eflags)
	th.ctx.setPC(th.resumePC(pc + uint64(inst.Len)))
	return true
}

// archNoStoreStep reports whether the instruction at pc cannot run as a store
// step. Every amd64 store restarts cleanly, so none is excluded.
func (th *thread) archNoStoreStep(*addressSpace, uint64) bool { return false }

// illegalSignal classifies an illegal-instruction exception.
func (th *thread) illegalSignal(*addressSpace, uint64) (linuxSig, int32) { return sigILL, illIllOpc }

// archFault repairs a guest access through %fs that faulted because Windows
// reset the FS base. It returns true when it changed th.ctx. The Sentry runs
// the instruction when it can, so that every repair makes progress. Otherwise
// the thread runs the instruction again after it loads the base. In both cases
// the thread continues through the trampoline that loads the base.
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
	code := as.codeBytes(pc, 15)
	if !hasFSPrefix(code) {
		if traceEvents && ev.Info[1] < 0x10000 {
			tracef("pid %d thread %d: no FS repair, no FS prefix at pc %#x, fault at %#x, code % x", th.sp.pid, th.tid, pc, ev.Info[1], code)
		}
		return false
	}
	if th.emulateFSAccess(as, pc, fs, code) {
		// A failed trampoline only costs the next FS access one more stop.
		if err := th.goThroughTrampoline(fs); err != nil {
			tracef("pid %d thread %d: FS access emulated at pc %#x, no base reload: %v", th.sp.pid, th.tid, pc, err)
		}
		if traceAll {
			tracef("pid %d thread %d: FS access emulated at pc %#x, fault at %#x, access %d", th.sp.pid, th.tid, pc, ev.Info[1], ev.Info[0])
		}
		th.fsFix.n = 0
		th.sp.fsRepairs.Add(1)
		return true
	}
	sum := th.ctx.registerSum()
	if th.fsFix.pc == pc && th.fsFix.sum == sum && th.fsFix.n >= fsRepairLimit {
		text := "undecodable"
		if inst, err := decodeX86(code); err == nil {
			text = x86asm.GNUSyntax(inst, pc, nil)
		}
		tracef("pid %d thread %d: no FS repair, %d repairs at pc %#x without progress: fs %#x, fault at %#x, access %d, code % x (%s)", th.sp.pid, th.tid, th.fsFix.n, pc, fs, ev.Info[1], ev.Info[0], code, text)
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
		if b == 0x64 {
			return true
		}
		if !isX86Prefix(b) {
			return false
		}
	}
	return false
}

// siteStats counts the SYSCALL sites that patchPage met, by outcome, for the
// statistics line of GVX_SYSTRAP_TRACE=3. A trap counts under the reason that
// the planner gave.
var siteStats struct {
	// post counts the sites that became a JMP over the SYSCALL and the bytes
	// behind it. pre counts the sites that kept the trap while a JMP replaced
	// the instructions in front of the SYSCALL.
	post, pre atomic.Uint64
	// noSlot counts the sites that kept the trap because no island had room.
	noSlot atomic.Uint64
	trap   [planRejects]atomic.Uint64
}

// archStatsLine summarizes siteStats.
func archStatsLine() string {
	var b strings.Builder
	fmt.Fprintf(&b, "SYSCALL sites: jmp behind %d, jmp before %d, trap for no slot %d; trap for", siteStats.post.Load(), siteStats.pre.Load(), siteStats.noSlot.Load())
	for r := planOK + 1; r < planRejects; r++ {
		fmt.Fprintf(&b, " %s %d,", r, siteStats.trap[r].Load())
	}
	return strings.TrimSuffix(b.String(), ",")
}

// patchPage replaces the SYSCALL and RDFSBASE instructions of one page with
// traps. page is a copy of the original frame. With the fast path, a SYSCALL
// whose following instructions can move becomes a JMP to a trampoline slot,
// and every other SYSCALL keeps the trap.
//
// A writable page without an ELF image behind it stays unpatched. Such a page
// holds the output of a JIT compiler, such as V8, and the data that the
// compiler keeps beside its code. The guest reads the bytes of the copy that
// runs, and the scan finds false sites in that data, so a patch would change
// the data.
func (as *addressSpace) patchPage(ctx context.Context, mm platform.MemoryManager, base uint64, page []byte, writable bool, continuations []uint64) (map[uint16]siteInfo, []winSlotRef, []patchSpan, []uint16, error) {
	before := as.neighborBytes(base, true, amd64ScanLead)
	after := as.neighborBytes(base, false, amd64MaxInsnLen)
	found := scanAMD64GS(before, page, after, true)
	hasRaw := hasRemainingKernelExit(before, page, after)
	if len(found) == 0 && !hasRaw {
		return nil, nil, nil, nil, nil
	}
	scope := as.p.scopeOf(ctx, mm, base)
	if writable && scope.unbacked {
		return nil, nil, nil, nil, nil
	}
	origPage := append([]byte(nil), page...)
	var plan *jmpPlanner
	if as.p.fast && len(found) > 0 {
		// The plan reads the original bytes, because an earlier patch changes
		// the page. A wider neighbor window catches branches that start more
		// than one instruction before or after the page boundary.
		jmpBefore := as.neighborBytes(base, true, winJmpNeighborLen)
		jmpAfter := as.neighborBytes(base, false, winJmpNeighborLen)
		plan = newJmpPlanner(jmpBefore, origPage, jmpAfter)
		for _, pc := range continuations {
			plan.restartAt(int(pc - base))
		}
	}
	var keep []amd64Site
	var slots []winSlotRef
	var spans []patchSpan
	var prevTail []uint16
	addPrevTail := func(negOff int) {
		if blockSize+negOff < 0 {
			return
		}
		want := uint16(blockSize + negOff)
		if !slices.Contains(prevTail, want) {
			prevTail = append(prevTail, want)
		}
	}
	sites := make(map[uint16]siteInfo, len(found))
	// jumpEnd is the end of the bytes that the last JMP patch owns. prevEnd is
	// the end of every site that the loop met. A pre-window patch must not
	// overwrite either.
	jumpEnd, prevEnd := 0, 0
	for _, s := range found {
		floor := max(jumpEnd, prevEnd)
		prevEnd = max(prevEnd, s.Offset+s.Len)
		// A file image proves which bytes are code. Anonymous memory and files
		// without section headers give no proof, and the decoder alone decides.
		startOff := uint64(max(s.Offset, 0))
		endOff := uint64(min(s.Offset+s.Len, blockSize))
		if scope.proven() && !scope.containsRange(base+startOff, endOff-startOff) {
			continue
		}
		if jumpEnd > 0 && s.Offset < jumpEnd {
			// The bytes of this site belong to the previous slot.
			continue
		}
		if as.p.fast && s.Offset >= 0 {
			switch s.Kind {
			case amd64SiteSyscall:
				pl := plan.planSite(s.Offset, floor)
				if pl.kind == planPre && scope.proven() && !scope.containsRange(base+uint64(pl.start), uint64(s.Offset-pl.start)) {
					// The window is not in a code section of the file.
					pl = sitePlan{kind: planTrap, reject: pl.reject}
				}
				switch pl.kind {
				case planPost:
					if end, tail, ref, ok := as.patchJump(ctx, mm, base, page, s.Offset, pl.reloc); ok {
						jumpEnd = end
						sites[uint16(s.Offset)] = siteInfo{kind: winSiteJump, tail: tail}
						slots = append(slots, ref)
						spans = append(spans, patchSpan{s.Offset + 1, end})
						continue
					}
				case planPre:
					if pw, ok := as.patchJumpBefore(ctx, mm, base, page, s.Offset, pl); ok {
						jumpEnd = s.Offset
						slots = append(slots, pw.ref)
						spans = append(spans, patchSpan{pw.start + 1, s.Offset})
						maps.Copy(sites, preWindowSites(pw.start, pw.slotVA, pw.insn, s))
						keep = append(keep, s)
						continue
					}
				default:
					siteStats.trap[pl.reject].Add(1)
				}
			case amd64SiteRDFSBASE, amd64SiteRDGSBASE:
				if ref, ok := as.patchTLSBaseJump(ctx, mm, base, plan, page, s); ok {
					slots = append(slots, ref)
					spans = append(spans, patchSpan{s.Offset + 1, s.Offset + s.Len})
					continue
				}
			case amd64SiteGSMem:
				if gp, ref, ok := as.patchGSMovJump(ctx, mm, base, plan, page, s); ok {
					sites[uint16(s.Offset)] = siteInfo{
						kind:    amd64SiteGSMem,
						reg:     gp.reg,
						scratch: gp.scratch,
						wide:    gp.wide,
						store:   gp.store,
						length:  uint8(s.Len),
						disp:    gp.disp,
					}
					slots = append(slots, ref)
					spans = append(spans, patchSpan{s.Offset + 1, s.Offset + s.Len})
					continue
				}
			}
		}
		keep = append(keep, s)
		if s.Offset >= 0 {
			sites[uint16(s.Offset)] = siteInfo{kind: s.Kind, reg: s.Reg, wide: s.Wide, length: uint8(s.Len)}
		} else {
			addPrevTail(s.Offset)
		}
	}
	if _, err := patchAMD64(page, keep); err != nil {
		as.mu.Lock()
		discardSlotRefsLocked(slots)
		as.mu.Unlock()
		return nil, nil, nil, nil, err
	}
	if hidden := scanAMD64HiddenExits(before, origPage, after, page); len(hidden) > 0 {
		// Neutralize remaining raw kernel-exit byte pairs across the entire
		// executable page without trusting optional ELF SHF_EXECINSTR section
		// headers, while preserving fast-path E9 jump spans written above.
		inJumpSpan := func(off int) bool {
			for _, sp := range spans {
				if off >= sp.lo-1 && off < sp.hi {
					return true
				}
			}
			return false
		}
		var filtered []amd64HiddenExit
		for _, h := range hidden {
			if h.ExitOffset < 0 && base < blockSize {
				continue
			}
			if h.ExitOffset >= 0 && h.ExitOffset < len(page) && inJumpSpan(h.ExitOffset) {
				continue
			}
			if h.HasOuter {
				if h.OuterOffset < 0 && base < blockSize {
					h.HasOuter = false
				} else if h.OuterOffset >= 0 && h.OuterOffset < len(page) && inJumpSpan(h.OuterOffset) {
					h.HasOuter = false
				}
			}
			if h.ExitOffset >= len(page) && (!h.HasOuter || h.OuterOffset >= len(page)) {
				continue
			}
			filtered = append(filtered, h)
		}
		added, hiddenPrev := applyAMD64HiddenExits(page, origPage, filtered)
		for _, s := range added {
			sites[uint16(s.Offset)] = siteInfo{kind: s.Kind, length: uint8(s.Len)}
		}
		for _, off := range hiddenPrev {
			if !slices.Contains(prevTail, off) {
				prevTail = append(prevTail, off)
			}
		}
	}
	return sites, slots, spans, prevTail, nil
}

// patchJump replaces the SYSCALL at offset off of page and the bytes behind it
// with a JMP to a new slot that runs reloc. It returns the end of the bytes that
// the patch owns, the address of the slot tail, and the slot reference, or false
// when the site keeps its trap.
func (as *addressSpace) patchJump(ctx context.Context, mm platform.MemoryManager, base uint64, page []byte, off int, reloc []byte) (int, uint64, winSlotRef, bool) {
	site := base + uint64(off)
	spanLen := max(winJmpLen, winSiteLen+len(reloc))
	rec := plainSlot(site, winSlotSize)
	rec.resume = site + winSiteLen + uint64(len(reloc))
	slotVA, ref, err := as.installSlot(ctx, mm, rec, func(buf []byte, slotVA uint64) error {
		if _, err := encodeJmpSite(page, off, spanLen, site, slotVA); err != nil {
			return err
		}
		return encodeWinSlot(buf, slotVA, site, as.p.spillVA(), reloc)
	})
	if err == nil {
		if err = patchJmpSite(page, off, spanLen, site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.discard(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		if traceEvents {
			tracef("no trampoline slot for the SYSCALL at %#x: %v", site, err)
		}
		siteStats.noSlot.Add(1)
		return 0, 0, winSlotRef{}, false
	}
	siteStats.post.Add(1)
	return off + winSiteLen + len(reloc), slotVA + winSlotTailOffset, ref, true
}

func initIslandBytes(b []byte) {
	for i := range b {
		b[i] = amd64INT3
	}
}

func slotSeamSafe(page []byte, off, size uint32) bool {
	lo := int(off)
	if lo > 0 {
		lo--
	}
	hi := min(len(page), int(off+size)+1)
	if hasRawKernelExit(page[lo:hi]) {
		for i := off; i < off+size && int(i) < len(page); i++ {
			page[i] = amd64INT3
		}
		return false
	}
	return true
}

// preWindowPatch describes a pre-window patch that patchJumpBefore installed.
type preWindowPatch struct {
	ref    winSlotRef
	slotVA uint64
	// start is the page offset of the JMP.
	start int
	// insn holds the offset of each relocated instruction, counted from start.
	insn []uint8
}

// patchJumpBefore replaces the instructions in front of the SYSCALL at offset
// off of page with a JMP to a new slot, as pl describes. The SYSCALL keeps its
// trap. It returns false when the site keeps its trap.
func (as *addressSpace) patchJumpBefore(ctx context.Context, mm platform.MemoryManager, base uint64, page []byte, off int, pl sitePlan) (preWindowPatch, bool) {
	insn, ok := insnOffsets(pl.reloc)
	if !ok {
		return preWindowPatch{}, false
	}
	site, jmpVA := base+uint64(off), base+uint64(pl.start)
	rec := islandSlot{site: site, size: winSlotSize, jmpVA: jmpVA, resume: site + winSiteLen, insn: insn}
	slotVA, ref, err := as.installSlot(ctx, mm, rec, func(buf []byte, slotVA uint64) error {
		if _, err := encodeJmpSite(page, pl.start, off-pl.start, jmpVA, slotVA); err != nil {
			return err
		}
		return encodeWinPreSlot(buf, slotVA, site, as.p.spillVA(), pl.reloc)
	})
	if err == nil {
		if err = patchJmpSite(page, pl.start, off-pl.start, jmpVA, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.discard(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		if traceEvents {
			tracef("no trampoline slot for the instructions before the SYSCALL at %#x: %v", site, err)
		}
		siteStats.noSlot.Add(1)
		return preWindowPatch{}, false
	}
	siteStats.pre.Add(1)
	return preWindowPatch{ref: ref, slotVA: slotVA, start: pl.start, insn: insn}, true
}

// patchTLSBaseJump replaces the RDFSBASE or RDGSBASE instruction s in page
// with a JMP to a trampoline slot when the instruction can be replaced in
// place.
func (as *addressSpace) patchTLSBaseJump(ctx context.Context, mm platform.MemoryManager, base uint64, plan *jmpPlanner, page []byte, s amd64Site) (winSlotRef, bool) {
	if hasPrefixBefore(plan.before, plan.page, s.Offset) || !plan.canReplaceInPlace(s.Offset, s.Len) {
		return winSlotRef{}, false
	}
	site := base + uint64(s.Offset)
	isGS := s.Kind == amd64SiteRDGSBASE
	slotVA, ref, err := as.installSlot(ctx, mm, plainSlot(site, winTLSSlotSize), func(buf []byte, slotVA uint64) error {
		if _, err := encodeJmpSite(page, s.Offset, s.Len, site, slotVA); err != nil {
			return err
		}
		return encodeWinTLSBaseSlot(buf, slotVA, site, s.Len, s.Reg, s.Wide, isGS)
	})
	if err == nil {
		if err = patchJmpSite(page, s.Offset, s.Len, site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.discard(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		return winSlotRef{}, false
	}
	return ref, true
}

// patchGSMovJump replaces a 32-bit or 64-bit GS-segment MOV instruction s in
// page with a JMP to a trampoline slot when the instruction can be replaced in
// place.
func (as *addressSpace) patchGSMovJump(ctx context.Context, mm platform.MemoryManager, base uint64, plan *jmpPlanner, page []byte, s amd64Site) (gsMovPlan, winSlotRef, bool) {
	if hasPrefixBefore(plan.before, plan.page, s.Offset) || !plan.canReplaceInPlace(s.Offset, s.Len) {
		return gsMovPlan{}, winSlotRef{}, false
	}
	gp, ok := planGSMov(plan.page[s.Offset : s.Offset+s.Len])
	if !ok {
		return gsMovPlan{}, winSlotRef{}, false
	}
	site := base + uint64(s.Offset)
	slotVA, ref, err := as.installSlot(ctx, mm, plainSlot(site, winGSMovSlotSize), func(buf []byte, slotVA uint64) error {
		if _, err := encodeJmpSite(page, s.Offset, s.Len, site, slotVA); err != nil {
			return err
		}
		return encodeWinGSMovSlot(buf, slotVA, site, s.Len, gp)
	})
	if err == nil {
		if err = patchJmpSite(page, s.Offset, s.Len, site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.discard(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		return gsMovPlan{}, winSlotRef{}, false
	}
	return gp, ref, true
}

// recoverIslandFault restores the guest registers and program counter when a
// GS-segment MOV trampoline slot faults on the guest memory access.
func (th *thread) recoverIslandFault(as *addressSpace, ac *arch.Context64, ev *debugEvent) (bool, error) {
	if ev.Info[0] == avExecute {
		return false, nil
	}
	pc := th.ctx.pc()
	if inGuardCode(pc) && th.guardSite != 0 && th.slot != 0 {
		slotAddr := guardCodeAddr(th.slot - 1)
		if pc == slotAddr {
			if th.guardScratchUsed {
				th.ctx.put64(ctxOffRax+8*int(th.guardScratchReg), th.guardSavedVal)
			}
			th.ctx.setPC(th.guardSite)
			th.guardSite = 0
			th.guardScratchUsed = false
			return true, nil
		}
	}
	slot, slotVA, ok := as.slotContaining(pc)
	if !ok {
		return false, nil
	}
	site := slot.site
	info, ok := as.siteAt(site)
	if !ok || info.kind != amd64SiteGSMem {
		return false, nil
	}
	if pc > slotVA {
		var saved uint64
		var read uintptr
		if err := windows.ReadProcessMemory(th.sp.proc, uintptr(th.teb+winTEBScratchA), (*byte)(unsafe.Pointer(&saved)), unsafe.Sizeof(saved), &read); err != nil || read != unsafe.Sizeof(saved) {
			return false, fmt.Errorf("ReadProcessMemory(TEB scratch of thread %d): %w", th.tid, err)
		}
		th.ctx.put64(ctxOffRax+8*int(info.scratch), saved)
	}
	th.ctx.setPC(site)
	// The slot ran the access through the thread sysmsg, so the guest address
	// is the guest GS base plus the displacement, and the hardware address
	// can differ. gsFaultAddr keeps the hardware address only for an access
	// that crosses into the next page, which the memory manager must resolve.
	start := ac.StateData().Regs.Gs_base + uint64(int64(info.disp))
	ev.Info[1] = gsFaultAddr(ev.Info[1], start, info.gsAccessSize())
	if info.store {
		ev.Info[0] = avWrite
	} else {
		ev.Info[0] = avRead
	}
	return true, nil
}

// newWinTrap describes the trap of the SYSCALL at site.
func newWinTrap(site uint64, _ *winRegs) winTrap {
	return winTrap{site: site, ret: winSiteReturn(site)}
}

// archFastTrap adds the amd64 state to the registers of a fast trap.
func (th *thread) archFastTrap(ac *arch.Context64) {
	th.fsFix.n = 0
	th.restartPC.Store(0)
	if ac.StateData().Regs.Fs_base != 0 {
		th.fsNonZero = true
	}
}

// archFastHot reports whether the thread can resume without a debug stop. The
// stub loads the FS base on every return.
func (th *thread) archFastHot(*arch.Context64) bool { return true }

// archFastRecycleStart prepares a recycled thread that waits in the spill
// routine to jump directly to the entry address of the new guest context
// through the hot resume path without raising a debug trap.
func (th *thread) archFastRecycleStart(f *fastThread, ac *arch.Context64) uint32 {
	f.slot.sm.tail().Store(th.startPC(archPC(ac)))
	return winStateRunHot
}

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
