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

//go:build windows && arm64

package systrap

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// Windows runs a guest `svc #0` as an NT system call, and EL0 code cannot read
// CTR_EL0 or run IC IVAU. The patcher replaces these instructions and the
// writes of TPIDR_EL0 with BRK instructions. Windows reports a BRK with an
// immediate that it does not know as an illegal instruction, so the Sentry
// receives it through the debug object, finds the site in its table, and
// emulates the instruction (docs/systrap-windows.md, 3.4 and 6.3).
//
// Windows keeps TPIDR_EL0 and x18 of a thread across every stop and resume,
// so the guest reads TPIDR_EL0 natively. CONTEXT has no field for TPIDR_EL0.
// A small routine in the engine page writes it:
//
//	msr tpidr_el0, x16
//	brk #brkSetTLS

const (
	arm64BRK = 0xd4200000 // brk #imm16 with imm16 in bits 20:5.

	brkSyscall = 0x5c0
	brkCTR     = 0x5c1
	brkICIVAU  = 0x5c2
	brkSetTLS  = 0x5c3
	brkMSRTLS  = 0x5c4
	// brkMRSTLS replaces `mrs xN, tpidr_el0` when the fast path has no slot for
	// it. 0x5c5 belongs to the cold resume of the fast path.
	brkMRSTLS = 0x5c6

	arm64ICIVAU = 0xd50b7520 // ic ivau, xN with N in bits 4:0.

	// siteICIVAU is a guest `ic ivau, xN`.
	siteICIVAU siteKind = 5
)

func brkWord(imm uint32) uint32 { return arm64BRK | imm<<5 }

// fetchWindow is the length of an instruction in bytes. Instructions are
// aligned, so a fetch never crosses a block.
const fetchWindow = 4

// archProc is the arm64 state of a stub process.
type archProc struct{}

// archThread is the arm64 state of a guest thread.
type archThread struct {
	// tls is the value of TPIDR_EL0 of the thread, valid when tlsKnown is true.
	tls      uint64
	tlsKnown bool
	// spare is the scratch record of the TLS routine.
	spare *hostContext
}

func configureArch() { arch.ConfigureAddressSpace(1 << 48) }

func (th *thread) initArch() { th.spare = newHostContext() }

func (th *thread) releaseArch() {}

// writeInternalCode writes the TLS routine at the start of the code page.
func writeInternalCode(page []byte) {
	for i := 0; i+4 <= len(page); i += 4 {
		binary.LittleEndian.PutUint32(page[i:], brkWord(0xfff))
	}
	binary.LittleEndian.PutUint32(page[0:], 0xd51bd050) // msr tpidr_el0, x16
	binary.LittleEndian.PutUint32(page[4:], brkWord(brkSetTLS))
}

// setTLS writes TPIDR_EL0 of the parked thread. It runs the TLS routine with
// the value in x16 and parks the thread again. th.ctx keeps the guest state.
// Callers hold mu.
func (th *thread) setTLS(value uint64) error {
	copy(th.spare.buf, th.ctx.buf)
	th.spare.setFlags(th.spare.gprFlags())
	th.spare.setReg(16, value)
	th.spare.setPC(internalBase)
	th.ctx, th.spare = th.spare, th.ctx
	err := th.resumeParked()
	th.ctx, th.spare = th.spare, th.ctx
	if err != nil {
		return err
	}
	ev, err := th.waitEvent(startTimeout)
	if err != nil {
		return fmt.Errorf("wait for the TLS routine: %w", err)
	}
	if ev.Addr != internalBase+4 {
		return fmt.Errorf("the TLS routine stopped at %#x with code %#x", ev.Addr, ev.Code)
	}
	if err := th.park(ev); err != nil {
		return err
	}
	th.tls, th.tlsKnown = value, true
	return nil
}

// archStart makes TPIDR_EL0 of the thread equal to the TLS value of ac. A fast
// thread keeps the address of its sysmsg there, and the guest value goes to the
// TLS word of the sysmsg.
func (th *thread) archStart(ac *arch.Context64) error {
	want := ac.StateData().Regs.TPIDR_EL0
	if f := th.fast.Load(); f != nil {
		f.slot.sm.TLS = want
		want = f.slot.va
	}
	if th.tlsKnown && th.tls == want {
		return nil
	}
	return th.setTLS(want)
}

// resumePC returns pc unchanged on arm64 because a patched SVC never overwrites
// the instruction behind it.
func (th *thread) resumePC(pc uint64) uint64 { return pc }

// pullArch completes the copy of the registers into ac.
func (th *thread) pullArch(ac *arch.Context64) {
	if f := th.fast.Load(); f != nil {
		ac.StateData().Regs.TPIDR_EL0 = f.slot.sm.TLS
		return
	}
	if th.tlsKnown {
		ac.StateData().Regs.TPIDR_EL0 = th.tls
	}
}

// inEngineCode reports whether pc lies in the engine pages or in a trampoline
// island.
func (th *thread) inEngineCode(pc uint64) bool { return inInternal(pc) || th.inIslandPC(pc) }

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. arm64 has no
// GS register.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error { return nil }

// archEvent serves the traps of patched instructions.
func (th *thread) archEvent(as *addressSpace, ac *arch.Context64, ev debugEvent) (outcome, bool) {
	if ev.Code != statusIllegalInsn && ev.Code != statusBreakpoint {
		return outcome{}, false
	}
	if th.isFastExit(ev) {
		return th.fastExit(ac, ev), true
	}
	site, ok := as.siteAt(ev.Addr)
	if !ok {
		if ev.Code == statusIllegalInsn && th.emulateARM64MRS(as, ev.Addr) {
			if err := th.continueEvent(ev); err != nil {
				return fatal(err, unix.EFAULT), true
			}
			return running, true
		}
		return outcome{}, false
	}
	pc := ev.Addr
	switch site.kind {
	case siteSVC:
		th.ctx.setPC(pc + 4)
		if err := th.stopAndPull(ac, ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		ac.StateData().OrigR0 = ac.StateData().Regs.Regs[0]
		return outcome{done: true}, true
	case siteCTR:
		if site.reg != 31 {
			th.ctx.setReg(int(site.reg), ctrEL0Value)
		}
	case siteICIVAU:
		// The instruction names a virtual address. FlushInstructionCache makes
		// the instruction cache of every CPU coherent for the range.
		if site.reg != 31 {
			a := th.ctx.reg(int(site.reg))
			_ = flushInstructionCache(th.sp.proc, uintptr(a&^63), 64)
		}
	case siteMSR:
		var v uint64
		if site.reg != 31 {
			v = th.ctx.reg(int(site.reg))
		}
		th.ctx.setPC(pc + 4)
		if f := th.fast.Load(); f != nil {
			// The register of the thread keeps the address of the sysmsg. The
			// guest thread pointer lives in the sysmsg.
			f.slot.sm.TLS = v
			if err := th.continueEvent(ev); err != nil {
				return fatal(err, unix.EFAULT), true
			}
			return running, true
		}
		if err := th.park(ev); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		if err := th.setTLS(v); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		if err := th.resumeParked(); err != nil {
			return fatal(err, unix.EFAULT), true
		}
		return running, true
	case siteMRS:
		// A read of the guest thread pointer that no slot serves.
		if f := th.fast.Load(); f != nil && site.reg != 31 {
			th.ctx.setReg(int(site.reg), f.slot.sm.TLS)
		}
	default:
		return outcome{}, false
	}
	th.ctx.setPC(pc + 4)
	if err := th.continueEvent(ev); err != nil {
		return fatal(err, unix.EFAULT), true
	}
	return running, true
}

// illegalSignal classifies an illegal-instruction exception. Windows reports
// every BRK with an unknown immediate as an illegal instruction, but Linux
// raises SIGTRAP for it.
func (th *thread) illegalSignal(as *addressSpace, pc uint64) (linuxSig, int32) {
	if b := as.codeBytes(pc, 4); len(b) == 4 && binary.LittleEndian.Uint32(b)&0xffe0001f == arm64BRK {
		return sigTRAP, trapBrkpt
	}
	return sigILL, illIllOpc
}

// emulateARM64MRS emulates an EL0 read of an AArch64 ID register, CTR_EL0, or
// DCZID_EL0 when Windows reports an illegal instruction at pc.
func (th *thread) emulateARM64MRS(as *addressSpace, pc uint64) bool {
	b := as.codeBytes(pc, 4)
	if len(b) != 4 {
		return false
	}
	rt, val, ok := decodeARM64SysRegMRS(binary.LittleEndian.Uint32(b))
	if !ok {
		return false
	}
	if rt != 31 {
		th.ctx.setReg(int(rt), val)
	}
	th.ctx.setPC(pc + 4)
	return true
}

// archFault reports whether the engine repaired a fault. arm64 has no FS base.
func (th *thread) archFault(*addressSpace, *arch.Context64, debugEvent) bool { return false }

// siteInfo describes one patched instruction.
type siteInfo struct {
	kind siteKind
	reg  uint8
}

// patchPage replaces the instructions that Windows cannot run with BRK or
// NOP. page is a copy of the original frame. With the fast path, each `svc #0`
// becomes a branch to a trampoline slot, and a site without a slot keeps the
// BRK.
func (as *addressSpace) patchPage(ctx context.Context, mm platform.MemoryManager, base uint64, page []byte) (map[uint16]siteInfo, []winSlotRef, error) {
	sites := make(map[uint16]siteInfo)
	var slots []winSlotRef
	for _, s := range scanARM64(page) {
		var imm uint32
		switch s.Kind {
		case siteSVC:
			if as.p.fast {
				if word, ref, ok := as.fastBranch(ctx, mm, base+uint64(s.Offset)); ok {
					binary.LittleEndian.PutUint32(page[s.Offset:], word)
					slots = append(slots, ref)
					continue
				}
			}
			imm = brkSyscall
		case siteCTR:
			imm = brkCTR
		case siteMSR:
			imm = brkMSRTLS
		case siteMRS:
			// With the fast path, TPIDR_EL0 holds the address of the sysmsg, so
			// the guest reads its thread pointer through a slot or a trap.
			if !as.p.fast || s.Reg == 31 {
				continue
			}
			if word, ref, ok := as.fastTLSBranch(ctx, mm, base+uint64(s.Offset), s.Reg); ok {
				binary.LittleEndian.PutUint32(page[s.Offset:], word)
				slots = append(slots, ref)
				continue
			}
			imm = brkMRSTLS
		default:
			// Reads of TPIDR_EL0 run natively.
			continue
		}
		binary.LittleEndian.PutUint32(page[s.Offset:], brkWord(imm))
		sites[uint16(s.Offset)] = siteInfo{kind: s.Kind, reg: s.Reg}
	}
	for off := 0; off+4 <= len(page); off += 4 {
		w := binary.LittleEndian.Uint32(page[off:])
		switch {
		case w&^arm64RegMask == arm64ICIVAU:
			binary.LittleEndian.PutUint32(page[off:], brkWord(brkICIVAU))
			sites[uint16(off)] = siteInfo{kind: siteICIVAU, reg: uint8(w & arm64RegMask)}
		case isDataCacheMaintenance(w):
			// No stop is needed: the operation has no effect to emulate.
			binary.LittleEndian.PutUint32(page[off:], arm64NOP)
		}
	}
	return sites, slots, nil
}

// fastTLSBranch allocates a slot for the `mrs xN, tpidr_el0` at site and
// returns the branch that replaces the instruction.
func (as *addressSpace) fastTLSBranch(ctx context.Context, mm platform.MemoryManager, site uint64, reg uint8) (uint32, winSlotRef, bool) {
	slotVA, ref, err := as.installSlot(ctx, mm, site, winTLSSlotSize, func(buf []byte, slotVA uint64) error {
		return encodeWinTLSSlot(buf, slotVA, site, reg)
	})
	var word uint32
	if err == nil {
		if word, err = encodeBranch(site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.free(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		if traceEvents {
			tracef("no trampoline slot for the mrs at %#x: %v", site, err)
		}
		return 0, winSlotRef{}, false
	}
	return word, ref, true
}

// fastBranch allocates a trampoline slot for the `svc #0` at site and returns
// the branch that replaces the instruction.
func (as *addressSpace) fastBranch(ctx context.Context, mm platform.MemoryManager, site uint64) (uint32, winSlotRef, bool) {
	slotVA, ref, err := as.installSlot(ctx, mm, site, winSlotSize, func(buf []byte, slotVA uint64) error {
		return encodeWinSlot(buf, slotVA, site, as.p.spillVA())
	})
	var word uint32
	if err == nil {
		if word, err = encodeBranch(site, slotVA); err != nil {
			as.mu.Lock()
			ref.isl.free(ref.off, ref.size)
			as.mu.Unlock()
		}
	}
	if err != nil {
		if traceEvents {
			tracef("no trampoline slot for the svc at %#x: %v", site, err)
		}
		return 0, winSlotRef{}, false
	}
	return word, ref, true
}

// newWinTrap describes the trap of the `svc #0` at site.
func newWinTrap(site uint64, regs *winRegs) winTrap {
	return winTrap{site: site, ret: winSiteReturn(site), sp: regs.SP}
}

// archFastTrap adds the arm64 state to the registers of a fast trap.
func (th *thread) archFastTrap(ac *arch.Context64) { th.pullArch(ac) }

// archFastHot reports whether the thread can resume without a debug stop. The
// Sentry writes the TLS word of the sysmsg at each start, so the TLS value never
// forces a cold resume.
func (th *thread) archFastHot(*arch.Context64) bool { return true }

// archPC returns the program counter of ac.
func archPC(ac *arch.Context64) uint64 { return ac.StateData().Regs.Pc }

// archAttachFast has nothing to write. The first start sets TPIDR_EL0 to the
// address of the sysmsg, which names the page to the spill routine.
func (th *thread) archAttachFast(*fastSlot) error { return nil }

// archFastSetFP writes the vector state of ac into the sysmsg of a thread that
// waits in the spill routine. The routine loads it on the next resume. A system
// call of Windows can clobber the volatile vector registers, so the live
// context of the thread cannot carry the state. Callers hold mu.
func (th *thread) archFastSetFP(f *fastThread, ac *arch.Context64) error {
	f.slot.sm.loadVector(ac)
	return nil
}

// archFastGetFP reads the vector state that the spill routine saved in the
// sysmsg into ac. Callers hold mu.
func (th *thread) archFastGetFP(f *fastThread, ac *arch.Context64) error {
	f.slot.sm.storeVector(ac)
	return nil
}

func movzImm(rd, imm uint32) uint32 { return 0xd2800000 | imm<<5 | rd }
func subsImm1(rd uint32) uint32     { return 0xf1000400 | rd<<5 | rd }

// probeProgram returns the guest code of Probe: calls system calls with
// number 5, then one with number 6.
func probeProgram(calls int) []byte {
	words := []uint32{
		movzImm(1, uint32(calls)), movzImm(8, 5),
		arm64SVC0, subsImm1(1), 0x54ffffc1, // svc; subs x1, x1, #1; b.ne -8
		movzImm(8, 6), arm64SVC0,
	}
	code := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(code[4*i:], w)
	}
	return code
}

// probeSyscallNumber returns the number of the system call that stopped the guest.
func probeSyscallNumber(ac *arch.Context64) uint64 { return ac.StateData().Regs.Regs[8] }
