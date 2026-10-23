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

	arm64SVCMask   = 0xffe0001f
	brkHostSyscall = 0x5cf
	brkSyscall     = 0x5c0
	brkCTR         = 0x5c1
	brkICIVAU      = 0x5c2
	brkSetTLS      = 0x5c3
	brkMSRTLS      = 0x5c4

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

// archStart makes TPIDR_EL0 of the thread equal to the TLS value of ac.
func (th *thread) archStart(ac *arch.Context64) error {
	want := ac.StateData().Regs.TPIDR_EL0
	if th.tlsKnown && th.tls == want {
		return nil
	}
	return th.setTLS(want)
}

// pullArch completes the copy of the registers into ac.
func (th *thread) pullArch(ac *arch.Context64) {
	if th.tlsKnown {
		ac.StateData().Regs.TPIDR_EL0 = th.tls
	}
}

// inEngineCode reports whether pc lies in the engine pages.
func (th *thread) inEngineCode(pc uint64) bool { return inInternal(pc) }

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. arm64 has no
// GS register.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error { return nil }

// archEvent serves the traps of patched instructions.
func (th *thread) archEvent(as *addressSpace, ac *arch.Context64, ev debugEvent) (outcome, bool) {
	if ev.Code != statusIllegalInsn && ev.Code != statusBreakpoint {
		return outcome{}, false
	}
	site, ok := as.siteAt(ev.Addr)
	if !ok {
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

// archFault reports whether the engine repaired a fault. arm64 has no FS base.
func (th *thread) archFault(*addressSpace, *arch.Context64, debugEvent) bool { return false }

// siteInfo describes one patched instruction.
type siteInfo struct {
	kind siteKind
	reg  uint8
}

// patchPage replaces the instructions that Windows cannot run with BRK or
// NOP. page is a copy of the original frame.
func (as *addressSpace) patchPage(_ context.Context, _ platform.MemoryManager, _ uint64, page []byte) (map[uint16]siteInfo, error) {
	sites := make(map[uint16]siteInfo)
	for offset := 0; offset+4 <= len(page); offset += 4 {
		word := binary.LittleEndian.Uint32(page[offset:])
		if word&arm64SVCMask == arm64SVC0 {
			binary.LittleEndian.PutUint32(page[offset:], brkWord(brkSyscall))
			sites[uint16(offset)] = siteInfo{kind: siteSVC}
		}
	}
	for _, s := range scanARM64(page) {
		var imm uint32
		switch s.Kind {
		case siteSVC:
			imm = brkSyscall
		case siteCTR:
			imm = brkCTR
		case siteMSR:
			imm = brkMSRTLS
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
	return sites, nil
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
