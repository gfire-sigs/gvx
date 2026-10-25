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

//go:build (darwin || windows) && arm64

package systrap

import (
	"encoding/binary"
	"fmt"
)

// The Windows engine has no C toolchain step, so Go code generates the spill
// routine of the fast path. The routine is the arm64 counterpart of the code
// that the amd64 file generates. A trap slot (encodeTrapSlot) jumps to it with
// x17 set to the slot tail. The guest x16 and x17 wait below the guest stack
// pointer, where the slot saved them.
//
// Register use of the routine:
//
//	x16  sysmsg base at entry, until the routine copies it to x19
//	x19  sysmsg base, a callee-saved register that the ntdll calls keep
//	x20  poll counter
//	x9   call target
//
// The thread finds its sysmsg in TPIDR_EL0. The guest owns x18, and Windows
// keeps the CPU number in TPIDRRO_EL0, so neither register can name the thread.
// The engine therefore keeps the address of the sysmsg in the real TPIDR_EL0
// and the guest thread pointer in the TLS word of the sysmsg. A patched
// `mrs xN, tpidr_el0` loads that word (encodeWinTLSSlot). Windows keeps
// TPIDR_EL0 across waits and stops (docs/systrap-windows.md, 3.4). The engine
// proves the whole design at start with a short guest run.
const (
	a64TPIDR   = 0xd53bd040 // mrs xN, tpidr_el0 with N in bits 4:0.
	a64MRSNZCV = 0xd53b4200 // mrs xN, nzcv.
	a64MSRNZCV = 0xd51b4200 // msr nzcv, xN.
	a64MRSFPSR = 0xd53b4420 // mrs xN, fpsr.
	a64MRSFPCR = 0xd53b4400 // mrs xN, fpcr.
	a64MSRFPSR = 0xd51b4420 // msr fpsr, xN.
	a64MSRFPCR = 0xd51b4400 // msr fpcr, xN.
	a64DMBISH  = 0xd5033bbf
	a64YIELD   = 0xd503203f
	a64BRK     = 0xd4200000

	a64CondNE = 1
	a64CondHS = 2
	a64CondLO = 3
	a64CondEQ = 0
)

// a64Reg numbers used by the routine.
const (
	a64SP  = 31
	a64XZR = 31
)

// a64ldrX and the other encoders build one instruction word. Each takes the
// operands in the order of the assembler text.
func a64ldrX(rt, rn, off uint32) uint32 { return 0xf9400000 | (off/8)<<10 | rn<<5 | rt }
func a64strX(rt, rn, off uint32) uint32 { return 0xf9000000 | (off/8)<<10 | rn<<5 | rt }
func a64ldrW(rt, rn, off uint32) uint32 { return 0xb9400000 | (off/4)<<10 | rn<<5 | rt }
func a64strW(rt, rn, off uint32) uint32 { return 0xb9000000 | (off/4)<<10 | rn<<5 | rt }
func a64ldarW(rt, rn uint32) uint32     { return 0x88dffc00 | rn<<5 | rt }
func a64stlrW(rt, rn uint32) uint32     { return 0x889ffc00 | rn<<5 | rt }

// a64stpQ and a64ldpQ store and load two 128-bit vector registers. off is a
// byte offset that is a multiple of 16 between -1024 and 1008.
func a64stpQ(rt, rt2, rn uint32, off int32) uint32 {
	return 0xad000000 | uint32(off/16)&0x7f<<15 | rt2<<10 | rn<<5 | rt
}

func a64ldpQ(rt, rt2, rn uint32, off int32) uint32 {
	return 0xad400000 | uint32(off/16)&0x7f<<15 | rt2<<10 | rn<<5 | rt
}

// a64ldp and a64stp use the signed offset form. off is a byte offset that is a
// multiple of 8 between -512 and 504.
func a64ldp(rt, rt2, rn uint32, off int32) uint32 {
	return 0xa9400000 | uint32(off/8)&0x7f<<15 | rt2<<10 | rn<<5 | rt
}

func a64stp(rt, rt2, rn uint32, off int32) uint32 {
	return 0xa9000000 | uint32(off/8)&0x7f<<15 | rt2<<10 | rn<<5 | rt
}

func a64movReg(rd, rm uint32) uint32 { return 0xaa0003e0 | rm<<16 | rd }

// a64movFromSP is `mov xd, sp`, and a64movToSP is `mov sp, xn`.
func a64movFromSP(rd uint32) uint32 { return 0x91000000 | a64SP<<5 | rd }
func a64movToSP(rn uint32) uint32   { return 0x91000000 | rn<<5 | a64SP }

// a64addSPShifted is `add sp, xn, #imm, lsl #12`.
func a64addSPShifted(rn, imm uint32) uint32 { return 0x91400000 | imm<<10 | rn<<5 | a64SP }

func a64movzX(rd, imm uint32) uint32 { return 0xd2800000 | imm<<5 | rd }
func a64movzW(rd, imm uint32) uint32 { return 0x52800000 | imm<<5 | rd }

// a64cmpW is `cmp wn, #imm`, and a64subsW1 is `subs wd, wd, #1`.
func a64cmpW(rn, imm uint32) uint32 { return 0x7100001f | imm<<10 | rn<<5 }
func a64subsW1(rd uint32) uint32    { return 0x71000400 | rd<<5 | rd }

func a64blr(rn uint32) uint32 { return 0xd63f0000 | rn<<5 }
func a64br(rn uint32) uint32  { return 0xd61f0000 | rn<<5 }

// a64Asm collects words and resolves branches to labels.
type a64Asm struct {
	words  []uint32
	labels map[string]int
	fixes  []a64Fix
}

type a64Fix struct {
	at    int
	label string
	// kind is 'c' for CBZ, 'b' for B.cond.
	kind byte
	arg  uint32
}

func (a *a64Asm) emit(w ...uint32) { a.words = append(a.words, w...) }

func (a *a64Asm) label(name string) {
	if a.labels == nil {
		a.labels = make(map[string]int)
	}
	a.labels[name] = len(a.words)
}

func (a *a64Asm) cbzW(rt uint32, label string) {
	a.fixes = append(a.fixes, a64Fix{at: len(a.words), label: label, kind: 'c', arg: rt})
	a.emit(0x34000000 | rt)
}

func (a *a64Asm) bCond(cond uint32, label string) {
	a.fixes = append(a.fixes, a64Fix{at: len(a.words), label: label, kind: 'b', arg: cond})
	a.emit(0x54000000 | cond)
}

// finish resolves the labels and returns the code.
func (a *a64Asm) finish() ([]byte, error) {
	for _, f := range a.fixes {
		to, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("undefined label %q", f.label)
		}
		delta := int32(to - f.at)
		if delta < -(1<<18) || delta >= 1<<18 {
			return nil, fmt.Errorf("branch to %q is out of range", f.label)
		}
		a.words[f.at] |= uint32(delta) & 0x7ffff << 5
	}
	out := make([]byte, 4*len(a.words))
	for i, w := range a.words {
		binary.LittleEndian.PutUint32(out[4*i:], w)
	}
	return out, nil
}

// winSpillCode is the generated spill routine and the offsets in it.
type winSpillCode struct {
	code []byte
	// coldBrk is the offset of the BRK instruction that a cold resume executes.
	coldBrk int
}

// coldExit returns the offset of the trap that a cold resume executes.
func (c winSpillCode) coldExit() int {
	return c.coldBrk
}

// brkFastExit is the BRK immediate of a cold resume. The patched instruction
// BRKs of the engine use 0x5c0 to 0x5c4.
const brkFastExit = 0x5c5

// saveVector returns the instructions that store V0 to V31, FPSR, and FPCR in
// the sysmsg that base names. They use x0 as scratch, which the caller saved.
func saveVector(base uint32) []uint32 {
	var w []uint32
	for i := uint32(0); i < 32; i += 2 {
		w = append(w, a64stpQ(i, i+1, base, int32(winOffVec+16*i)))
	}
	return append(w,
		a64MRSFPSR|0,
		a64strX(0, base, winOffFpsr),
		a64MRSFPCR|0,
		a64strX(0, base, winOffFpcr),
	)
}

// restoreVector returns the instructions that load V0 to V31, FPSR, and FPCR
// from the sysmsg that base names. They use x0 as scratch.
func restoreVector(base uint32) []uint32 {
	var w []uint32
	for i := uint32(0); i < 32; i += 2 {
		w = append(w, a64ldpQ(i, i+1, base, int32(winOffVec+16*i)))
	}
	return append(w,
		a64ldrX(0, base, winOffFpsr),
		a64MSRFPSR|0,
		a64ldrX(0, base, winOffFpcr),
		a64MSRFPCR|0,
	)
}

// buildSpill generates the spill routine for the layout of this file.
func buildSpill() (winSpillCode, error) {
	var a a64Asm
	const (
		base = 19
		cnt  = 20
		tmp  = 9
	)
	// The real TPIDR_EL0 of the thread holds the address of its sysmsg.
	a.emit(a64TPIDR | 16)
	// Save x0 to x15, then the guest x16 and x17 from the sysmsg scratch words.
	for i := uint32(0); i < 16; i += 2 {
		a.emit(a64stp(i, i+1, 16, int32(winOffX+8*i)))
	}
	a.emit(
		a64ldp(0, 1, 16, int32(winOffScratch)),
		a64stp(0, 1, 16, int32(winOffX+8*16)),
	)
	for i := uint32(18); i < 30; i += 2 {
		a.emit(a64stp(i, i+1, 16, int32(winOffX+8*i)))
	}
	a.emit(saveVector(16)...)
	a.emit(
		a64strX(30, 16, winOffX+8*30),
		a64movFromSP(0),
		a64strX(0, 16, winOffSP),
		a64MRSNZCV|0,
		a64strX(0, 16, winOffNZCV),
		a64strX(17, 16, winOffTail),
		// Switch to the stack of the stub and keep the base in x19.
		a64movReg(base, 16),
		a64addSPShifted(base, winThreadMapSize>>12),
		// Publish Trapped, then wake a sleeping Sentry.
		a64movzW(0, uint32(winStateTrapped)),
		a64stlrW(0, base),
		a64DMBISH,
		a64ldrW(0, base, winOffSentryWaiter),
	)
	a.cbzW(0, "spin")
	a.emit(
		a64ldrX(0, base, winOffGuestEvent),
		a64movzX(1, 0),
		a64ldrX(tmp, base, winOffNtSetEvent),
		a64blr(tmp),
	)
	a.label("spin")
	a.emit(a64movzW(cnt, winSpinStub))
	a.label("poll")
	a.emit(
		a64ldarW(0, base),
		a64cmpW(0, uint32(winStateRunHot)),
	)
	a.bCond(a64CondHS, "run")
	a.emit(
		a64YIELD,
		a64subsW1(cnt),
	)
	a.bCond(a64CondNE, "poll")
	// Sleep until the Sentry sets HostEvent.
	a.label("sleep")
	a.emit(
		a64movzW(0, 1),
		a64strW(0, base, winOffStubWaiter),
		a64DMBISH,
		a64ldarW(0, base),
		a64cmpW(0, uint32(winStateRunHot)),
	)
	a.bCond(a64CondHS, "runclear")
	a.emit(
		a64ldrX(0, base, winOffHostEvent),
		a64movzW(1, 0),
		a64movzX(2, 0),
		a64ldrX(tmp, base, winOffNtWait),
		a64blr(tmp),
		a64ldarW(0, base),
		a64cmpW(0, uint32(winStateRunHot)),
	)
	a.bCond(a64CondLO, "sleep")
	a.label("runclear")
	a.emit(a64strW(a64XZR, base, winOffStubWaiter))
	a.label("run")
	a.emit(a64cmpW(0, uint32(winStateRunCold)))
	a.bCond(a64CondEQ, "cold")

	// Hot resume. The scratch words of the sysmsg receive the guest x16 and
	// x17 again, and X18 receives the guest x18, because a system call can
	// change those words. The slot tail loads them back.
	a.emit(
		a64ldp(0, 1, base, int32(winOffX+8*16)),
		a64stp(0, 1, base, int32(winOffScratch)),
		a64ldrX(0, base, winOffX+8*18),
		a64strX(0, base, winOffX18),
	)
	a.emit(restoreCommon(base)...)
	a.emit(
		a64ldrX(17, base, winOffTail),
		a64ldrX(16, base, winOffSP),
		a64movToSP(16),
		a64ldp(0, 1, base, winOffX),
		a64ldrX(base, base, winOffX+8*base),
		a64br(17),
	)

	// Cold resume. Every register comes from the sysmsg, including x16 and
	// x17, and the BRK reports the stop to the Sentry.
	a.label("cold")
	a.emit(restoreCommon(base)...)
	a.emit(
		a64ldp(16, 17, base, int32(winOffX+8*16)),
		a64ldrX(0, base, winOffSP),
		a64movToSP(0),
		a64ldp(0, 1, base, winOffX),
		a64ldrX(base, base, winOffX+8*base),
	)
	coldBrk := len(a.words) * 4
	a.emit(a64BRK | brkFastExit<<5)
	code, err := a.finish()
	if err != nil {
		return winSpillCode{}, err
	}
	return winSpillCode{code: code, coldBrk: coldBrk}, nil
}

// restoreCommon loads the vector state, the flags, and the registers that both
// resumes load the same way: x2 to x15, x18, x20 to x29, and x30. It runs
// before the registers that differ. It uses x0 as scratch.
func restoreCommon(base uint32) []uint32 {
	w := restoreVector(base)
	w = append(w,
		a64ldrX(0, base, winOffNZCV),
		a64MSRNZCV|0,
	)
	for i := uint32(2); i < 16; i += 2 {
		w = append(w, a64ldp(i, i+1, base, int32(winOffX+8*i)))
	}
	w = append(w, a64ldrX(18, base, winOffX+8*18))
	for i := uint32(20); i < 30; i += 2 {
		w = append(w, a64ldp(i, i+1, base, int32(winOffX+8*i)))
	}
	w = append(w, a64ldrX(30, base, winOffX+8*30))
	return w
}

// encodeWinSlot encodes the trap slot for a patched `svc #0` at site. The slot
// saves x16 and x17 in the scratch words of the thread's winSysmsg through x18,
// restores x18 from the X18 word of the winSysmsg, and returns to the
// instruction after the site.
func encodeWinSlot(buf []byte, slotVA, site, spill uint64) error {
	if len(buf) < winSlotSize {
		return fmt.Errorf("trap slot buffer has %d bytes", len(buf))
	}
	back, err := encodeBranch(slotVA+winSlotTailOffset+12, winSiteReturn(site))
	if err != nil {
		return err
	}
	words := [...]uint32{
		a64TPIDR | 18,
		a64stp(16, 17, 18, int32(winOffScratch)),
		a64ldrX(18, 18, winOffX18),
		arm64ADRx17 | uint32((winSlotTailOffset-12)>>2)<<5,   // adr x17, tail: byte offset 24.
		arm64LDRLitx16 | uint32((winSlotLitOffset-16)>>2)<<5, // ldr x16, [pc, +24].
		a64br(16),
		a64TPIDR | 18,
		a64ldp(16, 17, 18, int32(winOffScratch)),
		a64ldrX(18, 18, winOffX18),
		back,
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	binary.LittleEndian.PutUint64(buf[winSlotLitOffset:], spill)
	return nil
}

// winTLSSlotSize is the size of the slot that replaces `mrs xN, tpidr_el0`.
const winTLSSlotSize = loadSlotSize

// encodeWinTLSSlot writes the slot that replaces `mrs xN, tpidr_el0` at site.
// The real TPIDR_EL0 holds the address of the sysmsg, so the slot reads that
// address into xN, loads the TLS word of the guest through it, and returns to
// the instruction after the site. It changes no other register and no flag.
func encodeWinTLSSlot(buf []byte, slotVA, site uint64, reg uint8) error {
	if len(buf) < winTLSSlotSize {
		return fmt.Errorf("TLS slot buffer has %d bytes", len(buf))
	}
	if reg >= 31 {
		return fmt.Errorf("TLS slot register %d", reg)
	}
	back, err := encodeBranch(slotVA+8, winSiteReturn(site))
	if err != nil {
		return err
	}
	r := uint32(reg)
	binary.LittleEndian.PutUint32(buf[0:], a64TPIDR|r)
	binary.LittleEndian.PutUint32(buf[4:], a64ldrX(r, r, winOffTLS))
	binary.LittleEndian.PutUint32(buf[8:], back)
	binary.LittleEndian.PutUint32(buf[12:], arm64NOP)
	return nil
}

// encodeWinX18SetSlot writes the slot that replaces `mov x18, xN` at site. The
// slot stores xN into the X18 word of the thread's winSysmsg, copies xN into
// hardware x18, and returns to the instruction after the site.
func encodeWinX18SetSlot(buf []byte, slotVA, site uint64, reg uint8) error {
	if len(buf) < winTLSSlotSize {
		return fmt.Errorf("X18 slot buffer has %d bytes", len(buf))
	}
	if reg == 18 || reg > 31 {
		return fmt.Errorf("X18 slot register %d", reg)
	}
	back, err := encodeBranch(slotVA+12, winSiteReturn(site))
	if err != nil {
		return err
	}
	r := uint32(reg)
	binary.LittleEndian.PutUint32(buf[0:], a64TPIDR|18)
	binary.LittleEndian.PutUint32(buf[4:], a64strX(r, 18, winOffX18))
	binary.LittleEndian.PutUint32(buf[8:], a64movReg(18, r))
	binary.LittleEndian.PutUint32(buf[12:], back)
	return nil
}
