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

	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
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
//	x21  call flag: 0 after the save, 1 once the routine called into ntdll
//	x9   call target
//
// A hot resume loads the vector state only when a call ran, because the call
// can clobber V0 to V7 and V16 to V31, or when the Sentry wrote the vector
// block (FPDirty). Without both, the vector registers still hold the guest
// state that the routine saved. A cold resume always loads it.
//
// The thread finds its sysmsg in TPIDR_EL0. The guest owns x18, and Windows
// keeps the CPU number in TPIDRRO_EL0, so neither register can name the thread.
// The engine therefore keeps the address of the sysmsg in the real TPIDR_EL0
// and the guest thread pointer in the TLS word of the sysmsg. A patched
// `mrs xN, tpidr_el0` loads that word (encodeWinTLSSlot). Windows keeps
// TPIDR_EL0 across waits and stops (docs/systrap-windows.md, 3.4). The engine
// proves the whole design at start with a short guest run.
const (
	a64MRSNZCV = 0xd53b4200 // mrs xN, nzcv.
	a64MSRNZCV = 0xd51b4200 // msr nzcv, xN.
	a64DMBISH  = 0xd5033bbf
	a64YIELD   = 0xd503203f

	a64CondNE = 1
	a64CondHS = 2
	a64CondLO = 3
	a64CondEQ = 0

	a64SP  = 31
	a64XZR = 31
)

func a64ldarW(rt, rn uint32) uint32         { return 0x88dffc00 | rn<<5 | rt }
func a64stlrW(rt, rn uint32) uint32         { return 0x889ffc00 | rn<<5 | rt }
func a64movFromSP(rd uint32) uint32         { return 0x91000000 | a64SP<<5 | rd }
func a64movToSP(rn uint32) uint32           { return 0x91000000 | rn<<5 | a64SP }
func a64addSPShifted(rn, imm uint32) uint32 { return 0x91400000 | imm<<10 | rn<<5 | a64SP }
func a64cmpW(rn, imm uint32) uint32         { return 0x7100001f | imm<<10 | rn<<5 }
func a64subsW1(rd uint32) uint32            { return 0x71000400 | rd<<5 | rd }

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

func (a *a64Asm) cbnzW(rt uint32, label string) {
	a.fixes = append(a.fixes, a64Fix{at: len(a.words), label: label, kind: 'c', arg: rt})
	a.emit(0x35000000 | rt)
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
func saveVector(base int) []uint32 {
	var w []uint32
	for i := 0; i < 32; i += 2 {
		w = append(w, hvcommon.STPQ(base, i, i+1, winOffVec+16*i))
	}
	return append(w,
		hvcommon.MRS(0, hvcommon.SysRegFPSR),
		hvcommon.STRX(base, 0, winOffFpsr),
		hvcommon.MRS(0, hvcommon.SysRegFPCR),
		hvcommon.STRX(base, 0, winOffFpcr),
	)
}

// restoreVector returns the instructions that load V0 to V31, FPSR, and FPCR
// from the sysmsg that base names. They use x0 as scratch.
func restoreVector(base int) []uint32 {
	var w []uint32
	for i := 0; i < 32; i += 2 {
		w = append(w, hvcommon.LDPQ(base, i, i+1, winOffVec+16*i))
	}
	return append(w,
		hvcommon.LDRX(base, 0, winOffFpsr),
		hvcommon.MSR(hvcommon.SysRegFPSR, 0),
		hvcommon.LDRX(base, 0, winOffFpcr),
		hvcommon.MSR(hvcommon.SysRegFPCR, 0),
	)
}

// buildSpill generates the spill routine for the layout of this file.
func buildSpill() (winSpillCode, error) { return buildSpillWith(spillOptions{}) }

// buildSpillWith generates the spill routine with the changes of opts.
func buildSpillWith(opts spillOptions) (winSpillCode, error) {
	var a a64Asm
	const (
		base = 19
		cnt  = 20
		flag = 21
		tmp  = 9
	)
	// The real TPIDR_EL0 of the thread holds the address of its sysmsg.
	a.emit(arm64MRSTPIDR | 16)
	// Save x0 to x15, then the guest x16 and x17 from the sysmsg scratch words.
	for i := 0; i < 16; i += 2 {
		a.emit(hvcommon.STPX(16, i, i+1, winOffX+8*i))
	}
	a.emit(
		hvcommon.LDPX(16, 0, 1, winOffScratch),
		hvcommon.STPX(16, 0, 1, winOffX+8*16),
	)
	for i := 18; i < 30; i += 2 {
		a.emit(hvcommon.STPX(16, i, i+1, winOffX+8*i))
	}
	if !opts.noVector {
		a.emit(saveVector(16)...)
	}
	a.emit(
		hvcommon.MOVZW(flag, 0),
		hvcommon.STRX(16, 30, winOffX+8*30),
		a64movFromSP(0),
		hvcommon.STRX(16, 0, winOffSP),
		a64MRSNZCV|0,
		hvcommon.STRX(16, 0, winOffNZCV),
		hvcommon.STRX(16, 17, winOffTail),
		// Switch to the stack of the stub and keep the base in x19.
		hvcommon.MOVReg(base, 16),
		a64addSPShifted(base, winThreadMapSize>>12),
		// Publish Trapped, then wake a sleeping Sentry.
		hvcommon.MOVZW(0, uint16(winStateTrapped)),
		a64stlrW(0, base),
		a64DMBISH,
		hvcommon.LDRW(base, 0, winOffSentryWaiter),
	)
	a.cbzW(0, "spin")
	a.emit(
		hvcommon.LDRX(base, 0, winOffGuestEvent),
		hvcommon.MOVZ(1, 0),
		hvcommon.LDRX(base, tmp, winOffNtSetEvent),
		hvcommon.MOVZW(flag, 1),
		hvcommon.BLR(tmp),
	)
	a.label("spin")
	a.emit(hvcommon.MOVZW(cnt, winSpinStub))
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
		hvcommon.MOVZW(0, 1),
		hvcommon.STRW(base, 0, winOffStubWaiter),
		a64DMBISH,
		a64ldarW(0, base),
		a64cmpW(0, uint32(winStateRunHot)),
	)
	a.bCond(a64CondHS, "runclear")
	a.emit(
		hvcommon.LDRX(base, 0, winOffHostEvent),
		hvcommon.MOVZW(1, 0),
		hvcommon.MOVZ(2, 0),
		hvcommon.LDRX(base, tmp, winOffNtWait),
		hvcommon.MOVZW(flag, 1),
		hvcommon.BLR(tmp),
		a64ldarW(0, base),
		a64cmpW(0, uint32(winStateRunHot)),
	)
	a.bCond(a64CondLO, "sleep")
	a.label("runclear")
	a.emit(hvcommon.STRW(base, a64XZR, winOffStubWaiter))
	a.label("run")
	a.emit(a64cmpW(0, uint32(winStateRunCold)))
	a.bCond(a64CondEQ, "cold")

	// Hot resume.
	a.emit(
		hvcommon.LDPX(base, 0, 1, winOffX+8*16),
		hvcommon.STPX(base, 0, 1, winOffScratch),
		hvcommon.LDRX(base, 0, winOffX+8*18),
		hvcommon.STRX(base, 0, winOffX18),
	)
	switch {
	case opts.noVector:
	case opts.alwaysRestore:
		a.emit(restoreVector(base)...)
		a.emit(hvcommon.STRW(base, a64XZR, winOffFPDirty))
	default:
		a.cbnzW(flag, "hotload")
		a.emit(hvcommon.LDRW(base, 0, winOffFPDirty))
		a.cbzW(0, "hotskip")
		a.label("hotload")
		a.emit(restoreVector(base)...)
		a.emit(hvcommon.STRW(base, a64XZR, winOffFPDirty))
		a.label("hotskip")
	}
	a.emit(restoreCommon(base)...)
	a.emit(
		hvcommon.LDRX(base, 17, winOffTail),
		hvcommon.LDRX(base, 16, winOffSP),
		a64movToSP(16),
		hvcommon.LDPX(base, 0, 1, winOffX),
		hvcommon.LDRX(base, base, winOffX+8*base),
		hvcommon.BR(17),
	)

	// Cold resume.
	a.label("cold")
	if !opts.noVector {
		a.emit(restoreVector(base)...)
		a.emit(hvcommon.STRW(base, a64XZR, winOffFPDirty))
	}
	a.emit(restoreCommon(base)...)
	a.emit(
		hvcommon.LDPX(base, 16, 17, winOffX+8*16),
		hvcommon.LDRX(base, 0, winOffSP),
		a64movToSP(0),
		hvcommon.LDPX(base, 0, 1, winOffX),
		hvcommon.LDRX(base, base, winOffX+8*base),
	)
	coldBrk := len(a.words) * 4
	a.emit(hvcommon.BRK(brkFastExit))
	code, err := a.finish()
	if err != nil {
		return winSpillCode{}, err
	}
	return winSpillCode{code: code, coldBrk: coldBrk}, nil
}

// restoreCommon loads the flags and the registers that both resumes load the
// same way: x2 to x15, x18, x20 to x29, and x30.
func restoreCommon(base int) []uint32 {
	var w []uint32
	w = append(w,
		hvcommon.LDRX(base, 0, winOffNZCV),
		a64MSRNZCV|0,
	)
	for i := 2; i < 16; i += 2 {
		w = append(w, hvcommon.LDPX(base, i, i+1, winOffX+8*i))
	}
	w = append(w, hvcommon.LDRX(base, 18, winOffX+8*18))
	for i := 20; i < 30; i += 2 {
		w = append(w, hvcommon.LDPX(base, i, i+1, winOffX+8*i))
	}
	w = append(w, hvcommon.LDRX(base, 30, winOffX+8*30))
	return w
}

// encodeWinSlot encodes the trap slot for a patched `svc #0` at site.
func encodeWinSlot(buf []byte, slotVA, site, spill uint64) error {
	save := []uint32{
		arm64MRSTPIDR | 18,
		hvcommon.STPX(18, 16, 17, winOffScratch),
		hvcommon.LDRX(18, 18, winOffX18),
	}
	restore := []uint32{
		arm64MRSTPIDR | 18,
		hvcommon.LDPX(18, 16, 17, winOffScratch),
		hvcommon.LDRX(18, 18, winOffX18),
	}
	return encodeTrapSysmsgSlot(buf, slotVA, winSiteReturn(site), spill, save, restore)
}

// winTLSSlotSize is the size of the slot that replaces `mrs xN, tpidr_el0`.
const winTLSSlotSize = loadSlotSize

// encodeWinTLSSlot writes the slot that replaces `mrs xN, tpidr_el0` at site.
func encodeWinTLSSlot(buf []byte, slotVA, site uint64, reg uint8) error {
	return encodeLoadSysmsgSlot(buf, slotVA, winSiteReturn(site), reg, arm64MRSTPIDR, false, winOffTLS)
}

// encodeWinX18SetSlot writes the slot that replaces `mov x18, xN` at site.
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
	r := int(reg)
	binary.LittleEndian.PutUint32(buf[0:], arm64MRSTPIDR|18)
	binary.LittleEndian.PutUint32(buf[4:], hvcommon.STRX(18, r, winOffX18))
	binary.LittleEndian.PutUint32(buf[8:], hvcommon.MOVReg(18, r))
	binary.LittleEndian.PutUint32(buf[12:], back)
	return nil
}

// probeProgram returns the guest code of Probe: calls system calls with
// number 5, then one with number 6.
func probeProgram(calls int) []byte {
	words := []uint32{
		hvcommon.MOVZ(1, uint16(calls)), hvcommon.MOVZ(8, 5),
		arm64SVC0, 0xf1000400 | 1<<5 | 1, 0x54ffffc1, // svc; subs x1, x1, #1; b.ne -8
		hvcommon.MOVZ(8, 6), arm64SVC0,
	}
	code := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(code[4*i:], w)
	}
	return code
}

// probeSyscallNumber returns the number of the system call that stopped the guest.
func probeSyscallNumber(ac *arch.Context64) uint64 { return ac.StateData().Regs.Regs[8] }
