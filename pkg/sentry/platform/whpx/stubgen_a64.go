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
	"encoding/binary"
	"fmt"
)

// This file generates the EL1 code that runs inside an arm64 partition.
//
// Every slot of the exception vector table loads the slot number and branches
// to Common. SP_EL1 always equals the CommPage address of the virtual
// processor, so the handler addresses CommPage through SP without a scratch
// register. Common spills X0 to X30, SP_EL0, ELR_EL1, SPSR_EL1, TPIDR_EL0,
// FAR_EL1 and ESR_EL1, writes ExitException and executes HVC #1. The Sentry
// resumes the virtual processor at Reload, which restores the system
// registers and the general registers and returns with ERET.

// Vector table slot numbers in architectural order.
const (
	a64SlotCurSP0Sync  = 0
	a64SlotCurSPxSync  = 4
	a64SlotLowA64Sync  = 8
	a64SlotLowA64IRQ   = 9
	a64SlotLowA64FIQ   = 10
	a64SlotLowA64SErr  = 11
	a64SlotLowA32Sync  = 12
	a64VectorSlots     = 16
	a64VectorSlotSize  = 0x80
	a64CodeOffVectors  = 0x000
	a64CodeOffCommon   = 0x800
	a64PstateKernel    = 0x3C5 // EL1h with D, A, I and F masked.
	a64PstateModeMask  = 0xF
	a64PstateUserMask  = 0x3CF // Bits that a user-mode PSTATE must keep clear.
	a64ECSVC64         = 0x15
	a64ECDataAbortLow  = 0x24
	a64ECInstrAbortLow = 0x20

	// Hyper-V consumes HVC #0 as its own hypercall ABI. HVC #1 exits to WHP.
	a64StubHvc = 1
)

// MAIR_EL1 attribute bytes. Index 0 must be Normal write-back because
// hostarch.MemoryTypeWriteBack is zero and PTE attribute index 0 selects it.
const (
	a64MairNormal   = 0xFF
	a64MairNormalNC = 0x44
	a64MairDevice   = 0x00

	// a64Mair mirrors the MAIR_EL1 value of the KVM platform.
	a64Mair = a64MairNormal | a64MairNormalNC<<8 | a64MairDevice<<16

	// a64TCR configures 48-bit translation for both halves with 4KB
	// granules, inner-shareable write-back write-allocate walks, a 36-bit
	// physical address size and top-byte-ignore for TTBR0.
	a64TCR = (16 << 0) | (1 << 8) | (1 << 10) | (3 << 12) | (0 << 14) |
		(16 << 16) | (1 << 24) | (1 << 26) | (3 << 28) | (2 << 30) |
		(1 << 32) | (1 << 37)

	// a64SctlrSet lists the SCTLR_EL1 bits that bring-up turns on. They
	// match the KVM platform: MMU, data cache, instruction cache, DC ZVA at
	// EL0 and CTR_EL0 and cache maintenance at EL0. Bring-up reads the
	// register first, so reserved-to-one bits keep their reset value.
	a64SctlrM   = 1 << 0
	a64SctlrC   = 1 << 2
	a64SctlrI   = 1 << 12
	a64SctlrDZE = 1 << 14
	a64SctlrUCT = 1 << 15
	a64SctlrUCI = 1 << 26
	a64SctlrSet = a64SctlrM | a64SctlrC | a64SctlrI | a64SctlrDZE | a64SctlrUCT | a64SctlrUCI

	// a64CpacrNoTrap lets EL0 and EL1 use FP and Advanced SIMD.
	a64CpacrNoTrap = 3 << 20

	// a64CntkctlEL0 lets EL0 read the virtual and physical counters.
	a64CntkctlEL0 = 3
)

// a64Stubs is the generated arm64 guest code.
type a64Stubs struct {
	// Code is the stub code page. The vector table starts at offset 0 and
	// is 2KB aligned, as VBAR_EL1 requires.
	Code []byte

	Vectors   int
	Common    int
	Hvc       int
	Reload    int
	ReloadEnd int
}

// buildA64Stubs generates the stub code page.
func buildA64Stubs() (*a64Stubs, error) {
	s := &a64Stubs{
		Code:    make([]byte, pageSize),
		Vectors: a64CodeOffVectors,
		Common:  a64CodeOffCommon,
	}

	// Vector table: save X0 and X1, load the slot number, branch to Common.
	for slot := range a64VectorSlots {
		a := newA64Asm()
		a.stpSP(0, 1, 0)
		a.movz(0, uint16(slot))
		base := a64CodeOffVectors + slot*a64VectorSlotSize
		a.bAbs(int32(a64CodeOffCommon - (base + a.pos())))
		code, err := a.finish()
		if err != nil {
			return nil, fmt.Errorf("whpx: assemble vector slot %d: %w", slot, err)
		}
		copy(s.Code[base:], code)
	}

	a := newA64Asm()
	// Spill X2 to X30 and the system registers.
	a.strSP(0, commOffVector)
	for r := 2; r < 30; r += 2 {
		a.stpSP(r, r+1, commOffRegs+r*8)
	}
	a.strSP(30, commOffRegs+30*8)
	a.mrs(0, a64SysSPEL0)
	a.mrs(1, a64SysELREL1)
	a.mrs(2, a64SysSPSREL1)
	a.mrs(3, a64SysTPIDREL0)
	a.mrs(4, a64SysFAREL1)
	a.mrs(5, a64SysESREL1)
	a.stpSP(0, 1, commOffSP)
	a.stpSP(2, 3, commOffPstate)
	a.stpSP(4, 5, commOffFaultAddr)
	a.movzW(0, uint16(ExitException))
	a.strWSP(0, commOffExitReason)
	hvc := a.pos()
	a.hvc(a64StubHvc)

	// Reload path. HVC returns here, and the Sentry can also start here.
	reload := a.pos()
	a.ldpSP(0, 1, commOffSP)
	a.ldpSP(2, 3, commOffPstate)
	a.msr(a64SysSPEL0, 0)
	a.msr(a64SysELREL1, 1)
	a.msr(a64SysSPSREL1, 2)
	a.msr(a64SysTPIDREL0, 3)
	a.ldrWSP(0, commOffFlags)
	a.tbz(0, 0, "noroot")
	a.ldrSP(1, commOffRoot)
	a.msr(a64SysTTBR0EL1, 1)
	a.isb()
	a.tlbiVMALLE1()
	a.dsbNSH()
	a.isb()
	a.label("noroot")
	a.tbz(0, 2, "noicache")
	a.icIALLUIS()
	a.dsbISH()
	a.isb()
	a.label("noicache")
	for r := 2; r < 30; r += 2 {
		a.ldpSP(r, r+1, commOffRegs+r*8)
	}
	a.ldrSP(30, commOffRegs+30*8)
	a.ldpSP(0, 1, commOffRegs)
	a.eret()
	reloadEnd := a.pos()

	code, err := a.finish()
	if err != nil {
		return nil, fmt.Errorf("whpx: assemble common handler: %w", err)
	}
	if a64CodeOffCommon+len(code) > pageSize {
		return nil, fmt.Errorf("whpx: common handler is %d bytes and overflows the page", len(code))
	}
	copy(s.Code[a64CodeOffCommon:], code)
	s.Hvc = a64CodeOffCommon + hvc
	s.Reload = a64CodeOffCommon + reload
	s.ReloadEnd = a64CodeOffCommon + reloadEnd
	return s, nil
}

// a64SysReg is the (op0, op1, CRn, CRm, op2) encoding of a system register.
type a64SysReg struct {
	op0, op1, crn, crm, op2 uint32
}

var (
	a64SysSPEL0    = a64SysReg{3, 0, 4, 1, 0}
	a64SysELREL1   = a64SysReg{3, 0, 4, 0, 1}
	a64SysSPSREL1  = a64SysReg{3, 0, 4, 0, 0}
	a64SysTPIDREL0 = a64SysReg{3, 3, 13, 0, 2}
	a64SysFAREL1   = a64SysReg{3, 0, 6, 0, 0}
	a64SysESREL1   = a64SysReg{3, 0, 5, 2, 0}
	a64SysTTBR0EL1 = a64SysReg{3, 0, 2, 0, 0}
)

func (r a64SysReg) bits() uint32 {
	return (r.op0&1)<<19 | r.op1<<16 | r.crn<<12 | r.crm<<8 | r.op2<<5
}

// a64Asm assembles the AArch64 subset that the stub uses.
type a64Asm struct {
	words  []uint32
	labels map[string]int
	fixups []a64Fixup
}

type a64Fixup struct {
	at    int
	label string
	kind  byte
}

func newA64Asm() *a64Asm { return &a64Asm{labels: make(map[string]int)} }

// pos returns the byte offset of the next instruction.
func (a *a64Asm) pos() int { return len(a.words) * 4 }

func (a *a64Asm) emit(w uint32) { a.words = append(a.words, w) }

func (a *a64Asm) label(name string) { a.labels[name] = len(a.words) }

func pairOff(off int) uint32 {
	if off%8 != 0 || off < -512 || off > 504 {
		panic(fmt.Sprintf("whpx: pair offset %d is out of range", off))
	}
	return uint32(off/8) & 0x7F
}

func slotOff(off, scale int) uint32 {
	if off%scale != 0 || off < 0 || off/scale > 0xFFF {
		panic(fmt.Sprintf("whpx: slot offset %d is out of range", off))
	}
	return uint32(off / scale)
}

// stpSP emits STP Xt1, Xt2, [SP, #off].
func (a *a64Asm) stpSP(t1, t2, off int) {
	a.emit(0xA9000000 | pairOff(off)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1))
}

// ldpSP emits LDP Xt1, Xt2, [SP, #off].
func (a *a64Asm) ldpSP(t1, t2, off int) {
	a.emit(0xA9400000 | pairOff(off)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1))
}

// strSP emits STR Xt, [SP, #off].
func (a *a64Asm) strSP(t, off int) {
	a.emit(0xF9000000 | slotOff(off, 8)<<10 | 31<<5 | uint32(t))
}

// ldrSP emits LDR Xt, [SP, #off].
func (a *a64Asm) ldrSP(t, off int) {
	a.emit(0xF9400000 | slotOff(off, 8)<<10 | 31<<5 | uint32(t))
}

// strWSP emits STR Wt, [SP, #off].
func (a *a64Asm) strWSP(t, off int) {
	a.emit(0xB9000000 | slotOff(off, 4)<<10 | 31<<5 | uint32(t))
}

// ldrWSP emits LDR Wt, [SP, #off].
func (a *a64Asm) ldrWSP(t, off int) {
	a.emit(0xB9400000 | slotOff(off, 4)<<10 | 31<<5 | uint32(t))
}

// movz emits MOVZ Xd, #imm.
func (a *a64Asm) movz(d int, imm uint16) { a.emit(0xD2800000 | uint32(imm)<<5 | uint32(d)) }

// movzW emits MOVZ Wd, #imm.
func (a *a64Asm) movzW(d int, imm uint16) { a.emit(0x52800000 | uint32(imm)<<5 | uint32(d)) }

// mrs emits MRS Xt, reg.
func (a *a64Asm) mrs(t int, r a64SysReg) { a.emit(0xD5300000 | r.bits() | uint32(t)) }

// msr emits MSR reg, Xt.
func (a *a64Asm) msr(r a64SysReg, t int) { a.emit(0xD5100000 | r.bits() | uint32(t)) }

// bAbs emits B with a byte displacement from this instruction.
func (a *a64Asm) bAbs(disp int32) {
	a.emit(0x14000000 | uint32(disp/4)&0x03FFFFFF)
}

// tbz emits TBZ Wt, #bit, label.
func (a *a64Asm) tbz(t, bit int, label string) {
	a.fixups = append(a.fixups, a64Fixup{at: len(a.words), label: label, kind: 'z'})
	a.emit(0x36000000 | uint32(bit)<<19 | uint32(t))
}

func (a *a64Asm) hvc(imm uint16) { a.emit(0xD4000002 | uint32(imm)<<5) }
func (a *a64Asm) eret()          { a.emit(0xD69F03E0) }
func (a *a64Asm) isb()           { a.emit(0xD5033FDF) }
func (a *a64Asm) dsbNSH()        { a.emit(0xD503379F) }
func (a *a64Asm) dsbISH()        { a.emit(0xD5033B9F) }
func (a *a64Asm) tlbiVMALLE1()   { a.emit(0xD508871F) }
func (a *a64Asm) icIALLUIS()     { a.emit(0xD508711F) }

// finish resolves the branches and returns the code.
func (a *a64Asm) finish() ([]byte, error) {
	for _, f := range a.fixups {
		target, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("undefined label %q", f.label)
		}
		rel := target - f.at
		if rel < -(1<<13) || rel >= 1<<13 {
			return nil, fmt.Errorf("branch to %q is out of range", f.label)
		}
		a.words[f.at] |= (uint32(rel) & 0x3FFF) << 5
	}
	out := make([]byte, len(a.words)*4)
	for i, w := range a.words {
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out, nil
}
