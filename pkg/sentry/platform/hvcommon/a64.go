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

// Package hvcommon holds the pure code that the hardware-virtualization
// backends whpx and hvf share: the AArch64 instruction encoders, the x86-64
// descriptor tables, and the architectural constants of the guest kernel stubs.
//
// Each backend keeps its own CommPage layout and its own stub generator,
// because the two hypervisor interfaces exchange different state. This package
// holds only the parts that the architecture fixes. It has no host dependency,
// so tests on every OS verify it.
package hvcommon

import "fmt"

// SysReg is the (op0, op1, CRn, CRm, op2) encoding of an AArch64 system
// register, in the bit positions that MRS and MSR use.
type SysReg uint32

// MakeSysReg encodes a system register. Only bit 0 of op0 matters, because the
// system register space has op0 equal to 2 or 3.
func MakeSysReg(op0, op1, crn, crm, op2 uint32) SysReg {
	return SysReg((op0&1)<<19 | op1<<16 | crn<<12 | crm<<8 | op2<<5)
}

// The system registers that the exception stubs spill and reload.
var (
	SysRegSPEL0    = MakeSysReg(3, 0, 4, 1, 0)
	SysRegELREL1   = MakeSysReg(3, 0, 4, 0, 1)
	SysRegSPSREL1  = MakeSysReg(3, 0, 4, 0, 0)
	SysRegTPIDREL0 = MakeSysReg(3, 3, 13, 0, 2)
	SysRegFAREL1   = MakeSysReg(3, 0, 6, 0, 0)
	SysRegESREL1   = MakeSysReg(3, 0, 5, 2, 0)
	SysRegFPSR     = MakeSysReg(3, 3, 4, 4, 1)
	SysRegFPCR     = MakeSysReg(3, 3, 4, 4, 0)
	SysRegTTBR0EL1 = MakeSysReg(3, 0, 2, 0, 0)
)

// Fixed instruction words of the stubs.
const (
	ERET uint32 = 0xD69F03E0
	ISB  uint32 = 0xD5033FDF
	// DSBNSH is DSB NSH. DSBISH is DSB ISH.
	DSBNSH uint32 = 0xD503379F
	DSBISH uint32 = 0xD5033B9F
	// TLBIVMALLE1 invalidates every stage-1 EL1&0 translation of the current
	// VMID, including cached intermediate walk entries.
	TLBIVMALLE1 uint32 = 0xD508871F
	// ICIALLUIS invalidates all instruction caches in the inner shareable
	// domain, so it also reaches host cores that ran the virtual processor
	// earlier.
	ICIALLUIS uint32 = 0xD508711F
)

// HVC encodes HVC #imm.
func HVC(imm uint16) uint32 { return 0xD4000002 | uint32(imm)<<5 }

// MRS encodes MRS Xt, reg.
func MRS(rt int, reg SysReg) uint32 { return 0xD5300000 | uint32(reg) | uint32(rt) }

// MSR encodes MSR reg, Xt.
func MSR(reg SysReg, rt int) uint32 { return 0xD5100000 | uint32(reg) | uint32(rt) }

// MOVZ encodes MOVZ Xd, #imm.
func MOVZ(rd int, imm uint16) uint32 { return 0xD2800000 | uint32(imm)<<5 | uint32(rd) }

// MOVZW encodes MOVZ Wd, #imm.
func MOVZW(rd int, imm uint16) uint32 { return 0x52800000 | uint32(imm)<<5 | uint32(rd) }

// B encodes an unconditional branch by a byte displacement from the branch.
func B(byteOff int) uint32 { return 0x14000000 | uint32(byteOff/4)&0x03FFFFFF }

// CBZ encodes CBZ Xt with a byte displacement from the branch.
func CBZ(rt, byteOff int) uint32 {
	return 0xB4000000 | (uint32(byteOff/4)&0x7FFFF)<<5 | uint32(rt)
}

// TBZ encodes TBZ Xt, #bit with a byte displacement from the branch. The bit
// number must be below 32, so the encoding is the one of TBZ Wt.
func TBZ(rt, bit, byteOff int) uint32 {
	return 0x36000000 | uint32(bit)<<19 | (uint32(byteOff/4)&0x3FFF)<<5 | uint32(rt)
}

// The load and store encoders use SP as the base register, because the stubs
// address the CommPage through SP_EL1. An offset that the instruction cannot
// encode is a bug of the generator, so the encoders panic.

// STPXSP encodes STP Xt1, Xt2, [SP, #off].
func STPXSP(t1, t2, off int) uint32 {
	return 0xA9000000 | pairOffset(off, 8)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1)
}

// LDPXSP encodes LDP Xt1, Xt2, [SP, #off].
func LDPXSP(t1, t2, off int) uint32 {
	return 0xA9400000 | pairOffset(off, 8)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1)
}

// STPQSP encodes STP Qt1, Qt2, [SP, #off].
func STPQSP(t1, t2, off int) uint32 {
	return 0xAD000000 | pairOffset(off, 16)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1)
}

// LDPQSP encodes LDP Qt1, Qt2, [SP, #off].
func LDPQSP(t1, t2, off int) uint32 {
	return 0xAD400000 | pairOffset(off, 16)<<15 | uint32(t2)<<10 | 31<<5 | uint32(t1)
}

// STRXSP encodes STR Xt, [SP, #off].
func STRXSP(t, off int) uint32 { return 0xF9000000 | slotOffset(off, 8)<<10 | 31<<5 | uint32(t) }

// LDRXSP encodes LDR Xt, [SP, #off].
func LDRXSP(t, off int) uint32 { return 0xF9400000 | slotOffset(off, 8)<<10 | 31<<5 | uint32(t) }

// STRWSP encodes STR Wt, [SP, #off].
func STRWSP(t, off int) uint32 { return 0xB9000000 | slotOffset(off, 4)<<10 | 31<<5 | uint32(t) }

// LDRWSP encodes LDR Wt, [SP, #off].
func LDRWSP(t, off int) uint32 { return 0xB9400000 | slotOffset(off, 4)<<10 | 31<<5 | uint32(t) }

// pairOffset returns the signed 7-bit field of a load or store pair. The
// instruction scales the offset by the size of one register.
func pairOffset(off, scale int) uint32 {
	if off%scale != 0 || off < -64*scale || off > 63*scale {
		panic(fmt.Sprintf("hvcommon: pair offset %d is out of range", off))
	}
	return uint32(off/scale) & 0x7F
}

// slotOffset returns the unsigned 12-bit field of a load or store.
func slotOffset(off, scale int) uint32 {
	if off%scale != 0 || off < 0 || off/scale > 0xFFF {
		panic(fmt.Sprintf("hvcommon: slot offset %d is out of range", off))
	}
	return uint32(off / scale)
}

// Layout of the EL1 exception vector table. The table has 16 slots of 0x80
// bytes, and the common routine starts behind them.
const (
	VectorSlots        = 16
	VectorSlotSize     = 0x80
	VectorCommonOffset = VectorSlots * VectorSlotSize

	// The slot numbers that the backends tell apart, in architectural order.
	SlotCurrentSPxSync = 4
	SlotLowerSync      = 8
	SlotLowerIRQ       = 9
	SlotLowerSError    = 11
)

// ESR_ELx exception classes that the backends decode.
const (
	ECSVC64           = 0x15
	ECInstrAbortLower = 0x20
	ECDataAbortLower  = 0x24
)

// PstateEL1h is EL1 with SP_EL1 selected and the D, A, I, and F masks set.
const PstateEL1h = 0x3C5

// Values that every EL1 setup of the backends shares.
const (
	// MAIRNormalWB is the attribute byte of Normal write-back memory with read
	// and write allocation.
	MAIRNormalWB = 0xFF

	// CPACRNoTrap sets FPEN to 0b11: EL0 and EL1 use FP and Advanced SIMD
	// without a trap.
	CPACRNoTrap = 3 << 20

	// CNTKCTLEL0 sets EL0PCTEN and EL0VCTEN, so guest code reads the physical
	// and virtual counters without a trap.
	CNTKCTLEL0 = 3
)

// TCR returns the TCR_EL1 value for 4KB granules, 48-bit input addresses in
// both halves, inner-shareable write-back table walks, top-byte-ignore for
// TTBR0, and an output size of ips (the IPS field encoding). EPD0 and EPD1 stay
// clear, so both TTBR0_EL1 and TTBR1_EL1 translate.
func TCR(ips uint64) uint64 {
	const (
		t0sz  = 16
		irgn0 = 1 << 8
		orgn0 = 1 << 10
		sh0   = 3 << 12
		tg0   = 0 << 14 // 4KB.
		t1sz  = 16 << 16
		irgn1 = 1 << 24
		orgn1 = 1 << 26
		sh1   = 3 << 28
		tg1   = 2 << 30 // 4KB: TG1 encodes granules differently from TG0.
		tbi0  = 1 << 37
	)
	return t0sz | irgn0 | orgn0 | sh0 | tg0 | t1sz | irgn1 | orgn1 | sh1 | tg1 | ips<<32 | tbi0
}

// SysRegISS holds the decoded ISS fields of an EC = 0x18 (MRS, MSR, or SYS)
// exception syndrome.
type SysRegISS struct {
	Read                    bool
	Rt                      uint32
	Op0, Op1, CRn, CRm, Op2 uint32
}

// DecodeSysRegISS extracts the instruction fields from ESR_EL1 when EC is 0x18.
func DecodeSysRegISS(esr uint64) SysRegISS {
	return SysRegISS{
		Read: esr&1 != 0,
		Rt:   uint32(esr >> 5 & 0x1f),
		CRm:  uint32(esr >> 1 & 0xf),
		CRn:  uint32(esr >> 10 & 0xf),
		Op1:  uint32(esr >> 14 & 0x7),
		Op2:  uint32(esr >> 17 & 0x7),
		Op0:  uint32(esr >> 20 & 0x3),
	}
}

// Key returns the packed (op0, op1, CRn, CRm, op2) identifier of s.
func (s SysRegISS) Key() uint32 {
	return s.Op0<<14 | s.Op1<<11 | s.CRn<<7 | s.CRm<<3 | s.Op2
}

// Packed keys of the system registers that EL0 reads and the hypervisor
// backends emulate.
const (
	KeyMIDR        = 3<<14 | 0<<11 | 0<<7 | 0<<3 | 0
	KeyREVIDR      = 3<<14 | 0<<11 | 0<<7 | 0<<3 | 6
	KeyIDAA64PFR0  = 3<<14 | 0<<11 | 0<<7 | 4<<3 | 0
	KeyIDAA64PFR1  = 3<<14 | 0<<11 | 0<<7 | 4<<3 | 1
	KeyIDAA64ISAR0 = 3<<14 | 0<<11 | 0<<7 | 6<<3 | 0
	KeyIDAA64ISAR1 = 3<<14 | 0<<11 | 0<<7 | 6<<3 | 1
	KeyIDAA64MMFR0 = 3<<14 | 0<<11 | 0<<7 | 7<<3 | 0
	KeyIDAA64MMFR1 = 3<<14 | 0<<11 | 0<<7 | 7<<3 | 1
	KeyIDAA64MMFR2 = 3<<14 | 0<<11 | 0<<7 | 7<<3 | 2
	KeyCTREL0      = 3<<14 | 3<<11 | 0<<7 | 0<<3 | 1
	KeyDCZIDEL0    = 3<<14 | 3<<11 | 0<<7 | 0<<3 | 7
	KeyCNTPCT      = 3<<14 | 3<<11 | 14<<7 | 0<<3 | 1
	KeyCNTVCT      = 3<<14 | 3<<11 | 14<<7 | 0<<3 | 2
)

// DecodeMRSSysRegISS decodes a 32-bit AArch64 MRS instruction word into a
// SysRegISS value suitable for IDRegisters.EmulateSysRegRead.
func DecodeMRSSysRegISS(insn uint32) (SysRegISS, bool) {
	if insn&0xfff00000 != 0xd5300000 {
		return SysRegISS{}, false
	}
	return SysRegISS{
		Read: true,
		Rt:   insn & 0x1f,
		Op2:  (insn >> 5) & 0x7,
		CRm:  (insn >> 8) & 0xf,
		CRn:  (insn >> 12) & 0xf,
		Op1:  (insn >> 16) & 0x7,
		Op0:  3,
	}, true
}

// ID register fields hidden from the guest when the backend does not
// virtualize scalable vectors, memory tagging, or pointer authentication.
const (
	IDAA64PFR0Hide  uint64 = 0xf<<32 | 0xff<<40
	IDAA64PFR1Hide  uint64 = 0xf<<8 | 0xf<<16 | 0xf<<24 | 0xf<<40
	IDAA64ISAR1Hide uint64 = 0xf<<4 | 0xf<<8 | 0xf<<24 | 0xf<<28
)

// Baseline architectural register values used when a backend does not query
// host hardware ID registers directly.
const (
	DefaultMIDREL1        uint64 = 0x410fd030
	DefaultIDAA64PFR0EL1  uint64 = 0x00000011
	DefaultIDAA64ISAR0EL1 uint64 = 0x00211120
	DefaultIDAA64MMFR0EL1 uint64 = 0x00100005
	DefaultCTREL0         uint64 = 0x8444c004
	DefaultDCZIDEL0       uint64 = 0x00000004
)

// IDRegisters holds the values that EL0 reads of the ID registers, CTR_EL0,
// and the physical/virtual counters return.
type IDRegisters struct {
	MIDR, PFR0, PFR1    uint64
	ISAR0, ISAR1        uint64
	MMFR0, MMFR1, MMFR2 uint64
	CTR                 uint64
	Counter             func() uint64
}

// DefaultIDRegisters returns an IDRegisters populated with baseline ARMv8-A
// feature values and 64-byte cache line geometry.
func DefaultIDRegisters() IDRegisters {
	return IDRegisters{
		MIDR:  DefaultMIDREL1,
		PFR0:  DefaultIDAA64PFR0EL1,
		ISAR0: DefaultIDAA64ISAR0EL1,
		MMFR0: DefaultIDAA64MMFR0EL1,
		CTR:   DefaultCTREL0,
	}
}

// EmulateSysRegRead returns the value a trapped MRS must produce. It reports
// false for writes and for registers that must raise SIGILL at EL0.
func (ids *IDRegisters) EmulateSysRegRead(iss SysRegISS) (uint64, bool) {
	if !iss.Read {
		return 0, false
	}
	switch iss.Key() {
	case KeyMIDR:
		return ids.MIDR, true
	case KeyREVIDR:
		return 0, true
	case KeyIDAA64PFR0:
		return ids.PFR0 &^ IDAA64PFR0Hide, true
	case KeyIDAA64PFR1:
		return ids.PFR1 &^ IDAA64PFR1Hide, true
	case KeyIDAA64ISAR0:
		return ids.ISAR0, true
	case KeyIDAA64ISAR1:
		return ids.ISAR1 &^ IDAA64ISAR1Hide, true
	case KeyIDAA64MMFR0:
		return ids.MMFR0, true
	case KeyIDAA64MMFR1:
		return ids.MMFR1, true
	case KeyIDAA64MMFR2:
		return ids.MMFR2, true
	case KeyCTREL0:
		if ids.CTR != 0 {
			return ids.CTR, true
		}
		return DefaultCTREL0, true
	case KeyDCZIDEL0:
		return DefaultDCZIDEL0, true
	case KeyCNTPCT, KeyCNTVCT:
		if ids.Counter != nil {
			return ids.Counter(), true
		}
	}
	return 0, false
}
