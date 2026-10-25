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
// backends whpx and hvf and the user-mode systrap backend share: AArch64 and
// x86-64 instruction encoders, exception classifiers, CommHeader layouts, and
// Stage-1 page-table allocators.
package hvcommon

import (
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

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
	NOP  uint32 = 0xD503201F
	SVC0 uint32 = 0xD4000001
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

// BRK encodes BRK #imm.
func BRK(imm uint16) uint32 { return 0xD4200000 | uint32(imm)<<5 }

// MRS encodes MRS Xt, reg.
func MRS(rt int, reg SysReg) uint32 { return 0xD5300000 | uint32(reg) | uint32(rt) }

// MSR encodes MSR reg, Xt.
func MSR(reg SysReg, rt int) uint32 { return 0xD5100000 | uint32(reg) | uint32(rt) }

// MOVZShift encodes MOVZ Xd, #imm, LSL #shift (shift in {0, 16, 32, 48}).
func MOVZShift(rd int, imm uint16, shift int) uint32 {
	return 0xD2800000 | uint32(shift/16)<<21 | uint32(imm)<<5 | uint32(rd)
}

// MOVZ encodes MOVZ Xd, #imm.
func MOVZ(rd int, imm uint16) uint32 { return MOVZShift(rd, imm, 0) }

// MOVZW encodes MOVZ Wd, #imm.
func MOVZW(rd int, imm uint16) uint32 { return 0x52800000 | uint32(imm)<<5 | uint32(rd) }

// MOVK encodes MOVK Xd, #imm, LSL #shift (shift in {0, 16, 32, 48}).
func MOVK(rd int, imm uint16, shift int) uint32 {
	return 0xF2800000 | uint32(shift/16)<<21 | uint32(imm)<<5 | uint32(rd)
}

// MovConst encodes a 4-instruction 64-bit immediate load into Xd using MOVZ
// followed by three MOVK instructions.
func MovConst(rd int, val uint64) [4]uint32 {
	return [4]uint32{
		MOVZ(rd, uint16(val)),
		MOVK(rd, uint16(val>>16), 16),
		MOVK(rd, uint16(val>>32), 32),
		MOVK(rd, uint16(val>>48), 48),
	}
}

// MovConstCompact encodes a variable-length (1..4 instruction) 64-bit immediate
// load into Xd using MOVZ followed by MOVK for non-zero 16-bit chunks.
func MovConstCompact(rd int, val uint64) []uint32 {
	words := []uint32{MOVZ(rd, uint16(val))}
	for sh := 16; sh < 64; sh += 16 {
		if chunk := uint16(val >> sh); chunk != 0 {
			words = append(words, MOVK(rd, chunk, sh))
		}
	}
	return words
}

// MOVReg encodes MOV Xd, Xm (ORR Xd, XZR, Xm).
func MOVReg(dst, src int) uint32 { return 0xAA0003E0 | uint32(src)<<16 | uint32(dst) }

// BR encodes BR Xn.
func BR(rn int) uint32 { return 0xD61F0000 | uint32(rn)<<5 }

// BLR encodes BLR Xn.
func BLR(rn int) uint32 { return 0xD63F0000 | uint32(rn)<<5 }

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

// TBNZ encodes TBNZ Xt, #bit with a byte displacement from the branch.
func TBNZ(rt, bit, byteOff int) uint32 {
	b5 := uint32(bit>>5) & 1
	b40 := uint32(bit & 0x1F)
	return 0x37000000 | b5<<31 | b40<<19 | (uint32(byteOff/4)&0x3FFF)<<5 | uint32(rt)
}

// STPX encodes STP Xt1, Xt2, [Xn, #off].
func STPX(rn, t1, t2, off int) uint32 {
	return 0xA9000000 | pairOffset(off, 8)<<15 | uint32(t2)<<10 | uint32(rn)<<5 | uint32(t1)
}

// LDPX encodes LDP Xt1, Xt2, [Xn, #off].
func LDPX(rn, t1, t2, off int) uint32 {
	return 0xA9400000 | pairOffset(off, 8)<<15 | uint32(t2)<<10 | uint32(rn)<<5 | uint32(t1)
}

// STPQ encodes STP Qt1, Qt2, [Xn, #off].
func STPQ(rn, t1, t2, off int) uint32 {
	return 0xAD000000 | pairOffset(off, 16)<<15 | uint32(t2)<<10 | uint32(rn)<<5 | uint32(t1)
}

// LDPQ encodes LDP Qt1, Qt2, [Xn, #off].
func LDPQ(rn, t1, t2, off int) uint32 {
	return 0xAD400000 | pairOffset(off, 16)<<15 | uint32(t2)<<10 | uint32(rn)<<5 | uint32(t1)
}

// STRX encodes STR Xt, [Xn, #off].
func STRX(rn, t, off int) uint32 {
	return 0xF9000000 | slotOffset(off, 8)<<10 | uint32(rn)<<5 | uint32(t)
}

// LDRX encodes LDR Xt, [Xn, #off].
func LDRX(rn, t, off int) uint32 {
	return 0xF9400000 | slotOffset(off, 8)<<10 | uint32(rn)<<5 | uint32(t)
}

// STRW encodes STR Wt, [Xn, #off].
func STRW(rn, t, off int) uint32 {
	return 0xB9000000 | slotOffset(off, 4)<<10 | uint32(rn)<<5 | uint32(t)
}

// LDRW encodes LDR Wt, [Xn, #off].
func LDRW(rn, t, off int) uint32 {
	return 0xB9400000 | slotOffset(off, 4)<<10 | uint32(rn)<<5 | uint32(t)
}

// STPXSP encodes STP Xt1, Xt2, [SP, #off].
func STPXSP(t1, t2, off int) uint32 { return STPX(31, t1, t2, off) }

// LDPXSP encodes LDP Xt1, Xt2, [SP, #off].
func LDPXSP(t1, t2, off int) uint32 { return LDPX(31, t1, t2, off) }

// STPQSP encodes STP Qt1, Qt2, [SP, #off].
func STPQSP(t1, t2, off int) uint32 { return STPQ(31, t1, t2, off) }

// LDPQSP encodes LDP Qt1, Qt2, [SP, #off].
func LDPQSP(t1, t2, off int) uint32 { return LDPQ(31, t1, t2, off) }

// STRXSP encodes STR Xt, [SP, #off].
func STRXSP(t, off int) uint32 { return STRX(31, t, off) }

// LDRXSP encodes LDR Xt, [SP, #off].
func LDRXSP(t, off int) uint32 { return LDRX(31, t, off) }

// STRWSP encodes STR Wt, [SP, #off].
func STRWSP(t, off int) uint32 { return STRW(31, t, off) }

// LDRWSP encodes LDR Wt, [SP, #off].
func LDRWSP(t, off int) uint32 { return LDRW(31, t, off) }

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

// CommHeader is the 304-byte (0x000..0x130) register and exception header
// shared at offset 0 of both hvf.CommPage and whpx.CommPage.
type CommHeader struct {
	Regs      [31]uint64 // 0x000: X0..X30 on arm64; RAX..R15 on amd64.
	SP        uint64     // 0x0F8: SP_EL0 on arm64; RSP on amd64.
	PC        uint64     // 0x100: ELR_EL1 on arm64; RIP on amd64.
	Pstate    uint64     // 0x108: SPSR_EL1 on arm64; RFLAGS on amd64.
	TLS       uint64     // 0x110: TPIDR_EL0 on arm64.
	FaultAddr uint64     // 0x118: FAR_EL1 on arm64; CR2 on amd64.
	ESR       uint64     // 0x120: ESR_EL1 on arm64; error code on amd64.
	Vector    uint64     // 0x128: exception vector slot or number.
}

// Compile-time byte offsets inside CommHeader.
const (
	CommOffRegs      = 0x000
	CommOffSP        = 0x0F8
	CommOffPC        = 0x100
	CommOffPstate    = 0x108
	CommOffTLS       = 0x110
	CommOffFaultAddr = 0x118
	CommOffESR       = 0x120
	CommOffVector    = 0x128
	CommHeaderSize   = 0x130
)

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

// ESR_ELx exception classes and syndrome fields decoded by the backends.
const (
	ECUnknown         = 0x00
	ECWFx             = 0x01
	ECFPAccess        = 0x07
	ECIllegalState    = 0x0E
	ECSVC64           = 0x15
	ECHVC64           = 0x16
	ECSysReg          = 0x18
	ECInstrAbortLower = 0x20
	ECPCAlignment     = 0x22
	ECDataAbortLower  = 0x24
	ECSPAlignment     = 0x26
	ECFPExc64         = 0x2C
	ECSError          = 0x2F
	ECBreakpointLower = 0x30
	ECBreakpointCur   = 0x31
	ECSoftStepLower   = 0x32
	ECSoftStepCur     = 0x33
	ECWatchpointLower = 0x34
	ECWatchpointCur   = 0x35
	ECBRK64           = 0x3C

	ESRECShift = 26
	ESRFSCMask = 0x3F

	FSCTranslationL0 = 0x04
	FSCTranslationL3 = 0x07
	FSCPermissionL1  = 0x0D
	FSCPermissionL3  = 0x0F
	FSCSyncExternal  = 0x10
	FSCAlignment     = 0x21
)

// ESREC extracts the 6-bit Exception Class (EC) field from an ESR_ELx value.
func ESREC(esr uint64) uint64 { return (esr >> ESRECShift) & 0x3F }

// ESRFSC extracts the 6-bit Fault Status Code (FSC) field from an ESR_ELx value.
func ESRFSC(esr uint64) uint64 { return esr & ESRFSCMask }

// A64ExitKind classifies an AArch64 lower-EL synchronous exception.
type A64ExitKind uint8

const (
	// A64ExitSyscall indicates an EL0 SVC #0 system call.
	A64ExitSyscall A64ExitKind = iota
	// A64ExitSignal indicates a fault or trap that delivers a Linux signal.
	A64ExitSignal
	// A64ExitSysReg indicates a trapped MRS/MSR/SYS instruction (EC 0x18).
	A64ExitSysReg
	// A64ExitSkip indicates a trapped WFI/WFE instruction (EC 0x01) that
	// advances PC by 4 bytes.
	A64ExitSkip
)

// UntagA64UserAddr strips the Top-Byte-Ignore (TBI0) tag from a lower-half
// AArch64 user address (bit 55 == 0).
func UntagA64UserAddr(addr uint64) uint64 {
	if addr&(1<<55) == 0 {
		return addr &^ (0xFF << 56)
	}
	return addr
}

// ESRAccessType returns the memory AccessType for an AArch64 instruction or
// data abort ESR_ELx value. Cache maintenance faults (ISS.CM, bit 8) are
// treated as reads even when ISS.WnR (bit 6) is set.
func ESRAccessType(esr uint64) hostarch.AccessType {
	if ESREC(esr) == ECInstrAbortLower {
		return hostarch.Execute
	}
	const (
		esrISSWnR = 1 << 6
		esrISSCM  = 1 << 8
	)
	if esr&esrISSWnR != 0 && esr&esrISSCM == 0 {
		return hostarch.Write
	}
	return hostarch.Read
}

// DecodeA64SyncException classifies a lower-EL AArch64 synchronous exception
// (SlotLowerSync) from ESR_EL1, FAR_EL1, ELR_EL1 (pc), and SP_EL0 (sp).
//
// It strips the Top-Byte-Ignore (TBI) tag from FAR_EL1 on data and instruction
// aborts, reports SP_EL0 on SP alignment faults, reports FAR_EL1 on watchpoint
// traps, and maps trapped floating-point exceptions (EC 0x2C) to SIGFPE.
func DecodeA64SyncException(esr, far, pc, sp uint64) (kind A64ExitKind, sig *linux.SignalInfo, at hostarch.AccessType) {
	mkSig := func(signo linux.Signal, code int32, addr uint64, access hostarch.AccessType) (A64ExitKind, *linux.SignalInfo, hostarch.AccessType) {
		info := &linux.SignalInfo{Signo: int32(signo), Code: code}
		info.SetAddr(addr)
		return A64ExitSignal, info, access
	}
	switch ec := ESREC(esr); ec {
	case ECSVC64:
		return A64ExitSyscall, nil, hostarch.NoAccess
	case ECWFx:
		return A64ExitSkip, nil, hostarch.NoAccess
	case ECSysReg:
		return A64ExitSysReg, nil, hostarch.NoAccess
	case ECInstrAbortLower, ECDataAbortLower:
		addr := UntagA64UserAddr(far)
		access := ESRAccessType(esr)
		switch fsc := ESRFSC(esr); {
		case fsc == FSCAlignment:
			return mkSig(linux.SIGBUS, BusAdrAln, addr, access)
		case fsc <= FSCTranslationL3:
			return mkSig(linux.SIGSEGV, SegvMapErr, addr, access)
		case fsc >= 0x09 && fsc <= FSCPermissionL3:
			return mkSig(linux.SIGSEGV, SegvAccErr, addr, access)
		default:
			return mkSig(linux.SIGBUS, BusAdrErr, addr, access)
		}
	case ECPCAlignment:
		return mkSig(linux.SIGBUS, BusAdrAln, far, hostarch.NoAccess)
	case ECSPAlignment:
		return mkSig(linux.SIGBUS, BusAdrAln, sp, hostarch.NoAccess)
	case ECFPExc64:
		return mkSig(linux.SIGFPE, FpeFltInv, pc, hostarch.NoAccess)
	case ECBRK64:
		return mkSig(linux.SIGTRAP, linux.TRAP_BRKPT, pc, hostarch.NoAccess)
	case ECSoftStepLower, ECSoftStepCur:
		return mkSig(linux.SIGTRAP, linux.TRAP_TRACE, pc, hostarch.NoAccess)
	case ECBreakpointLower, ECBreakpointCur:
		return mkSig(linux.SIGTRAP, linux.TRAP_HWBKPT, pc, hostarch.NoAccess)
	case ECWatchpointLower, ECWatchpointCur:
		return mkSig(linux.SIGTRAP, linux.TRAP_HWBKPT, far, hostarch.NoAccess)
	default:
		return mkSig(linux.SIGILL, IllIllOpc, pc, hostarch.NoAccess)
	}
}

// A64StubOptions configures the shared ARM64 EL1 exception vector and
// spill/reload page generator.
type A64StubOptions struct {
	// SpillFP spills and reloads Q0..Q31, FPSR, and FPCR in the EL1 stub.
	SpillFP  bool
	OffVRegs int
	OffFPSR  int
	OffFPCR  int

	// WriteExitReason stores ExitException (32-bit) at OffExitReason before HVC #0.
	WriteExitReason bool
	OffExitReason   int
	ExitException   uint16

	// ReloadTTBR0 reloads TTBR0_EL1 from OffRoot when bit 0 of OffFlags is set,
	// and invalidates the instruction cache when bit 2 of OffFlags is set.
	// When false, OffFlags is read as 64-bit with bit 0 = TLBI and bit 1 = IC.
	ReloadTTBR0 bool
	OffRoot     int
	OffFlags    int
}

// BuildA64VectorPage generates the 4KB ARM64 EL1 exception vector table,
// common register spill handler, HVC #0 exit point, and reload/ERET routine.
func BuildA64VectorPage(opts A64StubOptions) (page []byte, hvcOff, reloadOff, reloadEnd int) {
	page = make([]byte, PageSize4K)
	off := 0
	emit := func(insn uint32) {
		binary.LittleEndian.PutUint32(page[off:off+4], insn)
		off += 4
	}
	emitAll := func(insns ...uint32) {
		for _, insn := range insns {
			emit(insn)
		}
	}

	for slot := range VectorSlots {
		off = slot * VectorSlotSize
		emit(STPXSP(0, 1, CommOffRegs))
		emit(MOVZ(0, uint16(slot)))
		emit(STRXSP(0, CommOffVector))
		emit(B(VectorCommonOffset - off))
	}

	off = VectorCommonOffset
	for k := 1; k <= 14; k++ {
		emit(STPXSP(2*k, 2*k+1, CommOffRegs+16*k))
	}
	emit(STRXSP(30, CommOffRegs+30*8))
	emitAll(
		MRS(0, SysRegSPEL0),
		MRS(1, SysRegELREL1),
		MRS(2, SysRegSPSREL1),
		MRS(3, SysRegTPIDREL0),
		MRS(4, SysRegFAREL1),
		MRS(5, SysRegESREL1),
		STPXSP(0, 1, CommOffSP),
		STPXSP(2, 3, CommOffPstate),
		STPXSP(4, 5, CommOffFaultAddr),
	)
	if opts.SpillFP {
		for k := range 16 {
			emit(STPQSP(2*k, 2*k+1, opts.OffVRegs+32*k))
		}
		emitAll(
			MRS(0, SysRegFPSR),
			MRS(1, SysRegFPCR),
			STRXSP(0, opts.OffFPSR),
			STRXSP(1, opts.OffFPCR),
			DSBISH,
		)
	}
	if opts.WriteExitReason {
		emitAll(
			MOVZW(0, opts.ExitException),
			STRWSP(0, opts.OffExitReason),
		)
	}
	hvcOff = off
	emit(HVC(0))
	reloadOff = off

	if !opts.ReloadTTBR0 {
		emit(LDRXSP(0, opts.OffFlags))
		emit(CBZ(0, 7*4))
		emit(TBZ(0, 0, 2*4))
		emit(TLBIVMALLE1)
		emit(TBZ(0, 1, 2*4))
		emit(ICIALLUIS)
		emit(DSBISH)
		emit(ISB)
	}
	if opts.SpillFP {
		emitAll(
			LDRXSP(0, opts.OffFPSR),
			LDRXSP(1, opts.OffFPCR),
			MSR(SysRegFPSR, 0),
			MSR(SysRegFPCR, 1),
		)
		for k := range 16 {
			emit(LDPQSP(2*k, 2*k+1, opts.OffVRegs+32*k))
		}
	}
	emitAll(
		LDPXSP(0, 1, CommOffSP),
		LDPXSP(2, 3, CommOffPstate),
		MSR(SysRegSPEL0, 0),
		MSR(SysRegELREL1, 1),
		MSR(SysRegSPSREL1, 2),
		MSR(SysRegTPIDREL0, 3),
	)
	if opts.ReloadTTBR0 {
		emitAll(
			LDRWSP(0, opts.OffFlags),
			TBZ(0, 0, 7*4),
			LDRXSP(1, opts.OffRoot),
			MSR(SysRegTTBR0EL1, 1),
			ISB,
			TLBIVMALLE1,
			DSBNSH,
			ISB,
			TBZ(0, 2, 4*4),
			ICIALLUIS,
			DSBISH,
			ISB,
		)
		for r := 2; r < 30; r += 2 {
			emit(LDPXSP(r, r+1, CommOffRegs+r*8))
		}
		emit(LDRXSP(30, CommOffRegs+30*8))
		emit(LDPXSP(0, 1, CommOffRegs))
	} else {
		for k := 0; k <= 14; k++ {
			emit(LDPXSP(2*k, 2*k+1, CommOffRegs+16*k))
		}
		emit(LDRXSP(30, CommOffRegs+30*8))
	}
	emit(ERET)
	reloadEnd = off
	return page, hvcOff, reloadOff, reloadEnd
}

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

	// SCTLREL1Set lists the SCTLR_EL1 bits that EL1 bring-up enables: MMU (M),
	// data cache (C), instruction cache (I), DC ZVA at EL0 (DZE), CTR_EL0 at
	// EL0 (UCT), and cache maintenance at EL0 (UCI).
	SCTLREL1Set = 1<<0 | 1<<2 | 1<<12 | 1<<14 | 1<<15 | 1<<26
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
	DefaultIDAA64ISAR1EL1 uint64 = 0x00100001
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
		ISAR1: DefaultIDAA64ISAR1EL1,
		MMFR0: DefaultIDAA64MMFR0EL1,
		CTR:   DefaultCTREL0,
	}
}

// EmulateSysRegRead returns the value a trapped MRS must produce. It reports
// false for writes and for registers that must raise SIGILL at EL0.
func (ids IDRegisters) EmulateSysRegRead(iss SysRegISS) (uint64, bool) {
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
