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

package hvcommon

import (
	"encoding/binary"
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
)

// Linux si_code values for SIGSEGV, SIGBUS, SIGILL, SIGFPE, and SIGTRAP.
const (
	SegvMapErr = 1
	SegvAccErr = 2
	BusAdrAln  = 1
	BusAdrErr  = 2
	BusObjErr  = 3
	IllIllOpc  = 1
	IllIllOpn  = 2
	IllIllTrp  = 4
	TrapBrkpt  = 1
	FpeIntDiv  = 1
	FpeIntOvf  = 2
	FpeFltDiv  = 3
	FpeFltOvf  = 4
	FpeFltUnd  = 5
	FpeFltRes  = 6
	FpeFltInv  = 7
)

// Architectural x86-64 exception vector numbers.
const (
	X86VecDivide        = 0
	X86VecDebug         = 1
	X86VecNMI           = 2
	X86VecBreakpoint    = 3
	X86VecOverflow      = 4
	X86VecBound         = 5
	X86VecInvalidOpcode = 6
	X86VecNoMath        = 7
	X86VecDoubleFault   = 8
	X86VecInvalidTSS    = 10
	X86VecSegNotPresent = 11
	X86VecStackSegment  = 12
	X86VecGeneralProt   = 13
	X86VecPageFault     = 14
	X86VecX87           = 16
	X86VecAlignment     = 17
	X86VecMachineCheck  = 18
	X86VecSIMD          = 19
)

// ClassifyX86Exception maps an x86-64 guest exception vector, error code, CR2,
// and RIP to a Linux SignalInfo and memory AccessType.
func ClassifyX86Exception(vector, errCode, cr2, rip uint64) (sig *linux.SignalInfo, at hostarch.AccessType, hasAddr bool, addr uint64, err error) {
	info := &linux.SignalInfo{}
	hasAddr = true
	addr = rip
	switch vector {
	case X86VecPageFault:
		info.Signo = int32(linux.SIGSEGV)
		addr = cr2
		at = hostarch.AccessType{
			Read:    errCode&(1<<1) == 0,
			Write:   errCode&(1<<1) != 0,
			Execute: errCode&(1<<4) != 0,
		}
		info.Code = SegvMapErr
		if errCode&1 != 0 {
			info.Code = SegvAccErr
		}
	case X86VecDebug:
		info.Signo = int32(linux.SIGTRAP)
		info.Code = linux.TRAP_TRACE
	case X86VecBreakpoint:
		info.Signo = int32(linux.SIGTRAP)
		info.Code = linux.SI_KERNEL
		hasAddr, addr = false, 0
	case X86VecGeneralProt, X86VecSegNotPresent, X86VecBound, X86VecInvalidTSS, X86VecStackSegment:
		info.Signo = int32(linux.SIGSEGV)
		info.Code = linux.SI_KERNEL
	case X86VecInvalidOpcode, X86VecNoMath:
		info.Signo = int32(linux.SIGILL)
		info.Code = IllIllOpc
	case X86VecDivide:
		info.Signo = int32(linux.SIGFPE)
		info.Code = FpeIntDiv
	case X86VecOverflow:
		info.Signo = int32(linux.SIGFPE)
		info.Code = FpeIntOvf
	case X86VecX87, X86VecSIMD:
		info.Signo = int32(linux.SIGFPE)
		info.Code = FpeFltInv
	case X86VecAlignment:
		info.Signo = int32(linux.SIGBUS)
		info.Code = BusAdrAln
		hasAddr, addr = false, 0
	case X86VecNMI, X86VecDoubleFault, X86VecMachineCheck:
		return nil, hostarch.NoAccess, false, 0, fmt.Errorf("unrecoverable guest exception, vector %d, error code %#x, rip %#x", vector, errCode, rip)
	default:
		info.Signo = int32(linux.SIGSEGV)
		info.Code = linux.SI_KERNEL
	}
	if hasAddr {
		info.SetAddr(addr)
	}
	return info, at, hasAddr, addr, nil
}

// Segment selectors of the guest GDT. They follow the Linux x86-64 layout, so
// the user selectors equal the values that pkg/sentry/arch stores in the user
// registers.
const (
	SelKernelCS = 0x10
	SelKernelSS = 0x18
	SelUserCS32 = 0x23
	SelUserSS   = 0x2B
	SelUserCS64 = 0x33
)

// GDT descriptors for those selectors. Every accessed bit is set, so the CPU
// never writes a read-only GDT page.
const (
	DescKernelCode64 = 0x00AF9B000000FFFF
	DescKernelData   = 0x00CF93000000FFFF
	DescUserCode32   = 0x00CFFB000000FFFF
	DescUserData     = 0x00CFF3000000FFFF
	DescUserCode64   = 0x00AFFB000000FFFF
)

// VectorHasErrorCode reports whether the CPU pushes an error code for the
// exception vector.
func VectorHasErrorCode(vec int) bool {
	switch vec {
	case 8, 10, 11, 12, 13, 14, 17, 21, 29, 30:
		return true
	}
	return false
}

// Layout of the 64-bit task state segment. Only RSP0 and the I/O map base are
// meaningful.
const (
	// TSSSize is the size of the structure without an I/O bitmap.
	TSSSize = 104
	// TSSLimit is the segment limit that names the last byte of the structure.
	TSSLimit = TSSSize - 1
	// TSSRSP0Offset is the offset of RSP0, the stack that a privilege change uses.
	TSSRSP0Offset = 4
	// TSSIOMapOffset is the offset of the I/O map base.
	TSSIOMapOffset = 102
)

// FillTSS writes the task state segment template into tss, which must hold
// TSSSize bytes. The I/O map base points past the limit, so user I/O
// instructions raise #GP.
func FillTSS(tss []byte, kernelStackTop uint64) {
	clear(tss[:TSSSize])
	binary.LittleEndian.PutUint64(tss[TSSRSP0Offset:], kernelStackTop)
	binary.LittleEndian.PutUint16(tss[TSSIOMapOffset:], TSSSize)
}

// IDTGate encodes a 64-bit interrupt gate at the kernel code segment. User
// code reaches the gate with an INT instruction only when dpl is 3. IST 0
// selects the stack of RSP0.
func IDTGate(handler uint64, dpl int) [16]byte {
	var g [16]byte
	binary.LittleEndian.PutUint16(g[0:], uint16(handler))
	binary.LittleEndian.PutUint16(g[2:], SelKernelCS)
	g[5] = 0x8E | byte(dpl&3)<<5 // Present, interrupt gate.
	binary.LittleEndian.PutUint16(g[6:], uint16(handler>>16))
	binary.LittleEndian.PutUint32(g[8:], uint32(handler>>32))
	return g
}

// The appenders write one instruction at the end of b and return the longer
// slice. The stubs address the CommPage through the GS segment, because
// SWAPGS exchanges the user GS base with the CommPage address.

// AppendSwapgs appends SWAPGS.
func AppendSwapgs(b []byte) []byte { return append(b, 0x0F, 0x01, 0xF8) }

// AppendHlt appends HLT.
func AppendHlt(b []byte) []byte { return append(b, 0xF4) }

// AppendIretq appends IRETQ.
func AppendIretq(b []byte) []byte { return append(b, 0x48, 0xCF) }

// AppendGSOperand appends the ModRM and SIB bytes of an absolute disp32
// operand, then the displacement. reg is the ModRM reg field. A caller
// puts the GS segment prefix and the opcode in front of it.
func AppendGSOperand(b []byte, reg byte, disp uint32) []byte {
	b = append(b, 0x04|(reg&7)<<3, 0x25)
	return binary.LittleEndian.AppendUint32(b, disp)
}

// rexW returns the REX.W prefix, with REX.R for the registers 8 to 15.
func rexW(reg int) byte { return 0x48 | byte(reg>>3)<<2 }

// AppendMovToGS appends MOV [gs:disp32], r64.
func AppendMovToGS(b []byte, reg int, disp uint32) []byte {
	return AppendGSOperand(append(b, 0x65, rexW(reg), 0x89), byte(reg), disp)
}

// AppendMovFromGS appends MOV r64, [gs:disp32].
func AppendMovFromGS(b []byte, reg int, disp uint32) []byte {
	return AppendGSOperand(append(b, 0x65, rexW(reg), 0x8B), byte(reg), disp)
}

// AppendPushGS appends PUSH QWORD [gs:disp32].
func AppendPushGS(b []byte, disp uint32) []byte {
	return AppendGSOperand(append(b, 0x65, 0xFF), 6, disp)
}
