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

//go:build linux && arm64

#include "textflag.h"
#include "go_asm.h"

// The Go assembler reserves R18, R27, and R28. It can use R27 for a large
// offset. The macros therefore encode each access to a general purpose register.
// X9 points to the State. Offsets stay below 504 for LDP and STP, below 32760
// for LDR and STR, and below 1008 for FLDPQ and FSTPQ.
#define LDPX(rt, rt2, off) WORD $(0xa9400000 | (((off)/8)<<15) | ((rt2)<<10) | (9<<5) | (rt))
#define STPX(rt, rt2, off) WORD $(0xa9000000 | (((off)/8)<<15) | ((rt2)<<10) | (9<<5) | (rt))
#define LDRX(rt, off) WORD $(0xf9400000 | (((off)/8)<<10) | (9<<5) | (rt))
#define STRX(rt, off) WORD $(0xf9000000 | (((off)/8)<<10) | (9<<5) | (rt))
#define LDRSP(rt, off) WORD $(0xf9400000 | (((off)/8)<<10) | (31<<5) | (rt))
#define STRSP(rt, off) WORD $(0xf9000000 | (((off)/8)<<10) | (31<<5) | (rt))
#define MSR_FPCR(rt) WORD $(0xd51b4400 | (rt))
#define MSR_FPSR(rt) WORD $(0xd51b4420 | (rt))
#define MRS_FPCR(rt) WORD $(0xd53b4400 | (rt))
#define MRS_FPSR(rt) WORD $(0xd53b4420 | (rt))
#define XREG(i) (State_X+8*(i))

// LOAD_CTL_VEC loads the FP control registers and V0 to V31. It uses X10.
#define LOAD_CTL_VEC \
	LDRX(10, State_FPCR); \
	MSR_FPCR(10); \
	LDRX(10, State_FPSR); \
	MSR_FPSR(10); \
	FLDPQ (State_V+16*0)(R9), (F0, F1); \
	FLDPQ (State_V+16*2)(R9), (F2, F3); \
	FLDPQ (State_V+16*4)(R9), (F4, F5); \
	FLDPQ (State_V+16*6)(R9), (F6, F7); \
	FLDPQ (State_V+16*8)(R9), (F8, F9); \
	FLDPQ (State_V+16*10)(R9), (F10, F11); \
	FLDPQ (State_V+16*12)(R9), (F12, F13); \
	FLDPQ (State_V+16*14)(R9), (F14, F15); \
	FLDPQ (State_V+16*16)(R9), (F16, F17); \
	FLDPQ (State_V+16*18)(R9), (F18, F19); \
	FLDPQ (State_V+16*20)(R9), (F20, F21); \
	FLDPQ (State_V+16*22)(R9), (F22, F23); \
	FLDPQ (State_V+16*24)(R9), (F24, F25); \
	FLDPQ (State_V+16*26)(R9), (F26, F27); \
	FLDPQ (State_V+16*28)(R9), (F28, F29); \
	FLDPQ (State_V+16*30)(R9), (F30, F31)

// LOAD_X loads X0 to X8 and X10 to X29, and LOAD_X30 loads the link register.
#define LOAD_X \
	LDPX(0, 1, XREG(0)); \
	LDPX(2, 3, XREG(2)); \
	LDPX(4, 5, XREG(4)); \
	LDPX(6, 7, XREG(6)); \
	LDRX(8, XREG(8)); \
	LDPX(10, 11, XREG(10)); \
	LDPX(12, 13, XREG(12)); \
	LDPX(14, 15, XREG(14)); \
	LDPX(16, 17, XREG(16)); \
	LDPX(18, 19, XREG(18)); \
	LDPX(20, 21, XREG(20)); \
	LDPX(22, 23, XREG(22)); \
	LDPX(24, 25, XREG(24)); \
	LDPX(26, 27, XREG(26)); \
	LDPX(28, 29, XREG(28))
#define LOAD_X30 LDRX(30, XREG(30))
#define LOAD_X9 LDRX(9, XREG(9))

// STORE_STATE stores every register to the output State. X9 holds the address
// of the State of the caller. The macro keeps the value of X9 in a slot first.
#define STORE_STATE \
	STRSP(9, const_slotStash); \
	LDRSP(9, const_slotOut); \
	STPX(0, 1, XREG(0)); \
	STPX(2, 3, XREG(2)); \
	STPX(4, 5, XREG(4)); \
	STPX(6, 7, XREG(6)); \
	STRX(8, XREG(8)); \
	STPX(10, 11, XREG(10)); \
	STPX(12, 13, XREG(12)); \
	STPX(14, 15, XREG(14)); \
	STPX(16, 17, XREG(16)); \
	STPX(18, 19, XREG(18)); \
	STPX(20, 21, XREG(20)); \
	STPX(22, 23, XREG(22)); \
	STPX(24, 25, XREG(24)); \
	STPX(26, 27, XREG(26)); \
	STPX(28, 29, XREG(28)); \
	STRX(30, XREG(30)); \
	MOVD RSP, R0; \
	STRX(0, State_SP); \
	LDRSP(0, const_slotStash); \
	STRX(0, XREG(9)); \
	MRS_FPCR(0); \
	STRX(0, State_FPCR); \
	MRS_FPSR(0); \
	STRX(0, State_FPSR); \
	FSTPQ (F0, F1), (State_V+16*0)(R9); \
	FSTPQ (F2, F3), (State_V+16*2)(R9); \
	FSTPQ (F4, F5), (State_V+16*4)(R9); \
	FSTPQ (F6, F7), (State_V+16*6)(R9); \
	FSTPQ (F8, F9), (State_V+16*8)(R9); \
	FSTPQ (F10, F11), (State_V+16*10)(R9); \
	FSTPQ (F12, F13), (State_V+16*12)(R9); \
	FSTPQ (F14, F15), (State_V+16*14)(R9); \
	FSTPQ (F16, F17), (State_V+16*16)(R9); \
	FSTPQ (F18, F19), (State_V+16*18)(R9); \
	FSTPQ (F20, F21), (State_V+16*20)(R9); \
	FSTPQ (F22, F23), (State_V+16*22)(R9); \
	FSTPQ (F24, F25), (State_V+16*24)(R9); \
	FSTPQ (F26, F27), (State_V+16*26)(R9); \
	FSTPQ (F28, F29), (State_V+16*28)(R9); \
	FSTPQ (F30, F31), (State_V+16*30)(R9)

// ENTER points X9 to the input State and saves these items in the frame: the
// registers that the caller expects (the g register X28, the platform register
// X18, X29, and X30), the FP control state, and the output address. It stores
// SP in the input State. The Go compiler does not reload X28 after a call to
// assembly.
#define ENTER \
	MOVD in+0(FP), R9; \
	MOVD out+8(FP), R10; \
	SUB  $const_frameSize, RSP; \
	MOVD R29, const_slotFP(RSP); \
	MOVD R30, const_slotLR(RSP); \
	MOVD R10, const_slotOut(RSP); \
	MOVD RSP, R10; \
	STRX(10, State_SP); \
	MRS_FPCR(10); \
	STRSP(10, const_slotFPCR); \
	MRS_FPSR(10); \
	STRSP(10, const_slotFPSR); \
	STRSP(28, const_slotG); \
	STRSP(18, const_slotPlatform)

// LEAVE restores the FP control state and the registers of the caller.
#define LEAVE \
	LDRSP(10, const_slotFPCR); \
	MSR_FPCR(10); \
	LDRSP(10, const_slotFPSR); \
	MSR_FPSR(10); \
	LDRSP(28, const_slotG); \
	LDRSP(18, const_slotPlatform); \
	MOVD const_slotFP(RSP), R29; \
	MOVD const_slotLR(RSP), R30; \
	ADD  $const_frameSize, RSP; \
	RET

// func runSyscall(in, out *State)
TEXT ·runSyscall(SB), NOSPLIT|NOFRAME, $0-16
	ENTER
	LOAD_CTL_VEC
	LOAD_X
	LOAD_X30
	LOAD_X9
	SVC $0
	STORE_STATE
	LEAVE

// func runSpin(in, out *State)
TEXT ·runSpin(SB), NOSPLIT|NOFRAME, $0-16
	ENTER
	LOAD_CTL_VEC
	LOAD_X
	LOAD_X30
	LOAD_X9
spin:
	MOVD  $·spinFlag(SB), R0
	MOVWU (R0), R0
	CBZW  R0, spin
	STORE_STATE
	LEAVE

// func runFault(in, out *State)
TEXT ·runFault(SB), NOSPLIT|NOFRAME, $0-16
	ENTER
	LOAD_CTL_VEC
	LOAD_X
	LOAD_X30
	LOAD_X9
	MOVD ZR, (R1)
	STORE_STATE
	LEAVE

// EDIT_FRAME writes the State at R13 into the ucontext at R10: X1 to X30, FPSR,
// FPCR, and V0 to V31. It leaves X0, SP, and PC alone. The loop of runSpin uses
// X0 as a pointer between two instructions, so a changed X0 would make it fault.
#define EDIT_FRAME \
	MOVD (State_X+8*1)(R13), R4; \
	MOVD R4, (const_ucRegs+8*1)(R10); \
	LDP (State_X+8*2)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*2)(R10); \
	LDP (State_X+8*4)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*4)(R10); \
	LDP (State_X+8*6)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*6)(R10); \
	LDP (State_X+8*8)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*8)(R10); \
	LDP (State_X+8*10)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*10)(R10); \
	LDP (State_X+8*12)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*12)(R10); \
	LDP (State_X+8*14)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*14)(R10); \
	LDP (State_X+8*16)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*16)(R10); \
	LDP (State_X+8*18)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*18)(R10); \
	LDP (State_X+8*20)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*20)(R10); \
	LDP (State_X+8*22)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*22)(R10); \
	LDP (State_X+8*24)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*24)(R10); \
	LDP (State_X+8*26)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*26)(R10); \
	LDP (State_X+8*28)(R13), (R4, R5); \
	STP (R4, R5), (const_ucRegs+8*28)(R10); \
	MOVD (State_X+8*30)(R13), R4; \
	MOVD R4, (const_ucRegs+8*30)(R10); \
	MOVWU State_FPSR(R13), R4; \
	MOVW R4, (const_ucFpsimd+const_fpsimdFPSR)(R10); \
	MOVWU State_FPCR(R13), R4; \
	MOVW R4, (const_ucFpsimd+const_fpsimdFPCR)(R10); \
	FLDPQ (State_V+16*0)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*0)(R10); \
	FLDPQ (State_V+16*2)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*2)(R10); \
	FLDPQ (State_V+16*4)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*4)(R10); \
	FLDPQ (State_V+16*6)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*6)(R10); \
	FLDPQ (State_V+16*8)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*8)(R10); \
	FLDPQ (State_V+16*10)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*10)(R10); \
	FLDPQ (State_V+16*12)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*12)(R10); \
	FLDPQ (State_V+16*14)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*14)(R10); \
	FLDPQ (State_V+16*16)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*16)(R10); \
	FLDPQ (State_V+16*18)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*18)(R10); \
	FLDPQ (State_V+16*20)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*20)(R10); \
	FLDPQ (State_V+16*22)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*22)(R10); \
	FLDPQ (State_V+16*24)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*24)(R10); \
	FLDPQ (State_V+16*26)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*26)(R10); \
	FLDPQ (State_V+16*28)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*28)(R10); \
	FLDPQ (State_V+16*30)(R13), (F0, F1); \
	FSTPQ (F0, F1), (const_ucFpsimd+const_fpsimdVregs+16*30)(R10)

// func evilHandler()
// The kernel calls the handler with R0 = signal, R1 = siginfo, R2 = ucontext,
// and R30 = the return address of the sigreturn trampoline. The handler does
// not load R30.
TEXT ·evilHandler(SB), NOSPLIT|NOFRAME, $0-0
	MOVD  R0, R11 // signal
	MOVD  R1, R9  // siginfo
	MOVD  R2, R10 // ucontext
	MOVD  $·handlerMode(SB), R3
	MOVWU (R3), R12
	MOVD  $·sigCount(SB), R3
	MOVWU (R3), R4
	ADD   $1, R4
	MOVW  R4, (R3)
	MOVD  $·spinFlag(SB), R3
	MOVWU (R3), R4
	MOVD  $·flagSeen(SB), R3
	MOVW  R4, (R3)
	TST   $const_ModeCapture, R12
	BEQ   nocapture
	MOVD  $·captured(SB), R8
	MOVD  R11, capture_Sig(R8)
	MOVD  R10, capture_UCAddr(R8)
	ADD   $capture_Info, R8, R3
	MOVD  R9, R1
	MOVD  $(const_siBytes/16), R6
infocopy:
	LDP.P 16(R1), (R4, R5)
	STP.P (R4, R5), 16(R3)
	SUBS  $1, R6
	BNE   infocopy
	ADD   $capture_UC, R8, R3
	MOVD  R10, R1
	MOVD  $(const_ucBytes/16), R6
uccopy:
	LDP.P 16(R1), (R4, R5)
	STP.P (R4, R5), 16(R3)
	SUBS  $1, R6
	BNE   uccopy
nocapture:
	TST   $const_ModeEdit, R12
	BEQ   noedit
	MOVD  $·editState(SB), R13
	EDIT_FRAME
noedit:
	CMP   $11, R11 // SIGSEGV
	BNE   trash
	TST   $const_ModeSkipFault, R12
	BEQ   fixpage
	MOVD  $·sigCount(SB), R3
	MOVWU (R3), R4
	CMP   $1, R4
	BHI   fixpage
	MOVD  const_ucPC(R10), R4
	ADD   $const_faultInsnLen, R4
	MOVD  R4, const_ucPC(R10)
	B     trash
fixpage:
	// A second SIGSEGV means that the first fix did not help. End the program,
	// so that the run does not loop for ever.
	MOVD  $·sigCount(SB), R3
	MOVWU (R3), R4
	CMP   $1, R4
	BHI   die
	// Make the page of si_addr writable so that the faulting store succeeds.
	MOVD  const_siAddr(R9), R0
	MOVD  $·pageMask(SB), R3
	MOVD  (R3), R3
	AND   R3, R0
	MOVD  $·pageSize(SB), R3
	MOVD  (R3), R1
	MOVD  $3, R2 // PROT_READ|PROT_WRITE
	MOVD  $226, R8 // mprotect
	SVC   $0
trash:
	MOVD $·trashState(SB), R9
	LOAD_CTL_VEC
	LOAD_X
	LOAD_X9
	RET
die:
	MOVD $94, R8 // exit_group
	MOVD $2, R0
	SVC  $0

// func handlerPC() uintptr
TEXT ·handlerPC(SB), NOSPLIT|NOFRAME, $0-8
	MOVD $·evilHandler(SB), R0
	MOVD R0, ret+0(FP)
	RET

// func runClone(in, out *State)
// The parent and the child load the same registers. The parent stores its
// registers in out. The child, which has the stack of a ChildStack, stores its
// registers in the State that its stack names, or calls execve when its stack
// holds the arguments, and then exits.
TEXT ·runClone(SB), NOSPLIT|NOFRAME, $0-16
	ENTER
	MOVD ZR, const_slotChild(RSP)
	LOAD_CTL_VEC
	LOAD_X
	LOAD_X30
	LOAD_X9
	SVC  $0
	CBNZ R0, store
	STRSP(10, const_slotStash)
	LDRSP(10, const_slotExecPath)
	CBNZ R10, doexec
	MOVD $1, R10
	STRSP(10, const_slotChild)
	LDRSP(10, const_slotStash)
store:
	STORE_STATE
	LDRSP(10, const_slotChild)
	CBNZ R10, childexit
	LEAVE
childexit:
	MOVD $93, R8 // exit
	MOVD $0, R0
	SVC  $0
	WORD $0xd4200000 // BRK #0
doexec:
	LDRSP(0, const_slotExecPath)
	LDRSP(1, const_slotExecArgv)
	LDRSP(2, const_slotExecEnvp)
	MOVD $221, R8 // execve
	SVC  $0
	MOVD $93, R8 // exit
	MOVD $127, R0
	SVC  $0
	WORD $0xd4200000 // BRK #0

// func ReadControl() (fpcr, fpsr uint64)
TEXT ·ReadControl(SB), NOSPLIT|NOFRAME, $0-16
	MRS_FPCR(0)
	MOVD R0, fpcr+0(FP)
	MRS_FPSR(0)
	MOVD R0, fpsr+8(FP)
	RET
