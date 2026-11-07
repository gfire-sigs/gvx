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

// func evilHandler()
// The kernel calls the handler with R0 = signal, R1 = siginfo, R2 = ucontext,
// and R30 = the return address of the sigreturn trampoline. The handler does
// not load R30.
TEXT ·evilHandler(SB), NOSPLIT|NOFRAME, $0-0
	MOVD  $·sigCount(SB), R3
	MOVWU (R3), R4
	ADD   $1, R4
	MOVW  R4, (R3)
	MOVD  $·spinFlag(SB), R3
	MOVWU (R3), R4
	MOVD  $·flagSeen(SB), R3
	MOVW  R4, (R3)
	CMP   $11, R0 // SIGSEGV
	BNE   trash
	// A second SIGSEGV means that the first fix did not help. End the program,
	// so that the run does not loop for ever.
	MOVD  $·sigCount(SB), R3
	MOVWU (R3), R4
	CMP   $1, R4
	BHI   die
	// Make the page of si_addr writable so that the faulting store succeeds.
	MOVD  16(R1), R0
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
