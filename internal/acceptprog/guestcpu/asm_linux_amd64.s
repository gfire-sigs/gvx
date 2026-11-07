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

//go:build linux && amd64

#include "textflag.h"
#include "go_asm.h"

#define GPR(r) (State_GPR+8*(r))
#define VEC(i) (State_Vec+32*(i))

// LOAD_STATE loads every register from the State at R15. It loads R15 last.
#define LOAD_STATE \
	LDMXCSR State_MXCSR(R15); \
	FLDCW State_FCW(R15); \
	CMPB ·hasAVX(SB), $0; \
	JEQ loadsse; \
	VMOVDQU VEC(0)(R15), Y0; \
	VMOVDQU VEC(1)(R15), Y1; \
	VMOVDQU VEC(2)(R15), Y2; \
	VMOVDQU VEC(3)(R15), Y3; \
	VMOVDQU VEC(4)(R15), Y4; \
	VMOVDQU VEC(5)(R15), Y5; \
	VMOVDQU VEC(6)(R15), Y6; \
	VMOVDQU VEC(7)(R15), Y7; \
	VMOVDQU VEC(8)(R15), Y8; \
	VMOVDQU VEC(9)(R15), Y9; \
	VMOVDQU VEC(10)(R15), Y10; \
	VMOVDQU VEC(11)(R15), Y11; \
	VMOVDQU VEC(12)(R15), Y12; \
	VMOVDQU VEC(13)(R15), Y13; \
	VMOVDQU VEC(14)(R15), Y14; \
	VMOVDQU VEC(15)(R15), Y15; \
	JMP loadvecdone; \
	loadsse:; \
	MOVOU VEC(0)(R15), X0; \
	MOVOU VEC(1)(R15), X1; \
	MOVOU VEC(2)(R15), X2; \
	MOVOU VEC(3)(R15), X3; \
	MOVOU VEC(4)(R15), X4; \
	MOVOU VEC(5)(R15), X5; \
	MOVOU VEC(6)(R15), X6; \
	MOVOU VEC(7)(R15), X7; \
	MOVOU VEC(8)(R15), X8; \
	MOVOU VEC(9)(R15), X9; \
	MOVOU VEC(10)(R15), X10; \
	MOVOU VEC(11)(R15), X11; \
	MOVOU VEC(12)(R15), X12; \
	MOVOU VEC(13)(R15), X13; \
	MOVOU VEC(14)(R15), X14; \
	MOVOU VEC(15)(R15), X15; \
	loadvecdone:; \
	MOVQ GPR(const_RAX)(R15), AX; \
	MOVQ GPR(const_RBX)(R15), BX; \
	MOVQ GPR(const_RCX)(R15), CX; \
	MOVQ GPR(const_RDX)(R15), DX; \
	MOVQ GPR(const_RSI)(R15), SI; \
	MOVQ GPR(const_RDI)(R15), DI; \
	MOVQ GPR(const_RBP)(R15), BP; \
	MOVQ GPR(const_R8)(R15), R8; \
	MOVQ GPR(const_R9)(R15), R9; \
	MOVQ GPR(const_R10)(R15), R10; \
	MOVQ GPR(const_R11)(R15), R11; \
	MOVQ GPR(const_R12)(R15), R12; \
	MOVQ GPR(const_R13)(R15), R13; \
	MOVQ GPR(const_R14)(R15), R14; \
	MOVQ GPR(const_R15)(R15), R15

// STORE_STATE stores every register to the output State. The output address
// is in the slot const_slotOut of the frame, and the macro puts the value of
// R15 in that slot.
#define STORE_STATE \
	XCHGQ R15, const_slotOut(SP); \
	MOVQ AX, GPR(const_RAX)(R15); \
	MOVQ BX, GPR(const_RBX)(R15); \
	MOVQ CX, GPR(const_RCX)(R15); \
	MOVQ DX, GPR(const_RDX)(R15); \
	MOVQ SI, GPR(const_RSI)(R15); \
	MOVQ DI, GPR(const_RDI)(R15); \
	MOVQ BP, GPR(const_RBP)(R15); \
	MOVQ R8, GPR(const_R8)(R15); \
	MOVQ R9, GPR(const_R9)(R15); \
	MOVQ R10, GPR(const_R10)(R15); \
	MOVQ R11, GPR(const_R11)(R15); \
	MOVQ R12, GPR(const_R12)(R15); \
	MOVQ R13, GPR(const_R13)(R15); \
	MOVQ R14, GPR(const_R14)(R15); \
	MOVQ SP, State_RSP(R15); \
	MOVQ const_slotOut(SP), AX; \
	MOVQ AX, GPR(const_R15)(R15); \
	STMXCSR State_MXCSR(R15); \
	FSTCW State_FCW(R15); \
	CMPB ·hasAVX(SB), $0; \
	JEQ storesse; \
	VMOVDQU Y0, VEC(0)(R15); \
	VMOVDQU Y1, VEC(1)(R15); \
	VMOVDQU Y2, VEC(2)(R15); \
	VMOVDQU Y3, VEC(3)(R15); \
	VMOVDQU Y4, VEC(4)(R15); \
	VMOVDQU Y5, VEC(5)(R15); \
	VMOVDQU Y6, VEC(6)(R15); \
	VMOVDQU Y7, VEC(7)(R15); \
	VMOVDQU Y8, VEC(8)(R15); \
	VMOVDQU Y9, VEC(9)(R15); \
	VMOVDQU Y10, VEC(10)(R15); \
	VMOVDQU Y11, VEC(11)(R15); \
	VMOVDQU Y12, VEC(12)(R15); \
	VMOVDQU Y13, VEC(13)(R15); \
	VMOVDQU Y14, VEC(14)(R15); \
	VMOVDQU Y15, VEC(15)(R15); \
	JMP storevecdone; \
	storesse:; \
	MOVOU X0, VEC(0)(R15); \
	MOVOU X1, VEC(1)(R15); \
	MOVOU X2, VEC(2)(R15); \
	MOVOU X3, VEC(3)(R15); \
	MOVOU X4, VEC(4)(R15); \
	MOVOU X5, VEC(5)(R15); \
	MOVOU X6, VEC(6)(R15); \
	MOVOU X7, VEC(7)(R15); \
	MOVOU X8, VEC(8)(R15); \
	MOVOU X9, VEC(9)(R15); \
	MOVOU X10, VEC(10)(R15); \
	MOVOU X11, VEC(11)(R15); \
	MOVOU X12, VEC(12)(R15); \
	MOVOU X13, VEC(13)(R15); \
	MOVOU X14, VEC(14)(R15); \
	MOVOU X15, VEC(15)(R15); \
	storevecdone:

// ENTER saves the FP control state and the output address in the frame, points
// R15 to the input State, and stores RSP in it.
#define ENTER \
	STMXCSR const_slotCtl(SP); \
	FSTCW (const_slotCtl+4)(SP); \
	MOVQ out+8(FP), AX; \
	MOVQ AX, const_slotOut(SP); \
	MOVQ in+0(FP), R15; \
	MOVQ SP, State_RSP(R15)

// LEAVE restores the FP control state and returns.
#define LEAVE \
	LDMXCSR const_slotCtl(SP); \
	FLDCW (const_slotCtl+4)(SP); \
	CMPB ·hasAVX(SB), $0; \
	JEQ leavedone; \
	VZEROUPPER; \
leavedone: \
	RET

// func runSyscall(in, out *State)
TEXT ·runSyscall(SB), NOSPLIT, $const_frameSize-16
	ENTER
	LOAD_STATE
	SYSCALL
	STORE_STATE
	LEAVE

// func runSpin(in, out *State)
TEXT ·runSpin(SB), NOSPLIT, $const_frameSize-16
	ENTER
	LOAD_STATE
spin:
	PAUSE
	CMPL ·spinFlag(SB), $0
	JEQ  spin
	STORE_STATE
	LEAVE

// func runFault(in, out *State)
TEXT ·runFault(SB), NOSPLIT, $const_frameSize-16
	ENTER
	LOAD_STATE
	// MOVQ $0, (SI) with a fixed length of const_faultInsnLen bytes.
	BYTE $0x48; BYTE $0xc7; BYTE $0x06; LONG $0
	STORE_STATE
	LEAVE

// EDIT_FRAME writes the State at R13 into the frame: the ucontext at R9 and
// the xsave area that its fpstate field names. It leaves RSP and RIP alone.
#define EDIT_FRAME \
	MOVQ GPR(const_RAX)(R13), AX; \
	MOVQ AX, const_ucRAX(R9); \
	MOVQ GPR(const_RBX)(R13), AX; \
	MOVQ AX, const_ucRBX(R9); \
	MOVQ GPR(const_RCX)(R13), AX; \
	MOVQ AX, const_ucRCX(R9); \
	MOVQ GPR(const_RDX)(R13), AX; \
	MOVQ AX, const_ucRDX(R9); \
	MOVQ GPR(const_RSI)(R13), AX; \
	MOVQ AX, const_ucRSI(R9); \
	MOVQ GPR(const_RDI)(R13), AX; \
	MOVQ AX, const_ucRDI(R9); \
	MOVQ GPR(const_RBP)(R13), AX; \
	MOVQ AX, const_ucRBP(R9); \
	MOVQ GPR(const_R8)(R13), AX; \
	MOVQ AX, const_ucR8(R9); \
	MOVQ GPR(const_R9)(R13), AX; \
	MOVQ AX, const_ucR9(R9); \
	MOVQ GPR(const_R10)(R13), AX; \
	MOVQ AX, const_ucR10(R9); \
	MOVQ GPR(const_R11)(R13), AX; \
	MOVQ AX, const_ucR11(R9); \
	MOVQ GPR(const_R12)(R13), AX; \
	MOVQ AX, const_ucR12(R9); \
	MOVQ GPR(const_R13)(R13), AX; \
	MOVQ AX, const_ucR13(R9); \
	MOVQ GPR(const_R14)(R13), AX; \
	MOVQ AX, const_ucR14(R9); \
	MOVQ GPR(const_R15)(R13), AX; \
	MOVQ AX, const_ucR15(R9); \
	MOVQ const_ucFpstate(R9), R14; \
	MOVOU VEC(0)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*0)(R14); \
	MOVOU VEC(1)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*1)(R14); \
	MOVOU VEC(2)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*2)(R14); \
	MOVOU VEC(3)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*3)(R14); \
	MOVOU VEC(4)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*4)(R14); \
	MOVOU VEC(5)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*5)(R14); \
	MOVOU VEC(6)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*6)(R14); \
	MOVOU VEC(7)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*7)(R14); \
	MOVOU VEC(8)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*8)(R14); \
	MOVOU VEC(9)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*9)(R14); \
	MOVOU VEC(10)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*10)(R14); \
	MOVOU VEC(11)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*11)(R14); \
	MOVOU VEC(12)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*12)(R14); \
	MOVOU VEC(13)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*13)(R14); \
	MOVOU VEC(14)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*14)(R14); \
	MOVOU VEC(15)(R13), X0; \
	MOVOU X0, (const_fpXMM+16*15)(R14); \
	CMPB ·hasAVX(SB), $0; \
	JEQ editnoymm; \
	MOVOU (VEC(0)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*0)(R14); \
	MOVOU (VEC(1)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*1)(R14); \
	MOVOU (VEC(2)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*2)(R14); \
	MOVOU (VEC(3)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*3)(R14); \
	MOVOU (VEC(4)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*4)(R14); \
	MOVOU (VEC(5)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*5)(R14); \
	MOVOU (VEC(6)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*6)(R14); \
	MOVOU (VEC(7)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*7)(R14); \
	MOVOU (VEC(8)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*8)(R14); \
	MOVOU (VEC(9)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*9)(R14); \
	MOVOU (VEC(10)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*10)(R14); \
	MOVOU (VEC(11)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*11)(R14); \
	MOVOU (VEC(12)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*12)(R14); \
	MOVOU (VEC(13)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*13)(R14); \
	MOVOU (VEC(14)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*14)(R14); \
	MOVOU (VEC(15)+16)(R13), X0; \
	MOVOU X0, (const_fpYMMHi+16*15)(R14); \
	editnoymm:; \
	MOVL State_MXCSR(R13), AX; \
	MOVL AX, (const_fpMXCSR)(R14); \
	MOVW State_FCW(R13), AX; \
	MOVW AX, (const_fpFCW)(R14)

// func evilHandler()
// The kernel calls the handler with DI = signal, SI = siginfo, DX = ucontext.
TEXT ·evilHandler(SB), NOSPLIT, $0-0
	CLD
	MOVQ DI, R11 // signal
	MOVQ SI, R10 // siginfo
	MOVQ DX, R9  // ucontext
	MOVL ·handlerMode(SB), R12
	INCL ·sigCount(SB)
	MOVL ·spinFlag(SB), AX
	MOVL AX, ·flagSeen(SB)
	TESTL $const_ModeCapture, R12
	JZ    nocapture
	LEAQ  ·captured(SB), R8
	MOVQ  R11, capture_Sig(R8)
	MOVQ  R9, capture_UCAddr(R8)
	MOVQ  R10, SI
	LEAQ  capture_Info(R8), DI
	MOVQ  $(const_siBytes/8), CX
	REP; MOVSQ
	MOVQ  R9, SI
	LEAQ  capture_UC(R8), DI
	MOVQ  $(const_ucBytes/8), CX
	REP; MOVSQ
	MOVQ  const_ucFpstate(R9), SI
	MOVQ  SI, capture_FPAddr(R8)
	TESTQ SI, SI
	JZ    nocapture
	// The software bytes of the xsave area hold its size. Copy that size and
	// the 4 bytes of magic2 behind it, but at most the buffer.
	MOVL  (const_fpSWBytes+16)(SI), CX
	ADDQ  $11, CX
	SHRQ  $3, CX
	CMPQ  CX, $(const_fpMax/8)
	JLS   fpcopy
	MOVQ  $(const_fpMax/8), CX
fpcopy:
	LEAQ  capture_FP(R8), DI
	REP; MOVSQ
nocapture:
	TESTL $const_ModeEdit, R12
	JZ    noedit
	LEAQ  ·editState(SB), R13
	EDIT_FRAME
noedit:
	CMPQ R11, $11 // SIGSEGV
	JNE  trash
	TESTL $const_ModeSkipFault, R12
	JZ    fixpage
	CMPL ·sigCount(SB), $1
	JHI  fixpage
	ADDQ $const_faultInsnLen, const_ucRIP(R9)
	JMP  trash
fixpage:
	// A second SIGSEGV means that the first fix did not help. End the program,
	// so that the run does not loop for ever.
	CMPL ·sigCount(SB), $1
	JHI  die
	// Make the page of si_addr writable so that the faulting store succeeds.
	MOVQ const_siAddr(R10), DI
	ANDQ ·pageMask(SB), DI
	MOVQ ·pageSize(SB), SI
	MOVQ $3, DX // PROT_READ|PROT_WRITE
	MOVL $10, AX // mprotect
	SYSCALL
trash:
	MOVQ $·trashState(SB), R15
	LOAD_STATE
	RET
die:
	MOVL $231, AX // exit_group
	MOVL $2, DI
	SYSCALL

// func handlerPC() uintptr
TEXT ·handlerPC(SB), NOSPLIT, $0-8
	LEAQ ·evilHandler(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// func restorerPC() uintptr
TEXT ·restorerPC(SB), NOSPLIT, $0-8
	LEAQ ·sigreturn(SB), AX
	MOVQ AX, ret+0(FP)
	RET

// func sigreturn()
// The kernel returns to this code when evilHandler returns.
TEXT ·sigreturn(SB), NOSPLIT, $0-0
	MOVL $15, AX // rt_sigreturn
	SYSCALL
	INT  $3

// func cpuid(leaf, sub uint32) (eax, ebx, ecx, edx uint32)
TEXT ·cpuid(SB), NOSPLIT, $0-24
	MOVL leaf+0(FP), AX
	MOVL sub+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

// func xgetbv() uint32
TEXT ·xgetbv(SB), NOSPLIT, $0-4
	XORL CX, CX
	XGETBV
	MOVL AX, ret+0(FP)
	RET
