#include "textflag.h"

// func asmCPUID(leaf, sub uint32) (eax, ebx, ecx, edx uint32)
TEXT ·asmCPUID(SB), NOSPLIT, $0-24
	MOVL leaf+0(FP), AX
	MOVL sub+4(FP), CX
	CPUID
	MOVL AX, eax+8(FP)
	MOVL BX, ebx+12(FP)
	MOVL CX, ecx+16(FP)
	MOVL DX, edx+20(FP)
	RET

// func asmXGETBV0() uint64
TEXT ·asmXGETBV0(SB), NOSPLIT, $0-8
	XORL CX, CX
	// xgetbv
	BYTE $0x0f; BYTE $0x01; BYTE $0xd0
	SHLQ $32, DX
	ORQ  DX, AX
	MOVQ AX, ret+0(FP)
	RET

// func asmProbeYMMAMD64(in, out *[16][4]uint64, faultPage, tid uint64)
TEXT ·asmProbeYMMAMD64(SB), NOSPLIT, $0-32
	MOVQ in+0(FP), DI
	VMOVDQU 0(DI), Y0
	VMOVDQU 32(DI), Y1
	VMOVDQU 64(DI), Y2
	VMOVDQU 96(DI), Y3
	VMOVDQU 128(DI), Y4
	VMOVDQU 160(DI), Y5
	VMOVDQU 192(DI), Y6
	VMOVDQU 224(DI), Y7
	VMOVDQU 256(DI), Y8
	VMOVDQU 288(DI), Y9
	VMOVDQU 320(DI), Y10
	VMOVDQU 352(DI), Y11
	VMOVDQU 384(DI), Y12
	VMOVDQU 416(DI), Y13
	VMOVDQU 448(DI), Y14
	VMOVDQU 480(DI), Y15
	// SYS_getpid (39) while YMM0..YMM15 are live.
	MOVL $39, AX
	SYSCALL
	// Demand page fault while YMM0..YMM15 are live.
	MOVQ faultPage+16(FP), SI
	MOVQ $0xdeadbeef, AX
	MOVQ AX, (SI)
	// SYS_tgkill(getpid(), tid, SIGUSR1): the handler runs on this thread
	// and returns through sigreturn before the next instruction.
	MOVL $39, AX
	SYSCALL
	MOVQ AX, DI
	MOVQ tid+24(FP), SI
	MOVL $10, DX
	MOVL $234, AX
	SYSCALL
	MOVQ out+8(FP), DI
	VMOVDQU Y0, 0(DI)
	VMOVDQU Y1, 32(DI)
	VMOVDQU Y2, 64(DI)
	VMOVDQU Y3, 96(DI)
	VMOVDQU Y4, 128(DI)
	VMOVDQU Y5, 160(DI)
	VMOVDQU Y6, 192(DI)
	VMOVDQU Y7, 224(DI)
	VMOVDQU Y8, 256(DI)
	VMOVDQU Y9, 288(DI)
	VMOVDQU Y10, 320(DI)
	VMOVDQU Y11, 352(DI)
	VMOVDQU Y12, 384(DI)
	VMOVDQU Y13, 416(DI)
	VMOVDQU Y14, 448(DI)
	VMOVDQU Y15, 480(DI)
	VZEROUPPER
	RET

// func asmProbeGSAMD64(faultPage, writeVal uint64) (selfBefore, pebBefore, selfAfterSVC, tls1AfterFault uint64)
TEXT ·asmProbeGSAMD64(SB), NOSPLIT, $0-48
	// mov r8, qword ptr gs:[0x30]
	BYTE $0x65; BYTE $0x4c; BYTE $0x8b; BYTE $0x04; BYTE $0x25; BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
	// mov r9, qword ptr gs:[0x60]
	BYTE $0x65; BYTE $0x4c; BYTE $0x8b; BYTE $0x0c; BYTE $0x25; BYTE $0x60; BYTE $0x00; BYTE $0x00; BYTE $0x00
	MOVQ writeVal+8(FP), R10
	// mov qword ptr gs:[0x1480], r10
	BYTE $0x65; BYTE $0x4c; BYTE $0x89; BYTE $0x14; BYTE $0x25; BYTE $0x80; BYTE $0x14; BYTE $0x00; BYTE $0x00
	// add qword ptr gs:[0x1488], 0x2a
	BYTE $0x65; BYTE $0x48; BYTE $0x83; BYTE $0x04; BYTE $0x25; BYTE $0x88; BYTE $0x14; BYTE $0x00; BYTE $0x00; BYTE $0x2a
	MOVQ R8, selfBefore+16(FP)
	MOVQ R9, pebBefore+24(FP)
	// SYS_getpid (39)
	MOVL $39, AX
	SYSCALL
	// mov r12, qword ptr gs:[0x30]
	BYTE $0x65; BYTE $0x4c; BYTE $0x8b; BYTE $0x24; BYTE $0x25; BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
	MOVQ R12, selfAfterSVC+32(FP)
	// Trigger demand page fault on faultPage.
	MOVQ faultPage+0(FP), SI
	MOVQ $0x55aa55aa, AX
	MOVQ AX, (SI)
	// mov r13, qword ptr gs:[0x1488]
	BYTE $0x65; BYTE $0x4c; BYTE $0x8b; BYTE $0x2c; BYTE $0x25; BYTE $0x88; BYTE $0x14; BYTE $0x00; BYTE $0x00
	MOVQ R13, tls1AfterFault+40(FP)
	RET

// func asmReadGS30AMD64() uint64
TEXT ·asmReadGS30AMD64(SB), NOSPLIT, $0-8
	// mov rax, qword ptr gs:[0x30]
	BYTE $0x65; BYTE $0x48; BYTE $0x8b; BYTE $0x04; BYTE $0x25; BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
	MOVQ AX, ret+0(FP)
	RET

// func asmBenchTEBAMD64(iters int) uint64
TEXT ·asmBenchTEBAMD64(SB), NOSPLIT, $0-16
	MOVQ iters+0(FP), CX
	XORQ DX, DX
loop:
	// mov rax, qword ptr gs:[0x30]
	BYTE $0x65; BYTE $0x48; BYTE $0x8b; BYTE $0x04; BYTE $0x25; BYTE $0x30; BYTE $0x00; BYTE $0x00; BYTE $0x00
	ADDQ AX, DX
	DECQ CX
	JNZ  loop
	MOVQ DX, ret+8(FP)
	RET

// func asmProbeSIMDAMD64(in, out *[16][2]uint64, faultPage uint64)
TEXT ·asmProbeSIMDAMD64(SB), NOSPLIT, $0-24
	MOVQ in+0(FP), DI
	MOVOU 0(DI), X0
	MOVOU 16(DI), X1
	MOVOU 32(DI), X2
	MOVOU 48(DI), X3
	MOVOU 64(DI), X4
	MOVOU 80(DI), X5
	MOVOU 96(DI), X6
	MOVOU 112(DI), X7
	MOVOU 128(DI), X8
	MOVOU 144(DI), X9
	MOVOU 160(DI), X10
	MOVOU 176(DI), X11
	MOVOU 192(DI), X12
	MOVOU 208(DI), X13
	MOVOU 224(DI), X14
	MOVOU 240(DI), X15
	// Syscall while X0..X15 are live.
	MOVL $39, AX
	SYSCALL
	// Demand page fault while X0..X15 are live.
	MOVQ faultPage+16(FP), SI
	MOVQ $0xdeadbeef, AX
	MOVQ AX, (SI)
	MOVQ out+8(FP), DI
	MOVOU X0, 0(DI)
	MOVOU X1, 16(DI)
	MOVOU X2, 32(DI)
	MOVOU X3, 48(DI)
	MOVOU X4, 64(DI)
	MOVOU X5, 80(DI)
	MOVOU X6, 96(DI)
	MOVOU X7, 112(DI)
	MOVOU X8, 128(DI)
	MOVOU X9, 144(DI)
	MOVOU X10, 160(DI)
	MOVOU X11, 176(DI)
	MOVOU X12, 192(DI)
	MOVOU X13, 208(DI)
	MOVOU X14, 224(DI)
	MOVOU X15, 240(DI)
	RET

// func asmCallEntryAMD64(fn uintptr, arg uint64) uint64
TEXT ·asmCallEntryAMD64(SB), NOSPLIT, $0-24
	MOVQ fn+0(FP), AX
	MOVQ arg+8(FP), DI
	MOVQ DI, CX
	SUBQ $40, SP
	CALL AX
	ADDQ $40, SP
	MOVQ AX, ret+16(FP)
	RET
