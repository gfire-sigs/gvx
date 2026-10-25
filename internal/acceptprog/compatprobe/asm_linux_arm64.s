#include "textflag.h"

// func asmReadSysRegsARM64() (midr, pfr0, isar0, mmfr0, ctr, dczid, cntvct, tpidr uint64)
TEXT ·asmReadSysRegsARM64(SB), NOSPLIT, $0-64
	// mrs x0, midr_el1
	WORD $0xd5380000
	MOVD R0, midr+0(FP)
	// mrs x0, id_aa64pfr0_el1
	WORD $0xd5380400
	MOVD R0, pfr0+8(FP)
	// mrs x0, id_aa64isar0_el1
	WORD $0xd5380600
	MOVD R0, isar0+16(FP)
	// mrs x0, id_aa64mmfr0_el1
	WORD $0xd5380700
	MOVD R0, mmfr0+24(FP)
	// mrs x0, ctr_el0
	WORD $0xd53b0020
	MOVD R0, ctr+32(FP)
	// mrs x0, dczid_el0
	WORD $0xd53b00e0
	MOVD R0, dczid+40(FP)
	// mrs x0, cntvct_el0
	WORD $0xd53be040
	MOVD R0, cntvct+48(FP)
	// mrs x0, tpidr_el0
	WORD $0xd53bd040
	MOVD R0, tpidr+56(FP)
	RET

// func asmProbeX18ARM64(teb, faultPage, writeVal uint64) (selfBefore, pebBefore, selfAfterSVC, tls1AfterFault uint64)
TEXT ·asmProbeX18ARM64(SB), NOSPLIT, $0-56
	MOVD teb+0(FP), R2
	MOVD faultPage+8(FP), R3
	MOVD writeVal+16(FP), R4
	// mov x18, x2
	WORD $0xaa0203f2
	// ldr x5, [x18, #0x30]
	WORD $0xf9401a45
	// ldr x6, [x18, #0x60]
	WORD $0xf9403246
	// str x4, [x18, #0x1480]
	WORD $0xf90a4244
	// ldr x7, [x18, #0x1488]
	WORD $0xf94a4647
	ADD  $0x2a, R7, R7
	// str x7, [x18, #0x1488]
	WORD $0xf90a4647
	MOVD R5, selfBefore+24(FP)
	MOVD R6, pebBefore+32(FP)
	// SYS_getpid (172)
	MOVD $172, R8
	SVC  $0
	// ldr x5, [x18, #0x30]
	WORD $0xf9401a45
	MOVD R5, selfAfterSVC+40(FP)
	// Trigger demand page fault on faultPage while x18 holds teb.
	MOVD $0x55aa55aa, R6
	MOVD R6, (R3)
	// ldr x7, [x18, #0x1488]
	WORD $0xf94a4647
	MOVD R7, tls1AfterFault+48(FP)
	RET

// func asmSetTPIDRARM64(val uint64)
TEXT ·asmSetTPIDRARM64(SB), NOSPLIT, $0-8
	MOVD val+0(FP), R0
	// msr tpidr_el0, x0
	WORD $0xd51bd040
	RET

// func asmSetX18ARM64(val uint64)
TEXT ·asmSetX18ARM64(SB), NOSPLIT, $0-8
	MOVD val+0(FP), R0
	// mov x18, x0
	WORD $0xaa0003f2
	RET

// func asmReadX18ARM64() uint64
TEXT ·asmReadX18ARM64(SB), NOSPLIT, $0-8
	// mov x0, x18
	WORD $0xaa1203e0
	MOVD R0, ret+0(FP)
	RET

// func asmBenchTEBARM64(teb uint64, iters int) uint64
TEXT ·asmBenchTEBARM64(SB), NOSPLIT, $0-24
	MOVD teb+0(FP), R2
	// mov x18, x2
	WORD $0xaa0203f2
	MOVD iters+8(FP), R1
	MOVD $0, R3
loop:
	// ldr x4, [x18, #0x30]
	WORD $0xf9401a44
	ADD  R4, R3, R3
	SUBS $1, R1, R1
	BNE  loop
	MOVD R3, ret+16(FP)
	RET

// func asmProbeSIMDARM64(in, out *[32][2]uint64, faultPage uint64)
TEXT ·asmProbeSIMDARM64(SB), NOSPLIT, $0-24
	MOVD in+0(FP), R0
	FLDPQ 0(R0), (F0, F1)
	FLDPQ 32(R0), (F2, F3)
	FLDPQ 64(R0), (F4, F5)
	FLDPQ 96(R0), (F6, F7)
	FLDPQ 128(R0), (F8, F9)
	FLDPQ 160(R0), (F10, F11)
	FLDPQ 192(R0), (F12, F13)
	FLDPQ 224(R0), (F14, F15)
	FLDPQ 256(R0), (F16, F17)
	FLDPQ 288(R0), (F18, F19)
	FLDPQ 320(R0), (F20, F21)
	FLDPQ 352(R0), (F22, F23)
	FLDPQ 384(R0), (F24, F25)
	FLDPQ 416(R0), (F26, F27)
	FLDPQ 448(R0), (F28, F29)
	FLDPQ 480(R0), (F30, F31)
	// Syscall while V0..V31 are live.
	MOVD $172, R8
	SVC  $0
	// Demand page fault while V0..V31 are live.
	MOVD faultPage+16(FP), R1
	MOVD $0xdeadbeef, R2
	MOVD R2, (R1)
	MOVD out+8(FP), R0
	FSTPQ (F0, F1), 0(R0)
	FSTPQ (F2, F3), 32(R0)
	FSTPQ (F4, F5), 64(R0)
	FSTPQ (F6, F7), 96(R0)
	FSTPQ (F8, F9), 128(R0)
	FSTPQ (F10, F11), 160(R0)
	FSTPQ (F12, F13), 192(R0)
	FSTPQ (F14, F15), 224(R0)
	FSTPQ (F16, F17), 256(R0)
	FSTPQ (F18, F19), 288(R0)
	FSTPQ (F20, F21), 320(R0)
	FSTPQ (F22, F23), 352(R0)
	FSTPQ (F24, F25), 384(R0)
	FSTPQ (F26, F27), 416(R0)
	FSTPQ (F28, F29), 448(R0)
	FSTPQ (F30, F31), 480(R0)
	RET

// func asmCallEntryARM64(fn uintptr, arg, teb uint64) uint64
TEXT ·asmCallEntryARM64(SB), NOSPLIT, $0-32
	MOVD fn+0(FP), R2
	MOVD arg+8(FP), R0
	MOVD teb+16(FP), R3
	// mov x18, x3
	WORD $0xaa0303f2
	CALL (R2)
	MOVD R0, ret+24(FP)
	RET

// func asmFlushICacheARM64(addr uintptr)
TEXT ·asmFlushICacheARM64(SB), NOSPLIT, $0-8
	MOVD addr+0(FP), R0
	// dc cvau, x0
	WORD $0xd50b7b20
	// dsb ish
	WORD $0xd5033b9f
	// ic ivau, x0
	WORD $0xd50b7520
	// dsb ish
	WORD $0xd5033b9f
	// isb
	WORD $0xd5033fdf
	RET
