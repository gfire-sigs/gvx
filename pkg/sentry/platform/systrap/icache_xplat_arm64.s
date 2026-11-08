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

//go:build linux

#include "textflag.h"

// func flushICache(addr, length uintptr)
//
// Cleans the D-cache to the point of unification and invalidates the I-cache
// for [addr, addr+length), with the line sizes of CTR_EL0. The maintenance
// acts on the physical memory behind addr, so it also covers another virtual
// mapping of the same memory, such as the stub mapping of a composite page.
TEXT ·flushICache(SB),NOSPLIT,$0-16
	MOVD	addr+0(FP), R0
	MOVD	length+8(FP), R1
	ADD	R0, R1, R1
	MRS	CTR_EL0, R3

	UBFX	$16, R3, $4, R4
	MOVD	$4, R5
	LSL	R4, R5, R4
	SUB	$1, R4, R5
	BIC	R5, R0, R2
dc_loop:
	CMP	R1, R2
	BHS	dc_done
	WORD	$0xd50b7b22	// DC CVAU, R2
	ADD	R4, R2, R2
	B	dc_loop
dc_done:
	DSB	$11		// DSB ISH

	AND	$15, R3, R4
	MOVD	$4, R5
	LSL	R4, R5, R4
	SUB	$1, R4, R5
	BIC	R5, R0, R2
ic_loop:
	CMP	R1, R2
	BHS	ic_done
	WORD	$0xd50b7522	// IC IVAU, R2
	ADD	R4, R2, R2
	B	ic_loop
ic_done:
	DSB	$11		// DSB ISH
	ISB	$15		// ISB SY
	RET
