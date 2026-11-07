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

#include "textflag.h"

// func flushLine(addr uintptr)
TEXT ·flushLine(SB), NOSPLIT, $0-8
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

// func callCode(fn, arg uintptr) uint32
TEXT ·callCode(SB), NOSPLIT, $0-20
	MOVD fn+0(FP), R1
	MOVD arg+8(FP), R0
	CALL (R1)
	MOVW R0, ret+16(FP)
	RET

// func storeByte(addr uintptr, v byte)
// storeByte stores v at addr without a load.
TEXT ·storeByte(SB), NOSPLIT, $0-9
	MOVD  addr+0(FP), R0
	MOVBU v+8(FP), R1
	MOVB  R1, (R0)
	RET
