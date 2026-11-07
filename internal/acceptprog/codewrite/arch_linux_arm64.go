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

package main

import "encoding/binary"

// The machine code of the checks. Each function follows its own convention: it
// leaves its result in w0 and takes one pointer in x0.

const (
	sysMemfdCreate     = 279
	sysProcessVMWritev = 271

	// slotOff is the offset of the data word that the counter code writes.
	slotOff = 0x800
	// patchOff is the offset of the instruction that the alias code patches.
	patchOff = 0x800
)

const (
	insnRet       = 0xd65f03c0
	insnDSBISH    = 0xd5033b9f
	insnISB       = 0xd5033fdf
	insnMovzW0x1  = 0x52800020 // movz w0, #1
	insnMovzW0x2A = 0x52800540 // movz w0, #42
)

func words(ws ...uint32) []byte {
	b := make([]byte, 0, 4*len(ws))
	for _, w := range ws {
		b = binary.LittleEndian.AppendUint32(b, w)
	}
	return b
}

// codeReturn returns code for a function that returns n, below 65536.
func codeReturn(n uint32) []byte {
	return words(0x52800000|n<<5, insnRet)
}

// codeSyscall returns code for a function that calls getpid and returns the
// result plus n, which must not exceed maxCodeVersion. The code holds an SVC instruction,
// which an engine can patch.
func codeSyscall(n uint32) []byte {
	if n > maxCodeVersion {
		panic("codeSyscall: the version does not fit the immediate of ADD")
	}
	return words(
		0xd2801588,       // movz x8, #172 (getpid)
		0xd4000001,       // svc #0
		0x11000000|n<<10, // add w0, w0, #n
		insnRet,
	)
}

// codeSelfPatch returns code that writes the instruction `movz w0, #42` over
// the instruction at offset 36, cleans the caches, and runs it. The unpatched
// instruction returns 1.
func codeSelfPatch() []byte {
	return words(
		0x10000121, // adr x1, #36
		0x5280a802, // movz w2, #0x0540
		0x72aa5002, // movk w2, #0x5280, lsl #16
		0xb9000022, // str w2, [x1]
		0xd50b7b21, // dc cvau, x1
		insnDSBISH,
		0xd50b7521, // ic ivau, x1
		insnDSBISH,
		insnISB,
		insnMovzW0x1, // patched
		insnRet,
	)
}

// codeCounter returns code that stores 100 down to 1 in a word of its own page
// at slotOff and returns the last value that it stored.
func codeCounter() []byte {
	return words(
		0x10004001, // adr x1, #0x800
		0x52800c82, // movz w2, #100
		0xb9000022, // loop: str w2, [x1]
		0x71000442, // subs w2, w2, #1
		0x54ffffc1, // b.ne loop
		0xb9400020, // ldr w0, [x1]
		insnRet,
	)
}

// codeAliasPatch returns code for a page that runs through one view and
// receives the address of another view of the same frame in x0. It stores the
// instruction `movz w0, #42` through that view over the instruction at
// patchOff, cleans the caches, jumps there, and returns the result.
func codeAliasPatch() []byte {
	page := make([]byte, patchOff+8)
	copy(page, words(
		0x5280a802, // movz w2, #0x0540
		0x72aa5002, // movk w2, #0x5280, lsl #16
		0x91200003, // add x3, x0, #0x800
		0xb9000062, // str w2, [x3]
		0xd50b7b23, // dc cvau, x3
		insnDSBISH,
		0x10003f44, // adr x4, #2024
		0xd50b7524, // ic ivau, x4
		insnDSBISH,
		insnISB,
		0x140001f6, // b #2008
	))
	copy(page[patchOff:], words(insnMovzW0x1, insnRet))
	return page
}

// syncICache makes the instruction fetches of the program see the stores to
// [addr, addr+n), as a JIT compiler does after it writes code.
func syncICache(addr uintptr, n int) {
	for p := addr &^ 63; p < addr+uintptr(n); p += 64 {
		flushLine(p)
	}
}

func flushLine(addr uintptr)
func callCode(fn, arg uintptr) uint32
func storeByte(addr uintptr, v byte)
