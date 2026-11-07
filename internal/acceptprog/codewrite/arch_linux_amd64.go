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

package main

import (
	"encoding/binary"
)

// The machine code of the checks. Each function follows its own convention: it
// leaves its result in eax and takes one pointer in rdi.

const (
	sysMemfdCreate     = 319
	sysProcessVMWritev = 311

	// slotOff is the offset of the data word that the counter code writes.
	slotOff = 0x800
	// patchOff is the offset of the instruction that the alias code patches.
	patchOff = 0x800
)

// codeReturn returns code for a function that returns n.
func codeReturn(n uint32) []byte {
	c := binary.LittleEndian.AppendUint32([]byte{0xb8}, n) // mov eax, n
	return append(c, 0xc3)                                 // ret
}

// codeSyscall returns code for a function that calls getpid and returns the
// result plus n. The code holds a SYSCALL instruction, which an engine can
// patch.
func codeSyscall(n uint32) []byte {
	c := []byte{0xb8, 39, 0, 0, 0, 0x0f, 0x05, 0x05} // mov eax, 39; syscall; add eax, imm32
	c = binary.LittleEndian.AppendUint32(c, n)
	return append(c, 0xc3) // ret
}

// codeSelfPatch returns code that writes 42 into the immediate of the next
// instruction and runs it. The unpatched instruction returns 1.
func codeSelfPatch() []byte {
	return []byte{
		0xc6, 0x05, 0x01, 0x00, 0x00, 0x00, 0x2a, // mov byte [rip+1], 42
		0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
		0xc3, // ret
	}
}

// codeCounter returns code that stores 100 down to 1 in a word of its own page
// at slotOff and returns the last value that it stored.
func codeCounter() []byte {
	c := []byte{0xb9, 100, 0, 0, 0} // mov ecx, 100
	c = append(c, 0x89, 0x0d)       // loop: mov [rip+disp32], ecx
	c = binary.LittleEndian.AppendUint32(c, slotOff-11)
	c = append(c, 0xff, 0xc9, 0x75, 0xf6) // dec ecx; jnz loop
	c = append(c, 0x8b, 0x05)             // mov eax, [rip+disp32]
	c = binary.LittleEndian.AppendUint32(c, slotOff-21)
	return append(c, 0xc3)
}

// codeAliasPatch returns code for a page that runs through one view and
// receives the address of another view of the same frame in rdi. It stores 42
// through that view into the immediate of the instruction at patchOff, jumps
// there, and returns the result.
func codeAliasPatch() []byte {
	page := make([]byte, patchOff+6)
	c := []byte{0xc6, 0x87} // mov byte [rdi+disp32], 42
	c = binary.LittleEndian.AppendUint32(c, patchOff+1)
	c = append(c, 0x2a, 0xe9) // jmp patchOff
	c = binary.LittleEndian.AppendUint32(c, patchOff-12)
	copy(page, c)
	copy(page[patchOff:], []byte{0xb8, 0x01, 0, 0, 0, 0xc3}) // mov eax, 1; ret
	return page
}

// syncICache has nothing to do on amd64, where instruction fetches see stores.
func syncICache(uintptr, int) {}

func callCode(fn, arg uintptr) uint32
func storeByte(addr uintptr, v byte)
