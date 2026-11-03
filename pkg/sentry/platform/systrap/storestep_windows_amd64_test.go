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

//go:build windows && amd64

package systrap

import (
	"bytes"
	"testing"
)

// TestRepStoreIntoTheExecutingPage fills 256 bytes of the executing page with
// REP STOSB. The instruction does not retire after one step, so the engine
// repeats the step until it closes the window, and then the next store opens a
// new one. Every byte must arrive.
func TestRepStoreIntoTheExecutingPage(t *testing.T) {
	r := newRig(t, newPlatform(t))
	code := imm64([]byte{0x48, 0xBF}, codeVA+0x800)   // mov rdi, codeVA+0x800
	code = append(code, 0xB9, 0x00, 0x01, 0x00, 0x00) // mov ecx, 256
	code = append(code, 0xB0, 0x5A)                   // mov al, 0x5a
	code = append(code, 0xFC, 0xF3, 0xAA)             // cld; rep stosb
	code = append(code, gSyscall(5)...)
	page := r.mapPage(codeVA, rwxAccess, code)
	r.mapStack()
	r.wantCall(5)
	if want := bytes.Repeat([]byte{0x5A}, 256); !bytes.Equal(page[0x800:0x900], want) {
		t.Errorf("the page holds % x at 0x800, want 256 bytes of 0x5a", page[0x800:0x900])
	}
	if page[0x7FF] != 0 || page[0x900] != 0 {
		t.Errorf("the fill reached %#x before and %#x after its range", page[0x7FF], page[0x900])
	}
}

// TestStackInTheExecutingPage points the stack at the page that runs. PUSH and
// CALL store and change the stack pointer in one instruction, and CALL also
// branches.
func TestStackInTheExecutingPage(t *testing.T) {
	const want = 0x0123456789abcdef
	toStack := imm64([]byte{0x48, 0xBC}, codeVA+0x900) // mov rsp, codeVA+0x900
	back := imm64([]byte{0x48, 0xBC}, stackVA+blockSize-0x100)
	rax := imm64([]byte{0x48, 0xB8}, want) // mov rax, want
	for _, c := range []struct {
		name string
		code []byte
		slot int
	}{
		{"push", append(append(append([]byte(nil), toStack...), rax...), 0x50), 0x8F8},
		{"call", append(append([]byte(nil), toStack...), 0xE8, 0, 0, 0, 0), 0x8F8},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, newPlatform(t))
			code := append(c.code, back...)
			code = append(code, gSyscall(6)...)
			page := r.mapPage(codeVA, rwxAccess, code)
			r.mapStack()
			r.wantCall(6)
			got := load64(page[c.slot:])
			if c.name == "push" && got != want {
				t.Errorf("the stack slot holds %#x, want %#x", got, want)
			}
			if c.name == "call" && got != codeVA+uint64(len(toStack)+5) {
				t.Errorf("the stack slot holds %#x, want the return address %#x", got, codeVA+uint64(len(toStack)+5))
			}
		})
	}
}
