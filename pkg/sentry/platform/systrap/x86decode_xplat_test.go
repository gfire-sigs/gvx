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

//go:build darwin || windows

package systrap

import (
	"bytes"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

// vzeroEpilogue is the end of a function in Node 22 that uses AVX2: VZEROUPPER,
// then LEA RSP, [RBP-0x28], the pops of the callee-saved registers, and RET.
// The ModRM byte 0x65 of the LEA is also the GS segment prefix.
var vzeroEpilogue = []byte{
	0xc5, 0xf8, 0x77, // vzeroupper
	0x48, 0x8d, 0x65, 0xd8, // lea rsp, [rbp-0x28]
	0x5b, 0x41, 0x5c, 0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3, // pop rbx; pop r12 to r15; pop rbp; ret
}

func TestDecodeX86LengthOfVZero(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		op   x86asm.Op
	}{
		{"vzeroupper, 2-byte prefix", []byte{0xc5, 0xf8, 0x77}, x86asm.VZEROUPPER},
		{"vzeroall, 2-byte prefix", []byte{0xc5, 0xfc, 0x77}, x86asm.VZEROALL},
		{"vzeroupper, 2-byte prefix with R clear", []byte{0xc5, 0x78, 0x77}, x86asm.VZEROUPPER},
		{"vzeroupper, 3-byte prefix", []byte{0xc4, 0xe1, 0x78, 0x77}, x86asm.VZEROUPPER},
		{"vzeroall, 3-byte prefix", []byte{0xc4, 0xe1, 0x7c, 0x77}, x86asm.VZEROALL},
		{"vzeroupper, 3-byte prefix with W set", []byte{0xc4, 0xe1, 0xf8, 0x77}, x86asm.VZEROUPPER},
	}
	// The length must not depend on the bytes behind the instruction. The old
	// decode read the next byte as ModRM, so each trailing byte gave a length.
	for _, c := range cases {
		for _, next := range []byte{0x00, 0x48, 0x65, 0x90, 0xc0, 0xff} {
			code := append(bytes.Clone(c.code), next, 0x90, 0x90, 0x90, 0x90, 0x90)
			inst, err := decodeX86(code)
			if err != nil || inst.Op != c.op || inst.Len != len(c.code) {
				t.Errorf("%s followed by %#x: decodeX86 = (%v, len %d, %v), want (%v, len %d)", c.name, next, inst.Op, inst.Len, err, c.op, len(c.code))
			}
		}
		// The instruction at the end of the buffer needs no byte behind it.
		inst, err := decodeX86(c.code)
		if err != nil || inst.Op != c.op || inst.Len != len(c.code) {
			t.Errorf("%s alone: decodeX86 = (%v, len %d, %v), want (%v, len %d)", c.name, inst.Op, inst.Len, err, c.op, len(c.code))
		}
	}
}

func TestDecodeX86KeepsOtherInstructions(t *testing.T) {
	cases := []struct {
		name string
		code []byte
		op   x86asm.Op
	}{
		{"vpxor", []byte{0xc5, 0xf9, 0xef, 0xc0}, x86asm.VPXOR},
		{"vptest", []byte{0xc4, 0xe2, 0x7d, 0x17, 0xc0}, x86asm.VPTEST},
		{"vpshufd with imm8", []byte{0xc5, 0xf9, 0x70, 0xc0, 0x1b}, x86asm.VPSHUFD},
		{"evex vpternlogd with imm8", []byte{0x62, 0xf3, 0x7d, 0x48, 0x25, 0xc1, 0x01}, x86asm.VPTERNLOGD},
		{"lea", []byte{0x48, 0x8d, 0x65, 0xd8}, x86asm.LEA},
		{"syscall", []byte{0x0f, 0x05}, x86asm.SYSCALL},
	}
	for _, c := range cases {
		code := append(bytes.Clone(c.code), 0x90, 0x90, 0x90, 0x90)
		inst, err := decodeX86(code)
		if err != nil || inst.Op != c.op || inst.Len != len(c.code) {
			t.Errorf("%s: decodeX86 = (%v, len %d, %v), want (%v, len %d)", c.name, inst.Op, inst.Len, err, c.op, len(c.code))
		}
	}
	// A VEX prefix with vvvv or pp set is not VZEROUPPER. The decoder of x86asm
	// decides what the bytes are, and decodeX86 must not claim them.
	for _, code := range [][]byte{
		{0xc5, 0xf0, 0x77, 0x90, 0x90, 0x90, 0x90, 0x90}, // vvvv is 1110
		{0xc5, 0xf9, 0x77, 0x90, 0x90, 0x90, 0x90, 0x90}, // pp is 1
		{0xc4, 0xe2, 0x78, 0x77, 0x90, 0x90, 0x90, 0x90}, // map select 2
	} {
		got, gotErr := decodeX86(code)
		want, wantErr := x86asm.Decode(code, 64)
		if got.Op != want.Op || got.Len != want.Len || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("% x: decodeX86 = (%v, len %d, %v), want the result of x86asm.Decode (%v, len %d, %v)", code, got.Op, got.Len, gotErr, want.Op, want.Len, wantErr)
		}
	}
}

// TestScanAMD64KeepsBoundariesAfterVZero checks the failure of Node 22. The
// length of VZEROUPPER came out as 5, so the scan started an instruction at the
// ModRM byte 0x65 of the LEA behind it. It reported a GS memory instruction
// there, and the patch turned LEA RSP, [RBP-0x28] into an illegal instruction.
func TestScanAMD64KeepsBoundariesAfterVZero(t *testing.T) {
	for _, lead := range []int{0, 1, 5} {
		page := catBytes(nops(lead), vzeroEpilogue)
		if got := scanAMD64GS(nil, page, nil, true); len(got) != 0 {
			t.Errorf("lead %d: scanAMD64GS = %+v, want none", lead, got)
		}
	}
}

// TestScanAMD64FindsSyscallBehindVZero checks that a real site right behind a
// VZEROUPPER survives. The old length moved the scan over the SYSCALL.
func TestScanAMD64FindsSyscallBehindVZero(t *testing.T) {
	// vzeroupper; syscall; ret
	page := []byte{0xc5, 0xf8, 0x77, 0x0f, 0x05, 0xc3}
	got := scanAMD64GS(nil, page, nil, true)
	if want := syscallSite(3); len(got) != 1 || got[0] != want {
		t.Errorf("scanAMD64GS = %+v, want %+v", got, want)
	}
}
