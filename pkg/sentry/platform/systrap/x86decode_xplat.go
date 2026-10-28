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

import "golang.org/x/arch/x86/x86asm"

// decodeX86 decodes the instruction at the start of b in 64-bit mode. It
// returns the result of x86asm.Decode, with a correction for VZEROUPPER and
// VZEROALL. These two VEX instructions have no ModRM byte, but x86asm.Decode
// reads one. The length that it returns then depends on the next byte, and it
// is 1 to 5 bytes too long. A scan that trusts that length starts the next
// instruction inside the previous one, and it finds sites that are not
// instructions.
func decodeX86(b []byte) (x86asm.Inst, error) {
	if op, n := vzeroInsn(b); n > 0 {
		return x86asm.Inst{Op: op, Mode: 64, Len: n}, nil
	}
	return x86asm.Decode(b, 64)
}

// vzeroInsn recognizes VZEROUPPER and VZEROALL at the start of b. It returns
// the operation and the length in bytes, or zero when b holds another
// instruction.
//
// The encoding is VEX.128.0F.WIG 77 for VZEROUPPER and VEX.256.0F.WIG 77 for
// VZEROALL. The 2-byte VEX prefix is C5 and one payload byte. The 3-byte prefix
// is C4 and two payload bytes, with the map select 1 for 0F. The last payload
// byte must have vvvv set to 1111 and pp set to 0. Any other value raises #UD,
// and the bytes are not a VZERO instruction.
func vzeroInsn(b []byte) (x86asm.Op, int) {
	var payload byte
	var n int
	switch {
	case len(b) >= 3 && b[0] == 0xC5 && b[2] == 0x77:
		payload, n = b[1], 3
	case len(b) >= 4 && b[0] == 0xC4 && b[1]&0x1F == 1 && b[3] == 0x77:
		payload, n = b[2], 4
	default:
		return 0, 0
	}
	if payload&0x7B != 0x78 {
		// vvvv is not 1111, or pp is not 0.
		return 0, 0
	}
	if payload&0x04 != 0 {
		return x86asm.VZEROALL, n
	}
	return x86asm.VZEROUPPER, n
}
