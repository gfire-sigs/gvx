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
// returns the result of x86asm.Decode with three corrections:
//  1. VZEROUPPER and VZEROALL have no ModRM byte, whereas x86asm.Decode reads
//     one and returns a length 1 to 5 bytes too long. A scan that trusts that
//     length starts the next instruction inside the previous one.
//  2. x86asm.Decode recognizes VEX (0xC5, 0xC4) and EVEX (0x62) only at byte 0.
//     When legal segment or address-size prefixes precede VEX or EVEX,
//     decodeX86 decodes the VEX or EVEX tail and restores those prefixes.
//  3. x86asm.Decode zero-extends 32-bit ModRM displacements of non-VEX
//     instructions instead of sign-extending them to 64 bits.
func decodeX86(b []byte) (x86asm.Inst, error) {
	lead := 0
	var lastSeg x86asm.Reg
	hasAddr32 := false
	for lead < len(b) && lead < amd64MaxInsnLen {
		switch b[lead] {
		case 0x26, 0x2E, 0x36, 0x3E:
			lead++
			continue
		case 0x64:
			lastSeg = x86asm.FS
			lead++
			continue
		case 0x65:
			lastSeg = x86asm.GS
			lead++
			continue
		case 0x67:
			hasAddr32 = true
			lead++
			continue
		}
		break
	}
	if lead < len(b) {
		if op, n := vzeroInsn(b[lead:]); n > 0 && lead+n <= amd64MaxInsnLen {
			inst := x86asm.Inst{Op: op, Mode: 64, Len: lead + n, AddrSize: 64}
			if hasAddr32 {
				inst.AddrSize = 32
			}
			copyLeadingPrefixes(&inst, b[:lead])
			return inst, nil
		}
		if lead > 0 && (b[lead] == 0xC5 || b[lead] == 0xC4 || b[lead] == 0x62) {
			inner, ierr := x86asm.Decode(b[lead:], 64)
			if ierr == nil && inner.Op != 0 && inner.Len > 0 && lead+inner.Len <= amd64MaxInsnLen {
				copyLeadingPrefixes(&inner, b[:lead])
				inner.Len += lead
				if inner.PCRel > 0 {
					inner.PCRelOff += lead
				}
				if hasAddr32 {
					inner.AddrSize = 32
				} else if inner.AddrSize == 0 {
					inner.AddrSize = 64
				}
				if lastSeg != 0 {
					for i, arg := range inner.Args {
						if m, ok := arg.(x86asm.Mem); ok && m.Segment == 0 {
							m.Segment = lastSeg
							inner.Args[i] = m
						}
					}
				}
				return inner, nil
			}
		}
	}
	inst, err := x86asm.Decode(b, 64)
	if err != nil || inst.Op == 0 || inst.Len == 0 || inst.Len > len(b) {
		return inst, err
	}
	if !isMoffsInsn(b[:inst.Len]) {
		for i, arg := range inst.Args {
			m, ok := arg.(x86asm.Mem)
			if !ok {
				continue
			}
			if m.Disp > 0x7fffffff && m.Disp <= 0xffffffff {
				m.Disp = int64(int32(m.Disp))
				inst.Args[i] = m
			}
		}
	}
	return inst, nil
}

// copyLeadingPrefixes prepends raw legacy prefix bytes into inst.Prefix.
func copyLeadingPrefixes(inst *x86asm.Inst, raw []byte) {
	if len(raw) == 0 {
		return
	}
	var merged x86asm.Prefixes
	n := 0
	for _, b := range raw {
		if n >= len(merged) {
			break
		}
		merged[n] = x86asm.Prefix(b)
		n++
	}
	for _, p := range inst.Prefix {
		if p == 0 || n >= len(merged) {
			break
		}
		merged[n] = p
		n++
	}
	inst.Prefix = merged
}

// isMoffsInsn reports whether raw starts with a direct-offset MOV (opcodes
// 0xA0..0xA3 after legacy and REX prefixes). Those are the only 64-bit
// instructions whose x86asm.Mem.Disp holds an unsigned 64-bit direct offset
// rather than a signed 32-bit ModRM displacement.
func isMoffsInsn(raw []byte) bool {
	i := 0
	for i < len(raw) && isX86Prefix(raw[i]) {
		i++
	}
	return i < len(raw) && raw[i] >= 0xA0 && raw[i] <= 0xA3
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
