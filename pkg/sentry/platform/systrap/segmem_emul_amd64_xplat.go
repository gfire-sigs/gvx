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
	"encoding/binary"
	"math/bits"

	"golang.org/x/arch/x86/x86asm"
)

// x86 EFLAGS arithmetic status bits.
const (
	eflagCF uint32 = 1 << 0
	eflagPF uint32 = 1 << 2
	eflagAF uint32 = 1 << 4
	eflagZF uint32 = 1 << 6
	eflagSF uint32 = 1 << 7
	eflagOF uint32 = 1 << 11

	eflagsArithMask = eflagCF | eflagPF | eflagAF | eflagZF | eflagSF | eflagOF
)

// segEmulOutcome describes the result of emulating a segment-prefixed
// instruction.
type segEmulOutcome struct {
	ok         bool
	fault      bool
	faultAddr  uint64
	faultWrite bool
}

// emulateSegMemInsn decodes and emulates the memory instruction at the start
// of code that addresses memory through segment seg (x86asm.FS or x86asm.GS)
// with base segBase. It works on the 16 general-purpose registers in regs
// (indexed in hardware order RAX=0..R15=15) and eflags.
func emulateSegMemInsn(
	code []byte,
	seg x86asm.Reg,
	segBase uint64,
	regs *[16]uint64,
	eflags *uint32,
	readMem func(addr uint64, buf []byte) bool,
	writeMem func(addr uint64, buf []byte) bool,
) segEmulOutcome {
	inst, err := decodeX86(code)
	if err != nil || inst.Len == 0 {
		return segEmulOutcome{}
	}
	memIdx := -1
	var memArg x86asm.Mem
	for i, arg := range inst.Args {
		if m, ok := arg.(x86asm.Mem); ok && m.Segment == seg {
			memIdx = i
			memArg = m
			break
		}
	}
	if memIdx < 0 {
		return segEmulOutcome{}
	}
	addr, addrOK := evalSegMemAddr(memArg, segBase, regs)
	if !addrOK {
		return segEmulOutcome{}
	}
	memBytes := inst.MemBytes
	if memBytes == 0 {
		memBytes = inferMemBytes(inst)
	}
	if memBytes != 1 && memBytes != 2 && memBytes != 4 && memBytes != 8 {
		return segEmulOutcome{}
	}

	readVal := func(n int) (uint64, bool) {
		var buf [8]byte
		if !readMem(addr, buf[:n]) {
			return 0, false
		}
		return decodeLittleUint(buf[:n]), true
	}
	writeVal := func(n int, v uint64) bool {
		var buf [8]byte
		encodeLittleUint(buf[:n], v)
		return writeMem(addr, buf[:n])
	}

	switch inst.Op {
	case x86asm.MOV:
		if memIdx == 1 {
			dstReg, ok := inst.Args[0].(x86asm.Reg)
			if !ok {
				return segEmulOutcome{}
			}
			v, ok := readVal(memBytes)
			if !ok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			if !writeX86Reg(regs, dstReg, v) {
				return segEmulOutcome{}
			}
			return segEmulOutcome{ok: true}
		}
		if memIdx == 0 {
			srcVal, ok := evalX86Src(inst.Args[1], memBytes, regs)
			if !ok {
				return segEmulOutcome{}
			}
			if !writeVal(memBytes, srcVal) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			return segEmulOutcome{ok: true}
		}

	case x86asm.MOVZX:
		if memIdx != 1 {
			return segEmulOutcome{}
		}
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		v, ok := readVal(memBytes)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: addr}
		}
		if !writeX86Reg(regs, dstReg, v) {
			return segEmulOutcome{}
		}
		return segEmulOutcome{ok: true}

	case x86asm.MOVSX, x86asm.MOVSXD:
		if memIdx != 1 {
			return segEmulOutcome{}
		}
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		v, ok := readVal(memBytes)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: addr}
		}
		ext := uint64(signExtendTo64(v, memBytes))
		if !writeX86Reg(regs, dstReg, ext) {
			return segEmulOutcome{}
		}
		return segEmulOutcome{ok: true}

	case x86asm.ADD, x86asm.SUB, x86asm.AND, x86asm.OR, x86asm.XOR, x86asm.CMP, x86asm.TEST:
		if memIdx == 1 {
			dstReg, ok := inst.Args[0].(x86asm.Reg)
			if !ok {
				return segEmulOutcome{}
			}
			lhs, width, ok := readX86Reg(regs, dstReg)
			if !ok || width != memBytes {
				return segEmulOutcome{}
			}
			rhs, ok := readVal(memBytes)
			if !ok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			res, writeBack := evalX86ALU(inst.Op, lhs, rhs, memBytes, eflags)
			if writeBack && !writeX86Reg(regs, dstReg, res) {
				return segEmulOutcome{}
			}
			return segEmulOutcome{ok: true}
		}
		if memIdx == 0 {
			rhs, ok := evalX86Src(inst.Args[1], memBytes, regs)
			if !ok {
				return segEmulOutcome{}
			}
			lhs, ok := readVal(memBytes)
			if !ok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			res, writeBack := evalX86ALU(inst.Op, lhs, rhs, memBytes, eflags)
			if writeBack && !writeVal(memBytes, res) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			return segEmulOutcome{ok: true}
		}

	case x86asm.INC, x86asm.DEC:
		if memIdx != 0 {
			return segEmulOutcome{}
		}
		lhs, ok := readVal(memBytes)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: addr}
		}
		oldCF := *eflags & eflagCF
		op := x86asm.ADD
		if inst.Op == x86asm.DEC {
			op = x86asm.SUB
		}
		res, _ := evalX86ALU(op, lhs, 1, memBytes, eflags)
		*eflags = (*eflags &^ eflagCF) | oldCF
		if !writeVal(memBytes, res) {
			return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
		}
		return segEmulOutcome{ok: true}

	case x86asm.XCHG:
		otherIdx := 1 - memIdx
		regArg, ok := inst.Args[otherIdx].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		regVal, width, ok := readX86Reg(regs, regArg)
		if !ok || width != memBytes {
			return segEmulOutcome{}
		}
		memVal, ok := readVal(memBytes)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: addr}
		}
		if !writeVal(memBytes, regVal) {
			return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
		}
		if !writeX86Reg(regs, regArg, memVal) {
			return segEmulOutcome{}
		}
		return segEmulOutcome{ok: true}

	case x86asm.CMPXCHG:
		if memIdx != 0 {
			return segEmulOutcome{}
		}
		srcReg, ok := inst.Args[1].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		srcVal, width, ok := readX86Reg(regs, srcReg)
		if !ok || width != memBytes {
			return segEmulOutcome{}
		}
		memVal, ok := readVal(memBytes)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: addr}
		}
		mask := widthMask(memBytes)
		acc := regs[0] & mask
		evalX86ALU(x86asm.CMP, acc, memVal, memBytes, eflags)
		if acc == (memVal & mask) {
			if !writeVal(memBytes, srcVal) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
		} else {
			writeX86Acc(regs, memBytes, memVal)
		}
		return segEmulOutcome{ok: true}
	}
	return segEmulOutcome{}
}

// isAtomicMemInsn reports whether inst changes memory atomically: it has a LOCK
// prefix, or it is an exchange that locks the bus without one. A read and a
// write from the Sentry cannot replace such an instruction while other guest
// threads run.
func isAtomicMemInsn(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.XCHG, x86asm.CMPXCHG, x86asm.CMPXCHG8B, x86asm.CMPXCHG16B, x86asm.XADD:
		return true
	}
	for _, p := range inst.Prefix {
		if p == 0 {
			break
		}
		if p&0xFF == x86asm.PrefixLOCK {
			return true
		}
	}
	return false
}

func evalSegMemAddr(m x86asm.Mem, segBase uint64, regs *[16]uint64) (uint64, bool) {
	addr := segBase + uint64(m.Disp)
	if m.Base != 0 {
		if m.Base == x86asm.RIP {
			return 0, false
		}
		v, _, ok := readX86Reg(regs, m.Base)
		if !ok {
			return 0, false
		}
		addr += v
	}
	if m.Index != 0 {
		v, _, ok := readX86Reg(regs, m.Index)
		if !ok {
			return 0, false
		}
		scale := uint64(m.Scale)
		if scale == 0 {
			scale = 1
		}
		addr += v * scale
	}
	return addr, true
}

func inferMemBytes(inst x86asm.Inst) int {
	for _, arg := range inst.Args {
		if r, ok := arg.(x86asm.Reg); ok {
			if idx, w, _ := x86RegIndexWidth(r); idx >= 0 {
				return w
			}
		}
	}
	return int(inst.DataSize / 8)
}

func evalX86Src(arg x86asm.Arg, memBytes int, regs *[16]uint64) (uint64, bool) {
	switch a := arg.(type) {
	case x86asm.Reg:
		v, w, ok := readX86Reg(regs, a)
		if !ok || w != memBytes {
			return 0, false
		}
		return v, true
	case x86asm.Imm:
		return uint64(int64(a)) & widthMask(memBytes), true
	}
	return 0, false
}

func x86RegIndexWidth(r x86asm.Reg) (idx int, width int, highByte bool) {
	switch {
	case r >= x86asm.RAX && r <= x86asm.R15:
		return int(r - x86asm.RAX), 8, false
	case r >= x86asm.EAX && r <= x86asm.R15L:
		return int(r - x86asm.EAX), 4, false
	case r >= x86asm.AX && r <= x86asm.R15W:
		return int(r - x86asm.AX), 2, false
	case r >= x86asm.AL && r <= x86asm.BL:
		return int(r - x86asm.AL), 1, false
	case r >= x86asm.AH && r <= x86asm.BH:
		return int(r - x86asm.AH), 1, true
	case r >= x86asm.SPB && r <= x86asm.R15B:
		return int(r-x86asm.SPB) + 4, 1, false
	}
	return -1, 0, false
}

func readX86Reg(regs *[16]uint64, r x86asm.Reg) (uint64, int, bool) {
	idx, w, high := x86RegIndexWidth(r)
	if idx < 0 {
		return 0, 0, false
	}
	v := regs[idx]
	if high {
		return (v >> 8) & 0xff, 1, true
	}
	return v & widthMask(w), w, true
}

func writeX86Reg(regs *[16]uint64, r x86asm.Reg, val uint64) bool {
	idx, w, high := x86RegIndexWidth(r)
	if idx < 0 {
		return false
	}
	switch {
	case w == 8:
		regs[idx] = val
	case w == 4:
		// 32-bit writes zero-extend to 64 bits on x86-64.
		regs[idx] = val & 0xffffffff
	case w == 2:
		regs[idx] = (regs[idx] &^ 0xffff) | (val & 0xffff)
	case high:
		regs[idx] = (regs[idx] &^ 0xff00) | ((val & 0xff) << 8)
	default:
		regs[idx] = (regs[idx] &^ 0xff) | (val & 0xff)
	}
	return true
}

func writeX86Acc(regs *[16]uint64, width int, val uint64) {
	switch width {
	case 8:
		regs[0] = val
	case 4:
		regs[0] = val & 0xffffffff
	case 2:
		regs[0] = (regs[0] &^ 0xffff) | (val & 0xffff)
	case 1:
		regs[0] = (regs[0] &^ 0xff) | (val & 0xff)
	}
}

func widthMask(n int) uint64 {
	switch n {
	case 1:
		return 0xff
	case 2:
		return 0xffff
	case 4:
		return 0xffffffff
	default:
		return ^uint64(0)
	}
}

func signExtendTo64(v uint64, n int) int64 {
	switch n {
	case 1:
		return int64(int8(v))
	case 2:
		return int64(int16(v))
	case 4:
		return int64(int32(v))
	default:
		return int64(v)
	}
}

func decodeLittleUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(b))
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	default:
		return binary.LittleEndian.Uint64(b)
	}
}

func encodeLittleUint(b []byte, v uint64) {
	switch len(b) {
	case 1:
		b[0] = byte(v)
	case 2:
		binary.LittleEndian.PutUint16(b, uint16(v))
	case 4:
		binary.LittleEndian.PutUint32(b, uint32(v))
	default:
		binary.LittleEndian.PutUint64(b, v)
	}
}

func evalX86ALU(op x86asm.Op, a, b uint64, width int, eflags *uint32) (res uint64, writeBack bool) {
	mask := widthMask(width)
	signBit := uint64(1) << (width*8 - 1)
	a &= mask
	b &= mask
	var cf, af, of bool
	switch op {
	case x86asm.ADD:
		res = (a + b) & mask
		cf = res < a
		af = ((a ^ b ^ res) & 0x10) != 0
		of = ((^(a ^ b)) & (a ^ res) & signBit) != 0
		writeBack = true
	case x86asm.SUB, x86asm.CMP:
		res = (a - b) & mask
		cf = a < b
		af = ((a ^ b ^ res) & 0x10) != 0
		of = ((a ^ b) & (a ^ res) & signBit) != 0
		writeBack = op == x86asm.SUB
	case x86asm.AND, x86asm.TEST:
		res = a & b
		writeBack = op == x86asm.AND
	case x86asm.OR:
		res = a | b
		writeBack = true
	case x86asm.XOR:
		res = a ^ b
		writeBack = true
	}
	f := *eflags &^ eflagsArithMask
	if cf {
		f |= eflagCF
	}
	if af {
		f |= eflagAF
	}
	if of {
		f |= eflagOF
	}
	if res == 0 {
		f |= eflagZF
	}
	if res&signBit != 0 {
		f |= eflagSF
	}
	if bits.OnesCount8(uint8(res))%2 == 0 {
		f |= eflagPF
	}
	*eflags = f
	return res, writeBack
}

// evalX86Cond evaluates a conditional code suffix (such as "E", "NE", "AE",
// "L", "LE", "G") against eflags.
func evalX86Cond(cc string, eflags uint32) (bool, bool) {
	cf := eflags&eflagCF != 0
	pf := eflags&eflagPF != 0
	zf := eflags&eflagZF != 0
	sf := eflags&eflagSF != 0
	of := eflags&eflagOF != 0
	switch cc {
	case "O":
		return of, true
	case "NO":
		return !of, true
	case "B", "C", "NAE":
		return cf, true
	case "AE", "NB", "NC":
		return !cf, true
	case "E", "Z":
		return zf, true
	case "NE", "NZ":
		return !zf, true
	case "BE", "NA":
		return cf || zf, true
	case "A", "NBE":
		return !cf && !zf, true
	case "S":
		return sf, true
	case "NS":
		return !sf, true
	case "P", "PE":
		return pf, true
	case "NP", "PO":
		return !pf, true
	case "L", "NGE":
		return sf != of, true
	case "GE", "NL":
		return sf == of, true
	case "LE", "NG":
		return zf || (sf != of), true
	case "G", "NLE":
		return !zf && (sf == of), true
	}
	return false, false
}

// evalX86MemAddr computes the linear guest address of m for an instruction of
// length insnLen at pc. When withSeg is false (as in LEA), segment bases are
// ignored.
func evalX86MemAddr(m x86asm.Mem, pc uint64, insnLen int, fsBase, gsBase uint64, regs *[16]uint64, withSeg bool) (uint64, bool) {
	var seg uint64
	if withSeg {
		switch m.Segment {
		case 0, x86asm.CS, x86asm.DS, x86asm.ES, x86asm.SS:
		case x86asm.FS:
			seg = fsBase
		case x86asm.GS:
			seg = gsBase
		default:
			return 0, false
		}
	}
	off := uint64(m.Disp)
	addr32 := false
	switch m.Base {
	case 0:
	case x86asm.RIP:
		off += pc + uint64(insnLen)
	case x86asm.EIP:
		off += uint64(uint32(pc + uint64(insnLen)))
		addr32 = true
	default:
		v, w, ok := readX86Reg(regs, m.Base)
		if !ok || (w != 8 && w != 4) {
			return 0, false
		}
		if w == 4 {
			addr32 = true
		}
		off += v
	}
	if m.Index != 0 {
		v, w, ok := readX86Reg(regs, m.Index)
		if !ok || (w != 8 && w != 4) {
			return 0, false
		}
		if w == 4 {
			addr32 = true
		}
		scale := uint64(m.Scale)
		if scale == 0 {
			scale = 1
		}
		off += v * scale
	}
	if addr32 {
		off &= 0xffffffff
	}
	return seg + off, true
}

func evalX86ALUCarry(op x86asm.Op, a, b uint64, width int, eflags *uint32) (res uint64, writeBack bool) {
	if op != x86asm.ADC && op != x86asm.SBB {
		return evalX86ALU(op, a, b, width, eflags)
	}
	mask := widthMask(width)
	signBit := uint64(1) << (width*8 - 1)
	a &= mask
	b &= mask
	var cIn uint64
	if *eflags&eflagCF != 0 {
		cIn = 1
	}
	var cf, af, of bool
	if op == x86asm.ADC {
		s1 := (a + b) & mask
		c1 := s1 < a
		res = (s1 + cIn) & mask
		c2 := res < s1
		cf = c1 || c2
		af = ((a & 0xf) + (b & 0xf) + cIn) > 0xf
		of = ((^(a ^ b)) & (a ^ res) & signBit) != 0
	} else {
		d1 := (a - b) & mask
		b1 := a < b
		res = (d1 - cIn) & mask
		b2 := d1 < cIn
		cf = b1 || b2
		af = (a & 0xf) < ((b & 0xf) + cIn)
		of = ((a ^ b) & (a ^ res) & signBit) != 0
	}
	f := *eflags &^ eflagsArithMask
	if cf {
		f |= eflagCF
	}
	if af {
		f |= eflagAF
	}
	if of {
		f |= eflagOF
	}
	if res == 0 {
		f |= eflagZF
	}
	if res&signBit != 0 {
		f |= eflagSF
	}
	if bits.OnesCount8(uint8(res))%2 == 0 {
		f |= eflagPF
	}
	*eflags = f
	return res, true
}

func evalX86Shift(op x86asm.Op, v uint64, count uint8, width int, eflags *uint32) (uint64, bool) {
	shiftMask := uint8(0x1f)
	if width == 8 {
		shiftMask = 0x3f
	}
	c := count & shiftMask
	mask := widthMask(width)
	bitsW := uint(width * 8)
	v &= mask
	if c == 0 {
		return v, true
	}
	switch op {
	case x86asm.SHL, x86asm.SHR, x86asm.SAR:
		var res uint64
		var cf, of bool
		switch op {
		case x86asm.SHL:
			if uint(c) <= bitsW {
				if uint(c) == bitsW {
					cf = (v & 1) != 0
				} else {
					cf = (v>>(bitsW-uint(c)))&1 != 0
				}
				res = (v << c) & mask
			}
			if c == 1 {
				msb := (res >> (bitsW - 1)) & 1
				of = (msb != 0) != cf
			}
		case x86asm.SHR:
			if uint(c) <= bitsW {
				cf = (v>>(uint(c)-1))&1 != 0
				if uint(c) < bitsW {
					res = (v >> c) & mask
				}
			}
			if c == 1 {
				of = (v>>(bitsW-1))&1 != 0
			}
		case x86asm.SAR:
			sv := signExtendTo64(v, width)
			if uint(c) >= bitsW {
				cf = sv < 0
				if sv < 0 {
					res = mask
				}
			} else {
				cf = (uint64(sv)>>(uint(c)-1))&1 != 0
				res = uint64(sv>>c) & mask
			}
			// SAR by 1 clears OF.
		}
		f := *eflags &^ (eflagCF | eflagZF | eflagSF | eflagPF)
		if cf {
			f |= eflagCF
		}
		if c == 1 {
			f &^= eflagOF
			if of {
				f |= eflagOF
			}
		}
		if res == 0 {
			f |= eflagZF
		}
		if (res>>(bitsW-1))&1 != 0 {
			f |= eflagSF
		}
		if bits.OnesCount8(uint8(res))%2 == 0 {
			f |= eflagPF
		}
		*eflags = f
		return res, true
	case x86asm.ROL, x86asm.ROR:
		mod := uint(c) % bitsW
		res := v
		if mod != 0 {
			if op == x86asm.ROL {
				res = ((v << mod) | (v >> (bitsW - mod))) & mask
			} else {
				res = ((v >> mod) | (v << (bitsW - mod))) & mask
			}
		}
		var cf bool
		if op == x86asm.ROL {
			cf = (res & 1) != 0
		} else {
			cf = (res>>(bitsW-1))&1 != 0
		}
		f := *eflags &^ eflagCF
		if cf {
			f |= eflagCF
		}
		if c == 1 {
			f &^= eflagOF
			msb := (res >> (bitsW - 1)) & 1
			if op == x86asm.ROL {
				if (msb != 0) != cf {
					f |= eflagOF
				}
			} else {
				nextMsb := (res >> (bitsW - 2)) & 1
				if msb != nextMsb {
					f |= eflagOF
				}
			}
		}
		*eflags = f
		return res, true
	}
	return 0, false
}

// emulateGuardedX86Insn decodes and emulates a general-purpose or control-flow
// instruction at guest address pc whose unmodified bytes are code. It updates
// regs, eflags, and *nextPC on success. Atomic memory instructions return
// ok=false so the caller runs a sanitized hardware sequence instead.
func emulateGuardedX86Insn(
	code []byte,
	pc uint64,
	fsBase, gsBase uint64,
	regs *[16]uint64,
	eflags *uint32,
	nextPC *uint64,
	readMem func(addr uint64, buf []byte) bool,
	writeMem func(addr uint64, buf []byte) bool,
) segEmulOutcome {
	inst, err := decodeX86(code)
	if err != nil || inst.Len == 0 {
		return segEmulOutcome{}
	}
	hasMem := false
	for _, arg := range inst.Args {
		if _, ok := arg.(x86asm.Mem); ok {
			hasMem = true
			break
		}
	}
	if hasMem && isAtomicMemInsn(inst) {
		return segEmulOutcome{}
	}

	fallthroughPC := pc + uint64(inst.Len)
	readAt := func(addr uint64, n int) (uint64, bool) {
		var buf [8]byte
		if !readMem(addr, buf[:n]) {
			return 0, false
		}
		return decodeLittleUint(buf[:n]), true
	}
	writeAt := func(addr uint64, n int, v uint64) bool {
		var buf [8]byte
		encodeLittleUint(buf[:n], v)
		return writeMem(addr, buf[:n])
	}
	memWidth := func() int {
		if inst.MemBytes != 0 {
			return inst.MemBytes
		}
		return inferMemBytes(inst)
	}
	readOperand := func(arg x86asm.Arg, width int) (val uint64, fault bool, faultAddr uint64, ok bool) {
		switch a := arg.(type) {
		case x86asm.Reg:
			v, w, rok := readX86Reg(regs, a)
			if !rok || (width != 0 && w != width) {
				return 0, false, 0, false
			}
			return v, false, 0, true
		case x86asm.Imm:
			return uint64(int64(a)) & widthMask(width), false, 0, true
		case x86asm.Mem:
			if width != 1 && width != 2 && width != 4 && width != 8 {
				return 0, false, 0, false
			}
			addr, aok := evalX86MemAddr(a, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return 0, false, 0, false
			}
			v, mok := readAt(addr, width)
			if !mok {
				return 0, true, addr, false
			}
			return v, false, 0, true
		}
		return 0, false, 0, false
	}

	opStr := inst.Op.String()
	switch {
	case inst.Op == x86asm.NOP:
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.LEA:
		dstReg, ok1 := inst.Args[0].(x86asm.Reg)
		memArg, ok2 := inst.Args[1].(x86asm.Mem)
		if !ok1 || !ok2 {
			return segEmulOutcome{}
		}
		dstIdx, dstW, _ := x86RegIndexWidth(dstReg)
		if dstIdx < 0 || (dstW != 2 && dstW != 4 && dstW != 8) {
			return segEmulOutcome{}
		}
		addr, aok := evalX86MemAddr(memArg, pc, inst.Len, 0, 0, regs, false)
		if !aok || !writeX86Reg(regs, dstReg, addr) {
			return segEmulOutcome{}
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.MOV:
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			dstIdx, dstW, _ := x86RegIndexWidth(dst)
			if dstIdx < 0 {
				return segEmulOutcome{}
			}
			v, fault, fAddr, ok := readOperand(inst.Args[1], dstW)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			if !ok || !writeX86Reg(regs, dst, v) {
				return segEmulOutcome{}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		case x86asm.Mem:
			w := memWidth()
			if w != 1 && w != 2 && w != 4 && w != 8 {
				return segEmulOutcome{}
			}
			v, ok := evalX86Src(inst.Args[1], w, regs)
			if !ok {
				return segEmulOutcome{}
			}
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return segEmulOutcome{}
			}
			if !writeAt(addr, w, v) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		}

	case inst.Op == x86asm.MOVZX, inst.Op == x86asm.MOVSX, inst.Op == x86asm.MOVSXD:
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		var srcW int
		switch s := inst.Args[1].(type) {
		case x86asm.Reg:
			_, srcW, _ = x86RegIndexWidth(s)
		case x86asm.Mem:
			srcW = inst.MemBytes
			if srcW == 0 && inst.Op == x86asm.MOVSXD {
				srcW = 4
			}
		}
		if srcW != 1 && srcW != 2 && srcW != 4 {
			return segEmulOutcome{}
		}
		v, fault, fAddr, rok := readOperand(inst.Args[1], srcW)
		if fault {
			return segEmulOutcome{fault: true, faultAddr: fAddr}
		}
		if !rok {
			return segEmulOutcome{}
		}
		if inst.Op != x86asm.MOVZX {
			v = uint64(signExtendTo64(v, srcW))
		}
		if !writeX86Reg(regs, dstReg, v) {
			return segEmulOutcome{}
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case len(opStr) > 4 && opStr[:4] == "CMOV":
		cond, cok := evalX86Cond(opStr[4:], *eflags)
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !cok || !ok {
			return segEmulOutcome{}
		}
		dstIdx, dstW, _ := x86RegIndexWidth(dstReg)
		if dstIdx < 0 || (dstW != 2 && dstW != 4 && dstW != 8) {
			return segEmulOutcome{}
		}
		v, fault, fAddr, rok := readOperand(inst.Args[1], dstW)
		if fault {
			return segEmulOutcome{fault: true, faultAddr: fAddr}
		}
		if !rok {
			return segEmulOutcome{}
		}
		if cond {
			writeX86Reg(regs, dstReg, v)
		} else if dstW == 4 {
			regs[dstIdx] &= 0xffffffff
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case len(opStr) > 3 && opStr[:3] == "SET":
		cond, cok := evalX86Cond(opStr[3:], *eflags)
		if !cok {
			return segEmulOutcome{}
		}
		var b uint64
		if cond {
			b = 1
		}
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			if idx, w, _ := x86RegIndexWidth(dst); idx < 0 || w != 1 || !writeX86Reg(regs, dst, b) {
				return segEmulOutcome{}
			}
		case x86asm.Mem:
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return segEmulOutcome{}
			}
			if !writeAt(addr, 1, b) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
		default:
			return segEmulOutcome{}
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.ADD, inst.Op == x86asm.SUB, inst.Op == x86asm.ADC, inst.Op == x86asm.SBB,
		inst.Op == x86asm.AND, inst.Op == x86asm.OR, inst.Op == x86asm.XOR, inst.Op == x86asm.CMP, inst.Op == x86asm.TEST:
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			lhs, dstW, rok := readX86Reg(regs, dst)
			if !rok {
				return segEmulOutcome{}
			}
			rhs, fault, fAddr, ok := readOperand(inst.Args[1], dstW)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			if !ok {
				return segEmulOutcome{}
			}
			res, wb := evalX86ALUCarry(inst.Op, lhs, rhs, dstW, eflags)
			if wb && !writeX86Reg(regs, dst, res) {
				return segEmulOutcome{}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		case x86asm.Mem:
			w := memWidth()
			if w != 1 && w != 2 && w != 4 && w != 8 {
				return segEmulOutcome{}
			}
			rhs, ok := evalX86Src(inst.Args[1], w, regs)
			if !ok {
				return segEmulOutcome{}
			}
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return segEmulOutcome{}
			}
			lhs, mok := readAt(addr, w)
			if !mok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			res, wb := evalX86ALUCarry(inst.Op, lhs, rhs, w, eflags)
			if wb && !writeAt(addr, w, res) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		}

	case inst.Op == x86asm.INC, inst.Op == x86asm.DEC, inst.Op == x86asm.NEG, inst.Op == x86asm.NOT:
		runUnary := func(v uint64, w int) uint64 {
			switch inst.Op {
			case x86asm.INC, x86asm.DEC:
				oldCF := *eflags & eflagCF
				aluOp := x86asm.ADD
				if inst.Op == x86asm.DEC {
					aluOp = x86asm.SUB
				}
				res, _ := evalX86ALU(aluOp, v, 1, w, eflags)
				*eflags = (*eflags &^ eflagCF) | oldCF
				return res
			case x86asm.NEG:
				res, _ := evalX86ALU(x86asm.SUB, 0, v, w, eflags)
				if v&widthMask(w) != 0 {
					*eflags |= eflagCF
				} else {
					*eflags &^= eflagCF
				}
				return res
			default:
				return (^v) & widthMask(w)
			}
		}
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			lhs, w, ok := readX86Reg(regs, dst)
			if !ok || !writeX86Reg(regs, dst, runUnary(lhs, w)) {
				return segEmulOutcome{}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		case x86asm.Mem:
			w := memWidth()
			if w != 1 && w != 2 && w != 4 && w != 8 {
				return segEmulOutcome{}
			}
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return segEmulOutcome{}
			}
			lhs, mok := readAt(addr, w)
			if !mok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			if !writeAt(addr, w, runUnary(lhs, w)) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		}

	case inst.Op == x86asm.SHL, inst.Op == x86asm.SHR, inst.Op == x86asm.SAR, inst.Op == x86asm.ROL, inst.Op == x86asm.ROR:
		var cnt uint8
		switch c := inst.Args[1].(type) {
		case x86asm.Imm:
			cnt = uint8(c)
		case x86asm.Reg:
			if c != x86asm.CL {
				return segEmulOutcome{}
			}
			cnt = uint8(regs[1])
		default:
			return segEmulOutcome{}
		}
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			lhs, w, ok := readX86Reg(regs, dst)
			if !ok {
				return segEmulOutcome{}
			}
			res, sok := evalX86Shift(inst.Op, lhs, cnt, w, eflags)
			if !sok || !writeX86Reg(regs, dst, res) {
				return segEmulOutcome{}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		case x86asm.Mem:
			w := memWidth()
			if w != 1 && w != 2 && w != 4 && w != 8 {
				return segEmulOutcome{}
			}
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				return segEmulOutcome{}
			}
			lhs, mok := readAt(addr, w)
			if !mok {
				return segEmulOutcome{fault: true, faultAddr: addr}
			}
			res, sok := evalX86Shift(inst.Op, lhs, cnt, w, eflags)
			if !sok {
				return segEmulOutcome{}
			}
			if !writeAt(addr, w, res) {
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
			*nextPC = fallthroughPC
			return segEmulOutcome{ok: true}
		}

	case inst.Op == x86asm.IMUL:
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !ok || inst.Args[1] == nil {
			return segEmulOutcome{}
		}
		dstVal, w, rok := readX86Reg(regs, dstReg)
		if !rok || (w != 2 && w != 4 && w != 8) {
			return segEmulOutcome{}
		}
		var lhs, rhs int64
		if inst.Args[2] != nil {
			v1, fault, fAddr, ok1 := readOperand(inst.Args[1], w)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			imm, ok2 := inst.Args[2].(x86asm.Imm)
			if !ok1 || !ok2 {
				return segEmulOutcome{}
			}
			lhs = signExtendTo64(v1, w)
			rhs = int64(imm)
		} else {
			v2, fault, fAddr, ok2 := readOperand(inst.Args[1], w)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			if !ok2 {
				return segEmulOutcome{}
			}
			lhs = signExtendTo64(dstVal, w)
			rhs = signExtendTo64(v2, w)
		}
		var res uint64
		var overflow bool
		if w == 8 {
			hi, lo := bits.Mul64(uint64(lhs), uint64(rhs))
			if (lhs < 0) != (rhs < 0) {
				if lhs < 0 {
					hi -= uint64(rhs)
				} else {
					hi -= uint64(lhs)
				}
			} else if lhs < 0 && rhs < 0 {
				hi -= uint64(lhs) + uint64(rhs)
			}
			res = lo
			signExt := uint64(int64(lo) >> 63)
			overflow = hi != signExt
		} else {
			prod := lhs * rhs
			res = uint64(prod) & widthMask(w)
			overflow = signExtendTo64(res, w) != prod
		}
		if !writeX86Reg(regs, dstReg, res) {
			return segEmulOutcome{}
		}
		if overflow {
			*eflags |= eflagCF | eflagOF
		} else {
			*eflags &^= eflagCF | eflagOF
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.BT, inst.Op == x86asm.BTS, inst.Op == x86asm.BTR, inst.Op == x86asm.BTC:
		dstReg, ok := inst.Args[0].(x86asm.Reg)
		if !ok {
			return segEmulOutcome{}
		}
		lhs, w, rok := readX86Reg(regs, dstReg)
		if !rok || (w != 2 && w != 4 && w != 8) {
			return segEmulOutcome{}
		}
		var bitIdx uint64
		switch b := inst.Args[1].(type) {
		case x86asm.Imm:
			bitIdx = uint64(uint8(b)) % uint64(w*8)
		case x86asm.Reg:
			bv, bw, bok := readX86Reg(regs, b)
			if !bok || bw != w {
				return segEmulOutcome{}
			}
			bitIdx = bv % uint64(w*8)
		default:
			return segEmulOutcome{}
		}
		bitMask := uint64(1) << bitIdx
		if lhs&bitMask != 0 {
			*eflags |= eflagCF
		} else {
			*eflags &^= eflagCF
		}
		switch inst.Op {
		case x86asm.BTS:
			writeX86Reg(regs, dstReg, lhs|bitMask)
		case x86asm.BTR:
			writeX86Reg(regs, dstReg, lhs&^bitMask)
		case x86asm.BTC:
			writeX86Reg(regs, dstReg, lhs^bitMask)
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.XCHG:
		r0, ok0 := inst.Args[0].(x86asm.Reg)
		r1, ok1 := inst.Args[1].(x86asm.Reg)
		if !ok0 || !ok1 {
			return segEmulOutcome{}
		}
		v0, w0, rok0 := readX86Reg(regs, r0)
		v1, w1, rok1 := readX86Reg(regs, r1)
		if !rok0 || !rok1 || w0 != w1 {
			return segEmulOutcome{}
		}
		writeX86Reg(regs, r0, v1)
		writeX86Reg(regs, r1, v0)
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.PUSH:
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		var val uint64
		switch a := inst.Args[0].(type) {
		case x86asm.Reg:
			v, w, ok := readX86Reg(regs, a)
			if !ok || w != 8 {
				return segEmulOutcome{}
			}
			val = v
		case x86asm.Imm:
			val = uint64(int64(a))
		case x86asm.Mem:
			v, fault, fAddr, ok := readOperand(a, 8)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			if !ok {
				return segEmulOutcome{}
			}
			val = v
		default:
			return segEmulOutcome{}
		}
		newSP := regs[4] - 8
		if !writeAt(newSP, 8, val) {
			return segEmulOutcome{fault: true, faultAddr: newSP, faultWrite: true}
		}
		regs[4] = newSP
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.POP:
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		sp := regs[4]
		val, ok := readAt(sp, 8)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: sp}
		}
		switch dst := inst.Args[0].(type) {
		case x86asm.Reg:
			idx, w, _ := x86RegIndexWidth(dst)
			if idx < 0 || w != 8 {
				return segEmulOutcome{}
			}
			regs[4] = sp + 8
			regs[idx] = val
		case x86asm.Mem:
			// Note: POP [rsp+...] evaluates the destination address after incrementing RSP.
			regs[4] = sp + 8
			addr, aok := evalX86MemAddr(dst, pc, inst.Len, fsBase, gsBase, regs, true)
			if !aok {
				regs[4] = sp
				return segEmulOutcome{}
			}
			if !writeAt(addr, 8, val) {
				regs[4] = sp
				return segEmulOutcome{fault: true, faultAddr: addr, faultWrite: true}
			}
		default:
			return segEmulOutcome{}
		}
		*nextPC = fallthroughPC
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.JMP, inst.Op == x86asm.CALL:
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		var target uint64
		switch a := inst.Args[0].(type) {
		case x86asm.Rel:
			target = uint64(int64(fallthroughPC) + int64(a))
		case x86asm.Reg:
			v, w, ok := readX86Reg(regs, a)
			if !ok || w != 8 {
				return segEmulOutcome{}
			}
			target = v
		case x86asm.Mem:
			v, fault, fAddr, ok := readOperand(a, 8)
			if fault {
				return segEmulOutcome{fault: true, faultAddr: fAddr}
			}
			if !ok {
				return segEmulOutcome{}
			}
			target = v
		default:
			return segEmulOutcome{}
		}
		if inst.Op == x86asm.CALL {
			newSP := regs[4] - 8
			if !writeAt(newSP, 8, fallthroughPC) {
				return segEmulOutcome{fault: true, faultAddr: newSP, faultWrite: true}
			}
			regs[4] = newSP
		}
		*nextPC = target
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.RET:
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		var popExtra uint64
		if inst.Args[0] != nil {
			imm, ok := inst.Args[0].(x86asm.Imm)
			if !ok {
				return segEmulOutcome{}
			}
			popExtra = uint64(uint16(imm))
		}
		sp := regs[4]
		retAddr, ok := readAt(sp, 8)
		if !ok {
			return segEmulOutcome{fault: true, faultAddr: sp}
		}
		regs[4] = sp + 8 + popExtra
		*nextPC = retAddr
		return segEmulOutcome{ok: true}

	case inst.Op == x86asm.JECXZ, inst.Op == x86asm.JRCXZ:
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		rel, ok := inst.Args[0].(x86asm.Rel)
		if !ok {
			return segEmulOutcome{}
		}
		taken := regs[1] == 0
		if inst.Op == x86asm.JECXZ {
			taken = uint32(regs[1]) == 0
		}
		if taken {
			*nextPC = uint64(int64(fallthroughPC) + int64(rel))
		} else {
			*nextPC = fallthroughPC
		}
		return segEmulOutcome{ok: true}

	case len(opStr) > 1 && opStr[0] == 'J':
		if hasOperandSize16(inst, code[:inst.Len]) {
			return segEmulOutcome{}
		}
		cond, cok := evalX86Cond(opStr[1:], *eflags)
		rel, rok := inst.Args[0].(x86asm.Rel)
		if !cok || !rok {
			return segEmulOutcome{}
		}
		if cond {
			*nextPC = uint64(int64(fallthroughPC) + int64(rel))
		} else {
			*nextPC = fallthroughPC
		}
		return segEmulOutcome{ok: true}
	}
	return segEmulOutcome{}
}

func hasOperandSize16(inst x86asm.Inst, raw []byte) bool {
	if inst.DataSize == 16 {
		return true
	}
	for _, p := range inst.Prefix {
		if p == 0 {
			break
		}
		if p&0xFF == 0x66 {
			return true
		}
	}
	for i := 0; i < len(raw) && isX86Prefix(raw[i]); i++ {
		if raw[i] == 0x66 {
			return true
		}
	}
	return false
}

func isDisallowedScratchOp(inst x86asm.Inst) bool {
	switch inst.Op {
	case x86asm.MOVSB, x86asm.MOVSW, x86asm.MOVSQ,
		x86asm.CMPSB, x86asm.CMPSW, x86asm.CMPSQ,
		x86asm.STOSB, x86asm.STOSW, x86asm.STOSD, x86asm.STOSQ,
		x86asm.LODSB, x86asm.LODSW, x86asm.LODSD, x86asm.LODSQ,
		x86asm.SCASB, x86asm.SCASW, x86asm.SCASD, x86asm.SCASQ,
		x86asm.INSB, x86asm.INSW, x86asm.INSD,
		x86asm.OUTSB, x86asm.OUTSW, x86asm.OUTSD,
		x86asm.XLATB, x86asm.MASKMOVQ, x86asm.MASKMOVDQU, x86asm.VMASKMOVDQU,
		x86asm.ENTER, x86asm.LEAVE,
		x86asm.PUSH, x86asm.POP, x86asm.PUSHF, x86asm.PUSHFQ, x86asm.POPF, x86asm.POPFQ,
		x86asm.CALL, x86asm.RET, x86asm.IRET, x86asm.IRETD, x86asm.IRETQ,
		x86asm.SYSCALL, x86asm.SYSENTER, x86asm.SYSEXIT, x86asm.SYSRET,
		x86asm.INT, x86asm.INTO, x86asm.UD2, x86asm.HLT,
		x86asm.RDFSBASE, x86asm.RDGSBASE, x86asm.WRFSBASE, x86asm.WRGSBASE:
		return true
	case x86asm.MOVSD, x86asm.CMPSD:
		hasXMM := false
		for _, arg := range inst.Args {
			if r, ok := arg.(x86asm.Reg); ok && r >= x86asm.X0 && r <= x86asm.X31 {
				hasXMM = true
				break
			}
		}
		if !hasXMM {
			return true
		}
	}
	opStr := inst.Op.String()
	if (len(opStr) >= 5 && opStr[:5] == "XSAVE") ||
		(len(opStr) >= 6 && (opStr[:6] == "XRSTOR" || opStr[:6] == "FXSAVE")) ||
		(len(opStr) >= 7 && opStr[:7] == "FXRSTOR") {
		return true
	}
	return false
}

// guardedScratchPlan describes how to run a guarded instruction that pure-Go
// GPR emulation declined (such as SSE, AVX, FPU, or LOCK memory instructions)
// from a per-thread engine code slot without leaving any raw kernel-entry
// opcode in executable memory.
type guardedScratchPlan struct {
	// insn holds the sanitized instruction bytes (at most 15 bytes).
	insn []byte
	// useScratch reports whether scratchReg must be loaded with effAddr before
	// insn runs and restored afterward.
	useScratch bool
	scratchReg uint8
	effAddr    uint64
}

// planGuardedScratchInsn builds a raw-kernel-exit-free rewrite of the first
// instruction in code at guest address pc.
func planGuardedScratchInsn(code []byte, pc, fsBase, gsBase uint64, regs *[16]uint64) (guardedScratchPlan, bool) {
	inst, err := decodeX86(code)
	if err == nil && inst.Op == 0 {
		// golang.org/x/arch/x86/x86asm stops at legacy segment prefixes before VEX (0xC5/0xC4).
		segLead := 0
		for segLead < len(code) && segLead < amd64MaxInsnLen {
			switch code[segLead] {
			case 0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65:
				segLead++
				continue
			}
			break
		}
		if segLead > 0 && segLead < len(code) && (code[segLead] == 0xC5 || code[segLead] == 0xC4) {
			if inner, ierr := decodeX86(code[segLead:]); ierr == nil && inner.Op != 0 && inner.Len > 0 && segLead+inner.Len <= amd64MaxInsnLen {
				inner.Len += segLead
				inst = inner
			}
		}
	}
	if err != nil || inst.Op == 0 || inst.Len == 0 || inst.Len > len(code) {
		return guardedScratchPlan{}, false
	}
	if inst.AddrSize == 32 || isDisallowedScratchOp(inst) {
		return guardedScratchPlan{}, false
	}
	raw := code[:inst.Len]
	var memArg x86asm.Mem
	memCount := 0
	hasHighByteReg := false
	usedGPR := [16]bool{}
	// Reserve RAX, RCX, RDX, RBX, RSP, and RBP so implicit register operands
	// (such as CMPXCHG, CMPXCHG8B, CMPXCHG16B, MUL, DIV, and variable shifts)
	// and stack/frame pointers are never clobbered as scratchReg.
	for r := 0; r <= 5; r++ {
		usedGPR[r] = true
	}
	for _, arg := range inst.Args {
		switch a := arg.(type) {
		case x86asm.Rel:
			return guardedScratchPlan{}, false
		case x86asm.Reg:
			if idx, _, high := x86RegIndexWidth(a); idx >= 0 {
				usedGPR[idx] = true
				if high {
					hasHighByteReg = true
				}
			}
		case x86asm.Mem:
			memCount++
			memArg = a
			if idx, _, _ := x86RegIndexWidth(a.Base); idx >= 0 {
				usedGPR[idx] = true
			}
			if idx, _, _ := x86RegIndexWidth(a.Index); idx >= 0 {
				usedGPR[idx] = true
			}
		}
	}
	if memCount > 1 {
		return guardedScratchPlan{}, false
	}

	// Parse legacy/REX prefixes up to the opcode or VEX/EVEX/XOP lead byte.
	pIdx := 0
	var cleanPrefixes []byte
	rexIdx := -1
	var lastSeg x86asm.Reg
	for pIdx < len(raw) && isX86Prefix(raw[pIdx]) {
		b := raw[pIdx]
		pIdx++
		switch b {
		case 0x64:
			lastSeg = x86asm.FS
			continue
		case 0x65:
			lastSeg = x86asm.GS
			continue
		case 0x26, 0x2E, 0x36, 0x3E:
			lastSeg = 0
			continue
		case 0x67:
			// Reject 32-bit address-size overrides rather than stripping them.
			return guardedScratchPlan{}, false
		}
		if b >= 0x40 && b <= 0x4F {
			rexIdx = len(cleanPrefixes)
		}
		cleanPrefixes = append(cleanPrefixes, b)
	}
	if pIdx >= len(raw) {
		return guardedScratchPlan{}, false
	}
	// Reject 4-byte EVEX (0x62) and XOP (0x8F /8+) encodings.
	if raw[pIdx] == 0x62 || (raw[pIdx] == 0x8F && pIdx+1 < len(raw) && (raw[pIdx+1]&0x38) != 0) {
		return guardedScratchPlan{}, false
	}

	if memCount == 0 {
		if lastSeg != 0 || hasRawKernelExit(raw) || inst.PCRel != 0 || len(raw) > amd64MaxInsnLen {
			return guardedScratchPlan{}, false
		}
		// Require ModRM.mod == 3 on register-only VEX instructions (except VZEROUPPER/VZEROALL 0x77)
		// so VSIB gather/scatter encodings cannot bypass scratch address validation.
		if raw[pIdx] == 0xC5 {
			if pIdx+2 >= len(raw) {
				return guardedScratchPlan{}, false
			}
			if raw[pIdx+2] != 0x77 && (pIdx+3 >= len(raw) || (raw[pIdx+3]>>6) != 3) {
				return guardedScratchPlan{}, false
			}
		} else if raw[pIdx] == 0xC4 {
			if pIdx+3 >= len(raw) {
				return guardedScratchPlan{}, false
			}
			if raw[pIdx+3] != 0x77 && (pIdx+4 >= len(raw) || (raw[pIdx+4]>>6) != 3) {
				return guardedScratchPlan{}, false
			}
		}
		return guardedScratchPlan{insn: append([]byte(nil), raw...)}, true
	}

	if inst.Op == x86asm.LEA {
		return guardedScratchPlan{}, false
	}

	var head []byte
	var modrmPos int
	isVEX2 := false
	vex1Idx := -1
	opcodeStartInHead := len(cleanPrefixes)
	switch raw[pIdx] {
	case 0xC5: // 2-byte VEX: C5 <RvvvvLpp> <opcode> <modrm> ...
		if pIdx+3 >= len(raw) {
			return guardedScratchPlan{}, false
		}
		isVEX2 = true
		head = append(append([]byte(nil), cleanPrefixes...), raw[pIdx], raw[pIdx+1], raw[pIdx+2])
		modrmPos = pIdx + 3
	case 0xC4: // 3-byte VEX: C4 <RXBmmmmm> <WvvvvLpp> <opcode> <modrm> ...
		if pIdx+4 >= len(raw) {
			return guardedScratchPlan{}, false
		}
		vex1Idx = len(cleanPrefixes) + 1
		vex1 := raw[pIdx+1] | 0x60 // set ~X=1 and ~B=1 for low GPR base with no index
		head = append(append([]byte(nil), cleanPrefixes...), raw[pIdx], vex1, raw[pIdx+2], raw[pIdx+3])
		modrmPos = pIdx + 4
	case 0x0F:
		if pIdx+2 >= len(raw) {
			return guardedScratchPlan{}, false
		}
		switch raw[pIdx+1] {
		case 0x38, 0x3A:
			if pIdx+3 >= len(raw) {
				return guardedScratchPlan{}, false
			}
			head = append(append([]byte(nil), cleanPrefixes...), raw[pIdx], raw[pIdx+1], raw[pIdx+2])
			modrmPos = pIdx + 3
		default:
			head = append(append([]byte(nil), cleanPrefixes...), raw[pIdx], raw[pIdx+1])
			modrmPos = pIdx + 2
		}
	default:
		if pIdx+1 >= len(raw) {
			return guardedScratchPlan{}, false
		}
		head = append(append([]byte(nil), cleanPrefixes...), raw[pIdx])
		modrmPos = pIdx + 1
	}
	if rexIdx >= 0 {
		// Clear REX.X and REX.B before selecting a scratch base register.
		head[rexIdx] &^= 0x03
	}

	origModRM := raw[modrmPos]
	mod := origModRM >> 6
	rm := origModRM & 7
	if mod == 3 {
		return guardedScratchPlan{}, false
	}
	// golang.org/x/arch/x86/x86asm omits Base=RIP and legacy segment overrides
	// on VEX memory operands; restore both from the raw encoding before evaluating effAddr.
	if mod == 0 && rm == 5 && memArg.Base == 0 {
		memArg.Base = x86asm.RIP
	}
	if lastSeg != 0 && memArg.Segment == 0 {
		memArg.Segment = lastSeg
	}
	effAddr, ok := evalX86MemAddr(memArg, pc, inst.Len, fsBase, gsBase, regs, true)
	if !ok {
		return guardedScratchPlan{}, false
	}
	afterMem := modrmPos + 1
	if rm == 4 {
		if afterMem >= len(raw) {
			return guardedScratchPlan{}, false
		}
		sibBase := raw[afterMem] & 7
		afterMem++
		if mod == 0 && sibBase == 5 {
			afterMem += 4
		}
	} else if mod == 0 && rm == 5 {
		afterMem += 4
	}
	switch mod {
	case 1:
		afterMem++
	case 2:
		afterMem++
		afterMem += 3
	}
	if afterMem > len(raw) {
		return guardedScratchPlan{}, false
	}
	tailImm := raw[afterMem:]

	// Candidate scratch GPRs whose [reg] form encodes as mod=00, rm=(reg&7)
	// with no SIB or disp8 (skipping R12=4 and R13=5).
	for _, cand := range []uint8{6, 7, 8, 9, 10, 11, 14, 15} {
		if usedGPR[cand] {
			continue
		}
		candHead := append([]byte(nil), head...)
		if cand >= 8 {
			if isVEX2 || hasHighByteReg {
				continue
			}
			if vex1Idx >= 0 {
				candHead[vex1Idx] &^= 0x20 // ~B = 0 selects R8..R15
			} else if rexIdx >= 0 {
				candHead[rexIdx] |= 0x01
			} else {
				withREX := make([]byte, 0, len(candHead)+1)
				withREX = append(withREX, candHead[:opcodeStartInHead]...)
				withREX = append(withREX, 0x41)
				withREX = append(withREX, candHead[opcodeStartInHead:]...)
				candHead = withREX
			}
		}
		rewritten := make([]byte, 0, len(candHead)+1+len(tailImm))
		rewritten = append(rewritten, candHead...)
		rewritten = append(rewritten, (origModRM&0x38)|(cand&7))
		rewritten = append(rewritten, tailImm...)
		// Leave room in the 28-byte scratch slot for 7-byte restore + 6-byte JMP + >=1 INT3.
		if len(rewritten) > 14 || hasRawKernelExit(rewritten) {
			continue
		}
		chk, cerr := decodeX86(rewritten)
		if cerr != nil || chk.Op != inst.Op || chk.Len != len(rewritten) {
			continue
		}
		return guardedScratchPlan{
			insn:       rewritten,
			useScratch: true,
			scratchReg: cand,
			effAddr:    effAddr,
		}, true
	}
	return guardedScratchPlan{}, false
}
