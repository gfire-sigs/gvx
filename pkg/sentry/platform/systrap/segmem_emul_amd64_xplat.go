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
			if _, w, ok := x86RegIndexWidth(r); ok {
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
