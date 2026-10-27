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

//go:build darwin && arm64

package systrap

import "encoding/binary"

// A guest can store to a block that also holds the storing instruction. A 16KB
// block with code and data in it has this shape when the guest links with 4KB
// segment alignment. The engine gives a block write access or execute access,
// never both, so the store cannot run in the stub. The Sentry runs the store
// for the guest instead. This file decodes the store forms that the Sentry
// runs, and computes the bytes and the registers that the instruction changes.

// storeMode is the addressing mode of a store.
type storeMode uint8

const (
	// storeOffset adds an immediate to the base register.
	storeOffset storeMode = iota
	// storePre adds the immediate and writes the sum to the base register
	// before the access.
	storePre
	// storePost uses the base register and adds the immediate after the access.
	storePost
	// storeIndexed adds an extended and shifted index register.
	storeIndexed
)

// storeInsn is a decoded store that the Sentry can run.
type storeInsn struct {
	base, rt, rt2 uint8
	// size is the number of bytes that one register stores.
	size   int
	pair   bool
	vector bool
	mode   storeMode
	// imm is the byte offset of the immediate forms.
	imm int64
	// index, extend, and shift describe the register offset form. The extend
	// field holds the option bits of the instruction.
	index, extend, shift uint8
	// exclusive is true for a store exclusive. The register status receives
	// the result of the store.
	exclusive bool
	status    uint8
}

// storeRegs gives the stores access to the registers of a stopped thread. The
// x18 field points to the virtual x18 of the guest, because the real x18 of
// the stub thread holds no guest value.
type storeRegs struct {
	ss  *armThreadState
	ns  *armNeonState
	x18 *uint64
}

// get returns a general-purpose register. Number 31 is the stack pointer when
// sp is true, and the zero register otherwise.
func (r storeRegs) get(n uint8, sp bool) uint64 {
	return r.ss.getReg(n, *r.x18, sp)
}

// set writes a register that a store updates: the base register of a
// writeback form, or the status register of a store exclusive. Number 31 is the
// stack pointer.
func (r storeRegs) set(n uint8, v uint64) {
	r.ss.setReg(n, v, r.x18, true)
}

// decodeStore decodes the store forms that the Sentry runs: the single register
// and register pair stores of general-purpose and vector registers in every
// immediate and register offset addressing mode, the store exclusive and store
// release forms, and their pair forms. It returns false for every other
// instruction, including atomic read-modify-write operations, compare and swap,
// and tagged stores.
func decodeStore(insn uint32) (storeInsn, bool) {
	s := storeInsn{base: uint8(insn >> 5 & 31), rt: uint8(insn & 31), rt2: uint8(insn >> 10 & 31)}
	v := insn>>26&1 == 1
	s.vector = v
	switch {
	case insn&0x3f000000 == 0x08000000: // Store exclusive and store release.
		if insn>>22&1 != 0 {
			return s, false // A load.
		}
		o2, o1 := insn>>23&1, insn>>21&1
		s.size = 1 << (insn >> 30)
		switch {
		case o2 == 0 && o1 == 0: // STXR and STLXR.
			s.exclusive, s.status = true, uint8(insn>>16&31)
		case o2 == 0 && o1 == 1 && insn>>30 >= 2: // STXP and STLXP.
			s.pair, s.exclusive, s.status = true, true, uint8(insn>>16&31)
		case o2 == 1 && o1 == 0: // STLR and STLLR.
		default:
			return s, false // Compare and swap, and the reserved encodings.
		}
		return s, true
	case insn&0x3a000000 == 0x28000000: // Store pair.
		if insn>>22&1 != 0 {
			return s, false // A load.
		}
		opc := insn >> 30
		switch {
		case !v && opc == 0:
			s.size = 4
		case !v && opc == 2:
			s.size = 8
		case v && opc <= 2:
			s.size = 4 << opc
		default:
			return s, false // STGP and the reserved encodings.
		}
		s.pair = true
		s.imm = int64(int32(insn>>15&0x7f)<<25>>25) * int64(s.size)
		switch insn >> 23 & 3 {
		case 0, 2:
			s.mode = storeOffset
		case 1:
			s.mode = storePost
		default:
			s.mode = storePre
		}
		return s, true
	case insn&0x3b000000 == 0x39000000: // Store with an unsigned immediate.
		size, ok := singleStoreSize(insn, v)
		if !ok {
			return s, false
		}
		s.size = size
		s.imm = int64(insn>>10&0xfff) * int64(size)
		return s, true
	case insn&0x3b200000 == 0x38000000: // Store with a signed immediate.
		size, ok := singleStoreSize(insn, v)
		if !ok {
			return s, false
		}
		s.size = size
		s.imm = int64(int32(insn>>12&0x1ff) << 23 >> 23)
		switch insn >> 10 & 3 {
		case 0, 2: // STUR and the unprivileged STTR, which behaves as STR at EL0.
			s.mode = storeOffset
		case 1:
			s.mode = storePost
		default:
			s.mode = storePre
		}
		return s, true
	case insn&0x3b200c00 == 0x38200800: // Store with a register offset.
		size, ok := singleStoreSize(insn, v)
		if !ok {
			return s, false
		}
		s.size = size
		s.mode = storeIndexed
		s.index = uint8(insn >> 16 & 31)
		s.extend = uint8(insn >> 13 & 7)
		if s.extend != 2 && s.extend != 3 && s.extend != 6 && s.extend != 7 {
			return s, false
		}
		if insn>>12&1 == 1 {
			for n := size; n > 1; n >>= 1 {
				s.shift++
			}
		}
		return s, true
	}
	return s, false
}

// singleStoreSize returns the byte count of a single register store, or false
// when the encoding is not a store. The size and opc fields tell the width.
func singleStoreSize(insn uint32, vector bool) (int, bool) {
	size, opc := int(insn>>30), insn>>22&3
	switch {
	case opc == 0:
		return 1 << size, true
	case vector && opc == 2 && size == 0:
		return 16, true
	}
	return 0, false
}

// address returns the address of the first stored register and the value that
// the instruction writes to its base register.
func (s storeInsn) address(r storeRegs) (addr, newBase uint64, writeback bool) {
	base := r.get(s.base, true)
	switch s.mode {
	case storePre:
		addr = base + uint64(s.imm)
		return addr, addr, true
	case storePost:
		return base, base + uint64(s.imm), true
	case storeIndexed:
		idx := r.get(s.index, false)
		switch s.extend {
		case 2:
			idx = uint64(uint32(idx))
		case 6:
			idx = uint64(int64(int32(idx)))
		}
		return base + idx<<s.shift, 0, false
	}
	return base + uint64(s.imm), 0, false
}

// value returns the bytes that register n of the instruction stores.
func (s storeInsn) value(r storeRegs, n uint8) []byte {
	out := make([]byte, s.size)
	if s.vector {
		copy(out, r.ns.V[n][:s.size])
		return out
	}
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], r.get(n, false))
	copy(out, word[:s.size])
	return out
}

// execute runs the store. The check function reports whether the range
// [addr, addr+n) can take the write, and the write function stores the bytes.
// Nothing changes unless check accepts the range. It returns the address of the
// first stored byte, and false when the check refused the range.
//
// The Sentry cannot arm the exclusive monitor of the hardware for the guest,
// so a store exclusive reports success. Two threads that run exclusive
// read-modify-write loops on one word of a shared page can lose updates.
func (s storeInsn) execute(r storeRegs, check func(addr uint64, n int) bool, write func(addr uint64, b []byte)) (uint64, bool) {
	addr, newBase, writeback := s.address(r)
	total := s.size
	if s.pair {
		total *= 2
	}
	if !check(addr, total) {
		return addr, false
	}
	write(addr, s.value(r, s.rt))
	if s.pair {
		write(addr+uint64(s.size), s.value(r, s.rt2))
	}
	if s.exclusive && s.status != 31 {
		r.set(s.status, 0)
	}
	if writeback {
		r.set(s.base, newBase)
	}
	return addr, true
}

// evalExclusiveALU evaluates a single-instruction register or immediate ALU
// operation (ADD, SUB, AND, ORR, EOR, BIC, ORN, EON) that updates rtOld in
// place between a load-exclusive and a store-exclusive instruction, replacing
// the stale value in rtOld with curVal.
func evalExclusiveALU(insn uint32, rtOld uint8, curVal uint64, r storeRegs) (uint64, bool) {
	rd := uint8(insn & 31)
	rn := uint8((insn >> 5) & 31)
	if rd != rtOld {
		return 0, false
	}
	sf := (insn >> 31) & 1
	mask := uint64(^uint32(0))
	if sf == 1 {
		mask = ^uint64(0)
	}
	switch {
	case insn&0x1f000000 == 0x11000000: // Add or subtract (immediate).
		if rn != rtOld {
			return 0, false
		}
		imm := uint64((insn >> 10) & 0xfff)
		if (insn>>22)&1 == 1 {
			imm <<= 12
		}
		if (insn>>30)&1 == 1 {
			return (curVal - imm) & mask, true
		}
		return (curVal + imm) & mask, true
	case insn&0x1f200000 == 0x0b000000: // Add or subtract (shifted register).
		rm := uint8((insn >> 16) & 31)
		if (rn != rtOld && rm != rtOld) || (rn == rtOld && rm == rtOld) {
			return 0, false
		}
		a := curVal
		if rn != rtOld {
			a = r.get(rn, false)
		}
		b := curVal
		if rm != rtOld {
			b = r.get(rm, false)
		}
		b = shiftALUOperand(b, (insn>>22)&3, (insn>>10)&0x3f, sf == 1)
		if (insn>>30)&1 == 1 {
			return (a - b) & mask, true
		}
		return (a + b) & mask, true
	case insn&0x1f000000 == 0x0a000000: // Logical (shifted register).
		rm := uint8((insn >> 16) & 31)
		if (rn != rtOld && rm != rtOld) || (rn == rtOld && rm == rtOld) {
			return 0, false
		}
		a := curVal
		if rn != rtOld {
			a = r.get(rn, false)
		}
		b := curVal
		if rm != rtOld {
			b = r.get(rm, false)
		}
		b = shiftALUOperand(b, (insn>>22)&3, (insn>>10)&0x3f, sf == 1)
		if (insn>>21)&1 == 1 {
			b = ^b
		}
		switch (insn >> 29) & 3 {
		case 0, 3: // AND, BIC, ANDS, BICS.
			return (a & b) & mask, true
		case 1: // ORR, ORN.
			return (a | b) & mask, true
		case 2: // EOR, EON.
			return (a ^ b) & mask, true
		}
	}
	return 0, false
}

func shiftALUOperand(v uint64, shiftType, amount uint32, is64 bool) uint64 {
	if !is64 {
		v32 := uint32(v)
		amount &= 31
		switch shiftType {
		case 0:
			return uint64(v32 << amount)
		case 1:
			return uint64(v32 >> amount)
		case 2:
			return uint64(uint32(int32(v32) >> amount))
		case 3:
			return uint64((v32 >> amount) | (v32 << ((32 - amount) & 31)))
		}
	}
	amount &= 63
	switch shiftType {
	case 0:
		return v << amount
	case 1:
		return v >> amount
	case 2:
		return uint64(int64(v) >> amount)
	case 3:
		return (v >> amount) | (v << ((64 - amount) & 63))
	}
	return v
}

func maskBySize(size int) uint64 {
	switch size {
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

func signExtendBySize(v uint64, size int) int64 {
	switch size {
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

func decodeLEUint(b []byte) uint64 {
	switch len(b) {
	case 1:
		return uint64(b[0])
	case 2:
		return uint64(binary.LittleEndian.Uint16(b))
	case 4:
		return uint64(binary.LittleEndian.Uint32(b))
	case 8:
		return binary.LittleEndian.Uint64(b)
	}
	return 0
}

func encodeLEUint(v uint64, size int) []byte {
	var word [8]byte
	binary.LittleEndian.PutUint64(word[:], v)
	out := make([]byte, size)
	copy(out, word[:size])
	return out
}

// emulateAtomicOrCacheOp runs an AArch64 LSE atomic operation (LDADD, LDCLR,
// LDEOR, LDSET, LDSMAX, LDSMIN, LDUMAX, LDUMIN, SWP, CAS, CASP) or an
// address-based cache maintenance instruction (DC ZVA and cache clean or
// invalidate ops).
func emulateAtomicOrCacheOp(
	insn uint32,
	r storeRegs,
	check func(addr uint64, n int) bool,
	read func(addr uint64, n int) []byte,
	write func(addr uint64, b []byte),
) (uint64, bool) {
	if isCacheMaintenanceByAddress(insn) {
		rt := uint8(insn & 31)
		if rt == 31 {
			return 0, false
		}
		addr := r.get(rt, false)
		if insn&^31 == 0xd50b7420 { // dc zva
			const zvaSize = 64
			line := addr &^ (zvaSize - 1)
			if !check(line, zvaSize) {
				return line, false
			}
			var zeros [zvaSize]byte
			write(line, zeros[:])
			return line, true
		}
		if !check(addr, 1) {
			return addr, false
		}
		return addr, true
	}

	switch {
	case insn&0x3f200c00 == 0x38200000: // LD<op> and SWP.
		size := 1 << (insn >> 30)
		rn := uint8(insn >> 5 & 31)
		rs := uint8(insn >> 16 & 31)
		rt := uint8(insn & 31)
		addr := r.get(rn, true)
		if !check(addr, size) {
			return addr, false
		}
		mask := maskBySize(size)
		oldVal := decodeLEUint(read(addr, size)) & mask
		srcVal := r.get(rs, false) & mask
		o3 := insn >> 15 & 1
		opc := insn >> 12 & 7
		var newVal uint64
		switch {
		case o3 == 1 && opc == 0: // SWP
			newVal = srcVal
		case o3 == 0 && opc == 0: // LDADD
			newVal = (oldVal + srcVal) & mask
		case o3 == 0 && opc == 1: // LDCLR
			newVal = oldVal &^ srcVal
		case o3 == 0 && opc == 2: // LDEOR
			newVal = oldVal ^ srcVal
		case o3 == 0 && opc == 3: // LDSET
			newVal = oldVal | srcVal
		case o3 == 0 && opc == 4: // LDSMAX
			if signExtendBySize(oldVal, size) >= signExtendBySize(srcVal, size) {
				newVal = oldVal
			} else {
				newVal = srcVal
			}
		case o3 == 0 && opc == 5: // LDSMIN
			if signExtendBySize(oldVal, size) <= signExtendBySize(srcVal, size) {
				newVal = oldVal
			} else {
				newVal = srcVal
			}
		case o3 == 0 && opc == 6: // LDUMAX
			if oldVal >= srcVal {
				newVal = oldVal
			} else {
				newVal = srcVal
			}
		case o3 == 0 && opc == 7: // LDUMIN
			if oldVal <= srcVal {
				newVal = oldVal
			} else {
				newVal = srcVal
			}
		default:
			return addr, false
		}
		write(addr, encodeLEUint(newVal, size))
		if rt != 31 {
			r.ss.setReg(rt, oldVal, r.x18, false)
		}
		return addr, true

	case insn&0x3fa07c00 == 0x08a07c00: // CAS.
		size := 1 << (insn >> 30)
		rn := uint8(insn >> 5 & 31)
		rs := uint8(insn >> 16 & 31)
		rt := uint8(insn & 31)
		addr := r.get(rn, true)
		if !check(addr, size) {
			return addr, false
		}
		mask := maskBySize(size)
		oldVal := decodeLEUint(read(addr, size)) & mask
		cmpVal := r.get(rs, false) & mask
		if oldVal == cmpVal {
			newVal := r.get(rt, false) & mask
			write(addr, encodeLEUint(newVal, size))
		}
		if rs != 31 {
			r.ss.setReg(rs, oldVal, r.x18, false)
		}
		return addr, true

	case insn&0xbfa07c00 == 0x08207c00: // CASP.
		size := 4 << (insn >> 30 & 1)
		rn := uint8(insn >> 5 & 31)
		rs := uint8(insn >> 16 & 31)
		rt := uint8(insn & 31)
		if rs&1 != 0 || rt&1 != 0 || rs >= 30 || rt >= 30 {
			return 0, false
		}
		addr := r.get(rn, true)
		if !check(addr, size*2) {
			return addr, false
		}
		mask := maskBySize(size)
		raw := read(addr, size*2)
		old0 := decodeLEUint(raw[:size]) & mask
		old1 := decodeLEUint(raw[size:]) & mask
		cmp0 := r.get(rs, false) & mask
		cmp1 := r.get(rs+1, false) & mask
		if old0 == cmp0 && old1 == cmp1 {
			buf := make([]byte, size*2)
			copy(buf[:size], encodeLEUint(r.get(rt, false)&mask, size))
			copy(buf[size:], encodeLEUint(r.get(rt+1, false)&mask, size))
			write(addr, buf)
		}
		r.ss.setReg(rs, old0, r.x18, false)
		r.ss.setReg(rs+1, old1, r.x18, false)
		return addr, true

	case insn>>31 == 0 && (insn&0xbf000000 == 0x0c000000 || insn&0xbf000000 == 0x0d000000):
		return emulateSIMDStoreStructure(insn, r, check, write)
	}
	return 0, false
}

// decodeSIMDStructMultiple decodes an AdvSIMD load or store multiple structures
// instruction (LD1..LD4 or ST1..ST4).
func decodeSIMDStructMultiple(insn uint32) (nregs, selem, regBytes, esize int, post, load bool, rn, rm, rt uint8, ok bool) {
	if insn>>31 != 0 || insn&0xbf000000 != 0x0c000000 {
		return
	}
	post = insn>>23&1 == 1
	load = insn>>22&1 == 1
	rm = uint8(insn >> 16 & 31)
	if post {
		if insn>>21&1 != 0 {
			return
		}
	} else if insn>>16&0x3f != 0 {
		return
	}
	q := int(insn >> 30 & 1)
	regBytes = 8 << q
	size := int(insn >> 10 & 3)
	esize = 1 << size
	if esize > regBytes {
		return
	}
	switch insn >> 12 & 0xf {
	case 0b0000:
		nregs, selem = 4, 4
	case 0b0010:
		nregs, selem = 4, 1
	case 0b0100:
		nregs, selem = 3, 3
	case 0b0110:
		nregs, selem = 3, 1
	case 0b0111:
		nregs, selem = 1, 1
	case 0b1000:
		nregs, selem = 2, 2
	case 0b1010:
		nregs, selem = 2, 1
	default:
		return
	}
	if esize == 8 && q == 0 && selem > 1 {
		return
	}
	rn = uint8(insn >> 5 & 31)
	rt = uint8(insn & 31)
	ok = true
	return
}

// decodeSIMDStructSingle decodes an AdvSIMD load or store single structure
// instruction (LD1..LD4, LD1R..LD4R, or ST1..ST4).
func decodeSIMDStructSingle(insn uint32) (selem, esize, index, regBytes int, replicate, post, load bool, rn, rm, rt uint8, ok bool) {
	if insn>>31 != 0 || insn&0xbf000000 != 0x0d000000 {
		return
	}
	post = insn>>23&1 == 1
	load = insn>>22&1 == 1
	rm = uint8(insn >> 16 & 31)
	if !post && rm != 0 {
		return
	}
	q := int(insn >> 30 & 1)
	regBytes = 8 << q
	rBit := int(insn >> 21 & 1)
	opcode := int(insn >> 13 & 7)
	sBit := int(insn >> 12 & 1)
	size := int(insn >> 10 & 3)
	selem = ((opcode&1)<<1 | rBit) + 1
	switch opcode >> 1 {
	case 0:
		esize = 1
		index = (q << 3) | (sBit << 2) | size
	case 1:
		if size&1 != 0 {
			return
		}
		esize = 2
		index = (q << 2) | (sBit << 1) | (size >> 1)
	case 2:
		if size == 0 {
			esize = 4
			index = (q << 1) | sBit
		} else if size == 1 && sBit == 0 {
			esize = 8
			index = q
		} else {
			return
		}
	case 3:
		if !load || sBit != 0 || (size == 3 && q == 0) {
			return
		}
		esize = 1 << size
		replicate = true
	}
	rn = uint8(insn >> 5 & 31)
	rt = uint8(insn & 31)
	ok = true
	return
}

func emulateSIMDStoreStructure(
	insn uint32,
	r storeRegs,
	check func(addr uint64, n int) bool,
	write func(addr uint64, b []byte),
) (uint64, bool) {
	if nregs, selem, regBytes, esize, post, load, rn, rm, rt, ok := decodeSIMDStructMultiple(insn); ok && !load {
		base := r.get(rn, true)
		total := nregs * regBytes
		if !check(base, total) {
			return base, false
		}
		buf := make([]byte, total)
		if selem == 1 {
			for i := 0; i < nregs; i++ {
				vreg := (rt + uint8(i)) & 31
				copy(buf[i*regBytes:(i+1)*regBytes], r.ns.V[vreg][:regBytes])
			}
		} else {
			elems := regBytes / esize
			off := 0
			for e := 0; e < elems; e++ {
				for s := 0; s < selem; s++ {
					vreg := (rt + uint8(s)) & 31
					copy(buf[off:off+esize], r.ns.V[vreg][e*esize:(e+1)*esize])
					off += esize
				}
			}
		}
		write(base, buf)
		if post {
			inc := uint64(total)
			if rm != 31 {
				inc = r.get(rm, false)
			}
			r.set(rn, base+inc)
		}
		return base, true
	}
	if selem, esize, index, _, _, post, load, rn, rm, rt, ok := decodeSIMDStructSingle(insn); ok && !load {
		base := r.get(rn, true)
		total := selem * esize
		if !check(base, total) {
			return base, false
		}
		buf := make([]byte, total)
		for s := 0; s < selem; s++ {
			vreg := (rt + uint8(s)) & 31
			copy(buf[s*esize:(s+1)*esize], r.ns.V[vreg][index*esize:(index+1)*esize])
		}
		write(base, buf)
		if post {
			inc := uint64(total)
			if rm != 31 {
				inc = r.get(rm, false)
			}
			r.set(rn, base+inc)
		}
		return base, true
	}
	return 0, false
}

// emulateLoad decodes and runs a general-purpose or vector load instruction
// when a zone memory access cannot be patched in place (such as an access
// through the stack pointer).
func emulateLoad(insn uint32, r storeRegs, read func(addr uint64, n int) ([]byte, bool)) bool {
	baseReg := uint8(insn >> 5 & 31)
	rt := uint8(insn & 31)
	rt2 := uint8(insn >> 10 & 31)
	v := insn>>26&1 == 1

	applyLoadReg := func(reg uint8, data []byte, signed bool, sixtyFour bool) {
		if v {
			clear(r.ns.V[reg][:])
			copy(r.ns.V[reg][:], data)
			return
		}
		if reg == 31 {
			return
		}
		val := decodeLEUint(data)
		if signed {
			sval := signExtendBySize(val, len(data))
			if sixtyFour {
				val = uint64(sval)
			} else {
				val = uint64(uint32(sval))
			}
		}
		r.ss.setReg(reg, val, r.x18, false)
	}

	switch {
	case insn&0x3f000000 == 0x08000000: // Load exclusive / load acquire.
		if insn>>22&1 == 0 {
			return false
		}
		o2, o1 := insn>>23&1, insn>>21&1
		size := 1 << (insn >> 30)
		pair := o2 == 0 && o1 == 1
		if o2 == 1 && o1 == 1 {
			return false
		}
		addr := r.get(baseReg, true)
		total := size
		if pair {
			total *= 2
		}
		data, ok := read(addr, total)
		if !ok {
			return false
		}
		applyLoadReg(rt, data[:size], false, true)
		if pair {
			applyLoadReg(rt2, data[size:], false, true)
		}
		return true

	case insn&0x3a000000 == 0x28000000: // Load pair.
		if insn>>22&1 == 0 {
			return false
		}
		opc := insn >> 30
		var size int
		signed := false
		switch {
		case !v && opc == 0:
			size = 4
		case !v && opc == 1:
			size = 4
			signed = true
		case !v && opc == 2:
			size = 8
		case v && opc <= 2:
			size = 4 << opc
		default:
			return false
		}
		imm := int64(int32(insn>>15&0x7f)<<25>>25) * int64(size)
		base := r.get(baseReg, true)
		addr := base + uint64(imm)
		mode := insn >> 23 & 3
		if mode == 1 {
			addr = base
		}
		data, ok := read(addr, size*2)
		if !ok {
			return false
		}
		if mode == 1 || mode == 3 {
			r.set(baseReg, base+uint64(imm))
		}
		applyLoadReg(rt, data[:size], signed, true)
		applyLoadReg(rt2, data[size:], signed, true)
		return true

	case insn&0x3b000000 == 0x39000000, insn&0x3b200000 == 0x38000000, insn&0x3b200c00 == 0x38200800:
		sizeBits := int(insn >> 30)
		opc := insn >> 22 & 3
		if opc == 0 {
			return false
		}
		var size int
		signed := false
		sixtyFour := false
		if v {
			if opc == 1 {
				size = 1 << sizeBits
			} else if opc == 3 && sizeBits == 0 {
				size = 16
			} else {
				return false
			}
		} else {
			size = 1 << sizeBits
			switch opc {
			case 1:
				signed = false
			case 2:
				if sizeBits >= 3 {
					return false
				}
				signed = true
				sixtyFour = true
			case 3:
				if sizeBits >= 2 {
					return false
				}
				signed = true
				sixtyFour = false
			}
		}
		base := r.get(baseReg, true)
		var addr, newBase uint64
		writeback := false
		switch {
		case insn&0x3b000000 == 0x39000000:
			addr = base + uint64(insn>>10&0xfff)*uint64(size)
		case insn&0x3b200c00 == 0x38200800:
			rm := uint8(insn >> 16 & 31)
			extend := uint8(insn >> 13 & 7)
			if extend != 2 && extend != 3 && extend != 6 && extend != 7 {
				return false
			}
			idx := r.get(rm, false)
			switch extend {
			case 2:
				idx = uint64(uint32(idx))
			case 6:
				idx = uint64(int64(int32(idx)))
			}
			var shift uint8
			if insn>>12&1 == 1 {
				for n := size; n > 1; n >>= 1 {
					shift++
				}
			}
			addr = base + idx<<shift
		default:
			imm := int64(int32(insn>>12&0x1ff) << 23 >> 23)
			switch insn >> 10 & 3 {
			case 0, 2:
				addr = base + uint64(imm)
			case 1:
				addr = base
				newBase = base + uint64(imm)
				writeback = true
			case 3:
				addr = base + uint64(imm)
				newBase = addr
				writeback = true
			}
		}
		data, ok := read(addr, size)
		if !ok {
			return false
		}
		if writeback {
			r.set(baseReg, newBase)
		}
		applyLoadReg(rt, data, signed, sixtyFour)
		return true

	case insn>>31 == 0 && (insn&0xbf000000 == 0x0c000000 || insn&0xbf000000 == 0x0d000000):
		return emulateSIMDLoadStructure(insn, r, read)
	}
	return false
}

func emulateSIMDLoadStructure(insn uint32, r storeRegs, read func(addr uint64, n int) ([]byte, bool)) bool {
	if nregs, selem, regBytes, esize, post, load, rn, rm, rt, ok := decodeSIMDStructMultiple(insn); ok && load {
		base := r.get(rn, true)
		total := nregs * regBytes
		buf, ok := read(base, total)
		if !ok {
			return false
		}
		if selem == 1 {
			for i := 0; i < nregs; i++ {
				vreg := (rt + uint8(i)) & 31
				clear(r.ns.V[vreg][:])
				copy(r.ns.V[vreg][:regBytes], buf[i*regBytes:(i+1)*regBytes])
			}
		} else {
			for s := 0; s < selem; s++ {
				clear(r.ns.V[(rt+uint8(s))&31][:])
			}
			elems := regBytes / esize
			off := 0
			for e := 0; e < elems; e++ {
				for s := 0; s < selem; s++ {
					vreg := (rt + uint8(s)) & 31
					copy(r.ns.V[vreg][e*esize:(e+1)*esize], buf[off:off+esize])
					off += esize
				}
			}
		}
		if post {
			inc := uint64(total)
			if rm != 31 {
				inc = r.get(rm, false)
			}
			r.set(rn, base+inc)
		}
		return true
	}
	if selem, esize, index, regBytes, replicate, post, load, rn, rm, rt, ok := decodeSIMDStructSingle(insn); ok && load {
		base := r.get(rn, true)
		total := selem * esize
		buf, ok := read(base, total)
		if !ok {
			return false
		}
		for s := 0; s < selem; s++ {
			vreg := (rt + uint8(s)) & 31
			elem := buf[s*esize : (s+1)*esize]
			if replicate {
				clear(r.ns.V[vreg][:])
				for off := 0; off < regBytes; off += esize {
					copy(r.ns.V[vreg][off:off+esize], elem)
				}
			} else {
				copy(r.ns.V[vreg][index*esize:(index+1)*esize], elem)
			}
		}
		if post {
			inc := uint64(total)
			if rm != 31 {
				inc = r.get(rm, false)
			}
			r.set(rn, base+inc)
		}
		return true
	}
	return false
}
