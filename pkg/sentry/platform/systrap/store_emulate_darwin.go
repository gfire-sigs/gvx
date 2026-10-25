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
