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

import (
	"encoding/binary"
	"fmt"
)

// Every arm64 task on macOS has a 4GB PAGEZERO, so a Linux executable that
// links below 4GB (type ET_EXEC) cannot map at its own addresses. The zone
// mode gives such an executable a bias. The guest sees the addresses that the
// linker chose, and the stub task holds the memory at the same address plus
// zoneBias.
//
// The stub runs the code at the biased addresses, because the hardware needs
// them. A guest pointer into the zone keeps its unbiased value, so a load or a
// store through it faults. The Sentry then replaces that instruction by a
// branch to a slot. The slot adds the bias to the base register, runs the
// instruction, and removes the bias again. The test of one bit tells a pointer
// of the zone from every other pointer, because the memory manager keeps every
// other mapping above zoneBias.
const (
	// zoneBias is the distance between a guest address of the zone and the
	// address of the same byte in the stub. It is a single bit above every
	// zone address, and every guest mapping outside the zone lies above it.
	zoneBias = 1 << zoneBiasBit
	// zoneBiasBit is the bit that a slot tests.
	zoneBiasBit = 46
	// zoneMin is the lowest guest address of the zone, the default of the
	// Linux mmap_min_addr.
	zoneMin = 0x10000
	// zoneLimit is the first guest address above the zone.
	zoneLimit = 1 << 32
)

// The slot sizes in bytes.
const (
	memSlotSize  = 80
	adrpSlotSize = 16
	brSlotSize   = 16
	blrSlotSize  = 32
)

// The words of the zone slots.
const (
	zoneMOVK    = 0xf2800000
	zoneBiasOrr = 0xb2520000 // orr xd, xn, #zoneBias
	zoneBiasAnd = 0x9251f800 // and xd, xn, #^zoneBias
	zoneMovX16  = 0xaa0003f0 // mov x16, xm with m in bits 20:16
	zoneMovX17  = 0xaa0003f1 // mov x17, xm with m in bits 20:16
	zoneBrReg   = 0xd61f0000 // br xn with n in bits 9:5
)

// siteKind values of the zone classes.
const (
	// siteMem is a load or a store through a base register that can hold a
	// pointer of the zone.
	siteMem siteKind = iota + 200
	// siteAdrp is an adr or adrp whose result lies in the zone.
	siteAdrp
	// siteIndirect is a br or blr through a register.
	siteIndirect
)

// Flags of a memory slot, stored in slotMeta.scratch.
const (
	memSkipsRestore = 1 << iota
	memFixesValue
)

// inZoneGuest reports whether a guest address lies in the zone.
func inZoneGuest(a uint64) bool { return a >= zoneMin && a < zoneLimit }

// inZoneStub reports whether a stub address holds a byte of the zone.
func inZoneStub(a uint64) bool { return a >= zoneBias+zoneMin && a < zoneBias+zoneLimit }

// memAccess describes how a slot must treat one load or store.
type memAccess struct {
	// base is the base register. It is never the stack pointer.
	base uint8
	// index is the second register of the address in the register offset form.
	index uint8
	// hasIndex is true for the register offset form.
	hasIndex bool
	// skipsRestore is true when the instruction writes the base register as
	// a result, so the slot must not clear the bias after it.
	skipsRestore bool
	// storeFirst and storeSecond are true when the first or the second stored
	// register is the base register. The slot then hands the unbiased value to
	// the instruction in a scratch register.
	storeFirst, storeSecond bool
}

// fixesValue reports whether the slot must replace a stored register.
func (a memAccess) fixesValue() bool { return a.storeFirst || a.storeSecond }

// classifyMemAccess decodes a load, a store, or a cache maintenance
// instruction by address. It returns false for every instruction that no slot
// covers. Examples are a literal load, an access through the stack pointer,
// and a form whose registers collide with the base.
func classifyMemAccess(insn uint32) (memAccess, bool) {
	rn := uint8(insn >> 5 & 31)
	rt := uint8(insn & 31)
	rt2 := uint8(insn >> 10 & 31)
	rm := uint8(insn >> 16 & 31)
	acc := memAccess{base: rn, index: 31}
	if isCacheMaintenanceByAddress(insn) {
		// The address register is Rt. Rt 31 is the zero register, which names
		// no address.
		if rt == 31 {
			return acc, false
		}
		return memAccess{base: rt, index: 31}, true
	}
	if rn == 31 {
		return acc, false
	}
	pairForm := false
	load := insn>>22&1 == 1
	switch {
	case insn&0x3b000000 == 0x18000000:
		return acc, false // LDR literal and PRFM literal use the program counter.
	case insn&0x3f000000 == 0x08000000: // Exclusive, ordered, and compare and swap.
		o2, o1 := insn>>23&1, insn>>21&1
		if o2 == 1 && o1 == 1 { // CAS and CASP: Rs and Rt carry values.
			if rm == rn || rt == rn {
				return acc, false
			}
			break
		}
		pair := o2 == 0 && o1 == 1
		pairForm = pair
		if o2 == 0 && !load && rm == rn {
			return acc, false // The status register of a store exclusive.
		}
		if load {
			acc.skipsRestore = rt == rn || (pair && rt2 == rn)
		} else {
			acc.storeFirst = rt == rn
			acc.storeSecond = pair && rt2 == rn
		}
	case insn&0x3a000000 == 0x28000000: // Load and store pair.
		pairForm = true
		if insn>>26&1 == 0 {
			if load {
				acc.skipsRestore = rt == rn || rt2 == rn
			} else {
				acc.storeFirst = rt == rn
				acc.storeSecond = rt2 == rn
			}
		}
	case insn&0x3a000000 == 0x38000000: // Load and store register.
		v := insn >> 26 & 1
		switch {
		case insn&0x3b200c00 == 0x38200800: // Register offset.
			acc.hasIndex, acc.index = true, rm
			acc.classifySingle(insn, v, rt, rn)
		case insn&0x3b200c00 == 0x38200000: // Atomic read-modify-write.
			if v != 0 || rm == rn {
				return acc, false
			}
			acc.skipsRestore = rt == rn
		case insn&0x01000000 == 0 && insn&0x00200000 != 0:
			// Pointer authentication and the other forms of bit 21. The form
			// with a 12-bit offset uses bit 21 as part of the offset.
			return acc, false
		default: // Immediate, unscaled, pre-index, post-index, and unprivileged.
			acc.classifySingle(insn, v, rt, rn)
		}
	case insn&0xbf000000 == 0x0c000000, insn&0xbf000000 == 0x0d000000: // Structure loads and stores.
	default:
		return acc, false
	}
	if acc.fixesValue() {
		// The slot borrows x16 and x17 for the stored values, so no other
		// register of the instruction may be one of them.
		scratch := func(r uint8) bool { return r == 16 || r == 17 }
		if scratch(rn) || (acc.hasIndex && scratch(acc.index)) || (pairForm && (scratch(rt) || scratch(rt2))) {
			return acc, false
		}
	}
	return acc, true
}

// isCacheMaintenanceByAddress reports whether insn is a system instruction
// that names an address in Rt: DC ZVA, DC IVAC, DC CVAC, DC CVAU, DC CVAP,
// DC CVADP, DC CIVAC, and IC IVAU. Such an instruction faults on an address
// that is not mapped, like a store does. The forms by set and way name no
// address, and they are not in the list.
func isCacheMaintenanceByAddress(insn uint32) bool {
	switch insn &^ 31 {
	case 0xd50b7420, // dc zva
		0xd5087620, // dc ivac
		0xd50b7a20, // dc cvac
		0xd50b7b20, // dc cvau
		0xd50b7c20, // dc cvap
		0xd50b7d20, // dc cvadp
		0xd50b7e20, // dc civac
		0xd50b7520: // ic ivau
		return true
	}
	return false
}

// classifySingle sets the collision flags of a single-register access. A
// vector register never collides with the base.
func (a *memAccess) classifySingle(insn, v uint32, rt, rn uint8) {
	if v != 0 || rt != rn {
		return
	}
	if insn>>22&3 != 0 {
		a.skipsRestore = true
	} else {
		a.storeFirst = true
	}
}

// encodeTBNZ returns tbnz xt, #bit with a branch of delta bytes. The bit
// number must be 32 or more, which is the case for every bit that a slot tests.
func encodeTBNZ(rt uint8, bit uint, delta int) uint32 {
	return 0x37000000 | 1<<31 | uint32(bit-32)<<19 | uint32(delta/4)&0x3fff<<5 | uint32(rt)
}

func encodeBiasTBNZ(rt uint8, delta int) uint32 { return encodeTBNZ(rt, zoneBiasBit, delta) }

func encodeBiasOrr(rd, rn uint8) uint32      { return zoneBiasOrr | uint32(rn)<<5 | uint32(rd) }
func encodeBiasAnd(rd, rn uint8) uint32      { return zoneBiasAnd | uint32(rn)<<5 | uint32(rd) }
func encodeMovZ(rd uint8, imm uint64) uint32 { return arm64MOVZ | uint32(imm&0xffff)<<5 | uint32(rd) }
func encodeMovK(rd uint8, imm uint64, shift uint) uint32 {
	return zoneMOVK | uint32(shift/16)<<21 | uint32(imm&0xffff)<<5 | uint32(rd)
}

// encodeMemSlot writes the slot of a load or store at site into buf. It
// returns the byte size of the slot and the word index of the biased copy of
// the instruction.
//
// The biased path tests the bias bit of the base register. A set bit leads to
// the plain copy of the instruction. A clear bit means the guest holds a
// pointer of the zone, so the slot adds the bias, runs the instruction, and
// removes it. In the register offset form the index can hold the pointer or an
// offset. A negative index is an offset, so only the base decides. Another
// index with the bias bit set is a pointer outside the zone, and the plain copy
// runs.
func encodeMemSlot(buf []byte, slotVA, site uint64, insn uint32, acc memAccess) (size, body int, err error) {
	// The first words test the registers. One word tests the base register.
	// The register offset form has two more words that test the index.
	tests := 1
	if acc.hasIndex {
		tests = 3
	}
	w := make([]uint32, tests, memSlotSize/4)
	biased := insn
	if acc.fixesValue() {
		ptr := sysmsgPointer()
		w = append(w, ptr[0], ptr[1],
			strFromSysmsg(16, scratchOffset),
			strFromSysmsg(17, scratchOffset+8))
		if acc.storeFirst {
			w = append(w, zoneMovX16|uint32(acc.base)<<16)
			biased = biased&^0x1f | 16
		}
		if acc.storeSecond {
			w = append(w, zoneMovX17|uint32(acc.base)<<16)
			biased = biased&^(0x1f<<10) | 17<<10
		}
	}
	w = append(w, encodeBiasOrr(acc.base, acc.base))
	body = len(w)
	w = append(w, biased)
	if !acc.skipsRestore {
		w = append(w, encodeBiasAnd(acc.base, acc.base))
	}
	if acc.fixesValue() {
		ptr := sysmsgPointer()
		w = append(w, ptr[0], ptr[1],
			ldrFromSysmsg(16, scratchOffset),
			ldrFromSysmsg(17, scratchOffset+8))
	}
	back, err := encodeBranch(slotVA+uint64(len(w))*4, site+4)
	if err != nil {
		return 0, 0, err
	}
	w = append(w, back)
	plain := len(w)
	w = append(w, insn)
	back, err = encodeBranch(slotVA+uint64(len(w))*4, site+4)
	if err != nil {
		return 0, 0, err
	}
	w = append(w, back)
	if len(w)*4 > memSlotSize || len(buf) < memSlotSize {
		return 0, 0, fmt.Errorf("memory slot has %d words in a buffer of %d bytes", len(w), len(buf))
	}
	// The tests lie at the start of the slot. In the register offset form the
	// first test skips the test of the index when the index is negative.
	if acc.hasIndex {
		w[0] = encodeTBNZ(acc.index, 63, 2*4)
		w[1] = encodeTBNZ(acc.index, zoneBiasBit, (plain-1)*4)
		w[2] = encodeTBNZ(acc.base, zoneBiasBit, (plain-2)*4)
	} else {
		w[0] = encodeTBNZ(acc.base, zoneBiasBit, plain*4)
	}
	for len(w)*4 < memSlotSize {
		w = append(w, arm64NOP)
	}
	for i, v := range w {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	return memSlotSize, body, nil
}

// encodeAdrpSlot writes a slot that loads the guest address value into rd and
// returns to site+4. It replaces an adr or adrp whose result is in the zone.
func encodeAdrpSlot(buf []byte, slotVA, site uint64, rd uint8, value uint64) error {
	if len(buf) < adrpSlotSize || value >= 1<<32 {
		return fmt.Errorf("adrp slot for value %#x in %d bytes", value, len(buf))
	}
	back, err := encodeBranch(slotVA+8, site+4)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(buf[0:], encodeMovZ(rd, value))
	binary.LittleEndian.PutUint32(buf[4:], encodeMovK(rd, value>>16, 16))
	binary.LittleEndian.PutUint32(buf[8:], back)
	binary.LittleEndian.PutUint32(buf[12:], arm64NOP)
	return nil
}

// encodeIndirectSlot writes a slot that replaces br or blr through register
// rn. The slot adds the bias to a pointer of the zone and jumps. For blr it
// first sets the link register to site+4, so that the callee returns to the
// guest code and not to the slot. It returns the byte size of the slot.
//
// A blr leaves rn unchanged, and a guest keeps a callback pointer in a
// callee-saved register for later compares and stores. The slot therefore
// biases a copy of the pointer in x16. No callee reads x16 on entry, because
// the calling convention names it a scratch register for the call itself. The
// registers x16 and x17 and every br change the register in place. A br does
// not return to the slot, so the slot cannot restore the register.
func encodeIndirectSlot(buf []byte, slotVA, site uint64, rn uint8, link bool) (int, error) {
	reg := rn
	var w []uint32
	if link && rn != 16 && rn != 17 {
		reg = 16
		w = append(w, zoneMovX16|uint32(rn)<<16)
	}
	w = append(w, encodeBiasTBNZ(reg, 8), encodeBiasOrr(reg, reg))
	size := brSlotSize
	if link {
		ret := site + 4
		w = append(w, encodeMovZ(30, ret), encodeMovK(30, ret>>16, 16), encodeMovK(30, ret>>32, 32))
		size = blrSlotSize
	}
	w = append(w, zoneBrReg|uint32(reg)<<5)
	if len(buf) < size || len(w)*4 > size {
		return 0, fmt.Errorf("indirect slot needs %d bytes, buffer has %d", size, len(buf))
	}
	for len(w)*4 < size {
		w = append(w, arm64NOP)
	}
	for i, v := range w {
		binary.LittleEndian.PutUint32(buf[i*4:], v)
	}
	return size, nil
}

// zoneSite is an instruction of a code page that needs a zone slot.
type zoneSite struct {
	offset uint32
	kind   siteKind
	reg    uint8
	// value is the guest address that an adr or adrp slot loads.
	value uint64
	link  bool
	orig  uint32
}

// decodePCRelative decodes adr and adrp. It returns the register and the stub
// address that the instruction computes at pc.
func decodePCRelative(w uint32, pc uint64) (rd uint8, target uint64, ok bool) {
	if w&0x1f000000 != 0x10000000 {
		return 0, 0, false
	}
	imm := int64(w>>5&0x7ffff)<<2 | int64(w>>29&3)
	imm = imm << 43 >> 43
	rd = uint8(w & 31)
	if w&0x80000000 != 0 { // adrp
		return rd, uint64(int64(pc&^0xfff) + imm<<12), true
	}
	return rd, uint64(int64(pc) + imm), true
}

// scanZone returns the instructions of a code page that need a zone slot. The
// base is the stub address of the page. The skip function names the words that
// another class of the patcher already claimed.
func scanZone(code []byte, base uint64, skip func(off int) bool) []zoneSite {
	var out []zoneSite
	for off := 0; off+4 <= len(code); off += 4 {
		w := binary.LittleEndian.Uint32(code[off:])
		switch {
		case w&0x1f000000 == 0x10000000:
			rd, target, ok := decodePCRelative(w, base+uint64(off))
			if !ok || rd == 31 || !inZoneStub(target) || skip(off) {
				continue
			}
			out = append(out, zoneSite{offset: uint32(off), kind: siteAdrp, reg: rd, value: target - zoneBias, orig: w})
		case w&0xfffffc1f == 0xd61f0000, w&0xfffffc1f == 0xd63f0000:
			rn := uint8(w >> 5 & 31)
			if rn == 30 || rn == x18Reg || skip(off) {
				continue
			}
			out = append(out, zoneSite{offset: uint32(off), kind: siteIndirect, reg: rn, link: w&0x00200000 != 0, orig: w})
		}
	}
	return out
}
