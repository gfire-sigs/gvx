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
	"fmt"
)

// The arm64 patcher rewrites four instruction classes of a Linux guest.
//
// The macOS kernel runs a guest `svc #0` as a host system call and clobbers
// TPIDR_EL0 on every preemption, so each of those instructions needs a
// replacement. `svc #0` and `msr tpidr_el0, xN` become a branch to a trap slot
// that spills the guest state to the Sentry. `mrs xN, tpidr_el0` becomes a
// branch to a slot that reads the virtual TLS word of the thread. A Linux
// kernel lets EL0 read CTR_EL0, and compilers and JIT engines read it to size
// their cache maintenance loops. macOS raises SIGILL on that read, so
// `mrs xN, ctr_el0` becomes a branch to a slot that loads a constant.
const (
	arm64SVC0       = 0xd4000001
	arm64MRSTPIDR   = 0xd53bd040 // mrs xN, tpidr_el0 with N in bits 4:0.
	arm64MRSCTR     = 0xd53b0020 // mrs xN, ctr_el0 with N in bits 4:0.
	arm64MOVZ       = 0xd2800000 // movz xN, #imm16 with imm16 in bits 20:5.
	arm64MOVKLSL16  = 0xf2a00000 // movk xN, #imm16, lsl #16 with imm16 in bits 20:5.
	arm64MSRTPIDR   = 0xd51bd040 // msr tpidr_el0, xN with N in bits 4:0.
	arm64RegMask    = 0x1f
	arm64NOP        = 0xd503201f
	arm64STPx16x17  = 0xa93f47f0 // stp x16, x17, [sp, #-16]
	arm64LDPx16x17  = 0xa97f47f0 // ldp x16, x17, [sp, #-16]
	arm64ADRx17     = 0x10000000 | 17
	arm64LDRLitx16  = 0x58000000 | 16
	arm64BRx16      = 0xd61f0200
	arm64B          = 0x14000000
	arm64MRSTPIDRRO = 0xd53bd060 // mrs xN, tpidrro_el0
	arm64ANDxMinus8 = 0x927df000 // and xN, xN, #0xfffffffffffffff8
	arm64LDRx       = 0xf9400000 // ldr xT, [xN, #imm12*8]

	// arm64BranchRange is the reach of a B instruction: plus or minus 128MiB.
	arm64BranchRange = 1 << 27

	// trapSlotSize and loadSlotSize are the byte sizes of the two slot kinds.
	trapSlotSize = 32
	loadSlotSize = 16

	// trapSlotTailOffset is the offset of the instruction that restores x16
	// and x17 in a trap slot. The stub receives its address in x17.
	trapSlotTailOffset = 16

	// ctrEL0Value is the CTR_EL0 value that the guest reads. It reports 64-byte
	// instruction and data cache lines, the line size that Apple silicon reports.
	// A guest uses the value only to step through cache maintenance by address,
	// and a line size at or below the real one only costs extra iterations.
	ctrEL0Value = 0x8444c004
)

// siteKind classifies a patched instruction.
type siteKind uint8

const (
	// siteSVC is a guest `svc #0`.
	siteSVC siteKind = iota + 1
	// siteMSR is a guest `msr tpidr_el0, xN`.
	siteMSR
	// siteMRS is a guest `mrs xN, tpidr_el0`.
	siteMRS
	// siteCTR is a guest `mrs xN, ctr_el0`.
	siteCTR
)

// patchSite is one instruction found in an executable page.
type patchSite struct {
	// Offset is the byte offset of the instruction inside the scanned code.
	Offset uint32
	Kind   siteKind
	// Reg is the general-purpose register operand of an MRS or MSR site.
	Reg uint8
	// Orig is the original instruction word.
	Orig uint32
}

// scanARM64 returns every aligned word of code that needs a replacement.
// The scan treats the whole page as code, because arm64 has no way to tell
// literal pool words from instructions without symbols. A data word that
// equals one of the four encodings is patched as well.
func scanARM64(code []byte) []patchSite {
	var sites []patchSite
	for off := 0; off+4 <= len(code); off += 4 {
		w := binary.LittleEndian.Uint32(code[off:])
		switch {
		case w == arm64SVC0:
			sites = append(sites, patchSite{Offset: uint32(off), Kind: siteSVC, Orig: w})
		case w&^arm64RegMask == arm64MRSTPIDR:
			sites = append(sites, patchSite{Offset: uint32(off), Kind: siteMRS, Reg: uint8(w & arm64RegMask), Orig: w})
		case w&^arm64RegMask == arm64MSRTPIDR:
			sites = append(sites, patchSite{Offset: uint32(off), Kind: siteMSR, Reg: uint8(w & arm64RegMask), Orig: w})
		case w&^arm64RegMask == arm64MRSCTR:
			sites = append(sites, patchSite{Offset: uint32(off), Kind: siteCTR, Reg: uint8(w & arm64RegMask), Orig: w})
		}
	}
	return sites
}

// arm64DCOps lists the `dc` operations by virtual address that a Linux kernel
// lets EL0 run, with register 0: cvac, cvau, cvap, cvadp, and civac.
var arm64DCOps = [...]uint32{0xd50b7a20, 0xd50b7b20, 0xd50b7c20, 0xd50b7d20, 0xd50b7e20}

// isDataCacheMaintenance reports whether w is a `dc` operation by virtual
// address that cleans or invalidates a cache line. Windows raises an illegal
// instruction exception for it at EL0. The guest memory stays coherent, so the
// operation has no effect that a guest can observe, and a NOP replaces it.
func isDataCacheMaintenance(w uint32) bool {
	for _, op := range arm64DCOps {
		if w&^arm64RegMask == op {
			return true
		}
	}
	return false
}

// encodeBranch returns the B instruction at address from that jumps to to.
func encodeBranch(from, to uint64) (uint32, error) {
	if from&3 != 0 || to&3 != 0 {
		return 0, fmt.Errorf("unaligned branch %#x -> %#x", from, to)
	}
	delta := int64(to) - int64(from)
	if delta <= -arm64BranchRange || delta >= arm64BranchRange {
		return 0, fmt.Errorf("branch %#x -> %#x exceeds the 128MiB range", from, to)
	}
	return arm64B | uint32(delta>>2)&0x03ffffff, nil
}

// decodeBranch returns the target of the B instruction at address from.
func decodeBranch(from uint64, insn uint32) (uint64, bool) {
	if insn&0xfc000000 != arm64B {
		return 0, false
	}
	imm := int64(insn&0x03ffffff) << 38 >> 38
	return uint64(int64(from) + imm*4), true
}

// slotSizeFor returns the slot size of a site kind.
func slotSizeFor(k siteKind) int {
	if k == siteMRS || k == siteCTR {
		return loadSlotSize
	}
	return trapSlotSize
}

// encodeTrapSlot writes a trap slot at slotVA into buf. The slot saves x16
// and x17 below the guest stack pointer, loads the stub's spill routine and
// jumps to it with x17 set to the slot tail. After the Sentry resumes the
// thread, the stub jumps back to the tail, which restores x16 and x17 and
// branches to retPC.
func encodeTrapSlot(buf []byte, slotVA, retPC, spill uint64) error {
	if len(buf) < trapSlotSize {
		return fmt.Errorf("trap slot buffer has %d bytes", len(buf))
	}
	back, err := encodeBranch(slotVA+trapSlotTailOffset+4, retPC)
	if err != nil {
		return err
	}
	words := [...]uint32{
		arm64STPx16x17,
		arm64ADRx17 | uint32((trapSlotTailOffset-4)>>2)<<5, // adr x17, tail: byte offset 12.
		arm64LDRLitx16 | ((24-8)>>2)<<5,                    // ldr x16, [pc, +16].
		arm64BRx16,
		arm64LDPx16x17,
		back,
	}
	for i, w := range words {
		binary.LittleEndian.PutUint32(buf[i*4:], w)
	}
	binary.LittleEndian.PutUint64(buf[24:], spill)
	return nil
}

// encodeLoadSlot writes a slot at slotVA that replaces `mrs xN, tpidr_el0`.
// The slot reads the thread's sysmsg pointer from TPIDRRO_EL0, clears the low
// bits that the kernel may use for a CPU number, loads the virtual TLS word
// into xN and returns to retPC. It clobbers no other register and no flag.
func encodeLoadSlot(buf []byte, slotVA, retPC uint64, reg uint8, tlsOffset uint32) error {
	if len(buf) < loadSlotSize {
		return fmt.Errorf("load slot buffer has %d bytes", len(buf))
	}
	if reg >= 31 {
		return fmt.Errorf("load slot register %d", reg)
	}
	if tlsOffset%8 != 0 || tlsOffset/8 > 0xfff {
		return fmt.Errorf("tls offset %#x is not encodable", tlsOffset)
	}
	back, err := encodeBranch(slotVA+12, retPC)
	if err != nil {
		return err
	}
	r := uint32(reg)
	binary.LittleEndian.PutUint32(buf[0:], arm64MRSTPIDRRO|r)
	binary.LittleEndian.PutUint32(buf[4:], arm64ANDxMinus8|r<<5|r)
	binary.LittleEndian.PutUint32(buf[8:], arm64LDRx|(tlsOffset/8)<<10|r<<5|r)
	binary.LittleEndian.PutUint32(buf[12:], back)
	return nil
}

// ctrWords returns the two instructions that load ctrEL0Value into register
// reg: movz for the low half and movk for the high half.
func ctrWords(reg uint8) [2]uint32 {
	r := uint32(reg)
	return [2]uint32{
		arm64MOVZ | (ctrEL0Value&0xffff)<<5 | r,
		arm64MOVKLSL16 | (ctrEL0Value>>16)<<5 | r,
	}
}

// encodeCTRSlot writes a slot at slotVA that replaces `mrs xN, ctr_el0`. The
// slot loads ctrEL0Value into xN and returns to retPC. It clobbers no other
// register and no flag.
func encodeCTRSlot(buf []byte, slotVA, retPC uint64, reg uint8) error {
	if len(buf) < loadSlotSize {
		return fmt.Errorf("ctr slot buffer has %d bytes", len(buf))
	}
	if reg >= 31 {
		return fmt.Errorf("ctr slot register %d", reg)
	}
	back, err := encodeBranch(slotVA+8, retPC)
	if err != nil {
		return err
	}
	ws := ctrWords(reg)
	binary.LittleEndian.PutUint32(buf[0:], ws[0])
	binary.LittleEndian.PutUint32(buf[4:], ws[1])
	binary.LittleEndian.PutUint32(buf[8:], back)
	binary.LittleEndian.PutUint32(buf[12:], arm64NOP)
	return nil
}
