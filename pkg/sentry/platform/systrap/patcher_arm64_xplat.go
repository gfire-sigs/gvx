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

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
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
	arm64SVC0       = hvcommon.SVC0
	arm64MRSTPIDR   = 0xd53bd040 // mrs xN, tpidr_el0 with N in bits 4:0.
	arm64MRSCTR     = 0xd53b0020 // mrs xN, ctr_el0 with N in bits 4:0.
	arm64MSRTPIDR   = 0xd51bd040 // msr tpidr_el0, xN with N in bits 4:0.
	arm64RegMask    = 0x1f
	arm64NOP        = hvcommon.NOP
	arm64ADRx17     = 0x10000000 | 17
	arm64LDRLitx16  = 0x58000000 | 16
	arm64B          = 0x14000000
	arm64MRSTPIDRRO = 0xd53bd060 // mrs xN, tpidrro_el0
	arm64ANDxMinus8 = 0x927df000 // and xN, xN, #0xfffffffffffffff8

	// arm64ScratchReg is the hardware x18 register, which holds no guest value
	// on macOS because scanX18 moves guest x18 accesses to sysmsg.X18.
	arm64ScratchReg = 18

	// trapScratchOffset is the byte offset of sysmsg.Scratch on macOS arm64.
	trapScratchOffset = 928

	// arm64BranchRange is the reach of a B instruction: plus or minus 128MiB.
	arm64BranchRange = 1 << 27

	// trapSlotSize and loadSlotSize are the byte sizes of the two slot kinds.
	trapSlotSize = 56
	loadSlotSize = 16

	// trapSlotTailOffset is the offset of the phase that restores x16 and x17
	// in a trap slot. The stub receives its address in x17.
	trapSlotTailOffset = 28

	// trapSlotLitOffset is the byte offset of the 8-byte spill address literal
	// inside a trap slot.
	trapSlotLitOffset = 48

	// ctrEL0Value is the CTR_EL0 value that the guest reads. It reports 64-byte
	// instruction and data cache lines, the line size that Apple silicon reports.
	// A guest uses the value only to step through cache maintenance by address,
	// and a line size at or below the real one only costs extra iterations.
	ctrEL0Value = hvcommon.DefaultCTREL0
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

// encodeTrapSysmsgSlot writes a syscall trap slot at slotVA into buf using
// save as the entry prologue and restore as the tail epilogue.
func encodeTrapSysmsgSlot(buf []byte, slotVA, retPC, spill uint64, save, restore []uint32) error {
	tailOff := (len(save) + 3) * 4
	litOff := (len(save) + 3 + len(restore) + 1) * 4
	if len(buf) < litOff+8 {
		return fmt.Errorf("trap slot buffer has %d bytes", len(buf))
	}
	backOff := len(save)*4 + 4
	adrOff := len(save) * 4
	ldrOff := adrOff + 4
	back, err := encodeBranch(slotVA+uint64(tailOff+len(restore)*4), retPC)
	if err != nil {
		return err
	}
	_ = backOff
	off := 0
	for _, w := range save {
		binary.LittleEndian.PutUint32(buf[off:], w)
		off += 4
	}
	binary.LittleEndian.PutUint32(buf[off:], arm64ADRx17|uint32((tailOff-adrOff)>>2)<<5)
	binary.LittleEndian.PutUint32(buf[off+4:], arm64LDRLitx16|uint32((litOff-ldrOff)>>2)<<5)
	binary.LittleEndian.PutUint32(buf[off+8:], hvcommon.BR(16))
	off += 12
	for _, w := range restore {
		binary.LittleEndian.PutUint32(buf[off:], w)
		off += 4
	}
	binary.LittleEndian.PutUint32(buf[off:], back)
	binary.LittleEndian.PutUint64(buf[litOff:], spill)
	return nil
}

// encodeTrapSlot writes a trap slot at slotVA into buf.
func encodeTrapSlot(buf []byte, slotVA, retPC, spill uint64) error {
	const (
		ptr0 = arm64MRSTPIDRRO | arm64ScratchReg
		ptr1 = arm64ANDxMinus8 | arm64ScratchReg<<5 | arm64ScratchReg
	)
	save := []uint32{
		ptr0, ptr1,
		hvcommon.STRX(arm64ScratchReg, 16, trapScratchOffset),
		hvcommon.STRX(arm64ScratchReg, 17, trapScratchOffset+8),
	}
	restore := []uint32{
		ptr0, ptr1,
		hvcommon.LDRX(arm64ScratchReg, 16, trapScratchOffset),
		hvcommon.LDRX(arm64ScratchReg, 17, trapScratchOffset+8),
	}
	return encodeTrapSysmsgSlot(buf, slotVA, retPC, spill, save, restore)
}

// encodeLoadSysmsgSlot writes a 16-byte slot at slotVA that reads a thread
// sysmsg base register (`sysRegBase | reg`), optionally clears its low 3 CPU-ID
// bits (`AND xN, xN, #-8`), loads the 64-bit word at `off` into `reg`, and
// branches to `retPC`.
func encodeLoadSysmsgSlot(buf []byte, slotVA, retPC uint64, reg uint8, sysRegBase uint32, maskLowBits bool, off uint32) error {
	if len(buf) < loadSlotSize {
		return fmt.Errorf("load slot buffer has %d bytes", len(buf))
	}
	if reg >= 31 {
		return fmt.Errorf("load slot register %d", reg)
	}
	if off%8 != 0 || off/8 > 0xfff {
		return fmt.Errorf("tls offset %#x is not encodable", off)
	}
	r := uint32(reg)
	if maskLowBits {
		back, err := encodeBranch(slotVA+12, retPC)
		if err != nil {
			return err
		}
		binary.LittleEndian.PutUint32(buf[0:], sysRegBase|r)
		binary.LittleEndian.PutUint32(buf[4:], arm64ANDxMinus8|r<<5|r)
		binary.LittleEndian.PutUint32(buf[8:], hvcommon.LDRX(int(reg), int(reg), int(off)))
		binary.LittleEndian.PutUint32(buf[12:], back)
		return nil
	}
	back, err := encodeBranch(slotVA+8, retPC)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(buf[0:], sysRegBase|r)
	binary.LittleEndian.PutUint32(buf[4:], hvcommon.LDRX(int(reg), int(reg), int(off)))
	binary.LittleEndian.PutUint32(buf[8:], back)
	binary.LittleEndian.PutUint32(buf[12:], arm64NOP)
	return nil
}

// encodeLoadSlot writes a slot at slotVA that replaces `mrs xN, tpidr_el0`.
// The slot reads the thread's sysmsg pointer from TPIDRRO_EL0, clears the low
// bits that the kernel may use for a CPU number, loads the virtual TLS word
// into xN and returns to retPC. It clobbers no other register and no flag.
func encodeLoadSlot(buf []byte, slotVA, retPC uint64, reg uint8, tlsOffset uint32) error {
	return encodeLoadSysmsgSlot(buf, slotVA, retPC, reg, arm64MRSTPIDRRO, true, tlsOffset)
}

// ctrWords returns the two instructions that load ctrEL0Value into register
// reg: movz for the low half and movk for the high half.
func ctrWords(reg uint8) [2]uint32 {
	return [2]uint32{
		hvcommon.MOVZ(int(reg), uint16(ctrEL0Value&0xffff)),
		hvcommon.MOVK(int(reg), uint16(ctrEL0Value>>16), 16),
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

// decodeARM64SysRegMRS decodes an AArch64 MRS instruction (`0xD5300000 | ...`)
// for the EL1 identification registers, CTR_EL0, and DCZID_EL0 that Linux
// exposes to EL0 via HWCAP_CPUID.
func decodeARM64SysRegMRS(insn uint32) (rt uint8, val uint64, ok bool) {
	iss, ok := hvcommon.DecodeMRSSysRegISS(insn)
	if !ok {
		return 0, 0, false
	}
	val, ok = hvcommon.DefaultIDRegisters().EmulateSysRegRead(iss)
	if !ok {
		return 0, 0, false
	}
	return uint8(iss.Rt), val, true
}
