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

//go:build (darwin || windows) && amd64

package systrap

import (
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/arch/x86/x86asm"

	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// The Windows engine has no C toolchain step, so Go code generates the amd64
// slot and the spill routine of the fast path.
//
// A patched SYSCALL becomes a 5-byte JMP rel32 to a slot. The JMP overwrites
// the SYSCALL and the three bytes after it. The slot therefore holds a copy of
// the instructions that those bytes belong to (the relocated bytes). The slot
// has no stack use: the guest stack can hold live data below the stack
// pointer (the red zone), and a signal frame never arrives while the thread
// runs engine code. The slot saves RAX and the return address in two words of
// the TEB, loads RAX with the address of its tail, and jumps to the spill
// routine:
//
//	mov  gs:[winTEBScratchA], rax
//	lea  rax, [rip+tail]
//	mov  gs:[winTEBScratchB], rax
//	jmp  [rip+literal]        ; literal holds the address of the spill routine
//	tail:
//	  <relocated instructions>
//	  jmp  site+2+len(relocated)
//
// The spill routine finds the sysmsg of the thread in the TEB, saves every
// register and the vector state, switches to the stub stack, runs the handoff,
// loads the vector state and the registers again, and jumps to the tail with a
// JMP through the TEB. A guest can never write the GS base, so GS names the TEB
// of the thread.

const (
	// winSlotLiteralOffset is the offset of the 8-byte literal that holds the
	// address of the spill routine.
	winSlotLiteralOffset = 32
	// winSlotTailOffset is the offset of the slot tail.
	winSlotTailOffset = 40
	// winMaxRelocated is the most relocated bytes that fit in the slot: the
	// tail offset, the jump back, and the slot size bound it.
	winMaxRelocated = winSlotSize - winSlotTailOffset - 5

	// winJmpLen is the length of the JMP rel32 that replaces the SYSCALL and
	// the three bytes after it.
	winJmpLen = 5
	// winMinRelocated is the number of bytes that the JMP overwrites behind
	// the SYSCALL.
	winMinRelocated = winJmpLen - 2

	// winIslandReach32 is the reach of a rel32 jump. The island allocator keeps
	// far below it.
	winIslandReach32 = 1 << 31

	// winJmpNeighborLen is the number of bytes on each side of a page that
	// jmpPlanner scans for relative branches into a patched site.
	winJmpNeighborLen = 256
)

// x86Reg numbers are the numbers that an instruction encodes.
const (
	x86RAX = iota
	x86RCX
	x86RDX
	x86RBX
	x86RSP
	x86RBP
	x86RSI
	x86RDI
	x86R8
	x86R9
	x86R10
	x86R11
	x86R12
	x86R13
	x86R14
	x86R15
)

// x86Asm collects bytes and resolves jumps to labels.
type x86Asm struct {
	b      []byte
	labels map[string]int
	fixes  []x86Fix
}

type x86Fix struct {
	// at is the offset of the displacement. size is 1 or 4.
	at    int
	size  int
	label string
}

func (a *x86Asm) emit(b ...byte) { a.b = append(a.b, b...) }

func (a *x86Asm) imm32(v uint32) { a.b = binary.LittleEndian.AppendUint32(a.b, v) }

func (a *x86Asm) label(name string) {
	if a.labels == nil {
		a.labels = make(map[string]int)
	}
	a.labels[name] = len(a.b)
}

// rex returns the REX prefix for a 64-bit operation. reg extends ModRM.reg
// and base extends ModRM.rm.
func x86Rex(w bool, reg, base int) byte {
	r := byte(0x40)
	if w {
		r |= 8
	}
	if reg >= 8 {
		r |= 4
	}
	if base >= 8 {
		r |= 1
	}
	return r
}

// memOp emits opcode bytes with a ModRM [base+disp32] operand. A base of RSP
// or R12 emits the required 0x24 SIB byte. w selects REX.W.
func (a *x86Asm) memOp(w bool, op []byte, reg, base int, disp int32) {
	if r := x86Rex(w, reg, base); r != 0x40 {
		a.emit(r)
	}
	a.emit(op...)
	a.emit(0x80 | byte(reg&7)<<3 | byte(base&7))
	if base&7 == 4 {
		a.emit(0x24)
	}
	a.imm32(uint32(disp))
}

// movLoad is `mov r64, [base+disp32]`.
func (a *x86Asm) movLoad(reg, base int, disp int32) { a.memOp(true, []byte{0x8B}, reg, base, disp) }

// movStore is `mov [base+disp32], r64`.
func (a *x86Asm) movStore(base int, disp int32, reg int) {
	a.memOp(true, []byte{0x89}, reg, base, disp)
}

// movLoad32 is `mov r32, [base+disp32]`.
func (a *x86Asm) movLoad32(reg, base int, disp int32) { a.memOp(false, []byte{0x8B}, reg, base, disp) }

// movStore32 is `mov [base+disp32], r32`.
func (a *x86Asm) movStore32(base int, disp int32, reg int) {
	a.memOp(false, []byte{0x89}, reg, base, disp)
}

// movStoreImm32 is `mov dword [base+disp32], imm32`.
func (a *x86Asm) movStoreImm32(base int, disp int32, v uint32) {
	a.memOp(false, []byte{0xC7}, 0, base, disp)
	a.imm32(v)
}

// cmpMemImm8 is `cmp dword [base+disp32], imm8`.
func (a *x86Asm) cmpMemImm8(base int, disp int32, v int8) {
	a.memOp(false, []byte{0x83}, 7, base, disp)
	a.emit(byte(v))
}

// pushMem is `push qword [base+disp32]`, and popMem is `pop qword [base+disp32]`.
func (a *x86Asm) pushMem(base int, disp int32) { a.memOp(false, []byte{0xFF}, 6, base, disp) }
func (a *x86Asm) popMem(base int, disp int32)  { a.memOp(false, []byte{0x8F}, 0, base, disp) }

// callMem is `call qword [base+disp32]`.
func (a *x86Asm) callMem(base int, disp int32) { a.memOp(false, []byte{0xFF}, 2, base, disp) }

// leaBase is `lea r64, [base+disp32]`.
func (a *x86Asm) leaBase(reg, base int, disp int32) { a.memOp(true, []byte{0x8D}, reg, base, disp) }

// loadXsaveMask is `mov eax, winXsaveMask; xor edx, edx`. XSAVE and XRSTOR take
// the requested-feature bitmap in EDX:EAX.
func (a *x86Asm) loadXsaveMask() {
	a.emit(0xB8)
	a.imm32(winXsaveMask)
	a.emit(0x31, 0xD2)
}

// xsave64 is `xsave64 [base+disp32]`.
func (a *x86Asm) xsave64(base int, disp int32) { a.memOp(true, []byte{0x0F, 0xAE}, 4, base, disp) }

// xrstor64 is `xrstor64 [base+disp32]`.
func (a *x86Asm) xrstor64(base int, disp int32) { a.memOp(true, []byte{0x0F, 0xAE}, 5, base, disp) }

// movLoadGS is `mov r64, gs:[abs32]`, and movStoreGS is `mov gs:[abs32], r64`.
func (a *x86Asm) movLoadGS(reg int, abs uint32) {
	a.b = hvcommon.AppendMovFromGS(a.b, reg, abs)
}

func (a *x86Asm) movStoreGS(abs uint32, reg int) {
	a.b = hvcommon.AppendMovToGS(a.b, reg, abs)
}

// jmpGS is `jmp qword gs:[abs32]`.
func (a *x86Asm) jmpGS(abs uint32) {
	a.emit(0x65, 0xFF, 0x24, 0x25)
	a.imm32(abs)
}

// movRegReg is `mov dst, src` for 64-bit registers.
func (a *x86Asm) movRegReg(dst, src int) {
	a.emit(x86Rex(true, src, dst), 0x89, 0xC0|byte(src&7)<<3|byte(dst&7))
}

// jcc8 and jcc32 emit a conditional jump to a label with a 1-byte or 4-byte
// displacement. cc is the low nibble of the opcode: 2 jb, 3 jae, 4 je, 5 jne.
func (a *x86Asm) jcc8(cc byte, label string) {
	a.emit(0x70 | cc)
	a.fixes = append(a.fixes, x86Fix{at: len(a.b), size: 1, label: label})
	a.emit(0)
}

func (a *x86Asm) jcc32(cc byte, label string) {
	a.emit(0x0F, 0x80|cc)
	a.fixes = append(a.fixes, x86Fix{at: len(a.b), size: 4, label: label})
	a.imm32(0)
}

// finish resolves the labels and returns the code.
func (a *x86Asm) finish() ([]byte, error) {
	for _, f := range a.fixes {
		to, ok := a.labels[f.label]
		if !ok {
			return nil, fmt.Errorf("undefined label %q", f.label)
		}
		delta := to - (f.at + f.size)
		switch f.size {
		case 1:
			if delta < -128 || delta > 127 {
				return nil, fmt.Errorf("short jump to %q is out of range (%d)", f.label, delta)
			}
			a.b[f.at] = byte(int8(delta))
		case 4:
			binary.LittleEndian.PutUint32(a.b[f.at:], uint32(int32(delta)))
		}
	}
	return a.b, nil
}

const (
	x86CCB  = 0x2
	x86CCAE = 0x3
	x86CCE  = 0x4
	x86CCNE = 0x5
)

// winSpillCode is the generated spill routine and the offsets in it.
type winSpillCode struct {
	code []byte
	// coldTrap is the offset of the INT3 that a cold resume executes.
	coldTrap int
}

// coldExit returns the offset of the trap that a cold resume executes.
func (c winSpillCode) coldExit() int {
	return c.coldTrap
}

// buildSpill generates the spill routine.
//
// Register use after the save: R15 holds the sysmsg and RBX counts the polls.
// Both are callee-saved in the Windows calling convention, so the calls into
// ntdll keep them. The stack pointer lies 64 bytes below the top of the stub
// stack, which leaves the 32-byte shadow space of a call and keeps the 16-byte
// alignment.
func buildSpill() (winSpillCode, error) {
	var a x86Asm
	const base = x86R15

	// Find the sysmsg, then save the registers. RAX is the base until R15 takes
	// over, so the guest RAX and the tail come from the TEB words.
	a.movLoadGS(x86RAX, winTEBSysmsg)
	for _, r := range []int{x86RCX, x86RDX, x86RBX, x86RBP, x86RSI, x86RDI, x86R8, x86R9, x86R10, x86R11, x86R12, x86R13, x86R14, x86R15} {
		a.movStore(x86RAX, int32(winRegOffset(r)), r)
	}
	a.movStore(x86RAX, int32(winRegOffset(x86RSP)), x86RSP)
	a.movLoadGS(x86RBX, winTEBScratchA)
	a.movStore(x86RAX, int32(winRegOffset(x86RAX)), x86RBX)
	a.movLoadGS(x86RBX, winTEBScratchB)
	a.movStore(x86RAX, winOffTail, x86RBX)
	a.movRegReg(base, x86RAX)
	a.leaBase(x86RSP, base, winStubStackTop)
	a.emit(0x9C) // pushfq
	a.popMem(base, winOffRflags)

	// Save the vector state before the first call. A call into ntdll can
	// clobber the volatile vector registers, and the Sentry reads the saved
	// image while the thread waits.
	a.loadXsaveMask()
	a.xsave64(base, winOffXsave)

	// Publish Trapped. An x86 store has release semantics. The fence orders the
	// store before the load of the Sentry flag.
	a.movStoreImm32(base, winOffState, uint32(winStateTrapped))
	a.emit(0x0F, 0xAE, 0xF0) // mfence
	a.cmpMemImm8(base, winOffSentryWaiter, 0)
	a.jcc8(x86CCE, "spin")
	a.movLoad(x86RCX, base, winOffGuestEvent)
	a.emit(0x31, 0xD2) // xor edx, edx
	a.callMem(base, winOffNtSetEvent)

	a.label("spin")
	a.emit(0xBB)
	a.imm32(winSpinStub) // mov ebx, spin count
	a.label("poll")
	a.movLoad32(x86RAX, base, winOffState)
	a.emit(0x83, 0xF8, byte(winStateRunHot)) // cmp eax, RunHot
	a.jcc8(x86CCAE, "run")
	a.emit(0xF3, 0x90) // pause
	a.emit(0xFF, 0xCB) // dec ebx
	a.jcc8(x86CCNE, "poll")

	a.label("sleep")
	a.movStoreImm32(base, winOffStubWaiter, 1)
	a.emit(0x0F, 0xAE, 0xF0) // mfence
	a.movLoad32(x86RAX, base, winOffState)
	a.emit(0x83, 0xF8, byte(winStateRunHot))
	a.jcc8(x86CCAE, "runclear")
	a.movLoad(x86RCX, base, winOffHostEvent)
	a.emit(0x31, 0xD2)       // xor edx, edx
	a.emit(0x45, 0x31, 0xC0) // xor r8d, r8d
	a.callMem(base, winOffNtWait)
	a.movLoad32(x86RAX, base, winOffState)
	a.emit(0x83, 0xF8, byte(winStateRunHot))
	a.jcc8(x86CCB, "sleep")
	a.label("runclear")
	a.movStoreImm32(base, winOffStubWaiter, 0)
	a.label("run")
	a.emit(0x83, 0xF8, byte(winStateRunCold)) // cmp eax, RunCold
	a.jcc32(x86CCE, "cold")

	// Hot resume: load the vector state, the FS base, the flags, the return
	// address, and every register, then jump to the tail.
	a.loadXsaveMask()
	a.xrstor64(base, winOffXsave)
	a.movLoad(x86RAX, base, winOffFsBase)
	a.emit(0xF3, 0x48, 0x0F, 0xAE, 0xD0) // wrfsbase rax
	a.pushMem(base, winOffRflags)
	a.emit(0x9D) // popfq
	a.movLoad(x86RAX, base, winOffTail)
	a.movStoreGS(winTEBScratchB, x86RAX)
	loadAll(&a, base)
	a.jmpGS(winTEBScratchB)

	// Cold resume: load the flags and every register, then trap. The Sentry
	// continues the thread at Target and loads the FS base itself.
	a.label("cold")
	a.loadXsaveMask()
	a.xrstor64(base, winOffXsave)
	a.pushMem(base, winOffRflags)
	a.emit(0x9D)
	loadAll(&a, base)
	coldTrap := len(a.b)
	a.emit(0xCC) // int3
	code, err := a.finish()
	if err != nil {
		return winSpillCode{}, err
	}
	return winSpillCode{code: code, coldTrap: coldTrap}, nil
}

// loadAll loads every general-purpose register from the sysmsg that base
// names. It loads the stack pointer and then the base register last.
func loadAll(a *x86Asm, base int) {
	for _, r := range []int{x86RAX, x86RCX, x86RDX, x86RBX, x86RBP, x86RSI, x86RDI, x86R8, x86R9, x86R10, x86R11, x86R12, x86R13, x86R14} {
		a.movLoad(r, base, int32(winRegOffset(r)))
	}
	a.movLoad(x86RSP, base, int32(winRegOffset(x86RSP)))
	a.movLoad(base, base, int32(winRegOffset(base)))
}

// encodeWinSlot writes the slot for a patched SYSCALL at site. reloc holds the
// instructions that the JMP overwrites behind the SYSCALL. The slot jumps to
// the spill routine, runs reloc, and jumps to the address behind reloc.
func encodeWinSlot(buf []byte, slotVA, site, spill uint64, reloc []byte) error {
	if len(buf) < winSlotSize {
		return fmt.Errorf("slot buffer has %d bytes", len(buf))
	}
	if len(reloc) < winMinRelocated || len(reloc) > winMaxRelocated {
		return fmt.Errorf("slot with %d relocated bytes", len(reloc))
	}
	var a x86Asm
	a.movStoreGS(winTEBScratchA, x86RAX)
	// lea rax, [rip+tail]: the instruction ends at offset 16.
	a.emit(0x48, 0x8D, 0x05)
	a.imm32(uint32(winSlotTailOffset - 16))
	a.movStoreGS(winTEBScratchB, x86RAX)
	// jmp [rip+literal]: the instruction ends at offset 31.
	a.emit(0xFF, 0x25)
	a.imm32(uint32(winSlotLiteralOffset - 31))
	for len(a.b) < winSlotLiteralOffset {
		a.emit(0xCC)
	}
	a.b = binary.LittleEndian.AppendUint64(a.b, spill)
	a.b = append(a.b, reloc...)
	back := slotVA + uint64(len(a.b)) + 5
	rel, err := rel32(back, site+winSiteLen+uint64(len(reloc)))
	if err != nil {
		return err
	}
	a.emit(0xE9)
	a.imm32(rel)
	for len(a.b) < winSlotSize {
		a.emit(0xCC)
	}
	copy(buf, a.b)
	return nil
}

// rel32 returns the displacement of a rel32 jump whose next instruction is at
// from and whose target is to.
func rel32(from, to uint64) (uint32, error) {
	d := int64(to) - int64(from)
	if d <= -winIslandReach32 || d >= winIslandReach32 {
		return 0, fmt.Errorf("jump %#x to %#x exceeds the rel32 range", from, to)
	}
	return uint32(int32(d)), nil
}

// patchJmp writes `jmp rel32` to slotVA over the SYSCALL at page[off] and the
// three bytes behind it.
func patchJmp(page []byte, off int, siteVA, slotVA uint64) error {
	return patchJmpSite(page, off, winJmpLen, siteVA, slotVA)
}

// patchJmpSite writes `jmp rel32` to slotVA over the siteLen-byte instruction
// at page[off] and fills any trailing bytes of the instruction with INT3.
func patchJmpSite(page []byte, off, siteLen int, siteVA, slotVA uint64) error {
	if siteLen < winJmpLen || off < 0 || off+siteLen > len(page) {
		return fmt.Errorf("jump at %d (len %d) does not fit in a page of %d bytes", off, siteLen, len(page))
	}
	rel, err := rel32(siteVA+winJmpLen, slotVA)
	if err != nil {
		return err
	}
	page[off] = 0xE9
	binary.LittleEndian.PutUint32(page[off+1:], rel)
	for i := winJmpLen; i < siteLen; i++ {
		page[off+i] = 0xCC
	}
	return nil
}

// encodeWinTLSBaseSlot writes the slot for a patched RDFSBASE or RDGSBASE
// instruction of siteLen bytes at site. It reads FsBase or GsBase from the
// thread winSysmsg into reg without touching flags or other registers, then
// jumps to site+siteLen.
func encodeWinTLSBaseSlot(buf []byte, slotVA, site uint64, siteLen int, reg uint8, wide, isGS bool) error {
	if len(buf) < winTLSSlotSize {
		return fmt.Errorf("TLS slot buffer has %d bytes", len(buf))
	}
	var a x86Asm
	a.movLoadGS(int(reg), winTEBSysmsg)
	disp := int32(winOffFsBase)
	if isGS {
		disp = int32(winOffGsBase)
	}
	if wide {
		a.movLoad(int(reg), int(reg), disp)
	} else {
		a.movLoad32(int(reg), int(reg), disp)
	}
	back := slotVA + uint64(len(a.b)) + 5
	rel, err := rel32(back, site+uint64(siteLen))
	if err != nil {
		return err
	}
	a.emit(0xE9)
	a.imm32(rel)
	for len(a.b) < winTLSSlotSize {
		a.emit(0xCC)
	}
	copy(buf[:winTLSSlotSize], a.b)
	return nil
}

// gsMovPlan describes a 32-bit or 64-bit MOV between a general-purpose
// register and a constant displacement in the GS segment (`gs:[disp32]`).
type gsMovPlan struct {
	reg     uint8
	scratch uint8
	wide    bool
	store   bool
	disp    int32
}

// gsMovReg maps a 32-bit or 64-bit x86asm general-purpose register to its
// hardware register number (0..15) and width.
func gsMovReg(r x86asm.Reg) (uint8, bool, bool) {
	if r >= x86asm.RAX && r <= x86asm.R15 {
		return uint8(r - x86asm.RAX), true, true
	}
	if r >= x86asm.EAX && r <= x86asm.R15L {
		return uint8(r - x86asm.EAX), false, true
	}
	return 0, false, false
}

// planGSMov decodes a GS-prefixed instruction and reports whether it is a
// 32-bit or 64-bit MOV between a general-purpose register and `gs:[disp32]`.
func planGSMov(code []byte) (gsMovPlan, bool) {
	if len(code) < winJmpLen {
		return gsMovPlan{}, false
	}
	inst, err := decodeX86(code)
	if err != nil || inst.Len != len(code) || inst.Op != x86asm.MOV {
		return gsMovPlan{}, false
	}
	for _, p := range inst.Prefix {
		if p == 0 {
			break
		}
		b := byte(p & 0xFF)
		if b != 0x65 && (b < 0x40 || b > 0x4F) {
			return gsMovPlan{}, false
		}
	}
	if r, ok := inst.Args[0].(x86asm.Reg); ok {
		mem, memOK := inst.Args[1].(x86asm.Mem)
		reg, wide, regOK := gsMovReg(r)
		if !memOK || !regOK || mem.Segment != x86asm.GS || mem.Base != 0 || mem.Index != 0 || int64(int32(mem.Disp)) != mem.Disp {
			return gsMovPlan{}, false
		}
		scratch := reg
		if reg == x86RSP {
			scratch = x86RAX
		}
		return gsMovPlan{reg: reg, scratch: scratch, wide: wide, store: false, disp: int32(mem.Disp)}, true
	}
	if r, ok := inst.Args[1].(x86asm.Reg); ok {
		mem, memOK := inst.Args[0].(x86asm.Mem)
		reg, wide, regOK := gsMovReg(r)
		if !memOK || !regOK || mem.Segment != x86asm.GS || mem.Base != 0 || mem.Index != 0 || int64(int32(mem.Disp)) != mem.Disp {
			return gsMovPlan{}, false
		}
		scratch := uint8(x86RAX)
		if reg == x86RAX {
			scratch = x86RCX
		}
		return gsMovPlan{reg: reg, scratch: scratch, wide: wide, store: true, disp: int32(mem.Disp)}, true
	}
	return gsMovPlan{}, false
}

// encodeWinGSMovSlot writes a trampoline slot for a patched GS-segment MOV
// instruction of siteLen bytes at site. It spills p.scratch to winTEBScratchA,
// loads GsMemBase from the thread winSysmsg, performs the 32-bit or 64-bit
// memory access at [GsMemBase+disp], restores p.scratch when needed, and jumps
// to site+siteLen without modifying RFLAGS.
func encodeWinGSMovSlot(buf []byte, slotVA, site uint64, siteLen int, p gsMovPlan) error {
	if len(buf) < winGSMovSlotSize {
		return fmt.Errorf("GS MOV slot buffer has %d bytes", len(buf))
	}
	var a x86Asm
	a.movStoreGS(winTEBScratchA, int(p.scratch))
	a.movLoadGS(int(p.scratch), winTEBSysmsg)
	a.movLoad(int(p.scratch), int(p.scratch), winOffGsMemBase)
	switch {
	case p.store && p.wide:
		a.movStore(int(p.scratch), p.disp, int(p.reg))
	case p.store && !p.wide:
		a.movStore32(int(p.scratch), p.disp, int(p.reg))
	case !p.store && p.wide:
		a.movLoad(int(p.reg), int(p.scratch), p.disp)
	default:
		a.movLoad32(int(p.reg), int(p.scratch), p.disp)
	}
	if p.store || p.scratch != p.reg {
		a.movLoadGS(int(p.scratch), winTEBScratchA)
	}
	back := slotVA + uint64(len(a.b)) + 5
	rel, err := rel32(back, site+uint64(siteLen))
	if err != nil {
		return err
	}
	a.emit(0xE9)
	a.imm32(rel)
	for len(a.b) < winGSMovSlotSize {
		a.emit(0xCC)
	}
	copy(buf[:winGSMovSlotSize], a.b)
	return nil
}

// relocatable reports whether an instruction keeps its meaning when it moves
// to another address. A branch, a call, a return, and an instruction with a
// RIP-relative operand depend on the address. A system call instruction or an
// interrupt would reach the engine again. An operand with a segment override
// stays in place, because Windows can reset the FS base while the slot runs,
// and the engine repairs the base only for faults in guest pages.
func relocatable(inst x86asm.Inst) bool {
	op := inst.Op.String()
	for _, p := range []string{"J", "CALL", "LCALL", "LJMP", "RET", "LRET", "IRET", "INT", "SYSCALL", "SYSENTER", "SYSEXIT", "SYSRET", "LOOP", "XBEGIN", "HLT", "UD", "RDFSBASE", "RDGSBASE", "WRFSBASE", "WRGSBASE"} {
		if strings.HasPrefix(op, p) {
			return false
		}
	}
	for _, arg := range inst.Args {
		switch a := arg.(type) {
		case x86asm.Rel:
			return false
		case x86asm.Mem:
			if a.Base == x86asm.RIP || a.Segment != 0 {
				return false
			}
		}
	}
	return true
}

// isX86Prefix reports whether b is a legacy instruction prefix or a REX prefix.
func isX86Prefix(b byte) bool {
	if b >= 0x40 && b <= 0x4F {
		return true
	}
	switch b {
	case 0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65:
		return true
	}
	return false
}

// hasPrefixBefore reports whether the byte in front of page[off] is an
// instruction prefix, a legacy prefix or REX.
func hasPrefixBefore(before, page []byte, off int) bool {
	switch {
	case off > 0:
		return isX86Prefix(page[off-1])
	case len(before) > 0:
		return isX86Prefix(before[len(before)-1])
	default:
		return false
	}
}

// noReturnSyscallSetup reports whether inst loads a system call number that
// never returns to the instruction after SYSCALL: rt_sigreturn (15),
// exit (60), or exit_group (231). A function that ends with such a call needs
// no return instruction, so the next function can start directly at site+2.
func noReturnSyscallSetup(inst x86asm.Inst) bool {
	if inst.Op != x86asm.MOV {
		return false
	}
	reg, ok := inst.Args[0].(x86asm.Reg)
	if !ok || (reg != x86asm.AL && reg != x86asm.EAX && reg != x86asm.RAX) {
		return false
	}
	imm, ok := inst.Args[1].(x86asm.Imm)
	if !ok {
		return false
	}
	switch int64(imm) {
	case 15, 60, 231:
		return true
	}
	return false
}

// jmpPlanner decides which SYSCALL sites of one page can become a JMP rel32.
// It decodes the page once, and each plan reuses the result.
type jmpPlanner struct {
	before, page, after []byte
	buf                 []byte
	// target marks the buffer positions that a relative branch lands on. The
	// buffer is before, page, and after joined. The scan decodes at every byte
	// position, so a decode inside another instruction adds false targets, which
	// only make the planner more careful.
	target []bool
}

func newJmpPlanner(before, page, after []byte) *jmpPlanner {
	return &jmpPlanner{before: before, page: page, after: after}
}

// scan fills the target marks on first use.
func (p *jmpPlanner) scan() {
	if p.target != nil {
		return
	}
	buf := make([]byte, 0, len(p.before)+len(p.page)+len(p.after))
	buf = append(buf, p.before...)
	buf = append(buf, p.page...)
	buf = append(buf, p.after...)
	p.buf = buf
	p.target = make([]bool, len(buf))
	for pos := range buf {
		inst, err := decodeX86(buf[pos:])
		if err != nil || inst.Op == 0 || inst.Len == 0 {
			continue
		}
		for _, arg := range inst.Args {
			if rel, ok := arg.(x86asm.Rel); ok {
				if t := pos + inst.Len + int(rel); t >= 0 && t < len(buf) {
					p.target[t] = true
				}
			}
		}
	}
}

// precededByNoReturn reports whether an instruction that ends at p.buf[end]
// loads a system call number that never returns.
func (p *jmpPlanner) precededByNoReturn(end int) bool {
	for back := 1; back <= amd64MaxInsnLen && back <= end; back++ {
		inst, err := decodeX86(p.buf[end-back : end])
		if err == nil && inst.Len == back && noReturnSyscallSetup(inst) {
			return true
		}
	}
	return false
}

// planReject names the reason why a SYSCALL keeps its INT3 trap.
type planReject uint8

const (
	// planOK means that the planner found a patch.
	planOK planReject = iota
	// planPageEdge means that the bytes that the JMP needs leave the page.
	planPageEdge
	// planNotRelocatable means that an instruction that the JMP overwrites
	// cannot move, or does not decode.
	planNotRelocatable
	// planNoReturn means that the preceding instruction loads the number of a
	// system call that never returns.
	planNoReturn
	// planBranchTarget means that a relative branch lands inside the bytes that
	// the JMP overwrites.
	planBranchTarget
	// planPrefix means that a prefix byte stands in front of the SYSCALL.
	planPrefix

	planRejects
)

var planRejectNames = [planRejects]string{"ok", "page edge", "not relocatable", "no-return call", "branch target", "prefix"}

func (r planReject) String() string { return planRejectNames[r] }

// plan decides whether the SYSCALL at page[off] can become a JMP rel32. It
// returns the bytes to relocate into the slot, which are the whole
// instructions that start behind the SYSCALL and cover at least three bytes.
//
// The plan fails when the JMP or the relocated bytes leave the page, when an
// instruction behind the SYSCALL cannot move, when the preceding instruction
// loads a non-returning system call number, or when a relative branch that
// decodes in the page or in the neighbor bytes lands inside the bytes that the
// JMP overwrites. A branch from another page or an indirect jump can still land
// there. The patcher cannot see those, and it accepts the risk that the amd64
// scan already accepts for the bytes of the SYSCALL itself. The reason of a
// failure is the second result.
func (p *jmpPlanner) plan(off int) ([]byte, planReject) {
	page := p.page
	if off < 0 || off+winJmpLen > len(page) {
		return nil, planPageEdge
	}
	var reloc []byte
	pos := off + winSiteLen
	for len(reloc) < winMinRelocated {
		if pos >= len(page) {
			return nil, planPageEdge
		}
		inst, err := decodeX86(page[pos:])
		if err != nil || inst.Op == 0 || inst.Len == 0 || pos+inst.Len > len(page) || !relocatable(inst) {
			return nil, planNotRelocatable
		}
		reloc = append(reloc, page[pos:pos+inst.Len]...)
		pos += inst.Len
	}
	if len(reloc) > winMaxRelocated {
		return nil, planNotRelocatable
	}
	p.scan()
	start := len(p.before) + off
	if p.precededByNoReturn(start) {
		return nil, planNoReturn
	}
	for t := start + 1; t < start+winJmpLen; t++ {
		if p.target[t] {
			return nil, planBranchTarget
		}
	}
	return reloc, planOK
}

// canReplaceInPlace reports whether a siteLen-byte instruction at offset off in
// page can be overwritten with a 5-byte JMP without relocating the following
// instruction.
func (p *jmpPlanner) canReplaceInPlace(off, siteLen int) bool {
	if siteLen < winJmpLen || off < 0 || off+siteLen > len(p.page) {
		return false
	}
	p.scan()
	start := len(p.before) + off
	if p.precededByNoReturn(start) {
		return false
	}
	for t := start + 1; t < start+siteLen; t++ {
		if p.target[t] {
			return false
		}
	}
	return true
}

// planJmpPatch plans one site. A caller with many sites in one page uses a
// jmpPlanner, which decodes the page once.
func planJmpPatch(before, page, after []byte, off int) ([]byte, bool) {
	reloc, reject := newJmpPlanner(before, page, after).plan(off)
	return reloc, reject == planOK
}

// probeProgram returns the guest code of Probe: calls system calls with
// number 5, then one with number 6.
func probeProgram(calls int) []byte {
	n := uint32(calls)
	return []byte{
		0x41, 0xBC, byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24), // mov r12d, calls
		0xB8, 5, 0, 0, 0, // loop: mov eax, 5
		0x0F, 0x05, // syscall
		0x41, 0xFF, 0xCC, // dec r12d
		0x75, 0xF4, // jnz loop
		0xB8, 6, 0, 0, 0, // mov eax, 6
		0x0F, 0x05, // syscall
	}
}

// probeSyscallNumber returns the number of the system call that stopped the guest.
func probeSyscallNumber(ac *arch.Context64) uint64 { return ac.StateData().Regs.Orig_rax }
