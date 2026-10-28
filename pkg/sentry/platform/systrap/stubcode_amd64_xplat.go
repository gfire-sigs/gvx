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
	// winSlotEntryLen is the length of the entry code of a slot: the two stores
	// to the TEB, the load of the tail address, and the jump to the spill
	// routine.
	winSlotEntryLen = 31
	// winPreSlotLiteralOffset is the offset of the literal that holds the address
	// of the spill routine in a pre-window slot. The literal follows the tail.
	winPreSlotLiteralOffset = 48
	// winPreMaxRelocated is the most bytes that the instructions before a
	// SYSCALL can have in a pre-window slot. The instructions run in front of the
	// entry code, and the entry code must end before the tail.
	winPreMaxRelocated = winSlotTailOffset - winSlotEntryLen

	// winPreSweeps is the number of linear decode sweeps that find the first
	// instruction of a pre-window. At least winPreAgree sweeps must reach the
	// SYSCALL and agree on that instruction.
	winPreSweeps = 16
	winPreAgree  = 12
	// winPreSweepBack is the distance in bytes from the SYSCALL to the first
	// byte of the first sweep. Each next sweep starts one byte later. Every
	// sweep then has at least 25 bytes to find the instruction boundaries
	// before it reaches a window of at most 9 bytes.
	winPreSweepBack = 40

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
// R14 is the call flag: it is 0 after the save, and 1 once the routine called
// into ntdll. These registers are callee-saved in the Windows calling
// convention, so the calls into ntdll keep them. The stack pointer lies 64
// bytes below the top of the stub stack, which leaves the 32-byte shadow space
// of a call and keeps the 16-byte alignment.
//
// A hot resume loads the vector state only when a call ran, because the call
// can clobber the volatile vector registers, or when the Sentry wrote the
// vector image (FPDirty). Without both, the vector registers still hold the
// guest state that the routine saved. A cold resume always loads it.
func buildSpill() (winSpillCode, error) { return buildSpillWith(spillOptions{}) }

// buildSpillWith generates the spill routine with the changes of opts.
func buildSpillWith(opts spillOptions) (winSpillCode, error) {
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
	if !opts.noVector {
		a.loadXsaveMask()
		a.xsave64(base, winOffXsave)
	}
	a.emit(0x45, 0x31, 0xF6) // xor r14d, r14d: no call yet

	// Publish Trapped. An x86 store has release semantics. The fence orders the
	// store before the load of the Sentry flag.
	a.movStoreImm32(base, winOffState, uint32(winStateTrapped))
	a.emit(0x0F, 0xAE, 0xF0) // mfence
	a.cmpMemImm8(base, winOffSentryWaiter, 0)
	a.jcc8(x86CCE, "spin")
	a.movLoad(x86RCX, base, winOffGuestEvent)
	a.emit(0x31, 0xD2) // xor edx, edx
	a.emit(0x41, 0xBE) // mov r14d, 1: a call can clobber the vector registers
	a.imm32(1)
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
	a.emit(0x41, 0xBE)       // mov r14d, 1
	a.imm32(1)
	a.callMem(base, winOffNtWait)
	a.movLoad32(x86RAX, base, winOffState)
	a.emit(0x83, 0xF8, byte(winStateRunHot))
	a.jcc8(x86CCB, "sleep")
	a.label("runclear")
	a.movStoreImm32(base, winOffStubWaiter, 0)
	a.label("run")
	a.emit(0x83, 0xF8, byte(winStateRunCold)) // cmp eax, RunCold
	a.jcc32(x86CCE, "cold")

	// Hot resume: load the vector state when a call ran or the Sentry wrote the
	// image, then load the FS base, the flags, the return address, and every
	// register, and jump to the tail.
	if !opts.noVector {
		a.emit(0x41, 0x83, 0xFE, 0x00) // cmp r14d, 0
		a.jcc8(x86CCNE, "hotload")
		a.cmpMemImm8(base, winOffFPDirty, 0)
		a.jcc8(x86CCE, "hotskip")
		a.label("hotload")
		a.loadXsaveMask()
		a.xrstor64(base, winOffXsave)
		a.movStoreImm32(base, winOffFPDirty, 0)
		a.label("hotskip")
	}
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
	if !opts.noVector {
		a.loadXsaveMask()
		a.xrstor64(base, winOffXsave)
		a.movStoreImm32(base, winOffFPDirty, 0)
	}
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
	if len(reloc) < winMinRelocated {
		return fmt.Errorf("slot with %d relocated bytes", len(reloc))
	}
	moved, err := relocateInstructions(reloc, site+winSiteLen, slotVA+winSlotTailOffset, true)
	if err != nil {
		return err
	}
	if len(moved) > winMaxRelocated {
		return fmt.Errorf("slot with %d relocated bytes after the move", len(moved))
	}
	var a x86Asm
	a.slotEntry(winSlotTailOffset, winSlotLiteralOffset)
	for len(a.b) < winSlotLiteralOffset {
		a.emit(0xCC)
	}
	a.b = binary.LittleEndian.AppendUint64(a.b, spill)
	a.b = append(a.b, moved...)
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

// slotEntry emits the entry code of a slot at the current position. The code
// saves RAX in the TEB, loads RAX with the address of the slot tail, saves it
// in the TEB, and jumps through the literal to the spill routine. tailOffset
// and literalOffset are slot offsets, and the code starts at the slot offset
// len(a.b). The code has winSlotEntryLen bytes.
func (a *x86Asm) slotEntry(tailOffset, literalOffset int) {
	at := len(a.b)
	a.movStoreGS(winTEBScratchA, x86RAX)
	// lea rax, [rip+tail]: the instruction ends 16 bytes after the entry start.
	a.emit(0x48, 0x8D, 0x05)
	a.imm32(uint32(int32(tailOffset - (at + 16))))
	a.movStoreGS(winTEBScratchB, x86RAX)
	// jmp [rip+literal]: the instruction ends at the end of the entry code.
	a.emit(0xFF, 0x25)
	a.imm32(uint32(int32(literalOffset - (at + winSlotEntryLen))))
}

// The pre-window slot must hold at least the 5 bytes of a JMP.
var _ = [winPreMaxRelocated - winJmpLen]struct{}{}

// encodeWinPreSlot writes the slot for a SYSCALL at site that a JMP in front
// of the SYSCALL reaches. reloc holds the instructions that the JMP overwrites.
// They end at site. The SYSCALL keeps its INT3 trap. The slot runs reloc, jumps
// to the spill routine, and its tail jumps to site+2 without relocated
// instructions:
//
//	reloc
//	mov  gs:[winTEBScratchA], rax
//	lea  rax, [rip+tail]
//	mov  gs:[winTEBScratchB], rax
//	jmp  [rip+literal]
//	tail:
//	  jmp  site+2
//	literal: <address of the spill routine>
func encodeWinPreSlot(buf []byte, slotVA, site, spill uint64, reloc []byte) error {
	if len(buf) < winSlotSize {
		return fmt.Errorf("slot buffer has %d bytes", len(buf))
	}
	if len(reloc) < winJmpLen || len(reloc) > winPreMaxRelocated {
		return fmt.Errorf("pre-window slot with %d relocated bytes", len(reloc))
	}
	// The instructions end at site, so they start len(reloc) bytes before it.
	moved, err := relocateInstructions(reloc, site-uint64(len(reloc)), slotVA, false)
	if err != nil {
		return err
	}
	if len(moved) != len(reloc) {
		return fmt.Errorf("the move changed %d relocated bytes to %d", len(reloc), len(moved))
	}
	var a x86Asm
	a.emit(moved...)
	a.slotEntry(winSlotTailOffset, winPreSlotLiteralOffset)
	if len(a.b) != len(reloc)+winSlotEntryLen {
		return fmt.Errorf("slot entry code has %d bytes, want %d", len(a.b)-len(reloc), winSlotEntryLen)
	}
	for len(a.b) < winSlotTailOffset {
		a.emit(0xCC)
	}
	rel, err := rel32(slotVA+winSlotTailOffset+winJmpLen, site+winSiteLen)
	if err != nil {
		return err
	}
	a.emit(0xE9)
	a.imm32(rel)
	for len(a.b) < winPreSlotLiteralOffset {
		a.emit(0xCC)
	}
	a.b = binary.LittleEndian.AppendUint64(a.b, spill)
	for len(a.b) < winSlotSize {
		a.emit(0xCC)
	}
	copy(buf, a.b)
	return nil
}

// insnOffsets returns the offset of each instruction in code. It returns false
// when code does not consist of whole instructions.
func insnOffsets(code []byte) ([]uint8, bool) {
	var offs []uint8
	for pos := 0; pos < len(code); {
		inst, err := decodeX86(code[pos:])
		if err != nil || inst.Op == 0 || inst.Len == 0 || pos+inst.Len > len(code) {
			return nil, false
		}
		offs = append(offs, uint8(pos))
		pos += inst.Len
	}
	return offs, true
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

// relocClass names how an instruction moves into a slot.
type relocClass uint8

const (
	// relocNone means that the instruction cannot move.
	relocNone relocClass = iota
	// relocCopy means that the bytes keep their meaning at another address.
	relocCopy
	// relocRIP means that the instruction has a RIP-relative operand. The move
	// adjusts the 32-bit displacement and keeps the length.
	relocRIP
	// relocJcc means a conditional branch with a rel8 or rel32 target. The move
	// re-encodes it as `0F 8x rel32` to the original target.
	relocJcc
	// relocJmp means an unconditional JMP with a rel8 or rel32 target. The move
	// re-encodes it as `E9 rel32` to the original target.
	relocJmp
)

// movesBeforeSyscall reports whether an instruction of the class can move to a
// pre-window slot. The slot runs the instructions in front of the SYSCALL, and
// a branch there leaves the window while the SYSCALL has not run.
func (c relocClass) movesBeforeSyscall() bool { return c == relocCopy || c == relocRIP }

// size returns the length in bytes of an instruction of origLen bytes after
// the move.
func (c relocClass) size(origLen int) int {
	switch c {
	case relocJcc:
		return 6
	case relocJmp:
		return winJmpLen
	}
	return origLen
}

// classifyReloc decides how the instruction inst, which has the bytes code,
// moves to another address. A call, a return, and the loop and JCXZ forms
// depend on the address and have no `rel32` form, so they cannot move. A system
// call instruction or an interrupt would reach the engine again. An operand with
// a segment override stays in place, because Windows can reset the FS base while
// the slot runs, and the engine repairs the base only for faults in guest pages.
func classifyReloc(inst x86asm.Inst, code []byte) relocClass {
	if class := classifyBranch(inst, code); class != relocNone {
		return class
	}
	op := inst.Op.String()
	for _, p := range []string{"J", "CALL", "LCALL", "LJMP", "RET", "LRET", "IRET", "INT", "SYSCALL", "SYSENTER", "SYSEXIT", "SYSRET", "LOOP", "XBEGIN", "HLT", "UD", "RDFSBASE", "RDGSBASE", "WRFSBASE", "WRGSBASE"} {
		if strings.HasPrefix(op, p) {
			return relocNone
		}
	}
	class := relocCopy
	for _, arg := range inst.Args {
		switch a := arg.(type) {
		case x86asm.Rel:
			return relocNone
		case x86asm.Mem:
			if a.Segment != 0 {
				return relocNone
			}
			switch {
			case a.Base == x86asm.RIP:
				if inst.PCRel != 4 || inst.PCRelOff+inst.PCRel > inst.Len {
					return relocNone
				}
				class = relocRIP
			case a.Base == x86asm.EIP || a.Base == x86asm.IP:
				// An address-size prefix makes the displacement relative to EIP, and
				// the move would need a 32-bit wrap.
				return relocNone
			case a.Base == 0 && a.Index == 0 && hasVEXOpcode(code):
				// x86asm leaves out the RIP base of a VEX or EVEX operand, so the
				// decode cannot tell it from an absolute address.
				return relocNone
			}
		}
	}
	return class
}

// classifyBranch returns relocJcc or relocJmp for a branch in one of the four
// forms that have a `rel32` encoding: Jcc rel8, Jcc rel32, JMP rel8, and JMP
// rel32, with no prefix. It returns relocNone for any other instruction.
func classifyBranch(inst x86asm.Inst, code []byte) relocClass {
	if len(code) != inst.Len || len(inst.Args) == 0 {
		return relocNone
	}
	if _, ok := inst.Args[0].(x86asm.Rel); !ok {
		return relocNone
	}
	switch {
	case inst.Len == 2 && code[0] >= 0x70 && code[0] <= 0x7F,
		inst.Len == 6 && code[0] == 0x0F && code[1] >= 0x80 && code[1] <= 0x8F:
		return relocJcc
	case inst.Len == 2 && code[0] == 0xEB, inst.Len == winJmpLen && code[0] == 0xE9:
		return relocJmp
	}
	return relocNone
}

// hasVEXOpcode reports whether the instruction in code has a VEX or EVEX
// prefix after its legacy prefixes.
func hasVEXOpcode(code []byte) bool {
	for _, b := range code {
		if b == 0xC4 || b == 0xC5 || b == 0x62 {
			return true
		}
		if !isX86Prefix(b) {
			return false
		}
	}
	return false
}

// appendRelocated appends the instruction inst, which has the bytes code, as
// it must read at newVA when its original address is origVA. A RIP-relative
// operand keeps its target. A branch becomes the `rel32` form with its original
// target. It fails when a displacement no longer fits in 32 bits.
func appendRelocated(dst, code []byte, inst x86asm.Inst, class relocClass, origVA, newVA uint64) ([]byte, error) {
	origNext := int64(origVA) + int64(inst.Len)
	switch class {
	case relocCopy:
		return append(dst, code...), nil
	case relocRIP:
		start := len(dst)
		dst = append(dst, code...)
		disp := int64(int32(binary.LittleEndian.Uint32(code[inst.PCRelOff:])))
		moved := disp + origNext - (int64(newVA) + int64(inst.Len))
		if moved != int64(int32(moved)) {
			return nil, fmt.Errorf("RIP-relative displacement %#x of the instruction at %#x does not fit at %#x", disp, origVA, newVA)
		}
		binary.LittleEndian.PutUint32(dst[start+inst.PCRelOff:], uint32(int32(moved)))
		return dst, nil
	case relocJcc, relocJmp:
		target := origNext + int64(inst.Args[0].(x86asm.Rel))
		size := class.size(inst.Len)
		moved := target - (int64(newVA) + int64(size))
		if moved != int64(int32(moved)) {
			return nil, fmt.Errorf("branch at %#x to %#x does not reach from %#x", origVA, uint64(target), newVA)
		}
		if class == relocJmp {
			dst = append(dst, 0xE9)
		} else {
			cc := code[0] & 0x0F
			if code[0] == 0x0F {
				cc = code[1] & 0x0F
			}
			dst = append(dst, 0x0F, 0x80|cc)
		}
		return binary.LittleEndian.AppendUint32(dst, uint32(int32(moved))), nil
	}
	return nil, fmt.Errorf("instruction at %#x cannot move", origVA)
}

// relocateInstructions returns the whole instructions in code, which sit at the
// address origVA, as they must read at the address newVA. With branches false,
// a branch cannot move.
func relocateInstructions(code []byte, origVA, newVA uint64, branches bool) ([]byte, error) {
	var out []byte
	for pos := 0; pos < len(code); {
		inst, err := decodeX86(code[pos:])
		if err != nil || inst.Op == 0 || inst.Len == 0 || pos+inst.Len > len(code) {
			return nil, fmt.Errorf("bytes % x at %#x are not a whole instruction", code[pos:], origVA+uint64(pos))
		}
		raw := code[pos : pos+inst.Len]
		class := classifyReloc(inst, raw)
		if class == relocNone || (!branches && !class.movesBeforeSyscall()) {
			return nil, fmt.Errorf("instruction % x at %#x cannot move into the slot", raw, origVA+uint64(pos))
		}
		out, err = appendRelocated(out, raw, inst, class, origVA+uint64(pos), newVA+uint64(len(out)))
		if err != nil {
			return nil, err
		}
		pos += inst.Len
	}
	return out, nil
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
	moved := 0
	pos := off + winSiteLen
	for len(reloc) < winMinRelocated {
		if pos >= len(page) {
			return nil, planPageEdge
		}
		inst, err := decodeX86(page[pos:])
		if err != nil || inst.Op == 0 || inst.Len == 0 || pos+inst.Len > len(page) {
			return nil, planNotRelocatable
		}
		class := classifyReloc(inst, page[pos:pos+inst.Len])
		switch class {
		case relocNone:
			return nil, planNotRelocatable
		case relocJcc, relocJmp:
			// The slot jumps to the original target. A target inside the bytes
			// that the JMP overwrites would run the JMP bytes as code.
			if target := pos + inst.Len + int(inst.Args[0].(x86asm.Rel)); target > off && target < off+winJmpLen {
				return nil, planBranchTarget
			}
			// An unconditional jump ends the slot, and the bytes behind it can
			// be the target of a branch from another page. The JMP of the patch
			// must not overwrite them, so the jump must end at or behind the end of
			// the patch.
			if class == relocJmp && len(reloc)+inst.Len < winMinRelocated {
				return nil, planNotRelocatable
			}
		}
		moved += class.size(inst.Len)
		reloc = append(reloc, page[pos:pos+inst.Len]...)
		pos += inst.Len
	}
	if moved > winMaxRelocated {
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

// preWindowStart returns the buffer position of the first instruction of the
// window that ends at the buffer position site. The window is the fewest whole
// instructions that cover at least winJmpLen bytes.
//
// The decoder cannot run backward, so winPreSweeps linear sweeps start at
// consecutive bytes before the site. A sweep votes when it reaches the site
// exactly, which means that the site is an instruction boundary for it. At
// least winPreAgree sweeps must agree on the first instruction of the window.
func (p *jmpPlanner) preWindowStart(site int) (int, bool) {
	type vote struct{ start, n int }
	var votes [winPreSweeps]vote
	nvotes := 0
	// lens caches the instruction length at each position before the site.
	// Zero is unknown, and -1 is a byte that does not start an instruction.
	var lens [winPreSweepBack]int8
	first := site - winPreSweepBack
	prev := -1
	for k := 0; k < winPreSweeps; k++ {
		from := max(first+k, 0)
		if from == prev {
			continue
		}
		prev = from
		cand := -1
		pos := from
		for pos < site {
			if pos <= site-winJmpLen {
				cand = pos
			}
			l := &lens[pos-first]
			if *l == 0 {
				inst, err := decodeX86(p.buf[pos:])
				if err != nil || inst.Op == 0 || inst.Len == 0 {
					*l = -1
				} else {
					*l = int8(inst.Len)
				}
			}
			pos += max(int(*l), 1)
		}
		if pos != site || cand < 0 {
			continue
		}
		i := 0
		for i < nvotes && votes[i].start != cand {
			i++
		}
		if i == nvotes {
			votes[i].start = cand
			nvotes++
		}
		votes[i].n++
	}
	for _, v := range votes[:nvotes] {
		if v.n >= winPreAgree {
			return v.start, true
		}
	}
	return 0, false
}

// planBefore decides whether the SYSCALL at page[off] can keep its INT3 trap
// while a JMP rel32 replaces the instructions in front of it. It returns the
// page offset of the JMP and the bytes of the instructions that the JMP
// overwrites, which the slot runs before it enters the spill routine.
//
// The plan succeeds only when all of these hold:
//
//   - At least winPreAgree decode sweeps agree on the instruction boundaries
//     and reach the SYSCALL exactly.
//   - The instructions cover winJmpLen to winPreMaxRelocated bytes.
//   - The first instruction and the byte behind the SYSCALL lie in the page.
//   - Every instruction can move to another address.
//   - No relative branch that decodes in the page or in the neighbor bytes
//     lands inside the window, except at its first byte.
//
// A branch to the SYSCALL meets its INT3 trap, which stays correct. The bytes
// behind the SYSCALL do not change, so the plan needs no check of them. The
// caller checks that the window does not overlap another patch, and that no
// prefix stands in front of the SYSCALL.
func (p *jmpPlanner) planBefore(off int) (int, []byte, bool) {
	if off < 0 || off+winSiteLen >= len(p.page) {
		return 0, nil, false
	}
	p.scan()
	site := len(p.before) + off
	start, ok := p.preWindowStart(site)
	if !ok || start < len(p.before) || site-start < winJmpLen || site-start > winPreMaxRelocated {
		return 0, nil, false
	}
	for pos := start; pos < site; {
		inst, err := decodeX86(p.buf[pos:site])
		if err != nil || inst.Op == 0 || inst.Len == 0 || !classifyReloc(inst, p.buf[pos:pos+inst.Len]).movesBeforeSyscall() {
			return 0, nil, false
		}
		pos += inst.Len
	}
	for t := start + 1; t < site; t++ {
		if p.target[t] {
			return 0, nil, false
		}
	}
	return start - len(p.before), append([]byte(nil), p.buf[start:site]...), true
}

// planKind names how patchPage patches a SYSCALL site.
type planKind uint8

const (
	// planTrap keeps the INT3 trap. The debugger serves the system call.
	planTrap planKind = iota
	// planPost replaces the SYSCALL and the bytes behind it with a JMP.
	planPost
	// planPre replaces the instructions in front of the SYSCALL with a JMP and
	// keeps the INT3 trap at the SYSCALL.
	planPre
)

func (k planKind) String() string { return [...]string{"trap", "post", "pre"}[k] }

// sitePlan is the result of planSite.
type sitePlan struct {
	kind planKind
	// reject is the reason why the post plan failed. It is planOK for planPost.
	reject planReject
	// reloc holds the instructions that the slot runs. They follow the SYSCALL
	// for planPost and end at the SYSCALL for planPre.
	reloc []byte
	// start is the page offset of the JMP of a planPre.
	start int
}

// planSite decides how to patch the SYSCALL at page[off]. The post plan, which
// keeps the current behavior of every site that it patches, comes first. The
// pre plan applies only when the post plan fails. floor is the lowest page
// offset that a pre plan can overwrite, because the bytes below it belong to
// another site.
func (p *jmpPlanner) planSite(off, floor int) sitePlan {
	if hasPrefixBefore(p.before, p.page, off) {
		// A prefix applies to the instruction at the JMP, or becomes a part of
		// the instruction that ends at the SYSCALL.
		return sitePlan{kind: planTrap, reject: planPrefix}
	}
	reloc, reject := p.plan(off)
	if reject == planOK {
		return sitePlan{kind: planPost, reloc: reloc}
	}
	if start, reloc, ok := p.planBefore(off); ok && start >= floor {
		return sitePlan{kind: planPre, reject: reject, reloc: reloc, start: start}
	}
	return sitePlan{kind: planTrap, reject: reject}
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
