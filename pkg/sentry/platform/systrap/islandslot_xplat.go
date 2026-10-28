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

// islandSlot describes one trampoline slot of the Windows engine.
type islandSlot struct {
	// site is the address of the patched instruction. For a SYSCALL it is the
	// address of the SYSCALL, and a trap at the slot returns to site+2.
	site uint64
	size uint32
	// jmpVA is the address of the JMP or the branch that enters the slot. It
	// equals site, except for a pre-window slot, where the JMP starts in front
	// of the SYSCALL.
	jmpVA uint64
	// insn holds the offset of each relocated instruction of a pre-window slot,
	// counted from the start of the slot. The instruction at offset k of the
	// slot is the instruction at jmpVA+k of the original code. The relocated
	// bytes end at site, so the entry code starts at offset site-jmpVA. insn is
	// nil for every other slot.
	insn []uint8
}

// plainSlot returns the record of a slot that a patched instruction at site
// enters directly.
func plainSlot(site uint64, size uint32) islandSlot {
	return islandSlot{site: site, size: size, jmpVA: site}
}

// contains reports whether the slot at slotVA holds the address pc.
func (s islandSlot) contains(slotVA, pc uint64) bool {
	return pc >= slotVA && pc-slotVA < uint64(s.size)
}

// guestPC translates the address pc in the slot at slotVA to the address that
// the original code had for the same instruction. It returns false when pc does
// not start a relocated instruction of a pre-window slot.
func (s islandSlot) guestPC(slotVA, pc uint64) (uint64, bool) {
	if len(s.insn) == 0 || !s.contains(slotVA, pc) {
		return 0, false
	}
	rel := pc - slotVA
	for _, off := range s.insn {
		if uint64(off) == rel {
			return s.jmpVA + rel, true
		}
	}
	return 0, false
}
