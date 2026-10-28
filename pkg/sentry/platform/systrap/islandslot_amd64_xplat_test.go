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

import "testing"

func TestPreWindowSitesMapEveryRelocatedInstructionBothWays(t *testing.T) {
	// nop; mov eax, ebx; mov [rsp+8], r11
	window := []byte{0x90, 0x89, 0xD8, 0x4C, 0x89, 0x5C, 0x24, 0x08}
	insn, ok := insnOffsets(window)
	if !ok {
		t.Fatal("the window does not decode")
	}
	const (
		base   = 0x7ff0_1000_0000
		start  = 0x100
		slotVA = 0x7ff0_1100_0040
	)
	site := start + len(window)
	sys := amd64Site{Offset: site, Len: 2, Kind: amd64SiteSyscall}
	sites := preWindowSites(start, slotVA, insn, sys)
	slot := islandSlot{site: base + uint64(site), size: winSlotSize, jmpVA: base + start, insn: insn}

	if got := sites[start].kind; got != winSiteJumpBefore {
		t.Errorf("the JMP has kind %#x, want winSiteJumpBefore", got)
	}
	if s := sites[uint16(site)]; s.kind != amd64SiteSyscall || s.length != 2 || s.entry != slotVA+uint64(len(window)) {
		t.Errorf("the SYSCALL site is %+v, want a trap whose entry is the entry code of the slot", s)
	}
	if len(sites) != len(insn)+1 {
		t.Errorf("the patch has %d sites, want one for each relocated instruction and one for the SYSCALL", len(sites))
	}
	for _, off := range insn[1:] {
		s := sites[uint16(start+int(off))]
		if s.kind != winSiteRelocated || s.entry != slotVA+uint64(off) {
			t.Errorf("relocated instruction at %d has site %+v, want entry %#x", off, s, slotVA+uint64(off))
		}
		// The way back: the slot address names the original address.
		if got, ok := slot.guestPC(slotVA, s.entry); !ok || got != base+start+uint64(off) {
			t.Errorf("guestPC(%#x) = %#x, %v; want %#x", s.entry, got, ok, base+start+uint64(off))
		}
	}
	if got, ok := slot.guestPC(slotVA, slotVA); !ok || got != base+start {
		t.Errorf("guestPC of the first instruction = %#x, %v; want the JMP at %#x", got, ok, base+start)
	}
	// An address that no relocated instruction starts at keeps its value.
	for _, pc := range []uint64{slotVA + 2, slotVA + 4, slotVA + uint64(len(window)), slotVA + winSlotTailOffset, slotVA + winSlotSize} {
		if got, ok := slot.guestPC(slotVA, pc); ok {
			t.Errorf("guestPC(%#x) = %#x, want no translation", pc, got)
		}
	}
	if _, ok := plainSlot(base+start, winSlotSize).guestPC(slotVA, slotVA); ok {
		t.Error("a plain slot translated an address")
	}
}
