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
	"testing"
)

func TestClassifyMemAccess(t *testing.T) {
	// The words come from an assembler. The comment names the instruction.
	for _, tc := range []struct {
		name string
		insn uint32
		ok   bool
		want memAccess
	}{
		{"ldr x0, [x1, #8]", 0xf9400420, true, memAccess{base: 1, index: 31}},
		{"str x0, [x1], #8", 0xf8008420, true, memAccess{base: 1, index: 31}},
		{"ldp x0, x1, [x2]", 0xa9400440, true, memAccess{base: 2, index: 31}},
		{"ldxr w4, [x10]", 0x885f7d44, true, memAccess{base: 10, index: 31}},
		{"ldadd x1, x2, [x3]", 0xf8210062, true, memAccess{base: 3, index: 31}},
		{"ldr x0, [x1, x2, lsl #3]", 0xf8627820, true, memAccess{base: 1, index: 2, hasIndex: true}},
		{"ld1 {v0.16b}, [x0], x1", 0x4cc17000, true, memAccess{base: 0, index: 31}},
		{"ldr x1, [x1]", 0xf9400021, true, memAccess{base: 1, index: 31, skipsRestore: true}},
		{"ldrb w0, [x27, #0xe08] (offset bit 11 set)", 0x39782360, true, memAccess{base: 27, index: 31}},
		{"ldr x0, [x1, #0x7ff8] (largest offset)", 0xf97ffc20, true, memAccess{base: 1, index: 31}},
		{"ldr x3, [x16, x5, lsl #3] (Go uses x16)", 0xf8657a03, true, memAccess{base: 16, index: 5, hasIndex: true}},
		{"str x16, [x16] (stored scratch base)", 0xf9000210, false, memAccess{}},
		{"str x1, [x1, #16]", 0xf9000821, true, memAccess{base: 1, index: 31, storeFirst: true}},
		{"ldp x2, x1, [x1]", 0xa9400422, true, memAccess{base: 1, index: 31, skipsRestore: true}},
		{"stp x1, x2, [x1]", 0xa9000821, true, memAccess{base: 1, index: 31, storeFirst: true}},
		{"dc zva, x3", 0xd50b7423, true, memAccess{base: 3, index: 31}},
		{"dc civac, x0", 0xd50b7e20, true, memAccess{base: 0, index: 31}},
		{"ic ivau, x1", 0xd50b7521, true, memAccess{base: 1, index: 31}},
		{"dc ivac, x10", 0xd508762a, true, memAccess{base: 10, index: 31}},
		{"dc zva, xzr (names no address)", 0xd50b743f, false, memAccess{}},
		{"dc isw, x0 (by set and way)", 0xd5087640, false, memAccess{}},
		{"ldr x0, [sp, #8]", 0xf94007e0, false, memAccess{}},
		{"ldr x0, #8 (literal)", 0x58000040, false, memAccess{}},
		{"add x0, x1, x2", 0x8b020020, false, memAccess{}},
	} {
		got, ok := classifyMemAccess(tc.insn)
		if ok != tc.ok {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.ok)
			continue
		}
		if ok && got != tc.want {
			t.Errorf("%s: access = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}

func TestZoneBiasEncodings(t *testing.T) {
	// These words come from an assembler: orr x5, x5, #0x400000000000 and
	// and x5, x5, #0xffffbfffffffffff and tbnz x5, #46, +8.
	if got := encodeBiasOrr(5, 5); got != 0xb25200a5 {
		t.Errorf("orr = %#x, want 0xb25200a5", got)
	}
	if got := encodeBiasAnd(5, 5); got != 0x9251f8a5 {
		t.Errorf("and = %#x, want 0x9251f8a5", got)
	}
	if got := encodeBiasTBNZ(5, 8); got != 0xb7700045 {
		t.Errorf("tbnz = %#x, want 0xb7700045", got)
	}
	if zoneBias != 1<<46 {
		t.Errorf("zoneBias = %#x, want bit 46", uint64(zoneBias))
	}
}

func TestMemSlotKeepsTheBranchBackAndBothPaths(t *testing.T) {
	const site, slotVA = zoneBias + 0x400100, zoneBias + 0x10_0000
	insn := uint32(0xf9400420) // ldr x0, [x1, #8]
	acc, _ := classifyMemAccess(insn)
	buf := make([]byte, memSlotSize)
	size, body, err := encodeMemSlot(buf, slotVA, site, insn, acc)
	if err != nil || size != memSlotSize {
		t.Fatalf("encodeMemSlot = (%d, %d, %v)", size, body, err)
	}
	word := func(i int) uint32 { return binary.LittleEndian.Uint32(buf[i*4:]) }
	if word(body) != insn {
		t.Errorf("biased word %d = %#x, want the instruction %#x", body, word(body), insn)
	}
	var plain int
	for i := body + 1; i < memSlotSize/4; i++ {
		if word(i) == insn {
			plain = i
		}
	}
	if plain == 0 {
		t.Fatal("the slot has no plain copy of the instruction")
	}
	for _, i := range []int{plain + 1, body + 2} {
		target, ok := decodeBranch(slotVA+uint64(i)*4, word(i))
		if !ok || target != site+4 {
			t.Errorf("word %d branches to %#x, want %#x", i, target, uint64(site+4))
		}
	}
	// The test of the base register jumps over the biased path to the plain copy.
	if got, want := word(0), encodeBiasTBNZ(1, plain*4); got != want {
		t.Errorf("first word = %#x, want %#x", got, want)
	}
}

func TestScanZoneFindsTheInstructionsThatNeedSlots(t *testing.T) {
	// The page lies in the zone. adrp x3 reaches a page of the zone, and the
	// second adrp reaches a page outside it.
	const base = zoneBias + 0x400000
	code := make([]byte, 64)
	put := func(i int, w uint32) { binary.LittleEndian.PutUint32(code[i*4:], w) }
	put(0, 0x90000003) // adrp x3, +0 pages: the page of the instruction itself
	put(1, 0x907fffe4) // adrp x4, +4GB less 16KB: outside the zone
	put(2, 0xd63f0100) // blr x8
	put(3, 0xd61f0120) // br x9
	put(4, 0xd65f03c0) // ret x30
	put(5, 0x9000001f) // adrp xzr: discards the result
	put(6, 0x94000010) // bl +0x40
	sites := scanZone(code, base, func(int) bool { return false })
	if len(sites) != 5 {
		t.Fatalf("scanZone found %d sites, want 5: %+v", len(sites), sites)
	}
	if s := sites[0]; s.kind != siteAdrp || s.reg != 3 || s.value != 0x400000 {
		t.Errorf("first site = %+v, want adrp x3 with value 0x400000", s)
	}
	if s := sites[1]; s.kind != siteIndirect || s.reg != 8 || !s.link {
		t.Errorf("second site = %+v, want blr x8", s)
	}
	if s := sites[2]; s.kind != siteIndirect || s.reg != 9 || s.link {
		t.Errorf("third site = %+v, want br x9", s)
	}
	if s := sites[3]; s.kind != siteIndirect || s.reg != 30 || s.link {
		t.Errorf("fourth site = %+v, want ret x30", s)
	}
	if s := sites[4]; s.kind != siteBL || s.value != base+24+0x40 {
		t.Errorf("fifth site = %+v, want bl with target %#x", s, uint64(base+24+0x40))
	}
}
