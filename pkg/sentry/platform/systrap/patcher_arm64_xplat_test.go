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
	"reflect"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func words(ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

func TestScanARM64FindsEveryClass(t *testing.T) {
	code := words(
		0xd503201f, // nop
		0xd4000001, // svc #0
		0xd4000021, // svc #1: not a Linux system call
		0xd53bd040, // mrs x0, tpidr_el0
		0xd53bd05e, // mrs x30, tpidr_el0
		0xd53bd05f, // mrs xzr, tpidr_el0
		0xd53bd060, // mrs x0, tpidrro_el0: not virtualized
		0xd51bd041, // msr tpidr_el0, x1
		0xd51bd05f, // msr tpidr_el0, xzr
		0xd53bd240, // mrs x0, a different system register
		0xd5033fdf, // isb
		0xd4000001, // svc #0 again
	)
	want := []patchSite{
		{Offset: 4, Kind: siteSVC, Orig: 0xd4000001},
		{Offset: 12, Kind: siteMRS, Reg: 0, Orig: 0xd53bd040},
		{Offset: 16, Kind: siteMRS, Reg: 30, Orig: 0xd53bd05e},
		{Offset: 20, Kind: siteMRS, Reg: 31, Orig: 0xd53bd05f},
		{Offset: 28, Kind: siteMSR, Reg: 1, Orig: 0xd51bd041},
		{Offset: 32, Kind: siteMSR, Reg: 31, Orig: 0xd51bd05f},
		{Offset: 44, Kind: siteSVC, Orig: 0xd4000001},
	}
	if got := scanARM64(code); !reflect.DeepEqual(got, want) {
		t.Fatalf("scanARM64 = %+v, want %+v", got, want)
	}
	if got := scanARM64(code[:6]); len(got) != 0 {
		t.Fatalf("a short buffer yielded %+v", got)
	}
}

func TestEncodeBranchRange(t *testing.T) {
	cases := []struct {
		from, to uint64
		ok       bool
	}{
		{0x1000_0000, 0x1000_0004, true},
		{0x1000_0000, 0x1000_0000 - 4, true},
		{0x1000_0000, 0x1000_0000 + arm64BranchRange - 4, true},
		{0x1000_0000, 0x1000_0000 - arm64BranchRange + 4, true},
		{0x1000_0000, 0x1000_0000 + arm64BranchRange, false},
		{0x1000_0000, 0x1000_0000 - arm64BranchRange, false},
		{0x1000_0000, 0x1000_0002, false},
		{0x1000_0002, 0x1000_0004, false},
	}
	for _, c := range cases {
		insn, err := encodeBranch(c.from, c.to)
		if (err == nil) != c.ok {
			t.Errorf("encodeBranch(%#x, %#x) error = %v, want ok=%v", c.from, c.to, err, c.ok)
			continue
		}
		if !c.ok {
			continue
		}
		if got, ok := decodeBranch(c.from, insn); !ok || got != c.to {
			t.Errorf("decodeBranch(%#x, %#x) = %#x, %v, want %#x", c.from, insn, got, ok, c.to)
		}
	}
	// Known encoding: b .+8 is 0x14000002.
	if insn, _ := encodeBranch(0x1000, 0x1008); insn != 0x14000002 {
		t.Errorf("b .+8 = %#x, want 0x14000002", insn)
	}
	if _, ok := decodeBranch(0, 0xd4000001); ok {
		t.Errorf("decodeBranch accepted svc")
	}
}

func TestTrapSlotLayout(t *testing.T) {
	const slotVA, ret, spill = 0x5000_0100, 0x5000_8000, 0x1_0000_1234
	buf := make([]byte, trapSlotSize)
	if err := encodeTrapSlot(buf, slotVA, ret, spill); err != nil {
		t.Fatal(err)
	}
	w := func(i int) uint32 { return binary.LittleEndian.Uint32(buf[4*i:]) }
	// Disassembly: stp x16, x17, [sp, #-16]; adr x17, .+12; ldr x16, .+16; br x16;
	// ldp x16, x17, [sp, #-16]; b ret; .quad spill.
	if w(0) != 0xa93f47f0 || w(1) != 0x10000071 || w(2) != 0x58000090 || w(3) != 0xd61f0200 || w(4) != 0xa97f47f0 {
		t.Errorf("slot words = %#x %#x %#x %#x %#x", w(0), w(1), w(2), w(3), w(4))
	}
	if target, ok := decodeBranch(slotVA+20, w(5)); !ok || target != ret {
		t.Errorf("slot returns to %#x, %v, want %#x", target, ok, uint64(ret))
	}
	if got := binary.LittleEndian.Uint64(buf[24:]); got != spill {
		t.Errorf("slot literal = %#x, want %#x", got, uint64(spill))
	}
	// The slot must keep X30: no instruction of the slot writes x30.
	for i := 0; i < 6; i++ {
		if w(i)&0x1f == 30 && w(i)&0xffe00000 != 0xa9000000 && i != 5 {
			t.Errorf("slot word %d (%#x) names x30", i, w(i))
		}
	}
	if err := encodeTrapSlot(make([]byte, 8), slotVA, ret, spill); err == nil {
		t.Error("a short buffer must fail")
	}
	if err := encodeTrapSlot(buf, slotVA, slotVA+arm64BranchRange+64, spill); err == nil {
		t.Error("an out-of-range return must fail")
	}
}

func TestLoadSlotLayout(t *testing.T) {
	for reg := uint8(0); reg < 31; reg++ {
		buf := make([]byte, loadSlotSize)
		if err := encodeLoadSlot(buf, 0x6000_0000, 0x6000_4000, reg, 24); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		w := func(i int) uint32 { return binary.LittleEndian.Uint32(buf[4*i:]) }
		r := uint32(reg)
		if w(0) != 0xd53bd060|r {
			t.Errorf("x%d: mrs tpidrro word %#x", reg, w(0))
		}
		if w(1) != 0x927df000|r<<5|r {
			t.Errorf("x%d: and word %#x", reg, w(1))
		}
		if w(2) != 0xf9400c00|r<<5|r {
			t.Errorf("x%d: ldr word %#x", reg, w(2))
		}
		if target, ok := decodeBranch(0x6000_0000+12, w(3)); !ok || target != 0x6000_4000 {
			t.Errorf("x%d: returns to %#x, %v", reg, target, ok)
		}
	}
	if err := encodeLoadSlot(make([]byte, loadSlotSize), 0, 4, 31, 24); err == nil {
		t.Error("xzr must be rejected")
	}
	if err := encodeLoadSlot(make([]byte, loadSlotSize), 0, 4, 1, 20); err == nil {
		t.Error("an unaligned tls offset must be rejected")
	}
}

func TestScanARM64FindsCtrReads(t *testing.T) {
	code := words(
		0xd503201f, // nop
		0xd53b0020, // mrs x0, ctr_el0
		0xd53b003e, // mrs x30, ctr_el0
		0xd53b003f, // mrs xzr, ctr_el0
		0xd53b00e0, // mrs x0, dczid_el0: macOS runs it natively
		0xd53b0000, // mrs x0, midr_el1: guarded by HWCAP_CPUID, which is not advertised
		0xd53bd040, // mrs x0, tpidr_el0
	)
	want := []patchSite{
		{Offset: 4, Kind: siteCTR, Reg: 0, Orig: 0xd53b0020},
		{Offset: 8, Kind: siteCTR, Reg: 30, Orig: 0xd53b003e},
		{Offset: 12, Kind: siteCTR, Reg: 31, Orig: 0xd53b003f},
		{Offset: 24, Kind: siteMRS, Reg: 0, Orig: 0xd53bd040},
	}
	if got := scanARM64(code); !reflect.DeepEqual(got, want) {
		t.Fatalf("scanARM64 = %+v, want %+v", got, want)
	}
}

func TestCtrSlotLoadsTheConstantAndReturns(t *testing.T) {
	const slotVA, retPC = 0x6000_0000, 0x6000_4000
	for reg := uint8(0); reg < 31; reg++ {
		buf := make([]byte, loadSlotSize)
		if err := encodeCTRSlot(buf, slotVA, retPC, reg); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		w := func(i int) uint32 { return binary.LittleEndian.Uint32(buf[4*i:]) }

		var value uint64
		// The decoder reports a movz with a plain immediate as its MOV alias.
		for i, wantOp := range []arm64asm.Op{arm64asm.MOV, arm64asm.MOVK} {
			var raw [4]byte
			binary.LittleEndian.PutUint32(raw[:], w(i))
			inst, err := arm64asm.Decode(raw[:])
			if err != nil {
				t.Fatalf("x%d: word %d (%#x) does not decode: %v", reg, i, w(i), err)
			}
			if inst.Op != wantOp {
				t.Fatalf("x%d: word %d is %v, want %v", reg, i, inst.Op, wantOp)
			}
			if dst, ok := inst.Args[0].(arm64asm.Reg); !ok || dst != arm64asm.X0+arm64asm.Reg(reg) {
				t.Fatalf("x%d: word %d writes %v", reg, i, inst.Args[0])
			}
			value |= uint64(w(i)>>5&0xffff) << (16 * uint(i))
		}
		if value != ctrEL0Value {
			t.Errorf("x%d: the slot loads %#x, want %#x", reg, value, uint64(ctrEL0Value))
		}
		if target, ok := decodeBranch(slotVA+8, w(2)); !ok || target != retPC {
			t.Errorf("x%d: returns to %#x, %v", reg, target, ok)
		}
		if w(3) != arm64NOP {
			t.Errorf("x%d: padding word %#x, want a nop", reg, w(3))
		}
	}
	if err := encodeCTRSlot(make([]byte, loadSlotSize), 0, 4, 31); err == nil {
		t.Error("xzr must be rejected")
	}
	if err := encodeCTRSlot(make([]byte, 8), 0, 4, 1); err == nil {
		t.Error("a short buffer must be rejected")
	}
	if err := encodeCTRSlot(make([]byte, loadSlotSize), 0, arm64BranchRange+64, 1); err == nil {
		t.Error("an out-of-range return must be rejected")
	}
}

func TestIsDataCacheMaintenance(t *testing.T) {
	for _, tc := range []struct {
		name string
		word uint32
		want bool
	}{
		{"dc civac, x3", 0xd50b7e23, true},
		{"dc cvau, x0", 0xd50b7b20, true},
		{"dc cvac, xzr", 0xd50b7a3f, true},
		{"dc cvap, x30", 0xd50b7c3e, true},
		{"dc zva, x1", 0xd50b7421, false},
		{"ic ivau, x1", 0xd50b7521, false},
		{"dc ivac, x1", 0xd5087621, false},
		{"nop", 0xd503201f, false},
	} {
		if got := isDataCacheMaintenance(tc.word); got != tc.want {
			t.Errorf("isDataCacheMaintenance(%#x), %s = %v, want %v", tc.word, tc.name, got, tc.want)
		}
	}
}
