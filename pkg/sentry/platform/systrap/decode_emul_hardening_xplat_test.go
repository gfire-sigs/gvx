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
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"

	"golang.org/x/arch/x86/x86asm"
)

func TestDecodeX86LegacyPrefixesBeforeVEXAndEVEX(t *testing.T) {
	cases := []struct {
		name         string
		code         []byte
		wantOp       x86asm.Op
		wantLen      int
		wantSeg      x86asm.Reg
		wantAddrSize int
	}{
		{
			name:         "gs_vex2_vmovdqu_store",
			code:         []byte{0x65, 0xC5, 0xFA, 0x7F, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00},
			wantOp:       x86asm.VMOVDQU,
			wantLen:      10,
			wantSeg:      x86asm.GS,
			wantAddrSize: 64,
		},
		{
			name:         "gs_evex_vmovups_store",
			code:         []byte{0x65, 0x62, 0xF1, 0x7C, 0x48, 0x11, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00},
			wantOp:       x86asm.VMOVUPS,
			wantLen:      12,
			wantSeg:      x86asm.GS,
			wantAddrSize: 64,
		},
		{
			name:         "fs_vex2_vmovss_rip_disp32",
			code:         []byte{0x64, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00},
			wantOp:       x86asm.VMOVSS,
			wantLen:      9,
			wantSeg:      x86asm.FS,
			wantAddrSize: 64,
		},
		{
			name:         "fs_ds_null_override_preserves_fs",
			code:         []byte{0x64, 0x3E, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00},
			wantOp:       x86asm.VMOVSS,
			wantLen:      10,
			wantSeg:      x86asm.FS,
			wantAddrSize: 64,
		},
		{
			name:         "addr32_vex2_vmovss",
			code:         []byte{0x67, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00},
			wantOp:       x86asm.VMOVSS,
			wantLen:      9,
			wantSeg:      0,
			wantAddrSize: 32,
		},
		{
			name:         "cs_prefix_before_vzeroupper",
			code:         []byte{0x2E, 0xC5, 0xF8, 0x77},
			wantOp:       x86asm.VZEROUPPER,
			wantLen:      4,
			wantSeg:      0,
			wantAddrSize: 64,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := append(bytes.Clone(tc.code), 0x90, 0x90, 0x90, 0x90)
			inst, err := decodeX86(code)
			if err != nil {
				t.Fatalf("decodeX86(% x) error: %v", tc.code, err)
			}
			if inst.Op != tc.wantOp || inst.Len != tc.wantLen {
				t.Fatalf("decodeX86 = (%v, len %d), want (%v, len %d)", inst.Op, inst.Len, tc.wantOp, tc.wantLen)
			}
			if tc.wantAddrSize != 0 && inst.AddrSize != tc.wantAddrSize {
				t.Errorf("AddrSize = %d, want %d", inst.AddrSize, tc.wantAddrSize)
			}
			if tc.wantSeg != 0 {
				var gotSeg x86asm.Reg
				for _, arg := range inst.Args {
					if m, ok := arg.(x86asm.Mem); ok {
						gotSeg = m.Segment
					}
				}
				if gotSeg != tc.wantSeg {
					t.Errorf("Mem.Segment = %v, want %v", gotSeg, tc.wantSeg)
				}
			}
		})
	}
}

func TestScanAMD64CatchesGSVEXAndPreservesPrefixBoundaries(t *testing.T) {
	t.Run("gs_vex_and_evex_are_patched_as_gsmem", func(t *testing.T) {
		gsVEX := []byte{0x65, 0xC5, 0xFA, 0x7F, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00}
		gsEVEX := []byte{0x65, 0x62, 0xF1, 0x7C, 0x48, 0x11, 0x04, 0x25, 0x80, 0x14, 0x00, 0x00}
		page := catBytes(nops(64), gsVEX, gsEVEX, []byte{0xC3})
		sites := scanAMD64GS(nil, page, nil, true)
		want := []amd64Site{
			{Offset: 64, Len: len(gsVEX), Kind: amd64SiteGSMem},
			{Offset: 64 + len(gsVEX), Len: len(gsEVEX), Kind: amd64SiteGSMem},
		}
		if !reflect.DeepEqual(sites, want) {
			t.Fatalf("scanAMD64GS = %+v, want %+v", sites, want)
		}
	})

	t.Run("hidden_exit_keeps_fs_and_addr32_prefix_on_vex", func(t *testing.T) {
		fsVEX := []byte{0x64, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00}
		addr32VEX := []byte{0x67, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00}
		orig := catBytes(nops(64), fsVEX, addr32VEX, []byte{0xC3})
		patched := bytes.Clone(orig)
		hidden := scanAMD64HiddenExits(nil, orig, nil, patched)
		added, _ := applyAMD64HiddenExits(patched, orig, hidden)
		want := []amd64Site{
			{Offset: 64, Len: len(fsVEX), Kind: amd64SiteGuardedInsn},
			{Offset: 64 + 5, Len: 2, Kind: amd64SiteSyscall},
			{Offset: 64 + len(fsVEX), Len: len(addr32VEX), Kind: amd64SiteGuardedInsn},
			{Offset: 64 + len(fsVEX) + 5, Len: 2, Kind: amd64SiteSyscall},
		}
		if !reflect.DeepEqual(added, want) {
			t.Fatalf("added = %+v, want %+v", added, want)
		}
	})

	t.Run("invalid_prefixed_opcode_counts_as_skip", func(t *testing.T) {
		d := decodeAMD64WithGS([]byte{0x66, 0x06, 0x90}, true)
		if d.size != 0 {
			t.Fatalf("decodeAMD64WithGS(66 06) size = %d, want 0", d.size)
		}
	})
}

func TestHardenedGuardedEmulationAndScratchPlanning(t *testing.T) {
	var mem [512]byte
	const memBase = 0x200000
	readMem := func(addr uint64, buf []byte) bool {
		if addr < memBase || addr+uint64(len(buf)) > memBase+uint64(len(mem)) {
			return false
		}
		copy(buf, mem[addr-memBase:])
		return true
	}
	writeMem := func(addr uint64, buf []byte) bool {
		if addr < memBase || addr+uint64(len(buf)) > memBase+uint64(len(mem)) {
			return false
		}
		copy(mem[addr-memBase:], buf)
		return true
	}

	t.Run("disallows_control_transfer_and_lock_bt_reg_in_scratch", func(t *testing.T) {
		var regs [16]uint64
		regs[0] = memBase
		disallowed := [][]byte{
			{0x66, 0xFF, 0x25, 0x0F, 0x05, 0x00, 0x00},       // jmp16 [rip+0x50f]
			{0xFF, 0x2D, 0x0F, 0x05, 0x00, 0x00},             // ljmp [rip+0x50f]
			{0xFF, 0x1D, 0x0F, 0x05, 0x00, 0x00},             // lcall [rip+0x50f]
			{0xF0, 0x48, 0x0F, 0xAB, 0x88, 0x0F, 0x05, 0, 0}, // lock bts [rax+0x50f], rcx
			{0xF0, 0x48, 0xB8, 0x0F, 0x05, 0, 0, 0, 0, 0, 0}, // invalid lock movabs
		}
		for _, code := range disallowed {
			if pl, ok := planGuardedScratchInsn(code, 0x50000, 0, 0, &regs); ok {
				t.Errorf("planGuardedScratchInsn accepted % x: %+v", code, pl)
			}
		}
	})

	t.Run("emulates_memory_bt_bts_btr_btc_with_signed_bit_offset", func(t *testing.T) {
		var regs [16]uint64
		var eflags uint32
		var nextPC uint64
		regs[0] = memBase + 0x100 - 0x50F // [rax+0x50f] == memBase+0x100
		// bts qword ptr [rax+0x50f], rcx with rcx = +67 -> bit 3 of qword at memBase+0x108
		regs[1] = 67
		btsPos := []byte{0x48, 0x0F, 0xAB, 0x88, 0x0F, 0x05, 0x00, 0x00}
		out := emulateGuardedX86Insn(btsPos, 0x1000, 0, 0, &regs, &eflags, &nextPC, readMem, writeMem)
		if !out.ok || out.fault || eflags&eflagCF != 0 || nextPC != 0x1008 {
			t.Fatalf("BTS +67 = %+v, CF=%v, nextPC=%#x", out, eflags&eflagCF != 0, nextPC)
		}
		if got := binary.LittleEndian.Uint64(mem[0x108:]); got != 1<<3 {
			t.Fatalf("mem[0x108] = %#x, want 0x8", got)
		}
		// btc qword ptr [rax+0x50f], rcx with rcx = -65 -> bit 63 of qword at memBase+0xF0
		regs[1] = ^uint64(64) // -65
		btcNeg := []byte{0x48, 0x0F, 0xBB, 0x88, 0x0F, 0x05, 0x00, 0x00}
		out = emulateGuardedX86Insn(btcNeg, 0x1010, 0, 0, &regs, &eflags, &nextPC, readMem, writeMem)
		if !out.ok || out.fault || eflags&eflagCF != 0 {
			t.Fatalf("BTC -65 = %+v, CF=%v", out, eflags&eflagCF != 0)
		}
		if got := binary.LittleEndian.Uint64(mem[0xF0:]); got != 1<<63 {
			t.Fatalf("mem[0xF0] = %#x, want 1<<63", got)
		}
		// Out-of-bounds bit offset faults at the computed word address instead of escaping.
		regs[1] = 0x100000 * 8
		out = emulateGuardedX86Insn(btsPos, 0x1020, 0, 0, &regs, &eflags, &nextPC, readMem, writeMem)
		if !out.fault || out.faultAddr != memBase+0x100+0x100000 {
			t.Fatalf("OOB BTS = %+v, want fault at %#x", out, memBase+0x100+0x100000)
		}
	})

	t.Run("promotes_vex2_to_vex3_when_rsi_and_rdi_are_both_used", func(t *testing.T) {
		var regs [16]uint64
		regs[6] = 0x5000000 // RSI
		regs[7] = 0x10000   // RDI
		cases := []struct {
			name     string
			code     []byte
			wantAddr uint64
		}{
			{
				name:     "vmovdqu_rsi_rdi_pos_disp32",
				code:     []byte{0xC5, 0xFA, 0x6F, 0x84, 0x3E, 0x0F, 0x05, 0x00, 0x00},
				wantAddr: 0x5000000 + 0x10000 + 0x50F,
			},
			{
				name:     "vmovaps_ymm0_rsi_rdi4_neg_disp32",
				code:     []byte{0xC5, 0xFC, 0x28, 0x84, 0xBE, 0xCD, 0x2E, 0x99, 0xFE},
				wantAddr: 0x5000000 + 0x10000*4 - 0x166D133,
			},
		}
		for _, tc := range cases {
			pl, ok := planGuardedScratchInsn(tc.code, 0x60000, 0, 0, &regs)
			if !ok || !pl.useScratch {
				t.Fatalf("%s: planGuardedScratchInsn failed", tc.name)
			}
			if pl.scratchReg < 8 {
				t.Errorf("%s: scratchReg = %d, want R8..R15", tc.name, pl.scratchReg)
			}
			if pl.effAddr != tc.wantAddr {
				t.Errorf("%s: effAddr = %#x, want %#x", tc.name, pl.effAddr, tc.wantAddr)
			}
			if pl.insn[0] != 0xC4 {
				t.Errorf("%s: rewritten prefix = %#x, want 0xC4 (VEX3)", tc.name, pl.insn[0])
			}
			if hasRawKernelExit(pl.insn) {
				t.Errorf("%s: rewritten contains raw kernel exit: % x", tc.name, pl.insn)
			}
		}
	})

	t.Run("null_segment_override_after_fs_keeps_fs_base_on_vex", func(t *testing.T) {
		var regs [16]uint64
		const fsBase = 0x7f000000
		code := []byte{0x64, 0x3E, 0xC5, 0xFA, 0x10, 0x05, 0x0F, 0x05, 0x00, 0x00}
		pl, ok := planGuardedScratchInsn(code, 0x40000, fsBase, 0, &regs)
		if !ok || !pl.useScratch {
			t.Fatalf("planGuardedScratchInsn failed on % x", code)
		}
		want := uint64(fsBase) + 0x40000 + uint64(len(code)) + 0x50F
		if pl.effAddr != want {
			t.Fatalf("effAddr = %#x, want %#x", pl.effAddr, want)
		}
	})

	t.Run("invalid_lock_on_register_insn_reports_illegal", func(t *testing.T) {
		var regs [16]uint64
		var eflags uint32
		var nextPC uint64
		for _, code := range [][]byte{
			{0xF0, 0x48, 0xB8, 0x0F, 0x05, 0, 0, 0, 0, 0, 0},
			{0xF0, 0x48, 0x01, 0xC0},
		} {
			out := emulateGuardedX86Insn(code, 0x2000, 0, 0, &regs, &eflags, &nextPC, readMem, writeMem)
			if !out.illegal || out.ok {
				t.Errorf("emulateGuardedX86Insn(% x) = %+v, want illegal=true ok=false", code, out)
			}
		}
		// Invalid LOCK on %gs: MOV and CMP must also report illegal in emulateSegMemInsn.
		for _, code := range [][]byte{
			{0xF0, 0x65, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00}, // lock mov eax, gs:[0x30]
			{0xF0, 0x65, 0x48, 0x39, 0x04, 0x25, 0x30, 0, 0, 0},    // lock cmp gs:[0x30], rax
		} {
			out := emulateSegMemInsn(code, x86asm.GS, memBase, &regs, &eflags, readMem, writeMem)
			if !out.illegal || out.ok {
				t.Errorf("emulateSegMemInsn(% x) = %+v, want illegal=true ok=false", code, out)
			}
		}
	})

	t.Run("movsxd_16bit_reads_only_2_bytes", func(t *testing.T) {
		// Place 2 bytes right at the end of mem so a 4-byte read would fault.
		binary.LittleEndian.PutUint16(mem[len(mem)-2:], 0xBEEF)
		var regs [16]uint64
		var eflags uint32
		var nextPC uint64
		regs[0] = memBase + uint64(len(mem)-2) - 0x50F
		// 66 63 80 0f 05 00 00: movsxd ax, word ptr [rax+0x50f]
		movsxd16 := []byte{0x66, 0x63, 0x80, 0x0F, 0x05, 0x00, 0x00}
		out := emulateGuardedX86Insn(movsxd16, 0x3000, 0, 0, &regs, &eflags, &nextPC, readMem, writeMem)
		if !out.ok || out.fault || regs[0]&0xffff != 0xBEEF {
			t.Fatalf("guarded MOVSXD16 = %+v, AX=%#x, want 0xBEEF", out, regs[0]&0xffff)
		}
		// Same check through emulateSegMemInsn on %fs.
		regs[0] = 0
		fsMovsxd16 := []byte{0x64, 0x66, 0x63, 0x04, 0x25, 0xFE, 0x01, 0x00, 0x00}
		out = emulateSegMemInsn(fsMovsxd16, x86asm.FS, memBase, &regs, &eflags, readMem, writeMem)
		if !out.ok || out.fault || regs[0]&0xffff != 0xBEEF {
			t.Fatalf("seg MOVSXD16 = %+v, AX=%#x, want 0xBEEF", out, regs[0]&0xffff)
		}
	})

	t.Run("guardedMemBytes_covers_x87_and_prefixed_vex", func(t *testing.T) {
		cases := []struct {
			name string
			code []byte
			want int
		}{
			{"fld_tbyte", []byte{0xDB, 0x2D, 0x0F, 0x05, 0x00, 0x00}, 10},
			{"fldenv", []byte{0xD9, 0x25, 0x0F, 0x05, 0x00, 0x00}, 28},
			{"frstor", []byte{0xDD, 0x25, 0x0F, 0x05, 0x00, 0x00}, 108},
			{"fnsave", []byte{0xDD, 0x35, 0x0F, 0x05, 0x00, 0x00}, 108},
			{"fs_vmovdqu_xmm", []byte{0x64, 0xC5, 0xFA, 0x6F, 0x05, 0x0F, 0x05, 0x00, 0x00}, 16},
		}
		for _, tc := range cases {
			inst, err := decodeX86(tc.code)
			if err != nil {
				t.Fatalf("%s: decodeX86 failed: %v", tc.name, err)
			}
			if got := guardedMemBytes(inst); got != tc.want {
				t.Errorf("%s: guardedMemBytes = %d, want %d", tc.name, got, tc.want)
			}
		}
	})
}

func TestARM64ScanAllSVCAndRejectOp02MRS(t *testing.T) {
	// Every SVC #imm16 encoding must be patched; HVC/SMC/BRK/HLT must not.
	code := words(
		0xd4000001, // svc #0
		0xd4000021, // svc #1
		0xd4000301, // svc #0x18 (Windows ARM64 NtAllocateVirtualMemory)
		0xd41fffe1, // svc #0xffff
		0xd4000002, // hvc #0
		0xd4000003, // smc #0
		0xd4200000, // brk #0
		0xd4400000, // hlt #0
	)
	sites := scanARM64(code)
	want := []patchSite{
		{Offset: 0, Kind: siteSVC, Orig: 0xd4000001},
		{Offset: 4, Kind: siteSVC, Orig: 0xd4000021},
		{Offset: 8, Kind: siteSVC, Orig: 0xd4000301},
		{Offset: 12, Kind: siteSVC, Orig: 0xd41fffe1},
	}
	if !reflect.DeepEqual(sites, want) {
		t.Fatalf("scanARM64 = %+v, want %+v", sites, want)
	}

	// Privileged op0=2 debug/trace MRS must not alias op0=3 ID/CTR/DCZID registers.
	for _, insn := range []uint32{
		0xD5300000, // mrs x0, osdtrrx_el1 (op0=2)
		0xD5300400, // mrs x0, dbgbvr0_el1 (op0=2)
		0xD5300420, // mrs x0, dbgbcr0_el1 (op0=2)
		0xD5300600, // mrs x0, dbgwvr0_el1 (op0=2)
		0xD5300620, // mrs x0, dbgwcr0_el1 (op0=2)
		0xD5330020, // mrs x0, s2_3_c0_c0_1 (op0=2, aliases CTR_EL0 if bit 19 ignored)
		0xD53300E0, // mrs x0, s2_3_c0_c0_7 (op0=2, aliases DCZID_EL0 if bit 19 ignored)
	} {
		if rt, val, ok := decodeARM64SysRegMRS(insn); ok {
			t.Errorf("decodeARM64SysRegMRS(%#x) = (x%d, %#x, true), want false", insn, rt, val)
		}
	}
	// Legitimate op0=3 reads must still succeed.
	for _, insn := range []uint32{
		0xD5380000, // mrs x0, midr_el1
		0xD53B0020, // mrs x0, ctr_el0
		0xD53B00E0, // mrs x0, dczid_el0
	} {
		if _, _, ok := decodeARM64SysRegMRS(insn); !ok {
			t.Errorf("decodeARM64SysRegMRS(%#x) = false, want true", insn)
		}
	}
}
