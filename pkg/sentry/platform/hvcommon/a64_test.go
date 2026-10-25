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

package hvcommon

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

func decodeA64(t *testing.T, word uint32) string {
	t.Helper()
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], word)
	inst, err := arm64asm.Decode(b[:])
	if err != nil {
		t.Fatalf("word %#x does not decode: %v", word, err)
	}
	return inst.String()
}

func TestA64EncodersDecodeAsIntended(t *testing.T) {
	for _, c := range []struct {
		name string
		word uint32
		want string
	}{
		// The decoder prints a system register by its (op0, op1, CRn, CRm, op2)
		// name, so these lines check the encoding of each register field.
		{"mrs sp_el0", MRS(0, SysRegSPEL0), "MRS X0, S3_0_C4_C1_0"},
		{"mrs elr_el1", MRS(1, SysRegELREL1), "MRS X1, S3_0_C4_C0_1"},
		{"mrs spsr_el1", MRS(2, SysRegSPSREL1), "MRS X2, S3_0_C4_C0_0"},
		{"mrs tpidr_el0", MRS(3, SysRegTPIDREL0), "MRS X3, S3_3_C13_C0_2"},
		{"mrs far_el1", MRS(4, SysRegFAREL1), "MRS X4, S3_0_C6_C0_0"},
		{"mrs esr_el1", MRS(5, SysRegESREL1), "MRS X5, S3_0_C5_C2_0"},
		{"mrs fpsr", MRS(6, SysRegFPSR), "MRS X6, S3_3_C4_C4_1"},
		{"mrs fpcr", MRS(7, SysRegFPCR), "MRS X7, S3_3_C4_C4_0"},
		{"msr ttbr0_el1", MSR(SysRegTTBR0EL1, 1), "MSR S3_0_C2_C0_0, X1"},
		{"msr sp_el0", MSR(SysRegSPEL0, 30), "MSR S3_0_C4_C1_0, X30"},
		{"movz x", MOVZ(3, 0x1234), "MOV X3, #0x1234"},
		{"movz w", MOVZW(4, 7), "MOV W4, #0x7"},
		{"b forward", B(0x40), "B .+0x40"},
		{"b backward", B(-0x40), "B .+0xffffffffffffffc0"},
		{"cbz", CBZ(5, 0x20), "CBZ X5, .+0x20"},
		{"tbz", TBZ(2, 3, 0x10), "TBZ W2, #3, .+0x10"},
		{"stp x", STPXSP(2, 3, 0x10), "STP X2, X3, [SP,#16]"},
		{"stp x negative", STPXSP(0, 1, -512), "STP X0, X1, [SP,#-512]"},
		{"ldp x", LDPXSP(4, 5, 504), "LDP X4, X5, [SP,#504]"},
		{"stp q", STPQSP(0, 1, 0x20), "STP Q0, Q1, [SP,#32]"},
		{"ldp q", LDPQSP(30, 31, -1024), "LDP Q30, Q31, [SP,#-1024]"},
		{"str x", STRXSP(30, 0x108), "STR X30, [SP,#264]"},
		{"ldr x", LDRXSP(1, 8), "LDR X1, [SP,#8]"},
		{"str w", STRWSP(0, 0x14), "STR W0, [SP,#20]"},
		{"ldr w", LDRWSP(0, 4), "LDR W0, [SP,#4]"},
		{"eret", ERET, "ERET "},
		{"isb", ISB, "ISB SY"},
		{"tlbi vmalle1", TLBIVMALLE1, "TLBI VMALLE1"},
		{"movk", MOVK(3, 0xABCD, 16), "MOVK X3, #0xabcd, LSL #16"},
		{"mov reg", MOVReg(4, 17), "MOV X4, X17"},
		{"br", BR(16), "BR X16"},
		{"blr", BLR(17), "BLR X17"},
		{"tbnz", TBNZ(0, 0, 0x10), "TBNZ W0, #0, .+0x10"},
		{"brk", BRK(1), "BRK #0x1"},
		{"nop", NOP, "NOP "},
		{"svc #0", SVC0, "SVC #0x0"},
	} {
		if got := decodeA64(t, c.word); got != c.want {
			t.Errorf("%s: %#x decodes as %q, want %q", c.name, c.word, got, c.want)
		}
	}
}

func TestHVCEncodesTheImmediate(t *testing.T) {
	// The decoder does not name HVC, so the test pins the words of the Arm
	// Architecture Reference Manual: 0xD4000002 | imm16<<5.
	if got := HVC(0); got != 0xD4000002 {
		t.Errorf("HVC(0) = %#x, want 0xD4000002", got)
	}
	if got := HVC(0x1234); got != 0xD4000002|0x1234<<5 {
		t.Errorf("HVC(0x1234) = %#x", got)
	}
}

func TestA64BarrierWordsAreTheDocumentedOnes(t *testing.T) {
	// The decoder names the barriers by option, so the test pins the options.
	if got := decodeA64(t, DSBNSH); got != "DSB NSH" {
		t.Errorf("DSBNSH decodes as %q", got)
	}
	if got := decodeA64(t, DSBISH); got != "DSB ISH" {
		t.Errorf("DSBISH decodes as %q", got)
	}
	// IC IALLUIS is SYS #0, C7, C1, #0 with XZR, which the decoder does not
	// name. The words differ from TLBI VMALLE1 only in CRn, CRm, and op2.
	if ICIALLUIS != 0xD508711F {
		t.Errorf("ICIALLUIS = %#x, want SYS #0, C7, C1, #0", ICIALLUIS)
	}
}

func TestA64LoadStoreRanges(t *testing.T) {
	for _, c := range []struct {
		name string
		f    func()
	}{
		{"pair x above range", func() { STPXSP(0, 1, 512) }},
		{"pair x below range", func() { LDPXSP(0, 1, -520) }},
		{"pair x unaligned", func() { STPXSP(0, 1, 4) }},
		{"pair q above range", func() { STPQSP(0, 1, 1024) }},
		{"pair q unaligned", func() { LDPQSP(0, 1, 8) }},
		{"slot negative", func() { LDRXSP(0, -8) }},
		{"slot unaligned", func() { STRXSP(0, 4) }},
		{"slot above range", func() { STRWSP(0, 4*4096) }},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: the encoder accepted an offset that the instruction cannot hold", c.name)
				}
			}()
			c.f()
		}()
	}
}

func TestTCRFieldsFollowTheArchitecture(t *testing.T) {
	// The value that the 36-bit physical address size gives, written out
	// field by field: T0SZ 16, IRGN0 1, ORGN0 1, SH0 3, TG0 0, T1SZ 16,
	// IRGN1 1, ORGN1 1, SH1 3, TG1 2, IPS 1, and TBI0.
	if got, want := TCR(1), uint64(0x21B5103510); got != want {
		t.Fatalf("TCR(1) = %#x, want %#x", got, want)
	}
	for ips := uint64(0); ips < 8; ips++ {
		if got := TCR(ips) >> 32 & 7; got != ips {
			t.Errorf("TCR(%d) has IPS %d", ips, got)
		}
	}
	const epd0, epd1 = 1 << 7, 1 << 23
	if TCR(5)&(epd0|epd1) != 0 {
		t.Error("TCR sets EPD0 or EPD1, which would turn a translation half off")
	}
}

func TestVectorTableGeometry(t *testing.T) {
	if VectorCommonOffset != 0x800 {
		t.Errorf("the common routine starts at %#x, want 0x800 behind the 16 slots", VectorCommonOffset)
	}
	// VBAR_EL1 needs a 2KB aligned table.
	if VectorSlots*VectorSlotSize != 0x800 {
		t.Errorf("the table has %#x bytes, want 0x800", VectorSlots*VectorSlotSize)
	}
	// Four groups of four slots: current EL with SP0, current EL with SPx,
	// lower EL on AArch64, and lower EL on AArch32.
	for name, got := range map[string]int{
		"current EL SPx sync": SlotCurrentSPxSync, "lower sync": SlotLowerSync,
		"lower IRQ": SlotLowerIRQ, "lower SError": SlotLowerSError,
	} {
		if got < 0 || got >= VectorSlots {
			t.Errorf("slot %s = %d is outside the table", name, got)
		}
	}
	if SlotCurrentSPxSync != 4 || SlotLowerSync != 8 || SlotLowerIRQ != 9 || SlotLowerSError != 11 {
		t.Error("a slot number differs from the architectural table")
	}
}

func TestPstateEL1hMasksDAIFAndSelectsSPx(t *testing.T) {
	if PstateEL1h&0x3C0 != 0x3C0 {
		t.Errorf("PstateEL1h = %#x does not mask D, A, I, and F", PstateEL1h)
	}
	if PstateEL1h&0xF != 5 {
		t.Errorf("PstateEL1h = %#x does not select EL1h", PstateEL1h)
	}
}

// The encoders must reproduce words that ran on real hardware in the earlier
// hand-written stub. The constants below come from that stub.
func TestA64EncodersMatchKnownGoodWords(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uint32
		want uint32
	}{
		{"STP X0,X1,[SP]", STPXSP(0, 1, 0), 0xa90007e0},
		{"LDP X0,X1,[SP,#248]", LDPXSP(0, 1, 248), 0xa9400000 | 31<<15 | 1<<10 | 31<<5},
		{"STP X2,X3,[SP,#264]", STPXSP(2, 3, 264), 0xa9000000 | 33<<15 | 3<<10 | 31<<5 | 2},
		{"STR X30,[SP,#240]", STRXSP(30, 240), 0xf9000000 | 30<<10 | 31<<5 | 30},
		{"LDR X0,[SP,#832]", LDRXSP(0, 832), 0xf9400000 | 104<<10 | 31<<5},
		{"STP Q0,Q1,[SP,#320]", STPQSP(0, 1, 320), 0xad000000 | 20<<15 | 1<<10 | 31<<5},
		{"LDP Q30,Q31,[SP,#800]", LDPQSP(30, 31, 800), 0xad400000 | 50<<15 | 31<<10 | 31<<5 | 30},
		{"MRS X0,SP_EL0", MRS(0, SysRegSPEL0), 0xd5384100},
		{"MRS X1,ELR_EL1", MRS(1, SysRegELREL1), 0xd5384021},
		{"MRS X2,SPSR_EL1", MRS(2, SysRegSPSREL1), 0xd5384002},
		{"MRS X3,TPIDR_EL0", MRS(3, SysRegTPIDREL0), 0xd53bd043},
		{"MRS X4,FAR_EL1", MRS(4, SysRegFAREL1), 0xd5386004},
		{"MRS X5,ESR_EL1", MRS(5, SysRegESREL1), 0xd5385205},
		{"MRS X0,FPSR", MRS(0, SysRegFPSR), 0xd53b4420},
		{"MRS X1,FPCR", MRS(1, SysRegFPCR), 0xd53b4401},
		{"MSR SP_EL0,X0", MSR(SysRegSPEL0, 0), 0xd5184100},
		{"MSR ELR_EL1,X1", MSR(SysRegELREL1, 1), 0xd5184021},
		{"MSR SPSR_EL1,X2", MSR(SysRegSPSREL1, 2), 0xd5184002},
		{"MSR TPIDR_EL0,X3", MSR(SysRegTPIDREL0, 3), 0xd51bd043},
		{"MSR FPSR,X0", MSR(SysRegFPSR, 0), 0xd51b4420},
		{"MSR FPCR,X1", MSR(SysRegFPCR, 1), 0xd51b4401},
		{"MOVZ X0,#7", MOVZ(0, 7), 0xd2800000 | 7<<5},
		{"B +0x7f4", B(0x7f4), 0x14000000 | 0x7f4/4},
		{"B -8", B(-8), 0x17fffffe},
		{"HVC #0", HVC(0), 0xd4000002},
	} {
		if c.got != c.want {
			t.Errorf("%s = %#08x, want %#08x", c.name, c.got, c.want)
		}
	}
}

func TestTCRFieldValues(t *testing.T) {
	tcr := TCR(1)
	field := func(shift, width uint) uint64 { return tcr >> shift & (1<<width - 1) }
	for _, c := range []struct {
		name string
		got  uint64
		want uint64
	}{
		{"T0SZ", field(0, 6), 16},
		{"EPD0", field(7, 1), 0},
		{"TG0", field(14, 2), 0},
		{"T1SZ", field(16, 6), 16},
		{"EPD1", field(23, 1), 0},
		{"TG1", field(30, 2), 2},
		{"IPS", field(32, 3), 1},
		{"TBI0", field(37, 1), 1},
		{"TBI1", field(38, 1), 0},
		{"SH0", field(12, 2), 3},
		{"SH1", field(28, 2), 3},
		{"IRGN1", field(24, 2), 1},
		{"ORGN1", field(26, 2), 1},
	} {
		if c.got != c.want {
			t.Errorf("TCR_EL1.%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

func TestEmulateSysRegReadAndDefaults(t *testing.T) {
	ids := DefaultIDRegisters()
	read := func(op0, op1, crn, crm, op2 uint32) SysRegISS {
		return SysRegISS{Read: true, Rt: 4, Op0: op0, Op1: op1, CRn: crn, CRm: crm, Op2: op2}
	}
	for _, tc := range []struct {
		name string
		iss  SysRegISS
		want uint64
		ok   bool
	}{
		{"MIDR_EL1", read(3, 0, 0, 0, 0), DefaultMIDREL1, true},
		{"REVIDR_EL1", read(3, 0, 0, 0, 6), 0, true},
		{"ID_AA64PFR0_EL1", read(3, 0, 0, 4, 0), DefaultIDAA64PFR0EL1, true},
		{"ID_AA64ISAR0_EL1", read(3, 0, 0, 6, 0), DefaultIDAA64ISAR0EL1, true},
		{"ID_AA64MMFR0_EL1", read(3, 0, 0, 7, 0), DefaultIDAA64MMFR0EL1, true},
		{"CTR_EL0", read(3, 3, 0, 0, 1), DefaultCTREL0, true},
		{"DCZID_EL0", read(3, 3, 0, 0, 7), DefaultDCZIDEL0, true},
		{"write rejected", SysRegISS{Read: false, Rt: 0, Op0: 3}, 0, false},
		{"unknown rejected", read(3, 3, 9, 12, 0), 0, false},
	} {
		got, ok := ids.EmulateSysRegRead(tc.iss)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s = (%#x, %v), want (%#x, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}

	for _, tc := range []struct {
		name string
		insn uint32
		rt   uint32
		want uint64
		ok   bool
	}{
		{"MRS X7, MIDR_EL1", 0xd5380007, 7, DefaultMIDREL1, true},
		{"MRS X9, ID_AA64PFR0_EL1", 0xd5380409, 9, DefaultIDAA64PFR0EL1, true},
		{"MRS X11, ID_AA64ISAR0_EL1", 0xd538060b, 11, DefaultIDAA64ISAR0EL1, true},
		{"MRS X12, ID_AA64MMFR0_EL1", 0xd538070c, 12, DefaultIDAA64MMFR0EL1, true},
		{"MRS X13, CTR_EL0", 0xd53b002d, 13, DefaultCTREL0, true},
		{"MRS X14, DCZID_EL0", 0xd53b00ee, 14, DefaultDCZIDEL0, true},
		{"MSR rejected", 0xd5180000, 0, 0, false},
	} {
		iss, ok := DecodeMRSSysRegISS(tc.insn)
		if ok != tc.ok {
			t.Fatalf("%s: DecodeMRSSysRegISS(%#x) ok = %v, want %v", tc.name, tc.insn, ok, tc.ok)
		}
		if !ok {
			continue
		}
		if iss.Rt != tc.rt {
			t.Errorf("%s: Rt = %d, want %d", tc.name, iss.Rt, tc.rt)
		}
		got, ok := ids.EmulateSysRegRead(iss)
		if !ok || got != tc.want {
			t.Errorf("%s: EmulateSysRegRead = (%#x, %v), want (%#x, true)", tc.name, got, ok, tc.want)
		}
	}
}
