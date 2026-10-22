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

package whpx

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"
)

// Raw encodings that the arm64 decoder does not name. They come from the
// Arm Architecture Reference Manual: HVC #imm16 is 0xD4000002 | imm16<<5,
// and IC IALLUIS is SYS #0, C7, C1, #0.
const (
	a64WordHVC1     = 0xD4000022
	a64WordICIALLUS = 0xD508711F
)

// a64Listing returns the decoded text of each instruction in [start, end).
// An instruction that the decoder cannot name appears as "word 0x...".
func a64Listing(t *testing.T, code []byte, start, end int) []string {
	t.Helper()
	var out []string
	for off := start; off < end; off += 4 {
		inst, err := arm64asm.Decode(code[off : off+4])
		if err != nil {
			out = append(out, fmt.Sprintf("word %#x", binary.LittleEndian.Uint32(code[off:])))
			continue
		}
		out = append(out, inst.String())
	}
	return out
}

func TestA64VectorTableSlots(t *testing.T) {
	s, err := buildA64Stubs()
	if err != nil {
		t.Fatal(err)
	}
	if s.Vectors%0x800 != 0 {
		t.Errorf("vector table at %#x is not 2KB aligned, VBAR_EL1 requires it", s.Vectors)
	}
	for slot := range a64VectorSlots {
		base := s.Vectors + slot*a64VectorSlotSize
		got := a64Listing(t, s.Code, base, base+12)
		want := []string{
			"STP X0, X1, [SP]",
			fmt.Sprintf("MOV X0, #%#x", slot),
			fmt.Sprintf("B .+%#x", s.Common-(base+8)),
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("slot %d instruction %d is %q, want %q", slot, i, got[i], want[i])
			}
		}
	}
	// A slot must not use a register before it saves X0 and X1.
	if a64VectorSlotSize*a64VectorSlots != 0x800 {
		t.Errorf("vector table is %#x bytes, want 0x800", a64VectorSlotSize*a64VectorSlots)
	}
}

func TestA64CommonHandlerSpillsAndExits(t *testing.T) {
	s, err := buildA64Stubs()
	if err != nil {
		t.Fatal(err)
	}
	got := a64Listing(t, s.Code, s.Common, s.Hvc+4)
	var want []string
	want = append(want, fmt.Sprintf("STR X0, [SP,#%d]", commOffVector))
	for r := 2; r < 30; r += 2 {
		want = append(want, fmt.Sprintf("STP X%d, X%d, [SP,#%d]", r, r+1, commOffRegs+r*8))
	}
	want = append(want,
		fmt.Sprintf("STR X30, [SP,#%d]", commOffRegs+30*8),
		"MRS X0, S3_0_C4_C1_0",  // SP_EL0
		"MRS X1, S3_0_C4_C0_1",  // ELR_EL1
		"MRS X2, S3_0_C4_C0_0",  // SPSR_EL1
		"MRS X3, S3_3_C13_C0_2", // TPIDR_EL0
		"MRS X4, S3_0_C6_C0_0",  // FAR_EL1
		"MRS X5, S3_0_C5_C2_0",  // ESR_EL1
		fmt.Sprintf("STP X0, X1, [SP,#%d]", commOffSP),
		fmt.Sprintf("STP X2, X3, [SP,#%d]", commOffPstate),
		fmt.Sprintf("STP X4, X5, [SP,#%d]", commOffFaultAddr),
		fmt.Sprintf("MOV W0, #%#x", uint32(ExitException)),
		fmt.Sprintf("STR W0, [SP,#%d]", commOffExitReason),
		fmt.Sprintf("word %#x", a64WordHVC1),
	)
	if len(got) != len(want) {
		t.Fatalf("common handler has %d instructions, want %d:\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("instruction %d is %q, want %q", i, got[i], want[i])
		}
	}
	if s.Reload != s.Hvc+4 {
		t.Errorf("reload starts at %#x, want right after HVC at %#x so that the resume falls through", s.Reload, s.Hvc+4)
	}
	// The saved field offsets must be reachable by the instruction forms.
	if commOffFlags/4 > 0xFFF || commOffRoot/8 > 0xFFF {
		t.Error("CommPage offsets exceed the load and store immediates")
	}
}

func TestA64ReloadRestoresAndReturns(t *testing.T) {
	s, err := buildA64Stubs()
	if err != nil {
		t.Fatal(err)
	}
	got := a64Listing(t, s.Code, s.Reload, s.ReloadEnd)
	rel := func(from, to int) int { return to - from }
	// Compute the branch displacements from the generated layout.
	idx := func(name string) int {
		for i, g := range got {
			if g == name {
				return i
			}
		}
		t.Fatalf("instruction %q is missing", name)
		return 0
	}
	if got[0] != fmt.Sprintf("LDP X0, X1, [SP,#%d]", commOffSP) || got[1] != fmt.Sprintf("LDP X2, X3, [SP,#%d]", commOffPstate) {
		t.Fatalf("reload starts with %q, %q", got[0], got[1])
	}
	want := map[int]string{
		2: "MSR S3_0_C4_C1_0, X0",  // SP_EL0
		3: "MSR S3_0_C4_C0_1, X1",  // ELR_EL1
		4: "MSR S3_0_C4_C0_0, X2",  // SPSR_EL1
		5: "MSR S3_3_C13_C0_2, X3", // TPIDR_EL0
		6: fmt.Sprintf("LDR W0, [SP,#%d]", commOffFlags),
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("instruction %d is %q, want %q", i, got[i], w)
		}
	}
	root := idx(fmt.Sprintf("LDR X1, [SP,#%d]", commOffRoot))
	for i, w := range []string{"MSR S3_0_C2_C0_0, X1", "ISB SY", "TLBI VMALLE1", "DSB NSH", "ISB SY"} {
		if got[root+1+i] != w {
			t.Errorf("TLB flush instruction %d is %q, want %q", i, got[root+1+i], w)
		}
	}
	// TBZ W0,#0 skips exactly the root load and the flush.
	if want := fmt.Sprintf("TBZ W0, #0, .+%#x", 4*rel(root-1, root+6)); got[root-1] != want {
		t.Errorf("root test is %q, want %q", got[root-1], want)
	}
	ic := idx(fmt.Sprintf("word %#x", a64WordICIALLUS))
	for i, w := range []string{"DSB ISH", "ISB SY"} {
		if got[ic+1+i] != w {
			t.Errorf("icache sync instruction %d is %q, want %q", i, got[ic+1+i], w)
		}
	}
	if want := fmt.Sprintf("TBZ W0, #2, .+%#x", 4*rel(ic-1, ic+3)); got[ic-1] != want {
		t.Errorf("icache test is %q, want %q", got[ic-1], want)
	}
	// X2 to X30 reload next, X0 and X1 last, then ERET.
	tail := got[ic+3:]
	var wantTail []string
	for r := 2; r < 30; r += 2 {
		wantTail = append(wantTail, fmt.Sprintf("LDP X%d, X%d, [SP,#%d]", r, r+1, commOffRegs+r*8))
	}
	wantTail = append(wantTail,
		fmt.Sprintf("LDR X30, [SP,#%d]", commOffRegs+30*8),
		"LDP X0, X1, [SP]",
		"ERET ")
	if len(tail) != len(wantTail) {
		t.Fatalf("reload tail has %d instructions, want %d:\n%v", len(tail), len(wantTail), tail)
	}
	for i := range wantTail {
		if tail[i] != wantTail[i] {
			t.Errorf("tail instruction %d is %q, want %q", i, tail[i], wantTail[i])
		}
	}
}

func TestA64SystemRegisterValues(t *testing.T) {
	if a64MairNormal != 0xFF || a64Mair&0xFF != 0xFF {
		t.Errorf("MAIR attribute 0 is %#x, must be Normal write-back because hostarch.MemoryTypeWriteBack is zero", a64Mair&0xFF)
	}
	if a64Mair>>8&0xFF != a64MairNormalNC || a64Mair>>16&0xFF != a64MairDevice {
		t.Errorf("MAIR attributes 1 and 2 are %#x and %#x", a64Mair>>8&0xFF, a64Mair>>16&0xFF)
	}
	tcr := uint64(a64TCR)
	for _, c := range []struct {
		name         string
		shift, width uint
		want         uint64
	}{
		{"T0SZ", 0, 6, 16}, {"IRGN0", 8, 2, 1}, {"ORGN0", 10, 2, 1}, {"SH0", 12, 2, 3}, {"TG0", 14, 2, 0},
		{"T1SZ", 16, 6, 16}, {"A1", 22, 1, 0}, {"EPD1", 23, 1, 0}, {"IRGN1", 24, 2, 1}, {"ORGN1", 26, 2, 1},
		{"SH1", 28, 2, 3}, {"TG1", 30, 2, 2}, {"IPS", 32, 3, 1}, {"TBI0", 37, 1, 1},
	} {
		if got := tcr >> c.shift & (1<<c.width - 1); got != c.want {
			t.Errorf("TCR_EL1.%s is %d, want %d", c.name, got, c.want)
		}
	}
	if a64PstateKernel&a64PstateModeMask != 5 {
		t.Errorf("kernel PSTATE mode is %d, want EL1h (5)", a64PstateKernel&a64PstateModeMask)
	}
	if a64PstateKernel&0x3C0 != 0x3C0 {
		t.Errorf("kernel PSTATE does not mask D, A, I and F")
	}
	if a64PstateUserMask != 0xF|0x3C0 {
		t.Errorf("user PSTATE clear mask is %#x", a64PstateUserMask)
	}
	if a64SctlrSet&a64SctlrM == 0 || a64SctlrSet&a64SctlrC == 0 || a64SctlrSet&a64SctlrI == 0 {
		t.Error("SCTLR_EL1 bring-up does not enable the MMU and the caches")
	}
}
