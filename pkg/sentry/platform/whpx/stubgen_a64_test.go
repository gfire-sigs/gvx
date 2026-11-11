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

package whpx_test

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"

	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)

// The decoder does not name IC IALLUIS: SYS #0, C7, C1, #0.
const a64WordICIALLUIS = 0xD508711F

// a64CPU models the ARM64 architectural state that the exception vector stub
// and reload path read and write.
type a64CPU struct {
	X            [31]uint64
	SP           []byte
	SPEL0        uint64
	ELREL1       uint64
	SPSREL1      uint64
	TPIDREL0     uint64
	FAREL1       uint64
	ESREL1       uint64
	TTBR0EL1     uint64
	TLBFlushed   bool
	ICacheSynced bool
	MMIOExitAddr uint64
	ERET         bool
}

func (cpu *a64CPU) reg(arg arm64asm.Arg) (int, bool, bool) {
	r, ok := arg.(arm64asm.Reg)
	if !ok {
		if rs, ok := arg.(arm64asm.RegSP); ok {
			r = arm64asm.Reg(rs)
		} else {
			return 0, false, false
		}
	}
	switch {
	case r >= arm64asm.X0 && r <= arm64asm.X30:
		return int(r - arm64asm.X0), true, true
	case r >= arm64asm.W0 && r <= arm64asm.W30:
		return int(r - arm64asm.W0), false, true
	case r == arm64asm.XZR || r == arm64asm.WZR:
		return -1, r == arm64asm.XZR, true
	default:
		return 0, false, false
	}
}

func (cpu *a64CPU) getReg(arg arm64asm.Arg) uint64 {
	idx, wide, ok := cpu.reg(arg)
	if !ok || idx < 0 {
		return 0
	}
	if !wide {
		return uint64(uint32(cpu.X[idx]))
	}
	return cpu.X[idx]
}

func (cpu *a64CPU) setReg(arg arm64asm.Arg, val uint64) {
	idx, wide, ok := cpu.reg(arg)
	if !ok || idx < 0 {
		return
	}
	if !wide {
		cpu.X[idx] = uint64(uint32(val))
		return
	}
	cpu.X[idx] = val
}

func extractImm(arg arm64asm.Arg) uint64 {
	switch v := arg.(type) {
	case arm64asm.Imm:
		return uint64(v.Imm)
	case arm64asm.Imm64:
		return v.Imm
	default:
		return 0
	}
}

// emulateA64Stub steps the generated ARM64 stub instructions in [startPC, endPC)
// against cpu until pc reaches endPC, an MMIO exit load executes, or ERET runs.
func emulateA64Stub(t *testing.T, code []byte, startPC, endPC int, cpu *a64CPU) {
	t.Helper()
	for pc := startPC; pc < endPC; {
		raw := binary.LittleEndian.Uint32(code[pc : pc+4])
		if raw == a64WordICIALLUIS {
			cpu.ICacheSynced = true
			pc += 4
			continue
		}
		inst, err := arm64asm.Decode(code[pc : pc+4])
		if err != nil {
			t.Fatalf("decode at %#x (word %#x): %v", pc, raw, err)
		}
		switch inst.Op {
		case arm64asm.STP:
			off := int((raw >> 15) & 0x7F)
			if off&0x40 != 0 {
				off |= ^0x7F
			}
			off *= 8
			binary.LittleEndian.PutUint64(cpu.SP[off:], cpu.getReg(inst.Args[0]))
			binary.LittleEndian.PutUint64(cpu.SP[off+8:], cpu.getReg(inst.Args[1]))
		case arm64asm.LDP:
			off := int((raw >> 15) & 0x7F)
			if off&0x40 != 0 {
				off |= ^0x7F
			}
			off *= 8
			v0 := binary.LittleEndian.Uint64(cpu.SP[off:])
			v1 := binary.LittleEndian.Uint64(cpu.SP[off+8:])
			cpu.setReg(inst.Args[0], v0)
			cpu.setReg(inst.Args[1], v1)
		case arm64asm.STR:
			_, wide, _ := cpu.reg(inst.Args[0])
			uimm12 := int((raw >> 10) & 0xFFF)
			if wide {
				off := uimm12 * 8
				binary.LittleEndian.PutUint64(cpu.SP[off:], cpu.getReg(inst.Args[0]))
			} else {
				off := uimm12 * 4
				binary.LittleEndian.PutUint32(cpu.SP[off:], uint32(cpu.getReg(inst.Args[0])))
			}
		case arm64asm.LDR:
			idx, wide, _ := cpu.reg(inst.Args[0])
			if idx < 0 {
				// LDR XZR, [X0] triggers the hypervisor MMIO exit.
				rn := int((raw >> 5) & 0x1F)
				cpu.MMIOExitAddr = cpu.X[rn]
				return
			}
			uimm12 := int((raw >> 10) & 0xFFF)
			if wide {
				off := uimm12 * 8
				cpu.setReg(inst.Args[0], binary.LittleEndian.Uint64(cpu.SP[off:]))
			} else {
				off := uimm12 * 4
				cpu.setReg(inst.Args[0], uint64(binary.LittleEndian.Uint32(cpu.SP[off:])))
			}
		case arm64asm.MOV:
			cpu.setReg(inst.Args[0], extractImm(inst.Args[1]))
		case arm64asm.MOVK:
			hw := uint((raw >> 21) & 0x3)
			imm16 := uint64((raw >> 5) & 0xFFFF)
			shift := hw * 16
			cur := cpu.getReg(inst.Args[0]) & ^(uint64(0xFFFF) << shift)
			cpu.setReg(inst.Args[0], cur|(imm16<<shift))
		case arm64asm.MRS:
			switch inst.Args[1].String() {
			case "S3_0_C4_C1_0":
				cpu.setReg(inst.Args[0], cpu.SPEL0)
			case "S3_0_C4_C0_1":
				cpu.setReg(inst.Args[0], cpu.ELREL1)
			case "S3_0_C4_C0_0":
				cpu.setReg(inst.Args[0], cpu.SPSREL1)
			case "S3_3_C13_C0_2":
				cpu.setReg(inst.Args[0], cpu.TPIDREL0)
			case "S3_0_C6_C0_0":
				cpu.setReg(inst.Args[0], cpu.FAREL1)
			case "S3_0_C5_C2_0":
				cpu.setReg(inst.Args[0], cpu.ESREL1)
			default:
				t.Fatalf("unexpected MRS source %s at %#x", inst.Args[1], pc)
			}
		case arm64asm.MSR:
			val := cpu.getReg(inst.Args[1])
			switch inst.Args[0].String() {
			case "S3_0_C4_C1_0":
				cpu.SPEL0 = val
			case "S3_0_C4_C0_1":
				cpu.ELREL1 = val
			case "S3_0_C4_C0_0":
				cpu.SPSREL1 = val
			case "S3_3_C13_C0_2":
				cpu.TPIDREL0 = val
			case "S3_0_C2_C0_0":
				cpu.TTBR0EL1 = val
			default:
				t.Fatalf("unexpected MSR destination %s at %#x", inst.Args[0], pc)
			}
		case arm64asm.B:
			rel := int(inst.Args[0].(arm64asm.PCRel))
			pc += rel
			continue
		case arm64asm.TBZ:
			val := cpu.getReg(inst.Args[0])
			bit := extractImm(inst.Args[1])
			if (val>>bit)&1 == 0 {
				rel := int(inst.Args[2].(arm64asm.PCRel))
				pc += rel
				continue
			}
		case arm64asm.TLBI:
			cpu.TLBFlushed = true
		case arm64asm.DSB, arm64asm.ISB:
		case arm64asm.ERET:
			cpu.ERET = true
			return
		default:
			t.Fatalf("unhandled instruction %v at %#x", inst, pc)
		}
		pc += 4
	}
}

func TestA64VectorTableAndCommonHandlerSpillContract(t *testing.T) {
	s, err := whpx.BuildA64StubsForTest()
	if err != nil {
		t.Fatal(err)
	}
	if s.Vectors%0x800 != 0 {
		t.Errorf("vector table at %#x is not 2KB aligned, VBAR_EL1 requires it", s.Vectors)
	}
	if whpx.A64VectorSlotSizeForTest*whpx.A64VectorSlotsForTest != 0x800 {
		t.Errorf("vector table is %#x bytes, want 0x800", whpx.A64VectorSlotSizeForTest*whpx.A64VectorSlotsForTest)
	}
	if s.Reload != s.Exit+4 {
		t.Errorf("reload starts at %#x, want after the exit at %#x", s.Reload, s.Exit+4)
	}
	if whpx.CommOffFlagsForTest/4 > 0xFFF || whpx.CommOffRootForTest/8 > 0xFFF {
		t.Error("CommPage offsets exceed the load and store immediates")
	}

	for slot := range whpx.A64VectorSlotsForTest {
		page := make([]byte, whpx.PageSizeForTest)
		comm := whpx.OverlayCommPageForTest(page)
		cpu := &a64CPU{
			SP:       page,
			SPEL0:    0x7FFF00001000 + uint64(slot),
			ELREL1:   0x000000401234 + uint64(slot*4),
			SPSREL1:  0x60000000,
			TPIDREL0: 0x7FFF80002000,
			FAREL1:   0x0000deadbeef0000 + uint64(slot),
			ESREL1:   0x56000000 | uint64(slot),
		}
		for r := range cpu.X {
			cpu.X[r] = 0x1100000000000000 | uint64(slot)<<16 | uint64(r+1)
		}

		entryPC := s.Vectors + slot*whpx.A64VectorSlotSizeForTest
		emulateA64Stub(t, s.Code, entryPC, s.Exit+4, cpu)

		for r := range comm.Regs {
			want := uint64(0x1100000000000000) | uint64(slot)<<16 | uint64(r+1)
			if comm.Regs[r] != want {
				t.Fatalf("slot %d: CommPage.Regs[%d] = %#x, want %#x", slot, r, comm.Regs[r], want)
			}
		}
		if comm.Vector != uint64(slot) {
			t.Errorf("slot %d: CommPage.Vector = %d, want %d", slot, comm.Vector, slot)
		}
		if comm.SP != cpu.SPEL0 {
			t.Errorf("slot %d: CommPage.SP = %#x, want %#x", slot, comm.SP, cpu.SPEL0)
		}
		if comm.PC != cpu.ELREL1 {
			t.Errorf("slot %d: CommPage.PC = %#x, want %#x", slot, comm.PC, cpu.ELREL1)
		}
		if comm.Pstate != cpu.SPSREL1 {
			t.Errorf("slot %d: CommPage.Pstate = %#x, want %#x", slot, comm.Pstate, cpu.SPSREL1)
		}
		if comm.TLS != cpu.TPIDREL0 {
			t.Errorf("slot %d: CommPage.TLS = %#x, want %#x", slot, comm.TLS, cpu.TPIDREL0)
		}
		if comm.FaultAddr != cpu.FAREL1 {
			t.Errorf("slot %d: CommPage.FaultAddr = %#x, want %#x", slot, comm.FaultAddr, cpu.FAREL1)
		}
		if comm.ESR != cpu.ESREL1 {
			t.Errorf("slot %d: CommPage.ESR = %#x, want %#x", slot, comm.ESR, cpu.ESREL1)
		}
		if got := whpx.ExitReason(comm.ExitReason.Load()); got != whpx.ExitException {
			t.Errorf("slot %d: CommPage.ExitReason = %v, want %v", slot, got, whpx.ExitException)
		}
		wantMMIO := uint64(whpx.KernelBaseA64ForTest + whpx.KernelSysOffForTest)
		if cpu.MMIOExitAddr != wantMMIO {
			t.Errorf("slot %d: MMIO exit address = %#x, want %#x", slot, cpu.MMIOExitAddr, wantMMIO)
		}
	}
}

func TestA64ReloadRestoresAndReturns(t *testing.T) {
	s, err := whpx.BuildA64StubsForTest()
	if err != nil {
		t.Fatal(err)
	}
	for _, flags := range []uint32{
		0,
		whpx.FlagReloadRootForTest,
		whpx.FlagICacheSyncForTest,
		whpx.FlagReloadRootForTest | whpx.FlagICacheSyncForTest,
	} {
		page := make([]byte, whpx.PageSizeForTest)
		comm := whpx.OverlayCommPageForTest(page)
		for r := range comm.Regs {
			comm.Regs[r] = 0x2200000000000000 | uint64(r+1)
		}
		comm.SP = 0x7FFF12340000
		comm.PC = 0x000000405678
		comm.Pstate = 0x80000000
		comm.TLS = 0x7FFF99990000
		comm.Root = 0x0000000140002000
		comm.Flags.Store(flags)

		cpu := &a64CPU{SP: page, TTBR0EL1: 0xDEAD0000}
		emulateA64Stub(t, s.Code, s.Reload, s.ReloadEnd, cpu)

		if !cpu.ERET {
			t.Fatalf("flags %#x: reload did not end with ERET", flags)
		}
		for r := range cpu.X {
			if cpu.X[r] != comm.Regs[r] {
				t.Errorf("flags %#x: X%d = %#x, want %#x", flags, r, cpu.X[r], comm.Regs[r])
			}
		}
		if cpu.SPEL0 != comm.SP || cpu.ELREL1 != comm.PC || cpu.SPSREL1 != comm.Pstate || cpu.TPIDREL0 != comm.TLS {
			t.Errorf("flags %#x: restored sysregs = (%#x, %#x, %#x, %#x), want (%#x, %#x, %#x, %#x)",
				flags, cpu.SPEL0, cpu.ELREL1, cpu.SPSREL1, cpu.TPIDREL0, comm.SP, comm.PC, comm.Pstate, comm.TLS)
		}
		wantRootReload := flags&whpx.FlagReloadRootForTest != 0
		if cpu.TLBFlushed != wantRootReload {
			t.Errorf("flags %#x: TLBFlushed = %v, want %v", flags, cpu.TLBFlushed, wantRootReload)
		}
		if wantRootReload && cpu.TTBR0EL1 != comm.Root {
			t.Errorf("flags %#x: TTBR0_EL1 = %#x, want %#x", flags, cpu.TTBR0EL1, comm.Root)
		}
		if !wantRootReload && cpu.TTBR0EL1 != 0xDEAD0000 {
			t.Errorf("flags %#x: TTBR0_EL1 changed to %#x without flagReloadRoot", flags, cpu.TTBR0EL1)
		}
		wantICache := flags&whpx.FlagICacheSyncForTest != 0
		if cpu.ICacheSynced != wantICache {
			t.Errorf("flags %#x: ICacheSynced = %v, want %v", flags, cpu.ICacheSynced, wantICache)
		}
	}
}

func TestA64SystemRegisterValues(t *testing.T) {
	if whpx.A64MairNormalForTest != 0xFF || whpx.A64MairForTest&0xFF != 0xFF {
		t.Errorf("MAIR attribute 0 is %#x, must be Normal write-back because hostarch.MemoryTypeWriteBack is zero", whpx.A64MairForTest&0xFF)
	}
	if whpx.A64MairForTest>>8&0xFF != whpx.A64MairNormalNCForTest || whpx.A64MairForTest>>16&0xFF != whpx.A64MairDeviceForTest {
		t.Errorf("MAIR attributes 1 and 2 are %#x and %#x", whpx.A64MairForTest>>8&0xFF, whpx.A64MairForTest>>16&0xFF)
	}
	tcr := uint64(whpx.A64TCRForTest)
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
	if whpx.A64PstateKernelForTest&whpx.A64PstateModeMaskForTest != 5 {
		t.Errorf("kernel PSTATE mode is %d, want EL1h (5)", whpx.A64PstateKernelForTest&whpx.A64PstateModeMaskForTest)
	}
	if whpx.A64PstateKernelForTest&0x3C0 != 0x3C0 {
		t.Errorf("kernel PSTATE does not mask D, A, I and F")
	}
	if whpx.A64PstateUserMaskForTest != 0xF|0x3C0 {
		t.Errorf("user PSTATE clear mask is %#x", whpx.A64PstateUserMaskForTest)
	}
	if whpx.A64SctlrSetForTest&whpx.A64SctlrMForTest == 0 || whpx.A64SctlrSetForTest&whpx.A64SctlrCForTest == 0 || whpx.A64SctlrSetForTest&whpx.A64SctlrIForTest == 0 {
		t.Error("SCTLR_EL1 bring-up does not enable the MMU and the caches")
	}
}
