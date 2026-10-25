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
	"testing"
	"unsafe"
)

// TestRegisterNamesMatchTheHeader pins every register name to the value in
// winhvplatformdefs.h. A wrong name writes a different register, so the table
// is the contract with the hypervisor.
func TestRegisterNamesMatchTheHeader(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want uint32
	}{
		{"Rax", x64RegRax, 0x00}, {"Rcx", x64RegRcx, 0x01}, {"Rdx", x64RegRdx, 0x02}, {"Rbx", x64RegRbx, 0x03},
		{"Rsp", x64RegRsp, 0x04}, {"Rbp", x64RegRbp, 0x05}, {"Rsi", x64RegRsi, 0x06}, {"Rdi", x64RegRdi, 0x07},
		{"R8", x64RegR8, 0x08}, {"R9", x64RegR9, 0x09}, {"R10", x64RegR10, 0x0A}, {"R11", x64RegR11, 0x0B},
		{"R12", x64RegR12, 0x0C}, {"R13", x64RegR13, 0x0D}, {"R14", x64RegR14, 0x0E}, {"R15", x64RegR15, 0x0F},
		{"Rip", x64RegRip, 0x10}, {"Rflags", x64RegRflags, 0x11},
		{"Es", x64RegEs, 0x12}, {"Cs", x64RegCs, 0x13}, {"Ss", x64RegSs, 0x14}, {"Ds", x64RegDs, 0x15},
		{"Fs", x64RegFs, 0x16}, {"Gs", x64RegGs, 0x17}, {"Ldtr", x64RegLdtr, 0x18}, {"Tr", x64RegTr, 0x19},
		{"Idtr", x64RegIdtr, 0x1A}, {"Gdtr", x64RegGdtr, 0x1B},
		{"Cr0", x64RegCr0, 0x1C}, {"Cr2", x64RegCr2, 0x1D}, {"Cr3", x64RegCr3, 0x1E}, {"Cr4", x64RegCr4, 0x1F},
		{"XCr0", x64RegXcr0, 0x27},
		{"Xmm0", x64RegXmm0, 0x1000}, {"FpMmx0", x64RegFpMmx0, 0x1010},
		{"FpControlStatus", x64RegFpControlStatus, 0x1018}, {"XmmControlStatus", x64RegXmmControlStatus, 0x1019},
		{"Efer", x64RegEfer, 0x2001}, {"KernelGsBase", x64RegKernelGsBase, 0x2002},
		{"Star", x64RegStar, 0x2008}, {"Lstar", x64RegLstar, 0x2009}, {"Cstar", x64RegCstar, 0x200A}, {"Sfmask", x64RegSfmask, 0x200B},
		{"InternalActivityState", x64RegInternalActivity, 0x80000005},
		{"X0", a64RegX0, 0x20000}, {"Fp", a64RegFp, 0x2001D}, {"Lr", a64RegLr, 0x2001E},
		{"Sp", a64RegSp, 0x2001F}, {"SpEl0", a64RegSpEl0, 0x20020}, {"SpEl1", a64RegSpEl1, 0x20021},
		{"Pc", a64RegPc, 0x20022}, {"Pstate", a64RegPstate, 0x20023}, {"Q0", a64RegQ0, 0x30000},
		{"SctlrEl1", a64RegSctlr, 0x40002}, {"CpacrEl1", a64RegCpacr, 0x40004}, {"Ttbr0El1", a64RegTtbr0, 0x40005},
		{"Ttbr1El1", a64RegTtbr1, 0x40006}, {"TcrEl1", a64RegTcr, 0x40007}, {"EsrEl1", a64RegEsr, 0x40008},
		{"FarEl1", a64RegFar, 0x40009}, {"MairEl1", a64RegMair, 0x4000B}, {"VbarEl1", a64RegVbar, 0x4000C},
		{"TpidrEl1", a64RegTpidrEl1, 0x4000E}, {"TpidrroEl0", a64RegTpidrro, 0x40010}, {"TpidrEl0", a64RegTpidrEl0, 0x40011},
		{"Fpcr", a64RegFpcr, 0x40012}, {"Fpsr", a64RegFpsr, 0x40013}, {"SpsrEl1", a64RegSpsrEl1, 0x40014},
		{"ElrEl1", a64RegElrEl1, 0x40015}, {"CntkctlEl1", a64RegCntkctl, 0x58008},
	} {
		if c.got != c.want {
			t.Errorf("register %s is %#x, the header says %#x", c.name, c.got, c.want)
		}
	}
}

func TestExitReasonsMatchTheHeader(t *testing.T) {
	for _, c := range []struct {
		name      string
		got, want uint32
	}{
		{"x64 MemoryAccess", x64ExitMemoryAccess, 0x1}, {"x64 Halt", x64ExitHalt, 0x8},
		{"x64 Exception", x64ExitException, 0x1002}, {"x64 Hypercall", x64ExitHypercall, 0x1005},
		{"x64 Canceled", x64ExitCanceled, 0x2001}, {"x64 Unrecoverable", x64ExitUnrecoverable, 0x4},
		{"arm64 UnmappedGpa", a64ExitUnmappedGpa, 0x80000000}, {"arm64 GpaIntercept", a64ExitGpaIntercept, 0x80000001},
		{"arm64 Unrecoverable", a64ExitUnrecoverable, 0x80000021}, {"arm64 InvalidVpRegister", a64ExitInvalidVpRegister, 0x80000020},
		{"arm64 Hypercall", a64ExitHypercall, 0x80000050}, {"arm64 Canceled", a64ExitCanceled, 0xFFFFFFFF},
		{"capability Features", capCodeFeatures, 1}, {"capability HypervisorPresent", capCodeHypervisorPresent, 0},
		{"property ProcessorCount", propCodeProcessorCount, 0x1FFF}, {"property ExtendedVmExits", propCodeExtendedVmExits, 1},
		{"map Read", mapFlagRead, 1}, {"map Write", mapFlagWrite, 2}, {"map Execute", mapFlagExecute, 4},
	} {
		if c.got != c.want {
			t.Errorf("%s is %#x, the header says %#x", c.name, c.got, c.want)
		}
	}
	// Arm64Support follows ten other bits in WHV_CAPABILITY_FEATURES, and
	// HypercallExit follows five bits in WHV_EXTENDED_VM_EXITS.
	if featArm64Support != 1<<11 || extExitHypercall != 1<<5 {
		t.Errorf("Arm64Support is %#x and HypercallExit is %#x", featArm64Support, extExitHypercall)
	}
}

func TestRegisterIndexSequences(t *testing.T) {
	// X0 to X28 and Q0 to Q31 count up by one, and Fp and Lr are X29 and X30.
	if a64RegFp != a64RegX0+29 || a64RegLr != a64RegX0+30 {
		t.Errorf("Fp is X0+%d and Lr is X0+%d, want X29 and X30", a64RegFp-a64RegX0, a64RegLr-a64RegX0)
	}
	if x64RegXmm0+15 != 0x100F || x64RegFpMmx0+7 != 0x1017 {
		t.Error("XMM and FP register runs do not match the header")
	}
}

func TestCommPageOffsets(t *testing.T) {
	var c CommPage
	for _, f := range []struct {
		name      string
		got, want uintptr
	}{
		{"Regs", unsafe.Offsetof(c.Regs), commOffRegs},
		{"SP", unsafe.Offsetof(c.SP), commOffSP},
		{"PC", unsafe.Offsetof(c.PC), commOffPC},
		{"Pstate", unsafe.Offsetof(c.Pstate), commOffPstate},
		{"TLS", unsafe.Offsetof(c.TLS), commOffTLS},
		{"FaultAddr", unsafe.Offsetof(c.FaultAddr), commOffFaultAddr},
		{"ESR", unsafe.Offsetof(c.ESR), commOffFaultCode},
		{"Vector", unsafe.Offsetof(c.Vector), commOffVector},
		{"CS", unsafe.Offsetof(c.CS), commOffCS},
		{"SS", unsafe.Offsetof(c.SS), commOffSS},
		{"Root", unsafe.Offsetof(c.Root), commOffRoot},
		{"ExitReason", unsafe.Offsetof(c.ExitReason), commOffExitReason},
		{"Flags", unsafe.Offsetof(c.Flags), commOffFlags},
		{"TSS", unsafe.Offsetof(c.TSS), commTSSOff},
		{"size", commPageSize, pageSize},
	} {
		if f.got != f.want {
			t.Errorf("CommPage %s is at %#x, the stubs use %#x", f.name, f.got, f.want)
		}
	}
	if commOffRegs+31*8 > commOffSP {
		t.Error("Regs overlaps SP")
	}
}

func TestKernelLayout(t *testing.T) {
	for _, arm := range []bool{false, true} {
		k := newKernelLayout(arm)
		if k.code() != k.base+0x1000 || k.sys() != k.base+0x2000 || k.comm(3) != k.base+0x10000+3*0x1000 {
			t.Errorf("layout of arm64=%v is %#x %#x %#x", arm, k.code(), k.sys(), k.comm(3))
		}
		// Every slot must stay in the same upper-half region.
		if last := k.comm(maxVPs - 1); last+pageSize < k.base || last-k.base >= 1<<39 {
			t.Errorf("last CommPage %#x leaves the region", last)
		}
	}
	if kernelBaseX64 != 0xFFFFFF8000000000 || kernelBaseA64 != 0xFFFF000000000000 {
		t.Error("kernel bases moved")
	}
	// The amd64 base must be a PGD-aligned address in the last PML4 slot, as
	// pagetables.NewWithUpper requires.
	if kernelBaseX64&(1<<39-1) != 0 {
		t.Error("amd64 kernel base is not PGD aligned")
	}
}
