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

package hvf

import (
	"errors"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// mrsX0 encodes "MRS X0, S<op0>_<op1>_C<crn>_C<crm>_<op2>".
func mrsX0(op0, op1, crn, crm, op2 uint32) uint32 {
	return 0xd5300000 | ((op0 - 2) << 19) | (op1 << 16) | (crn << 12) | (crm << 8) | (op2 << 5)
}

// TestGuestIDRegisterSanitizationAndHWCAPConsistency runs real EL0 MRS
// instructions inside an hvf guest and verifies that hidden host fields never
// leak, untracked ID registers read as zero instead of raising SIGILL,
// privileged registers still fault, and advertised AT_HWCAP features match the
// sanitized ID registers the guest sees.
func TestGuestIDRegisterSanitizationAndHWCAPConsistency(t *testing.T) {
	plat := newTestPlatform(t)

	readReg := func(t *testing.T, name string, insn uint32) uint64 {
		t.Helper()
		g := newGuest(t, plat, insn, insnSVC0)
		g.regs().Regs[0] = 0xdeadbeefcafebabe
		sig, _, err := g.switchOnce()
		if sig != nil || err != nil {
			t.Fatalf("MRS %s (%#x): Switch = (%v, %v), want syscall", name, insn, sig, err)
		}
		return g.regs().Regs[0]
	}

	if got := readReg(t, "MIDR_EL1", mrsX0(3, 0, 0, 0, 0)); got != hvcommon.HVFMIDREL1 {
		t.Errorf("MIDR_EL1 = %#x, want %#x", got, hvcommon.HVFMIDREL1)
	}
	if got := readReg(t, "MPIDR_EL1", mrsX0(3, 0, 0, 0, 5)); got != hvcommon.MPIDRSafeVal {
		t.Errorf("MPIDR_EL1 = %#x, want %#x", got, hvcommon.MPIDRSafeVal)
	}
	if got := readReg(t, "REVIDR_EL1", mrsX0(3, 0, 0, 0, 6)); got != 0 {
		t.Errorf("REVIDR_EL1 = %#x, want 0", got)
	}

	pfr0 := readReg(t, "ID_AA64PFR0_EL1", mrsX0(3, 0, 0, 4, 0))
	if leaked := pfr0 &^ (hvcommon.IDAA64PFR0SafeVal | hvcommon.IDAA64PFR0Visible); leaked != 0 {
		t.Errorf("ID_AA64PFR0_EL1 = %#x leaked hidden bits %#x", pfr0, leaked)
	}
	if pfr0&0xff != hvcommon.IDAA64PFR0SafeVal {
		t.Errorf("ID_AA64PFR0_EL1 EL0/EL1 = %#x, want %#x", pfr0&0xff, hvcommon.IDAA64PFR0SafeVal)
	}
	if got := readReg(t, "ID_AA64PFR1_EL1", mrsX0(3, 0, 0, 4, 1)); got != 0 {
		t.Errorf("ID_AA64PFR1_EL1 = %#x, want 0", got)
	}
	if got := readReg(t, "ID_AA64DFR0_EL1", mrsX0(3, 0, 0, 5, 0)); got != hvcommon.IDAA64DFR0SafeVal {
		t.Errorf("ID_AA64DFR0_EL1 = %#x, want %#x", got, hvcommon.IDAA64DFR0SafeVal)
	}

	isar0 := readReg(t, "ID_AA64ISAR0_EL1", mrsX0(3, 0, 0, 6, 0))
	if leaked := isar0 &^ hvcommon.IDAA64ISAR0Visible; leaked != 0 {
		t.Errorf("ID_AA64ISAR0_EL1 = %#x leaked hidden bits %#x", isar0, leaked)
	}
	isar1 := readReg(t, "ID_AA64ISAR1_EL1", mrsX0(3, 0, 0, 6, 1))
	if leaked := isar1 &^ hvcommon.IDAA64ISAR1Visible; leaked != 0 {
		t.Errorf("ID_AA64ISAR1_EL1 = %#x leaked hidden bits %#x", isar1, leaked)
	}

	mmfr0 := readReg(t, "ID_AA64MMFR0_EL1", mrsX0(3, 0, 0, 7, 0))
	if mmfr0 != hvcommon.IDAA64MMFR0SafeVal {
		t.Errorf("ID_AA64MMFR0_EL1 = %#x, want %#x", mmfr0, hvcommon.IDAA64MMFR0SafeVal)
	}
	if got := readReg(t, "ID_AA64MMFR1_EL1", mrsX0(3, 0, 0, 7, 1)); got != 0 {
		t.Errorf("ID_AA64MMFR1_EL1 = %#x, want 0", got)
	}
	mmfr2 := readReg(t, "ID_AA64MMFR2_EL1", mrsX0(3, 0, 0, 7, 2))
	if leaked := mmfr2 &^ hvcommon.IDAA64MMFR2Visible; leaked != 0 {
		t.Errorf("ID_AA64MMFR2_EL1 = %#x leaked hidden bits %#x", mmfr2, leaked)
	}

	// Untracked CRm=2..7 ID registers must read as zero rather than raising SIGILL.
	for _, tc := range []struct {
		name string
		insn uint32
	}{
		{"ID_AA64PFR2_EL1", mrsX0(3, 0, 0, 4, 2)},
		{"ID_AA64ZFR0_EL1", mrsX0(3, 0, 0, 4, 4)},
		{"ID_AA64SMFR0_EL1", mrsX0(3, 0, 0, 4, 5)},
		{"ID_AA64DFR1_EL1", mrsX0(3, 0, 0, 5, 1)},
		{"ID_AA64ISAR2_EL1", mrsX0(3, 0, 0, 6, 2)},
		{"ID_AA64MMFR3_EL1", mrsX0(3, 0, 0, 7, 3)},
	} {
		if got := readReg(t, tc.name, tc.insn); got != 0 {
			t.Errorf("%s = %#x, want 0 (RAZ)", tc.name, got)
		}
	}

	// Privileged and non-emulated system registers must still deliver SIGILL.
	for _, tc := range []struct {
		name string
		insn uint32
	}{
		{"TCR_EL1", mrsX0(3, 0, 2, 0, 2)},
		{"ID_PFR0_EL1 (AArch32)", mrsX0(3, 0, 0, 1, 0)},
		{"CRm=0 Op2=1", mrsX0(3, 0, 0, 0, 1)},
	} {
		g := newGuest(t, plat, tc.insn, insnSVC0)
		sig, _, err := g.switchOnce()
		if !errors.Is(err, platform.ErrContextSignal) || sig == nil || sig.Signo != int32(linux.SIGILL) {
			t.Errorf("MRS %s: Switch = (%+v, %v), want SIGILL", tc.name, sig, err)
		}
	}

	// Every feature advertised in AT_HWCAP / AT_HWCAP2 must remain visible in
	// the guest's sanitized ID registers. Initialize cpuid explicitly so
	// HostFeatureSet populates AT_HWCAP and AT_HWCAP2 before checking.
	cpuid.Initialize()
	fs := cpuid.HostFeatureSet()
	hw1, hw2 := fs.AllowedHWCap1(), fs.AllowedHWCap2()
	const baselineHWCap1 = cpuid.HWCAP_FP | cpuid.HWCAP_ASIMD | cpuid.HWCAP_ATOMICS | cpuid.HWCAP_CRC32
	if hw1&baselineHWCap1 != baselineHWCap1 {
		t.Fatalf("AllowedHWCap1() = %#x lacks Apple Silicon baseline %#x", hw1, baselineHWCap1)
	}
	nibble := func(v uint64, shift uint) uint64 { return (v >> shift) & 0xf }
	for _, check := range []struct {
		name      string
		present   bool
		supported bool
	}{
		{"FP", hw1&cpuid.HWCAP_FP != 0, nibble(pfr0, 16) != 0xf},
		{"ASIMD", hw1&cpuid.HWCAP_ASIMD != 0, nibble(pfr0, 20) != 0xf},
		{"FPHP", hw1&cpuid.HWCAP_FPHP != 0, nibble(pfr0, 16) == 1},
		{"ASIMDHP", hw1&cpuid.HWCAP_ASIMDHP != 0, nibble(pfr0, 20) == 1},
		{"DIT", hw1&cpuid.HWCAP_DIT != 0, nibble(pfr0, 48) >= 1},
		{"AES", hw1&cpuid.HWCAP_AES != 0, nibble(isar0, 4) >= 1},
		{"PMULL", hw1&cpuid.HWCAP_PMULL != 0, nibble(isar0, 4) >= 2},
		{"SHA1", hw1&cpuid.HWCAP_SHA1 != 0, nibble(isar0, 8) >= 1},
		{"SHA2", hw1&cpuid.HWCAP_SHA2 != 0, nibble(isar0, 12) >= 1},
		{"SHA512", hw1&cpuid.HWCAP_SHA512 != 0, nibble(isar0, 12) >= 2},
		{"CRC32", hw1&cpuid.HWCAP_CRC32 != 0, nibble(isar0, 16) >= 1},
		{"ATOMICS", hw1&cpuid.HWCAP_ATOMICS != 0, nibble(isar0, 20) >= 2},
		{"RDM", hw1&cpuid.HWCAP_ASIMDRDM != 0, nibble(isar0, 28) >= 1},
		{"SHA3", hw1&cpuid.HWCAP_SHA3 != 0, nibble(isar0, 32) >= 1},
		{"SM3", hw1&cpuid.HWCAP_SM3 != 0, nibble(isar0, 36) >= 1},
		{"SM4", hw1&cpuid.HWCAP_SM4 != 0, nibble(isar0, 40) >= 1},
		{"ASIMDDP", hw1&cpuid.HWCAP_ASIMDDP != 0, nibble(isar0, 44) >= 1},
		{"ASIMDFHM", hw1&cpuid.HWCAP_ASIMDFHM != 0, nibble(isar0, 48) >= 1},
		{"FLAGM", hw1&cpuid.HWCAP_FLAGM != 0, nibble(isar0, 52) >= 1},
		{"FLAGM2", hw2&cpuid.HWCAP2_FLAGM2 != 0, nibble(isar0, 52) >= 2},
		{"DCPOP", hw1&cpuid.HWCAP_DCPOP != 0, nibble(isar1, 0) >= 1},
		{"DCPODP", hw2&cpuid.HWCAP2_DCPODP != 0, nibble(isar1, 0) >= 2},
		{"JSCVT", hw1&cpuid.HWCAP_JSCVT != 0, nibble(isar1, 12) >= 1},
		{"FCMA", hw1&cpuid.HWCAP_FCMA != 0, nibble(isar1, 16) >= 1},
		{"LRCPC", hw1&cpuid.HWCAP_LRCPC != 0, nibble(isar1, 20) >= 1},
		{"ILRCPC", hw1&cpuid.HWCAP_ILRCPC != 0, nibble(isar1, 20) >= 2},
		{"FRINT", hw2&cpuid.HWCAP2_FRINT != 0, nibble(isar1, 32) >= 1},
		{"BF16", hw2&cpuid.HWCAP2_BF16 != 0, nibble(isar1, 44) >= 1},
		{"DGH", hw2&cpuid.HWCAP2_DGH != 0, nibble(isar1, 48) >= 1},
		{"I8MM", hw2&cpuid.HWCAP2_I8MM != 0, nibble(isar1, 52) >= 1},
		{"USCAT", hw1&cpuid.HWCAP_USCAT != 0, nibble(mmfr2, 32) >= 1},
	} {
		if check.present && !check.supported {
			t.Errorf("AT_HWCAP advertises %s but guest ID registers hide it (pfr0=%#x isar0=%#x isar1=%#x mmfr2=%#x)",
				check.name, pfr0, isar0, isar1, mmfr2)
		}
	}
}
