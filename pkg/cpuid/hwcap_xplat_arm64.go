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

//go:build arm64

package cpuid

// hwcapEntry maps one host feature to the AT_HWCAP or AT_HWCAP2 bit that the
// feature implies. Feature names follow the Arm architecture (FEAT_*).
type hwcapEntry struct {
	feature string
	bit     uint64
}

// hwcap1Entries maps host features to AT_HWCAP bits. The pairs follow the
// Linux arm64 HWCAP definitions in arch/arm64/kernel/cpufeature.c.
//
// EVTSTRM has no entry because no host feature name reports it. PACA, PACG,
// and SVE have no entry because the guest must not depend on them.
var hwcap1Entries = []hwcapEntry{
	{"FEAT_FP", HWCAP_FP},
	{"FEAT_AdvSIMD", HWCAP_ASIMD},
	{"FEAT_FP16", HWCAP_FPHP},
	{"FEAT_FP16", HWCAP_ASIMDHP},
	{"FEAT_AES", HWCAP_AES},
	{"FEAT_PMULL", HWCAP_PMULL},
	{"FEAT_SHA1", HWCAP_SHA1},
	{"FEAT_SHA256", HWCAP_SHA2},
	{"FEAT_CRC32", HWCAP_CRC32},
	{"FEAT_LSE", HWCAP_ATOMICS},
	{"FEAT_DIT", HWCAP_DIT},
	{"FEAT_RDM", HWCAP_ASIMDRDM},
	{"FEAT_JSCVT", HWCAP_JSCVT},
	{"FEAT_FCMA", HWCAP_FCMA},
	{"FEAT_LRCPC", HWCAP_LRCPC},
	{"FEAT_LRCPC2", HWCAP_ILRCPC},
	{"FEAT_DPB", HWCAP_DCPOP},
	{"FEAT_SHA3", HWCAP_SHA3},
	{"FEAT_SM3", HWCAP_SM3},
	{"FEAT_SM4", HWCAP_SM4},
	{"FEAT_DotProd", HWCAP_ASIMDDP},
	{"FEAT_SHA512", HWCAP_SHA512},
	{"FEAT_FHM", HWCAP_ASIMDFHM},
	{"FEAT_FlagM", HWCAP_FLAGM},
	{"FEAT_SB", HWCAP_SB},
	{"FEAT_LSE2", HWCAP_USCAT},
}

// hwcap2Entries maps host features to AT_HWCAP2 bits.
var hwcap2Entries = []hwcapEntry{
	{"FEAT_DPB2", HWCAP2_DCPODP},
	{"FEAT_FlagM2", HWCAP2_FLAGM2},
	{"FEAT_FRINTTS", HWCAP2_FRINT},
	{"FEAT_I8MM", HWCAP2_I8MM},
	{"FEAT_BF16", HWCAP2_BF16},
}

// hwcapFromFeatures returns the AT_HWCAP and AT_HWCAP2 bits that the
// reported features imply. A feature that is absent from the map sets no bit.
func hwcapFromFeatures(features map[string]bool) hwCap {
	var c hwCap
	for _, e := range hwcap1Entries {
		if features[e.feature] {
			c.hwCap1 |= e.bit
		}
	}
	for _, e := range hwcap2Entries {
		if features[e.feature] {
			c.hwCap2 |= e.bit
		}
	}
	return c
}

// Indexes of the ID registers in an idRegisters array.
const (
	idRegPFR0 = iota
	idRegISAR0
	idRegISAR1
	idRegMMFR2
	idRegCount
)

// idFieldRule sets feature when the 4-bit field at shift in register reg is
// at least min.
type idFieldRule struct {
	reg     int
	shift   uint
	min     uint64
	feature string
}

// idFieldRules follows the field layout of the Arm ID registers. Each rule
// uses the minimum field value that the Linux HWCAP definitions require.
var idFieldRules = []idFieldRule{
	{idRegPFR0, 48, 1, "FEAT_DIT"},

	{idRegISAR0, 4, 1, "FEAT_AES"},
	{idRegISAR0, 4, 2, "FEAT_PMULL"},
	{idRegISAR0, 8, 1, "FEAT_SHA1"},
	{idRegISAR0, 12, 1, "FEAT_SHA256"},
	{idRegISAR0, 12, 2, "FEAT_SHA512"},
	{idRegISAR0, 16, 1, "FEAT_CRC32"},
	{idRegISAR0, 20, 2, "FEAT_LSE"},
	{idRegISAR0, 28, 1, "FEAT_RDM"},
	{idRegISAR0, 32, 1, "FEAT_SHA3"},
	{idRegISAR0, 36, 1, "FEAT_SM3"},
	{idRegISAR0, 40, 1, "FEAT_SM4"},
	{idRegISAR0, 44, 1, "FEAT_DotProd"},
	{idRegISAR0, 48, 1, "FEAT_FHM"},
	{idRegISAR0, 52, 1, "FEAT_FlagM"},
	{idRegISAR0, 52, 2, "FEAT_FlagM2"},

	{idRegISAR1, 0, 1, "FEAT_DPB"},
	{idRegISAR1, 0, 2, "FEAT_DPB2"},
	{idRegISAR1, 12, 1, "FEAT_JSCVT"},
	{idRegISAR1, 16, 1, "FEAT_FCMA"},
	{idRegISAR1, 20, 1, "FEAT_LRCPC"},
	{idRegISAR1, 20, 2, "FEAT_LRCPC2"},
	{idRegISAR1, 32, 1, "FEAT_FRINTTS"},
	{idRegISAR1, 36, 1, "FEAT_SB"},
	{idRegISAR1, 44, 1, "FEAT_BF16"},
	{idRegISAR1, 52, 1, "FEAT_I8MM"},

	{idRegMMFR2, 32, 1, "FEAT_LSE2"},
}

// featuresFromIDRegisters returns the features that the ID register values
// report. regs is indexed by idRegPFR0 through idRegMMFR2.
//
// The floating-point and Advanced SIMD fields use 0b1111 for absent, so a
// zero field means present. The other fields use zero for absent.
func featuresFromIDRegisters(regs [idRegCount]uint64) map[string]bool {
	features := make(map[string]bool)
	fp := idField(regs[idRegPFR0], 16)
	simd := idField(regs[idRegPFR0], 20)
	if fp != 0xf {
		features["FEAT_FP"] = true
	}
	if simd != 0xf {
		features["FEAT_AdvSIMD"] = true
	}
	if fp == 1 && simd == 1 {
		features["FEAT_FP16"] = true
	}
	for _, r := range idFieldRules {
		if idField(regs[r.reg], r.shift) >= r.min {
			features[r.feature] = true
		}
	}
	return features
}

// idField returns the 4-bit field of an ID register that starts at shift.
func idField(reg uint64, shift uint) uint64 {
	return reg >> shift & 0xf
}

// restrictFeatures returns the features that both the host and the guest
// report.
func restrictFeatures(host, guest map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for name, ok := range host {
		if ok && guest[name] {
			out[name] = true
		}
	}
	return out
}
