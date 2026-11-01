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

import "testing"

// featureSet returns the set of features named by names.
func featureSet(names ...string) map[string]bool {
	set := make(map[string]bool, len(names))
	for _, name := range names {
		set[name] = true
	}
	return set
}

// idFieldValue returns value placed in the 4-bit field that starts at shift.
func idFieldValue(value uint64, shift uint) uint64 {
	return value << shift
}

func TestHWCapFromFeaturesSetsBitsForReportedFeatures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features []string
		want1    uint64
		want2    uint64
	}{
		{
			name:     "floating point and Advanced SIMD set FP and ASIMD",
			features: []string{"FEAT_FP", "FEAT_AdvSIMD"},
			want1:    HWCAP_FP | HWCAP_ASIMD,
		},
		{
			name:     "AES alone does not set PMULL",
			features: []string{"FEAT_AES"},
			want1:    HWCAP_AES,
		},
		{
			name:     "AES and PMULL set separate bits",
			features: []string{"FEAT_AES", "FEAT_PMULL"},
			want1:    HWCAP_AES | HWCAP_PMULL,
		},
		{
			name:     "FP16 sets both half-precision bits",
			features: []string{"FEAT_FP16"},
			want1:    HWCAP_FPHP | HWCAP_ASIMDHP,
		},
		{
			name:     "LRCPC alone does not set ILRCPC",
			features: []string{"FEAT_LRCPC"},
			want1:    HWCAP_LRCPC,
		},
		{
			name:     "LRCPC2 sets ILRCPC on top of LRCPC",
			features: []string{"FEAT_LRCPC", "FEAT_LRCPC2"},
			want1:    HWCAP_LRCPC | HWCAP_ILRCPC,
		},
		{
			name:     "LSE sets ATOMICS and CRC32 sets CRC32",
			features: []string{"FEAT_LSE", "FEAT_CRC32"},
			want1:    HWCAP_ATOMICS | HWCAP_CRC32,
		},
		{
			name:     "DPB sets DCPOP and DPB2 sets DCPODP",
			features: []string{"FEAT_DPB", "FEAT_DPB2"},
			want1:    HWCAP_DCPOP,
			want2:    HWCAP2_DCPODP,
		},
		{
			name:     "BF16 sets an AT_HWCAP2 bit only",
			features: []string{"FEAT_BF16"},
			want2:    HWCAP2_BF16,
		},
		{
			name:     "pointer authentication, SVE, MTE, and SME set no bit",
			features: []string{"FEAT_PAuth", "FEAT_SVE", "FEAT_MTE", "FEAT_SME"},
		},
		{
			name: "no feature sets no bit",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hwcapFromFeatures(featureSet(tc.features...))
			if got.hwCap1 != tc.want1 {
				t.Errorf("hwcapFromFeatures(%v).hwCap1 = %#x, want %#x", tc.features, got.hwCap1, tc.want1)
			}
			if got.hwCap2 != tc.want2 {
				t.Errorf("hwcapFromFeatures(%v).hwCap2 = %#x, want %#x", tc.features, got.hwCap2, tc.want2)
			}
		})
	}
}

func TestFeaturesFromIDRegistersSetsBitsForReportedFields(t *testing.T) {
	for _, tc := range []struct {
		name  string
		regs  [idRegCount]uint64
		want1 uint64
		want2 uint64
	}{
		{
			name:  "zero ID registers report FP and Advanced SIMD only",
			want1: HWCAP_FP | HWCAP_ASIMD,
		},
		{
			name:  "field 0xf reports no floating point or Advanced SIMD",
			regs:  [idRegCount]uint64{idRegPFR0: idFieldValue(0xff, 16)},
			want1: 0,
		},
		{
			name:  "FP and Advanced SIMD fields of 1 report FP16",
			regs:  [idRegCount]uint64{idRegPFR0: idFieldValue(1, 16) | idFieldValue(1, 20)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_FPHP | HWCAP_ASIMDHP,
		},
		{
			name:  "PFR0 DIT field of 1 reports DIT",
			regs:  [idRegCount]uint64{idRegPFR0: idFieldValue(1, 48)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_DIT,
		},
		{
			name:  "AES field of 2 reports AES and PMULL",
			regs:  [idRegCount]uint64{idRegISAR0: idFieldValue(2, 4)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_AES | HWCAP_PMULL,
		},
		{
			name:  "SHA2 field of 2 reports SHA256 and SHA512",
			regs:  [idRegCount]uint64{idRegISAR0: idFieldValue(2, 12)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_SHA2 | HWCAP_SHA512,
		},
		{
			name:  "Atomic field of 2 reports ATOMICS",
			regs:  [idRegCount]uint64{idRegISAR0: idFieldValue(2, 20)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_ATOMICS,
		},
		{
			name:  "TS field of 2 reports FLAGM and FLAGM2",
			regs:  [idRegCount]uint64{idRegISAR0: idFieldValue(2, 52)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_FLAGM,
			want2: HWCAP2_FLAGM2,
		},
		{
			name:  "LRCPC field of 2 reports LRCPC and ILRCPC",
			regs:  [idRegCount]uint64{idRegISAR1: idFieldValue(2, 20)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_LRCPC | HWCAP_ILRCPC,
		},
		{
			name:  "FRINTTS field of 1 reports FRINT in AT_HWCAP2",
			regs:  [idRegCount]uint64{idRegISAR1: idFieldValue(1, 32)},
			want1: HWCAP_FP | HWCAP_ASIMD,
			want2: HWCAP2_FRINT,
		},
		{
			name:  "MMFR2 AT field of 1 reports USCAT",
			regs:  [idRegCount]uint64{idRegMMFR2: idFieldValue(1, 32)},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_USCAT,
		},
		{
			// Default registers of hvcommon, which whpx serves to the guest.
			name: "whpx default registers report only the baseline crypto and atomics",
			regs: [idRegCount]uint64{
				idRegPFR0:  0x00000011,
				idRegISAR0: 0x00211120,
				idRegISAR1: 0x00100001,
				idRegMMFR2: 0,
			},
			want1: HWCAP_FP | HWCAP_ASIMD | HWCAP_AES | HWCAP_PMULL | HWCAP_SHA1 | HWCAP_SHA2 |
				HWCAP_CRC32 | HWCAP_ATOMICS | HWCAP_LRCPC | HWCAP_DCPOP,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hwcapFromFeatures(featuresFromIDRegisters(tc.regs))
			if got.hwCap1 != tc.want1 {
				t.Errorf("AT_HWCAP bits = %#x, want %#x", got.hwCap1, tc.want1)
			}
			if got.hwCap2 != tc.want2 {
				t.Errorf("AT_HWCAP2 bits = %#x, want %#x", got.hwCap2, tc.want2)
			}
		})
	}
}

func TestRestrictFeaturesDropsFeaturesHiddenFromGuest(t *testing.T) {
	host := featureSet(
		"FEAT_FP", "FEAT_AdvSIMD", "FEAT_FP16", "FEAT_AES", "FEAT_PMULL",
		"FEAT_SHA1", "FEAT_SHA256", "FEAT_SHA512", "FEAT_SHA3", "FEAT_CRC32",
		"FEAT_LSE", "FEAT_DotProd", "FEAT_JSCVT", "FEAT_FCMA", "FEAT_LRCPC",
		"FEAT_LRCPC2", "FEAT_DPB", "FEAT_RDM", "FEAT_FHM", "FEAT_DIT",
	)
	// Only the features of the whpx default registers stay visible.
	guest := featuresFromIDRegisters([idRegCount]uint64{
		idRegPFR0:  0x00000011,
		idRegISAR0: 0x00211120,
		idRegISAR1: 0x00100001,
	})

	got := hwcapFromFeatures(restrictFeatures(host, guest))
	want := uint64(HWCAP_FP | HWCAP_ASIMD | HWCAP_AES | HWCAP_PMULL | HWCAP_SHA1 |
		HWCAP_SHA2 | HWCAP_CRC32 | HWCAP_ATOMICS | HWCAP_LRCPC | HWCAP_DCPOP)
	if got.hwCap1 != want {
		t.Errorf("restricted AT_HWCAP = %#x, want %#x", got.hwCap1, want)
	}
}
