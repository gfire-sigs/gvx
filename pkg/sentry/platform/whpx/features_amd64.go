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

import "z.gfire.dev/gvx/pkg/cpuid"

// xsaveCPUIDFeatures pairs each WHV_PROCESSOR_XSAVE_FEATURES bit with the
// Sentry features of the CPUID bits that it controls.
var xsaveCPUIDFeatures = []struct {
	bit      uint64
	features []cpuid.Feature
}{
	{xsaveFeatXsaveopt, []cpuid.Feature{cpuid.X86FeatureXSAVEOPT}},
	{xsaveFeatAvx, []cpuid.Feature{cpuid.X86FeatureAVX}},
	{xsaveFeatAvx2, []cpuid.Feature{cpuid.X86FeatureAVX2}},
	{xsaveFeatFma, []cpuid.Feature{cpuid.X86FeatureFMA}},
	{xsaveFeatMpx, []cpuid.Feature{cpuid.X86FeatureMPX}},
	{xsaveFeatAvx512, []cpuid.Feature{cpuid.X86FeatureAVX512F}},
	{xsaveFeatAvx512DQ, []cpuid.Feature{cpuid.X86FeatureAVX512DQ}},
	{xsaveFeatAvx512CD, []cpuid.Feature{cpuid.X86FeatureAVX512CD}},
	{xsaveFeatAvx512BW, []cpuid.Feature{cpuid.X86FeatureAVX512BW}},
	{xsaveFeatAvx512VL, []cpuid.Feature{cpuid.X86FeatureAVX512VL}},
	{xsaveFeatXsaveComp, []cpuid.Feature{cpuid.X86FeatureXSAVEC}},
	{xsaveFeatXsaveSupervisor, []cpuid.Feature{cpuid.X86FeatureXSAVES}},
	{xsaveFeatAvx512Bitalg, []cpuid.Feature{cpuid.X86FeatureAVX512_BITALG}},
	{xsaveFeatAvx512Ifma, []cpuid.Feature{cpuid.X86FeatureAVX512IFMA}},
	{xsaveFeatAvx512VBmi, []cpuid.Feature{cpuid.X86FeatureAVX512VBMI}},
	{xsaveFeatAvx512VBmi2, []cpuid.Feature{cpuid.X86FeatureAVX512_VBMI2}},
	{xsaveFeatAvx512Vnni, []cpuid.Feature{cpuid.X86FeatureAVX512_VNNI}},
	{xsaveFeatGfni, []cpuid.Feature{cpuid.X86FeatureGFNI}},
	{xsaveFeatVaes, []cpuid.Feature{cpuid.X86FeatureVAES}},
	{xsaveFeatAvx512VPopcntdq, []cpuid.Feature{cpuid.X86FeatureAVX512_VPOPCNTDQ}},
	{xsaveFeatVpclmulqdq, []cpuid.Feature{cpuid.X86FeatureVPCLMULQDQ}},
	{xsaveFeatAvx512Bf16, []cpuid.Feature{cpuid.X86FeatureAVX512_BF16}},
	{xsaveFeatAvx512Vp2Isect, []cpuid.Feature{cpuid.X86FeatureAVX512_VP2INTERSECT}},
	{xsaveFeatAvx512Fp16, []cpuid.Feature{cpuid.X86FeatureAVX512_FP16}},
	{xsaveFeatAmxTile, []cpuid.Feature{cpuid.X86FeatureAMX_TILE}},
	{xsaveFeatAmxBf16, []cpuid.Feature{cpuid.X86FeatureAMX_BF16}},
	{xsaveFeatAmxInt8, []cpuid.Feature{cpuid.X86FeatureAMX_INT8}},
	{xsaveFeatAvxVnni, []cpuid.Feature{cpuid.X86FeatureAVX_VNNI}},
}

// alwaysHidden are features that no guest of the partition can use. CR4.PKE
// stays clear, so PKU and OSPKE are absent. The Xeon Phi AVX-512 extensions
// have no WHV_PROCESSOR_XSAVE_FEATURES bit, so the partition never reports
// them.
var alwaysHidden = []cpuid.Feature{
	cpuid.X86FeaturePKU,
	cpuid.X86FeatureOSPKE,
	cpuid.X86FeatureAVX512PF,
	cpuid.X86FeatureAVX512ER,
	cpuid.X86FeatureAVX512_4VNNIW,
	cpuid.X86FeatureAVX512_4FMAPS,
}

// vexHidden are the VEX and XOP features outside the XSAVE property. They
// raise #UD while XCR0 does not enable the AVX state.
var vexHidden = []cpuid.Feature{cpuid.X86FeatureF16C, cpuid.X86FeatureXOP, cpuid.X86FeatureFMA4}

// hiddenFeatures returns the Sentry features that a guest cannot use, given
// applied, the ProcessorXsaveFeatures property of the partition, and the
// guest XCR0.
func hiddenFeatures(applied, xcr0 uint64) []cpuid.Feature {
	hidden := append([]cpuid.Feature(nil), alwaysHidden...)
	for _, m := range xsaveCPUIDFeatures {
		if applied&m.bit == 0 {
			hidden = append(hidden, m.features...)
		}
	}
	if xcr0&xcr0AVX == 0 {
		hidden = append(hidden, vexHidden...)
	}
	return hidden
}

// GuestFeatureSet returns the CPU features that guests of the platform can
// use. The Sentry builds /proc/cpuinfo, signal frames, and the sigreturn
// checks from it, so it must match the CPUID and XCR0 of the partition.
func (p *Platform) GuestFeatureSet(host cpuid.FeatureSet) cpuid.FeatureSet {
	return host.RestrictXSAVE(p.vec.xcr0, hiddenFeatures(p.info.xsaveFeatures, p.vec.xcr0)...)
}
