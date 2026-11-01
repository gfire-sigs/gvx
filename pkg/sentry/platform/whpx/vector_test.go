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

import "testing"

// testXsaveLayout is the XSAVE layout of a CPU with AVX-512 and protection
// keys, plus one supervisor component. Components 5 and 11 need 64-byte
// alignment in the compacted format, and 11 lands on a shifted offset.
func testXsaveLayout() *xsaveLayout {
	var l xsaveLayout
	l[2] = xsaveArea{size: 256, offset: 576}
	l[5] = xsaveArea{size: 64, offset: 1088, align64: true}
	l[6] = xsaveArea{size: 512, offset: 1152}
	l[7] = xsaveArea{size: 1024, offset: 1664}
	l[9] = xsaveArea{size: 8, offset: 2688}
	l[11] = xsaveArea{size: 16, align64: true, supervisor: true}
	return &l
}

const (
	// testXcompBV lists the components that the hypervisor saves for the
	// test layout: x87, SSE, AVX, AVX-512, PKRU and one supervisor component.
	testXcompBV = xcr0Legacy | xcr0AVX | xcr0AVX512 | 1<<9 | 1<<11

	// testFPLimit is a Sentry image that holds the AVX-512 state.
	testFPLimit = 2688

	// testXsaveCapability is a hypervisor that offers every vector feature,
	// including the ones that the platform must hide.
	testXsaveCapability = xsaveFeatXsave | xsaveFeatXsaveopt | xsaveFeatXsaveComp |
		xsaveAVXFeatures | xsaveAVX512Features | xsaveFeatGfni |
		xsaveFeatMpx | xsaveFeatXsaveSupervisor | xsaveFeatXcr1 | xsaveFeatXfd |
		xsaveFeatAmxTile | xsaveFeatAmxBf16 | xsaveFeatAmxInt8 | xsaveFeatAmxFp16 |
		xsaveFeatAvx10_1_256 | xsaveFeatAvx10_1_512

	// testHiddenFeatures are features of testXsaveCapability whose state the
	// Sentry does not implement.
	testHiddenFeatures = xsaveFeatMpx | xsaveFeatXsaveSupervisor | xsaveFeatXcr1 | xsaveFeatXfd |
		xsaveFeatAmxTile | xsaveFeatAmxBf16 | xsaveFeatAmxInt8 | xsaveFeatAmxFp16 |
		xsaveFeatAvx10_1_256 | xsaveFeatAvx10_1_512
)

func TestSelectGuestVector(t *testing.T) {
	noAVX512 := func() *xsaveLayout {
		l := testXsaveLayout()
		l[7] = xsaveArea{}
		return l
	}
	for _, tc := range []struct {
		name       string
		capability uint64
		layout     *xsaveLayout
		fpLimit    int
		xcr0       uint64
		imageSize  int
		// present and absent are XSAVE feature bits that the property must
		// and must not hold.
		present, absent uint64
		clearProc       uint64
	}{
		{
			name:       "AVX-512 host enables every saved component",
			capability: testXsaveCapability,
			layout:     testXsaveLayout(),
			fpLimit:    testFPLimit,
			xcr0:       xcr0Legacy | xcr0AVX | xcr0AVX512,
			imageSize:  2688,
			present:    xsaveFeatXsave | xsaveFeatAvx | xsaveFeatAvx2 | xsaveFeatFma | xsaveFeatAvx512 | xsaveFeatAvx512VL | xsaveFeatVaes | xsaveFeatGfni,
			absent:     testHiddenFeatures,
		},
		{
			name:       "AVX2 host without AVX-512",
			capability: testXsaveCapability &^ xsaveAVX512Features,
			layout:     testXsaveLayout(),
			fpLimit:    testFPLimit,
			xcr0:       xcr0Legacy | xcr0AVX,
			imageSize:  832,
			present:    xsaveFeatAvx | xsaveFeatAvx2 | xsaveFeatFma | xsaveFeatVpclmulqdq,
			absent:     xsaveAVX512Features | testHiddenFeatures,
		},
		{
			name:       "Sentry image without room for AVX-512",
			capability: testXsaveCapability,
			layout:     testXsaveLayout(),
			fpLimit:    832,
			xcr0:       xcr0Legacy | xcr0AVX,
			imageSize:  832,
			present:    xsaveFeatAvx | xsaveFeatAvx2,
			absent:     xsaveAVX512Features,
		},
		{
			name:       "one missing AVX-512 component drops all three",
			capability: testXsaveCapability,
			layout:     noAVX512(),
			fpLimit:    testFPLimit,
			xcr0:       xcr0Legacy | xcr0AVX,
			imageSize:  832,
			present:    xsaveFeatAvx2,
			absent:     xsaveAVX512Features,
		},
		{
			name:       "hypervisor without AVX",
			capability: testXsaveCapability &^ (xsaveAVXFeatures | xsaveAVX512Features),
			layout:     testXsaveLayout(),
			fpLimit:    testFPLimit,
			xcr0:       xcr0Legacy,
			imageSize:  576,
			present:    xsaveFeatXsave | xsaveFeatGfni,
			absent:     xsaveAVXFeatures | xsaveAVX512Features,
			clearProc:  procFeatXop | procFeatFma4 | procFeatF16C,
		},
		{
			name:       "Sentry FXSAVE image without an XSAVE header",
			capability: testXsaveCapability,
			layout:     testXsaveLayout(),
			fpLimit:    512,
			xcr0:       xcr0Legacy,
			imageSize:  512,
			present:    xsaveFeatXsave,
			absent:     xsaveAVXFeatures | xsaveAVX512Features,
			clearProc:  procFeatXop | procFeatFma4 | procFeatF16C,
		},
		{
			name:       "Sentry image without room for AVX",
			capability: testXsaveCapability,
			layout:     testXsaveLayout(),
			fpLimit:    576,
			xcr0:       xcr0Legacy,
			imageSize:  576,
			present:    xsaveFeatXsave,
			absent:     xsaveAVXFeatures | xsaveAVX512Features,
			clearProc:  procFeatXop | procFeatFma4 | procFeatF16C,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := selectGuestVector(tc.capability, tc.layout, tc.fpLimit)
			if v.xcr0 != tc.xcr0 {
				t.Errorf("XCR0 = %#x, want %#x", v.xcr0, tc.xcr0)
			}
			if v.imageSize != tc.imageSize {
				t.Errorf("image size = %d, want %d", v.imageSize, tc.imageSize)
			}
			if missing := tc.present &^ v.xsaveFeatures; missing != 0 {
				t.Errorf("ProcessorXsaveFeatures %#x lacks %#x", v.xsaveFeatures, missing)
			}
			if extra := v.xsaveFeatures & tc.absent; extra != 0 {
				t.Errorf("ProcessorXsaveFeatures %#x exposes %#x", v.xsaveFeatures, extra)
			}
			if extra := v.xsaveFeatures &^ tc.capability; extra != 0 {
				t.Errorf("ProcessorXsaveFeatures %#x exposes %#x beyond the capability", v.xsaveFeatures, extra)
			}
			if v.clearProcFeatures != tc.clearProc {
				t.Errorf("cleared ProcessorFeatures = %#x, want %#x", v.clearProcFeatures, tc.clearProc)
			}
		})
	}
}

func TestMissingFeaturesNamesTheFeatureThatXCR0Needs(t *testing.T) {
	applied := xsaveFeatXsave | xsaveFeatAvx2
	if got := missingFeatures(xcr0Legacy|xcr0AVX|xcr0AVX512, applied); got != xsaveFeatAvx|xsaveFeatAvx512 {
		t.Errorf("missingFeatures = %#x, want AVX and AVX-512 (%#x)", got, xsaveFeatAvx|xsaveFeatAvx512)
	}
	if got := missingFeatures(xcr0Legacy, applied); got != 0 {
		t.Errorf("missingFeatures for x87 and SSE = %#x, want 0", got)
	}
}
