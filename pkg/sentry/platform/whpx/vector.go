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

// This file selects the vector state of amd64 guests. One selection sets the
// CPUID bits that the partition reports, the XCR0 value of every processor,
// and the layout that the floating-point converters use. A guest therefore
// never sees a CPUID feature whose state the platform does not save.

// XSAVE state components. x87 and SSE live in the legacy region; every other
// component has its own area.
const (
	xcr0X87    uint64 = 1 << 0
	xcr0SSE    uint64 = 1 << 1
	xcr0AVX    uint64 = 1 << 2
	xcr0AVX512 uint64 = 1<<5 | 1<<6 | 1<<7

	xcr0Legacy = xcr0X87 | xcr0SSE

	// xsaveComponents bounds the component numbers. Bit 63 of XCOMP_BV is
	// the compacted-format flag, not a component.
	xsaveComponents = 63
)

// Layout of the XSAVE area that every format shares.
const (
	xsaveLegacySize  = 512
	xsaveOffXstateBV = 512
	xsaveOffXcompBV  = 520
	xsaveHeaderEnd   = 576

	// xcompBVCompacted is the bit of XCOMP_BV that marks the compacted format.
	xcompBVCompacted uint64 = 1 << 63
)

// xsaveArea describes the area of one state component, as CPUID leaf 0xD
// sub-leaf i of the host reports it.
type xsaveArea struct {
	size uint32
	// offset is the offset in the standard format. It is zero for a
	// supervisor component, which only the compacted format holds.
	offset     uint32
	align64    bool
	supervisor bool
}

// xsaveLayout holds the areas of components 2 to 62, indexed by component
// number.
type xsaveLayout [xsaveComponents]xsaveArea

// newXsaveLayout builds a layout from CPUID leaf 0xD. leaf returns EAX, EBX
// and ECX of sub-leaf sub.
func newXsaveLayout(leaf func(sub uint32) (eax, ebx, ecx uint32)) *xsaveLayout {
	var l xsaveLayout
	for i := uint32(2); i < xsaveComponents; i++ {
		eax, ebx, ecx := leaf(i)
		l[i] = xsaveArea{size: eax, offset: ebx, align64: ecx&2 != 0, supervisor: ecx&1 != 0}
	}
	return &l
}

// standardSize returns the size of a standard-format image that holds every
// component of xcr0. An image of x87 and SSE alone needs no XSAVE header,
// because the Sentry uses the FXSAVE format on a host without XSAVE.
func (l *xsaveLayout) standardSize(xcr0 uint64) int {
	size := xsaveLegacySize
	for i := 2; i < xsaveComponents; i++ {
		if xcr0&(1<<i) != 0 {
			size = max(size, int(l[i].offset+l[i].size))
		}
	}
	return size
}

// Groups of WHV_PROCESSOR_XSAVE_FEATURES bits.
const (
	// xsaveAVXFeatures need the AVX state component.
	xsaveAVXFeatures = xsaveFeatAvx | xsaveFeatAvx2 | xsaveFeatFma | xsaveFeatVaes |
		xsaveFeatVpclmulqdq | xsaveFeatAvxVnni | xsaveFeatAvxIfma | xsaveFeatAvxNeConvert |
		xsaveFeatAvxVnniInt8 | xsaveFeatAvxVnniInt16

	// xsaveAVX512Features need the three AVX-512 state components.
	xsaveAVX512Features = xsaveFeatAvx512 | xsaveFeatAvx512DQ | xsaveFeatAvx512CD |
		xsaveFeatAvx512BW | xsaveFeatAvx512VL | xsaveFeatAvx512Bitalg | xsaveFeatAvx512Ifma |
		xsaveFeatAvx512VBmi | xsaveFeatAvx512VBmi2 | xsaveFeatAvx512Vnni |
		xsaveFeatAvx512VPopcntdq | xsaveFeatAvx512Bf16 | xsaveFeatAvx512Vp2Isect |
		xsaveFeatAvx512Fp16

	// xsaveKept lists the features that a guest may see. The platform saves
	// x87, SSE, AVX, and AVX-512 state. MPX, AMX, XFD, XCR1, and the
	// supervisor state stay hidden: the Sentry implements none of them. AVX10
	// stays hidden because the Sentry does not know CPUID leaf 0x24.
	xsaveKept = xsaveFeatXsave | xsaveFeatXsaveopt | xsaveFeatXsaveComp | xsaveFeatGfni |
		xsaveAVXFeatures | xsaveAVX512Features

	// procVEXFeatures are the ProcessorFeatures bits that need the AVX state.
	procVEXFeatures = procFeatXop | procFeatFma4 | procFeatF16C
)

// guestVector is the vector state that the partition gives its guests.
type guestVector struct {
	// xsaveFeatures is the ProcessorXsaveFeatures property of the partition.
	xsaveFeatures uint64

	// clearProcFeatures lists the ProcessorFeatures bits that the partition
	// must hide.
	clearProcFeatures uint64

	// xcr0 is the XCR0 value of every processor.
	xcr0 uint64

	// imageSize is the size of a standard-format image that holds xcr0.
	imageSize int

	layout *xsaveLayout
}

// selectGuestVector chooses the vector state from the XSAVE capability of the
// hypervisor, the host layout, and fpLimit, the size of the Sentry
// floating-point image. capability must include XsaveSupport.
func selectGuestVector(capability uint64, layout *xsaveLayout, fpLimit int) guestVector {
	fits := func(mask uint64) bool {
		for i := 2; i < xsaveComponents; i++ {
			if mask&(1<<i) == 0 {
				continue
			}
			a := layout[i]
			if a.size == 0 || a.supervisor || a.offset < xsaveHeaderEnd || int(a.offset+a.size) > fpLimit {
				return false
			}
		}
		return true
	}
	v := guestVector{
		xsaveFeatures: capability & xsaveKept,
		xcr0:          xcr0Legacy,
		layout:        layout,
	}
	switch {
	case capability&xsaveFeatAvx == 0 || !fits(xcr0AVX):
		v.xsaveFeatures &^= xsaveAVXFeatures | xsaveAVX512Features
		v.clearProcFeatures = procVEXFeatures
	case capability&xsaveFeatAvx512 == 0 || !fits(xcr0AVX512):
		v.xsaveFeatures &^= xsaveAVX512Features
		v.xcr0 |= xcr0AVX
	default:
		v.xcr0 |= xcr0AVX | xcr0AVX512
	}
	v.imageSize = layout.standardSize(v.xcr0)
	if fpLimit >= xsaveHeaderEnd {
		// The Sentry image has an XSAVE header, and a saved copy carries it.
		v.imageSize = max(v.imageSize, xsaveHeaderEnd)
	}
	return v
}

// missingFeatures returns the features that xcr0 needs and that applied, the
// ProcessorXsaveFeatures value that the partition reports, lacks.
func missingFeatures(xcr0, applied uint64) uint64 {
	need := xsaveFeatXsave
	if xcr0&xcr0AVX != 0 {
		need |= xsaveFeatAvx
	}
	if xcr0&xcr0AVX512 != 0 {
		need |= xsaveFeatAvx512
	}
	return need &^ applied
}
