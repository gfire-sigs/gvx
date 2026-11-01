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
	"bytes"
	"encoding/binary"
	"testing"
)

// Compacted offsets of the test layout for testXcompBV. Component 5 and the
// supervisor component 11 start on a 64-byte boundary.
const (
	cOffAVX    = 576
	cOffOpmask = 832
	cOffZMMHi  = 896
	cOffHi16   = 1408
	cOffPKRU   = 2432
	cOffSuper  = 2496
	cEnd       = 2512

	xcr0All = xcr0Legacy | xcr0AVX | xcr0AVX512
)

// fill writes a pattern that differs for every byte and every seed.
func fill(b []byte, seed byte) {
	for i := range b {
		b[i] = seed + byte(i*7)
	}
}

// compactedState returns a compacted state of the test layout with every
// byte set to a pattern and the given XSTATE_BV.
func compactedState(xstateBV uint64) []byte {
	st := make([]byte, cEnd)
	fill(st, 1)
	clear(st[xsaveOffXstateBV:xsaveHeaderEnd])
	binary.LittleEndian.PutUint64(st[xsaveOffXstateBV:], xstateBV)
	binary.LittleEndian.PutUint64(st[xsaveOffXcompBV:], testXcompBV|xcompBVCompacted)
	binary.LittleEndian.PutUint32(st[fxOffMXCSR:], 0x1F80)
	binary.LittleEndian.PutUint32(st[fxOffMXCSRMask:], 0xFFBF)
	return st
}

// standardImage returns a standard-format image of size bytes with a pattern
// in every component and the given XSTATE_BV.
func standardImage(size int, xstateBV uint64) []byte {
	img := make([]byte, size)
	fill(img, 9)
	clear(img[xsaveOffXstateBV:xsaveHeaderEnd])
	binary.LittleEndian.PutUint64(img[xsaveOffXstateBV:], xstateBV)
	binary.LittleEndian.PutUint32(img[fxOffMXCSR:], 0x1F80)
	return img
}

func expectEqual(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs: got % x, want % x", what, got[:min(16, len(got))], want[:min(16, len(want))])
	}
}

func TestStandardFromCompactedMovesEachLiveComponentToItsStandardOffset(t *testing.T) {
	src := compactedState(xcr0All | 1<<9 | 1<<11)
	dst := bytes.Repeat([]byte{0xEE}, testFPLimit)
	if err := x86StandardFromCompacted(dst, src, xcr0All, testXsaveLayout()); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, "legacy region", dst[:xsaveLegacySize], src[:xsaveLegacySize])
	expectEqual(t, "AVX", dst[576:832], src[cOffAVX:cOffAVX+256])
	expectEqual(t, "opmask", dst[1088:1152], src[cOffOpmask:cOffOpmask+64])
	expectEqual(t, "ZMM_Hi256", dst[1152:1664], src[cOffZMMHi:cOffZMMHi+512])
	expectEqual(t, "Hi16_ZMM", dst[1664:2688], src[cOffHi16:cOffHi16+1024])
	if got := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:]); got != xcr0All {
		t.Errorf("XSTATE_BV = %#x, want only the XCR0 components %#x", got, uint64(xcr0All))
	}
	if !bytes.Equal(dst[xsaveOffXcompBV:xsaveHeaderEnd], make([]byte, xsaveHeaderEnd-xsaveOffXcompBV)) {
		t.Error("the standard header carries XCOMP_BV or reserved bytes")
	}
	if !bytes.Equal(dst[832:1088], bytes.Repeat([]byte{0xEE}, 1088-832)) {
		t.Error("the conversion wrote the MPX area, which XCR0 does not enable")
	}
}

func TestStandardFromCompactedWritesInitialValuesForUnusedLegacyComponents(t *testing.T) {
	src := compactedState(0)
	dst := bytes.Repeat([]byte{0xEE}, testFPLimit)
	if err := x86StandardFromCompacted(dst, src, xcr0All, testXsaveLayout()); err != nil {
		t.Fatal(err)
	}
	if fcw := binary.LittleEndian.Uint16(dst[fxOffFCW:]); fcw != x86FCWInit {
		t.Errorf("FCW = %#x, want the FNINIT value %#x", fcw, x86FCWInit)
	}
	if !bytes.Equal(dst[2:fxOffMXCSR], make([]byte, fxOffMXCSR-2)) || !bytes.Equal(dst[fxOffST:fxOffXMMEnd], make([]byte, fxOffXMMEnd-fxOffST)) {
		t.Error("an initial x87 or SSE component kept stale bytes")
	}
	if mxcsr := binary.LittleEndian.Uint32(dst[fxOffMXCSR:]); mxcsr != 0x1F80 {
		t.Errorf("MXCSR = %#x, want the saved %#x", mxcsr, 0x1F80)
	}
	if got := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:]); got != xcr0Legacy {
		t.Errorf("XSTATE_BV = %#x, want only x87 and SSE", got)
	}
}

func TestStandardFromCompactedCopiesOnlyTheXCR0Components(t *testing.T) {
	src := compactedState(xcr0All)
	dst := make([]byte, 832)
	if err := x86StandardFromCompacted(dst, src, xcr0Legacy|xcr0AVX, testXsaveLayout()); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:]); got != xcr0Legacy|xcr0AVX {
		t.Errorf("XSTATE_BV = %#x, want x87, SSE and AVX", got)
	}
	if err := x86StandardFromCompacted(make([]byte, 831), src, xcr0Legacy|xcr0AVX, testXsaveLayout()); err == nil {
		t.Error("an image without room for the AVX component was accepted")
	}
}

func TestCheckCompactedRejectsStatesThatDoNotMatchTheLayout(t *testing.T) {
	l := testXsaveLayout()
	for _, tc := range []struct {
		name  string
		state func() []byte
		xcr0  uint64
	}{
		{"standard format", func() []byte {
			st := compactedState(xcr0All)
			binary.LittleEndian.PutUint64(st[xsaveOffXcompBV:], 0)
			return st
		}, xcr0All},
		{"XCR0 component outside XCOMP_BV", func() []byte {
			st := compactedState(xcr0Legacy)
			binary.LittleEndian.PutUint64(st[xsaveOffXcompBV:], xcr0Legacy|xcompBVCompacted)
			return st
		}, xcr0Legacy | xcr0AVX},
		{"component unknown to CPUID", func() []byte {
			st := compactedState(xcr0All)
			binary.LittleEndian.PutUint64(st[xsaveOffXcompBV:], testXcompBV|1<<8|xcompBVCompacted)
			return st
		}, xcr0All},
		{"state shorter than its layout", func() []byte { return compactedState(xcr0All)[:cEnd-1] }, xcr0All},
		{"state shorter than the header", func() []byte { return compactedState(xcr0All)[:xsaveHeaderEnd-1] }, xcr0All},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := l.checkCompacted(tc.state(), tc.xcr0); err == nil {
				t.Error("checkCompacted accepted the state")
			}
		})
	}
}

func TestCompactedFromStandardKeepsTheStateOutsideXCR0(t *testing.T) {
	dst := compactedState(xcr0Legacy | 1<<9 | 1<<11)
	before := bytes.Clone(dst)
	src := standardImage(testFPLimit, xcr0All|1<<9)
	binary.LittleEndian.PutUint32(src[fxOffMXCSR:], 0xFFFF)
	if err := x86CompactedFromStandard(dst, src, xcr0All, testXsaveLayout()); err != nil {
		t.Fatal(err)
	}
	expectEqual(t, "AVX", dst[cOffAVX:cOffAVX+256], src[576:832])
	expectEqual(t, "opmask", dst[cOffOpmask:cOffOpmask+64], src[1088:1152])
	expectEqual(t, "ZMM_Hi256", dst[cOffZMMHi:cOffZMMHi+512], src[1152:1664])
	expectEqual(t, "Hi16_ZMM", dst[cOffHi16:cOffHi16+1024], src[1664:2688])
	expectEqual(t, "x87 and XMM registers", dst[fxOffST:fxOffXMMEnd], src[fxOffST:fxOffXMMEnd])
	expectEqual(t, "PKRU", dst[cOffPKRU:cOffPKRU+8], before[cOffPKRU:cOffPKRU+8])
	expectEqual(t, "supervisor component", dst[cOffSuper:cEnd], before[cOffSuper:cEnd])
	expectEqual(t, "XCOMP_BV", dst[xsaveOffXcompBV:xsaveOffXcompBV+8], before[xsaveOffXcompBV:xsaveOffXcompBV+8])
	if got, want := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:]), xcr0All|uint64(1<<9|1<<11); got != want {
		t.Errorf("XSTATE_BV = %#x, want %#x: the image sets XCR0 bits, the processor keeps the rest", got, want)
	}
	if mxcsr := binary.LittleEndian.Uint32(dst[fxOffMXCSR:]); mxcsr != 0xFFFF&0xFFBF {
		t.Errorf("MXCSR = %#x, want the reserved bits of MXCSR_MASK %#x cleared", mxcsr, 0xFFBF)
	}
	if mask := binary.LittleEndian.Uint32(dst[fxOffMXCSRMask:]); mask != 0xFFBF {
		t.Errorf("MXCSR_MASK = %#x, want the processor value", mask)
	}
}

func TestCompactedFromStandardResetsAComponentThatTheImageMarksInitial(t *testing.T) {
	dst := compactedState(xcr0All)
	src := standardImage(testFPLimit, xcr0Legacy)
	if err := x86CompactedFromStandard(dst, src, xcr0All, testXsaveLayout()); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:]); got != xcr0Legacy {
		t.Errorf("XSTATE_BV = %#x, want the AVX and AVX-512 bits cleared", got)
	}
}

func TestCompactedFromStandardRejectsAnImageShorterThanItsLiveComponents(t *testing.T) {
	src := standardImage(832, xcr0All)
	if err := x86CompactedFromStandard(compactedState(xcr0Legacy), src, xcr0All, testXsaveLayout()); err == nil {
		t.Error("an image that marks AVX-512 live without its bytes was accepted")
	}
}

func TestXsaveConversionAcceptsAnFXSAVEImage(t *testing.T) {
	l := testXsaveLayout()
	fx := make([]byte, xsaveLegacySize)
	fill(fx, 9)
	binary.LittleEndian.PutUint32(fx[fxOffMXCSR:], 0x1F80)
	st := compactedState(xcr0Legacy | xcr0AVX)
	if err := x86CompactedFromStandard(st, fx, xcr0Legacy, l); err != nil {
		t.Fatalf("load of an FXSAVE image: %v", err)
	}
	expectEqual(t, "x87 and XMM registers", st[fxOffST:fxOffXMMEnd], fx[fxOffST:fxOffXMMEnd])
	back := make([]byte, xsaveLegacySize)
	if err := x86StandardFromCompacted(back, st, xcr0Legacy, l); err != nil {
		t.Fatalf("store into an FXSAVE image: %v", err)
	}
	expectEqual(t, "x87 and XMM registers", back[fxOffST:fxOffXMMEnd], fx[fxOffST:fxOffXMMEnd])
}

func TestXsaveConversionRoundTripsTheSentryImage(t *testing.T) {
	l := testXsaveLayout()
	img := standardImage(testFPLimit, xcr0All)
	st := compactedState(xcr0Legacy)
	if err := x86CompactedFromStandard(st, img, xcr0All, l); err != nil {
		t.Fatal(err)
	}
	back := make([]byte, testFPLimit)
	if err := x86StandardFromCompacted(back, st, xcr0All, l); err != nil {
		t.Fatal(err)
	}
	// MXCSR_MASK belongs to the processor, and the area between the AVX and
	// the AVX-512 components belongs to MPX, which XCR0 does not enable.
	expectEqual(t, "x87 control words and MXCSR", back[:fxOffMXCSRMask], img[:fxOffMXCSRMask])
	expectEqual(t, "x87 and XMM registers", back[fxOffST:fxOffXMMEnd], img[fxOffST:fxOffXMMEnd])
	expectEqual(t, "AVX", back[576:832], img[576:832])
	expectEqual(t, "AVX-512", back[1088:2688], img[1088:2688])
	if got := binary.LittleEndian.Uint64(back[xsaveOffXstateBV:]); got != xcr0All {
		t.Errorf("XSTATE_BV = %#x after the round trip, want %#x", got, uint64(xcr0All))
	}
}

func TestA64FPLayoutAndRoundTrip(t *testing.T) {
	img := make([]byte, a64FPSize)
	binary.LittleEndian.PutUint64(img[a64FPOffFPSR:], 0x0800_0010)
	binary.LittleEndian.PutUint64(img[a64FPOffFPCR:], 0x0040_0000)
	for i := range 32 {
		binary.LittleEndian.PutUint64(img[a64FPOffQ+i*16:], 0xAB00_0000_0000_0000|uint64(i))
		binary.LittleEndian.PutUint64(img[a64FPOffQ+i*16+8:], 0xCD00_0000_0000_0000|uint64(i))
	}
	b := newRegBatch(a64FPRegCount)
	if err := a64FPToRegs(b, img); err != nil {
		t.Fatal(err)
	}
	names, _ := b.view()
	if len(names) != a64FPRegCount {
		t.Fatalf("batch has %d registers, want %d", len(names), a64FPRegCount)
	}
	for i := range 32 {
		if names[i] != a64RegQ0+uint32(i) {
			t.Errorf("register %d is %#x, want Q%d", i, names[i], i)
		}
		if lo, hi := b.u128(i); lo != 0xAB00_0000_0000_0000|uint64(i) || hi != 0xCD00_0000_0000_0000|uint64(i) {
			t.Errorf("Q%d is %#x:%#x", i, hi, lo)
		}
	}
	if names[32] != a64RegFpcr || names[33] != a64RegFpsr || b.u64(32) != 0x0040_0000 || b.u64(33) != 0x0800_0010 {
		t.Errorf("FPCR and FPSR are %#x=%#x and %#x=%#x", names[32], b.u64(32), names[33], b.u64(33))
	}
	back := make([]byte, a64FPSize)
	if err := a64FPFromRegs(back, b, 0); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(back, img) {
		t.Error("round trip changed the image")
	}

	wb := newRegBatch(a64FPRegCount)
	a64WantFP(wb)
	wn, _ := wb.view()
	if len(wn) != a64FPRegCount || wn[0] != a64RegQ0 || wn[31] != a64RegQ0+31 || wn[32] != a64RegFpcr || wn[33] != a64RegFpsr {
		t.Errorf("read list is %#x", wn)
	}
	if err := a64FPToRegs(newRegBatch(a64FPRegCount), make([]byte, a64FPSize-1)); err == nil {
		t.Error("short image accepted for a write")
	}
}
