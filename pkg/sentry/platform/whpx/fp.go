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
)

// This file converts between the Sentry floating-point image and the state
// formats of the Windows Hypervisor Platform. The converters are pure
// functions, so tests run them on every host.
//
// On amd64 the Sentry image is a standard-format XSAVE area. The hypervisor
// reads and writes the XSAVE state of a processor in the compacted format of
// XSAVES, which also holds supervisor components.
//
// On arm64 the image follows the layout of ring0.SaveFloatingPoint: FPSR at
// byte 0, FPCR at byte 8 and Q0 to Q31 from byte 16.

// Offsets in the legacy region of an XSAVE area (the FXSAVE layout).
const (
	fxOffFCW       = 0
	fxOffMXCSR     = 24
	fxOffMXCSRMask = 28
	fxOffST        = 32
	fxOffXMM       = 160
	fxOffXMMEnd    = 416

	// x86FCWInit is the x87 control word after FNINIT.
	x86FCWInit = 0x037F

	// x86MXCSRMaskDefault is the MXCSR mask of CPUs that report zero.
	x86MXCSRMaskDefault = 0xFFBF
)

// compactedOffsets returns the offset of each component of xcompBV in a
// compacted image, and the end of the last component.
func (l *xsaveLayout) compactedOffsets(xcompBV uint64) (offs [xsaveComponents]uint32, end int, err error) {
	off := uint32(xsaveHeaderEnd)
	for i := 2; i < xsaveComponents; i++ {
		if xcompBV&(1<<i) == 0 {
			continue
		}
		a := l[i]
		if a.size == 0 {
			return offs, 0, fmt.Errorf("whpx: XCOMP_BV %#x names component %d, which CPUID leaf 0xD does not describe", xcompBV, i)
		}
		if a.align64 {
			off = (off + 63) &^ 63
		}
		offs[i] = off
		off += a.size
	}
	return offs, int(off), nil
}

// checkCompacted verifies that buf is a compacted image that holds every
// component of xcr0, and returns the component offsets.
func (l *xsaveLayout) checkCompacted(buf []byte, xcr0 uint64) ([xsaveComponents]uint32, error) {
	if len(buf) < xsaveHeaderEnd {
		return [xsaveComponents]uint32{}, fmt.Errorf("whpx: XSAVE state is %d bytes, shorter than the XSAVE header", len(buf))
	}
	xcompBV := binary.LittleEndian.Uint64(buf[xsaveOffXcompBV:])
	if xcompBV&xcompBVCompacted == 0 {
		return [xsaveComponents]uint32{}, fmt.Errorf("whpx: XSAVE state has XCOMP_BV %#x, not the compacted format", xcompBV)
	}
	if missing := xcr0 &^ xcr0Legacy &^ xcompBV; missing != 0 {
		return [xsaveComponents]uint32{}, fmt.Errorf("whpx: XSAVE state with XCOMP_BV %#x lacks components %#x of XCR0 %#x", xcompBV, missing, xcr0)
	}
	offs, end, err := l.compactedOffsets(xcompBV &^ xcompBVCompacted)
	if err != nil {
		return offs, err
	}
	if end > len(buf) {
		return offs, fmt.Errorf("whpx: XSAVE state with XCOMP_BV %#x needs %d bytes, the hypervisor returned %d", xcompBV, end, len(buf))
	}
	return offs, nil
}

// x86StandardFromCompacted writes src, the compacted XSAVE state of a
// processor, into dst, the standard-format image of the Sentry. It writes the
// components of xcr0 and sets XSTATE_BV to the live ones.
func x86StandardFromCompacted(dst, src []byte, xcr0 uint64, l *xsaveLayout) error {
	offs, err := l.checkCompacted(src, xcr0)
	if err != nil {
		return err
	}
	if need := l.standardSize(xcr0); len(dst) < need {
		return fmt.Errorf("whpx: FP image is %d bytes, XCR0 %#x needs %d", len(dst), xcr0, need)
	}
	bv := binary.LittleEndian.Uint64(src[xsaveOffXstateBV:])
	copy(dst[:xsaveLegacySize], src[:xsaveLegacySize])
	// XSAVES skips a component in its initial state, so the buffer can hold
	// stale bytes for it. MXCSR is outside both components and always valid.
	if bv&xcr0X87 == 0 {
		clear(dst[:fxOffMXCSR])
		clear(dst[fxOffST:fxOffXMM])
		binary.LittleEndian.PutUint16(dst[fxOffFCW:], x86FCWInit)
	}
	if bv&xcr0SSE == 0 {
		clear(dst[fxOffXMM:fxOffXMMEnd])
	}
	for i := 2; i < xsaveComponents; i++ {
		bit := uint64(1) << i
		if xcr0&bit == 0 || bv&bit == 0 {
			continue
		}
		a := l[i]
		copy(dst[a.offset:a.offset+a.size], src[offs[i]:offs[i]+a.size])
	}
	if len(dst) < xsaveHeaderEnd {
		// An FXSAVE image has no header.
		return nil
	}
	// The legacy region now holds valid x87 and SSE values in every case.
	clear(dst[xsaveOffXstateBV:xsaveHeaderEnd])
	binary.LittleEndian.PutUint64(dst[xsaveOffXstateBV:], bv&xcr0|xcr0Legacy)
	return nil
}

// x86CompactedFromStandard loads src, the standard-format image of the
// Sentry, into dst, the current compacted XSAVE state of a processor. It
// keeps XCOMP_BV, MXCSR_MASK, and every component outside xcr0, so the
// supervisor state passes through unchanged. A component of xcr0 that src
// marks as initial becomes initial.
func x86CompactedFromStandard(dst, src []byte, xcr0 uint64, l *xsaveLayout) error {
	offs, err := l.checkCompacted(dst, xcr0)
	if err != nil {
		return err
	}
	if len(src) < xsaveLegacySize {
		return fmt.Errorf("whpx: FP image is %d bytes, shorter than the FXSAVE area", len(src))
	}
	// An FXSAVE image without a header holds x87 and SSE state only.
	srcBV := xcr0Legacy
	if len(src) >= xsaveHeaderEnd {
		srcBV = binary.LittleEndian.Uint64(src[xsaveOffXstateBV:]) & xcr0
	}
	for i := 2; i < xsaveComponents; i++ {
		bit := uint64(1) << i
		if srcBV&bit == 0 {
			continue
		}
		if a := l[i]; len(src) < int(a.offset+a.size) {
			return fmt.Errorf("whpx: FP image is %d bytes, component %d ends at %d", len(src), i, a.offset+a.size)
		}
	}
	copy(dst[:fxOffMXCSR], src[:fxOffMXCSR])
	mask := binary.LittleEndian.Uint32(dst[fxOffMXCSRMask:])
	if mask == 0 {
		mask = x86MXCSRMaskDefault
	}
	// XRSTORS faults on a reserved MXCSR bit.
	binary.LittleEndian.PutUint32(dst[fxOffMXCSR:], binary.LittleEndian.Uint32(src[fxOffMXCSR:])&mask)
	copy(dst[fxOffST:fxOffXMMEnd], src[fxOffST:fxOffXMMEnd])
	for i := 2; i < xsaveComponents; i++ {
		if srcBV&(1<<i) == 0 {
			continue
		}
		a := l[i]
		copy(dst[offs[i]:offs[i]+a.size], src[a.offset:a.offset+a.size])
	}
	bv := binary.LittleEndian.Uint64(dst[xsaveOffXstateBV:])
	binary.LittleEndian.PutUint64(dst[xsaveOffXstateBV:], bv&^xcr0|srcBV|xcr0Legacy)
	return nil
}

// Layout of the arm64 floating-point image.
const (
	a64FPOffFPSR = 0
	a64FPOffFPCR = 8
	a64FPOffQ    = 16
	a64FPSize    = 528

	// a64FPRegCount is the number of registers in an FP read or write: Q0 to
	// Q31, FPCR and FPSR.
	a64FPRegCount = 34
)

// a64WantFP appends the vector registers and the FP control registers to a
// read batch.
func a64WantFP(b *regBatch) {
	for i := range 32 {
		b.want(a64RegQ0 + uint32(i))
	}
	b.want(a64RegFpcr)
	b.want(a64RegFpsr)
}

// a64FPFromRegs writes the registers that a64WantFP requested into image.
func a64FPFromRegs(image []byte, b *regBatch, first int) error {
	if len(image) < a64FPSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), a64FPSize)
	}
	for i := range 32 {
		lo, hi := b.u128(first + i)
		binary.LittleEndian.PutUint64(image[a64FPOffQ+i*16:], lo)
		binary.LittleEndian.PutUint64(image[a64FPOffQ+i*16+8:], hi)
	}
	binary.LittleEndian.PutUint64(image[a64FPOffFPCR:], b.u64(first+32))
	binary.LittleEndian.PutUint64(image[a64FPOffFPSR:], b.u64(first+33))
	return nil
}

// a64FPToRegs appends the register writes that load image into a virtual
// processor.
func a64FPToRegs(b *regBatch, image []byte) error {
	if len(image) < a64FPSize {
		return fmt.Errorf("whpx: FP image is %d bytes, want at least %d", len(image), a64FPSize)
	}
	for i := range 32 {
		b.add128(a64RegQ0+uint32(i),
			binary.LittleEndian.Uint64(image[a64FPOffQ+i*16:]),
			binary.LittleEndian.Uint64(image[a64FPOffQ+i*16+8:]))
	}
	b.add64(a64RegFpcr, binary.LittleEndian.Uint64(image[a64FPOffFPCR:]))
	b.add64(a64RegFpsr, binary.LittleEndian.Uint64(image[a64FPOffFPSR:]))
	return nil
}
