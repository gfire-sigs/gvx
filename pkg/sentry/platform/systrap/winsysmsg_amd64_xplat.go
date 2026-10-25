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

//go:build (darwin || windows) && amd64

package systrap

import (
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// winRegs is the register block of an amd64 winSysmsg. The order of the
// general-purpose registers is the order of the CONTEXT record. FsBase holds
// the guest FS base, which the stub loads with WRFSBASE before it returns.
type winRegs struct {
	Rax, Rcx, Rdx, Rbx, Rsp, Rbp, Rsi, Rdi uint64
	R8, R9, R10, R11, R12, R13, R14, R15   uint64
	Rflags                                 uint64
	FsBase                                 uint64
}

// winSysmsg is the shared page of one guest thread.
type winSysmsg struct {
	winSysmsgHeader
	Regs winRegs
	_    [winOffXsave - winOffFsBase - 8]byte
	// Xsave holds the vector state of the trapped guest in the standard XSAVE
	// format. A call into ntdll can clobber the volatile vector registers on
	// Windows, so the spill routine saves them before its first call and loads
	// them again on every resume.
	Xsave [winXsaveSize]byte
}

// Offsets of the registers in the winSysmsg. A register number is the number
// that an instruction encodes: RAX 0, RCX 1, RDX 2, RBX 3, RSP 4, RBP 5, RSI 6,
// RDI 7, R8 to R15 8 to 15.
const (
	winOffRegBase = winOffRegs
	winOffRflags  = winOffRegs + 16*8
	winOffFsBase  = winOffRflags + 8

	// winOffXsave is the offset of the XSAVE area of the guest vector state.
	// XSAVE and XRSTOR fault on an address that is not 64-byte aligned, and
	// the shared page is page aligned.
	winOffXsave = 0x100
	// winXsaveMask names the components that the spill routine saves: x87,
	// SSE, AVX, and the three AVX-512 components. The processor ignores the
	// bits that XCR0 does not enable.
	winXsaveMask = winXsaveLegacy | 1<<2 | 1<<5 | 1<<6 | 1<<7
	// winXsaveLegacy names the x87 and SSE components, which every image holds.
	winXsaveLegacy = 0x3
	// winXsaveSize is the size of the standard XSAVE image of those components.
	winXsaveSize = 1664 + 1024
)

// winRegOffset returns the offset of general-purpose register n.
func winRegOffset(n int) int { return winOffRegBase + 8*n }

var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs)-winOffRegs]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rax)-0]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rsp)-4*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.R15)-15*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.Rflags)-16*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Regs.FsBase)-17*8]
var _ = [1]struct{}{}[unsafe.Offsetof(winSysmsg{}.Xsave)-winOffXsave]
var _ = [1]struct{}{}[unsafe.Sizeof(winSysmsg{})-(winOffXsave+winXsaveSize)]
var _ = [1]struct{}{}[winOffXsave%64]

const (
	// winSiteLen is the length of the SYSCALL instruction. Its return address
	// is the address of the site plus this length.
	winSiteLen = 2
	// winSlotSize is the size of one trampoline slot. The slot holds the entry
	// code, the relocated instructions, and the jump back.
	winSlotSize = 64
)

// winTrap describes one trap of a thread, as the Sentry decoded it.
type winTrap struct {
	// site is the address of the patched SYSCALL instruction.
	site uint64
	// ret is the address after the SYSCALL, as the hardware leaves it in RCX.
	ret uint64
}

// loadFrom copies the registers of ac into the block.
func (r *winRegs) loadFrom(ac *arch.Context64) {
	g := &ac.StateData().Regs
	r.Rax, r.Rcx, r.Rdx, r.Rbx, r.Rsp, r.Rbp, r.Rsi, r.Rdi = g.Rax, g.Rcx, g.Rdx, g.Rbx, g.Rsp, g.Rbp, g.Rsi, g.Rdi
	r.R8, r.R9, r.R10, r.R11, r.R12, r.R13, r.R14, r.R15 = g.R8, g.R9, g.R10, g.R11, g.R12, g.R13, g.R14, g.R15
	r.Rflags = g.Eflags
	r.FsBase = g.Fs_base
}

// storeTo copies the block into ac the way a SYSCALL leaves the registers: RCX
// holds the return address and R11 holds the flags.
func (r *winRegs) storeTo(ac *arch.Context64, ret uint64) {
	g := &ac.StateData().Regs
	g.Rax, g.Rdx, g.Rbx, g.Rsp, g.Rbp, g.Rsi, g.Rdi = r.Rax, r.Rdx, r.Rbx, r.Rsp, r.Rbp, r.Rsi, r.Rdi
	g.R8, g.R9, g.R10, g.R12, g.R13, g.R14, g.R15 = r.R8, r.R9, r.R10, r.R12, r.R13, r.R14, r.R15
	g.Eflags = r.Rflags
	g.Rip = ret
	g.Rcx = ret
	g.R11 = r.Rflags
	g.Orig_rax = r.Rax
}

// resumeState returns the state that the Sentry publishes for ac after a trap.
// The slot tail runs the relocated instructions and then jumps to the address
// after them, so a resume at another pc uses the cold path.
func (t winTrap) resumeState(ac *arch.Context64) uint32 {
	if ac.StateData().Regs.Rip == t.ret {
		return winStateRunHot
	}
	return winStateRunCold
}

// winSiteReturn returns the address where the guest continues after the site.
func winSiteReturn(site uint64) uint64 { return site + winSiteLen }

// loadVector builds the XSAVE image of the vector state of ac in the sysmsg.
// The spill routine loads the image with XRSTOR on the next resume.
func (m *winSysmsg) loadVector(ac *arch.Context64, enabled uint64) {
	m.loadXsave(*ac.FloatingPointData(), enabled)
}

// loadXsave builds the XSAVE image of the Linux XSAVE image fp in the sysmsg.
// Only the components in enabled can be live, because XRSTOR faults on an
// XSTATE_BV bit that XCR0 does not enable. x87 and SSE are always part of the
// image.
func (m *winSysmsg) loadXsave(fp []byte, enabled uint64) {
	clear(m.Xsave[:])
	copy(m.Xsave[:xsaveHeaderOffset], fp)
	loaded := loadXStateComponents(fp, enabled, func(comp xstateComponent) []byte {
		return m.Xsave[comp.offset : comp.offset+comp.size]
	})
	var bv uint64
	if len(fp) >= xsaveHeaderOffset+8 {
		bv = binary.LittleEndian.Uint64(fp[xsaveHeaderOffset:]) & winXsaveLegacy
	}
	bv |= winXsaveLegacy | loaded
	// XCOMP_BV and the reserved bytes of the header stay zero, which selects
	// the standard format.
	binary.LittleEndian.PutUint64(m.Xsave[xsaveHeaderOffset:], bv)
}

// storeVector copies the XSAVE image that the spill routine saved into the
// vector state of ac.
func (m *winSysmsg) storeVector(ac *arch.Context64) { m.storeXsave(*ac.FloatingPointData()) }

// storeXsave copies the saved XSAVE image into the Linux XSAVE image fp. A
// component that the saved image marks as initial becomes zeros, and its
// XSTATE_BV bit becomes clear.
func (m *winSysmsg) storeXsave(fp []byte) {
	copy(fp[:min(len(fp), xsaveHeaderOffset)], m.Xsave[:xsaveHeaderOffset])
	if len(fp) < xsaveHeaderOffset+8 {
		return
	}
	have := binary.LittleEndian.Uint64(m.Xsave[xsaveHeaderOffset:])
	storeXStateComponents(fp, ^uint64(0), have, func(comp xstateComponent) []byte {
		return m.Xsave[comp.offset : comp.offset+comp.size]
	})
}
