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
	"bytes"
	"encoding/binary"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

func newTrapContext() *arch.Context64 {
	ac := arch.New(arch.Host)
	r := &ac.StateData().Regs
	r.Rax, r.Rcx, r.Rdx, r.Rbx = 0xA0, 0xA1, 0xA2, 0xA3
	r.Rsp, r.Rbp, r.Rsi, r.Rdi = 0x7000_0000_1000, 0xA5, 0xA6, 0xA7
	r.R8, r.R9, r.R10, r.R11 = 0xB8, 0xB9, 0xBA, 0xBB
	r.R12, r.R13, r.R14, r.R15 = 0xBC, 0xBD, 0xBE, 0xBF
	r.Eflags = 0x246
	r.Rip = 0x5555_0000_0102
	r.Fs_base = 0x7000_0000_2000
	return ac
}

func TestWinRegsFollowTheSyscallInstruction(t *testing.T) {
	src := newTrapContext()
	var r winRegs
	r.loadFrom(src)
	if r.FsBase != src.StateData().Regs.Fs_base {
		t.Errorf("the block holds FS base %#x, want %#x", r.FsBase, src.StateData().Regs.Fs_base)
	}
	if r.GsBase != 0 || r.GsMemBase != winNonCanonGSBase {
		t.Errorf("zero GS base loaded GsBase=%#x GsMemBase=%#x, want 0 and %#x", r.GsBase, r.GsMemBase, winNonCanonGSBase)
	}
	src.StateData().Regs.Gs_base = 0x7000_0000_3000
	r.loadTLSFrom(src)
	if r.GsBase != 0x7000_0000_3000 || r.GsMemBase != 0x7000_0000_3000 {
		t.Errorf("non-zero GS base loaded GsBase=%#x GsMemBase=%#x", r.GsBase, r.GsMemBase)
	}

	dst := arch.New(arch.Host)
	dst.StateData().Regs.Fs_base = 0x1234
	const ret = 0x5555_0000_0102
	r.storeTo(dst, ret)

	want, got := &src.StateData().Regs, &dst.StateData().Regs
	// The hardware leaves the return address in RCX and the flags in R11. The
	// slot clobbers both registers, so storeTo sets them as the instruction does.
	if got.Rcx != ret || got.R11 != want.Eflags || got.Rip != ret {
		t.Errorf("rcx %#x, r11 %#x, rip %#x; want %#x, %#x, %#x", got.Rcx, got.R11, got.Rip, uint64(ret), want.Eflags, uint64(ret))
	}
	for name, pair := range map[string][2]uint64{
		"rax": {got.Rax, want.Rax}, "rdx": {got.Rdx, want.Rdx}, "rbx": {got.Rbx, want.Rbx},
		"rsp": {got.Rsp, want.Rsp}, "rbp": {got.Rbp, want.Rbp}, "rsi": {got.Rsi, want.Rsi}, "rdi": {got.Rdi, want.Rdi},
		"r8": {got.R8, want.R8}, "r9": {got.R9, want.R9}, "r10": {got.R10, want.R10},
		"r12": {got.R12, want.R12}, "r13": {got.R13, want.R13}, "r14": {got.R14, want.R14}, "r15": {got.R15, want.R15},
		"eflags": {got.Eflags, want.Eflags},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s = %#x after the round trip, want %#x", name, pair[0], pair[1])
		}
	}
	if got.Orig_rax != want.Rax {
		t.Errorf("Orig_rax = %#x, want rax %#x", got.Orig_rax, want.Rax)
	}
	if got.Fs_base != 0x1234 {
		t.Errorf("storeTo changed the FS base to %#x. The Sentry owns it.", got.Fs_base)
	}
}

func TestWinTrapResumesHotOnlyAtTheReturnAddress(t *testing.T) {
	ac := newTrapContext()
	regs := &ac.StateData().Regs
	trap := winTrap{site: regs.Rip - winSiteLen, ret: regs.Rip}
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Fatalf("an unchanged context resumes with state %d, want RunHot", got)
	}
	// Any register can change on amd64, because the stub loads all of them.
	regs.Rax, regs.Rsp, regs.R15 = 1, 0x7000_0000_0800, 2
	if got := trap.resumeState(ac); got != winStateRunHot {
		t.Errorf("changed registers resume with state %d, want RunHot", got)
	}
	regs.Rip += 1
	if got := trap.resumeState(ac); got != winStateRunCold {
		t.Errorf("a changed program counter resumes with state %d, want RunCold", got)
	}
}

func TestWinSiteReturnIsBehindTheSyscall(t *testing.T) {
	if got := winSiteReturn(0x1000); got != 0x1002 {
		t.Fatalf("the return address of a site at 0x1000 is %#x, want 0x1002", got)
	}
}

// extraTail is the number of bytes behind the saved components in the Linux
// XSAVE image of the tests. A real image carries more components than the
// routine saves, such as the protection key register.
const extraTail = 64

func xsaveBV(img []byte) uint64 { return binary.LittleEndian.Uint64(img[xsaveHeaderOffset:]) }

func TestWinSysmsgXsaveRoundTripsEveryComponent(t *testing.T) {
	src := vectorImage(5)
	src = append(src, bytes.Repeat([]byte{0x77}, extraTail)...)
	var m winSysmsg
	m.loadXsave(src, winXsaveMask)
	if !sameVector(m.Xsave[:], src) {
		t.Fatal("loadXsave changed a component on the way into the sysmsg")
	}

	dst := bytes.Repeat([]byte{0xAB}, len(src))
	binary.LittleEndian.PutUint64(dst[xsaveHeaderOffset:], 0)
	m.storeXsave(dst)
	if !bytes.Equal(dst[:xsaveHeaderOffset], src[:xsaveHeaderOffset]) {
		t.Error("storeXsave changed the legacy region on the way out of the sysmsg")
	}
	for _, comp := range xstateComponents {
		if !bytes.Equal(dst[comp.offset:comp.offset+comp.size], src[comp.offset:comp.offset+comp.size]) {
			t.Errorf("storeXsave changed component %d on the way out of the sysmsg", comp.id)
		}
	}
	// storeXsave sets the bits of the extended components and leaves the x87
	// and SSE bits to the Sentry, as the Windows context path does.
	if got, want := xsaveBV(dst), uint64(winXsaveMask&^winXsaveLegacy); got != want {
		t.Errorf("XSTATE_BV = %#x after storeXsave, want %#x", got, want)
	}
	for i := winXsaveSize; i < len(dst); i++ {
		if dst[i] != 0xAB {
			t.Fatalf("storeXsave wrote byte %d behind the saved components", i)
		}
	}
}

func TestWinSysmsgXsaveLoadsOnlyTheEnabledComponents(t *testing.T) {
	src := vectorImage(5)
	const avxOnly = 1 << 2
	var m winSysmsg
	m.loadXsave(src, avxOnly)
	if got, want := xsaveBV(m.Xsave[:]), uint64(winXsaveLegacy|avxOnly); got != want {
		t.Fatalf("XSTATE_BV = %#x, want %#x: XRSTOR faults on a bit that XCR0 does not enable", got, want)
	}
	for _, comp := range xstateComponents {
		loaded := !bytes.Equal(m.Xsave[comp.offset:comp.offset+comp.size], make([]byte, comp.size))
		if want := comp.id == 2; loaded != want {
			t.Errorf("component %d loaded = %v, want %v", comp.id, loaded, want)
		}
	}
}

func TestWinSysmsgXsaveHeaderIsInTheStandardFormat(t *testing.T) {
	src := vectorImage(5)
	// A guest can write any bytes into the header of its signal frame.
	for i := xsaveHeaderOffset + 8; i < xsaveHeaderOffset+64; i++ {
		src[i] = 0xFF
	}
	var m winSysmsg
	m.loadXsave(src, winXsaveMask)
	for i := xsaveHeaderOffset + 8; i < xsaveHeaderOffset+64; i++ {
		if m.Xsave[i] != 0 {
			t.Fatalf("header byte %d = %#x, want zero: XCOMP_BV and the reserved bytes select the standard format", i, m.Xsave[i])
		}
	}
}

func TestWinSysmsgXsaveAlwaysLoadsX87AndSSE(t *testing.T) {
	src := vectorImage(5)
	binary.LittleEndian.PutUint64(src[xsaveHeaderOffset:], 0)
	var m winSysmsg
	m.loadXsave(src, winXsaveMask)
	if got := xsaveBV(m.Xsave[:]); got != winXsaveLegacy {
		t.Fatalf("XSTATE_BV = %#x, want %#x: the legacy region always carries the registers", got, uint64(winXsaveLegacy))
	}
	if !bytes.Equal(m.Xsave[:xsaveHeaderOffset], src[:xsaveHeaderOffset]) {
		t.Error("the legacy region differs from the Sentry image")
	}
}

func TestWinSysmsgXsaveSurvivesAShortImage(t *testing.T) {
	for _, size := range []int{0, 100, xsaveHeaderOffset, xsaveHeaderOffset + 8, 1000} {
		src := vectorImage(5)[:size]
		var m winSysmsg
		m.loadXsave(src, winXsaveMask)
		if size >= xsaveHeaderOffset+8 && xsaveBV(m.Xsave[:])&^uint64(winXsaveLegacy|1<<2) != 0 {
			t.Errorf("size %d: XSTATE_BV %#x names a component that the image cannot hold", size, xsaveBV(m.Xsave[:]))
		}
		dst := make([]byte, size)
		m.storeXsave(dst)
	}
}

func TestWinSysmsgXsaveStoreClearsInitialComponents(t *testing.T) {
	var m winSysmsg
	m.loadXsave(vectorImage(5), winXsaveMask)
	// The processor reports an initial component by a clear XSTATE_BV bit.
	const opmask = 1 << 5
	binary.LittleEndian.PutUint64(m.Xsave[xsaveHeaderOffset:], winXsaveMask&^opmask)

	dst := vectorImage(9)
	m.storeXsave(dst)
	if got := xsaveBV(dst); got != winXsaveMask&^opmask {
		t.Errorf("XSTATE_BV = %#x, want %#x", got, uint64(winXsaveMask&^opmask))
	}
	if !bytes.Equal(dst[1088:1088+64], make([]byte, 64)) {
		t.Error("an initial component kept the old register contents in the Sentry image")
	}
}

func TestWinSysmsgLoadVectorMarksTheImageDirty(t *testing.T) {
	var m winSysmsg
	if m.FPDirty != 0 {
		t.Fatal("a new sysmsg is dirty")
	}
	m.loadVector(newTrapContext(), winXsaveMask)
	if m.FPDirty != 1 {
		t.Errorf("FPDirty = %d after the Sentry wrote the image, want 1", m.FPDirty)
	}
}
