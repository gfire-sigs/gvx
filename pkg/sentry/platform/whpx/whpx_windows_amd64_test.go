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

//go:build windows && amd64

package whpx

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/arch"
)

var (
	// syscall
	guestSyscallCode = []byte{0x0F, 0x05}
	// jmp .
	guestLoopCode = []byte{0xEB, 0xFE}
	// movabs rax, [0x10000000]
	guestFaultCode = []byte{0x48, 0xA1, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}
)

func setGuestEntry(ac *arch.Context64, pc uintptr) {
	r := &ac.StateData().Regs
	r.Rip = uint64(pc)
	r.Rsp = 0x7FFF0000
	r.Rax = 39
	r.Eflags = 0x202
	r.Rcx, r.R11 = r.Rip, r.Eflags
}

// guestVectorProbeCode reads the CPUID bits and XCR0 that the guest sees:
// R8 = CPUID.1:ECX, R9 = CPUID.(7,0):EBX, R10 = XCR0[31:0].
var guestVectorProbeCode = bytes.Join([][]byte{
	{0xB8, 0x01, 0x00, 0x00, 0x00}, // mov eax, 1
	{0x0F, 0xA2},                   // cpuid
	{0x49, 0x89, 0xC8},             // mov r8, rcx
	{0xB8, 0x07, 0x00, 0x00, 0x00}, // mov eax, 7
	{0x31, 0xC9},                   // xor ecx, ecx
	{0x0F, 0xA2},                   // cpuid
	{0x49, 0x89, 0xD9},             // mov r9, rbx
	{0x31, 0xC9},                   // xor ecx, ecx
	{0x0F, 0x01, 0xD0},             // xgetbv
	{0x49, 0x89, 0xC2},             // mov r10, rax
	{0x0F, 0x05},                   // syscall
}, nil)

// guestYMMCode fills YMM0 with ones, stops at a system call, and then moves
// the upper half of YMM0 into RAX before a second system call.
var guestYMMCode = bytes.Join([][]byte{
	{0xC5, 0xFC, 0xC2, 0xC0, 0x00},       // vcmpeqps ymm0, ymm0, ymm0
	{0x0F, 0x05},                         // syscall
	{0xC4, 0xE3, 0x7D, 0x19, 0xC1, 0x01}, // vextractf128 xmm1, ymm0, 1
	{0x66, 0x48, 0x0F, 0x7E, 0xC8},       // movq rax, xmm1
	{0x0F, 0x05},                         // syscall
}, nil)

// guestZMMCode is guestYMMCode for the upper 256 bits of ZMM0.
var guestZMMCode = bytes.Join([][]byte{
	{0x62, 0xF3, 0x7D, 0x48, 0x25, 0xC0, 0xFF}, // vpternlogd zmm0, zmm0, zmm0, 0xff
	{0x0F, 0x05}, // syscall
	{0x62, 0xF3, 0xFD, 0x48, 0x3B, 0xC1, 0x01}, // vextracti64x4 ymm1, zmm0, 1
	{0xC4, 0xE3, 0x7D, 0x39, 0xC9, 0x01},       // vextracti128 xmm1, ymm1, 1
	{0x66, 0x48, 0x0F, 0x7E, 0xC8},             // movq rax, xmm1
	{0x0F, 0x05},                               // syscall
}, nil)

func TestRealGuestCPUIDMatchesXCR0(t *testing.T) {
	p := newRealPlatform(t)
	c, mm, ac := realGuest(t, p, guestVectorProbeCode)
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	r := &ac.StateData().Regs
	leaf1, leaf7, xcr0 := uint32(r.R8), uint32(r.R9), r.R10&0xFFFF_FFFF
	t.Logf("CPUID.1:ECX=%#x CPUID.7:EBX=%#x XCR0=%#x ProcessorXsaveFeatures=%#x", leaf1, leaf7, xcr0, p.info.xsaveFeatures)
	if xcr0 != p.vec.xcr0 {
		t.Errorf("guest XCR0 = %#x, want the selected %#x", xcr0, p.vec.xcr0)
	}
	const (
		osxsave = 1 << 27
		avx     = 1 << 28
		avx2    = 1 << 5
		avx512f = 1 << 16
		mpx     = 1 << 14
	)
	if leaf1&osxsave == 0 {
		t.Error("CPUID reports OSXSAVE clear")
	}
	if (leaf1&avx != 0) != (xcr0&xcr0AVX != 0) {
		t.Errorf("CPUID AVX is %v, XCR0 AVX is %v", leaf1&avx != 0, xcr0&xcr0AVX != 0)
	}
	if leaf7&avx2 != 0 && xcr0&xcr0AVX == 0 {
		t.Error("CPUID reports AVX2, and XCR0 does not enable the AVX state")
	}
	if (leaf7&avx512f != 0) != (xcr0&xcr0AVX512 == xcr0AVX512) {
		t.Errorf("CPUID AVX512F is %v, XCR0 AVX-512 state is %#x", leaf7&avx512f != 0, xcr0&xcr0AVX512)
	}
	if leaf7&mpx != 0 {
		t.Error("CPUID reports MPX, whose state the platform does not save")
	}
}

// runUpperHalf runs code that sets a vector register, moves the state out of
// the processor between its two system calls, and returns RAX of the end.
func runUpperHalf(t *testing.T, p *Platform, code []byte) uint64 {
	t.Helper()
	limitVPs(p, 1)
	c, mm, ac := realGuest(t, p, code)
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		t.Fatalf("first Switch returned %v, %v", sig, err)
	}
	// Signal delivery and ptrace pull the state into the Sentry and push it
	// back.
	if err := c.PullFullState(nil, ac); err != nil {
		t.Fatalf("PullFullState: %v", err)
	}
	c.FullStateChanged()
	// A second Context takes the only processor, so the state of c moves to
	// its saved buffer and back.
	other, otherMM, otherAC := realGuest(t, p, guestSyscallCode)
	if sig, _, err := other.Switch(nil, otherMM, otherAC, -1); err != nil || sig != nil {
		t.Fatalf("Switch of the second Context returned %v, %v", sig, err)
	}
	if sig, _, err := c.Switch(nil, mm, ac, -1); err != nil || sig != nil {
		t.Fatalf("second Switch returned %v, %v", sig, err)
	}
	return ac.StateData().Regs.Rax
}

func TestRealYMMSurvivesTheSentryAndProcessorSharing(t *testing.T) {
	p := newRealPlatform(t)
	if p.vec.xcr0&xcr0AVX == 0 {
		t.Skipf("the guest XCR0 %#x has no AVX state", p.vec.xcr0)
	}
	if got := runUpperHalf(t, p, guestYMMCode); got != ^uint64(0) {
		t.Errorf("upper half of YMM0 = %#x, want all ones", got)
	}
}

func TestRealZMMSurvivesTheSentryAndProcessorSharing(t *testing.T) {
	p := newRealPlatform(t)
	if p.vec.xcr0&xcr0AVX512 != xcr0AVX512 {
		t.Skipf("the guest XCR0 %#x has no AVX-512 state", p.vec.xcr0)
	}
	if got := runUpperHalf(t, p, guestZMMCode); got != ^uint64(0) {
		t.Errorf("upper 256 bits of ZMM0 = %#x, want all ones", got)
	}
}

func checkSyscallExit(t *testing.T, ac *arch.Context64) {
	t.Helper()
	r := &ac.StateData().Regs
	if r.Rax != 39 || r.Orig_rax != 39 || r.Rip != guestCodeAddr+2 || r.Rcx != guestCodeAddr+2 {
		t.Errorf("after SYSCALL: rax=%d orig=%d rip=%#x rcx=%#x", r.Rax, r.Orig_rax, r.Rip, r.Rcx)
	}
}
