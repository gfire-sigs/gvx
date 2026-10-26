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

	"golang.org/x/arch/x86/x86asm"
)

func TestBuildSpillDecodesEveryInstruction(t *testing.T) {
	sc, err := buildSpill()
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.code) > winCodeSize-winSpillOffset {
		t.Fatalf("spill routine has %d bytes, the code pages leave %d", len(sc.code), winCodeSize-winSpillOffset)
	}
	for off := 0; off < len(sc.code); {
		inst, err := x86asm.Decode(sc.code[off:], 64)
		if err != nil {
			t.Fatalf("offset %#x does not decode: %v", off, err)
		}
		off += inst.Len
	}
	if sc.code[sc.coldTrap] != 0xCC || sc.coldTrap != len(sc.code)-1 {
		t.Fatalf("the cold trap offset %d does not name the last byte, INT3", sc.coldTrap)
	}
}

func TestX86EncodersDecodeAsIntended(t *testing.T) {
	enc := func(f func(a *x86Asm)) []byte {
		var a x86Asm
		f(&a)
		return a.b
	}
	for _, c := range []struct {
		name string
		code []byte
		want string
	}{
		{"load r15", enc(func(a *x86Asm) { a.movLoad(x86RCX, x86R15, 0x10) }), "mov rcx, qword ptr [r15+0x10]"},
		{"store high reg", enc(func(a *x86Asm) { a.movStore(x86RAX, 0x88, x86R9) }), "mov qword ptr [rax+0x88], r9"},
		{"load 32", enc(func(a *x86Asm) { a.movLoad32(x86RAX, x86R15, 0) }), "mov eax, dword ptr [r15]"},
		{"store imm", enc(func(a *x86Asm) { a.movStoreImm32(x86R15, winOffStubWaiter, 1) }), "mov dword ptr [r15+0x8], 0x1"},
		{"cmp imm8", enc(func(a *x86Asm) { a.cmpMemImm8(x86R15, winOffSentryWaiter, 0) }), "cmp dword ptr [r15+0x4], 0x0"},
		{"push mem", enc(func(a *x86Asm) { a.pushMem(x86R15, winOffRflags) }), "push qword ptr [r15+0xc8]"},
		{"pop mem", enc(func(a *x86Asm) { a.popMem(x86R15, winOffRflags) }), "pop qword ptr [r15+0xc8]"},
		{"call mem", enc(func(a *x86Asm) { a.callMem(x86R15, winOffNtWait) }), "call qword ptr [r15+0x28]"},
		{"lea rsp", enc(func(a *x86Asm) { a.leaBase(x86RSP, x86R15, winStubStackTop) }), "lea rsp, ptr [r15+0x1fc0]"},
		{"load gs", enc(func(a *x86Asm) { a.movLoadGS(x86RBX, winTEBScratchA) }), "mov rbx, qword ptr gs:[0x18]"},
		{"store gs", enc(func(a *x86Asm) { a.movStoreGS(winTEBScratchB, x86RAX) }), "mov qword ptr gs:[0x20], rax"},
		{"load gs high", enc(func(a *x86Asm) { a.movLoadGS(x86R10, winTEBSysmsg) }), "mov r10, qword ptr gs:[0x28]"},
		{"jmp gs", enc(func(a *x86Asm) { a.jmpGS(winTEBScratchB) }), "jmp qword ptr gs:[0x20]"},
		{"mov r15, rax", enc(func(a *x86Asm) { a.movRegReg(x86R15, x86RAX) }), "mov r15, rax"},
		{"mov rax, r15", enc(func(a *x86Asm) { a.movRegReg(x86RAX, x86R15) }), "mov rax, r15"},
		{"xsave64", enc(func(a *x86Asm) { a.xsave64(x86R15, winOffXsave) }), "xsave64 ptr [r15+0x100]"},
		{"xrstor64", enc(func(a *x86Asm) { a.xrstor64(x86R15, winOffXsave) }), "xrstor64 ptr [r15+0x100]"},
	} {
		inst, err := x86asm.Decode(c.code, 64)
		if err != nil {
			t.Errorf("%s: does not decode: %v", c.name, err)
			continue
		}
		if inst.Len != len(c.code) {
			t.Errorf("%s: instruction has %d bytes, the encoder wrote %d", c.name, inst.Len, len(c.code))
		}
		if got := x86asm.IntelSyntax(inst, 0, nil); got != c.want {
			t.Errorf("%s: decodes as %q, want %q", c.name, got, c.want)
		}
	}
}

func TestX86AsmResolvesJumps(t *testing.T) {
	var a x86Asm
	a.label("top")
	a.emit(0x90)
	a.jcc8(x86CCNE, "top")
	a.jcc32(x86CCE, "end")
	a.emit(0x90)
	a.label("end")
	code, err := a.finish()
	if err != nil {
		t.Fatal(err)
	}
	if code[2] != 0xFD { // jne back to the nop: 0 - (1+2)... displacement -3
		t.Fatalf("short jump displacement = %#x, want 0xfd", code[2])
	}
	if got := binary.LittleEndian.Uint32(code[5:]); got != 1 {
		t.Fatalf("near jump displacement = %d, want 1", int32(got))
	}
	var bad x86Asm
	bad.jcc8(x86CCE, "nowhere")
	if _, err := bad.finish(); err == nil {
		t.Fatal("finish accepted a jump to an undefined label")
	}
}

// The addresses of the rig are arbitrary but distinct. The code buffer holds
// the slot at its start and the spill routine at rigSpillOff.
const (
	rigCodeBase = 0x7ff0_1100_0000
	rigSpillOff = 0x100
	rigSite     = 0x7ff0_1000_0100
	rigSysm     = 0x7ff0_0100_0000
	rigTEB      = 0x7ff0_0200_0000
	rigStackTop = 0x7ff0_0300_1000
	rigGuestRSP = rigStackTop

	rigGuestEv = 0xE1
	rigHostEv  = 0xE2
	rigSetEv   = 0xF100
	rigWaitFn  = 0xF200

	rigFlags = 0x247
)

type spillRig struct {
	m       *x86Machine
	sc      winSpillCode
	guest   [16]uint64
	reloc   []byte
	tail    uint64
	callLog []string
	// onCallee acts as the kernel during a call.
	onCallee func(m *x86Machine, target uint64)
}

var rigNop3 = []byte{0x0F, 0x1F, 0x00} // nop dword ptr [rax]

func newSpillRig(t *testing.T, reloc []byte) *spillRig {
	t.Helper()
	sc, err := buildSpill()
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, rigSpillOff+len(sc.code))
	if err := encodeWinSlot(code, rigCodeBase, rigSite, rigCodeBase+rigSpillOff, reloc); err != nil {
		t.Fatal(err)
	}
	copy(code[rigSpillOff:], sc.code)
	m := newX86Machine(code, rigCodeBase)
	r := &spillRig{m: m, sc: sc, reloc: reloc, tail: rigCodeBase + winSlotTailOffset}
	for i := range r.guest {
		r.guest[i] = 0x1000_0000_0000_0000 + uint64(i)*0x0101_0101
	}
	r.guest[x86RSP] = rigGuestRSP
	copy(m.r[:], r.guest[:])
	m.rflags = rigFlags
	m.gsBase = rigTEB
	copy(m.vec[:], vectorImage(rigVectorSeed))
	m.put64(rigTEB+winTEBSysmsg, rigSysm)
	m.put64(rigSysm+winOffGuestEvent, rigGuestEv)
	m.put64(rigSysm+winOffHostEvent, rigHostEv)
	m.put64(rigSysm+winOffNtSetEvent, rigSetEv)
	m.put64(rigSysm+winOffNtWait, rigWaitFn)
	// The red zone below the guest stack pointer holds live data.
	for i := uint64(1); i <= 128; i++ {
		m.mem[rigGuestRSP-i] = byte(0xA0 + i)
	}
	m.onCall = func(m *x86Machine, target uint64) {
		top := uint64(rigSysm + winThreadMapSize)
		if m.r[x86RSP]+32 > top || m.r[x86RSP] <= top-winStubStackSize {
			t.Errorf("call with rsp %#x outside the stub stack or without shadow space", m.r[x86RSP])
		}
		switch target {
		case rigSetEv:
			r.callLog = append(r.callLog, "set")
			if m.r[x86RCX] != rigGuestEv || m.r[x86RDX] != 0 {
				t.Errorf("NtSetEvent got %#x, %#x, want handle %#x, NULL", m.r[x86RCX], m.r[x86RDX], uint64(rigGuestEv))
			}
		case rigWaitFn:
			r.callLog = append(r.callLog, "wait")
			if m.r[x86RCX] != rigHostEv || m.r[x86RDX] != 0 || m.r[x86R8] != 0 {
				t.Errorf("NtWaitForSingleObject got %#x, %#x, %#x, want handle %#x, FALSE, NULL", m.r[x86RCX], m.r[x86RDX], m.r[x86R8], uint64(rigHostEv))
			}
		default:
			t.Errorf("call to %#x", target)
		}
		// The callee may change every volatile register.
		for _, n := range []int{x86RAX, x86RCX, x86RDX, x86R8, x86R9, x86R10, x86R11} {
			m.r[n] = 0xDEAD_0000 + uint64(n)
		}
		// The callee may change the volatile vector registers.
		for _, rg := range volatileVector {
			for i := rg[0]; i < rg[1]; i++ {
				m.vec[i] = 0xEE
			}
		}
		if r.onCallee != nil {
			r.onCallee(m, target)
		}
	}
	return r
}

func (r *spillRig) state() uint32      { return r.m.get32(rigSysm + winOffState) }
func (r *spillRig) setState(s uint32)  { r.m.put32(rigSysm+winOffState, s) }
func (r *spillRig) stubWaiter() uint32 { return r.m.get32(rigSysm + winOffStubWaiter) }
func (r *spillRig) setSaved(n int, v uint64) {
	r.m.put64(rigSysm+uint64(winRegOffset(n)), v)
}
func (r *spillRig) saved(n int) uint64 { return r.m.get64(rigSysm + uint64(winRegOffset(n))) }

// checkSaved verifies the state that the routine stored for the Sentry.
func (r *spillRig) checkSaved(t *testing.T, except ...int) {
	t.Helper()
	skip := map[int]bool{}
	for _, n := range except {
		skip[n] = true
	}
	for n := range 16 {
		if !skip[n] && r.saved(n) != r.guest[n] {
			t.Errorf("saved register %d = %#x, want %#x", n, r.saved(n), r.guest[n])
		}
	}
	if got := r.m.get64(rigSysm + winOffRflags); got != rigFlags {
		t.Errorf("saved flags = %#x, want %#x", got, uint64(rigFlags))
	}
	if got := r.m.get64(rigSysm + winOffTail); got != r.tail {
		t.Errorf("saved tail = %#x, want %#x", got, r.tail)
	}
}

// checkHotExit verifies the return through the slot tail. The relocated
// instruction ran, and the jump back names the address behind it.
func (r *spillRig) checkHotExit(t *testing.T, want [16]uint64, wantFlags uint64) {
	t.Helper()
	m := r.m
	if m.exit.trap != 0 || m.exit.jump != rigSite+2+uint64(len(r.reloc)) {
		t.Fatalf("the code ended with trap %d, jump %#x; want a jump to %#x", m.exit.trap, m.exit.jump, rigSite+2+uint64(len(r.reloc)))
	}
	for n := range 16 {
		if m.r[n] != want[n] {
			t.Errorf("register %d = %#x after the return, want %#x", n, m.r[n], want[n])
		}
	}
	if m.rflags != wantFlags {
		t.Errorf("flags = %#x after the return, want %#x", m.rflags, wantFlags)
	}
	for i := uint64(1); i <= 128; i++ {
		if m.mem[rigGuestRSP-i] != byte(0xA0+i) {
			t.Fatalf("the code changed the guest stack at rsp-%d", i)
		}
	}
}

func TestSpillSpinHit(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	m := r.m
	want := r.guest
	want[x86RAX] = 42
	const fs = 0x7ff0_0600_0000
	m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			t.Errorf("state while the stub polls = %d, want Trapped", r.state())
		}
		if m.pauses == 3 {
			r.checkSaved(t)
			r.setSaved(x86RAX, 42)
			m.put64(rigSysm+winOffFsBase, fs)
			r.setState(winStateRunHot)
		}
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if len(r.callLog) != 0 {
		t.Fatalf("a spin hit made calls %v", r.callLog)
	}
	if r.stubWaiter() != 0 {
		t.Fatal("the stub left StubWaiter set")
	}
	if m.fsBase != fs {
		t.Fatalf("the stub loaded the FS base %#x, want %#x", m.fsBase, uint64(fs))
	}
	r.checkHotExit(t, want, rigFlags)
}

func TestSpillRunsRelocatedInstructionAfterRestore(t *testing.T) {
	// mov rdx, r12
	r := newSpillRig(t, []byte{0x4C, 0x89, 0xE2})
	want := r.guest
	want[x86RDX] = r.guest[x86R12]
	r.m.onYield = func(m *x86Machine) { r.setState(winStateRunHot) }
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, want, rigFlags)
}

func TestSpillWakesSleepingSentry(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	r.m.put32(rigSysm+winOffSentryWaiter, 1)
	r.m.onYield = func(m *x86Machine) {
		if len(r.callLog) != 1 || r.callLog[0] != "set" {
			t.Errorf("calls before the first poll = %v, want one NtSetEvent", r.callLog)
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest, rigFlags)
}

func TestSpillSleepsWhenSpinExpires(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	m := r.m
	want := r.guest
	want[x86RAX] = 7
	r.onCallee = func(m *x86Machine, target uint64) {
		if target != rigWaitFn {
			return
		}
		if r.stubWaiter() != 1 {
			t.Error("the stub slept without StubWaiter")
		}
		if r.state() != winStateTrapped {
			t.Errorf("state at the wait = %d, want Trapped", r.state())
		}
		r.checkSaved(t)
		r.setSaved(x86RAX, 7)
		r.setState(winStateRunHot)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if m.pauses != winSpinStub {
		t.Errorf("the stub polled %d times, want %d", m.pauses, winSpinStub)
	}
	if len(r.callLog) != 1 || r.callLog[0] != "wait" {
		t.Fatalf("calls = %v, want one NtWaitForSingleObject", r.callLog)
	}
	if r.stubWaiter() != 0 {
		t.Error("the stub left StubWaiter set after it woke")
	}
	r.checkHotExit(t, want, rigFlags)
}

func TestSpillSkipsSleepWhenStateArrivesAfterFlag(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	// The second fence follows the store of StubWaiter. The Sentry publishes
	// the state right there, so the test after the fence must see it.
	r.m.onFence = func(m *x86Machine) {
		if m.fences == 2 {
			if r.stubWaiter() != 1 {
				t.Error("the second fence does not follow the StubWaiter store")
			}
			r.setState(winStateRunHot)
		}
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if len(r.callLog) != 0 {
		t.Fatalf("the stub called %v although the state had arrived", r.callLog)
	}
	if r.stubWaiter() != 0 {
		t.Error("the stub left StubWaiter set")
	}
	r.checkHotExit(t, r.guest, rigFlags)
}

func TestSpillSleepsAgainAfterStaleWake(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	waits := 0
	r.onCallee = func(m *x86Machine, target uint64) {
		if target != rigWaitFn {
			return
		}
		waits++
		if waits == 2 {
			r.setState(winStateRunHot)
		}
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if waits != 2 {
		t.Fatalf("the stub waited %d times, want 2: a wake without a state must sleep again", waits)
	}
	r.checkHotExit(t, r.guest, rigFlags)
}

func TestSpillHotReturnLoadsRegistersTheSentryChanged(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	want := r.guest
	want[x86RSP] = rigGuestRSP - 0x400
	want[x86RCX] = 0x1234
	want[x86R11] = 0x5678
	want[x86R15] = 0x9abc
	const newFlags = 0x202
	r.m.onYield = func(m *x86Machine) {
		r.setSaved(x86RSP, want[x86RSP])
		r.setSaved(x86RCX, want[x86RCX])
		r.setSaved(x86R11, want[x86R11])
		r.setSaved(x86R15, want[x86R15])
		m.put64(rigSysm+winOffRflags, newFlags)
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	// The red zone check of checkHotExit follows the old stack pointer, which
	// stays valid because the test left that memory in place.
	r.checkHotExit(t, want, newFlags)
}

func TestSpillColdReturnLoadsEveryRegisterAndTraps(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	m := r.m
	var want [16]uint64
	for n := range want {
		want[n] = 0x7000_0000 + uint64(n)
	}
	const newFlags = 0x286
	m.onYield = func(m *x86Machine) {
		for n, v := range want {
			r.setSaved(n, v)
		}
		m.put64(rigSysm+winOffRflags, newFlags)
		m.put64(rigSysm+winOffTarget, 0xCAFE)
		r.setState(winStateRunCold)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if m.exit.trap != 3 || m.pc != rigCodeBase+rigSpillOff+uint64(r.sc.coldTrap) {
		t.Fatalf("the code ended with trap %d at %#x, want trap 3 at %#x", m.exit.trap, m.pc, rigCodeBase+rigSpillOff+uint64(r.sc.coldTrap))
	}
	for n := range 16 {
		if m.r[n] != want[n] {
			t.Errorf("register %d = %#x at the trap, want %#x", n, m.r[n], want[n])
		}
	}
	if m.rflags != newFlags {
		t.Errorf("flags = %#x at the trap, want %#x", m.rflags, uint64(newFlags))
	}
	if m.fsBase != 0 {
		t.Errorf("a cold resume loaded the FS base %#x, the Sentry loads it", m.fsBase)
	}
}

func TestSpillColdReturnAfterSleep(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	r.onCallee = func(m *x86Machine, target uint64) {
		if target == rigWaitFn {
			r.setState(winStateRunCold)
		}
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if r.m.exit.trap != 3 {
		t.Fatalf("the code ended with trap %d, want 3", r.m.exit.trap)
	}
	for n := range 16 {
		if r.m.r[n] != r.guest[n] {
			t.Errorf("register %d = %#x at the trap, want %#x", n, r.m.r[n], r.guest[n])
		}
	}
}

func TestEncodeWinSlotBounds(t *testing.T) {
	buf := make([]byte, winSlotSize)
	if err := encodeWinSlot(buf, rigCodeBase, rigSite, 0x9000, []byte{0x90}); err == nil {
		t.Error("a slot with one relocated byte was accepted")
	}
	if err := encodeWinSlot(buf, rigCodeBase, rigSite, 0x9000, make([]byte, winMaxRelocated+1)); err == nil {
		t.Error("a slot with too many relocated bytes was accepted")
	}
	if err := encodeWinSlot(buf, rigCodeBase, rigSite, 0x9000, make([]byte, winMaxRelocated)); err != nil {
		t.Errorf("a slot with the most relocated bytes was rejected: %v", err)
	}
	if err := encodeWinSlot(buf, rigCodeBase, rigSite+2*winIslandReach32, 0x9000, rigNop3); err == nil {
		t.Error("a slot that cannot reach the site was accepted")
	}
	if winMaxRelocated < 2+15 {
		t.Errorf("the slot holds %d relocated bytes, a three-instruction plan can need 17", winMaxRelocated)
	}
}

// pageWith returns a page that holds code at off and int3 elsewhere.
func pageWith(off int, code ...byte) []byte {
	p := make([]byte, amd64PageSize)
	for i := range p {
		p[i] = 0xCC
	}
	copy(p[off:], code)
	return p
}

func TestPlanJmpPatch(t *testing.T) {
	sys := []byte{0x0F, 0x05}
	cat := func(parts ...[]byte) []byte {
		var out []byte
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	for _, c := range []struct {
		name string
		code []byte
		want []byte // relocated bytes, nil when the site stays a trap
	}{
		{"cmp rax, imm32 (glibc)", cat(sys, []byte{0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF, 0x73, 0x01}), []byte{0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF}},
		{"test rax, rax", cat(sys, []byte{0x48, 0x85, 0xC0, 0x90}), []byte{0x48, 0x85, 0xC0}},
		{"two short instructions", cat(sys, []byte{0x89, 0xC3, 0x48, 0x85, 0xC0}), []byte{0x89, 0xC3, 0x48, 0x85, 0xC0}},
		{"mov r12d, eax then nop", cat(sys, []byte{0x41, 0x89, 0xC4, 0x90}), []byte{0x41, 0x89, 0xC4}},
		{"ret follows the syscall", cat(sys, []byte{0xC3, 0x90, 0x90}), nil},
		{"short test then branch", cat(sys, []byte{0x85, 0xC0, 0x74, 0x02, 0x90}), nil},
		{"call behind the syscall", cat(sys, []byte{0xE8, 0x00, 0x00, 0x00, 0x00}), nil},
		{"rip-relative load", cat(sys, []byte{0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}), nil},
		{"second syscall", cat(sys, sys, []byte{0x90}), nil},
		{"fs-relative load", cat(sys, []byte{0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}), nil},
		{"undecodable bytes", cat(sys, []byte{0x06, 0x06, 0x06}), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			page := pageWith(0x100, c.code...)
			got, ok := planJmpPatch(nil, page, nil, 0x100)
			if (c.want != nil) != ok {
				t.Fatalf("planJmpPatch ok = %v, want %v", ok, c.want != nil)
			}
			if ok && string(got) != string(c.want) {
				t.Fatalf("relocated bytes = % x, want % x", got, c.want)
			}
		})
	}
}

func TestPlanJmpPatchNeedsTheWindowInThePage(t *testing.T) {
	code := []byte{0x0F, 0x05, 0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF}
	for _, c := range []struct {
		off int
		ok  bool
	}{
		{amd64PageSize - 8, true},
		{amd64PageSize - 7, false}, // The relocated instruction ends in the next page.
		{amd64PageSize - 4, false}, // The jump itself needs five bytes.
		{amd64PageSize - 2, false},
	} {
		page := pageWith(0, nil...)
		copy(page[c.off:], code)
		_, ok := planJmpPatch(nil, page, nil, c.off)
		if ok != c.ok {
			t.Errorf("site at %d: ok = %v, want %v", c.off, ok, c.ok)
		}
	}
}

func TestPlanJmpPatchRejectsBranchIntoOverwrittenBytes(t *testing.T) {
	sysCmp := []byte{0x0F, 0x05, 0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF, 0x90}
	for _, c := range []struct {
		name   string
		target int // offset that a short jump at 0xE0 targets
		ok     bool
	}{
		{"target is the syscall", 0x100, true},
		{"target is the byte after the syscall", 0x101, false},
		{"target is the instruction behind it", 0x102, false},
		{"target is the last overwritten byte", 0x104, false},
		{"target is the first byte after the jump", 0x105, true},
		{"target is far away", 0x140, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			page := pageWith(0x100, sysCmp...)
			// jmp short: the displacement counts from the end of the jump.
			page[0xE0], page[0xE1] = 0xEB, byte(int8(c.target-0xE2))
			_, ok := planJmpPatch(nil, page, nil, 0x100)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
		})
	}
}

func TestPlanJmpPatchSeesBranchFromNeighborPage(t *testing.T) {
	sysCmp := []byte{0x0F, 0x05, 0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF, 0x90}
	page := pageWith(0x10, sysCmp...)
	// A near jump at the end of the previous page lands on the instruction
	// behind the syscall. It starts 5 bytes before the page end.
	before := make([]byte, 15)
	for i := range before {
		before[i] = 0xCC
	}
	copy(before[10:], []byte{0xE9, 0x00, 0x00, 0x00, 0x00})
	disp := int32(0x10 + 2 - 0) // from the end of the jump, which is the page start
	binary.LittleEndian.PutUint32(before[11:], uint32(disp))
	if _, ok := planJmpPatch(before, page, nil, 0x10); ok {
		t.Fatal("planJmpPatch missed a branch from the previous page")
	}
	clean := make([]byte, 15)
	for i := range clean {
		clean[i] = 0xCC
	}
	if _, ok := planJmpPatch(clean, page, nil, 0x10); !ok {
		t.Fatal("planJmpPatch rejected a site without a branch into it")
	}
}

func TestPlanJmpPatchRejectsNoReturnSyscall(t *testing.T) {
	// In musl, __unmapself ends with `mov eax, 60; syscall` and __clone
	// starts directly at site+2 (`xor eax, eax; mov al, 56`). A JMP patch on
	// the exit syscall would overwrite the entry of __clone.
	after := []byte{0x31, 0xC0, 0xB0, 0x38, 0x90}
	for _, tc := range []struct {
		name  string
		setup []byte
		want  bool
	}{
		{"mov eax, 60 (exit)", []byte{0xB8, 60, 0, 0, 0}, false},
		{"mov eax, 231 (exit_group)", []byte{0xB8, 231, 0, 0, 0}, false},
		{"mov rax, 15 (rt_sigreturn)", []byte{0x48, 0xC7, 0xC0, 15, 0, 0, 0}, false},
		{"mov al, 60 (exit)", []byte{0xB0, 60}, false},
		{"mov eax, 39 (getpid)", []byte{0xB8, 39, 0, 0, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := pageWith(0x100-len(tc.setup), tc.setup...)
			copy(page[0x100:], []byte{0x0F, 0x05})
			copy(page[0x102:], after)
			if _, ok := planJmpPatch(nil, page, nil, 0x100); ok != tc.want {
				t.Fatalf("planJmpPatch ok = %v, want %v", ok, tc.want)
			}
		})
	}
}

func TestPatchJmpEncodesRelativeJump(t *testing.T) {
	page := pageWith(0x40, 0x0F, 0x05, 0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF)
	const siteVA, slotVA = 0x7ff0_1000_0040, 0x7ff0_1100_0000
	if err := patchJmp(page, 0x40, siteVA, slotVA); err != nil {
		t.Fatal(err)
	}
	inst, err := x86asm.Decode(page[0x40:], 64)
	if err != nil || inst.Op != x86asm.JMP || inst.Len != winJmpLen {
		t.Fatalf("patched bytes % x decode as %v, %v", page[0x40:0x45], inst, err)
	}
	if target := siteVA + winJmpLen + uint64(int64(inst.Args[0].(x86asm.Rel))); target != slotVA {
		t.Fatalf("the jump targets %#x, want the slot %#x", target, uint64(slotVA))
	}
	if err := patchJmp(page, amd64PageSize-4, siteVA, slotVA); err == nil {
		t.Error("patchJmp wrote a jump that crosses the page end")
	}
	if err := patchJmp(page, 0x40, siteVA, siteVA+2*winIslandReach32); err == nil {
		t.Error("patchJmp wrote a jump that cannot reach the slot")
	}
}

// rigVectorSeed seeds the vector registers that the guest holds at the trap.
const rigVectorSeed = 1

// volatileVector lists the parts of the XSAVE image that a call into ntdll can
// clobber: XMM0 to XMM5 and the upper halves of YMM0 to YMM5.
var volatileVector = [][2]int{{160, 160 + 6*16}, {576, 576 + 6*16}}

// vectorImage returns an XSAVE image that a pattern of seed fills. XSTATE_BV
// marks every component as live.
func vectorImage(seed byte) []byte {
	img := make([]byte, winXsaveSize)
	for i := range img {
		img[i] = seed + byte(i*7)
	}
	binary.LittleEndian.PutUint64(img[xsaveHeaderOffset:], winXsaveMask)
	clear(img[xsaveHeaderOffset+8 : xsaveHeaderOffset+64])
	return img
}

// sameVector compares the parts of two XSAVE images that the routine saves.
func sameVector(a, b []byte) bool {
	for _, rg := range x86VectorRanges() {
		if !bytes.Equal(a[rg[0]:rg[1]], b[rg[0]:rg[1]]) {
			return false
		}
	}
	return true
}

func (r *spillRig) sysmsgVector() []byte {
	img := make([]byte, winXsaveSize)
	for i := range img {
		img[i] = r.m.mem[rigSysm+winOffXsave+uint64(i)]
	}
	return img
}

func (r *spillRig) putSysmsgVector(img []byte) {
	for i, b := range img {
		r.m.mem[rigSysm+winOffXsave+uint64(i)] = b
	}
}

func TestSpillSavesVectorStateBeforeItsFirstCall(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	guest := vectorImage(rigVectorSeed)
	r.m.put32(rigSysm+winOffSentryWaiter, 1)
	r.onCallee = func(m *x86Machine, target uint64) {
		if target != rigSetEv {
			return
		}
		if sameVector(m.vec[:], guest) {
			t.Error("the call left the volatile vector registers alone, so this test proves nothing")
		}
		if !sameVector(r.sysmsgVector(), guest) {
			t.Error("NtSetEvent ran before the routine saved the vector state")
		}
	}
	r.m.onYield = func(m *x86Machine) {
		if !sameVector(r.sysmsgVector(), guest) {
			t.Error("the saved vector state differs from the guest registers while the stub polls")
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if len(r.callLog) != 1 || r.callLog[0] != "set" {
		t.Fatalf("calls = %v, want one NtSetEvent", r.callLog)
	}
	r.checkHotExit(t, r.guest, rigFlags)
	if !sameVector(r.m.vec[:], guest) {
		t.Error("the guest vector registers changed across the call")
	}
}

func TestSpillKeepsVectorStateAcrossBothOfItsCalls(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	guest := vectorImage(rigVectorSeed)
	r.m.put32(rigSysm+winOffSentryWaiter, 1)
	r.onCallee = func(m *x86Machine, target uint64) {
		if target == rigWaitFn {
			r.setState(winStateRunHot)
		}
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if len(r.callLog) != 2 {
		t.Fatalf("calls = %v, want NtSetEvent and NtWaitForSingleObject", r.callLog)
	}
	if !sameVector(r.m.vec[:], guest) {
		t.Error("the guest vector registers changed across the two calls")
	}
}

func TestSpillLoadsTheVectorStateThatTheSentryWrote(t *testing.T) {
	for name, resume := range map[string]uint32{"hot": winStateRunHot, "cold": winStateRunCold} {
		t.Run(name, func(t *testing.T) {
			r := newSpillRig(t, rigNop3)
			sentry := vectorImage(rigVectorSeed + 8)
			r.onCallee = func(m *x86Machine, target uint64) {
				if target != rigWaitFn {
					return
				}
				if !sameVector(r.sysmsgVector(), vectorImage(rigVectorSeed)) {
					t.Error("the saved vector state changed before the Sentry wrote its own")
				}
				r.putSysmsgVector(sentry)
				r.setState(resume)
			}
			if err := r.m.run(100000); err != nil {
				t.Fatal(err)
			}
			if !sameVector(r.m.vec[:], sentry) {
				t.Error("the resume did not load the vector state that the Sentry wrote")
			}
		})
	}
}

func TestSpillDoesNotWriteTheVectorImageOutsideItsComponents(t *testing.T) {
	r := newSpillRig(t, rigNop3)
	const gap = 900 // between the AVX component and the opmask component
	r.m.mem[rigSysm+winOffXsave+gap] = 0x5A
	r.m.onYield = func(m *x86Machine) { r.setState(winStateRunHot) }
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if got := r.m.mem[rigSysm+winOffXsave+gap]; got != 0x5A {
		t.Errorf("the routine wrote %#x into a byte that no saved component owns", got)
	}
}

func TestEncodeWinTLSBaseSlotExecutesAllRegistersAndWidths(t *testing.T) {
	const (
		fsVal   = 0x7ff0_0400_1234_5678
		gsVal   = 0x7ff0_0500_9abc_def0
		siteLen = 5
	)
	for _, isGS := range []bool{false, true} {
		for _, wide := range []bool{true, false} {
			for reg := uint8(0); reg < 16; reg++ {
				slot := make([]byte, winTLSSlotSize)
				if err := encodeWinTLSBaseSlot(slot, rigCodeBase, rigSite, siteLen, reg, wide, isGS); err != nil {
					t.Fatalf("isGS=%v wide=%v reg=%d: %v", isGS, wide, reg, err)
				}
				m := newX86Machine(slot, rigCodeBase)
				var initRegs [16]uint64
				for i := range initRegs {
					initRegs[i] = 0x1111_0000_0000_0000 + uint64(i)*0x10101
				}
				m.r = initRegs
				m.rflags = rigFlags
				m.gsBase = rigTEB
				m.put64(rigTEB+winTEBSysmsg, rigSysm)
				m.put64(rigSysm+winOffFsBase, fsVal)
				m.put64(rigSysm+winOffGsBase, gsVal)
				if err := m.run(32); err != nil {
					t.Fatalf("isGS=%v wide=%v reg=%d: run failed: %v", isGS, wide, reg, err)
				}
				if m.exit.jump != rigSite+siteLen {
					t.Fatalf("jump = %#x, want %#x", m.exit.jump, uint64(rigSite+siteLen))
				}
				if m.rflags != rigFlags {
					t.Fatalf("rflags = %#x, want %#x", m.rflags, uint64(rigFlags))
				}
				want := uint64(fsVal)
				if isGS {
					want = gsVal
				}
				if !wide {
					want &= 0xffffffff
				}
				for i := range 16 {
					exp := initRegs[i]
					if uint8(i) == reg {
						exp = want
					}
					if m.r[i] != exp {
						t.Fatalf("isGS=%v wide=%v reg=%d: r[%d] = %#x, want %#x", isGS, wide, reg, i, m.r[i], exp)
					}
				}
			}
		}
	}
}

func TestPlanAndEncodeWinGSMovSlotExecutesLoadsAndStores(t *testing.T) {
	const (
		guestGSBase = 0x7ff0_0600_0000
		disp        = 0x28
	)
	cases := []struct {
		name  string
		insn  []byte
		reg   uint8
		wide  bool
		store bool
	}{
		{"mov rax, gs:[0x28]", []byte{0x65, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}, x86RAX, true, false},
		{"mov r12, gs:[0x28]", []byte{0x65, 0x4C, 0x8B, 0x24, 0x25, 0x28, 0, 0, 0}, x86R12, true, false},
		{"mov rsp, gs:[0x28]", []byte{0x65, 0x48, 0x8B, 0x24, 0x25, 0x28, 0, 0, 0}, x86RSP, true, false},
		{"mov eax, gs:[0x28]", []byte{0x65, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}, x86RAX, false, false},
		{"mov r15d, gs:[0x28]", []byte{0x65, 0x44, 0x8B, 0x3C, 0x25, 0x28, 0, 0, 0}, x86R15, false, false},
		{"mov gs:[0x28], rax", []byte{0x65, 0x48, 0x89, 0x04, 0x25, 0x28, 0, 0, 0}, x86RAX, true, true},
		{"mov gs:[0x28], r13", []byte{0x65, 0x4C, 0x89, 0x2C, 0x25, 0x28, 0, 0, 0}, x86R13, true, true},
		{"mov gs:[0x28], ecx", []byte{0x65, 0x89, 0x0C, 0x25, 0x28, 0, 0, 0}, x86RCX, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gp, ok := planGSMov(tc.insn)
			if !ok {
				t.Fatalf("planGSMov rejected % x", tc.insn)
			}
			if gp.reg != tc.reg || gp.wide != tc.wide || gp.store != tc.store || gp.disp != disp {
				t.Fatalf("planGSMov = %+v, want reg=%d wide=%v store=%v disp=%#x", gp, tc.reg, tc.wide, tc.store, disp)
			}
			slot := make([]byte, winGSMovSlotSize)
			if err := encodeWinGSMovSlot(slot, rigCodeBase, rigSite, len(tc.insn), gp); err != nil {
				t.Fatal(err)
			}
			m := newX86Machine(slot, rigCodeBase)
			var initRegs [16]uint64
			for i := range initRegs {
				initRegs[i] = 0x2222_0000_0000_0000 + uint64(i)*0x30303
			}
			m.r = initRegs
			m.rflags = rigFlags
			m.gsBase = rigTEB
			m.put64(rigTEB+winTEBSysmsg, rigSysm)
			m.put64(rigSysm+winOffGsMemBase, guestGSBase)
			const memSeed = 0xCAFE_BABE_1234_5678
			m.put64(guestGSBase+disp, memSeed)
			if err := m.run(32); err != nil {
				t.Fatalf("run failed: %v", err)
			}
			if m.exit.jump != rigSite+uint64(len(tc.insn)) {
				t.Fatalf("jump = %#x, want %#x", m.exit.jump, rigSite+uint64(len(tc.insn)))
			}
			if m.rflags != rigFlags {
				t.Fatalf("rflags = %#x, want %#x", m.rflags, uint64(rigFlags))
			}
			for i := range 16 {
				want := initRegs[i]
				if !tc.store && uint8(i) == tc.reg {
					want = memSeed
					if !tc.wide {
						want &= 0xffffffff
					}
				}
				if m.r[i] != want {
					t.Fatalf("r[%d] = %#x, want %#x", i, m.r[i], want)
				}
			}
			if tc.store {
				gotMem := m.get64(guestGSBase + disp)
				wantMem := initRegs[tc.reg]
				if !tc.wide {
					gotMem = uint64(m.get32(guestGSBase + disp))
					wantMem &= 0xffffffff
				}
				if gotMem != wantMem {
					t.Fatalf("stored %#x, want %#x", gotMem, wantMem)
				}
			}
		})
	}
}
