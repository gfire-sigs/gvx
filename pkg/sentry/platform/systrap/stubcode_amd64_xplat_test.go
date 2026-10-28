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
	"encoding/hex"
	"fmt"
	"strings"
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
		{"push mem", enc(func(a *x86Asm) { a.pushMem(x86R15, winOffRflags) }), "push qword ptr [r15+0xd0]"},
		{"pop mem", enc(func(a *x86Asm) { a.popMem(x86R15, winOffRflags) }), "pop qword ptr [r15+0xd0]"},
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

	// rigSpinTicks is the spin window of the stub. The emulated TSC advances one
	// tick for each read, so the window lasts this many polls.
	rigSpinTicks = 1024
)

type spillRig struct {
	m     *x86Machine
	sc    winSpillCode
	guest [16]uint64
	reloc []byte
	// pre is true for a pre-window slot. Its relocated instructions run before
	// the entry code, and its tail jumps to site+2.
	pre     bool
	tail    uint64
	callLog []string
	// onCallee acts as the kernel during a call.
	onCallee func(m *x86Machine, target uint64)
}

var rigNop3 = []byte{0x0F, 0x1F, 0x00} // nop dword ptr [rax]

func newSpillRig(t *testing.T, reloc []byte) *spillRig {
	t.Helper()
	return newSlotRig(t, reloc, false, spillOptions{})
}

// newPreSpillRig returns a rig whose slot is a pre-window slot with the
// relocated instructions reloc. The machine starts at the first of them.
func newPreSpillRig(t *testing.T, reloc []byte) *spillRig {
	t.Helper()
	return newSlotRig(t, reloc, true, spillOptions{})
}

func newSlotRig(t *testing.T, reloc []byte, pre bool, opts spillOptions) *spillRig {
	t.Helper()
	sc, err := buildSpillWith(opts)
	if err != nil {
		t.Fatal(err)
	}
	code := make([]byte, rigSpillOff+len(sc.code))
	encode := encodeWinSlot
	if pre {
		encode = encodeWinPreSlot
	}
	if err := encode(code, rigCodeBase, rigSite, rigCodeBase+rigSpillOff, reloc); err != nil {
		t.Fatal(err)
	}
	copy(code[rigSpillOff:], sc.code)
	m := newX86Machine(code, rigCodeBase)
	r := &spillRig{m: m, sc: sc, reloc: reloc, pre: pre, tail: rigCodeBase + winSlotTailOffset}
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
	m.put64(rigSysm+winOffSpinTicks, rigSpinTicks)
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
	wantJump := uint64(rigSite + 2)
	if !r.pre {
		wantJump += uint64(len(r.reloc))
	}
	if m.exit.trap != 0 || m.exit.jump != wantJump {
		t.Fatalf("the code ended with trap %d, jump %#x; want a jump to %#x", m.exit.trap, m.exit.jump, wantJump)
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
	if m.pauses != rigSpinTicks {
		t.Errorf("the stub polled %d times, want %d", m.pauses, rigSpinTicks)
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
	if err := encodeWinSlot(buf, rigCodeBase, rigSite, 0x9000, nops(winMaxRelocated+1)); err == nil {
		t.Error("a slot with too many relocated bytes was accepted")
	}
	if err := encodeWinSlot(buf, rigCodeBase, rigSite, 0x9000, nops(winMaxRelocated)); err != nil {
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
		{"short test then branch", cat(sys, []byte{0x85, 0xC0, 0x74, 0x02, 0x90}), []byte{0x85, 0xC0, 0x74, 0x02}},
		{"call behind the syscall", cat(sys, []byte{0xE8, 0x00, 0x00, 0x00, 0x00}), nil},
		{"rip-relative load", cat(sys, []byte{0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}), []byte{0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00}},
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

// TestPlanJmpPatchRelocatesVZero checks that the planner moves the three bytes
// of a VZEROUPPER behind a SYSCALL, and no byte of the next instruction. The old
// length of 5 moved two bytes of the LEA into the slot.
func TestPlanJmpPatchRelocatesVZero(t *testing.T) {
	// syscall; vzeroupper; lea rsp, [rbp-0x28]; ret
	page := []byte{0x0f, 0x05, 0xc5, 0xf8, 0x77, 0x48, 0x8d, 0x65, 0xd8, 0xc3}
	reloc, ok := planJmpPatch(nil, page, nil, 0)
	if want := []byte{0xc5, 0xf8, 0x77}; !ok || !bytes.Equal(reloc, want) {
		t.Errorf("planJmpPatch = (% x, %v), want (% x, true)", reloc, ok, want)
	}
}

// planKindOf returns how patchPage patches the SYSCALL at page[off] when no
// other site constrains the patch.
func planKindOf(before, page, after []byte, off int) planKind {
	return newJmpPlanner(before, page, after).planSite(off, 0).kind
}

// corpusSite is one SYSCALL site of a real binary, or the smallest synthetic
// byte pattern that reaches one reject reason of the planner.
type corpusSite struct {
	name string
	// code is the hex dump of the bytes around the SYSCALL. site is the offset
	// of the SYSCALL in code.
	code string
	site int
	// at is the page offset of code[0]. Zero means corpusDefaultAt, so that the
	// planner sees bytes in front of the site. The value atPageStart puts
	// code[0] at the first byte of the page, and atPageEnd puts the last byte
	// of code at the last byte of the page.
	at int
	// lead is the hex dump of the bytes that precede the page.
	lead string
	want planKind
}

const (
	atPageEnd       = -1
	atPageStart     = -2
	corpusDefaultAt = 0x200
)

// corpusSites lists the sites. The bytes of the real sites come from Alpine
// 3.20.3 (musl 1.2.5), Debian 12 libc6 2.36-9+deb12u14 (glibc), and a Go 1.27
// static linux/amd64 binary.
var corpusSites = []corpusSite{
	{
		// __syscall_cp_asm: the jnz at __cp_begin lands on the jmp behind the
		// ret, so the byte behind the ret is a branch target.
		name: "musl __syscall_cp_asm",
		code: "48890e0f0585c0750f31ed5f41ffd189c731c0b03c0f05f4c38b0785c075244989fb4889f04889d74889ce4c89c24d89ca4c8b4424084c8b4c24104c895c24080f05c3e901ccffff4154b802000000554889f5be00880800",
		site: 64,
		want: planPre,
	},
	{
		name: "Go runtime.osyield",
		code: "83ec204883c7084889febf02100000b89e0000000f05483d01f0ffff760bc70425f1000000f10000004883c4205dc3ccccccccccccccccccccccccb8180000000f05c3cccccccccccccccccccccccccccccccccccccccccc",
		site: 64,
		want: planPre,
	},
	{
		name: "glibc getpid",
		code: "b74c13fe66894c10fee9b7feffffe8282d04000f1f840000000000b901000000e9b6fcffff660f1f44000031c9e9a9fcffff660f1f840000000000b8270000000f05c30f1f840000000000b86e0000000f05c30f1f840000",
		site: 64,
		want: planPre,
	},
	{
		// The js at the start of the code lands on the instruction behind the
		// SYSCALL.
		name: "glibc futex of pthread_cond_wait with a branch target",
		code: "7864482b1425280000000f85b10100004881c4880000005b5d415c415d415e415fc30f1f40004889d048f7d083e0014939c675b0418b07488b314839f275a5a801750a8d7002f0410fb13775ea89ee4531d2ba010000004c89ff4080f681b8ca0000000f05483d00f0ffff0f8673ffffff83c01683e0f70f8467ff",
		site: 99,
		want: planPre,
	},
	{
		name: "Go Syscall6",
		code: "cccccccccccccccccccccccc4989f24889fa4889ce4889df0f05483d01f0ffff761348f7d84889c148c7c0ffffffffbb",
		site: 24,
		want: planPost,
	},
	{
		// mov dword [rip+0x546fc], 1 follows the SYSCALL.
		name: "musl setitimer with a RIP-relative store",
		code: "48c1e906488d04c8f0480910803db21f05000075378b052d47050085c0752d488d74242041ba0800000031d248b800000000030000004889442420b80e0000000f05c705fc46050001000000418b8088000000a900000010",
		site: 64,
		want: planPost,
	},
	{
		// test eax, eax; jne +0x25 follows the SYSCALL.
		name: "glibc clock_gettime with a Jcc",
		code: "3d00f0ffff76df4889c2ebc90f1f8000000000488b05713a1000488b80e00200004885c074154883ec08ffd085c0752331c04883c408c30f1f4000b8e40000000f0585c0752531c0c3662e0f1f840000000000488b157939",
		site: 64,
		want: planPost,
	},
	{
		// jmp rel8 follows the SYSCALL and ends before the end of the 5-byte
		// patch, so only the instructions in front of the SYSCALL can move.
		name: "Go nanotime1 with a JMP rel8",
		code: "3affd0488b0424488b5424084c89e4488b4c240848898b80030000488b0c2448898b880300004869c000ca9a3b4801d048894424204883c4105dc3b8e40000000f05ebbfcccccccccccccccccccccccccccccccccccc8b7c",
		site: 64,
		want: planPre,
	},
	{
		name: "SYSCALL followed by a JMP rel32",
		code: "b8e40000000f05e940000000cccc",
		site: 5,
		want: planPost,
	},
	{
		name: "call in the window",
		code: "909090e8000000000f05c3cccc",
		site: 8,
		want: planTrap,
	},
	{
		// jmp +0x10 at offset 0 lands at offset 18, one byte behind the
		// start of `mov eax, 24`.
		name: "branch target inside the window",
		code: "eb10" + "90909090909090909090909090" + "90" + "b8180000000f05c3cccc",
		site: 21,
		want: planTrap,
	},
	{
		// jmp +0x0e at offset 0 lands at offset 16, the start of `mov eax, 24`.
		name: "branch target at the start of the window",
		code: "eb0e" + "90909090909090909090909090" + "90" + "b8180000000f05c3cccc",
		site: 21,
		want: planPre,
	},
	{
		name: "window starts in the previous page",
		code: "0f05c3cccccccccc",
		site: 0,
		at:   atPageStart,
		lead: strings.Repeat("90", 59) + "b818000000",
		want: planTrap,
	},
	{
		name: "prefix in front of the SYSCALL",
		code: "b818000000" + "480f05" + "c3cccc",
		site: 6,
		want: planTrap,
	},
	{
		name: "exit with no byte behind the SYSCALL",
		code: "b83c0000000f05",
		site: 5,
		at:   atPageEnd,
		want: planTrap,
	},
}

func TestCorpusSitesPlan(t *testing.T) {
	for _, c := range corpusSites {
		t.Run(c.name, func(t *testing.T) {
			code, err := hex.DecodeString(c.code)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(code[c.site:], []byte{0x0F, 0x05}) {
				t.Fatalf("code[%d:] does not start with a SYSCALL", c.site)
			}
			lead, err := hex.DecodeString(c.lead)
			if err != nil {
				t.Fatal(err)
			}
			at := c.at
			switch at {
			case 0:
				at = corpusDefaultAt
			case atPageStart:
				at = 0
			case atPageEnd:
				at = amd64PageSize - len(code)
			}
			page := pageWith(at, code...)
			off := at + c.site
			found := false
			for _, s := range scanAMD64(lead, page, nil) {
				if s.Kind == amd64SiteSyscall && s.Offset == off {
					found = true
				}
			}
			if !found {
				t.Fatalf("scanAMD64 does not report a SYSCALL at page offset %d", off)
			}
			if got := planKindOf(lead, page, nil, off); got != c.want {
				t.Fatalf("plan = %s, want %s", got, c.want)
			}
		})
	}
}

func TestPlanSiteRules(t *testing.T) {
	var (
		sys      = []byte{0x0F, 0x05}
		ret      = []byte{0xC3}
		movEax24 = []byte{0xB8, 0x18, 0, 0, 0}
		// mov qword [rsp+8], 0x12345678
		movMem9 = []byte{0x48, 0xC7, 0x44, 0x24, 0x08, 0x78, 0x56, 0x34, 0x12}
		// mov rax, 0x1122334455667788
		movImm64 = []byte{0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}
		addEbx   = []byte{0x81, 0xC3, 1, 0, 0, 0}
		imulRax  = []byte{0x48, 0x0F, 0xAF, 0xC3}
		// mov rax, fs:[0x28]
		movFS = []byte{0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}
		call  = []byte{0xE8, 1, 2, 3, 4}
		// cmp rax, -4095; jbe +0x13
		cmpJbe = []byte{0x48, 0x3D, 0x01, 0xF0, 0xFF, 0xFF, 0x76, 0x13}
		xorEax = []byte{0x31, 0xC0, 0x90, 0x90}
	)
	// jumpTo returns lead bytes that start with a short jump to the byte at
	// offset target of the lead and the window.
	jumpTo := func(target int) []byte {
		lead := nops(64)
		lead[0], lead[1] = 0xEB, byte(target-2)
		return lead
	}
	for _, c := range []struct {
		name   string
		lead   []byte // nil means 64 NOPs
		window []byte
		tail   []byte
		atEnd  bool // the tail ends at the end of the page
		// floorDelta is the distance from the first window byte to the floor.
		floorDelta int
		want       planKind
	}{
		{name: "P1 sweeps agree", window: movEax24, tail: ret, want: planPre},
		{name: "P1 sweeps never agree", lead: bytes.Repeat([]byte{0xB8}, 64), tail: ret, want: planTrap},
		{name: "P2 nine bytes", window: movMem9, tail: ret, want: planPre},
		{name: "P2 nine bytes of two instructions", window: catBytes(movEax24, imulRax), tail: ret, want: planPre},
		{name: "P2 ten bytes of one instruction", window: movImm64, tail: ret, want: planTrap},
		{name: "P2 ten bytes of two instructions", window: catBytes(addEbx, imulRax), tail: ret, want: planTrap},
		{name: "P3 byte behind the SYSCALL in the page", window: movEax24, tail: ret, atEnd: true, want: planPre},
		{name: "P3 SYSCALL at the end of the page", window: movEax24, atEnd: true, want: planTrap},
		{name: "P4 movable instruction", window: movEax24, tail: ret, want: planPre},
		{name: "P4 segment override", window: movFS, tail: ret, want: planTrap},
		{name: "P4 call", window: call, tail: ret, want: planTrap},
		{name: "P5 branch to the first byte", lead: jumpTo(64), window: movEax24, tail: ret, want: planPre},
		{name: "P5 branch to the SYSCALL", lead: jumpTo(64 + 5), window: movEax24, tail: ret, want: planPre},
		{name: "P5 branch inside the window", lead: jumpTo(64 + 1), window: movEax24, tail: ret, want: planTrap},
		{name: "P5 branch to the last window byte", lead: jumpTo(64 + 4), window: movEax24, tail: ret, want: planTrap},
		{name: "P6 floor at the first byte", window: movEax24, tail: ret, floorDelta: 0, want: planPre},
		{name: "P6 floor inside the window", window: movEax24, tail: ret, floorDelta: 1, want: planTrap},
		{name: "P7 prefix", window: catBytes(movEax24, []byte{0x48}), tail: ret, want: planTrap},
		{name: "P8 post wins", window: movEax24, tail: cmpJbe, want: planPost},
		{name: "P8 pre when post fails", window: movEax24, tail: ret, want: planPre},
		{name: "P8 pre for a no-return call", window: []byte{0xB8, 60, 0, 0, 0}, tail: xorEax, want: planPre},
		{name: "P8 both fail", window: call, tail: ret, want: planTrap},
	} {
		t.Run(c.name, func(t *testing.T) {
			lead := c.lead
			if lead == nil {
				lead = nops(64)
			}
			code := catBytes(lead, c.window, sys, c.tail)
			at := corpusDefaultAt
			if c.atEnd {
				at = amd64PageSize - len(code)
			}
			page := pageWith(at, code...)
			site := at + len(lead) + len(c.window)
			floor := at + len(lead) + c.floorDelta
			got := newJmpPlanner(nil, page, nil).planSite(site, floor)
			if got.kind != c.want {
				t.Fatalf("plan = %s, want %s", got.kind, c.want)
			}
			if got.kind == planPre {
				if wantStart := at + len(lead); got.start != wantStart && len(c.window) > 0 {
					t.Errorf("window starts at %d, want %d", got.start, wantStart)
				}
				if !bytes.HasSuffix(c.window, got.reloc) || len(got.reloc) < winJmpLen || len(got.reloc) > winPreMaxRelocated {
					t.Errorf("relocated bytes % x are not the end of the window % x", got.reloc, c.window)
				}
			}
		})
	}
}

func TestEncodeWinPreSlotLayout(t *testing.T) {
	const slotVA, site, spill = rigCodeBase, rigSite, 0x7ff0_1100_0100
	for n := winJmpLen; n <= winPreMaxRelocated; n++ {
		t.Run(fmt.Sprintf("%d relocated bytes", n), func(t *testing.T) {
			reloc := bytes.Repeat([]byte{0x90}, n)
			buf := make([]byte, winSlotSize)
			if err := encodeWinPreSlot(buf, slotVA, site, spill, reloc); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buf[:n], reloc) {
				t.Fatalf("slot starts with % x, want the relocated bytes % x", buf[:n], reloc)
			}
			// The entry code is a store, a LEA, a store, and an indirect jump.
			wantOps := []x86asm.Op{x86asm.MOV, x86asm.LEA, x86asm.MOV, x86asm.JMP}
			pos := n
			var lea, jmp x86asm.Inst
			for i, op := range wantOps {
				inst, err := x86asm.Decode(buf[pos:], 64)
				if err != nil || inst.Op != op {
					t.Fatalf("entry instruction %d at offset %d decodes as %v, %v; want %v", i, pos, inst, err, op)
				}
				switch op {
				case x86asm.LEA:
					lea = inst
				case x86asm.JMP:
					jmp = inst
				}
				pos += inst.Len
			}
			if pos != n+winSlotEntryLen {
				t.Fatalf("entry code ends at offset %d, want %d", pos, n+winSlotEntryLen)
			}
			// The LEA names the tail, and the JMP reads the literal.
			leaEnd := slotVA + uint64(n) + 16
			if got := leaEnd + uint64(lea.Args[1].(x86asm.Mem).Disp); got != slotVA+winSlotTailOffset {
				t.Errorf("LEA loads %#x, want the tail %#x", got, uint64(slotVA+winSlotTailOffset))
			}
			if got := slotVA + uint64(pos) + uint64(jmp.Args[0].(x86asm.Mem).Disp); got != slotVA+winPreSlotLiteralOffset {
				t.Errorf("JMP reads %#x, want the literal %#x", got, uint64(slotVA+winPreSlotLiteralOffset))
			}
			if !bytes.Equal(buf[pos:winSlotTailOffset], bytes.Repeat([]byte{0xCC}, winSlotTailOffset-pos)) {
				t.Errorf("filler before the tail is % x", buf[pos:winSlotTailOffset])
			}
			// The tail jumps to the byte behind the SYSCALL.
			tail, err := x86asm.Decode(buf[winSlotTailOffset:], 64)
			if err != nil || tail.Op != x86asm.JMP || tail.Len != winJmpLen {
				t.Fatalf("tail decodes as %v, %v", tail, err)
			}
			if got := slotVA + winSlotTailOffset + winJmpLen + uint64(int64(tail.Args[0].(x86asm.Rel))); got != site+winSiteLen {
				t.Errorf("tail jumps to %#x, want %#x", got, uint64(site+winSiteLen))
			}
			if got := binary.LittleEndian.Uint64(buf[winPreSlotLiteralOffset:]); got != spill {
				t.Errorf("literal = %#x, want %#x", got, uint64(spill))
			}
			rest := buf[winSlotTailOffset+winJmpLen : winPreSlotLiteralOffset]
			if !bytes.Equal(rest, bytes.Repeat([]byte{0xCC}, len(rest))) || !bytes.Equal(buf[winPreSlotLiteralOffset+8:], bytes.Repeat([]byte{0xCC}, winSlotSize-winPreSlotLiteralOffset-8)) {
				t.Errorf("filler after the tail is % x and % x", rest, buf[winPreSlotLiteralOffset+8:])
			}
		})
	}
}

func TestEncodeWinPreSlotBounds(t *testing.T) {
	buf := make([]byte, winSlotSize)
	if err := encodeWinPreSlot(buf, rigCodeBase, rigSite, 0x9000, make([]byte, winJmpLen-1)); err == nil {
		t.Error("a slot with fewer bytes than a JMP was accepted")
	}
	if err := encodeWinPreSlot(buf, rigCodeBase, rigSite, 0x9000, make([]byte, winPreMaxRelocated+1)); err == nil {
		t.Error("a slot with too many relocated bytes was accepted")
	}
	if err := encodeWinPreSlot(buf, rigCodeBase, rigSite+2*winIslandReach32, 0x9000, nops(winJmpLen)); err == nil {
		t.Error("a slot that cannot reach the site was accepted")
	}
	if err := encodeWinPreSlot(buf[:winSlotSize-1], rigCodeBase, rigSite, 0x9000, nops(winJmpLen)); err == nil {
		t.Error("a short buffer was accepted")
	}
}

func TestPreSlotRunsRelocatedInstructionsBeforeTheSpill(t *testing.T) {
	// mov [rsp+8], r11
	r := newPreSpillRig(t, []byte{0x4C, 0x89, 0x5C, 0x24, 0x08})
	m := r.m
	stored := r.guest[x86R11]
	r.m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			return
		}
		if got := m.get64(rigGuestRSP + 8); got != stored {
			t.Errorf("[rsp+8] = %#x when the stub polls, want R11 %#x", got, stored)
		}
		r.checkSaved(t)
		r.setState(winStateRunHot)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest, rigFlags)
	if len(r.callLog) != 0 {
		t.Fatalf("a spin hit made calls %v", r.callLog)
	}
}

func TestPreSlotSavesTheRegistersThatTheRelocatedInstructionsChanged(t *testing.T) {
	// mov eax, 24
	r := newPreSpillRig(t, []byte{0xB8, 0x18, 0, 0, 0})
	r.guest[x86RAX] = 24
	r.m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			return
		}
		r.checkSaved(t)
		if got := r.saved(x86RAX); got != 24 {
			t.Errorf("saved RAX = %d, want the system call number 24", got)
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest, rigFlags)
}

func TestInsnOffsets(t *testing.T) {
	// mov eax, 24; mov [rsp+8], r11; nop
	code := []byte{0xB8, 0x18, 0, 0, 0, 0x4C, 0x89, 0x5C, 0x24, 0x08, 0x90}
	offs, ok := insnOffsets(code)
	if want := []uint8{0, 5, 10}; !ok || !bytes.Equal(offs, want) {
		t.Fatalf("insnOffsets = %v, %v; want %v", offs, ok, want)
	}
	if _, ok := insnOffsets(code[:len(code)-3]); ok {
		t.Error("insnOffsets accepted a cut instruction")
	}
}

func TestClassifyReloc(t *testing.T) {
	for _, c := range []struct {
		name string
		code []byte
		want relocClass
	}{
		{"register move", []byte{0x48, 0x89, 0xD8}, relocCopy},
		{"absolute displacement through a SIB byte", []byte{0x48, 0x8B, 0x04, 0x25, 0x10, 0, 0, 0}, relocCopy},
		{"RIP-relative load", []byte{0x48, 0x8B, 0x05, 0x10, 0, 0, 0}, relocRIP},
		{"RIP-relative store with an immediate", []byte{0xC7, 0x05, 0xFC, 0x46, 0x05, 0, 1, 0, 0, 0}, relocRIP},
		{"RIP-relative LEA", []byte{0x48, 0x8D, 0x05, 4, 0, 0, 0}, relocRIP},
		{"RIP-relative SSE load", []byte{0x66, 0x0F, 0x6F, 0x05, 4, 0, 0, 0}, relocRIP},
		// x86asm leaves out the RIP base of a VEX operand.
		{"RIP-relative VEX load", []byte{0xC5, 0xFA, 0x10, 0x05, 0x10, 0, 0, 0}, relocNone},
		{"RIP-relative EVEX load", []byte{0x62, 0xF1, 0x7C, 0x48, 0x10, 0x05, 0x10, 0, 0, 0}, relocNone},
		{"VEX load through a base register", []byte{0xC5, 0xFA, 0x10, 0x03}, relocCopy},
		{"EIP-relative load", []byte{0x67, 0x8B, 0x05, 4, 0, 0, 0}, relocNone},
		{"segment override", []byte{0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0, 0, 0}, relocNone},
		{"Jcc rel8", []byte{0x74, 0x05}, relocJcc},
		{"Jcc rel32", []byte{0x0F, 0x85, 1, 2, 3, 4}, relocJcc},
		{"JMP rel8", []byte{0xEB, 0xBF}, relocJmp},
		{"JMP rel32", []byte{0xE9, 1, 0, 0, 0}, relocJmp},
		{"branch with a prefix", []byte{0x2E, 0x74, 0x05}, relocNone},
		{"JRCXZ", []byte{0xE3, 0x05}, relocNone},
		{"JECXZ", []byte{0x67, 0xE3, 0x05}, relocNone},
		{"LOOP", []byte{0xE2, 0x05}, relocNone},
		{"CALL rel32", []byte{0xE8, 1, 2, 3, 4}, relocNone},
		{"RET", []byte{0xC3}, relocNone},
		{"SYSCALL", []byte{0x0F, 0x05}, relocNone},
		{"INT3", []byte{0xCC}, relocNone},
	} {
		t.Run(c.name, func(t *testing.T) {
			inst, err := decodeX86(c.code)
			if err != nil || inst.Len != len(c.code) {
				t.Fatalf("% x decodes as %v, %v", c.code, inst, err)
			}
			if got := classifyReloc(inst, c.code); got != c.want {
				t.Errorf("class = %d, want %d", got, c.want)
			}
		})
	}
}

func TestRelocateRIPRelativeOperand(t *testing.T) {
	// mov rax, [rip+disp]
	mov := func(disp int32) []byte {
		code := []byte{0x48, 0x8B, 0x05, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(code[3:], uint32(disp))
		return code
	}
	const orig = 0x7ff0_1000_0102
	for _, c := range []struct {
		name string
		disp int32
		// delta is newVA-origVA.
		delta int64
		ok    bool
	}{
		{"no move", 0x1234, 0, true},
		{"slot above the code", 0x1234, 0x1100_0000, true},
		{"slot below the code", 0x1234, -0x1100_0000, true},
		{"largest positive displacement", 0x7FFF_FFF0, -0x0F, true},
		{"one past the largest positive displacement", 0x7FFF_FFF0, -0x10, false},
		{"most negative displacement", -0x8000_0000 + 0x10, 0x10, true},
		{"one below the most negative displacement", -0x8000_0000 + 0x10, 0x11, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The new displacement is disp-delta. A row fails when it leaves int32.
			code := mov(c.disp)
			newVA := uint64(int64(orig) + c.delta)
			got, err := relocateInstructions(code, orig, newVA, true)
			if (err == nil) != c.ok {
				t.Fatalf("relocateInstructions error = %v, want success %v", err, c.ok)
			}
			if err != nil {
				return
			}
			if len(got) != len(code) {
				t.Fatalf("the move changed the length from %d to %d", len(code), len(got))
			}
			if !bytes.Equal(got[:3], code[:3]) {
				t.Errorf("the move changed the opcode bytes: % x", got)
			}
			// The target is the same: next+disp.
			wantTarget := int64(orig) + 7 + int64(c.disp)
			gotTarget := int64(newVA) + 7 + int64(int32(binary.LittleEndian.Uint32(got[3:])))
			if gotTarget != wantTarget {
				t.Errorf("the moved instruction reads %#x, want %#x", gotTarget, wantTarget)
			}
		})
	}
	// The displacement field sits before an immediate.
	code := []byte{0xC7, 0x05, 0x10, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD}
	got, err := relocateInstructions(code, orig, orig+0x100, true)
	if err != nil {
		t.Fatal(err)
	}
	// The new displacement is 0x10-0x100 = -0xF0, which is 0xFFFFFF10.
	if want := []byte{0xC7, 0x05, 0x10, 0xFF, 0xFF, 0xFF, 0xAA, 0xBB, 0xCC, 0xDD}; !bytes.Equal(got, want) {
		t.Errorf("mov [rip+0x10], imm32 moved up by 0x100 is % x, want % x", got, want)
	}
}

func TestRelocateBranches(t *testing.T) {
	const orig, slot = 0x7ff0_1000_0102, 0x7ff0_1100_0040
	for cc := byte(0); cc < 16; cc++ {
		for _, form := range []struct {
			name string
			code []byte
			len  int
		}{
			{"rel8", []byte{0x70 | cc, 0x20}, 2},
			{"rel32", []byte{0x0F, 0x80 | cc, 0x20, 0, 0, 0}, 6},
		} {
			t.Run(fmt.Sprintf("Jcc %x %s", cc, form.name), func(t *testing.T) {
				got, err := relocateInstructions(form.code, orig, slot, true)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 6 || got[0] != 0x0F || got[1] != 0x80|cc {
					t.Fatalf("moved branch is % x, want 0F %02X rel32", got, 0x80|cc)
				}
				inst, err := x86asm.Decode(got, 64)
				if err != nil {
					t.Fatal(err)
				}
				target := slot + 6 + uint64(int64(inst.Args[0].(x86asm.Rel)))
				if want := uint64(orig + form.len + 0x20); target != want {
					t.Errorf("the moved branch goes to %#x, want the original target %#x", target, want)
				}
			})
		}
	}
	for _, c := range []struct {
		name string
		code []byte
		len  int
		rel  int64
	}{
		{"JMP rel8 forward", []byte{0xEB, 0x20}, 2, 0x20},
		{"JMP rel8 backward", []byte{0xEB, 0xBF}, 2, -0x41},
		{"JMP rel32", []byte{0xE9, 0x00, 0x01, 0, 0}, 5, 0x100},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := relocateInstructions(c.code, orig, slot, true)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 5 || got[0] != 0xE9 {
				t.Fatalf("moved jump is % x, want E9 rel32", got)
			}
			target := slot + 5 + uint64(int64(int32(binary.LittleEndian.Uint32(got[1:]))))
			if want := uint64(int64(orig) + int64(c.len) + c.rel); target != want {
				t.Errorf("the moved jump goes to %#x, want %#x", target, want)
			}
		})
	}
	t.Run("no branch in a pre-window", func(t *testing.T) {
		if _, err := relocateInstructions([]byte{0x74, 0x05}, orig, slot, false); err == nil {
			t.Error("a branch moved into a pre-window slot")
		}
	})
	t.Run("target out of reach", func(t *testing.T) {
		far := uint64(orig) + 2<<31
		if _, err := relocateInstructions([]byte{0x74, 0x05}, orig, far, true); err == nil {
			t.Error("a branch whose target is out of rel32 reach was moved")
		}
	})
	t.Run("call stays in place", func(t *testing.T) {
		if _, err := relocateInstructions([]byte{0xE8, 1, 2, 3, 4}, orig, slot, true); err == nil {
			t.Error("a call moved")
		}
	})
}

func TestPlanRelocatesBranchesAndRIPOperands(t *testing.T) {
	sys := []byte{0x0F, 0x05}
	jmp8 := []byte{0xEB, 0x20}
	// Long NOPs with prefixes: a Jcc rel8 grows by four bytes when it moves, so a
	// short branch and a 15-byte NOP exceed the slot, and the 11-byte NOP fits.
	nop11 := []byte{0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0}
	nop15 := []byte{0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0}
	for _, c := range []struct {
		name string
		tail []byte
		want []byte // relocated original bytes, nil for a trap
	}{
		{"Jcc after a test", catBytes([]byte{0x85, 0xC0, 0x75, 0x25}, nops(8)), []byte{0x85, 0xC0, 0x75, 0x25}},
		{"Jcc rel32 alone", catBytes([]byte{0x0F, 0x84, 0x80, 0, 0, 0}, nops(4)), []byte{0x0F, 0x84, 0x80, 0, 0, 0}},
		{"Jcc to the SYSCALL", catBytes([]byte{0x85, 0xC0, 0x74, 0xFA}, nops(4)), []byte{0x85, 0xC0, 0x74, 0xFA}}, // -6 from the end: the SYSCALL
		{"Jcc into the overwritten bytes", catBytes([]byte{0x85, 0xC0, 0x74, 0xFC}, nops(4)), nil},                // lands at site+4
		{"Jcc to the first byte behind the patch", catBytes([]byte{0x85, 0xC0, 0x74, 0xFF}, nops(4)), []byte{0x85, 0xC0, 0x74, 0xFF}},
		{"JMP rel32", catBytes([]byte{0xE9, 0x40, 0, 0, 0}, nops(4)), []byte{0xE9, 0x40, 0, 0, 0}},
		{"JMP rel8 ends before the end of the patch", catBytes(jmp8, nops(8)), nil},
		{"JMP rel8 after a one-byte instruction", catBytes([]byte{0x90}, jmp8, nops(8)), []byte{0x90, 0xEB, 0x20}},
		{"JMP into the overwritten bytes", catBytes([]byte{0x90, 0xEB, 0xFD}, nops(8)), nil}, // lands at site+2
		{"instruction behind a JMP stays", catBytes([]byte{0xE9, 0x40, 0, 0, 0, 0x90}, nops(4)), []byte{0xE9, 0x40, 0, 0, 0}},
		{"JRCXZ", catBytes([]byte{0xE3, 0x05, 0x90}, nops(8)), nil},
		{"RIP-relative store", catBytes([]byte{0xC7, 0x05, 0x10, 0, 0, 0, 1, 0, 0, 0}, nops(4)), []byte{0xC7, 0x05, 0x10, 0, 0, 0, 1, 0, 0, 0}},
		{"RIP-relative VEX load", catBytes([]byte{0xC5, 0xFA, 0x10, 0x05, 0x10, 0, 0, 0}, nops(4)), nil},
		{"size after the move exceeds the slot", catBytes([]byte{0x74, 0x05}, nop15, nops(4)), nil},
		{"size after the move fits", catBytes([]byte{0x74, 0x05}, nop11, nops(4)), catBytes([]byte{0x74, 0x05}, nop11)},
	} {
		t.Run(c.name, func(t *testing.T) {
			page := pageWith(0x100, catBytes(sys, c.tail)...)
			got, ok := planJmpPatch(nil, page, nil, 0x100)
			if (c.want != nil) != ok || (ok && !bytes.Equal(got, c.want)) {
				t.Fatalf("planJmpPatch = (% x, %v), want (% x, %v)", got, ok, c.want, c.want != nil)
			}
		})
	}
}

// relocRig runs one slot of an emulated spill routine. The slot has been
// assembled with the instructions reloc, which sit at the original address
// origVA. The test sets the state through the registers that the Sentry saved.
func (r *spillRig) runHot(t *testing.T, saved map[int]uint64) {
	t.Helper()
	r.m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			return
		}
		for n, v := range saved {
			r.setSaved(n, v)
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
}

func TestPostSlotRunsRelocatedBranchOnBothEdges(t *testing.T) {
	// cmp rbx, 0; je +0x40
	reloc := []byte{0x48, 0x83, 0xFB, 0x00, 0x74, 0x40}
	end := uint64(rigSite + winSiteLen + len(reloc))
	for _, c := range []struct {
		name string
		rbx  uint64
		want uint64
	}{
		{"taken", 0, end + 0x40},
		{"not taken", 5, end},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newSpillRig(t, reloc)
			r.runHot(t, map[int]uint64{x86RBX: c.rbx})
			if r.m.exit.trap != 0 || r.m.exit.jump != c.want {
				t.Fatalf("the code ended with trap %d, jump %#x; want a jump to %#x", r.m.exit.trap, r.m.exit.jump, c.want)
			}
		})
	}
}

func TestSlotsRetargetRIPRelativeLoads(t *testing.T) {
	const want = 0x1122_3344_5566_7788
	t.Run("post-window", func(t *testing.T) {
		// mov rax, [rip+0x200], behind the SYSCALL.
		reloc := []byte{0x48, 0x8B, 0x05, 0x00, 0x02, 0x00, 0x00}
		target := uint64(rigSite + winSiteLen + len(reloc) + 0x200)
		r := newSpillRig(t, reloc)
		r.m.put64(target, want)
		r.runHot(t, nil)
		if got := r.m.r[x86RAX]; got != want {
			t.Fatalf("the relocated load returned %#x, want %#x", got, uint64(want))
		}
	})
	t.Run("pre-window", func(t *testing.T) {
		// mov rcx, [rip+0x200], in front of the SYSCALL.
		reloc := []byte{0x48, 0x8B, 0x0D, 0x00, 0x02, 0x00, 0x00}
		target := uint64(rigSite) + 0x200
		r := newPreSpillRig(t, reloc)
		r.m.put64(target, want)
		r.guest[x86RCX] = want
		r.runHot(t, nil)
		if got := r.m.r[x86RCX]; got != want {
			t.Fatalf("the relocated load returned %#x, want %#x", got, uint64(want))
		}
	})
}

func TestSpillWithoutVectorStateSkipsTheImage(t *testing.T) {
	full, err := buildSpill()
	if err != nil {
		t.Fatal(err)
	}
	lean, err := buildSpillWith(spillOptions{noVector: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(lean.code) >= len(full.code) {
		t.Errorf("the routine without the vector state has %d bytes, the full routine %d", len(lean.code), len(full.code))
	}
	for pos := 0; pos < len(lean.code); {
		inst, err := x86asm.Decode(lean.code[pos:], 64)
		if err != nil {
			t.Fatalf("instruction at offset %d does not decode: %v", pos, err)
		}
		if inst.Op == x86asm.XSAVE64 || inst.Op == x86asm.XRSTOR64 {
			t.Fatalf("the routine has %v at offset %d", inst, pos)
		}
		pos += inst.Len
	}

	r := newSlotRig(t, rigNop3, false, spillOptions{noVector: true})
	r.m.onYield = func(m *x86Machine) { r.setState(winStateRunHot) }
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest, rigFlags)
	for i, b := range r.sysmsgVector() {
		if b != 0 {
			t.Fatalf("the routine wrote byte %d of the vector image", i)
		}
	}
}

func TestSpillLoadsTheVectorStateOnlyWhenTheRegistersCanDiffer(t *testing.T) {
	guest := vectorImage(rigVectorSeed)
	sentry := vectorImage(rigVectorSeed + 8)
	for _, c := range []struct {
		name string
		// dirty is the value of FPDirty when the Sentry resumes the thread.
		dirty uint32
		// sentryWaits makes the routine call NtSetEvent before the poll.
		sentryWaits bool
		resume      uint32
		// loaded is true when the resume loads the image of the sysmsg.
		loaded bool
	}{
		{"hot spin hit with a clean image skips the load", 0, false, winStateRunHot, false},
		{"hot spin hit with a dirty image loads it", 1, false, winStateRunHot, true},
		{"hot resume after a call loads the image", 0, true, winStateRunHot, true},
		{"cold resume loads the image", 0, false, winStateRunCold, true},
		{"cold resume with a dirty image loads it", 1, false, winStateRunCold, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newSpillRig(t, rigNop3)
			if c.sentryWaits {
				r.m.put32(rigSysm+winOffSentryWaiter, 1)
			}
			r.m.onYield = func(m *x86Machine) {
				if r.state() != winStateTrapped {
					return
				}
				// The Sentry writes an image that differs from the live registers.
				// A clean image would be a bug of the Sentry, which the test uses
				// to see whether the routine loads it.
				r.putSysmsgVector(sentry)
				r.m.put32(rigSysm+winOffFPDirty, c.dirty)
				r.setState(c.resume)
			}
			if err := r.m.run(100000); err != nil {
				t.Fatal(err)
			}
			want := guest
			if c.loaded {
				want = sentry
			}
			if c.sentryWaits && !c.loaded {
				t.Fatal("a call always loads the image")
			}
			if !sameVector(r.m.vec[:], want) {
				t.Errorf("the vector registers hold the image of the %s, want the image of the %s", whichImage(r.m.vec[:], guest, sentry), whichImage(want, guest, sentry))
			}
			if got := r.m.get32(rigSysm + winOffFPDirty); got != 0 && c.loaded {
				t.Errorf("FPDirty = %d after a load, want 0", got)
			}
			if got := r.m.get32(rigSysm + winOffFPDirty); got != c.dirty && !c.loaded {
				t.Errorf("FPDirty = %d after a resume without a load, want %d", got, c.dirty)
			}
		})
	}
}

// whichImage names the image that vec holds.
func whichImage(vec, guest, sentry []byte) string {
	switch {
	case sameVector(vec, guest):
		return "guest"
	case sameVector(vec, sentry):
		return "Sentry"
	}
	return "neither"
}

func TestSpillCallFlagIsNotTheGuestR14(t *testing.T) {
	// The routine keeps its call flag in R14 after it saved the guest registers.
	// A guest R14 of 1 must not make a spin hit load the image, and the resume
	// must return the guest R14.
	guest := vectorImage(rigVectorSeed)
	sentry := vectorImage(rigVectorSeed + 8)
	r := newSpillRig(t, rigNop3)
	r.m.r[x86R14] = 1
	r.guest[x86R14] = 1
	r.m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			return
		}
		r.putSysmsgVector(sentry)
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if !sameVector(r.m.vec[:], guest) {
		t.Error("a spin hit loaded the image because the guest R14 was 1")
	}
	r.checkHotExit(t, r.guest, rigFlags)
}

func TestSpillAlwaysRestoreLoadsOnACleanHotSpinHit(t *testing.T) {
	// The benchmark compares this routine with the production routine, which
	// skips the load in the same case.
	sentry := vectorImage(rigVectorSeed + 8)
	r := newSlotRig(t, rigNop3, false, spillOptions{alwaysRestore: true})
	r.m.onYield = func(m *x86Machine) {
		if r.state() != winStateTrapped {
			return
		}
		r.putSysmsgVector(sentry)
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if !sameVector(r.m.vec[:], sentry) {
		t.Error("the always-restore routine did not load the image on a clean hot spin hit")
	}
}
