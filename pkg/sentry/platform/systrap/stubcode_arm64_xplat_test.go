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

//go:build (darwin || windows) && arm64

package systrap

import (
	"encoding/binary"
	"testing"

	"golang.org/x/arch/arm64/arm64asm"

	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

func TestA64EncodersDecodeAsIntended(t *testing.T) {
	for _, c := range []struct {
		word uint32
		want string
	}{
		{arm64MRSTPIDR | 16, "MRS X16, S3_3_C13_C0_2"},
		{a64MRSNZCV | 0, "MRS X0, S3_3_C4_C2_0"},
		{a64MSRNZCV | 0, "MSR S3_3_C4_C2_0, X0"},
		{hvcommon.LDRX(16, 16, 0x28), "LDR X16, [X16,#40]"},
		{hvcommon.STRX(16, 17, winOffTail), "STR X17, [X16,#48]"},
		{hvcommon.LDRW(19, 0, winOffSentryWaiter), "LDR W0, [X19,#4]"},
		{hvcommon.STRW(19, 0, winOffStubWaiter), "STR W0, [X19,#8]"},
		{hvcommon.STRW(19, a64XZR, winOffStubWaiter), "STR WZR, [X19,#8]"},
		{a64ldarW(0, 19), "LDAR W0, [X19]"},
		{a64stlrW(0, 19), "STLR W0, [X19]"},
		{hvcommon.LDPX(a64SP, 0, 1, -512), "LDP X0, X1, [SP,#-512]"},
		{hvcommon.STPX(2, 0, 1, -512), "STP X0, X1, [X2,#-512]"},
		{hvcommon.STPQ(16, 0, 1, winOffVec), "STP Q0, Q1, [X16,#512]"},
		{hvcommon.LDPQ(16, 30, 31, winOffVec+16*30), "LDP Q30, Q31, [X16,#992]"},
		{hvcommon.MRS(0, hvcommon.SysRegFPSR), "MRS X0, S3_3_C4_C4_1"},
		{hvcommon.MRS(0, hvcommon.SysRegFPCR), "MRS X0, S3_3_C4_C4_0"},
		{hvcommon.MSR(hvcommon.SysRegFPSR, 0), "MSR S3_3_C4_C4_1, X0"},
		{hvcommon.MSR(hvcommon.SysRegFPCR, 0), "MSR S3_3_C4_C4_0, X0"},
		{hvcommon.STPX(16, 14, 15, winOffX+8*14), "STP X14, X15, [X16,#184]"},
		{hvcommon.MOVReg(19, 16), "MOV X19, X16"},
		{a64movFromSP(0), "MOV X0, SP"},
		{a64movToSP(16), "MOV SP, X16"},
		{a64addSPShifted(19, 2), "ADD SP, X19, #0x2, LSL #12"},
		{hvcommon.MOVZ(1, 0), "MOV X1, #0x0"},
		{hvcommon.MOVZW(20, 1024), "MOV W20, #0x400"},
		{a64cmpW(0, 2), "CMP W0, #0x2"},
		{a64subsW1(20), "SUBS W20, W20, #0x1"},
		{hvcommon.BLR(9), "BLR X9"},
		{hvcommon.BR(17), "BR X17"},
		{a64DMBISH, "DMB ISH"},
		{a64YIELD, "YIELD "},
		{hvcommon.BRK(brkFastExit), "BRK #0x5c5"},
	} {
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], c.word)
		inst, err := arm64asm.Decode(b[:])
		if err != nil {
			t.Errorf("word %#x does not decode: %v", c.word, err)
			continue
		}
		if got := inst.String(); got != c.want {
			t.Errorf("word %#x decodes as %q, want %q", c.word, got, c.want)
		}
	}
}

func TestBuildSpillDecodesEveryWord(t *testing.T) {
	sc, err := buildSpill()
	if err != nil {
		t.Fatal(err)
	}
	if len(sc.code)%4 != 0 || len(sc.code) > winCodeSize-winSpillOffset {
		t.Fatalf("spill routine has %d bytes, the code pages leave %d", len(sc.code), winCodeSize-winSpillOffset)
	}
	for off := 0; off < len(sc.code); off += 4 {
		if _, err := arm64asm.Decode(sc.code[off : off+4]); err != nil {
			t.Fatalf("word at offset %#x does not decode: %v", off, err)
		}
	}
	w := binary.LittleEndian.Uint32(sc.code[sc.coldBrk:])
	if w != hvcommon.BRK(brkFastExit) {
		t.Fatalf("word at the cold BRK offset is %#x", w)
	}
}

// Addresses of the rig. The values are arbitrary but distinct.
const (
	rigCode  = 0x7ff0_0000_4000
	rigSysm  = 0x7ff0_0100_0000
	rigStack = 0x7ff0_0300_1000
	rigTail  = 0x7ff0_0400_0010

	rigGuestX16 = 0x1616_1616_1616_1616
	rigGuestX17 = 0x1717_1717_1717_1717

	rigGuestEv = 0xE1
	rigHostEv  = 0xE2
	rigSetEv   = 0xF100
	rigWaitFn  = 0xF200
)

// spillRig holds a machine that stands at the first instruction of the spill
// routine, as a trap slot leaves it.
type spillRig struct {
	m        *a64Machine
	sc       winSpillCode
	guest    [31]uint64
	callLog  []string
	stackLow uint64
	onCallee func(m *a64Machine, target uint64)
}

func newSpillRig(t *testing.T) *spillRig {
	t.Helper()
	return newSpillRigWith(t, spillOptions{})
}

func newSpillRigWith(t *testing.T, opts spillOptions) *spillRig {
	t.Helper()
	sc, err := buildSpillWith(opts)
	if err != nil {
		t.Fatal(err)
	}
	m := newA64Machine(sc.code, rigCode)
	r := &spillRig{m: m, sc: sc, stackLow: rigSysm + winSysmsgSize}
	for i := range r.guest {
		r.guest[i] = 0x1000_0000_0000_0000 + uint64(i)*0x0101_0101
	}
	r.guest[16], r.guest[17] = rigGuestX16, rigGuestX17
	copy(m.x[:], r.guest[:])
	// The slot clobbered x16 and x17 and saved the guest values in the sysmsg scratch words.
	m.x[16], m.x[17] = rigCode, rigTail
	m.sp = rigStack
	m.put64(rigSysm+winOffScratch, rigGuestX16)
	m.put64(rigSysm+winOffScratch+8, rigGuestX17)
	m.n, m.z, m.c, m.v = true, false, true, false
	m.tpidr = rigSysm
	m.put64(rigSysm+winOffGuestEvent, rigGuestEv)
	m.put64(rigSysm+winOffHostEvent, rigHostEv)
	m.put64(rigSysm+winOffNtSetEvent, rigSetEv)
	m.put64(rigSysm+winOffNtWait, rigWaitFn)
	m.onCall = func(m *a64Machine, target uint64) {
		if m.sp%16 != 0 || m.sp <= r.stackLow || m.sp > r.stackLow+winStubStackSize {
			t.Errorf("call with sp %#x outside the stub stack [%#x, %#x] or unaligned", m.sp, r.stackLow, r.stackLow+winStubStackSize)
		}
		switch target {
		case rigSetEv:
			r.callLog = append(r.callLog, "set")
			if m.x[0] != rigGuestEv {
				t.Errorf("NtSetEvent got handle %#x, want %#x", m.x[0], uint64(rigGuestEv))
			}
		case rigWaitFn:
			r.callLog = append(r.callLog, "wait")
			if m.x[0] != rigHostEv || m.x[1] != 0 || m.x[2] != 0 {
				t.Errorf("NtWaitForSingleObject got %#x, %#x, %#x, want handle %#x, FALSE, NULL", m.x[0], m.x[1], m.x[2], uint64(rigHostEv))
			}
		default:
			t.Errorf("call to %#x", target)
		}
		// The callee may change every caller-saved register.
		for i := 0; i < 18; i++ {
			m.x[i] = 0xDEAD_0000 + uint64(i)
		}
		if r.onCallee != nil {
			r.onCallee(m, target)
		}
	}
	return r
}

// onCallee is set by a test to act as the kernel during a call.

func (r *spillRig) state() uint32         { return r.m.get32(rigSysm + winOffState) }
func (r *spillRig) setState(s uint32)     { r.m.put32(rigSysm+winOffState, s) }
func (r *spillRig) stubWaiter() uint32    { return r.m.get32(rigSysm + winOffStubWaiter) }
func (r *spillRig) sentryWaiter(v uint32) { r.m.put32(rigSysm+winOffSentryWaiter, v) }
func (r *spillRig) savedX(i int) uint64   { return r.m.get64(rigSysm + winOffX + 8*uint64(i)) }

// checkSaved verifies that the routine stored the guest state in the sysmsg.
func (r *spillRig) checkSaved(t *testing.T) {
	t.Helper()
	for i := 0; i < 31; i++ {
		if got := r.savedX(i); got != r.guest[i] {
			t.Errorf("saved x%d = %#x, want %#x", i, got, r.guest[i])
		}
	}
	if got := r.m.get64(rigSysm + winOffSP); got != rigStack {
		t.Errorf("saved sp = %#x, want %#x", got, uint64(rigStack))
	}
	if got := r.m.get64(rigSysm + winOffNZCV); got != 0xa000_0000 {
		t.Errorf("saved nzcv = %#x, want %#x", got, uint64(0xa000_0000))
	}
	if got := r.m.get64(rigSysm + winOffTail); got != rigTail {
		t.Errorf("saved tail = %#x, want %#x", got, uint64(rigTail))
	}
}

// checkHotExit verifies a hot return: the routine branched to the tail with
// the registers of the sysmsg and wrote x16 and x17 to the scratch words.
func (r *spillRig) checkHotExit(t *testing.T, want [31]uint64) {
	t.Helper()
	m := r.m
	if m.exit.brk != -1 || m.exit.jump != rigTail {
		t.Fatalf("the routine ended with brk %d, jump %#x; want a jump to the tail %#x", m.exit.brk, m.exit.jump, uint64(rigTail))
	}
	// The tail loads x16 and x17 from the scratch words of the sysmsg.
	m.x[16], m.x[17] = m.get64(rigSysm+winOffScratch), m.get64(rigSysm+winOffScratch+8)
	for i := 0; i < 31; i++ {
		if m.x[i] != want[i] {
			t.Errorf("x%d = %#x after the return, want %#x", i, m.x[i], want[i])
		}
	}
	if m.sp != r.m.get64(rigSysm+winOffSP) {
		t.Errorf("sp = %#x after the return, want %#x", m.sp, r.m.get64(rigSysm+winOffSP))
	}
	if got := m.nzcvWord(); got != r.m.get64(rigSysm+winOffNZCV) {
		t.Errorf("flags = %#x after the return, want %#x", got, r.m.get64(rigSysm+winOffNZCV))
	}
}

func TestSpillSpinHit(t *testing.T) {
	r := newSpillRig(t)
	m := r.m
	want := r.guest
	want[0] = 42 // The system call result.
	m.onYield = func(m *a64Machine) {
		if r.state() != winStateTrapped {
			t.Errorf("state while the stub polls = %d, want Trapped", r.state())
		}
		if m.yields == 3 {
			r.checkSaved(t)
			m.put64(rigSysm+winOffX, 42)
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
	r.checkHotExit(t, want)
}

func TestSpillWakesSleepingSentry(t *testing.T) {
	r := newSpillRig(t)
	r.sentryWaiter(1)
	r.m.onYield = func(m *a64Machine) {
		if len(r.callLog) != 1 || r.callLog[0] != "set" {
			t.Errorf("calls before the first poll = %v, want one NtSetEvent", r.callLog)
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest)
}

func TestSpillSleepsWhenSpinExpires(t *testing.T) {
	r := newSpillRig(t)
	m := r.m
	want := r.guest
	want[0] = 7
	r.onCallee = func(m *a64Machine, target uint64) {
		if target != rigWaitFn {
			return
		}
		if r.stubWaiter() != 1 {
			t.Error("the stub slept without StubWaiter")
		}
		if r.state() != winStateTrapped {
			t.Errorf("state at the wait = %d, want Trapped", r.state())
		}
		m.put64(rigSysm+winOffX, 7)
		r.setState(winStateRunHot)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if m.yields != winSpinStub {
		t.Errorf("the stub polled %d times, want %d", m.yields, winSpinStub)
	}
	if len(r.callLog) != 1 || r.callLog[0] != "wait" {
		t.Fatalf("calls = %v, want one NtWaitForSingleObject", r.callLog)
	}
	if r.stubWaiter() != 0 {
		t.Error("the stub left StubWaiter set after it woke")
	}
	r.checkSaved2(t)
	r.checkHotExit(t, want)
}

// checkSaved2 verifies the registers that the routine saved, except x0, which
// the test changes during the wait.
func (r *spillRig) checkSaved2(t *testing.T) {
	t.Helper()
	for i := 1; i < 31; i++ {
		if got := r.savedX(i); got != r.guest[i] {
			t.Errorf("saved x%d = %#x, want %#x", i, got, r.guest[i])
		}
	}
}

func TestSpillSkipsSleepWhenStateArrivesAfterFlag(t *testing.T) {
	r := newSpillRig(t)
	m := r.m
	// The second barrier follows the store of StubWaiter. The Sentry publishes
	// the state right there, so the test after the barrier must see it.
	m.onFence = func(m *a64Machine) {
		if m.fences == 2 {
			if r.stubWaiter() != 1 {
				t.Error("the second barrier does not follow the StubWaiter store")
			}
			r.setState(winStateRunHot)
		}
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if len(r.callLog) != 0 {
		t.Fatalf("the stub called %v although the state had arrived", r.callLog)
	}
	if r.stubWaiter() != 0 {
		t.Error("the stub left StubWaiter set")
	}
	r.checkHotExit(t, r.guest)
}

func TestSpillSleepsAgainAfterStaleWake(t *testing.T) {
	r := newSpillRig(t)
	waits := 0
	r.onCallee = func(m *a64Machine, target uint64) {
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
	r.checkHotExit(t, r.guest)
}

func TestSpillHotReturnWritesGuestX16X17ToScratch(t *testing.T) {
	r := newSpillRig(t)
	m := r.m
	want := r.guest
	want[16], want[17] = 0xAAAA, 0xBBBB
	m.onYield = func(m *a64Machine) {
		m.put64(rigSysm+winOffX+8*16, 0xAAAA)
		m.put64(rigSysm+winOffX+8*17, 0xBBBB)
		// The scratch words hold stale values.
		m.put64(rigSysm+winOffScratch, 0)
		m.put64(rigSysm+winOffScratch+8, 0)
		r.setState(winStateRunHot)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, want)
}

func TestSpillColdReturnLoadsEveryRegisterAndTraps(t *testing.T) {
	r := newSpillRig(t)
	m := r.m
	var want [31]uint64
	for i := range want {
		want[i] = 0x7000_0000 + uint64(i)
	}
	const newSP, newNZCV = 0x7ff0_0500_0000, 0x4000_0000
	m.onYield = func(m *a64Machine) {
		for i, v := range want {
			m.put64(rigSysm+winOffX+8*uint64(i), v)
		}
		m.put64(rigSysm+winOffSP, newSP)
		m.put64(rigSysm+winOffNZCV, newNZCV)
		r.setState(winStateRunCold)
	}
	if err := m.run(100000); err != nil {
		t.Fatal(err)
	}
	if m.exit.brk != brkFastExit || m.pc != rigCode+uint64(r.sc.coldBrk) {
		t.Fatalf("the routine ended with brk %#x at %#x, want brk %#x at %#x", m.exit.brk, m.pc, brkFastExit, rigCode+uint64(r.sc.coldBrk))
	}
	for i := 0; i < 31; i++ {
		if m.x[i] != want[i] {
			t.Errorf("x%d = %#x at the trap, want %#x", i, m.x[i], want[i])
		}
	}
	if m.sp != newSP {
		t.Errorf("sp = %#x at the trap, want %#x", m.sp, uint64(newSP))
	}
	if got := m.nzcvWord(); got != newNZCV {
		t.Errorf("flags = %#x at the trap, want %#x", got, uint64(newNZCV))
	}
}

func TestSpillColdReturnAfterSleep(t *testing.T) {
	r := newSpillRig(t)
	r.onCallee = func(m *a64Machine, target uint64) {
		if target == rigWaitFn {
			r.setState(winStateRunCold)
		}
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	if r.m.exit.brk != brkFastExit {
		t.Fatalf("the routine ended with brk %d, want %#x", r.m.exit.brk, brkFastExit)
	}
	// The sysmsg held the guest registers, so the trap reproduces them.
	for i := 0; i < 31; i++ {
		if r.m.x[i] != r.guest[i] {
			t.Errorf("x%d = %#x at the trap, want %#x", i, r.m.x[i], r.guest[i])
		}
	}
}

func TestWinSlotReachesSpillAndReturnsAfterSite(t *testing.T) {
	const (
		site   = 0x7ff0_1000_0100
		slot   = 0x7ff0_1100_0040
		spill  = rigCode
		retPC  = site + 4
		tailVA = slot + winSlotTailOffset
	)
	buf := make([]byte, winSlotSize)
	if err := encodeWinSlot(buf, slot, site, spill); err != nil {
		t.Fatal(err)
	}
	word, err := encodeBranch(site, slot)
	if err != nil {
		t.Fatal(err)
	}
	if to, ok := decodeBranch(site, word); !ok || to != slot {
		t.Fatalf("the site branch targets %#x, want the slot %#x", to, uint64(slot))
	}
	// Run the slot. It ends in a BR to the spill routine, which it entered
	// with x17 set to the tail.
	const guestX18 = 0x1818_1818_1818_1818
	m := newA64Machine(buf, slot)
	m.sp = rigStack
	m.tpidr = rigSysm
	m.x[16], m.x[17], m.x[18] = rigGuestX16, rigGuestX17, guestX18
	m.put64(rigSysm+winOffX18, guestX18)
	for i, b := range buf {
		m.mem[slot+uint64(i)] = b
	}
	if err := m.run(100); err != nil {
		t.Fatal(err)
	}
	if m.exit.jump != spill {
		t.Fatalf("the slot jumped to %#x, want the spill routine %#x", m.exit.jump, uint64(spill))
	}
	if m.x[17] != tailVA {
		t.Fatalf("x17 = %#x at the jump, the tail is %#x", m.x[17], uint64(tailVA))
	}
	if m.x[18] != guestX18 {
		t.Fatalf("x18 = %#x at the jump, want %#x", m.x[18], uint64(guestX18))
	}
	if m.get64(rigSysm+winOffScratch) != rigGuestX16 || m.get64(rigSysm+winOffScratch+8) != rigGuestX17 {
		t.Fatal("the slot did not save x16 and x17 in the sysmsg scratch words")
	}
	// The tail restores x16, x17, and x18 and branches to the instruction after the site.
	m.x[16], m.x[17], m.x[18] = 0, 0, 0
	m.pc, m.exit = tailVA, a64Exit{brk: -1}
	if err := m.run(m.steps + 100); err != nil {
		t.Fatal(err)
	}
	if m.exit.jump != retPC {
		t.Fatalf("the tail returns to %#x, want %#x", m.exit.jump, uint64(retPC))
	}
	if m.x[16] != rigGuestX16 || m.x[17] != rigGuestX17 || m.x[18] != guestX18 {
		t.Fatalf("the tail restored x16 %#x, x17 %#x, x18 %#x", m.x[16], m.x[17], m.x[18])
	}
}

func TestWinX18SetSlotUpdatesSysmsgAndHardwareX18(t *testing.T) {
	const (
		site = 0x7ff0_1000_0240
		slot = 0x7ff0_1100_0140
	)
	for _, reg := range []uint8{0, 1, 17, 20, 31} {
		buf := make([]byte, winTLSSlotSize)
		if err := encodeWinX18SetSlot(buf, slot, site, reg); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		m := newA64Machine(buf, slot)
		for i := range m.x {
			m.x[i] = 0x9000 + uint64(i)
		}
		var wantX18 uint64
		if reg != 31 {
			wantX18 = m.x[reg]
		}
		want := m.x
		want[18] = wantX18
		m.sp = rigStack
		m.tpidr = rigSysm
		if err := m.run(10); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		if m.exit.jump != site+winSiteLen {
			t.Errorf("x%d: the slot returns to %#x, want %#x", reg, m.exit.jump, uint64(site+winSiteLen))
		}
		if m.x != want {
			t.Errorf("x%d: registers mismatch: got x18=%#x want=%#x", reg, m.x[18], wantX18)
		}
		if got := m.get64(rigSysm + winOffX18); got != wantX18 {
			t.Errorf("x%d: sysmsg.X18 = %#x, want %#x", reg, got, wantX18)
		}
	}
}

func TestWinTLSSlotLoadsTheVirtualThreadPointer(t *testing.T) {
	const (
		site = 0x7ff0_1000_0200
		slot = 0x7ff0_1100_0100
		tls  = 0x7ff0_0500_0abc
	)
	for _, reg := range []uint8{0, 5, 17, 18, 29, 30} {
		buf := make([]byte, winTLSSlotSize)
		if err := encodeWinTLSSlot(buf, slot, site, reg); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		m := newA64Machine(buf, slot)
		for i := range m.x {
			m.x[i] = 0x5000 + uint64(i)
		}
		want := m.x
		want[reg] = tls
		m.sp = rigStack
		m.n, m.z, m.c, m.v = true, false, true, true
		// The real TPIDR_EL0 names the sysmsg, and the TLS word holds the guest value.
		m.tpidr = rigSysm
		m.put64(rigSysm+winOffTLS, tls)
		if err := m.run(10); err != nil {
			t.Fatalf("x%d: %v", reg, err)
		}
		if m.exit.jump != site+winSiteLen {
			t.Errorf("x%d: the slot returns to %#x, want %#x", reg, m.exit.jump, uint64(site+winSiteLen))
		}
		if m.x != want {
			t.Errorf("x%d: the slot changed a register other than its destination", reg)
		}
		if m.sp != rigStack || !m.n || m.z || !m.c || !m.v {
			t.Errorf("x%d: the slot changed sp or the flags", reg)
		}
	}
	if err := encodeWinTLSSlot(make([]byte, winTLSSlotSize), slot, site, 31); err == nil {
		t.Error("a slot for xzr was accepted")
	}
}

// guestVector returns the vector register value that the rig gives the guest.
func guestVector(n, half int) uint64 { return uint64(0xA000+n)<<8 | uint64(half) }

const (
	rigGuestFpsr = 0x11
	rigGuestFpcr = 0x22
)

// armVectors makes the guest vector registers and the clobber of every call.
func (r *spillRig) armVectors() {
	m := r.m
	for n := range m.vec {
		m.vec[n] = [2]uint64{guestVector(n, 0), guestVector(n, 1)}
	}
	m.fpsr, m.fpcr = rigGuestFpsr, rigGuestFpcr
	prev := m.onCall
	m.onCall = func(m *a64Machine, target uint64) {
		prev(m, target)
		// The volatile vector registers of the Windows ARM64 ABI.
		for n := range m.vec {
			if n < 8 || n >= 16 {
				m.vec[n] = [2]uint64{0, 0}
			}
		}
	}
}

func (r *spillRig) checkVectorsAre(t *testing.T, when string, want func(n, half int) uint64, fpsr, fpcr uint64) {
	t.Helper()
	for n := range r.m.vec {
		for h := range 2 {
			if got := r.m.vec[n][h]; got != want(n, h) {
				t.Errorf("%s: v%d half %d = %#x, want %#x", when, n, h, got, want(n, h))
			}
		}
	}
	if r.m.fpsr != fpsr || r.m.fpcr != fpcr {
		t.Errorf("%s: fpsr %#x fpcr %#x, want %#x %#x", when, r.m.fpsr, r.m.fpcr, fpsr, fpcr)
	}
}

func TestSpillSavesVectorStateForTheSentry(t *testing.T) {
	r := newSpillRig(t)
	r.armVectors()
	r.m.onYield = func(m *a64Machine) {
		for n := range 32 {
			for h := range 2 {
				got := m.read(rigSysm+winOffVec+uint64(16*n+8*h), 8)
				if got != guestVector(n, h) {
					t.Errorf("saved v%d half %d = %#x, want %#x", n, h, got, guestVector(n, h))
				}
			}
		}
		if got := m.read(rigSysm+winOffFpsr, 8); got != rigGuestFpsr {
			t.Errorf("saved fpsr = %#x", got)
		}
		if got := m.read(rigSysm+winOffFpcr, 8); got != rigGuestFpcr {
			t.Errorf("saved fpcr = %#x", got)
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
}

func TestSpillKeepsVectorStateAcrossItsOwnSystemCalls(t *testing.T) {
	// The routine calls NtSetEvent when the Sentry sleeps and
	// NtWaitForSingleObject when the stub sleeps. Windows can clobber the
	// volatile vector registers in both calls.
	for _, resume := range []uint32{winStateRunHot, winStateRunCold} {
		r := newSpillRig(t)
		r.armVectors()
		r.sentryWaiter(1)
		r.onCallee = func(m *a64Machine, target uint64) {
			if target == rigWaitFn {
				r.setState(resume)
			}
		}
		if err := r.m.run(100000); err != nil {
			t.Fatal(err)
		}
		if len(r.callLog) != 2 {
			t.Fatalf("calls = %v, want NtSetEvent and NtWaitForSingleObject", r.callLog)
		}
		r.checkVectorsAre(t, "after both calls", guestVector, rigGuestFpsr, rigGuestFpcr)
	}
}

func TestSpillLoadsVectorStateThatTheSentryWrote(t *testing.T) {
	changed := func(n, h int) uint64 { return 0xC0DE0000 + uint64(n)<<4 + uint64(h) }
	for _, resume := range []uint32{winStateRunHot, winStateRunCold} {
		r := newSpillRig(t)
		r.armVectors()
		r.m.onYield = func(m *a64Machine) {
			for n := range 32 {
				for h := range 2 {
					m.write(rigSysm+winOffVec+uint64(16*n+8*h), 8, changed(n, h))
				}
			}
			m.write(rigSysm+winOffFpsr, 8, 0x33)
			m.write(rigSysm+winOffFpcr, 8, 0x44)
			// The Sentry marks every write of the vector block.
			m.put32(rigSysm+winOffFPDirty, 1)
			r.setState(resume)
		}
		if err := r.m.run(100000); err != nil {
			t.Fatal(err)
		}
		r.checkVectorsAre(t, "resume", changed, 0x33, 0x44)
		if got := r.m.get32(rigSysm + winOffFPDirty); got != 0 {
			t.Errorf("FPDirty = %d after the load, want 0", got)
		}
	}
}

func TestSpillLoadsTheVectorStateOnlyWhenTheRegistersCanDiffer(t *testing.T) {
	changed := func(n, h int) uint64 { return 0xC0DE0000 + uint64(n)<<4 + uint64(h) }
	for _, c := range []struct {
		name        string
		dirty       uint32
		sentryWaits bool
		resume      uint32
		loaded      bool
	}{
		{"hot spin hit with a clean block skips the load", 0, false, winStateRunHot, false},
		{"hot spin hit with a dirty block loads it", 1, false, winStateRunHot, true},
		{"hot resume after a call loads the block", 0, true, winStateRunHot, true},
		{"cold resume loads the block", 0, false, winStateRunCold, true},
		{"cold resume with a dirty block loads it", 1, false, winStateRunCold, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newSpillRig(t)
			r.armVectors()
			if c.sentryWaits {
				r.sentryWaiter(1)
			}
			r.m.onYield = func(m *a64Machine) {
				if r.state() != winStateTrapped {
					return
				}
				// The Sentry writes a block that differs from the live registers.
				// A clean block would be a bug of the Sentry, which the test uses to
				// see whether the routine loads it.
				for n := range 32 {
					for h := range 2 {
						m.write(rigSysm+winOffVec+uint64(16*n+8*h), 8, changed(n, h))
					}
				}
				m.write(rigSysm+winOffFpsr, 8, 0x33)
				m.write(rigSysm+winOffFpcr, 8, 0x44)
				m.put32(rigSysm+winOffFPDirty, c.dirty)
				r.setState(c.resume)
			}
			if err := r.m.run(100000); err != nil {
				t.Fatal(err)
			}
			if c.loaded {
				r.checkVectorsAre(t, "resume", changed, 0x33, 0x44)
				if got := r.m.get32(rigSysm + winOffFPDirty); got != 0 {
					t.Errorf("FPDirty = %d after the load, want 0", got)
				}
			} else {
				r.checkVectorsAre(t, "resume", guestVector, rigGuestFpsr, rigGuestFpcr)
				if got := r.m.get32(rigSysm + winOffFPDirty); got != c.dirty {
					t.Errorf("FPDirty = %d after a resume without a load, want %d", got, c.dirty)
				}
			}
		})
	}
}

func TestSpillCallFlagIsNotTheGuestX21(t *testing.T) {
	// The routine keeps its call flag in x21 after it saved the guest registers.
	// A guest x21 of 1 must not make a spin hit load the block, and the resume
	// must return the guest x21.
	changed := func(n, h int) uint64 { return 0xC0DE0000 + uint64(n)<<4 + uint64(h) }
	r := newSpillRig(t)
	r.armVectors()
	r.m.x[21] = 1
	r.guest[21] = 1
	r.m.onYield = func(m *a64Machine) {
		if r.state() != winStateTrapped {
			return
		}
		for n := range 32 {
			for h := range 2 {
				m.write(rigSysm+winOffVec+uint64(16*n+8*h), 8, changed(n, h))
			}
		}
		r.setState(winStateRunHot)
	}
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkVectorsAre(t, "resume", guestVector, rigGuestFpsr, rigGuestFpcr)
	r.checkHotExit(t, r.guest)
}

func TestWinSysmsgVectorBlockMatchesTheFloatingPointState(t *testing.T) {
	src := newTrapContext()
	state := *src.FloatingPointData()
	for i := range state[fpStateOffV : fpStateOffV+32*16] {
		state[fpStateOffV+i] = byte(i*7 + 1)
	}
	binary.LittleEndian.PutUint32(state[fpStateOffFpsr:], 0xAB)
	binary.LittleEndian.PutUint32(state[fpStateOffFpcr:], 0xCD)

	var sm winSysmsg
	sm.loadVector(src)
	if sm.Vec[0] != 1 || sm.Vec[16] != byte(16*7+1) || sm.Fpsr != 0xAB || sm.Fpcr != 0xCD {
		t.Fatalf("loadVector put v0 byte %#x, v1 byte %#x, fpsr %#x, fpcr %#x", sm.Vec[0], sm.Vec[16], sm.Fpsr, sm.Fpcr)
	}
	dst := arch.New(arch.Host)
	sm.storeVector(dst)
	got := *dst.FloatingPointData()
	if string(got[fpStateOffV:fpStateOffV+32*16]) != string(state[fpStateOffV:fpStateOffV+32*16]) {
		t.Error("the vector registers differ after the round trip")
	}
	if binary.LittleEndian.Uint32(got[fpStateOffFpsr:]) != 0xAB || binary.LittleEndian.Uint32(got[fpStateOffFpcr:]) != 0xCD {
		t.Error("fpsr or fpcr differ after the round trip")
	}
}

func TestSpillWithoutVectorStateSkipsTheImage(t *testing.T) {
	full, err := buildSpill()
	if err != nil {
		t.Fatal(err)
	}
	r := newSpillRigWith(t, spillOptions{noVector: true})
	if len(r.sc.code) >= len(full.code) {
		t.Errorf("the routine without the vector state has %d bytes, the full routine %d", len(r.sc.code), len(full.code))
	}
	r.m.onYield = func(m *a64Machine) { r.setState(winStateRunHot) }
	if err := r.m.run(100000); err != nil {
		t.Fatal(err)
	}
	r.checkHotExit(t, r.guest)
	for off := uint64(winOffVec); off < winOffVec+32*16; off += 8 {
		if got := r.m.get64(rigSysm + off); got != 0 {
			t.Fatalf("the routine wrote the vector image at offset %#x", off)
		}
	}
	for _, off := range []uint64{winOffFpsr, winOffFpcr} {
		if got := r.m.get64(rigSysm + off); got != 0 {
			t.Fatalf("the routine wrote the control word at offset %#x", off)
		}
	}
}
