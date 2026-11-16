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

//go:build arm64

package whpx

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/usermem"
)

func setFakeVPReg128(fb *fakeBackend, index uint32, name uint32, lo, hi uint64) {
	fb.mu.Lock()
	vp := fb.vps[index]
	fb.mu.Unlock()
	vp.mu.Lock()
	vp.regs[name] = [2]uint64{lo, hi}
	vp.mu.Unlock()
}

func getFakeVPReg128(vp *fakeVP, name uint32) (uint64, uint64) {
	vp.mu.Lock()
	defer vp.mu.Unlock()
	pair := vp.regs[name]
	return pair[0], pair[1]
}

// TestA64FPSurvivesSignalDeliveryAndRestore exercises the real Sentry ARM64
// Linux signal frame producer (Context64.SignalSetup and SignalRestore) across
// WHPX PullFullState, FullStateChanged, and Switch calls.
func TestA64FPSurvivesSignalDeliveryAndRestore(t *testing.T) {
	e := newA64Env(t, 1)
	c, ac := e.newContext()

	r := &ac.StateData().Regs
	r.Sp = 0x4000
	r.Pc = 0x400100
	r.Pstate = linux.PSR_MODE_EL0t

	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 0x400104, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatalf("initial Switch: %v", err)
	}

	const (
		wantFPCR = uint64(0x0100_0000)
		wantFPSR = uint64(0x0800_0010)
	)
	var wantQ [32][2]uint64
	for i := range 32 {
		lo := uint64(0xDEAD_BEEF_CAFE_0000) | uint64(i)
		hi := uint64(0x1122_3344_5566_0000) | uint64(i)
		wantQ[i] = [2]uint64{lo, hi}
		setFakeVPReg128(e.fb, 0, a64RegQ0+uint32(i), lo, hi)
	}
	e.fb.setReg(0, a64RegFpcr, wantFPCR)
	e.fb.setReg(0, a64RegFpsr, wantFPSR)

	if err := c.PullFullState(e.as, ac); err != nil {
		t.Fatalf("PullFullState before SignalSetup: %v", err)
	}
	stackBuf := make([]byte, 1<<14)
	st := &arch.Stack{
		Arch:   ac,
		IO:     &usermem.BytesIO{Bytes: stackBuf},
		Bottom: hostarch.Addr(len(stackBuf)),
	}
	act := &linux.SigAction{Handler: 0x500000, Restorer: 0x600000}
	info := &linux.SignalInfo{Signo: int32(linux.SIGURG)}
	if err := ac.SignalSetup(st, act, info, &linux.SignalStack{}, 0, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalSetup: %v", err)
	}
	c.FullStateChanged()

	// Verify the Linux ucontext written onto the guest stack holds the exact
	// FPSR, FPCR, and 128-bit V0 to V31 values captured from the WHPX vCPU.
	var uc arch.UContext64
	uc.UnmarshalBytes(stackBuf[st.Bottom:])
	sigFP := uc.MContext.Fpsimd64
	if uint64(sigFP.Fpsr) != wantFPSR || uint64(sigFP.Fpcr) != wantFPCR {
		t.Fatalf("signal frame FPSR=%#x FPCR=%#x, want FPSR=%#x FPCR=%#x", sigFP.Fpsr, sigFP.Fpcr, wantFPSR, wantFPCR)
	}
	for i := range 32 {
		gotLo, gotHi := sigFP.Vregs[2*i], sigFP.Vregs[2*i+1]
		if gotLo != wantQ[i][0] || gotHi != wantQ[i][1] {
			t.Fatalf("signal frame V%d = %#x:%#x, want %#x:%#x", i, gotHi, gotLo, wantQ[i][1], wantQ[i][0])
		}
	}

	// Verify the handler enters with clean zeroed Q0 to Q31 registers (including Q31.hi),
	// then rewrite the signal frame with distinct Linux fpsimd_context values and
	// verify SignalRestore loads FPCR, FPSR, and V0 to V31 into WHPX without
	// aliasing V0.lo into FPCR or setting upper RES0 bits.
	var handlerQ31Hi uint64
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		_, handlerQ31Hi = getFakeVPReg128(vp, a64RegQ0+31)
		e.svc(vp, exit, 0x600004, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatalf("handler Switch: %v", err)
	}
	if handlerQ31Hi != 0 {
		t.Fatalf("handler entered with leaked Q31.hi = %#x, want 0", handlerQ31Hi)
	}

	uc.MContext.Fpsimd64.Fpsr = 0x1000_0005
	uc.MContext.Fpsimd64.Fpcr = 0x0200_0000
	for i := range 32 {
		uc.MContext.Fpsimd64.Vregs[2*i] = 0xFEED_FACE_8888_0000 | uint64(i)
		uc.MContext.Fpsimd64.Vregs[2*i+1] = 0xCAFE_F00D_9999_0000 | uint64(i)
	}
	uc.MarshalBytes(stackBuf[st.Bottom:])

	stRestore := &arch.Stack{
		Arch:   ac,
		IO:     &usermem.BytesIO{Bytes: stackBuf},
		Bottom: st.Bottom,
	}
	if _, _, err := ac.SignalRestore(stRestore, false, cpuid.FeatureSet{}); err != nil {
		t.Fatalf("SignalRestore: %v", err)
	}
	c.FullStateChanged()

	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 0x400108, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatalf("post-sigreturn Switch: %v", err)
	}

	vp := e.fb.vps[0]
	if got := vp.reg(a64RegFpcr); got != 0x0200_0000 {
		t.Fatalf("post-sigreturn WHPX FPCR = %#x, want 0x2000000 (must not load V0.lo into FPCR)", got)
	}
	if got := vp.reg(a64RegFpsr); got != 0x1000_0005 {
		t.Fatalf("post-sigreturn WHPX FPSR = %#x, want 0x10000005 (upper 32 RES0 bits must stay zero)", got)
	}
	for i := range 32 {
		lo, hi := getFakeVPReg128(vp, a64RegQ0+uint32(i))
		wantLo := uint64(0xFEED_FACE_8888_0000) | uint64(i)
		wantHi := uint64(0xCAFE_F00D_9999_0000) | uint64(i)
		if lo != wantLo || hi != wantHi {
			t.Fatalf("post-sigreturn WHPX Q%d = %#x:%#x, want %#x:%#x", i, hi, lo, wantHi, wantLo)
		}
	}
}
