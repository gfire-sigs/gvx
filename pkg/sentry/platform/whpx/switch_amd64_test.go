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

//go:build amd64

package whpx

import (
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// sentryFPLimit returns the size of the Sentry floating-point image of this
// host. The vector selection of a test platform must fit the arch.Context64
// images that the test builds.
func sentryFPLimit() int {
	cpuid.Initialize()
	return len(arch.New(arch.AMD64).FloatingPointData().Slice())
}

// x64Env is a platform on a fake backend with one address space.
type x64Env struct {
	t  *testing.T
	fb *fakeBackend
	p  *Platform
	as *AddressSpace
	mm *fakeMM
}

func newX64Env(t *testing.T, vps int) *x64Env {
	t.Helper()
	cpuid.Initialize()
	fb := newFakeBackend()
	// newContext gives every Context an image of testFPLimit bytes, so the
	// AVX-512 selection holds on every host.
	p := newTestPlatform(t, fb, Options{xsaveLayout: testXsaveLayout(), fpLimit: testFPLimit})
	if vps > 0 {
		limitVPs(p, vps)
	}
	as := newTestAS(t, p)
	return &x64Env{t: t, fb: fb, p: p, as: as, mm: &fakeMM{as: as}}
}

// newContext returns a Context and an arch.Context64 whose floating-point
// image holds the AVX-512 state of the test layout. The image of arch.New
// follows the CPU of the host, which can lack XSAVE.
func (e *x64Env) newContext() (*Context, *arch.Context64) {
	ac := arch.New(arch.AMD64)
	img := make([]byte, testFPLimit+4)
	copy(img, ac.FloatingPointData().Slice()[:xsaveLegacySize])
	binary.LittleEndian.PutUint64(img[xsaveOffXstateBV:], xcr0Legacy)
	*ac.FloatingPointData() = img
	return e.p.NewContext(nil).(*Context), ac
}

func (e *x64Env) comm(vp *fakeVP) *CommPage { return e.p.kernel.commPage(int(vp.index)) }

func (e *x64Env) reload() uint64 {
	return e.p.kernel.layout.code() + uint64(e.p.kernel.x64.Reload)
}

func (e *x64Env) switchTo(c *Context, ac *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	return c.Switch(nil, e.mm, ac, -1)
}

// syscall simulates the SYSCALL entry stub: it spills the registers and
// halts at the HLT of the entry path.
func (e *x64Env) syscall(vp *fakeVP, exit []byte, rip, rflags uint64, mutate func(c *CommPage)) {
	c := e.comm(vp)
	c.Regs[1], c.Regs[11] = rip, rflags
	if mutate != nil {
		mutate(c)
	}
	atomic.StoreUint32(&c.ExitReason, uint32(ExitSyscall))
	writeStubExit(exit, e.p.kernel.layout.code()+uint64(e.p.kernel.x64.HltSyscall)+1)
}

// exception simulates the exception stub.
func (e *x64Env) exception(vp *fakeVP, exit []byte, vector, errCode, cr2, rip uint64) {
	c := e.comm(vp)
	c.Vector, c.ESR, c.FaultAddr, c.PC = vector, errCode, cr2, rip
	c.Pstate, c.CS, c.SS = 0x246, x64SelUserCS, x64SelUserSS
	atomic.StoreUint32(&c.ExitReason, uint32(ExitException))
	writeStubExit(exit, e.p.kernel.layout.code()+uint64(e.p.kernel.x64.HltException)+1)
}

func TestSwitchSyscallRoundTripAndResumeProtocol(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rax, r.Rbx, r.Rdx, r.Rsi, r.Rdi, r.Rbp = 1, 2, 3, 4, 5, 6
	r.R8, r.R9, r.R10, r.R12, r.R13, r.R14, r.R15 = 8, 9, 10, 12, 13, 14, 15
	r.Rip, r.Rsp, r.Eflags = 0x400000, 0x7FFF0000, 0x246
	r.Rcx, r.R11 = r.Rip, r.Eflags // Hardware state after a system call.
	r.Fs_base, r.Gs_base = 0x7F0000001000, 0x7F0000002000

	var saw []CommPage
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		saw = append(saw, *e.comm(vp))
		e.syscall(vp, exit, 0x400002, 0x246, func(c *CommPage) {
			c.Regs[0] = 0xAA
			c.Regs[15] = 0xFF
			c.SP = 0x7FFEFFF0
		})
		return nil
	}
	sig, _, err := e.switchTo(c, ac)
	if err != nil || sig != nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	first := saw[0]
	for idx, want := range map[int]uint64{0: 1, 1: 0x400000, 2: 3, 3: 2, 5: 6, 6: 4, 7: 5, 8: 8, 9: 9, 10: 10, 11: 0x246, 12: 12, 13: 13, 14: 14, 15: 15} {
		if first.Regs[idx] != want {
			t.Errorf("CommPage.Regs[%d] is %#x, want %#x", idx, first.Regs[idx], want)
		}
	}
	if first.SP != 0x7FFF0000 || first.PC != 0x400000 || first.Pstate != 0x246 {
		t.Errorf("SP %#x PC %#x RFLAGS %#x", first.SP, first.PC, first.Pstate)
	}
	if first.Flags != flagReloadRoot {
		t.Errorf("flags are %#x: SYSRET is correct and the first entry flushes", first.Flags)
	}
	if first.Root != e.as.rootValue() {
		t.Errorf("CR3 value is %#x, want %#x", first.Root, e.as.rootValue())
	}
	if r.Rax != 0xAA || r.R15 != 0xFF || r.Rsp != 0x7FFEFFF0 || r.Rip != 0x400002 || r.Eflags != 0x246 ||
		r.Rcx != 0x400002 || r.R11 != 0x246 || r.Orig_rax != 0xAA || r.Rbx != 2 {
		t.Errorf("registers after the syscall: rax=%#x rip=%#x rcx=%#x orig=%#x", r.Rax, r.Rip, r.Rcx, r.Orig_rax)
	}

	vp := e.fb.vps[0]
	// Bring-up and the park state use registers; the FP load uses the XSAVE
	// state.
	if len(vp.setCalls) != 2 || vp.xsaveSets != 1 {
		t.Fatalf("%d register writes and %d XSAVE writes, want 2 and 1", len(vp.setCalls), vp.xsaveSets)
	}
	if vp.reg(x64RegRip) != e.reload() || vp.reg(x64RegKernelGsBase) != 0x7F0000002000 || vp.reg(x64RegInternalActivity) != 0 {
		t.Errorf("park state: rip=%#x kernelGsBase=%#x", vp.reg(x64RegRip), vp.reg(x64RegKernelGsBase))
	}
	if got := vp.regs[x64RegFs][0]; got != 0x7F0000001000 {
		t.Errorf("FS base is %#x", got)
	}
	if got := vp.regs[x64RegGs][0]; got != e.p.kernel.layout.comm(0) {
		t.Errorf("kernel GS base is %#x, want the CommPage address", got)
	}
	if vp.reg(x64RegRsp) != e.p.kernel.layout.comm(0)+commStackTop || vp.reg(x64RegRflags) != 2 {
		t.Errorf("RSP %#x RFLAGS %#x", vp.reg(x64RegRsp), vp.reg(x64RegRflags))
	}

	// The next system call resumes with two register writes.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		saw = append(saw, *e.comm(vp))
		e.syscall(vp, exit, 0x400004, 0x246, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if len(vp.setCalls) != 3 {
		t.Fatalf("%d register writes after the second call", len(vp.setCalls))
	}
	if resume := vp.setCalls[2]; len(resume) != 2 || resume[0] != x64RegRip || resume[1] != x64RegInternalActivity {
		t.Errorf("resume writes %#x, want RIP and the activity state", resume)
	}
	if saw[1].Flags != 0 {
		t.Errorf("second entry flags are %#x", saw[1].Flags)
	}
	if saw[1].Regs[1] != 0x400002 || saw[1].Regs[11] != 0x246 {
		t.Errorf("SYSRET registers RCX=%#x R11=%#x", saw[1].Regs[1], saw[1].Regs[11])
	}

	// A new FS base forces the full park state.
	r.Fs_base = 0x7F0000009000
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if len(vp.setCalls[3]) < 8 || vp.reg(x64RegKernelGsBase) != 0x7F0000002000 || vp.regs[x64RegFs][0] != 0x7F0000009000 {
		t.Errorf("FS base change gave writes %#x", vp.setCalls[3])
	}
}

func TestSwitchUsesIRETWhenRCXOrR11AreNotTheSyscallValues(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rsp, r.Eflags = 0x400000, 0x7FFF0000, 0x246
	r.Rcx, r.R11 = 0x1111, 0x2222 // For example after a page fault.
	var saw CommPage
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		saw = *e.comm(vp)
		e.syscall(vp, exit, 0x400002, 0x246, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if saw.Flags != flagReloadRoot|flagFullRestore {
		t.Errorf("flags are %#x, want a full restore", saw.Flags)
	}
	if saw.Regs[1] != 0x1111 || saw.Regs[11] != 0x2222 {
		t.Errorf("RCX=%#x R11=%#x, want the application values", saw.Regs[1], saw.Regs[11])
	}
	if saw.CS != x64SelUserCS || saw.SS != x64SelUserSS {
		t.Errorf("CS=%#x SS=%#x", saw.CS, saw.SS)
	}
}

func TestSwitchSanitizesFlagsAndRefusesBadState(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rsp = 0x400000, 0x7FFF0000
	r.Rcx, r.R11 = r.Rip, 0x3246 // IOPL set.
	r.Eflags = 0x3246
	var saw CommPage
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		saw = *e.comm(vp)
		e.syscall(vp, exit, 0x400002, 0x246, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if saw.Pstate != 0x246 || saw.Flags&flagFullRestore == 0 {
		t.Errorf("RFLAGS %#x flags %#x: IOPL must not reach user mode, and SYSRET would carry it", saw.Pstate, saw.Flags)
	}

	runs := e.fb.vps[0].runs
	for _, c2 := range []struct {
		name string
		edit func(r *arch.Registers)
	}{
		{"non-canonical RIP", func(r *arch.Registers) { r.Rip = 0x8000_0000_0000 }},
		{"kernel RIP", func(r *arch.Registers) { r.Rip = 0xFFFF_FFFF_8000_0000 }},
		{"kernel code selector", func(r *arch.Registers) { r.Cs = 0x10 }},
		{"stack selector", func(r *arch.Registers) { r.Ss = 0x18 }},
		{"unknown FS selector", func(r *arch.Registers) { r.Fs = 0x40 }},
	} {
		ac2 := arch.New(arch.AMD64)
		ac2.StateData().Regs = *r
		c2.edit(&ac2.StateData().Regs)
		sig, _, err := c.Switch(nil, e.mm, ac2, -1)
		if !errors.Is(err, platform.ErrContextSignal) || sig == nil || sig.Signo != int32(linux.SIGSEGV) {
			t.Errorf("%s: Switch returned %v, %v", c2.name, sig, err)
		}
	}
	if e.fb.vps[0].runs != runs {
		t.Error("the guest ran with invalid state")
	}
}

func TestSwitchPageFaultBecomesSignalAndResumesWithIRET(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rsp, r.Eflags = 0x400000, 0x7FFF0000, 0x246
	r.Rcx, r.R11 = r.Rip, r.Eflags
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.comm(vp).Regs[1], e.comm(vp).Regs[11] = 0x1234, 0x5678 // The application's own values.
		e.comm(vp).SP = 0x7FFEFFF0
		e.exception(vp, exit, hvcommon.X86VecPageFault, 0b00110, 0xDEAD000, 0x400040)
		return nil
	}
	sig, at, err := e.switchTo(c, ac)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	if sig.Signo != int32(linux.SIGSEGV) || sig.Code != hvcommon.SegvMapErr || !at.Write {
		t.Errorf("signal %d code %d access %+v", sig.Signo, sig.Code, at)
	}
	if got := binary.LittleEndian.Uint64(sig.Fields[0:8]); got != 0xDEAD000 {
		t.Errorf("si_addr is %#x", got)
	}
	if r.Rip != 0x400040 || r.Rsp != 0x7FFEFFF0 || r.Rcx != 0x1234 || r.R11 != 0x5678 || r.Cs != x64SelUserCS || r.Ss != x64SelUserSS {
		t.Errorf("state after the fault: rip=%#x rsp=%#x rcx=%#x r11=%#x", r.Rip, r.Rsp, r.Rcx, r.R11)
	}
	// RCX and R11 survived the fault, so the restart must use IRET.
	var saw CommPage
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		saw = *e.comm(vp)
		e.syscall(vp, exit, 0x400042, 0x246, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if saw.Flags&flagFullRestore == 0 || saw.Regs[1] != 0x1234 || saw.Regs[11] != 0x5678 || saw.PC != 0x400040 {
		t.Errorf("restart flags %#x rcx %#x r11 %#x pc %#x", saw.Flags, saw.Regs[1], saw.Regs[11], saw.PC)
	}
}

func TestSwitchRejectsUnexpectedExits(t *testing.T) {
	for _, c := range []struct {
		name   string
		script func(e *x64Env, vp *fakeVP, exit []byte)
	}{
		{"halt without a stub exit reason", func(e *x64Env, vp *fakeVP, exit []byte) {
			writeStubExit(exit, 0x1000)
		}},
		{"kernel fault", func(e *x64Env, vp *fakeVP, exit []byte) {
			cp := e.comm(vp)
			atomic.StoreUint32(&cp.ExitReason, uint32(ExitKernelFault))
			writeStubExit(exit, 0x1000)
		}},
		{"double fault", func(e *x64Env, vp *fakeVP, exit []byte) {
			e.exception(vp, exit, hvcommon.X86VecDoubleFault, 0, 0, 0x400000)
		}},
		{"triple fault", func(e *x64Env, vp *fakeVP, exit []byte) {
			binary.LittleEndian.PutUint32(exit, x64ExitUnrecoverable)
		}},
		{"port I/O", func(e *x64Env, vp *fakeVP, exit []byte) {
			binary.LittleEndian.PutUint32(exit, x64ExitIoPortAccess)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newX64Env(t, 0)
			ctx, ac := e.newContext()
			ac.StateData().Regs.Rip = 0x400000
			ac.StateData().Regs.Rcx = 0x400000
			ac.StateData().Regs.Eflags = 0x202
			ac.StateData().Regs.R11 = 0x202
			e.fb.onRun = func(vp *fakeVP, exit []byte) error {
				c.script(e, vp, exit)
				return nil
			}
			sig, _, err := e.switchTo(ctx, ac)
			if err == nil || sig != nil || errors.Is(err, platform.ErrContextSignal) || errors.Is(err, platform.ErrContextInterrupt) {
				t.Fatalf("Switch returned %v, %v, want a plain error", sig, err)
			}
			// The next entry parks from scratch.
			e.fb.onRun = func(vp *fakeVP, exit []byte) error {
				e.syscall(vp, exit, 0x400002, 0x202, nil)
				return nil
			}
			vp := e.fb.vps[0]
			before := len(vp.setCalls)
			if _, _, err := e.switchTo(ctx, ac); err != nil {
				t.Fatal(err)
			}
			if park := vp.setCalls[len(vp.setCalls)-1]; len(vp.setCalls) == before || len(park) < 8 {
				t.Errorf("no full park after a failed exit: %v", vp.setCalls[before:])
			}
		})
	}
}

func TestSwitchInterruptStopsUserCodeAndSavesState(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rsp, r.Eflags, r.Rcx, r.R11 = 0x400000, 0x7FFF0000, 0x246, 0x400000, 0x246
	e.fb.cancelExit = func(buf []byte) { writeCancelExit(buf, 3, 0x400100) }
	done := make(chan error)
	go func() {
		_, _, err := e.switchTo(c, ac)
		done <- err
	}()
	vp := e.fb.waitRunning(0)
	for i, name := range []uint32{x64RegRax, x64RegRcx, x64RegRdx, x64RegRbx, x64RegRsp, x64RegRbp, x64RegRsi, x64RegRdi,
		x64RegR8, x64RegR9, x64RegR10, x64RegR11, x64RegR12, x64RegR13, x64RegR14, x64RegR15} {
		e.fb.setReg(0, name, 0x9000+uint64(i))
	}
	e.fb.setReg(0, x64RegRip, 0x400100)
	e.fb.setReg(0, x64RegRflags, 0x10246)
	c.Interrupt()
	if err := <-done; !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch returned %v", err)
	}
	if r.Rax != 0x9000 || r.Rcx != 0x9001 || r.Rsp != 0x9004 || r.R15 != 0x900F || r.Rip != 0x400100 || r.Eflags != 0x10246 {
		t.Errorf("saved state: rax=%#x rsp=%#x r15=%#x rip=%#x flags=%#x", r.Rax, r.Rsp, r.R15, r.Rip, r.Eflags)
	}
	before := len(vp.setCalls)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, r.Rip+2, 0x246, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if park := vp.setCalls[len(vp.setCalls)-1]; len(vp.setCalls) == before || len(park) < 8 {
		t.Errorf("no full park after user code stopped: %v", vp.setCalls[before:])
	}
}

func TestSwitchCancelInsideTheStub(t *testing.T) {
	e := newX64Env(t, 0)
	code := e.p.kernel.layout.code()
	stubs := e.p.kernel.x64
	for _, c := range []struct {
		name      string
		rip       uint64
		interrupt bool
		wantErr   bool
	}{
		{"syscall entry", code + uint64(stubs.Entry) + 0x20, false, false},
		{"exception stub", code + uint64(stubs.ExcStubs) + 3*x64ExcStubSize, false, false},
		{"common path", code + uint64(stubs.Common) + 4, false, false},
		{"reload path", code + uint64(stubs.Reload) + 0x30, true, false},
		{"unknown address", code + 0xF00, true, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newX64Env(t, 0)
			ctx, ac := e.newContext()
			r := &ac.StateData().Regs
			r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
			calls := 0
			e.fb.onRun = func(vp *fakeVP, exit []byte) error {
				calls++
				if calls == 1 {
					return errBlockRun
				}
				e.syscall(vp, exit, 0x400002, 0x202, nil)
				return nil
			}
			e.fb.cancelExit = func(buf []byte) { writeCancelExit(buf, 0, c.rip) }
			done := make(chan error)
			go func() {
				_, _, err := e.switchTo(ctx, ac)
				done <- err
			}()
			e.fb.waitRunning(0)
			ctx.Interrupt()
			err := <-done
			switch {
			case c.wantErr:
				if err == nil || errors.Is(err, platform.ErrContextInterrupt) {
					t.Errorf("Switch returned %v, want a plain error", err)
				}
			case c.interrupt:
				if !errors.Is(err, platform.ErrContextInterrupt) || calls != 1 {
					t.Errorf("Switch returned %v after %d runs", err, calls)
				}
			default:
				if err != nil || calls != 2 {
					t.Errorf("Switch returned %v after %d runs, want the run to continue", err, calls)
				}
			}
		})
	}
}

func TestSwitchMemoryFaultAtCPL3IsSIGBUS(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.fb.setReg(0, x64RegRip, 0x400000) // The processor sits in user mode.
		clear(exit)
		binary.LittleEndian.PutUint32(exit[x64ExitOffReason:], x64ExitMemoryAccess)
		binary.LittleEndian.PutUint16(exit[x64ExitOffExecState:], 3)
		binary.LittleEndian.PutUint32(exit[x64ExitOffMemInfo:], 1|1<<2|1<<3)
		binary.LittleEndian.PutUint64(exit[x64ExitOffMemGpa:], 0x9000_0000)
		binary.LittleEndian.PutUint64(exit[x64ExitOffMemGva:], 0x7000)
		return nil
	}
	sig, at, err := e.switchTo(c, ac)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil || sig.Signo != int32(linux.SIGBUS) || sig.Code != hvcommon.BusAdrErr || !at.Write {
		t.Fatalf("Switch returned %+v, %+v, %v", sig, at, err)
	}
	if got := binary.LittleEndian.Uint64(sig.Fields[0:8]); got != 0x7000 {
		t.Errorf("si_addr is %#x", got)
	}
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		clear(exit)
		binary.LittleEndian.PutUint32(exit[x64ExitOffReason:], x64ExitMemoryAccess)
		return nil // CPL 0: the fault is inside the stub.
	}
	if _, _, err := e.switchTo(c, ac); err == nil || errors.Is(err, platform.ErrContextSignal) {
		t.Errorf("fault in the stub returned %v", err)
	}
}

// requireAVX skips a test on a host whose Sentry image has no room for the
// AVX state, because the platform then runs its guests without AVX.
func (e *x64Env) requireAVX() {
	e.t.Helper()
	if e.p.vec.xcr0&xcr0AVX == 0 {
		e.t.Skip("the Sentry floating-point image of this host has no room for the AVX state")
	}
}

// setImageVector stores YMMn in the Sentry image of ac and marks the SSE and
// AVX components live.
func setImageVector(ac *arch.Context64, n int, low, high uint64) {
	img := acImage(ac)
	binary.LittleEndian.PutUint64(img[fxOffXMM+16*n:], low)
	binary.LittleEndian.PutUint64(img[576+16*n:], high)
	bv := binary.LittleEndian.Uint64(img[xsaveOffXstateBV:])
	binary.LittleEndian.PutUint64(img[xsaveOffXstateBV:], bv|xcr0SSE|xcr0AVX)
}

// imageVector returns YMMn from the Sentry image of ac.
func imageVector(ac *arch.Context64, n int) (low, high uint64) {
	img := acImage(ac)
	return binary.LittleEndian.Uint64(img[fxOffXMM+16*n:]), binary.LittleEndian.Uint64(img[576+16*n:])
}

func TestBringUpEnablesTheSelectedVectorState(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, 0x400002, 0x202, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	if got := vp.reg(x64RegXcr0); got != e.p.vec.xcr0 {
		t.Errorf("XCR0 = %#x, want the selected %#x", got, e.p.vec.xcr0)
	}
	if vp.reg(x64RegCr4)&x64Cr4OSXSAVE == 0 {
		t.Error("CR4.OSXSAVE is clear, so XGETBV and the AVX instructions fault")
	}
	if e.fb.cfg.xsaveFeatures != e.p.vec.xsaveFeatures {
		t.Errorf("the partition got ProcessorXsaveFeatures %#x, the selection is %#x", e.fb.cfg.xsaveFeatures, e.p.vec.xsaveFeatures)
	}
}

func TestFloatingPointStaysInsideTheProcessor(t *testing.T) {
	e := newX64Env(t, 0)
	e.requireAVX()
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	setImageVector(ac, 0, 0x1111, 0x9999)
	binary.LittleEndian.PutUint32(acImage(ac)[fxOffMXCSR:], 0x1F80)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, 0x400002, 0x202, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	if lo, hi := e.fb.vector(0, 0); lo != 0x1111 || hi != 0x9999 {
		t.Fatalf("first Switch loaded YMM0 = %#x:%#x, want 0x9999:0x1111", hi, lo)
	}
	e.fb.setVector(0, 0, 0x2222, 0xAAAA)
	gets, sets := vp.xsaveGets, vp.xsaveSets
	for range 3 {
		if _, _, err := e.switchTo(c, ac); err != nil {
			t.Fatal(err)
		}
	}
	if vp.xsaveGets != gets || vp.xsaveSets != sets {
		t.Errorf("the fast path moved the XSAVE state: %d reads and %d writes", vp.xsaveGets-gets, vp.xsaveSets-sets)
	}
	if err := c.PullFullState(e.as, ac); err != nil {
		t.Fatal(err)
	}
	if lo, hi := imageVector(ac, 0); lo != 0x2222 || hi != 0xAAAA {
		t.Errorf("pulled YMM0 = %#x:%#x, want 0xaaaa:0x2222", hi, lo)
	}
	if got := binary.LittleEndian.Uint32(acImage(ac)[fxOffMXCSR:]); got != 0x1F80 {
		t.Errorf("pulled MXCSR is %#x", got)
	}

	// A signal handler or ptrace changes the image; the next Switch loads it.
	setImageVector(ac, 0, 0x3333, 0xBBBB)
	c.FullStateChanged()
	gets = vp.xsaveGets
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if lo, hi := e.fb.vector(0, 0); lo != 0x3333 || hi != 0xBBBB {
		t.Errorf("Switch after FullStateChanged loaded YMM0 = %#x:%#x, want 0xbbbb:0x3333", hi, lo)
	}
	// No guest code ran between the pull and the push, so the push reuses
	// the state of the pull.
	if vp.xsaveGets != gets {
		t.Errorf("the push after a pull read the XSAVE state %d more times", vp.xsaveGets-gets)
	}
}

func TestFloatingPointLoadFailureStopsTheSwitch(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	boom := errors.New("set XSAVE state boom")
	e.fb.xsaveSetErr = boom
	if _, _, err := e.switchTo(c, ac); !errors.Is(err, boom) {
		t.Fatalf("Switch returned %v, want the XSAVE write error", err)
	}
}

func TestSwitchFlushesWhenTheTranslationStateChanges(t *testing.T) {
	e := newX64Env(t, 1)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	var flags []uint32
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		flags = append(flags, e.comm(vp).Flags)
		e.syscall(vp, exit, 0x400000, 0x202, nil)
		return nil
	}
	run := func(as *AddressSpace) {
		t.Helper()
		if _, _, err := c.Switch(nil, &fakeMM{as: as}, ac, -1); err != nil {
			t.Fatal(err)
		}
	}
	other := newTestAS(t, e.p)
	mem := mustHost(t, e.fb, 1)
	run(e.as)
	run(e.as)
	if err := e.as.mapHost(0x400000, mem, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	run(e.as)
	e.as.Unmap(0x400000, pageSize)
	run(e.as)
	run(other)
	want := []uint32{flagReloadRoot, 0, 0, flagReloadRoot, flagReloadRoot}
	if len(flags) != len(want) {
		t.Fatalf("flags %#x", flags)
	}
	for i := range want {
		if flags[i] != want[i] {
			t.Errorf("entry %d flags are %#x, want %#x", i, flags[i], want[i])
		}
	}
}

func TestFloatingPointSurvivesProcessorSharing(t *testing.T) {
	e := newX64Env(t, 1)
	a, acA := e.newContext()
	b, acB := e.newContext()
	for _, ac := range []*arch.Context64{acA, acB} {
		r := &ac.StateData().Regs
		r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	}
	setImageVector(acA, 0, 0xAAAA, 0xA0A0)
	setImageVector(acB, 0, 0xBBBB, 0xB0B0)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, 0x400000, 0x202, nil)
		return nil
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	e.fb.setVector(0, 0, 0xA1A1, 0xA2A2)
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if lo, hi := e.fb.vector(0, 0); lo != 0xBBBB || hi != 0xB0B0 {
		t.Fatalf("b runs with YMM0 = %#x:%#x", hi, lo)
	}
	e.fb.setVector(0, 0, 0xB1B1, 0xB2B2)
	if err := a.PullFullState(e.as, acA); err != nil {
		t.Fatal(err)
	}
	if lo, hi := imageVector(acA, 0); lo != 0xA1A1 || hi != 0xA2A2 {
		t.Errorf("a pulled YMM0 = %#x:%#x, want the value it had when b took the processor", hi, lo)
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if lo, hi := e.fb.vector(0, 0); lo != 0xB1B1 || hi != 0xB2B2 {
		t.Errorf("b resumes with YMM0 = %#x:%#x", hi, lo)
	}
}
