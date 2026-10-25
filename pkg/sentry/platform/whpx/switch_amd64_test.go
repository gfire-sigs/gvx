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
	p := newTestPlatform(t, fb, Options{})
	if vps > 0 {
		limitVPs(p, vps)
	}
	as := newTestAS(t, p)
	return &x64Env{t: t, fb: fb, p: p, as: as, mm: &fakeMM{as: as}}
}

func (e *x64Env) newContext() (*Context, *arch.Context64) {
	return e.p.NewContext(nil).(*Context), arch.New(arch.AMD64)
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
	// Bring-up, the FP load and the park state.
	if len(vp.setCalls) != 3 {
		t.Fatalf("%d register writes, want 3", len(vp.setCalls))
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
	if len(vp.setCalls) != 4 {
		t.Fatalf("%d register writes after the second call", len(vp.setCalls))
	}
	if resume := vp.setCalls[3]; len(resume) != 2 || resume[0] != x64RegRip || resume[1] != x64RegInternalActivity {
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
	if len(vp.setCalls[4]) < 8 || vp.reg(x64RegKernelGsBase) != 0x7F0000002000 || vp.regs[x64RegFs][0] != 0x7F0000009000 {
		t.Errorf("FS base change gave writes %#x", vp.setCalls[4])
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

func TestFloatingPointStaysInsideTheProcessor(t *testing.T) {
	e := newX64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	r.Rip, r.Rcx, r.Eflags, r.R11 = 0x400000, 0x400000, 0x202, 0x202
	img := acImage(ac)
	binary.LittleEndian.PutUint64(img[fxOffXMM:], 0x1111)
	binary.LittleEndian.PutUint32(img[fxOffMXCSR:], 0x1F80)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, 0x400002, 0x202, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	if vp.reg(x64RegXmm0) != 0x1111 || uint32(vp.regs[x64RegXmmControlStatus][1]) != 0x1F80 {
		t.Fatalf("first Switch loaded XMM0=%#x", vp.reg(x64RegXmm0))
	}
	e.fb.setReg(0, x64RegXmm0, 0x2222)
	for range 3 {
		if _, _, err := e.switchTo(c, ac); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range vp.getCalls {
		if len(call) > 0 && call[0] == x64RegXmm0 {
			t.Error("the fast path read the vector registers")
		}
	}
	if err := c.PullFullState(e.as, ac); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(acImage(ac)[fxOffXMM:]); got != 0x2222 {
		t.Errorf("pulled XMM0 is %#x", got)
	}
	// The pull must not touch bytes outside the FXSAVE area except XSTATE_BV.
	if got := binary.LittleEndian.Uint32(acImage(ac)[fxOffMXCSR:]); got != 0x1F80 {
		t.Errorf("pulled MXCSR is %#x", got)
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
	binary.LittleEndian.PutUint64(acImage(acA)[fxOffXMM:], 0xAAAA)
	binary.LittleEndian.PutUint64(acImage(acB)[fxOffXMM:], 0xBBBB)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.syscall(vp, exit, 0x400000, 0x202, nil)
		return nil
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	e.fb.setReg(0, x64RegXmm0, 0xA1A1)
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if vp.reg(x64RegXmm0) != 0xBBBB {
		t.Fatalf("b runs with XMM0=%#x", vp.reg(x64RegXmm0))
	}
	e.fb.setReg(0, x64RegXmm0, 0xB1B1)
	if err := a.PullFullState(e.as, acA); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(acImage(acA)[fxOffXMM:]); got != 0xA1A1 {
		t.Errorf("a pulled XMM0=%#x", got)
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if vp.reg(x64RegXmm0) != 0xB1B1 {
		t.Errorf("b resumes with XMM0=%#x", vp.reg(x64RegXmm0))
	}
}
