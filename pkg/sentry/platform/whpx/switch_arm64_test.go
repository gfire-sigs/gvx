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
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// a64Env is a platform on a fake backend with one address space.
type a64Env struct {
	t  *testing.T
	fb *fakeBackend
	p  *Platform
	as *AddressSpace
	mm *fakeMM
}

func newA64Env(t *testing.T, vps int) *a64Env {
	t.Helper()
	fb := newFakeBackend()
	p := newTestPlatform(t, fb, Options{})
	if vps > 0 {
		limitVPs(p, vps)
	}
	as := newTestAS(t, p)
	return &a64Env{t: t, fb: fb, p: p, as: as, mm: &fakeMM{as: as}}
}

func (e *a64Env) newContext() (*Context, *arch.Context64) {
	return e.p.NewContext(nil).(*Context), arch.New(arch.ARM64)
}

func (e *a64Env) comm(vp *fakeVP) *CommPage { return e.p.kernel.commPage(int(vp.index)) }

func (e *a64Env) reload() uint64 {
	return e.p.kernel.layout.code() + uint64(e.p.kernel.a64.Reload)
}

func (e *a64Env) hvc() uint64 {
	return e.p.kernel.layout.code() + uint64(e.p.kernel.a64.Hvc)
}

// trap simulates the EL1 stub: it spills state as the common handler does
// and reports the HVC exit at pc.
func (e *a64Env) trap(vp *fakeVP, exit []byte, slot, esrVal, far, elr uint64, mutate func(c *CommPage)) {
	c := e.comm(vp)
	c.Vector, c.ESR, c.FaultAddr, c.PC = slot, esrVal, far, elr
	if mutate != nil {
		mutate(c)
	}
	atomic.StoreUint32(&c.ExitReason, uint32(ExitException))
	writeStubExit(exit, e.reload())
}

func (e *a64Env) svc(vp *fakeVP, exit []byte, elr uint64, mutate func(c *CommPage)) {
	e.trap(vp, exit, a64SlotLowA64Sync, esr(hvcommon.ECSVC64, 0), 0, elr, mutate)
}

func (e *a64Env) switchTo(c *Context, ac *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	return c.Switch(nil, e.mm, ac, -1)
}

func TestSwitchSyscallRoundTripAndResumeProtocol(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	r := &ac.StateData().Regs
	for i := range r.Regs {
		r.Regs[i] = 0x1000 + uint64(i)
	}
	r.Sp, r.Pc, r.TPIDR_EL0 = 0x7FFF0000, 0x400000, 0x1234
	// Stray DAIF and mode bits must not reach EL0. NZCV must.
	r.Pstate = 0x60000000 | 0x3C0 | 0x5

	var saw []*CommPage
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		cp := *e.comm(vp)
		saw = append(saw, &cp)
		e.svc(vp, exit, 0x400004, func(c *CommPage) {
			c.Regs[0] = 0xAA
			c.TLS = 0x5678
			c.Pstate = 0x20000000
		})
		return nil
	}
	sig, _, err := e.switchTo(c, ac)
	if err != nil || sig != nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	first := saw[0]
	for i := range first.Regs {
		if first.Regs[i] != 0x1000+uint64(i) {
			t.Errorf("CommPage.Regs[%d] is %#x before the run", i, first.Regs[i])
		}
	}
	if first.SP != 0x7FFF0000 || first.PC != 0x400000 || first.TLS != 0x1234 {
		t.Errorf("CommPage has SP %#x PC %#x TLS %#x", first.SP, first.PC, first.TLS)
	}
	if first.Pstate != 0x60000000 {
		t.Errorf("PSTATE is %#x, want the NZCV bits only", first.Pstate)
	}
	if first.Root != e.as.rootValue() {
		t.Errorf("root is %#x, want %#x", first.Root, e.as.rootValue())
	}
	if first.Flags != flagReloadRoot|flagICacheSync {
		t.Errorf("first entry flags are %#x, want a TLB flush and an icache sync", first.Flags)
	}
	if first.ExitReason != uint32(ExitNone) {
		t.Errorf("exit reason is %d before the run", first.ExitReason)
	}
	if r.Regs[0] != 0xAA || r.Regs[1] != 0x1001 || r.Pc != 0x400004 || r.Sp != 0x7FFF0000 ||
		r.TPIDR_EL0 != 0x5678 || r.Pstate != 0x20000000 || ac.StateData().OrigR0 != 0xAA {
		t.Errorf("registers after the syscall: x0=%#x pc=%#x tls=%#x pstate=%#x orig=%#x", r.Regs[0], r.Pc, r.TPIDR_EL0, r.Pstate, ac.StateData().OrigR0)
	}

	vp := e.fb.vps[0]
	// Bring-up, the FP load and the park state are the three writes. The
	// park state carries the root of the first address space.
	if len(vp.setCalls) != 3 {
		t.Fatalf("%d register writes, want bring-up, FP load and park state", len(vp.setCalls))
	}
	if park := vp.setCalls[2]; len(park) != 4 || park[0] != a64RegSpEl1 || park[1] != a64RegPstate || park[2] != a64RegPc || park[3] != a64RegTtbr0 {
		t.Errorf("park registers are %#x", park)
	}
	if vp.reg(a64RegTtbr0) != e.as.rootValue() {
		t.Errorf("TTBR0_EL1 is %#x, want %#x", vp.reg(a64RegTtbr0), e.as.rootValue())
	}
	if vp.reg(a64RegSpEl1) != vp.regs[a64RegSpEl1][0] || vp.reg(a64RegSpEl1) != e.p.kernel.layout.comm(0) {
		t.Errorf("SP_EL1 is %#x, want the CommPage address %#x", vp.reg(a64RegSpEl1), e.p.kernel.layout.comm(0))
	}
	if vp.reg(a64RegPstate) != a64PstateKernel || vp.reg(a64RegPc) != e.reload() {
		t.Errorf("park PSTATE %#x PC %#x", vp.reg(a64RegPstate), vp.reg(a64RegPc))
	}

	// Second syscall of the same thread: no register call, no flush.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		cp := *e.comm(vp)
		saw = append(saw, &cp)
		e.svc(vp, exit, 0x400008, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if len(vp.setCalls) != 3 {
		t.Errorf("the fast path made %d register writes", len(vp.setCalls)-3)
	}
	if saw[1].Flags != 0 {
		t.Errorf("second entry flags are %#x, want none", saw[1].Flags)
	}
	if saw[1].PC != 0x400004 {
		t.Errorf("second entry resumes at %#x, want the previous ELR", saw[1].PC)
	}

	// A hypervisor that reports the HVC address instead of the next
	// instruction needs the program counter set once per exit.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 0x40000C, nil)
		writeStubExit(exit, e.hvc())
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 0x400010, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if n := len(vp.setCalls); n != 4 || len(vp.setCalls[3]) != 1 || vp.setCalls[3][0] != a64RegPc {
		t.Errorf("after an exit at the HVC address the writes are %v", vp.setCalls[3:])
	}
}

func TestSwitchPageFaultBecomesSignal(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	ac.StateData().Regs.Pc = 0x400000
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.trap(vp, exit, a64SlotLowA64Sync, esr(hvcommon.ECDataAbortLower, 1<<6|0x07), 0xDEAD000, 0x400040, nil)
		return nil
	}
	sig, at, err := e.switchTo(c, ac)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	if sig.Signo != int32(linux.SIGSEGV) || sig.Code != hvcommon.SegvMapErr || !at.Write || at.Read {
		t.Errorf("signal %d code %d access %+v", sig.Signo, sig.Code, at)
	}
	if got := binary.LittleEndian.Uint64(sig.Fields[0:8]); got != 0xDEAD000 {
		t.Errorf("si_addr is %#x", got)
	}
	if ac.StateData().Regs.Pc != 0x400040 {
		t.Errorf("PC is %#x, want the faulting instruction", ac.StateData().Regs.Pc)
	}
}

func TestSwitchInterruptBeforeEntryNeverRuns(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	c.Interrupt()
	if _, _, err := e.switchTo(c, ac); !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch returned %v", err)
	}
	if len(e.fb.vps) != 0 {
		t.Error("an interrupted Switch created a processor")
	}
	// The interrupt is consumed once.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatalf("second Switch returned %v", err)
	}
}

func TestSwitchInterruptStopsUserCodeAndSavesState(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	done := make(chan error)
	go func() {
		_, _, err := e.switchTo(c, ac)
		done <- err
	}()
	vp := e.fb.waitRunning(0)
	// The processor sits at EL0 with these registers.
	for i := range 31 {
		e.fb.setReg(0, a64RegX0+uint32(i), 0x9000+uint64(i))
	}
	e.fb.setReg(0, a64RegSpEl0, 0x7FFE0000)
	e.fb.setReg(0, a64RegPc, 0x400200)
	e.fb.setReg(0, a64RegPstate, 0x40000000)
	e.fb.setReg(0, a64RegTpidrEl0, 0xABCD)
	c.Interrupt()
	if err := <-done; !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch returned %v", err)
	}
	r := &ac.StateData().Regs
	if r.Regs[0] != 0x9000 || r.Regs[30] != 0x901E || r.Sp != 0x7FFE0000 || r.Pc != 0x400200 || r.Pstate != 0x40000000 || r.TPIDR_EL0 != 0xABCD {
		t.Errorf("saved state: x0=%#x x30=%#x sp=%#x pc=%#x pstate=%#x tls=%#x", r.Regs[0], r.Regs[30], r.Sp, r.Pc, r.Pstate, r.TPIDR_EL0)
	}

	// The next Switch must park the processor again, because user code ran.
	before := len(vp.setCalls)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, r.Pc+4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if park := vp.setCalls[len(vp.setCalls)-1]; len(vp.setCalls) == before || len(park) != 3 || park[0] != a64RegSpEl1 {
		t.Errorf("registers after the interrupt: %v", vp.setCalls[before:])
	}
}

func TestSwitchCancelInsideTheStubEntryKeepsRunning(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	calls := 0
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		calls++
		if calls == 1 {
			return errBlockRun
		}
		e.svc(vp, exit, 0x400004, nil)
		return nil
	}
	done := make(chan error)
	go func() {
		_, _, err := e.switchTo(c, ac)
		done <- err
	}()
	e.fb.waitRunning(0)
	// The cancel lands in the common handler, between the spill and HVC.
	e.fb.setReg(0, a64RegPstate, a64PstateKernel)
	e.fb.setReg(0, a64RegPc, e.p.kernel.layout.code()+uint64(e.p.kernel.a64.Common)+8)
	c.Interrupt()
	if err := <-done; err != nil {
		t.Fatalf("Switch returned %v, want the system call to complete", err)
	}
	if calls != 2 {
		t.Errorf("%d runs, want the run to continue once", calls)
	}
	// The interrupt stays pending for the next Switch.
	if _, _, err := e.switchTo(c, ac); err != nil && !errors.Is(err, platform.ErrContextInterrupt) {
		t.Errorf("next Switch returned %v", err)
	}
}

func TestSwitchCancelInsideTheReloadPathReturnsAndReparks(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	ac.StateData().Regs.Regs[7] = 0x77
	done := make(chan error)
	go func() {
		_, _, err := e.switchTo(c, ac)
		done <- err
	}()
	vp := e.fb.waitRunning(0)
	e.fb.setReg(0, a64RegPstate, a64PstateKernel)
	e.fb.setReg(0, a64RegPc, e.reload()+8)
	c.Interrupt()
	if err := <-done; !errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch returned %v", err)
	}
	if ac.StateData().Regs.Regs[7] != 0x77 {
		t.Error("an interrupt in the reload path changed the saved registers")
	}
	before := len(vp.setCalls)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if len(vp.setCalls) == before {
		t.Error("the reload restart did not re-park the processor")
	}
}

func TestSwitchCancelAtUnknownKernelAddressIsAnError(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	done := make(chan error)
	go func() {
		_, _, err := e.switchTo(c, ac)
		done <- err
	}()
	e.fb.waitRunning(0)
	e.fb.setReg(0, a64RegPstate, a64PstateKernel)
	e.fb.setReg(0, a64RegPc, 0x1234)
	c.Interrupt()
	if err := <-done; err == nil || errors.Is(err, platform.ErrContextInterrupt) {
		t.Fatalf("Switch returned %v", err)
	}
}

func TestSwitchSkipsWaitForInterruptInstructions(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	ac.StateData().Regs.Pc = 0x400000
	var pcs []uint64
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		cp := e.comm(vp)
		pcs = append(pcs, cp.PC)
		if len(pcs) == 1 {
			e.trap(vp, exit, a64SlotLowA64Sync, esr(hvcommon.ECWFx, 0), 0, 0x400010, nil)
			return nil
		}
		e.svc(vp, exit, cp.PC+4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if len(pcs) != 2 || pcs[1] != 0x400014 {
		t.Errorf("run program counters %#x, want the second run to resume after the WFI", pcs)
	}
	if e.fb.vps[0].runs != 2 {
		t.Errorf("%d runs", e.fb.vps[0].runs)
	}
}

func TestSwitchRejectsUnexpectedExits(t *testing.T) {
	for _, c := range []struct {
		name   string
		script func(e *a64Env, vp *fakeVP, exit []byte)
	}{
		{"HVC with an immediate", func(e *a64Env, vp *fakeVP, exit []byte) {
			e.svc(vp, exit, 4, nil)
			binary.LittleEndian.PutUint16(exit[a64ExitOffHvcImm:], 7)
		}},
		{"HVC without a stub exit reason", func(e *a64Env, vp *fakeVP, exit []byte) {
			writeStubExit(exit, e.reload())
		}},
		{"unrecoverable exception", func(e *a64Env, vp *fakeVP, exit []byte) {
			binary.LittleEndian.PutUint32(exit, a64ExitUnrecoverable)
		}},
		{"exception at EL1", func(e *a64Env, vp *fakeVP, exit []byte) {
			e.trap(vp, exit, a64SlotCurSPxSync, esr(hvcommon.ECDataAbortLower, 0x07), 0, 0x1000, nil)
		}},
		{"IRQ", func(e *a64Env, vp *fakeVP, exit []byte) {
			e.trap(vp, exit, a64SlotLowA64IRQ, 0, 0, 0x1000, nil)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := newA64Env(t, 0)
			ctx, ac := e.newContext()
			e.fb.onRun = func(vp *fakeVP, exit []byte) error {
				c.script(e, vp, exit)
				return nil
			}
			sig, _, err := e.switchTo(ctx, ac)
			if err == nil || sig != nil || errors.Is(err, platform.ErrContextSignal) || errors.Is(err, platform.ErrContextInterrupt) {
				t.Fatalf("Switch returned %v, %v, want a plain error", sig, err)
			}
			// The failure invalidates the cached state, so the next entry
			// parks the processor from scratch.
			e.fb.onRun = func(vp *fakeVP, exit []byte) error {
				e.svc(vp, exit, 4, nil)
				return nil
			}
			vp := e.fb.vps[0]
			before := len(vp.setCalls)
			if _, _, err := e.switchTo(ctx, ac); err != nil {
				t.Fatal(err)
			}
			if park := vp.setCalls[len(vp.setCalls)-1]; len(vp.setCalls) == before || park[0] != a64RegSpEl1 {
				t.Errorf("no park after a failed exit: %v", vp.setCalls[before:])
			}
		})
	}
}

func TestSwitchPropagatesRunAndRegisterErrors(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	boom := errors.New("run boom")
	e.fb.runErr = boom
	if _, _, err := e.switchTo(c, ac); !errors.Is(err, boom) {
		t.Fatalf("run error: %v", err)
	}
	e.fb.runErr = nil
	boom2 := errors.New("set boom")
	e.fb.setErr = func(uint32) error { return boom2 }
	if _, _, err := e.switchTo(c, ac); !errors.Is(err, boom2) {
		t.Fatalf("register error: %v", err)
	}
	// The failed Switch released the processor.
	e.fb.setErr = nil
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatalf("Switch after the errors returned %v", err)
	}
}

func TestSwitchMemoryFaultAtEL0IsSIGBUS(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		for i := range 31 {
			e.fb.vps[0].regs[a64RegX0+uint32(i)] = [2]uint64{uint64(i), 0}
		}
		clear(exit)
		binary.LittleEndian.PutUint32(exit[a64ExitOffReason:], a64ExitUnmappedGpa)
		binary.LittleEndian.PutUint64(exit[a64ExitOffHdrPc:], 0x400000)
		binary.LittleEndian.PutUint64(exit[a64ExitOffHdrCpsr:], 0)
		exit[a64ExitOffMemInfo] = 1
		exit[a64ExitOffHdrAccess] = 1
		binary.LittleEndian.PutUint64(exit[a64ExitOffMemGva:], 0x7000)
		binary.LittleEndian.PutUint64(exit[a64ExitOffMemGpa:], 0x9000_0000)
		return nil
	}
	sig, at, err := e.switchTo(c, ac)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil || sig.Signo != int32(linux.SIGBUS) || sig.Code != hvcommon.BusAdrErr || !at.Write {
		t.Fatalf("Switch returned %+v, %+v, %v", sig, at, err)
	}
	if got := binary.LittleEndian.Uint64(sig.Fields[0:8]); got != 0x7000 {
		t.Errorf("si_addr is %#x", got)
	}

	// The same exit while the stub runs is an error.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		clear(exit)
		binary.LittleEndian.PutUint32(exit[a64ExitOffReason:], a64ExitUnmappedGpa)
		binary.LittleEndian.PutUint64(exit[a64ExitOffHdrCpsr:], a64PstateKernel)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err == nil || errors.Is(err, platform.ErrContextSignal) {
		t.Errorf("fault in the stub returned %v", err)
	}
}

func TestSwitchFlushesWhenTheTranslationStateChanges(t *testing.T) {
	e := newA64Env(t, 1)
	c, ac := e.newContext()
	var flags []uint32
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		flags = append(flags, e.comm(vp).Flags)
		e.svc(vp, exit, 4, nil)
		return nil
	}
	run := func(as *AddressSpace) {
		t.Helper()
		mm := &fakeMM{as: as}
		if _, _, err := c.Switch(nil, mm, ac, -1); err != nil {
			t.Fatal(err)
		}
	}
	other := newTestAS(t, e.p)
	run(e.as)
	run(e.as)
	mem := mustHost(t, e.fb, 2)
	// A fresh mapping needs no flush. An executable one needs an icache sync.
	if err := e.as.mapHost(0x400000, mem[:pageSize], hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	run(e.as)
	if err := e.as.mapHost(0x401000, mem[pageSize:], hostarch.AccessType{Read: true, Execute: true}); err != nil {
		t.Fatal(err)
	}
	run(e.as)
	// Removing a mapping advances the generation.
	e.as.Unmap(0x400000, pageSize)
	run(e.as)
	// Another address space needs both.
	run(other)
	run(e.as)
	want := []uint32{
		flagReloadRoot | flagICacheSync, // first entry
		0,                               // nothing changed
		0,                               // data mapping only
		flagICacheSync,                  // executable mapping
		flagReloadRoot,                  // Unmap
		flagReloadRoot | flagICacheSync, // other address space
		flagReloadRoot | flagICacheSync, // back again
	}
	if len(flags) != len(want) {
		t.Fatalf("flags %#x", flags)
	}
	for i := range want {
		if flags[i] != want[i] {
			t.Errorf("entry %d flags are %#x, want %#x", i, flags[i], want[i])
		}
	}
}

func fillFP(ac *arch.Context64, q0 uint64) {
	img := acImage(ac)
	binary.LittleEndian.PutUint64(img[a64FPOffQ:], q0)
	binary.LittleEndian.PutUint64(img[a64FPOffFPCR:], 0x400000)
}

func TestFloatingPointStaysInsideTheProcessor(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	fillFP(ac, 0x1111)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	if vp.reg(a64RegQ0) != 0x1111 || vp.reg(a64RegFpcr) != 0x400000 {
		t.Fatalf("first Switch loaded Q0=%#x FPCR=%#x", vp.reg(a64RegQ0), vp.reg(a64RegFpcr))
	}
	loads := func() int {
		n := 0
		for _, call := range vp.setCalls {
			if len(call) > 0 && call[0] == a64RegQ0 {
				n++
			}
		}
		return n
	}
	if loads() != 1 {
		t.Fatalf("%d FP loads", loads())
	}
	// The guest changes V0 while it runs. Later Switch calls neither read nor
	// write the vector registers.
	e.fb.setReg(0, a64RegQ0, 0x2222)
	for range 3 {
		if _, _, err := e.switchTo(c, ac); err != nil {
			t.Fatal(err)
		}
	}
	if loads() != 1 {
		t.Errorf("the fast path loaded FP state %d times", loads())
	}
	for _, call := range vp.getCalls {
		if len(call) > 0 && call[0] == a64RegQ0 {
			t.Error("the fast path read the vector registers")
		}
	}

	// PullFullState copies the processor state into the Sentry image.
	if err := c.PullFullState(e.as, ac); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(acImage(ac)[a64FPOffQ:]); got != 0x2222 {
		t.Errorf("pulled Q0 is %#x, want the guest value", got)
	}
	reads := len(vp.getCalls)
	if err := c.PullFullState(e.as, ac); err != nil || len(vp.getCalls) != reads {
		t.Errorf("a second pull read the processor again: %v", err)
	}

	// FullStateChanged makes the Sentry image the truth and reloads it.
	fillFP(ac, 0x3333)
	c.FullStateChanged()
	if err := c.PullFullState(e.as, ac); err != nil || binary.LittleEndian.Uint64(acImage(ac)[a64FPOffQ:]) != 0x3333 {
		t.Errorf("PullFullState after FullStateChanged overwrote the image: %v", err)
	}
	if _, _, err := e.switchTo(c, ac); err != nil {
		t.Fatal(err)
	}
	if vp.reg(a64RegQ0) != 0x3333 || loads() != 2 {
		t.Errorf("after FullStateChanged Q0=%#x with %d loads", vp.reg(a64RegQ0), loads())
	}
}

func TestFloatingPointSurvivesProcessorSharing(t *testing.T) {
	e := newA64Env(t, 1)
	a, acA := e.newContext()
	b, acB := e.newContext()
	fillFP(acA, 0xAAAA)
	fillFP(acB, 0xBBBB)
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	vp := e.fb.vps[0]
	e.fb.setReg(0, a64RegQ0, 0xA1A1) // The guest of a changes V0.
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if vp.reg(a64RegQ0) != 0xBBBB {
		t.Fatalf("b runs with Q0=%#x", vp.reg(a64RegQ0))
	}
	e.fb.setReg(0, a64RegQ0, 0xB1B1)
	// a lost the processor. Its state was saved, and a pulls it back.
	if err := a.PullFullState(e.as, acA); err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(acImage(acA)[a64FPOffQ:]); got != 0xA1A1 {
		t.Errorf("a pulled Q0=%#x, want its own value 0xa1a1", got)
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	if vp.reg(a64RegQ0) != 0xA1A1 {
		t.Errorf("a resumes with Q0=%#x", vp.reg(a64RegQ0))
	}
	// And b gets its own state back on the next round.
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	if vp.reg(a64RegQ0) != 0xB1B1 {
		t.Errorf("b resumes with Q0=%#x, want 0xb1b1", vp.reg(a64RegQ0))
	}
}

func TestFloatingPointSaveFailureFailsTheOwner(t *testing.T) {
	e := newA64Env(t, 1)
	a, acA := e.newContext()
	b, acB := e.newContext()
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("get boom")
	e.fb.getErr = func(uint32) error { return boom }
	// b takes the processor. Saving the state of a fails.
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatalf("b returned %v", err)
	}
	e.fb.getErr = nil
	if err := a.PullFullState(e.as, acA); !errors.Is(err, boom) {
		t.Errorf("PullFullState returned %v, want the save error", err)
	}
	if _, _, err := e.switchTo(a, acA); !errors.Is(err, boom) {
		t.Errorf("Switch returned %v, want the save error", err)
	}
	// FullStateChanged clears the failure: the Sentry image is the truth again.
	a.FullStateChanged()
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Errorf("Switch after FullStateChanged returned %v", err)
	}
}

func TestThreadInitRunsOnEverySwitch(t *testing.T) {
	fb := newFakeBackend()
	var calls atomic.Int32
	hookErr := error(nil)
	p := newTestPlatform(t, fb, Options{ThreadInit: func() error {
		calls.Add(1)
		return hookErr
	}})
	as := newTestAS(t, p)
	mm := &fakeMM{as: as}
	c := p.NewContext(nil).(*Context)
	ac := arch.New(arch.ARM64)
	fb.onRun = func(vp *fakeVP, exit []byte) error {
		cp := p.kernel.commPage(int(vp.index))
		cp.Vector, cp.ESR = a64SlotLowA64Sync, esr(hvcommon.ECSVC64, 0)
		atomic.StoreUint32(&cp.ExitReason, uint32(ExitException))
		writeStubExit(exit, p.kernel.layout.code()+uint64(p.kernel.a64.Reload))
		return nil
	}
	for range 3 {
		if _, _, err := c.Switch(nil, mm, ac, -1); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 3 {
		t.Errorf("ThreadInit ran %d times for 3 Switch calls", calls.Load())
	}
	hookErr = errors.New("bind token failed")
	runs := fb.vps[0].runs
	if _, _, err := c.Switch(nil, mm, ac, -1); !errors.Is(err, hookErr) {
		t.Errorf("Switch returned %v, want the hook error", err)
	}
	if fb.vps[0].runs != runs {
		t.Error("the guest ran after a failed ThreadInit")
	}
}

func TestSwitchRejectsForeignAndReleasedAddressSpaces(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	other := newTestPlatform(t, newFakeBackend(), Options{})
	foreign := newTestAS(t, other)
	if _, _, err := c.Switch(nil, &fakeMM{as: foreign}, ac, -1); err == nil {
		t.Error("Switch accepted an address space of another platform")
	}
	released, err := e.p.NewAddressSpace(platformASOptions)
	if err != nil {
		t.Fatal(err)
	}
	released.Release()
	if _, _, err := c.Switch(nil, &fakeMM{as: released}, ac, -1); err == nil {
		t.Error("Switch accepted a released address space")
	}
	if len(e.fb.vps) != 0 {
		t.Error("a rejected Switch created a processor")
	}
}

func TestSwitchAfterCloseFails(t *testing.T) {
	fb := newFakeBackend()
	p, err := newPlatform(fb, Options{})
	if err != nil {
		t.Fatal(err)
	}
	as, _ := p.NewAddressSpace(platformASOptions)
	c := p.NewContext(nil).(*Context)
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Switch(nil, &fakeMM{as: as}, arch.New(arch.ARM64), -1); !errors.Is(err, errClosed) {
		t.Errorf("Switch returned %v", err)
	}
}

func TestReleaseDropsFloatingPointOwnership(t *testing.T) {
	e := newA64Env(t, 1)
	a, acA := e.newContext()
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.svc(vp, exit, 4, nil)
		return nil
	}
	if _, _, err := e.switchTo(a, acA); err != nil {
		t.Fatal(err)
	}
	a.Release()
	if e.fb.vps[0].regs == nil || e.p.vps[0].fpOwner != nil {
		t.Error("a released Context still owns the processor state")
	}
	b, acB := e.newContext()
	before := len(e.fb.vps[0].getCalls)
	if _, _, err := e.switchTo(b, acB); err != nil {
		t.Fatal(err)
	}
	for _, call := range e.fb.vps[0].getCalls[before:] {
		if len(call) > 0 && call[0] == a64RegQ0 {
			t.Error("the processor saved the state of a released Context")
		}
	}
}

// TestConcurrentSwitchAndInvalidation runs many Contexts of one address
// space while another goroutine remaps memory. Every Unmap must see the
// processors leave the guest, and no goroutine may deadlock.
func TestConcurrentSwitchAndInvalidation(t *testing.T) {
	e := newA64Env(t, 4)
	mem := mustHost(t, e.fb, 8)
	var sysCalls atomic.Int64
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		sysCalls.Add(1)
		e.svc(vp, exit, 4, nil)
		return nil
	}
	const workers, rounds = 6, 40
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, ac := e.newContext()
			for range rounds {
				if _, _, err := e.switchTo(c, ac); err != nil && !errors.Is(err, platform.ErrContextInterrupt) {
					t.Error(err)
					return
				}
				if sysCalls.Load()%7 == 0 {
					c.Interrupt()
				}
			}
			c.Release()
		}()
	}
	for i := range rounds {
		page := mem[(i%8)*pageSize : (i%8+1)*pageSize]
		if err := e.as.mapHost(0x400000, page, hostarch.ReadWrite); err != nil {
			t.Fatal(err)
		}
		e.as.Unmap(0x400000, pageSize)
	}
	wg.Wait()
	if _, _, _, ok := translate(e.as, 0x400000); ok {
		t.Error("the page stays mapped")
	}
}

func TestSwitchEmulatesSysRegReadsAndRejectsWrites(t *testing.T) {
	e := newA64Env(t, 0)
	c, ac := e.newContext()
	ac.StateData().Regs.Pc = 0x400000

	sysRegISS := func(read bool, rt, op0, op1, crn, crm, op2 uint32) uint64 {
		dir := uint32(0)
		if read {
			dir = 1
		}
		return esr(hvcommon.ECSysReg, uint64(op0<<20|op2<<17|op1<<14|crn<<10|rt<<5|crm<<1|dir))
	}

	step := 0
	var sawAfterCTR uint64
	var sawAfterMIDR uint64
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		step++
		comm := e.comm(vp)
		switch step {
		case 1:
			// MRS X3, MIDR_EL1 at 0x400000.
			e.trap(vp, exit, a64SlotLowA64Sync, sysRegISS(true, 3, 3, 0, 0, 0, 0), 0, 0x400000, nil)
		case 2:
			sawAfterMIDR = comm.Regs[3]
			if comm.PC != 0x400004 {
				t.Errorf("PC after MIDR_EL1 is %#x, want 0x400004", comm.PC)
			}
			// MRS X4, CTR_EL0 at 0x400004.
			e.trap(vp, exit, a64SlotLowA64Sync, sysRegISS(true, 4, 3, 3, 0, 0, 1), 0, comm.PC, nil)
		case 3:
			sawAfterCTR = comm.Regs[4]
			if comm.PC != 0x400008 {
				t.Errorf("PC after CTR_EL0 is %#x, want 0x400008", comm.PC)
			}
			e.svc(vp, exit, comm.PC+4, nil)
		}
		return nil
	}
	if sig, _, err := e.switchTo(c, ac); err != nil || sig != nil {
		t.Fatalf("Switch returned %v, %v", sig, err)
	}
	if sawAfterMIDR == 0 {
		t.Error("MIDR_EL1 read returned zero")
	}
	if sawAfterCTR == 0 {
		t.Error("CTR_EL0 read returned zero")
	}

	// An MSR write to MIDR_EL1 must still raise SIGILL.
	e.fb.onRun = func(vp *fakeVP, exit []byte) error {
		e.trap(vp, exit, a64SlotLowA64Sync, sysRegISS(false, 3, 3, 0, 0, 0, 0), 0, 0x400100, nil)
		return nil
	}
	sig, _, err := e.switchTo(c, ac)
	if !errors.Is(err, platform.ErrContextSignal) || sig == nil || sig.Signo != int32(linux.SIGILL) {
		t.Fatalf("MSR write returned (%v, %v), want SIGILL", sig, err)
	}
}
