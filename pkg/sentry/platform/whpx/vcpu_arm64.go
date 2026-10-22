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
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// regBatchCap is the capacity of a register batch. The largest batch reads
// the general registers and the user system registers.
const regBatchCap = 48

// archInit sets global state. The arm64 page tables need none.
func archInit() {}

// vpState is what the holder of a virtual processor knows about the guest
// state of the processor.
type vpState struct {
	// valid is true after the first run that completed. A zero vpState forces
	// the park state and a TLB flush.
	valid bool

	// parked is true when the processor waits at a stub exit or at the start
	// of the reload path.
	parked bool

	// exitPC is the program counter that the last stub exit reported.
	exitPC uint64

	// asID, asGen and execGen identify the translation and instruction
	// cache state that the processor may hold.
	asID    uint64
	asGen   uint64
	execGen uint64
}

// invalidate forgets everything about the processor.
func (s *vpState) invalidate() { *s = vpState{} }

// rootValue returns the TTBR0_EL1 value of the address space.
func (as *AddressSpace) rootValue() uint64 {
	return as.pt.TTBR0_EL1(false, 0)
}

// archBringUp configures EL1 of a new processor: the MMU, the exception
// vectors and the kernel stack. The processor then waits at the start of the
// reload path.
func (v *vcpu) archBringUp() error {
	p := v.p
	layout := p.kernel.layout
	stubs := p.kernel.a64
	b := v.regs

	// SCTLR_EL1 keeps its reserved-to-one bits, so read it first.
	b.reset()
	b.want(a64RegSctlr)
	if err := p.be.getRegs(v.index, b); err != nil {
		return fmt.Errorf("read SCTLR_EL1: %w", err)
	}
	sctlr := b.u64(0)

	b.reset()
	// Secondary processors start suspended until the host clears StartupSuspend.
	b.add64(a64RegActivity, 0)
	b.add64(a64RegGicrBase, a64GicRedistributors+uint64(v.index)*a64GicRedistributorSize)
	b.add64(a64RegMair, a64Mair)
	b.add64(a64RegTcr, a64TCR)
	b.add64(a64RegTtbr0, p.kernel.pt.TTBR0_EL1(false, 0))
	b.add64(a64RegTtbr1, p.kernel.pt.TTBR1_EL1(false, 0))
	b.add64(a64RegCpacr, a64CpacrNoTrap)
	b.add64(a64RegCntkctl, a64CntkctlEL0)
	b.add64(a64RegSctlr, sctlr|a64SctlrSet)
	b.add64(a64RegVbar, layout.code()+uint64(stubs.Vectors))
	b.add64(a64RegTpidrro, 0)
	v.addParkRegs(b)
	if err := p.be.setRegs(v.index, b); err != nil {
		return err
	}
	v.st.invalidate()
	return nil
}

// addParkRegs appends the registers that place the processor at the start of
// the reload path at EL1. SP_EL1 holds the CommPage address, which the stub
// uses as its base register.
func (v *vcpu) addParkRegs(b *regBatch) {
	b.add64(a64RegSpEl1, v.commVA)
	b.add64(a64RegPstate, a64PstateKernel)
	b.add64(a64RegPc, v.reloadVA())
}

func (v *vcpu) reloadVA() uint64 {
	return v.p.kernel.layout.code() + uint64(v.p.kernel.a64.Reload)
}

// prepareRun loads the registers of ac into the CommPage and arranges the
// processor so that the next run executes the reload path.
func (c *Context) prepareRun(v *vcpu, as *AddressSpace, ac *arch.Context64) (runResult, bool) {
	state := ac.StateData()
	r := &state.Regs

	if err := c.ensureFP(v, ac); err != nil {
		return runResult{err: err}, true
	}

	comm := v.comm
	comm.Regs = r.Regs
	comm.SP = r.Sp
	comm.PC = r.Pc
	comm.PstateOrRflags = r.Pstate &^ a64PstateUserMask
	comm.TLS = r.TPIDR_EL0
	comm.Root = as.rootValue()

	st := &v.st
	gen := as.gen.Load()
	execGen := as.execGen.Load()
	var cflags uint32
	if !st.valid || st.asID != as.id || st.asGen != gen {
		cflags |= flagReloadRoot
	}
	if !st.valid || st.asID != as.id || st.execGen != execGen {
		cflags |= flagICacheSync
	}
	atomic.StoreUint32(&comm.Flags, cflags)
	atomic.StoreUint32(&comm.ExitReason, uint32(ExitNone))

	b := v.regs
	b.reset()
	switch {
	case !st.valid || !st.parked:
		v.addParkRegs(b)
	case st.exitPC != v.reloadVA():
		b.add64(a64RegPc, v.reloadVA())
	}
	if b.n > 0 {
		if err := v.p.be.setRegs(v.index, b); err != nil {
			st.invalidate()
			return runResult{err: fmt.Errorf("whpx: resume virtual processor %d: %w", v.index, err)}, true
		}
	}
	st.valid = true
	st.parked = true
	st.exitPC = v.reloadVA()
	st.asID, st.asGen, st.execGen = as.id, gen, execGen
	return runResult{}, false
}

// onStubExit reads the CommPage after the stub executed HVC.
func (c *Context) onStubExit(v *vcpu, ex exitInfo, ac *arch.Context64) (runResult, bool) {
	comm := v.comm
	if ex.hvcImmediate != a64StubHvc {
		v.st.invalidate()
		return runResult{err: fmt.Errorf("whpx: virtual processor %d executed HVC #%d", v.index, ex.hvcImmediate)}, false
	}
	if reason := ExitReason(atomic.LoadUint32(&comm.ExitReason)); reason != ExitException {
		v.st.invalidate()
		return runResult{err: fmt.Errorf("whpx: virtual processor %d executed HVC with stub exit reason %d", v.index, reason)}, false
	}
	v.st.parked = true
	v.st.exitPC = ex.pc

	t, err := classifyA64(comm.Vector, comm.FaultCode, comm.FaultAddr, comm.PC)
	if err != nil {
		v.st.invalidate()
		return runResult{err: err}, false
	}
	if t.kind == trapSkip {
		// Resume after the instruction, as the KVM platform does for WFI.
		comm.PC += 4
		atomic.StoreUint32(&comm.Flags, 0)
		atomic.StoreUint32(&comm.ExitReason, uint32(ExitNone))
		if ex.pc != v.reloadVA() {
			b := v.regs
			b.reset()
			b.add64(a64RegPc, v.reloadVA())
			if err := v.p.be.setRegs(v.index, b); err != nil {
				v.st.invalidate()
				return runResult{err: fmt.Errorf("whpx: resume virtual processor %d: %w", v.index, err)}, false
			}
			v.st.exitPC = v.reloadVA()
		}
		return runResult{}, true
	}

	r := &ac.StateData().Regs
	r.Regs = comm.Regs
	r.Sp = comm.SP
	r.Pc = comm.PC
	r.Pstate = comm.PstateOrRflags
	r.TPIDR_EL0 = comm.TLS
	if t.kind == trapSyscall {
		ac.StateData().OrigR0 = r.Regs[0]
		return runResult{}, false
	}
	return t.result(), false
}

// result converts a trap into the return values of Switch.
func (t trap) result() runResult {
	info := &linux.SignalInfo{Signo: int32(t.signo), Code: t.code}
	if t.hasAddr {
		info.SetAddr(t.addr)
	}
	return runResult{sig: info, at: t.access, err: platform.ErrContextSignal}
}

// saveUserRegs reads the registers of a processor that stopped at EL0.
func (c *Context) saveUserRegs(v *vcpu, ac *arch.Context64) error {
	r := &ac.StateData().Regs
	b := v.regs
	b.reset()
	for i := range 31 {
		b.want(a64RegX0 + uint32(i))
	}
	b.want(a64RegSpEl0)
	b.want(a64RegPc)
	b.want(a64RegPstate)
	b.want(a64RegTpidrEl0)
	if err := v.p.be.getRegs(v.index, b); err != nil {
		return fmt.Errorf("whpx: read user registers of virtual processor %d: %w", v.index, err)
	}
	for i := range 31 {
		r.Regs[i] = b.u64(i)
	}
	r.Sp = b.u64(31)
	r.Pc = b.u64(32)
	r.Pstate = b.u64(33)
	r.TPIDR_EL0 = b.u64(34)
	return nil
}

// stubRanges returns the guest addresses of the entry and reload phases.
func (v *vcpu) stubRanges() (entry, reload addrRange) {
	code := v.p.kernel.layout.code()
	s := v.p.kernel.a64
	return addrRange{code + uint64(s.Vectors), code + uint64(s.Hvc) + 4},
		addrRange{code + uint64(s.Reload), code + uint64(s.ReloadEnd)}
}

// onCancel decides what to do after a cancelled run. The cancel context has
// no program counter, so the function reads PC and PSTATE.
func (c *Context) onCancel(v *vcpu, _ exitInfo, ac *arch.Context64) (cancelAction, error) {
	b := v.regs
	b.reset()
	b.want(a64RegPc)
	b.want(a64RegPstate)
	if err := v.p.be.getRegs(v.index, b); err != nil {
		return cancelInterrupt, fmt.Errorf("whpx: read state of cancelled virtual processor %d: %w", v.index, err)
	}
	pc, pstate := b.u64(0), b.u64(1)
	if pstate&a64PstateModeMask == 0 {
		if err := c.saveUserRegs(v, ac); err != nil {
			return cancelInterrupt, err
		}
		v.st.parked = false
		return cancelInterrupt, nil
	}
	entry, reload := v.stubRanges()
	switch {
	case entry.contains(pc):
		return cancelContinue, nil
	case reload.contains(pc):
		v.st.parked = false
		return cancelInterrupt, nil
	}
	return cancelInterrupt, fmt.Errorf("whpx: virtual processor %d was cancelled at unknown kernel address %#x", v.index, pc)
}

// onMemoryFault converts a guest physical access fault into SIGBUS.
func (c *Context) onMemoryFault(v *vcpu, ex exitInfo, ac *arch.Context64) runResult {
	if ex.cpsr&a64PstateModeMask != 0 {
		v.st.invalidate()
		return runResult{err: fmt.Errorf("whpx: virtual processor %d faulted on guest physical address %#x in the stub at %#x", v.index, ex.gpa, ex.pc)}
	}
	if err := c.saveUserRegs(v, ac); err != nil {
		return runResult{err: err}
	}
	v.st.parked = false
	log.Warningf("whpx: guest physical fault at gpa %#x, gva %#x, pc %#x", ex.gpa, ex.gva, ex.pc)
	t := trap{kind: trapSignal, signo: linux.SIGBUS, code: busAdrErr, hasAddr: true, addr: ex.gva}
	if !ex.gvaValid {
		t.addr = 0
	}
	t.access = hostarch.AccessType{Read: !ex.write && !ex.execute, Write: ex.write, Execute: ex.execute}
	return t.result()
}
