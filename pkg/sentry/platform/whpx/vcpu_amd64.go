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
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// regBatchCap is the capacity of a register batch. The largest batch loads
// the park state together with the segment registers.
const regBatchCap = 48

// Control register bits of the amd64 guest.
const (
	x64Cr0PE = 1 << 0
	x64Cr0MP = 1 << 1
	x64Cr0ET = 1 << 4
	x64Cr0NE = 1 << 5
	x64Cr0WP = 1 << 16
	x64Cr0PG = 1 << 31

	x64Cr4PAE        = 1 << 5
	x64Cr4OSFXSR     = 1 << 9
	x64Cr4OSXMMEXCPT = 1 << 10
	x64Cr4OSXSAVE    = 1 << 18

	x64EferSCE = 1 << 0
	x64EferLME = 1 << 8
	x64EferLMA = 1 << 10
	x64EferNXE = 1 << 11

	// x64Xcr0 enables the x87 and SSE state components. The AVX state is out
	// of reach of the WHPX register interface, so the guest never enables it.
	x64Xcr0 = 3
)

// archInit sets global state of the page table package. The
// guest uses 4-level paging, so it must not use 5 levels on hosts with LA57.
func archInit() {
	pagetables.DisableLA57()
}

// vpState is what the holder of a virtual processor knows about the guest
// state of the processor.
type vpState struct {
	// valid is true after the first run that completed. A zero vpState forces
	// the full park state and a TLB flush.
	valid bool

	// parked is true when the processor waits at a stub exit or at the start
	// of the reload path, so that setting RIP and the activity state resumes
	// it.
	parked bool

	// asID and asGen identify the translation state the TLB may hold.
	asID  uint64
	asGen uint64

	// fsBase, gsBase and the selectors are the values that the last full
	// park wrote.
	fsBase, gsBase uint64
	ds, es, fs, gs uint16
}

// rootValue returns the CR3 value of the address space.
func (as *AddressSpace) rootValue() uint64 {
	return as.pt.CR3(false, 0)
}

// archBringUp puts a new processor in 64-bit mode with the stub tables.
func (v *vcpu) archBringUp() error {
	p := v.p
	layout := p.kernel.layout
	stubs := p.kernel.x64
	b := v.regs
	b.reset()

	cr0 := uint64(x64Cr0PE | x64Cr0MP | x64Cr0ET | x64Cr0NE | x64Cr0WP | x64Cr0PG)
	cr4 := uint64(x64Cr4PAE | x64Cr4OSFXSR | x64Cr4OSXMMEXCPT)
	if p.info.xsave {
		cr4 |= x64Cr4OSXSAVE
		b.add64(x64RegXcr0, x64Xcr0)
	}
	b.add64(x64RegCr0, cr0)
	b.add64(x64RegCr3, p.kernel.pt.CR3(false, 0))
	b.add64(x64RegCr4, cr4)
	b.add64(x64RegEfer, x64EferSCE|x64EferLME|x64EferLMA|x64EferNXE)
	b.add64(x64RegStar, uint64(x64StarUserBase)<<48|uint64(x64SelKernelCS)<<32)
	b.add64(x64RegLstar, layout.code()+uint64(stubs.Entry))
	b.add64(x64RegCstar, 0)
	b.add64(x64RegSfmask, x64SfMask)
	b.addTable(x64RegGdtr, layout.sys()+x64SysOffGDT, x64GDTLimit)
	b.addTable(x64RegIdtr, layout.sys()+x64SysOffIDT, x64IDTLimit)
	b.addSegment(x64RegTr, segmentValue{
		base:     v.commVA + commTSSOff,
		limit:    commTSSSize - 1,
		selector: x64SelTR,
		attr:     x64AttrTSS,
	})
	v.addParkRegs(b)
	b.add64(x64RegKernelGsBase, 0)
	b.addSegment(x64RegDs, segmentValue{limit: x64SegLimit})
	b.addSegment(x64RegEs, segmentValue{limit: x64SegLimit})
	b.addSegment(x64RegFs, segmentValue{limit: x64SegLimit})
	if err := p.be.setRegs(v.index, b); err != nil {
		return err
	}
	v.st.invalidate()
	return nil
}

// addParkRegs appends the registers that place the processor at the start of
// the reload path in kernel mode with the kernel GS base.
func (v *vcpu) addParkRegs(b *regBatch) {
	stubs := v.p.kernel.x64
	b.add64(x64RegRip, v.p.kernel.layout.code()+uint64(stubs.Reload))
	b.add64(x64RegRflags, 2)
	b.add64(x64RegRsp, v.commVA+commStackTop)
	b.addSegment(x64RegCs, x64KernelCSValue())
	b.addSegment(x64RegSs, x64KernelSSValue())
	b.addSegment(x64RegGs, segmentValue{base: v.commVA, limit: x64SegLimit})
	b.add64(x64RegInternalActivity, 0)
}

// prepareRun loads the registers of ac into the CommPage and arranges the
// processor so that the next run executes the reload path. It returns done
// when the Sentry must see a result without running the guest.
func (c *Context) prepareRun(v *vcpu, as *AddressSpace, ac *arch.Context64) (runResult, bool) {
	state := ac.StateData()
	r := &state.Regs

	if !x64UserRIPValid(r.Rip) {
		info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: linux.SI_KERNEL}
		return runResult{sig: info, err: platform.ErrContextSignal}, true
	}
	_, csOK := x64UserCSValue(uint16(r.Cs))
	if !csOK || uint16(r.Ss) != x64SelUserSS {
		info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: linux.SI_KERNEL}
		info.SetAddr(r.Rip)
		return runResult{sig: info, err: platform.ErrContextSignal}, true
	}
	fsSeg, fsOK := x64UserDataValue(uint16(r.Fs), r.Fs_base)
	gsSeg, gsOK := x64UserDataValue(uint16(r.Gs), r.Gs_base)
	dsSeg, dsOK := x64UserDataValue(uint16(r.Ds), 0)
	esSeg, esOK := x64UserDataValue(uint16(r.Es), 0)
	if !fsOK || !gsOK || !dsOK || !esOK {
		info := &linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: linux.SI_KERNEL}
		info.SetAddr(r.Rip)
		return runResult{sig: info, err: platform.ErrContextSignal}, true
	}

	if err := c.ensureFP(v, ac); err != nil {
		return runResult{err: err}, true
	}

	comm := v.comm
	flags := x64UserFlags(r.Eflags)
	fast := !state.FullRestore() && flags == r.Eflags
	comm.Regs[0] = r.Rax
	comm.Regs[1] = r.Rcx
	comm.Regs[2] = r.Rdx
	comm.Regs[3] = r.Rbx
	comm.Regs[5] = r.Rbp
	comm.Regs[6] = r.Rsi
	comm.Regs[7] = r.Rdi
	comm.Regs[8] = r.R8
	comm.Regs[9] = r.R9
	comm.Regs[10] = r.R10
	comm.Regs[11] = r.R11
	comm.Regs[12] = r.R12
	comm.Regs[13] = r.R13
	comm.Regs[14] = r.R14
	comm.Regs[15] = r.R15
	comm.SP = r.Rsp
	comm.PC = r.Rip
	comm.Pstate = flags
	comm.CS = r.Cs
	comm.SS = r.Ss
	comm.Root = as.rootValue()
	var cflags uint32
	if fast {
		// SYSRET loads RIP from RCX and RFLAGS from R11.
		comm.Regs[1] = r.Rip
		comm.Regs[11] = flags
	} else {
		cflags |= flagFullRestore
	}
	st := &v.st
	gen := as.gen.Load()
	reloadRoot := rootStale(st, as, gen)
	if reloadRoot {
		cflags |= flagReloadRoot
	}
	atomic.StoreUint32(&comm.Flags, cflags)
	atomic.StoreUint32(&comm.ExitReason, uint32(ExitNone))

	full := !st.valid || !st.parked || c.parkDirty ||
		st.fsBase != r.Fs_base || st.gsBase != r.Gs_base ||
		st.ds != uint16(r.Ds) || st.es != uint16(r.Es) || st.fs != uint16(r.Fs) || st.gs != uint16(r.Gs)
	b := v.regs
	b.reset()
	if reloadRoot {
		b.add64(x64RegCr3, as.rootValue())
	}
	if full {
		v.addParkRegs(b)
		b.addSegment(x64RegDs, dsSeg)
		b.addSegment(x64RegEs, esSeg)
		b.addSegment(x64RegFs, fsSeg)
		b.add64(x64RegKernelGsBase, gsSeg.base)
	} else {
		stubs := v.p.kernel.x64
		b.add64(x64RegRip, v.p.kernel.layout.code()+uint64(stubs.Reload))
		b.add64(x64RegInternalActivity, 0)
	}
	if err := v.p.be.setRegs(v.index, b); err != nil {
		st.invalidate()
		return runResult{err: fmt.Errorf("whpx: resume virtual processor %d: %w", v.index, err)}, true
	}
	if full {
		st.fsBase, st.gsBase = r.Fs_base, r.Gs_base
		st.ds, st.es, st.fs, st.gs = uint16(r.Ds), uint16(r.Es), uint16(r.Fs), uint16(r.Gs)
		c.parkDirty = false
	}
	st.valid = true
	st.parked = true
	// Committing the address space before the run is safe. The batch above
	// wrote CR3 on the host, so the first fetch of the reload path walks the
	// new tables. A path that leaves without a run calls st.invalidate: the
	// kick check in Context.run and a cancel inside the reload path in
	// onCancel. The next entry then writes CR3 again.
	st.asID, st.asGen = as.id, gen
	return runResult{}, false
}

// onStubExit reads the CommPage after the stub halted the processor.
func (c *Context) onStubExit(v *vcpu, _ exitInfo, ac *arch.Context64) (runResult, bool) {
	comm := v.comm
	state := ac.StateData()
	r := &state.Regs
	reason := ExitReason(atomic.LoadUint32(&comm.ExitReason))
	switch reason {
	case ExitSyscall, ExitException:
		r.Rax, r.Rcx, r.Rdx, r.Rbx = comm.Regs[0], comm.Regs[1], comm.Regs[2], comm.Regs[3]
		r.Rbp, r.Rsi, r.Rdi = comm.Regs[5], comm.Regs[6], comm.Regs[7]
		r.R8, r.R9, r.R10, r.R11 = comm.Regs[8], comm.Regs[9], comm.Regs[10], comm.Regs[11]
		r.R12, r.R13, r.R14, r.R15 = comm.Regs[12], comm.Regs[13], comm.Regs[14], comm.Regs[15]
		r.Rsp = comm.SP
		v.st.parked = true
	default:
		v.st.invalidate()
		return runResult{err: fmt.Errorf("whpx: virtual processor %d halted with stub exit reason %d, rip %#x, vector %d, error code %#x",
			v.index, reason, comm.PC, comm.Vector, comm.ESR)}, false
	}
	if reason == ExitSyscall {
		// SYSCALL stores the return address in RCX and the flags in R11.
		r.Rip = r.Rcx
		r.Eflags = r.R11
		r.Orig_rax = r.Rax
		return runResult{}, false
	}
	r.Rip = comm.PC
	r.Eflags = comm.Pstate
	r.Cs = comm.CS
	r.Ss = comm.SS
	t, err := classifyX86(comm.Vector, comm.ESR, comm.FaultAddr, comm.PC)
	if err != nil {
		v.st.invalidate()
		return runResult{err: err}, false
	}
	return t.result(), false
}

// saveUserRegs reads the registers of a processor that stopped in user mode.
func (c *Context) saveUserRegs(v *vcpu, ac *arch.Context64) error {
	r := &ac.StateData().Regs
	b := v.regs
	b.reset()
	for _, name := range [...]uint32{
		x64RegRax, x64RegRcx, x64RegRdx, x64RegRbx, x64RegRsp, x64RegRbp, x64RegRsi, x64RegRdi,
		x64RegR8, x64RegR9, x64RegR10, x64RegR11, x64RegR12, x64RegR13, x64RegR14, x64RegR15,
		x64RegRip, x64RegRflags,
	} {
		b.want(name)
	}
	if err := v.p.be.getRegs(v.index, b); err != nil {
		return fmt.Errorf("whpx: read user registers of virtual processor %d: %w", v.index, err)
	}
	r.Rax, r.Rcx, r.Rdx, r.Rbx = b.u64(0), b.u64(1), b.u64(2), b.u64(3)
	r.Rsp, r.Rbp, r.Rsi, r.Rdi = b.u64(4), b.u64(5), b.u64(6), b.u64(7)
	r.R8, r.R9, r.R10, r.R11 = b.u64(8), b.u64(9), b.u64(10), b.u64(11)
	r.R12, r.R13, r.R14, r.R15 = b.u64(12), b.u64(13), b.u64(14), b.u64(15)
	r.Rip, r.Eflags = b.u64(16), b.u64(17)
	return nil
}

// stubRanges returns the guest addresses of the stub phases.
func (v *vcpu) stubRanges() (entry, exc, reload addrRange) {
	code := v.p.kernel.layout.code()
	s := v.p.kernel.x64
	return addrRange{code + uint64(s.Entry), code + uint64(s.EntryEnd)},
		addrRange{code + uint64(s.ExcStubs), code + uint64(s.CommonEnd)},
		addrRange{code + uint64(s.Reload), code + uint64(s.ReloadEnd)}
}

// onCancel decides what to do after a cancelled run. A processor in user
// mode saves its registers and returns to the Sentry. A processor in the entry
// path continues so that it completes the spill. A processor in the reload
// path returns to the Sentry too. The cancel can stop the reload before its
// MOV to CR3, so the function forgets the whole processor state and the next
// entry writes CR3 again.
func (c *Context) onCancel(v *vcpu, ex exitInfo, ac *arch.Context64) (cancelAction, error) {
	if ex.cpl == 3 {
		if err := c.saveUserRegs(v, ac); err != nil {
			return cancelInterrupt, err
		}
		v.st.parked = false
		return cancelInterrupt, nil
	}
	entry, exc, reload := v.stubRanges()
	switch {
	case entry.contains(ex.pc) || exc.contains(ex.pc):
		return cancelContinue, nil
	case reload.contains(ex.pc):
		v.st.invalidate()
		return cancelInterrupt, nil
	}
	return cancelInterrupt, fmt.Errorf("whpx: virtual processor %d was cancelled at unknown kernel address %#x", v.index, ex.pc)
}
