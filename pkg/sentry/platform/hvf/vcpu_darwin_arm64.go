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

package hvf

import (
	"errors"
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// Design notes for the vCPU state that this backend does not virtualize.
//
// ASIDs: every user translation uses ASID 0, and a vCPU flushes its TLB through
// the stub when the address space or its generation changes. Apple cores
// implement 8-bit ASIDs (ID_AA64MMFR0_EL1.ASIDBits is 0), so 255 live address
// spaces would exhaust them and force a global flush protocol. TTBR1 already
// removes the walk-cache hazard that motivated ASIDs, and the generation check
// already removes the per-return TLBI, so ASIDs would add cost without a gain.
//
// Pointer authentication: SCTLR_EL1 leaves EnIA, EnIB, EnDA and EnDB clear, so
// PAC instructions are no-ops that never fault. AT_HWCAP comes from
// cpuid.AllowedHWCap1, which excludes HWCAP_PACA and HWCAP_PACG, and the
// emulated ID registers hide APA, API, GPA and GPI. SPEC 3.4 allows this mask in
// place of key preservation. The APxKey registers keep the framework reset
// value on every vCPU, so no key can differ between Contexts.
//
// Debug registers: arch.Context64 has no field for DBGBVR, DBGBCR, DBGWVR or
// DBGWCR, the Sentry ptrace implementation exposes no hardware breakpoints, and
// EL0 cannot access the registers. No cold path needs to synchronize them.
//
// TPIDRRO_EL0: EL0 only reads it and the Sentry has no setter, so it stays
// zero, which is the Linux value for 64-bit tasks.

// syncState names the translation state a vCPU last flushed for.
type syncState struct {
	pt  uint64 // stage1Tables.id; zero means unknown.
	tlb uint64
	ic  uint64
}

// archWorker is the ARM64 state that only the worker thread touches.
type archWorker struct {
	ttbr0      uint64
	ttbr0Valid bool
	// needsReset means the vCPU does not wait at the reload stub, so the next
	// entry must reset PC and PSTATE first.
	needsReset bool
	// synced is the flush state that a completed guest run confirmed. entry is
	// the state the current entry asks the stub to establish.
	synced, entry syncState
	ids           hvcommon.IDRegisters
	// unknownExits counts consecutive hvExitReasonUnknown exits.
	unknownExits int
}

// reloadAddr is the address of the stub reload routine in the guest.
const reloadAddr = kernelVectorVA + vectorReloadOffset

// initVCPU creates the vCPU on the calling thread and loads the EL1 state that
// never changes between runs.
func (w *vcpuWorker) initVCPU() error {
	id, exit, err := hvVCPUCreate()
	if err != nil {
		return err
	}
	w.id, w.exit = id, exit
	if err := w.configure(); err != nil {
		w.destroyed.Store(true)
		return errors.Join(err, hvVCPUDestroy(id))
	}
	return nil
}

func (w *vcpuWorker) configure() error {
	mmfr0, err := hvGetSysReg(w.id, hvSysRegIDAA64MMFR0)
	if err != nil {
		return err
	}
	// PARange (bits 3:0) bounds the output size. Values above 5 name sizes
	// the descriptors of this backend do not use.
	ips := min(mmfr0&0xf, 5)

	for _, s := range []struct {
		reg uint32
		val uint64
	}{
		{hvSysRegMAIR, hvcommon.MAIRNormalWB},
		{hvSysRegTCR, hvcommon.TCR(ips)},
		{hvSysRegTTBR1, w.vm.kernel.ttbr1()},
		{hvSysRegCPACR, hvcommon.CPACRNoTrap},
		{hvSysRegCNTKCTL, hvcommon.CNTKCTLEL0},
		{hvSysRegCNTVCTL, cntvCtlMasked},
		{hvSysRegVBAR, kernelVectorVA},
		{hvSysRegSPEL1, w.comm.va},
		{hvSysRegTPIDRRO, 0},
		{hvSysRegSCTLR, sctlrEL1},
	} {
		if err := hvSetSysReg(w.id, s.reg, s.val); err != nil {
			return err
		}
	}
	if err := w.readIDRegisters(); err != nil {
		return err
	}
	w.ids.Counter = readSystemCounter
	w.needsReset = true
	return nil
}

// readIDRegisters caches the values that EL0 reads of the ID registers.
func (w *vcpuWorker) readIDRegisters() error {
	for _, f := range []struct {
		reg uint32
		dst *uint64
	}{
		{hvSysRegMIDR, &w.ids.MIDR},
		{hvSysRegIDAA64PFR0, &w.ids.PFR0},
		{hvSysRegIDAA64PFR1, &w.ids.PFR1},
		{hvSysRegIDAA64ISAR0, &w.ids.ISAR0},
		{hvSysRegIDAA64ISAR1, &w.ids.ISAR1},
		{hvSysRegIDAA64MMFR0, &w.ids.MMFR0},
		{hvSysRegIDAA64MMFR1, &w.ids.MMFR1},
		{hvSysRegIDAA64MMFR2, &w.ids.MMFR2},
	} {
		v, err := hvGetSysReg(w.id, f.reg)
		if err != nil {
			return err
		}
		*f.dst = v
	}
	return nil
}

// invalidateState forgets everything the host believes about the vCPU. The
// next entry rebuilds PC, PSTATE, TTBR0 and the flush state.
func (w *vcpuWorker) invalidateState() {
	w.needsReset = true
	w.ttbr0Valid = false
	w.synced = syncState{}
}

// loadContext copies the Sentry thread state into the CommPage. Every Switch
// loads all registers: ac stays the single source of truth.
func (w *vcpuWorker) loadContext(comm *CommPage, ac *arch.Context64) error {
	fp := *ac.FloatingPointData()
	if len(fp) < fpStateSize {
		return fmt.Errorf("hvf: floating point state has %d bytes, want %d", len(fp), fpStateSize)
	}
	r := &ac.StateData().Regs
	comm.Regs = r.Regs
	comm.SP = r.Sp
	comm.PC = r.Pc
	comm.Pstate = r.Pstate & pstateUserMask
	comm.TLS = r.TPIDR_EL0
	copy(vregBytes(comm), fp[:vregsSize])
	comm.FPSR = uint64(nativeUint32(fp[vregsSize:]))
	comm.FPCR = uint64(nativeUint32(fp[vregsSize+4:]))
	return nil
}

// storeContext copies the CommPage state back into ac.
func (w *vcpuWorker) storeContext(comm *CommPage, ac *arch.Context64) {
	r := &ac.StateData().Regs
	r.Regs = comm.Regs
	r.Sp = comm.SP
	r.Pc = comm.PC
	r.Pstate = comm.Pstate & pstateUserMask
	r.TPIDR_EL0 = comm.TLS
	fp := *ac.FloatingPointData()
	copy(fp[:vregsSize], vregBytes(comm))
	putNativeUint32(fp[vregsSize:], uint32(comm.FPSR))
	putNativeUint32(fp[vregsSize+4:], uint32(comm.FPCR))
}

const (
	vregsSize   = 32 * 16
	fpStateSize = vregsSize + 8 // V0..V31, FPSR, FPCR.
)

func vregBytes(comm *CommPage) []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&comm.VRegs[0])), vregsSize)
}

// The host is little-endian ARM64, which matches the FP state layout.
func nativeUint32(b []byte) uint32 {
	return *(*uint32)(unsafe.Pointer(&b[0]))
}

func putNativeUint32(b []byte, v uint32) {
	*(*uint32)(unsafe.Pointer(&b[0])) = v
}

// runSwitch executes one Switch request on the worker thread.
func (w *vcpuWorker) runSwitch(r *switchReq) (*linux.SignalInfo, hostarch.AccessType, error) {
	c, as, ac := r.c, r.as, r.ac
	pt := as.pt
	comm := w.comm.view

	// Publish the table before any test of its state. retire and quiesce scan
	// curPT after they mark the table dead or bump its generation.
	w.curPT.Store(pt)
	defer w.curPT.Store(nil)

	if err := w.loadContext(comm, ac); err != nil {
		return nil, hostarch.NoAccess, err
	}
	info, at, err := w.runLoop(c, pt, ac)
	w.storeContext(comm, ac)
	return info, at, err
}

// runLoop enters the guest until an exit needs the Sentry.
//
// The first check consumes an interrupt that is already pending. The vCPU holds
// a complete state at that point. After a later exit that resumes the guest,
// onCancel handles a pending interrupt. Returning straight from the spill
// routine would leave the stub exception in the CommPage. The next entry would
// then replay the HVC against that stale exception.
func (w *vcpuWorker) runLoop(c *Context, pt *stage1Tables, ac *arch.Context64) (*linux.SignalInfo, hostarch.AccessType, error) {
	if c.interrupted.CompareAndSwap(true, false) {
		return nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	for {
		if w.quit.Load() {
			return nil, hostarch.NoAccess, errPlatformClosed
		}
		if err := w.prepareEntry(pt); err != nil {
			return nil, hostarch.NoAccess, err
		}
		if !w.beginRun(pt) {
			continue
		}
		runErr := hvVCPURun(w.id)
		w.inGuest.Store(false)
		if runErr != nil {
			w.invalidateState()
			return nil, hostarch.NoAccess, runErr
		}
		if e := w.cancelErr.Swap(nil); e != nil {
			w.invalidateState()
			return nil, hostarch.NoAccess, fmt.Errorf("hvf: a cancellation of the vCPU failed: %w", *e)
		}
		done, info, at, err := w.dispatchExit(c, pt, ac)
		if done {
			return info, at, err
		}
		if c.interrupted.Load() {
			// The exit left the guest live. onCancel records the state for the
			// interrupt and consumes the flag, or it resumes the guest.
			if done, info, at, err = w.onCancel(c, pt); done {
				return info, at, err
			}
		}
	}
}

// prepareEntry readies PC, PSTATE, TTBR0 and the flush flags for one entry.
func (w *vcpuWorker) prepareEntry(pt *stage1Tables) error {
	if pt.dead.Load() {
		return errPageTableReleased
	}
	if w.needsReset {
		if err := hvSetReg(w.id, hvRegCPSR, hvcommon.PstateEL1h); err != nil {
			w.invalidateState()
			return err
		}
		if err := hvSetReg(w.id, hvRegPC, reloadAddr); err != nil {
			w.invalidateState()
			return err
		}
		w.needsReset = false
	}
	if root := pt.RootIPA(); !w.ttbr0Valid || w.ttbr0 != root {
		if err := hvSetSysReg(w.id, hvSysRegTTBR0, root); err != nil {
			w.invalidateState()
			return err
		}
		w.ttbr0, w.ttbr0Valid = root, true
	}
	tlb, ic := pt.generations()
	var flags uint64
	if w.synced.pt != pt.id || w.synced.tlb != tlb {
		flags |= flagFlushTLB
	}
	if w.synced.pt != pt.id || w.synced.ic != ic {
		flags |= flagFlushICache
	}
	w.comm.view.Flags = flags
	w.entry = syncState{pt: pt.id, tlb: tlb, ic: ic}
	return nil
}

// beginRun announces the entry to quiesce. It reports false when the table
// changed between prepareEntry and the announcement: the caller prepares
// again, so the flush flags cover the newer generation.
func (w *vcpuWorker) beginRun(pt *stage1Tables) bool {
	w.enterTLB.Store(w.entry.tlb)
	w.inGuest.Store(true)
	if pt.tlbGen.Load() != w.entry.tlb || pt.dead.Load() {
		w.inGuest.Store(false)
		return false
	}
	return true
}

// guestRan records that the guest executed at EL0 after the entry: the stub
// completed the flush it was asked for.
func (w *vcpuWorker) guestRan() {
	w.synced = w.entry
}

// maxUnknownExits bounds the consecutive hvExitReasonUnknown exits that
// dispatchExit resumes. A signal storm resumes within a few entries, so a
// vCPU that keeps failing this way has a real fault.
const maxUnknownExits = 4096

// dispatchExit decodes one hv_vcpu_run exit. It reports done=false when the
// loop must enter the guest again.
func (w *vcpuWorker) dispatchExit(c *Context, pt *stage1Tables, ac *arch.Context64) (done bool, info *linux.SignalInfo, at hostarch.AccessType, err error) {
	if w.exit.reason != hvExitReasonUnknown {
		w.unknownExits = 0
	}
	switch w.exit.reason {
	case hvExitReasonCanceled:
		return w.onCancel(c, pt)
	case hvExitReasonException:
		if hvcommon.ESREC(w.exit.syndrome) == hvcommon.ECHVC64 {
			return w.onStubExit(ac)
		}
		return w.onHypervisorException()
	case hvExitReasonUnknown:
		// WHY: under a collector that runs often (GOGC=1), 5 of 200 runs ended
		// with this reason, and the exit carried no information. With
		// GODEBUG=asyncpreemptoff=1, no run of 200 failed. A host signal that
		// interrupts hv_vcpu_run, such as the SIGURG of Go preemption, is the
		// probable cause. The vCPU keeps its registers across the exit. A real
		// fault repeats on the next entry and then reports its own reason, so a
		// resume loses nothing.
		w.unknownExits++
		if w.unknownExits > maxUnknownExits {
			w.invalidateState()
			return true, nil, hostarch.NoAccess, fmt.Errorf(
				"hvf: %d consecutive vCPU exits with an unknown reason", w.unknownExits)
		}
		return w.onCancel(c, pt)
	default:
		w.invalidateState()
		return true, nil, hostarch.NoAccess, fmt.Errorf(
			"hvf: unexpected vCPU exit reason %d (syndrome=%#x)", w.exit.reason, w.exit.syndrome)
	}
}

// inSpillRoutine reports whether an EL1 program counter lies before the HVC of
// the stub spill routine. The vCPU then holds guest state in hardware registers
// that only the stub can save.
func inSpillRoutine(pc uint64) bool {
	return pc >= kernelVectorVA && pc < reloadAddr
}

// onCancel resumes after a cancellation unless the Sentry needs the vCPU.
func (w *vcpuWorker) onCancel(c *Context, pt *stage1Tables) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	pending := c.interrupted.Load()
	stale := pt.tlbGen.Load() != w.entry.tlb || pt.dead.Load()
	quit := w.quit.Load()
	if !pending && !stale && !quit {
		// A stale cancellation from an earlier Switch. Resume exactly where
		// the vCPU stopped.
		return false, nil, hostarch.NoAccess, nil
	}
	cpsr, err := hvGetReg(w.id, hvRegCPSR)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if cpsr&pstateModeMask == 0 {
		// The guest runs at EL0: read its registers from the hardware.
		if err := w.captureGuest(); err != nil {
			w.invalidateState()
			return true, nil, hostarch.NoAccess, err
		}
		w.needsReset = true
		w.guestRan()
	} else {
		pc, err := hvGetReg(w.id, hvRegPC)
		if err != nil {
			w.invalidateState()
			return true, nil, hostarch.NoAccess, err
		}
		if inSpillRoutine(pc) {
			// The stub holds the guest state in registers. Let it spill and
			// reach its HVC: the stub exit then reports the state in the
			// CommPage and the interrupt flag stays set for the next Switch.
			return false, nil, hostarch.NoAccess, nil
		}
		// The reload routine only reads the CommPage, which is complete.
		// Restart it later from its first instruction and leave the guest.
		w.needsReset = true
		w.synced = syncState{}
	}
	switch {
	case quit:
		return true, nil, hostarch.NoAccess, errPlatformClosed
	case pending && c.interrupted.CompareAndSwap(true, false):
		return true, nil, hostarch.NoAccess, platform.ErrContextInterrupt
	}
	return false, nil, hostarch.NoAccess, nil
}

// onStubExit decodes an HVC from the EL1 stub. The CommPage holds the guest
// state.
func (w *vcpuWorker) onStubExit(ac *arch.Context64) (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	comm := w.comm.view
	act := decodeStubExit(comm.Vector, comm.ESR, comm.FaultAddr, comm.PC, comm.SP)
	if comm.Vector == vecLowerELSync {
		w.guestRan()
	} else {
		w.synced = syncState{}
	}
	switch act.kind {
	case exitSyscall:
		ac.StateData().OrigR0 = comm.Regs[0]
		return true, nil, hostarch.NoAccess, nil
	case exitSignal:
		return true, act.info, act.at, platform.ErrContextSignal
	case exitSysReg:
		iss := hvcommon.DecodeSysRegISS(comm.ESR)
		val, ok := w.ids.EmulateSysRegRead(iss)
		if !ok {
			// Writes and unknown registers raise SIGILL, as Linux does.
			ill := signalAction(linux.SIGILL, sigIllIllOpc, comm.PC, hostarch.NoAccess)
			return true, ill.info, ill.at, platform.ErrContextSignal
		}
		if iss.Rt != 31 {
			comm.Regs[iss.Rt] = val
		}
		comm.PC += 4
		return false, nil, hostarch.NoAccess, nil
	default:
		w.invalidateState()
		return true, nil, hostarch.NoAccess, act.err
	}
}

// onHypervisorException decodes an exception that the framework reports
// directly, without the stub. The guest registers still sit in the hardware.
func (w *vcpuWorker) onHypervisorException() (bool, *linux.SignalInfo, hostarch.AccessType, error) {
	exit := w.exit
	act := decodeHypervisorExit(exit.syndrome, exit.virtualAddress, exit.physicalAddress)
	cpsr, err := hvGetReg(w.id, hvRegCPSR)
	if err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	if cpsr&pstateModeMask != 0 {
		// The guest ran EL1 code: only the stub does, and it uses no
		// instruction that traps. The backend is inconsistent.
		w.invalidateState()
		return true, nil, hostarch.NoAccess, fmt.Errorf(
			"hvf: exception in the EL1 stub (syndrome=%#x va=%#x ipa=%#x cpsr=%#x)",
			exit.syndrome, exit.virtualAddress, exit.physicalAddress, cpsr)
	}
	switch act.kind {
	case exitWFx:
		return false, nil, hostarch.NoAccess, w.advancePC()
	case exitSysReg:
		iss := hvcommon.DecodeSysRegISS(exit.syndrome)
		if val, ok := w.ids.EmulateSysRegRead(iss); ok {
			if iss.Rt != 31 {
				if err := hvSetReg(w.id, hvRegX0+iss.Rt, val); err != nil {
					w.invalidateState()
					return true, nil, hostarch.NoAccess, err
				}
			}
			return false, nil, hostarch.NoAccess, w.advancePC()
		}
	}
	// A fault, an unsupported register access, or an unknown exception: report
	// it with the full guest state.
	if err := w.captureGuest(); err != nil {
		w.invalidateState()
		return true, nil, hostarch.NoAccess, err
	}
	w.needsReset = true
	w.guestRan()
	switch act.kind {
	case exitSignal:
		return true, act.info, act.at, platform.ErrContextSignal
	case exitSysReg:
		pc := w.comm.view.PC
		ill := signalAction(linux.SIGILL, sigIllIllOpc, pc, hostarch.NoAccess)
		return true, ill.info, ill.at, platform.ErrContextSignal
	default:
		w.invalidateState()
		return true, nil, hostarch.NoAccess, act.err
	}
}

// advancePC steps the guest over the trapped instruction.
func (w *vcpuWorker) advancePC() error {
	pc, err := hvGetReg(w.id, hvRegPC)
	if err != nil {
		w.invalidateState()
		return err
	}
	if err := hvSetReg(w.id, hvRegPC, pc+4); err != nil {
		w.invalidateState()
		return err
	}
	return nil
}

// captureGuest reads the EL0 register state of the vCPU from the hardware into
// the CommPage. It is the cold path: 31 general registers, SP_EL0, PC, PSTATE,
// TPIDR_EL0, FPCR, FPSR and 32 V registers.
func (w *vcpuWorker) captureGuest() error {
	comm := w.comm.view
	for i := range comm.Regs {
		v, err := hvGetReg(w.id, hvRegX0+uint32(i))
		if err != nil {
			return err
		}
		comm.Regs[i] = v
	}
	sp, err := hvGetSysReg(w.id, hvSysRegSPEL0)
	if err != nil {
		return err
	}
	pc, err := hvGetReg(w.id, hvRegPC)
	if err != nil {
		return err
	}
	cpsr, err := hvGetReg(w.id, hvRegCPSR)
	if err != nil {
		return err
	}
	tls, err := hvGetSysReg(w.id, hvSysRegTPIDREL0)
	if err != nil {
		return err
	}
	fpcr, err := hvGetReg(w.id, hvRegFPCR)
	if err != nil {
		return err
	}
	fpsr, err := hvGetReg(w.id, hvRegFPSR)
	if err != nil {
		return err
	}
	for i := range comm.VRegs {
		v, err := hvGetSimdFPReg(w.id, uint32(i))
		if err != nil {
			return err
		}
		comm.VRegs[i] = v
	}
	comm.SP, comm.PC, comm.Pstate, comm.TLS = sp, pc, cpsr&pstateUserMask, tls
	comm.FPCR, comm.FPSR = fpcr, fpsr
	return nil
}
