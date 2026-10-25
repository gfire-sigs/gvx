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

package whpx

import (
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// si_code values of SIGSEGV, SIGBUS, SIGILL and SIGFPE.
const (
	segvMapErr = hvcommon.SegvMapErr
	segvAccErr = hvcommon.SegvAccErr
	busAdrAln  = hvcommon.BusAdrAln
	busAdrErr  = hvcommon.BusAdrErr
	illIllOpc  = hvcommon.IllIllOpc
	illIllOpn  = hvcommon.IllIllOpn
	illIllTrp  = hvcommon.IllIllTrp
	fpeIntDiv  = hvcommon.FpeIntDiv
	fpeIntOvf  = hvcommon.FpeIntOvf
	fpeFltInv  = hvcommon.FpeFltInv
)

// trapKind tells the Switch loop what an exit from the stub means.
type trapKind uint8

const (
	// trapSyscall is a Linux system call.
	trapSyscall trapKind = iota

	// trapSignal is a fault that becomes a signal for the application.
	trapSignal

	// trapSkip is an instruction that the Sentry skips, as the KVM platform
	// does for WFI and WFE on arm64.
	trapSkip
)

// trap is the classification of one exit from the stub.
type trap struct {
	kind   trapKind
	signo  linux.Signal
	code   int32
	addr   uint64
	access hostarch.AccessType

	// hasAddr is true when addr goes into si_addr.
	hasAddr bool
}

// result converts a trap into the return values of Switch.
func (t trap) result() runResult {
	info := &linux.SignalInfo{Signo: int32(t.signo), Code: t.code}
	if t.hasAddr {
		info.SetAddr(t.addr)
	}
	return runResult{sig: info, at: t.access, err: platform.ErrContextSignal}
}

// Vectors of x86 exceptions.
const (
	x86VecDivide        = hvcommon.X86VecDivide
	x86VecDebug         = hvcommon.X86VecDebug
	x86VecNMI           = hvcommon.X86VecNMI
	x86VecBreakpoint    = hvcommon.X86VecBreakpoint
	x86VecOverflow      = hvcommon.X86VecOverflow
	x86VecBound         = hvcommon.X86VecBound
	x86VecInvalidOpcode = hvcommon.X86VecInvalidOpcode
	x86VecNoMath        = hvcommon.X86VecNoMath
	x86VecDoubleFault   = hvcommon.X86VecDoubleFault
	x86VecInvalidTSS    = hvcommon.X86VecInvalidTSS
	x86VecSegNotPresent = hvcommon.X86VecSegNotPresent
	x86VecStackSegment  = hvcommon.X86VecStackSegment
	x86VecGeneralProt   = hvcommon.X86VecGeneralProt
	x86VecPageFault     = hvcommon.X86VecPageFault
	x86VecX87           = hvcommon.X86VecX87
	x86VecAlignment     = hvcommon.X86VecAlignment
	x86VecMachineCheck  = hvcommon.X86VecMachineCheck
	x86VecSIMD          = hvcommon.X86VecSIMD
)

// classifyX86 maps an exception of the amd64 stub to a signal.
func classifyX86(vector, errCode, cr2, rip uint64) (trap, error) {
	sig, at, hasAddr, addr, err := hvcommon.ClassifyX86Exception(vector, errCode, cr2, rip)
	if err != nil {
		return trap{}, fmt.Errorf("whpx: %w", err)
	}
	return trap{
		kind:    trapSignal,
		signo:   linux.Signal(sig.Signo),
		code:    sig.Code,
		addr:    addr,
		access:  at,
		hasAddr: hasAddr,
	}, nil
}

// ESR_EL1 exception classes that EL0 can raise.
const (
	esrECUnknown   = hvcommon.ECUnknown
	esrECWFx       = hvcommon.ECWFx
	esrECFPAccess  = hvcommon.ECFPAccess
	esrECIllState  = hvcommon.ECIllegalState
	esrECSVC64     = hvcommon.ECSVC64
	esrECSysReg    = hvcommon.ECSysReg
	esrECInstrAbrt = hvcommon.ECInstrAbortLower
	esrECPCAlign   = hvcommon.ECPCAlignment
	esrECDataAbrt  = hvcommon.ECDataAbortLower
	esrECSPAlign   = hvcommon.ECSPAlignment
	esrECFPExc     = hvcommon.ECFPExc64
	esrECSError    = hvcommon.ECSError
	esrECBrkptLow  = hvcommon.ECBreakpointLower
	esrECStepLow   = hvcommon.ECSoftStepLower
	esrECWatchLow  = hvcommon.ECWatchpointLower
	esrECBrk64     = hvcommon.ECBRK64

	esrECShift = hvcommon.ESRECShift
	esrWnR     = 1 << 6
	esrCM      = 1 << 8
	esrFSCMask = hvcommon.ESRFSCMask
)

// classifyA64 maps an exception of the arm64 stub to a system call, a signal,
// or a skipped instruction.
func classifyA64(slot, esr, far, pc, sp uint64) (trap, error) {
	if slot != a64SlotLowA64Sync {
		if slot == a64SlotLowA64SErr {
			return trap{kind: trapSignal, signo: linux.SIGBUS, code: busAdrErr, hasAddr: true, addr: pc}, nil
		}
		return trap{}, fmt.Errorf("whpx: unexpected arm64 exception vector slot %d, esr %#x, pc %#x", slot, esr, pc)
	}
	kind, sig, at := hvcommon.DecodeA64SyncException(esr, far, pc, sp)
	switch kind {
	case hvcommon.A64ExitSyscall:
		return trap{kind: trapSyscall}, nil
	case hvcommon.A64ExitSkip:
		return trap{kind: trapSkip}, nil
	case hvcommon.A64ExitSysReg:
		return trap{kind: trapSignal, signo: linux.SIGILL, code: illIllOpc, hasAddr: true, addr: pc}, nil
	default:
		return trap{
			kind:    trapSignal,
			signo:   linux.Signal(sig.Signo),
			code:    sig.Code,
			addr:    sig.Addr(),
			access:  at,
			hasAddr: true,
		}, nil
	}
}

// emulateA64SysReg emulates an EL0 read of an ARM64 ID register or CTR_EL0 when
// the lower-EL synchronous exception has EC = 0x18.
func emulateA64SysReg(comm *CommPage, ids *hvcommon.IDRegisters) bool {
	if comm.Vector != hvcommon.SlotLowerSync {
		return false
	}
	if hvcommon.ESREC(comm.ESR) != esrECSysReg {
		return false
	}
	iss := hvcommon.DecodeSysRegISS(comm.ESR)
	val, ok := ids.EmulateSysRegRead(iss)
	if !ok {
		return false
	}
	if iss.Rt < 31 {
		comm.Regs[iss.Rt] = val
	}
	return true
}
