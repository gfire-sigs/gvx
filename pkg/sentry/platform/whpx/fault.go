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
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// si_code values of SIGSEGV, SIGBUS, SIGILL and SIGFPE. The linux package
// only defines the SIGTRAP and SI_* codes.
const (
	segvMapErr = 1
	segvAccErr = 2
	busAdrAln  = 1
	busAdrErr  = 2
	illIllOpc  = 1
	illIllOpn  = 2
	illIllTrp  = 4
	fpeIntDiv  = 1
	fpeIntOvf  = 2
	fpeFltInv  = 7
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

// Vectors of x86 exceptions.
const (
	x86VecDivide        = 0
	x86VecDebug         = 1
	x86VecNMI           = 2
	x86VecBreakpoint    = 3
	x86VecOverflow      = 4
	x86VecBound         = 5
	x86VecInvalidOpcode = 6
	x86VecNoMath        = 7
	x86VecDoubleFault   = 8
	x86VecInvalidTSS    = 10
	x86VecSegNotPresent = 11
	x86VecStackSegment  = 12
	x86VecGeneralProt   = 13
	x86VecPageFault     = 14
	x86VecX87           = 16
	x86VecAlignment     = 17
	x86VecMachineCheck  = 18
	x86VecSIMD          = 19
)

// classifyX86 maps an exception of the amd64 stub to a signal. The mapping
// follows the KVM platform so that applications see the same signals.
func classifyX86(vector, errCode, cr2, rip uint64) (trap, error) {
	t := trap{kind: trapSignal, hasAddr: true, addr: rip}
	switch vector {
	case x86VecPageFault:
		t.signo = linux.SIGSEGV
		t.addr = cr2
		t.access = hostarch.AccessType{
			Read:    errCode&(1<<1) == 0,
			Write:   errCode&(1<<1) != 0,
			Execute: errCode&(1<<4) != 0,
		}
		t.code = segvMapErr
		if errCode&1 != 0 {
			t.code = segvAccErr
		}
	case x86VecDebug:
		t.signo = linux.SIGTRAP
		t.code = linux.TRAP_TRACE
	case x86VecBreakpoint:
		t.signo = linux.SIGTRAP
		t.code = linux.SI_KERNEL
		t.hasAddr, t.addr = false, 0
	case x86VecGeneralProt, x86VecSegNotPresent, x86VecBound, x86VecInvalidTSS, x86VecStackSegment:
		t.signo = linux.SIGSEGV
		t.code = linux.SI_KERNEL
	case x86VecInvalidOpcode, x86VecNoMath:
		t.signo = linux.SIGILL
		t.code = illIllOpc
	case x86VecDivide:
		t.signo = linux.SIGFPE
		t.code = fpeIntDiv
	case x86VecOverflow:
		t.signo = linux.SIGFPE
		t.code = fpeIntOvf
	case x86VecX87, x86VecSIMD:
		t.signo = linux.SIGFPE
		t.code = fpeFltInv
	case x86VecAlignment:
		t.signo = linux.SIGBUS
		t.code = busAdrAln
		t.hasAddr, t.addr = false, 0
	case x86VecNMI, x86VecDoubleFault, x86VecMachineCheck:
		return trap{}, fmt.Errorf("whpx: unrecoverable guest exception, vector %d, error code %#x, rip %#x", vector, errCode, rip)
	default:
		t.signo = linux.SIGSEGV
		t.code = linux.SI_KERNEL
	}
	return t, nil
}

// ESR_EL1 exception classes that EL0 can raise.
const (
	esrECUnknown   = 0x00
	esrECWFx       = 0x01
	esrECFPAccess  = 0x07
	esrECIllState  = 0x0E
	esrECSVC64     = 0x15
	esrECSysReg    = 0x18
	esrECInstrAbrt = 0x20
	esrECPCAlign   = 0x22
	esrECDataAbrt  = 0x24
	esrECSPAlign   = 0x26
	esrECFPExc     = 0x2C
	esrECSError    = 0x2F
	esrECBrkptLow  = 0x30
	esrECStepLow   = 0x32
	esrECWatchLow  = 0x34
	esrECBrk64     = 0x3C

	esrECShift = 26
	esrWnR     = 1 << 6
	esrCM      = 1 << 8
	esrFSCMask = 0x3F
)

// classifyA64 maps an exception of the arm64 stub to a system call, a signal
// or a skipped instruction. slot is the vector table slot, esr and far are
// the syndrome and fault address registers, and pc is ELR_EL1.
func classifyA64(slot, esr, far, pc uint64) (trap, error) {
	if slot != a64SlotLowA64Sync {
		if slot == a64SlotLowA64SErr {
			return trap{kind: trapSignal, signo: linux.SIGBUS, code: busAdrErr, hasAddr: true, addr: pc}, nil
		}
		return trap{}, fmt.Errorf("whpx: unexpected arm64 exception vector slot %d, esr %#x, pc %#x", slot, esr, pc)
	}
	ec := esr >> esrECShift & 0x3F
	t := trap{kind: trapSignal, hasAddr: true, addr: pc}
	switch ec {
	case esrECSVC64:
		return trap{kind: trapSyscall}, nil
	case esrECWFx:
		return trap{kind: trapSkip}, nil
	case esrECDataAbrt, esrECInstrAbrt:
		t.addr = far
		t.access = a64AccessType(esr)
		fsc := esr & esrFSCMask
		switch {
		case fsc <= 0x03:
			t.signo, t.code = linux.SIGSEGV, segvMapErr
		case fsc >= 0x04 && fsc <= 0x07:
			t.signo, t.code = linux.SIGSEGV, segvMapErr
		case fsc == 0x21:
			t.signo, t.code = linux.SIGBUS, busAdrAln
		case fsc >= 0x09 && fsc <= 0x0F:
			t.signo, t.code = linux.SIGSEGV, segvAccErr
		default:
			t.signo, t.code = linux.SIGBUS, busAdrErr
		}
	case esrECPCAlign, esrECSPAlign:
		t.signo, t.code = linux.SIGBUS, busAdrAln
		if ec == esrECPCAlign {
			t.addr = far
		}
	case esrECSError:
		t.signo, t.code = linux.SIGBUS, busAdrErr
	case esrECFPExc:
		t.signo, t.code = linux.SIGFPE, fpeFltInv
	case esrECBrk64:
		t.signo, t.code = linux.SIGTRAP, linux.TRAP_BRKPT
	case esrECBrkptLow, esrECWatchLow:
		t.signo, t.code = linux.SIGTRAP, linux.TRAP_HWBKPT
	case esrECStepLow:
		t.signo, t.code = linux.SIGTRAP, linux.TRAP_TRACE
	case esrECUnknown, esrECIllState, esrECSysReg, esrECFPAccess:
		t.signo, t.code = linux.SIGILL, illIllOpc
	default:
		t.signo, t.code = linux.SIGILL, illIllTrp
	}
	return t, nil
}

// emulateA64SysReg emulates an EL0 read of an ARM64 ID register or CTR_EL0 when
// the lower-EL synchronous exception has EC = 0x18. It writes the result into
// comm.Regs and reports true when the guest should skip the trapped instruction
// and resume.
func emulateA64SysReg(comm *CommPage, ids *hvcommon.IDRegisters) bool {
	if comm.Vector != hvcommon.SlotLowerSync {
		return false
	}
	if comm.FaultCode>>esrECShift&0x3F != esrECSysReg {
		return false
	}
	iss := hvcommon.DecodeSysRegISS(comm.FaultCode)
	val, ok := ids.EmulateSysRegRead(iss)
	if !ok {
		return false
	}
	if iss.Rt < 31 {
		comm.Regs[iss.Rt] = val
	}
	return true
}

// a64AccessType decodes the access of a data or instruction abort from ESR_EL1.
func a64AccessType(esr uint64) hostarch.AccessType {
	switch esr >> esrECShift & 0x3F {
	case esrECInstrAbrt:
		return hostarch.Execute
	case esrECDataAbrt:
		if esr&(esrWnR|esrCM) == esrWnR {
			return hostarch.Write
		}
		return hostarch.Read
	}
	return hostarch.NoAccess
}
