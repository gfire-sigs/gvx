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
	"fmt"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// ESR_ELx exception classes (ARM DDI 0487, D17.2.37).
const (
	ecUnknown      = hvcommon.ECUnknown
	ecWFx          = hvcommon.ECWFx
	ecIllegalState = hvcommon.ECIllegalState
	ecSVC64        = hvcommon.ECSVC64
	ecHVC64        = hvcommon.ECHVC64
	ecSysReg       = hvcommon.ECSysReg
	ecInstrAbort   = hvcommon.ECInstrAbortLower
	ecPCAlignment  = hvcommon.ECPCAlignment
	ecDataAbort    = hvcommon.ECDataAbortLower
	ecSPAlignment  = hvcommon.ECSPAlignment
	ecFPExc64      = hvcommon.ECFPExc64
	ecBreakpoint   = hvcommon.ECBreakpointLower
	ecBreakpointEL = hvcommon.ECBreakpointCur
	ecSoftStep     = hvcommon.ECSoftStepLower
	ecSoftStepEL   = hvcommon.ECSoftStepCur
	ecWatchpoint   = hvcommon.ECWatchpointLower
	ecWatchpointEL = hvcommon.ECWatchpointCur
	ecBRK64        = hvcommon.ECBRK64
)

// Fault status codes in ESR_ELx.ISS for aborts.
const (
	fscTranslationL0 = hvcommon.FSCTranslationL0
	fscTranslationL3 = hvcommon.FSCTranslationL3
	fscPermissionL1  = hvcommon.FSCPermissionL1
	fscPermissionL3  = hvcommon.FSCPermissionL3
	fscSyncExternal  = hvcommon.FSCSyncExternal
	fscAlignment     = hvcommon.FSCAlignment

	issS1PTW = 1 << 7 // The abort happened during a stage-1 table walk.
)

func esrEC(esr uint64) uint64  { return hvcommon.ESREC(esr) }
func esrFSC(esr uint64) uint64 { return hvcommon.ESRFSC(esr) }

// decodeStubExit decodes the state that the EL1 stub spilled: the vector slot,
// ESR_EL1, FAR_EL1, ELR_EL1 and SP_EL0 of the guest exception.
func decodeStubExit(vec, esr, far, pc, sp uint64) exitAction {
	if vec != vecLowerELSync {
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: unexpected guest exception vector %d (esr=%#x far=%#x elr=%#x)", vec, esr, far, pc)}
	}
	kind, sig, at := hvcommon.DecodeA64SyncException(esr, far, pc, sp)
	switch kind {
	case hvcommon.A64ExitSyscall:
		return exitAction{kind: exitSyscall}
	case hvcommon.A64ExitSkip:
		return exitAction{kind: exitWFx}
	case hvcommon.A64ExitSysReg:
		return exitAction{kind: exitSysReg}
	default:
		return exitAction{kind: exitSignal, info: sig, at: at}
	}
}

// decodeHypervisorExit decodes an exception that Hypervisor.framework reports
// directly, without the EL1 stub. The syndrome is ESR_EL2 and virtualAddress
// is the guest virtual address of an abort.
func decodeHypervisorExit(syndrome, virtualAddress, physicalAddress uint64) exitAction {
	switch ec := esrEC(syndrome); ec {
	case ecInstrAbort, ecDataAbort:
		return decodeStage2Abort(syndrome, virtualAddress, physicalAddress)
	case ecSysReg:
		return exitAction{kind: exitSysReg}
	case ecWFx:
		return exitAction{kind: exitWFx}
	default:
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: unexpected hypervisor exception class %#x (syndrome=%#x va=%#x ipa=%#x)",
			ec, syndrome, virtualAddress, physicalAddress)}
	}
}

// decodeStage2Abort classifies an abort the stage-2 tables raise. Stage-1
// tables only name guest physical pages that Stage-2 maps, so an abort here
// means the guest touched memory with no backing page.
func decodeStage2Abort(syndrome, va, ipa uint64) exitAction {
	if syndrome&issS1PTW != 0 {
		return exitAction{kind: exitInternal, err: fmt.Errorf(
			"hvf: stage-2 abort during a stage-1 table walk (syndrome=%#x va=%#x ipa=%#x)", syndrome, va, ipa)}
	}
	addr := uint64(hostarch.UntaggedUserAddr(hostarch.Addr(va)))
	at := hostarch.ESRAccessType(syndrome)
	switch fsc := esrFSC(syndrome); {
	case fsc >= fscPermissionL1 && fsc <= fscPermissionL3:
		return signalAction(linux.SIGSEGV, sigSegvAcc, addr, at)
	case fsc >= fscTranslationL0 && fsc <= fscTranslationL3:
		return signalAction(linux.SIGBUS, sigBusAdrErr, addr, at)
	default:
		return signalAction(linux.SIGBUS, sigBusObjErr, addr, at)
	}
}

type sysRegISS = hvcommon.SysRegISS

func decodeSysRegISS(esr uint64) sysRegISS {
	return hvcommon.DecodeSysRegISS(esr)
}

const keyMIDR = hvcommon.KeyMIDR

type idRegisters = hvcommon.IDRegisters
