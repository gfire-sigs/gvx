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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// Linux si_code values shared by the exit decoders.
const (
	sigIllIllOpc = hvcommon.IllIllOpc
	sigBusAdrAln = hvcommon.BusAdrAln
	sigBusAdrErr = hvcommon.BusAdrErr
	sigBusObjErr = hvcommon.BusObjErr
	sigSegvMap   = hvcommon.SegvMapErr
	sigSegvAcc   = hvcommon.SegvAccErr
	sigTrapBrkpt = linux.TRAP_BRKPT
	sigTrapTrace = linux.TRAP_TRACE
	sigTrapHWBkp = linux.TRAP_HWBKPT
	sigFpeFltInv = hvcommon.FpeFltInv
)

// exitKind classifies a guest exit.
type exitKind int

const (
	// exitSyscall is a system call instruction.
	exitSyscall exitKind = iota
	// exitSignal delivers a Linux signal to the guest thread.
	exitSignal
	// exitSysReg is a trapped MSR, MRS or SYS instruction (ARM64).
	exitSysReg
	// exitWFx is a trapped WFI or WFE instruction (ARM64).
	exitWFx
	// exitBounce is the exception that the host injects to take a vCPU out
	// of user mode (x86).
	exitBounce
	// exitCPUID is a CPUID instruction that the guest executed (x86).
	exitCPUID
	// exitInternal is an exit the backend cannot attribute to guest behavior.
	exitInternal
)

// exitAction is the outcome of decoding one exit.
type exitAction struct {
	kind exitKind
	info *linux.SignalInfo
	at   hostarch.AccessType
	err  error
}

func signalAction(signo linux.Signal, code int32, addr uint64, at hostarch.AccessType) exitAction {
	info := &linux.SignalInfo{Signo: int32(signo), Code: code}
	info.SetAddr(addr)
	return exitAction{kind: exitSignal, info: info, at: at}
}
