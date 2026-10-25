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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

func esr(ec, iss uint64) uint64 { return ec<<hvcommon.ESRECShift | iss }

func TestDecodeStubExit(t *testing.T) {
	const pc, far, sp = 0x400100, 0xbeef000, 0x7ffff0
	for _, tc := range []struct {
		name  string
		vec   uint64
		esr   uint64
		kind  exitKind
		signo linux.Signal
		code  int32
	}{
		{name: "svc", vec: vecLowerELSync, esr: esr(hvcommon.ECSVC64, 0), kind: exitSyscall},
		{name: "wfi", vec: vecLowerELSync, esr: esr(hvcommon.ECWFx, 0), kind: exitWFx},
		{name: "system register trap", vec: vecLowerELSync, esr: esr(hvcommon.ECSysReg, 1), kind: exitSysReg},
		{name: "data abort", vec: vecLowerELSync, esr: esr(hvcommon.ECDataAbortLower, 0x05), kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvMap},
		{name: "irq from EL0", vec: vecLowerELIRQ, esr: 0, kind: exitInternal},
		{name: "serror from EL0", vec: vecLowerELSError, esr: 0, kind: exitInternal},
		{name: "fault in EL1", vec: vecCurrentELSPxSync, esr: esr(hvcommon.ECDataAbortLower, 0x05), kind: exitInternal},
	} {
		act := decodeStubExit(tc.vec, tc.esr, far, pc, sp)
		if act.kind != tc.kind {
			t.Fatalf("%s: kind = %d, want %d (err=%v)", tc.name, act.kind, tc.kind, act.err)
		}
		if tc.kind == exitSignal && (act.info.Signo != int32(tc.signo) || act.info.Code != tc.code) {
			t.Errorf("%s: signal = %d/%d, want %d/%d", tc.name, act.info.Signo, act.info.Code, tc.signo, tc.code)
		}
	}
}

func TestDecodeHypervisorExit(t *testing.T) {
	const va, ipa = 0x400800, 0x2_0000_8800
	cases := []struct {
		name  string
		syn   uint64
		kind  exitKind
		signo linux.Signal
		code  int32
		at    hostarch.AccessType
	}{
		{name: "stage-2 translation fault on read", syn: esr(hvcommon.ECDataAbortLower, 0x05),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Read},
		{name: "stage-2 translation fault on write", syn: esr(hvcommon.ECDataAbortLower, 1<<6|0x06),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Write},
		{name: "stage-2 instruction fetch", syn: esr(hvcommon.ECInstrAbortLower, 0x04),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Execute},
		{name: "stage-2 permission fault", syn: esr(hvcommon.ECDataAbortLower, 1<<6|0x0d),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvAcc, at: hostarch.Write},
		{name: "stage-2 other abort", syn: esr(hvcommon.ECDataAbortLower, 0x30),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusObjErr, at: hostarch.Read},
		{name: "abort during stage-1 walk", syn: esr(hvcommon.ECDataAbortLower, issS1PTW|0x05), kind: exitInternal},
		{name: "system register", syn: esr(hvcommon.ECSysReg, 1), kind: exitSysReg},
		{name: "wfi", syn: esr(hvcommon.ECWFx, 0), kind: exitWFx},
		{name: "unknown class", syn: esr(0x2f, 0), kind: exitInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			act := decodeHypervisorExit(tc.syn, va, ipa)
			if act.kind != tc.kind {
				t.Fatalf("kind = %d, want %d (err=%v)", act.kind, tc.kind, act.err)
			}
			if tc.kind == exitSignal {
				if act.info.Signo != int32(tc.signo) || act.info.Code != tc.code || act.info.Addr() != va || act.at != tc.at {
					t.Errorf("got signal %d code %d addr %#x access %v, want %d code %d addr %#x access %v",
						act.info.Signo, act.info.Code, act.info.Addr(), act.at, tc.signo, tc.code, uint64(va), tc.at)
				}
			}
			if tc.kind == exitInternal && act.err == nil {
				t.Error("an internal exit carries no error")
			}
		})
	}
}
