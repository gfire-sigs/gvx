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
)

func esr(ec, iss uint64) uint64 { return ec<<26 | iss }

func TestDecodeStubExit(t *testing.T) {
	const pc, far, sp = 0x400100, 0xbeef000, 0x7ffff0
	cases := []struct {
		name  string
		vec   uint64
		esr   uint64
		kind  exitKind
		signo linux.Signal
		code  int32
		addr  uint64
		at    hostarch.AccessType
	}{
		{name: "svc", vec: vecLowerELSync, esr: esr(ecSVC64, 0), kind: exitSyscall},
		{name: "data abort translation read", vec: vecLowerELSync, esr: esr(ecDataAbort, 0x05),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvMap, addr: far, at: hostarch.Read},
		{name: "data abort permission write", vec: vecLowerELSync, esr: esr(ecDataAbort, 1<<6|0x0f),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvAcc, addr: far, at: hostarch.Write},
		{name: "data abort cache maintenance counts as read", vec: vecLowerELSync, esr: esr(ecDataAbort, 1<<8|1<<6|0x0f),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvAcc, addr: far, at: hostarch.Read},
		{name: "instruction abort", vec: vecLowerELSync, esr: esr(ecInstrAbort, 0x07),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvMap, addr: far, at: hostarch.Execute},
		{name: "alignment fault", vec: vecLowerELSync, esr: esr(ecDataAbort, 0x21),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrAln, addr: far, at: hostarch.Read},
		{name: "external abort", vec: vecLowerELSync, esr: esr(ecDataAbort, 0x10),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, addr: far, at: hostarch.Read},
		{name: "pc alignment", vec: vecLowerELSync, esr: esr(ecPCAlignment, 0),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrAln, addr: far},
		{name: "sp alignment uses SP", vec: vecLowerELSync, esr: esr(ecSPAlignment, 0),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrAln, addr: sp},
		{name: "brk", vec: vecLowerELSync, esr: esr(ecBRK64, 0),
			kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapBrkpt, addr: pc},
		{name: "single step", vec: vecLowerELSync, esr: esr(ecSoftStep, 0),
			kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapTrace, addr: pc},
		{name: "hardware breakpoint", vec: vecLowerELSync, esr: esr(ecBreakpoint, 0),
			kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapHWBkp, addr: pc},
		{name: "watchpoint", vec: vecLowerELSync, esr: esr(ecWatchpoint, 0),
			kind: exitSignal, signo: linux.SIGTRAP, code: sigTrapHWBkp, addr: far},
		{name: "undefined instruction", vec: vecLowerELSync, esr: esr(ecUnknown, 0),
			kind: exitSignal, signo: linux.SIGILL, code: sigIllIllOpc, addr: pc},
		{name: "illegal execution state", vec: vecLowerELSync, esr: esr(ecIllegalState, 0),
			kind: exitSignal, signo: linux.SIGILL, code: sigIllIllOpc, addr: pc},
		{name: "unlisted class", vec: vecLowerELSync, esr: esr(0x2f, 0),
			kind: exitSignal, signo: linux.SIGILL, code: sigIllIllOpc, addr: pc},
		{name: "system register trap", vec: vecLowerELSync, esr: esr(ecSysReg, 1), kind: exitSysReg},
		{name: "irq from EL0", vec: vecLowerELIRQ, esr: 0, kind: exitInternal},
		{name: "serror from EL0", vec: vecLowerELSError, esr: 0, kind: exitInternal},
		{name: "fault in EL1", vec: vecCurrentELSPxSync, esr: esr(ecDataAbort, 0x05), kind: exitInternal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			act := decodeStubExit(tc.vec, tc.esr, far, pc, sp)
			if act.kind != tc.kind {
				t.Fatalf("kind = %d, want %d (err=%v)", act.kind, tc.kind, act.err)
			}
			switch tc.kind {
			case exitInternal:
				if act.err == nil {
					t.Error("an internal exit carries no error")
				}
			case exitSignal:
				if act.info.Signo != int32(tc.signo) || act.info.Code != tc.code {
					t.Errorf("signal = %d code %d, want %d code %d", act.info.Signo, act.info.Code, tc.signo, tc.code)
				}
				if got := act.info.Addr(); got != tc.addr {
					t.Errorf("si_addr = %#x, want %#x", got, tc.addr)
				}
				if act.at != tc.at {
					t.Errorf("access = %v, want %v", act.at, tc.at)
				}
			}
		})
	}
}

func TestDecodeStubExitUntagsAddresses(t *testing.T) {
	act := decodeStubExit(vecLowerELSync, esr(ecDataAbort, 0x05), 0x5a00_0000_1234_5000, 0, 0)
	if got := act.info.Addr(); got != 0x1234_5000 {
		t.Errorf("si_addr = %#x, want the address without its tag byte", got)
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
		{name: "stage-2 translation fault on read", syn: esr(ecDataAbort, 0x05),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Read},
		{name: "stage-2 translation fault on write", syn: esr(ecDataAbort, 1<<6|0x06),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Write},
		{name: "stage-2 instruction fetch", syn: esr(ecInstrAbort, 0x04),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusAdrErr, at: hostarch.Execute},
		{name: "stage-2 permission fault", syn: esr(ecDataAbort, 1<<6|0x0d),
			kind: exitSignal, signo: linux.SIGSEGV, code: sigSegvAcc, at: hostarch.Write},
		{name: "stage-2 other abort", syn: esr(ecDataAbort, 0x30),
			kind: exitSignal, signo: linux.SIGBUS, code: sigBusObjErr, at: hostarch.Read},
		{name: "abort during stage-1 walk", syn: esr(ecDataAbort, issS1PTW|0x05), kind: exitInternal},
		{name: "system register", syn: esr(ecSysReg, 1), kind: exitSysReg},
		{name: "wfi", syn: esr(ecWFx, 0), kind: exitWFx},
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

func TestEmulateSysRegRead(t *testing.T) {
	ids := &idRegisters{
		MIDR: 0x610f0000, PFR0: 0x1101_0000_1011_0011 | 0xf<<32, PFR1: 0xff00,
		ISAR0: 0x221100110212120, ISAR1: 0x11110211202 | 0xf<<4,
		MMFR0: 0x10000f100001, MMFR1: 0x11212000, MMFR2: 0x1001001100001011,
		Counter: func() uint64 { return 0x1234 },
	}
	read := func(op0, op1, crn, crm, op2 uint32) sysRegISS {
		return sysRegISS{Read: true, Rt: 3, Op0: op0, Op1: op1, CRn: crn, CRm: crm, Op2: op2}
	}
	cases := []struct {
		name string
		iss  sysRegISS
		want uint64
		ok   bool
	}{
		{"MIDR_EL1", read(3, 0, 0, 0, 0), ids.MIDR, true},
		{"REVIDR_EL1", read(3, 0, 0, 0, 6), 0, true},
		{"ID_AA64PFR0_EL1 hides SVE", read(3, 0, 0, 4, 0), ids.PFR0 &^ (0xf << 32), true},
		{"ID_AA64PFR1_EL1 hides MTE", read(3, 0, 0, 4, 1), 0xf000, true},
		{"ID_AA64ISAR0_EL1", read(3, 0, 0, 6, 0), ids.ISAR0, true},
		// 0x11110211202 has API=2 and GPI=1: both fields clear.
		{"ID_AA64ISAR1_EL1 hides pointer authentication", read(3, 0, 0, 6, 1), 0x11100211002, true},
		{"ID_AA64MMFR0_EL1", read(3, 0, 0, 7, 0), ids.MMFR0, true},
		{"ID_AA64MMFR1_EL1", read(3, 0, 0, 7, 1), ids.MMFR1, true},
		{"ID_AA64MMFR2_EL1", read(3, 0, 0, 7, 2), ids.MMFR2, true},
		{"CNTPCT_EL0 comes from the counter", read(3, 3, 14, 0, 1), 0x1234, true},
		{"CNTVCT_EL0 comes from the counter", read(3, 3, 14, 0, 2), 0x1234, true},
		{"unknown register", read(3, 3, 9, 12, 0), 0, false},
		{"ID_AA64DFR0_EL1 stays hidden", read(3, 0, 0, 5, 0), 0, false},
		{"write to MIDR_EL1", sysRegISS{Read: false, Rt: 0, Op0: 3}, 0, false},
	}
	for _, tc := range cases {
		got, ok := ids.EmulateSysRegRead(tc.iss)
		if ok != tc.ok || got != tc.want {
			t.Errorf("%s = (%#x, %v), want (%#x, %v)", tc.name, got, ok, tc.want, tc.ok)
		}
	}
	ids.Counter = nil
	if _, ok := ids.EmulateSysRegRead(read(3, 3, 14, 0, 1)); ok {
		t.Error("CNTPCT_EL0 emulated without a counter source")
	}
}

func TestDecodeSysRegISS(t *testing.T) {
	// MRS X7, MIDR_EL1 (op0=3, op1=0, CRn=0, CRm=0, op2=0, direction read).
	iss := decodeSysRegISS(esr(ecSysReg, 3<<20|7<<5|1))
	if !iss.Read || iss.Rt != 7 || iss.Key() != keyMIDR {
		t.Errorf("decoded %+v (key %#x), want a read of MIDR_EL1 into X7", iss, iss.Key())
	}
	// MSR TPIDR_EL0, X2 (op0=3, op1=3, CRn=13, CRm=0, op2=2, direction write).
	iss = decodeSysRegISS(esr(ecSysReg, 3<<20|2<<17|3<<14|13<<10|2<<5))
	if iss.Read || iss.Rt != 2 || iss.Op0 != 3 || iss.Op1 != 3 || iss.CRn != 13 || iss.CRm != 0 || iss.Op2 != 2 {
		t.Errorf("decoded %+v, want a write of TPIDR_EL0 from X2", iss)
	}
}
