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
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

func TestClassifyX86(t *testing.T) {
	const rip = 0x401000
	for _, c := range []struct {
		name         string
		vector, errc uint64
		cr2          uint64
		want         trap
		wantErr      bool
	}{
		{name: "page fault not present read", vector: 14, errc: 0b00100, cr2: 0x7000,
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: hvcommon.SegvMapErr, addr: 0x7000, hasAddr: true, access: hostarch.AccessType{Read: true}}},
		{name: "page fault protection write", vector: 14, errc: 0b00111, cr2: 0x7008,
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: hvcommon.SegvAccErr, addr: 0x7008, hasAddr: true, access: hostarch.AccessType{Write: true}}},
		{name: "page fault instruction fetch", vector: 14, errc: 0b10101, cr2: rip,
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: hvcommon.SegvAccErr, addr: rip, hasAddr: true, access: hostarch.AccessType{Read: true, Execute: true}}},
		{name: "divide", vector: 0,
			want: trap{kind: trapSignal, signo: linux.SIGFPE, code: hvcommon.FpeIntDiv, addr: rip, hasAddr: true}},
		{name: "debug", vector: 1,
			want: trap{kind: trapSignal, signo: linux.SIGTRAP, code: linux.TRAP_TRACE, addr: rip, hasAddr: true}},
		{name: "breakpoint", vector: 3,
			want: trap{kind: trapSignal, signo: linux.SIGTRAP, code: linux.SI_KERNEL}},
		{name: "overflow", vector: 4,
			want: trap{kind: trapSignal, signo: linux.SIGFPE, code: hvcommon.FpeIntOvf, addr: rip, hasAddr: true}},
		{name: "invalid opcode", vector: 6,
			want: trap{kind: trapSignal, signo: linux.SIGILL, code: hvcommon.IllIllOpc, addr: rip, hasAddr: true}},
		{name: "general protection", vector: 13, errc: 0x2,
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: linux.SI_KERNEL, addr: rip, hasAddr: true}},
		{name: "int 0x80 without gate", vector: 13, errc: 0x80<<3 | 2,
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: linux.SI_KERNEL, addr: rip, hasAddr: true}},
		{name: "x87", vector: 16,
			want: trap{kind: trapSignal, signo: linux.SIGFPE, code: hvcommon.FpeFltInv, addr: rip, hasAddr: true}},
		{name: "alignment", vector: 17,
			want: trap{kind: trapSignal, signo: linux.SIGBUS, code: hvcommon.BusAdrAln}},
		{name: "simd", vector: 19,
			want: trap{kind: trapSignal, signo: linux.SIGFPE, code: hvcommon.FpeFltInv, addr: rip, hasAddr: true}},
		{name: "double fault", vector: 8, wantErr: true},
		{name: "machine check", vector: 18, wantErr: true},
		{name: "nmi", vector: 2, wantErr: true},
	} {
		got, err := classifyX86(c.vector, c.errc, c.cr2, rip)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: error %v, want error %v", c.name, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func esr(ec, iss uint64) uint64 { return ec<<hvcommon.ESRECShift | 1<<25 | iss }

func TestClassifyA64(t *testing.T) {
	const pc uint64 = 0x400100
	const far uint64 = 0x7FFF0000
	const sp uint64 = 0x7FFEE003
	for _, c := range []struct {
		name      string
		slot, esr uint64
		want      trap
		wantErr   bool
	}{
		{name: "svc", slot: a64SlotLowA64Sync, esr: esr(hvcommon.ECSVC64, 0), want: trap{kind: trapSyscall}},
		{name: "wfi", slot: a64SlotLowA64Sync, esr: esr(hvcommon.ECWFx, 0), want: trap{kind: trapSkip}},
		{name: "data abort", slot: a64SlotLowA64Sync, esr: esr(hvcommon.ECDataAbortLower, 0x07),
			want: trap{kind: trapSignal, signo: linux.SIGSEGV, code: hvcommon.SegvMapErr, addr: far, hasAddr: true, access: hostarch.Read}},
		{name: "mrs from el0", slot: a64SlotLowA64Sync, esr: esr(hvcommon.ECSysReg, 0),
			want: trap{kind: trapSignal, signo: linux.SIGILL, code: hvcommon.IllIllOpc, addr: pc, hasAddr: true}},
		{name: "serror from el0", slot: a64SlotLowA64SErr, esr: 0,
			want: trap{kind: trapSignal, signo: linux.SIGBUS, code: hvcommon.BusAdrErr, addr: pc, hasAddr: true}},
		{name: "irq", slot: a64SlotLowA64IRQ, wantErr: true},
		{name: "exception taken at el1", slot: a64SlotCurSPxSync, esr: esr(hvcommon.ECDataAbortLower, 0x07), wantErr: true},
		{name: "aarch32 el0", slot: a64SlotLowA32Sync, wantErr: true},
	} {
		got, err := classifyA64(c.slot, c.esr, far, pc, sp)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: error %v, want error %v", c.name, err, c.wantErr)
			continue
		}
		if !c.wantErr && got != c.want {
			t.Errorf("%s: got %+v, want %+v", c.name, got, c.want)
		}
	}
}

func TestSegmentValues(t *testing.T) {
	if s, ok := x64UserCSValue(x64SelUserCS); !ok || s.attr != x64AttrUserCS64 || s.limit != x64SegLimit || s.selector != x64SelUserCS {
		t.Errorf("64-bit user CS is %+v, %v", s, ok)
	}
	if s, ok := x64UserCSValue(x64SelUserCS32); !ok || s.attr != x64AttrUserCS32 {
		t.Errorf("32-bit user CS is %+v, %v", s, ok)
	}
	if _, ok := x64UserCSValue(0x10); ok {
		t.Error("kernel CS accepted as a user selector")
	}
	if s, ok := x64UserDataValue(0, 0x7FFF_DEAD_0000); !ok || s.base != 0x7FFF_DEAD_0000 || s.attr != 0 || s.selector != 0 {
		t.Errorf("null FS is %+v, %v", s, ok)
	}
	if s, ok := x64UserDataValue(x64SelUserSS, 0); !ok || s.attr != x64AttrUserData {
		t.Errorf("user data segment is %+v, %v", s, ok)
	}
	if _, ok := x64UserDataValue(0x18, 0); ok {
		t.Error("kernel data selector accepted for user mode")
	}
	// Attribute layout: type, S, DPL, P in the low byte; L, D, G above.
	if x64AttrUserCS64 != 0xB|1<<4|3<<5|1<<7|1<<13|1<<15 {
		t.Errorf("64-bit user CS attributes are %#x", x64AttrUserCS64)
	}
	if x64AttrKernelSS != 0x3|1<<4|1<<7|1<<14|1<<15 {
		t.Errorf("kernel SS attributes are %#x", x64AttrKernelSS)
	}
	if x64AttrTSS != 0xB|1<<7 {
		t.Errorf("TSS attributes are %#x, want a present busy 64-bit TSS", x64AttrTSS)
	}
}

func TestUserFlagsAndRIP(t *testing.T) {
	if got := x64UserFlags(0); got != 0x202 {
		t.Errorf("flags of zero are %#x, want IF and the reserved bit", got)
	}
	// IOPL, NT, VM, VIF and VIP must never reach user mode.
	if got := x64UserFlags(0x3000 | 0x4000 | 1<<17 | 1<<19 | 1<<20); got != 0x202 {
		t.Errorf("privileged flags survive: %#x", got)
	}
	if got := x64UserFlags(0x1 | 0x40 | 0x100 | 0x400 | 0x40000); got != 0x1|0x40|0x100|0x400|0x40000|0x202 {
		t.Errorf("user flags are %#x", got)
	}
	if !x64UserRIPValid(0x7FFF_FFFF_F000) || x64UserRIPValid(1<<47) || x64UserRIPValid(0xFFFF_8000_0000_0000) {
		t.Error("user RIP validity is wrong")
	}
}
