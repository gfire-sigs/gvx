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

//go:build windows && arm64

package systrap

import (
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestDataCacheMaintenanceRuns runs the data cache operations that JIT
// engines and the compiler runtime use. Windows raises an illegal
// instruction exception for each of them at EL0. The engine replaces them with
// NOP, so the guest reaches its system call with the stored value intact.
func TestDataCacheMaintenanceRuns(t *testing.T) {
	r := newRig(t, newPlatform(t))
	code := gConst(1, dataVA)
	code = append(code, wordBytes(
		0xd50b7e21, // dc civac, x1
		0xd50b7b21, // dc cvau, x1
		0xd50b7a21, // dc cvac, x1
		0xd50b7c21, // dc cvap, x1
	)...)
	r.program(gStoreTo(dataVA, 0x0102030405060708), code, gInvalidateICache(), gSyscall(93))
	data := r.mapPage(dataVA, hostarch.ReadWrite)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got := load64(data); got != 0x0102030405060708 {
		t.Errorf("data = %#x, want 0x0102030405060708", got)
	}
}

// ldrX18 loads x18 from the address in x1. The engine rewrites no load of x18.
var ldrX18 = wordBytes(0xf9400032) // ldr x18, [x1]

// addX18 sets x18 to x1 plus 16. The engine rewrites no add to x18.
var addX18 = wordBytes(0x91004032) // add x18, x1, #16

// movX0FromX18 copies x18 to the return register.
var movX0FromX18 = wordBytes(0xaa1203e0) // mov x0, x18

// TestFastPathKeepsGuestX18AcrossSystemCall runs a guest that sets x18 with an
// instruction that is not a register move, then calls the Sentry. A Linux guest
// can hold a live value in x18, and a system call must preserve it.
func TestFastPathKeepsGuestX18AcrossSystemCall(t *testing.T) {
	const value = 0x1122_3344_5566_7788
	for _, c := range []struct {
		name string
		set  []byte
		want uint64
	}{
		{"movz and movk", gConst(18, value), value},
		{"load", append(gConst(1, dataVA), ldrX18...), value},
		{"add", append(gConst(1, value-16), addX18...), value},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, newFastPlatform(t))
			r.program(c.set, gSyscall(172), movX0FromX18, gSyscall(93))
			store64(r.mapPage(dataVA, hostarch.ReadWrite), value)
			si, _, err := r.run()
			mustSyscall(t, si, err, 172, r.ac)
			if got := r.ac.StateData().Regs.Regs[18]; got != c.want {
				t.Fatalf("x18 at the system call = %#x, want %#x", got, c.want)
			}
			setRet(r.ac, 1000)
			si, _, err = r.run()
			mustSyscall(t, si, err, 93, r.ac)
			if got := regRet(r.ac); got != c.want {
				t.Errorf("x18 after the system call = %#x, want %#x", got, c.want)
			}
			if got := fastStats(t, r).traps.Load(); got != 2 {
				t.Errorf("the fast path served %d of 2 system calls", got)
			}
		})
	}
}

// TestFastPathResumeLoadsX18FromTheSentry covers the two resumes: the hot
// resume that keeps the program counter, and the cold resume after the Sentry
// moves it. In both, the guest sees the x18 that the Sentry left in the
// register state, as it does after a signal handler returns.
func TestFastPathResumeLoadsX18FromTheSentry(t *testing.T) {
	const guestValue, sentryValue = 0x1818_0000_0001, 0x1818_0000_0002
	for _, cold := range []bool{false, true} {
		name := "hot"
		if cold {
			name = "cold"
		}
		t.Run(name, func(t *testing.T) {
			r := newRig(t, newFastPlatform(t))
			mem := r.program(gConst(18, guestValue), gSyscall(172), movX0FromX18, gSyscall(93))
			copy(mem[0x100:], append(append([]byte(nil), movX0FromX18...), gSyscall(93)...))
			si, _, err := r.run()
			mustSyscall(t, si, err, 172, r.ac)
			r.ac.StateData().Regs.Regs[18] = sentryValue
			if cold {
				r.ac.SetIP(codeVA + 0x100)
			}
			si, _, err = r.run()
			mustSyscall(t, si, err, 93, r.ac)
			if got := regRet(r.ac); got != sentryValue {
				t.Errorf("x18 after the %s resume = %#x, want %#x", name, got, uint64(sentryValue))
			}
			if got := fastStats(t, r).colds.Load(); (got == 1) != cold {
				t.Errorf("cold resumes = %d, want a cold resume: %v", got, cold)
			}
		})
	}
}

// TestFastPathServesSystemCallWhenTheStackPointerIsBad runs a system call with
// a stack pointer that the engine cannot use to save x18. Linux serves the call
// whatever the stack pointer holds, so the guest must get the call and keep x18.
func TestFastPathServesSystemCallWhenTheStackPointerIsBad(t *testing.T) {
	const value = 0x2828_2828_2828_2828
	for _, c := range []struct {
		name string
		sp   uint64
	}{
		{"zero", 0},
		{"unmapped address", 0x7000_0123_0000},
		{"mapped page above an unmapped page", stackVA},
		{"read-only page", dataVA + 0x800},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newRig(t, newFastPlatform(t))
			r.program(gConst(18, value), gSyscall(172), movX0FromX18, gSyscall(93))
			r.mapPage(dataVA, hostarch.Read)
			r.ac.SetStack(uintptr(c.sp))
			si, _, err := r.run()
			mustSyscall(t, si, err, 172, r.ac)
			regs := &r.ac.StateData().Regs
			if regs.Sp != c.sp || regs.Regs[18] != value {
				t.Errorf("sp = %#x, x18 = %#x at the system call, want %#x and %#x", regs.Sp, regs.Regs[18], c.sp, uint64(value))
			}
			if got, want := regPC(r.ac), uint64(codeVA+len(gConst(18, value))+len(gSyscall(172))); got != want {
				t.Errorf("pc after the system call = %#x, want %#x", got, want)
			}
			setRet(r.ac, 1000)
			si, _, err = r.run()
			mustSyscall(t, si, err, 93, r.ac)
			if got := regRet(r.ac); got != value {
				t.Errorf("x18 after the system call = %#x, want %#x", got, uint64(value))
			}
			if got := fastStats(t, r).traps.Load(); got != 0 {
				t.Errorf("the fast path served %d system calls with a stack pointer it cannot use", got)
			}
		})
	}
}

// TestCacheTypeRegisterNeedsNoMaintenance reads CTR_EL0 in the guest. The
// engine flushes the instruction cache when it maps a patched copy, so the
// register reports that a guest needs neither `dc cvau` nor `ic ivau`.
func TestCacheTypeRegisterNeedsNoMaintenance(t *testing.T) {
	r := newRig(t, newPlatform(t))
	r.program(gReadCacheType(), gSyscall(93))
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	got := regRet(r.ac)
	const dic, idc = 1 << 29, 1 << 28
	if got&dic == 0 || got&idc == 0 {
		t.Errorf("CTR_EL0 = %#x, want DIC and IDC set", got)
	}
	if line := 4 << (got & 0xf); line != 64 {
		t.Errorf("CTR_EL0 = %#x reports an instruction line of %d bytes, want 64", got, line)
	}
}

// TestFastPathKeepsTheWordsBelowTheStackPointer runs a system call while the
// guest keeps data just below its stack pointer. The child of a Go clone does
// this: it keeps three words at sp-8 to sp-32 across its first system call, and
// the kernel never writes below the stack pointer.
func TestFastPathKeepsTheWordsBelowTheStackPointer(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	stackTop := uint64(stackVA + blockSize - 0x100)
	var set []byte
	words := map[uint64]uint64{8: 0xa1a1, 16: 0xb2b2, 24: 0xc3c3, 32: 0xd4d4}
	for below, v := range words {
		set = append(set, gConst(0, v)...)
		set = append(set, wordBytes(a64sturX(0, a64SP, -int32(below)))...)
	}
	r.mapPage(codeVA, execAccess, set, gSyscall(172))
	stack := r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(uintptr(stackTop))
	si, _, err := r.run()
	mustSyscall(t, si, err, 172, r.ac)
	if got := fastStats(t, r).traps.Load(); got != 1 {
		t.Fatalf("the fast path served %d of 1 system calls", got)
	}
	for below, want := range words {
		if got := load64(stack[stackTop-stackVA-below:]); got != want {
			t.Errorf("word at sp-%d = %#x after the system call, want %#x", below, got, want)
		}
	}
}
