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

//go:build windows && amd64

package systrap

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// TestFSBaseIsRepairedAfterPreemption runs a loop that reads through %fs for
// long enough that Windows switches the thread out. The switch resets the FS
// base, the next read faults at a low address, and the engine loads the base
// again. The sum proves that no read returned a wrong value.
func TestFSBaseIsRepairedAfterPreemption(t *testing.T) {
	r := newRig(t, newPlatform(t))
	const iterations = 1_500_000_000
	loop := imm64([]byte{0x48, 0xB9}, iterations)                 // mov rcx, iterations
	loop = append(loop, 0x31, 0xDB)                               // xor ebx, ebx
	loop = append(loop, 0x64, 0x48, 0x8B, 0x04, 0x25, 0, 0, 0, 0) // loop: mov rax, fs:[0]
	loop = append(loop, 0x48, 0x01, 0xC3)                         // add rbx, rax
	loop = append(loop, 0x48, 0xFF, 0xC9)                         // dec rcx
	loop = append(loop, 0x75, 0xEF)                               // jnz loop (back 17 bytes)
	r.program(loop, gSyscall(93))
	page := r.mapPage(dataVA, hostarch.ReadWrite)
	store64(page, 7)
	setTLSBase(r.ac, dataVA)
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	if got, want := regAcc(r.ac), uint64(7*iterations); got != want {
		t.Errorf("sum = %d, want %d", got, want)
	}
	t.Logf("the engine repaired the FS base %d times", r.as.sp.fsRepairs.Load())
}

// TestInstructionCrossesBlockBoundary runs an instruction whose first bytes
// end one block and whose last bytes start the next block. The first block is
// executable when the fetch of the next block faults, so pc stays in a block
// that needs no patch. The engine must patch the block that the fault names.
// A guest that runs a pipeline of a shell hit this fault in a call
// instruction.
func TestInstructionCrossesBlockBoundary(t *testing.T) {
	r := newRig(t, newPlatform(t))
	movabs := imm64([]byte{0x48, 0xB8}, 93) // mov rax, 93: ten bytes.
	const inFirst = 4
	first := make([]byte, blockSize)
	for i := range first {
		first[i] = 0x90 // nop
	}
	copy(first[blockSize-inFirst:], movabs[:inFirst])
	second := append(append([]byte(nil), movabs[inFirst:]...), 0x0F, 0x05)
	r.mapPage(codeVA, execAccess, first)
	r.mapPage(codeVA+blockSize, execAccess, second)
	r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(stackVA + blockSize - 0x100)

	// A livelock of faults would block Switch for good, so a timer stops it.
	stop := time.AfterFunc(30*time.Second, r.ctx.Interrupt)
	defer stop.Stop()
	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
}

// TestFastPathResumeBehindPatchedSyscall starts a thread at the return address
// of a SYSCALL that the patcher replaced with a JMP. A new thread of clone and
// a sigreturn to an interrupted system call do this. The JMP overwrote the
// bytes at that address, so the thread must continue in the slot tail, run the
// relocated instruction, and go on behind it. A real Go guest crashed in the
// child of clone before this rule.
//
// The test resumes behind every one of many sites. Each site has its own slot,
// so the bytes of its JMP differ. A resume at the raw address executes those
// bytes as code, and the chance that all of them run without a fault and keep
// the count is negligible.
func TestFastPathResumeBehindPatchedSyscall(t *testing.T) {
	const sites = 12
	r := newRig(t, newFastPlatform(t))
	inc := []byte{0x48, 0xFF, 0xC3} // inc rbx
	var prog []byte
	var returns []uint64
	for range sites {
		prog = append(prog, gSyscall(1)...)
		returns = append(returns, codeVA+uint64(len(prog)))
		prog = append(prog, inc...)
	}
	prog = append(prog, gSyscall(3)...)
	r.program(prog)

	// runToExit continues after each system call 1 until system call 3.
	runToExit := func() {
		t.Helper()
		for {
			si, _, err := r.run()
			if si == nil && err == nil && regNr(r.ac) == 1 {
				continue
			}
			mustSyscall(t, si, err, 3, r.ac)
			return
		}
	}
	runToExit()
	if got := regAcc(r.ac); got != sites {
		t.Fatalf("the first pass counted %d, want %d", got, sites)
	}
	for i, ret := range returns {
		if _, ok := r.as.jumpTail(ret); !ok {
			t.Fatalf("the SYSCALL before %#x did not become a JMP", ret)
		}
		// Continue at the return address, as the child of a clone does. The
		// Sentry never writes the island address to the registers.
		r.ac.StateData().Regs.Rbx = 0
		r.ac.SetIP(uintptr(ret))
		runToExit()
		if got, want := regAcc(r.ac), uint64(sites-i); got != want {
			t.Errorf("resume behind site %d (%#x): the relocated instructions ran %d times, want %d", i, ret, got, want)
		}
	}

	// Simulate the child of fork: a fresh address space where the block is still
	// in blockData when the thread starts at the return address of a SYSCALL.
	// The first execute fault patches the block under the thread and must redirect
	// the program counter to the new slot tail.
	rFork := newRig(t, r.p)
	rFork.program(prog)
	rFork.ac.StateData().Regs.Rbx = 0
	rFork.ac.SetIP(uintptr(returns[0]))
	for {
		si, _, err := rFork.run()
		if si == nil && err == nil && regNr(rFork.ac) == 1 {
			continue
		}
		mustSyscall(t, si, err, 3, rFork.ac)
		break
	}
	if got := regAcc(rFork.ac); got != sites {
		t.Errorf("fork child resume behind site 0 on unpatched block: relocated instructions ran %d times, want %d", got, sites)
	}
}

// TestNearZeroBase checks which faults look like an access through a lost FS
// base. A positive offset from a zero base lies below the lowest guest
// address. A real guest address never counts, so a static executable at
// 0x400000 can use its own TLS block when the low window exists.
func TestNearZeroBase(t *testing.T) {
	for _, tc := range []struct {
		name     string
		guestMin uint64
		addr     uint64
		want     bool
	}{
		{"high window only, zero base", winBase, 0, true},
		{"high window only, small offset", winBase, 0x28, true},
		{"high window only, offset of a large TLS block", winBase, 0x100000, true},
		{"high window only, a guest address", winBase, winBase, false},
		{"low window, small offset", lowBase, 0x28, true},
		{"low window, last address below the guest range", lowBase, lowBase - 1, true},
		{"low window, lowest guest address", lowBase, lowBase, false},
		{"low window, address in a static executable", lowBase, 0x400000, false},
		{"low window, small negative offset", lowBase, ^uint64(0) - 7, true},
		{"high window only, small negative offset", winBase, ^uint64(0) - 0xfff, true},
		{"low window, a high guest address", lowBase, 0x7e4a080dfb28, false},
	} {
		if got := nearZeroBase(tc.addr, tc.guestMin); got != tc.want {
			t.Errorf("%s: nearZeroBase(%#x, %#x) = %v, want %v", tc.name, tc.addr, tc.guestMin, got, tc.want)
		}
	}
}

// TestFastPathTLSAndGSMovSlots verifies that RDFSBASE, RDGSBASE, and GS-segment
// MOV instructions execute through trampoline island slots without modifying
// RFLAGS, and that a faulting GS MOV restores the scratch register and reports
// SIGSEGV at the guest instruction address.
func TestFastPathTLSAndGSMovSlots(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	page := r.mapPage(dataVA, hostarch.ReadWrite)
	store64(page[0x28:], 0x1122_3344_5566_7788)

	var prog []byte
	prog = append(prog, imm64([]byte{0x48, 0xB8}, dataVA)...)                // mov rax, dataVA
	prog = append(prog, 0xF3, 0x48, 0x0F, 0xAE, 0xD8)                        // wrgsbase rax
	prog = append(prog, 0xF3, 0x48, 0x0F, 0xAE, 0xCB)                        // rdgsbase rbx
	prog = append(prog, 0x65, 0x4C, 0x8B, 0x24, 0x25, 0x28, 0, 0, 0)         // mov r12, gs:[0x28]
	prog = append(prog, imm64([]byte{0x49, 0xBD}, 0xDEAD_BEEF_CAFE_0001)...) // mov r13, 0xdeadbeefcafe0001
	prog = append(prog, 0x65, 0x4C, 0x89, 0x2C, 0x25, 0x30, 0, 0, 0)         // mov gs:[0x30], r13
	prog = append(prog, 0x65, 0x4C, 0x8B, 0x34, 0x25, 0x30, 0, 0, 0)         // mov r14, gs:[0x30]
	prog = append(prog, gSyscall(93)...)
	r.program(prog)

	si, _, err := r.run()
	mustSyscall(t, si, err, 93, r.ac)
	regs := &r.ac.StateData().Regs
	if regs.Rbx != dataVA {
		t.Errorf("rdgsbase rbx = %#x, want %#x", regs.Rbx, uint64(dataVA))
	}
	if regs.R12 != 0x1122_3344_5566_7788 {
		t.Errorf("mov r12, gs:[0x28] = %#x, want 0x1122334455667788", regs.R12)
	}
	if regs.R14 != 0xDEAD_BEEF_CAFE_0001 {
		t.Errorf("mov r14, gs:[0x30] = %#x, want 0xdeadbeefcafe0001", regs.R14)
	}

	// Verify that a faulting GS MOV with Gs_base == 0 preserves the destination
	// register and reports SIGSEGV at the guest instruction address.
	rFault := newRig(t, r.p)
	var faultProg []byte
	faultProg = append(faultProg, imm64([]byte{0x49, 0xBC}, 0xABCD_1234_5678_9000)...) // mov r12, sentinel
	faultSite := codeVA + uint64(len(faultProg))
	faultProg = append(faultProg, 0x65, 0x4C, 0x8B, 0x24, 0x25, 0x28, 0, 0, 0) // mov r12, gs:[0x28]
	faultProg = append(faultProg, gSyscall(93)...)
	rFault.program(faultProg)

	si, _, err = rFault.run()
	if si == nil || err == nil {
		t.Fatalf("expected SIGSEGV from GS load with zero base, got si=%v err=%v", si, err)
	}
	fregs := &rFault.ac.StateData().Regs
	if fregs.Rip != faultSite {
		t.Errorf("fault RIP = %#x, want %#x", fregs.Rip, faultSite)
	}
	if fregs.R12 != 0xABCD_1234_5678_9000 {
		t.Errorf("fault clobbered r12 = %#x, want 0xabcd123456789000", fregs.R12)
	}
	if si.Addr() != 0x28 {
		t.Errorf("fault addr = %#x, want 0x28", si.Addr())
	}
}
