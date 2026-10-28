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
	"errors"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
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

// preWindowGuest is a loop whose SYSCALL has the shape of the cancellation
// point of musl: instructions that carry the plan stand in front of the
// SYSCALL, and a jump follows it. The post plan fails on the jump, so only the
// pre-window can patch the SYSCALL. The loop counts in RBX and enters the
// system call 1.
type preWindowGuest struct {
	code []byte
	// start is the guest address of the first instruction of the window, which
	// the JMP replaces. site is the guest address of the SYSCALL.
	start, site uint64
}

// newPreWindowGuest returns a guest whose window holds the instructions of
// window, with at least five bytes.
func newPreWindowGuest(window ...[]byte) preWindowGuest {
	code := nops(64)
	loop := len(code)
	code = append(code, 0x48, 0xFF, 0xC3) // inc rbx
	code = append(code, 0xB8, 1, 0, 0, 0) // mov eax, 1
	start := len(code)
	for _, w := range window {
		code = append(code, w...)
	}
	site := len(code)
	code = append(code, 0x0F, 0x05)                           // syscall
	code = append(code, 0xEB, byte(int8(loop-(len(code)+2)))) // jmp loop
	return preWindowGuest{code: code, start: codeVA + uint64(start), site: codeVA + uint64(site)}
}

// movStackRbx is `mov [rsp+8], rbx`, which stores the count where a signal
// frame of musl keeps the cancellation state.
var movStackRbx = []byte{0x48, 0x89, 0x5C, 0x24, 0x08}

const preWindowSP = stackVA + blockSize - 0x100

// mapInto maps the guest and its stack and points the registers at the loop. It
// returns the Sentry view of the stack page.
func (g preWindowGuest) mapInto(r *rig) []byte {
	r.mapPage(codeVA, execAccess, g.code)
	stack := r.mapPage(stackVA, hostarch.ReadWrite)
	r.ac.SetIP(codeVA)
	r.ac.SetStack(preWindowSP)
	return stack
}

// stackWord reads the word at the guest address va of the stack page.
func stackWord(stack []byte, va uint64) uint64 { return load64(stack[va-stackVA:]) }

// TestFastPathPreWindowServesEverySystemCall runs the guest through 2000
// system calls. Every call must take the fast path, and the instruction in
// the window must run before each one.
func TestFastPathPreWindowServesEverySystemCall(t *testing.T) {
	g := newPreWindowGuest(movStackRbx)
	r := newRig(t, newFastPlatform(t))
	stack := g.mapInto(r)
	const calls = 2000
	for i := uint64(1); i <= calls; i++ {
		si, _, err := r.run()
		mustSyscall(t, si, err, 1, r.ac)
		if got := regPC(r.ac); got != g.site+2 {
			t.Fatalf("call %d: the guest pc is %#x, want %#x behind the SYSCALL", i, got, g.site+2)
		}
		if got := stackWord(stack, preWindowSP+8); got != i {
			t.Fatalf("call %d: the instruction in the window stored %d", i, got)
		}
		if got := regAcc(r.ac); got != i {
			t.Fatalf("call %d: the loop counted %d", i, got)
		}
	}
	f := fastStats(t, r)
	if got := f.traps.Load(); got != calls {
		t.Errorf("the fast path served %d of %d system calls", got, calls)
	}
	if got := f.colds.Load(); got != 0 {
		t.Errorf("%d resumes ended in a debug stop, want none", got)
	}
	if s, ok := r.as.siteAt(g.start); !ok || s.kind != winSiteJumpBefore {
		t.Errorf("site at the window = %+v, %v, want winSiteJumpBefore", s, ok)
	}
	if s, ok := r.as.siteAt(g.site); !ok || s.kind != amd64SiteSyscall || s.entry == 0 {
		t.Errorf("site at the SYSCALL = %+v, %v, want a trap with a slot entry", s, ok)
	}
}

// TestPreWindowFaultReportsTheOriginalAddress makes the second instruction of
// the window fault on a stack page that is not mapped. The slot runs that
// instruction, so the stop lies in the island. The guest must see the address
// of the instruction in the original code. After the Sentry maps the page, the
// guest continues at that instruction, and the first instruction of the window
// does not run again.
func TestPreWindowFaultReportsTheOriginalAddress(t *testing.T) {
	g := newPreWindowGuest(
		[]byte{0x48, 0x89, 0xDA}, // mov rdx, rbx
		movStackRbx,
	)
	r := newRig(t, newFastPlatform(t))
	r.mapPage(codeVA, execAccess, g.code)
	const sp = stackVA + 0x800 // the page at stackVA is not mapped
	r.ac.SetIP(codeVA)
	r.ac.SetStack(sp)

	si, at, err := r.run()
	wantSignal(t, si, err, linux.SIGSEGV)
	if at != hostarch.Write || si.Addr() != sp+8 {
		t.Fatalf("fault = access %v addr %#x, want a write at %#x", at, si.Addr(), uint64(sp+8))
	}
	pc := regPC(r.ac)
	if r.as.inIsland(pc) {
		t.Fatalf("the guest pc %#x lies in an island", pc)
	}
	if want := g.start + 3; pc != want {
		t.Fatalf("the guest pc is %#x, want %#x of the faulting instruction", pc, want)
	}
	if got := regArg(r.ac, 2); got != 1 {
		t.Fatalf("rdx = %d after the first instruction, want 1", got)
	}

	// The Sentry changes RBX and maps the page. A guest that runs the first
	// instruction again would copy the new value to RDX.
	r.ac.StateData().Regs.Rbx = 999
	stack := r.mapPage(stackVA, hostarch.ReadWrite)
	si, _, err = r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if got := regArg(r.ac, 2); got != 1 {
		t.Errorf("rdx = %d, the first instruction of the window ran again", got)
	}
	if got := stackWord(stack, sp+8); got != 999 {
		t.Errorf("the stored word = %d, want 999", got)
	}
	if got := regPC(r.ac); got != g.site+2 {
		t.Errorf("the guest pc is %#x, want %#x behind the SYSCALL", got, g.site+2)
	}
}

// TestPreWindowRestartAndSignalHandler restarts a system call the way the
// Sentry does after a signal: the program counter goes back to the SYSCALL. The
// handler and the sigreturn must see guest addresses only. The restart must
// not run the window again, and it stays on the fast path.
func TestPreWindowRestartAndSignalHandler(t *testing.T) {
	g := newPreWindowGuest(movStackRbx)
	r := newRig(t, newFastPlatform(t))
	stack := g.mapInto(r)
	const handlerVA = dataVA
	// mov eax, 2; syscall; nop; nop; nop; nop: the post plan patches this one.
	r.mapPage(handlerVA, execAccess, []byte{0xB8, 2, 0, 0, 0, 0x0F, 0x05, 0x90, 0x90, 0x90, 0x90})

	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if pc := regPC(r.ac); pc != g.site+2 || r.as.inIsland(pc) {
		t.Fatalf("the signal frame would hold pc %#x, want %#x", pc, g.site+2)
	}

	// Deliver a signal at the system call: save the frame with the restart
	// address, and run the handler.
	saved := *r.ac.StateData()
	saved.Regs.Rip = g.site
	r.ac.SetIP(handlerVA)
	si, _, err = r.run()
	mustSyscall(t, si, err, 2, r.ac)

	// sigreturn.
	*r.ac.StateData() = saved
	si, _, err = r.run()
	mustSyscall(t, si, err, 1, r.ac)
	if got := regAcc(r.ac); got != 1 {
		t.Errorf("the restart ran the loop again: RBX = %d, want 1", got)
	}
	if got := stackWord(stack, preWindowSP+8); got != 1 {
		t.Errorf("the restart ran the window again: stored word = %d, want 1", got)
	}
	if pc := regPC(r.ac); pc != g.site+2 {
		t.Errorf("the guest pc after the restart is %#x, want %#x", pc, g.site+2)
	}
	f := fastStats(t, r)
	if got := f.traps.Load(); got != 3 {
		t.Errorf("fast traps = %d, want 3: the restart must enter the slot", got)
	}
}

// TestPreWindowCloneChildStartsBehindTheSyscall starts a second thread at the
// byte behind the SYSCALL of a pre-window, as the child of clone does. The
// bytes there did not change, so the child runs them in place.
func TestPreWindowCloneChildStartsBehindTheSyscall(t *testing.T) {
	g := newPreWindowGuest(movStackRbx)
	r := newRig(t, newFastPlatform(t))
	g.mapInto(r)
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	child := r.newThread()
	child.ac.SetIP(uintptr(g.site + 2))
	child.ac.SetStack(preWindowSP - 0x200)
	child.ac.StateData().Regs.Rbx = 40
	si, _, err = child.run()
	mustSyscall(t, si, err, 1, child.ac)
	if got := regAcc(child.ac); got != 41 {
		t.Errorf("the child counted %d, want 41", got)
	}
	if got := regPC(child.ac); got != g.site+2 {
		t.Errorf("the child pc is %#x, want %#x", got, g.site+2)
	}
}

// TestStopThreadReturnsWhenTheThreadFaultsInASlot makes the instruction that a
// slot relocates fault. The thread then stands frozen at the exception inside
// the island, which counts as trap code, until Switch replies. This is the amd64
// form of the deadlock that TestStopThreadReturnsWhenTheThreadWaitsAtAnEvent
// covers on arm64. A hung guest on windows-latest showed it: Switch and the
// interrupter both stood in stopThread, and the thread had one event queued at
// the first instruction of a slot tail.
func TestStopThreadReturnsWhenTheThreadFaultsInASlot(t *testing.T) {
	r := newRig(t, newFastPlatform(t))
	// syscall; mov [rsp+8], rax; nop...: the post-window plan relocates the MOV.
	r.program(gSyscall(1), []byte{0x48, 0x89, 0x44, 0x24, 0x08}, nops(16), gSyscall(2))
	si, _, err := r.run()
	mustSyscall(t, si, err, 1, r.ac)

	// The relocated MOV writes to an address that no page backs.
	const unmapped = 0x7000_5000_0000
	r.ac.StateData().Regs.Rsp = unmapped
	th := r.ctx.th.Load()
	if err := th.start(r.ac, false); err != nil {
		t.Fatal(err)
	}
	if err := th.run(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for th.evQueued.Load() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the relocated MOV raised no event")
		}
		time.Sleep(time.Millisecond)
	}

	r.ctx.kicked.Store(true)
	done := make(chan struct{})
	go func() {
		r.ctx.stopThread(th)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("stopThread did not return while the thread waited at a fault in a slot")
	}

	// Switch serves the fault as a SIGSEGV of the guest.
	r.ctx.kicked.Store(false)
	ev, trapped, err := th.waitNext()
	if err != nil || trapped {
		t.Fatalf("waitNext = (trapped %v, %v), want the fault event", trapped, err)
	}
	out := r.ctx.handleEvent(r.rctx, r.mm, r.as, th, r.ac, ev)
	if !out.done || !errors.Is(out.err, platform.ErrContextSignal) {
		t.Fatalf("the fault ended with %+v, want a signal", out)
	}
}
