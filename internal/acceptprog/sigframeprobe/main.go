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

//go:build linux && (amd64 || arm64)

// Command sigframeprobe verifies the signal frame that the guest kernel builds,
// and that it reads the frame back when the handler returns. The handler is
// guestcpu.evilHandler, which copies the frame, so each check compares the
// copy with the registers that the thread had when the signal arrived. The
// checks cover:
//
//   - a signal in user code: registers, program counter, stack pointer, the
//     vector and FP record, the signal stack, the signal mask, and the siginfo
//     of tgkill,
//   - a store to a read-only page and to an unmapped page: si_code,
//     si_addr, and the fault fields of the architecture (amd64: trap number,
//     error code, CR2; arm64: fault_address and esr_context),
//   - a system call that restarts after the handler: the frame shows the state
//     before the call and a program counter on the call instruction,
//   - a system call that returns EINTR: the frame holds -EINTR and a program
//     counter behind the call instruction,
//   - a handler that edits the frame: the registers after the sigreturn have
//     the edited values, and the edited program counter skips a faulting
//     instruction.
//
// Each check prints "PASS name" or "FAIL name: reason", and the program prints
// "SIGFRAMEPROBE-OK" when all pass.
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/guestcpu"
)

const (
	sleepLength = 200 * time.Millisecond
	siTkill     = -6
	segvMaperr  = 1
	segvAccerr  = 2
)

func main() {
	// The thread that runs the event holds test values in registers. A garbage
	// collection or a preemption signal in that time stops the program.
	debug.SetGCPercent(-1)
	runtime.GOMAXPROCS(max(runtime.GOMAXPROCS(0), 2))
	runtime.LockOSThread()
	defer guestcpu.Watchdog(time.Minute).Stop()
	unblock, err := guestcpu.BlockSignals(syscall.SIGURG, syscall.SIGCHLD)
	if err != nil {
		fmt.Println("FAIL setup:", err)
		os.Exit(1)
	}
	defer unblock()

	checks := []struct {
		name string
		fn   func() error
	}{
		{"frame-signal-in-user-code", checkSignalInUserCode},
		{"frame-fault-read-only", func() error { return checkFault(true) }},
		{"frame-fault-unmapped", func() error { return checkFault(false) }},
		{"frame-restarted-syscall", checkRestartedSyscall},
		{"frame-interrupted-syscall", checkInterruptedSyscall},
		{"frame-edit-registers", checkEditRegisters},
		{"frame-edit-pc", checkEditPC},
	}
	failed := false
	for _, c := range checks {
		fmt.Println("RUN", c.name)
		if err := c.fn(); err != nil {
			fmt.Printf("FAIL %s: %v\n", c.name, err)
			failed = true
			continue
		}
		fmt.Println("PASS", c.name)
	}
	if failed {
		os.Exit(1)
	}
	fmt.Println("SIGFRAMEPROBE-OK")
}

func anonPage(prot int) ([]byte, error) {
	return syscall.Mmap(-1, 0, syscall.Getpagesize(), prot, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
}

// funcName returns the name of the function that holds pc.
func funcName(pc uint64) string {
	if f := runtime.FuncForPC(uintptr(pc)); f != nil {
		return f.Name()
	}
	return "unknown"
}

// inFunction verifies that pc is in the assembly function named name.
func inFunction(pc uint64, name string) error {
	if got := funcName(pc); !strings.HasSuffix(got, "."+name) {
		return fmt.Errorf("the program counter %#x is in %s, want %s", pc, got, name)
	}
	return nil
}

// sigaltstack returns the signal stack of the calling thread.
func sigaltstack() (sp, size uint64, flags int32, err error) {
	var ss struct {
		sp    uintptr
		flags int32
		_     int32
		size  uintptr
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_SIGALTSTACK, 0, uintptr(unsafe.Pointer(&ss)), 0); errno != 0 {
		return 0, 0, 0, errno
	}
	return uint64(ss.sp), uint64(ss.size), ss.flags, nil
}

// sigmask returns the signal mask of the calling thread.
func sigmask() (uint64, error) {
	var set uint64
	if _, _, errno := syscall.RawSyscall6(syscall.SYS_RT_SIGPROCMASK, 0, 0, uintptr(unsafe.Pointer(&set)), 8, 0, 0); errno != 0 {
		return 0, errno
	}
	return set, nil
}

// checkContext checks the fields of the frame that do not depend on the event:
// the signal stack and the signal mask of the interrupted thread. Linux sets
// SS_ONSTACK in uc_stack.ss_flags only when the interrupted code ran on the
// signal stack, so the flags equal what sigaltstack reports in that code.
func checkContext(f *guestcpu.Frame) error {
	sp, size, flags, err := sigaltstack()
	if err != nil {
		return fmt.Errorf("sigaltstack: %w", err)
	}
	if f.StackSP != sp || f.StackSize != size || f.StackFlags != flags {
		return fmt.Errorf("uc_stack = {sp %#x, size %#x, flags %#x}, want the signal stack {sp %#x, size %#x, flags %#x}",
			f.StackSP, f.StackSize, f.StackFlags, sp, size, flags)
	}
	mask, err := sigmask()
	if err != nil {
		return fmt.Errorf("rt_sigprocmask: %w", err)
	}
	if f.Sigmask != mask {
		return fmt.Errorf("uc_sigmask = %#x, want the mask %#x of the interrupted thread", f.Sigmask, mask)
	}
	return nil
}

// checkTkill checks the siginfo of a signal that tgkill sends.
func checkTkill(f *guestcpu.Frame, sig syscall.Signal) error {
	if f.Signal() != sig || f.Info.Code != siTkill || int(f.Info.Pid) != os.Getpid() {
		return fmt.Errorf("siginfo = {signo %d, code %d, pid %d}, want {signo %d, code %d (SI_TKILL), pid %d}",
			f.Info.Signo, f.Info.Code, f.Info.Pid, sig, siTkill, os.Getpid())
	}
	return nil
}

func installCapture(sig syscall.Signal, restart bool, mode guestcpu.Mode) (restore func(), err error) {
	restore, err = guestcpu.Install(sig, restart)
	if err != nil {
		return nil, err
	}
	guestcpu.ResetHandler()
	guestcpu.SetMode(mode)
	return restore, nil
}

func checkSignalInUserCode() error {
	restore, err := installCapture(syscall.SIGUSR1, false, guestcpu.ModeCapture)
	if err != nil {
		return err
	}
	defer restore()
	in := guestcpu.NewState(21)
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, guestcpu.ReleaseSpin)
	guestcpu.Run(guestcpu.EventSpin, &in, &out)
	wait()
	f, err := guestcpu.CapturedFrame()
	if err != nil {
		return err
	}
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	if guestcpu.SpinFlagAtHandler() != 0 {
		return fmt.Errorf("the signal handler ran after the loop ended")
	}
	if err := checkTkill(f, syscall.SIGUSR1); err != nil {
		return err
	}
	if err := checkContext(f); err != nil {
		return err
	}
	if err := inFunction(f.PC, "runSpin"); err != nil {
		return err
	}
	if err := guestcpu.Compare(&in, &f.Regs, guestcpu.SpinScratch()...); err != nil {
		return fmt.Errorf("the registers in the frame differ from the interrupted ones: %w", err)
	}
	return nil
}

// sink keeps the read of checkFault.
var sink byte

// checkFault stores to a page that is read-only (permission) or not mapped. A
// read-only page is present after a read, so the store fails on a protection
// violation. A PROT_NONE page is not present and gives another error code on
// amd64 and another fault type on arm64.
func checkFault(permission bool) error {
	prot := syscall.PROT_READ
	if !permission {
		prot |= syscall.PROT_WRITE
	}
	page, err := anonPage(prot)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	addr := uintptr(unsafe.Pointer(&page[0]))
	if permission {
		sink = page[0]
		defer syscall.Munmap(page)
	} else if err := syscall.Munmap(page); err != nil {
		return fmt.Errorf("munmap: %w", err)
	}
	restore, err := installCapture(syscall.SIGSEGV, false, guestcpu.ModeCapture|guestcpu.ModeSkipFault)
	if err != nil {
		return err
	}
	defer restore()
	in := guestcpu.NewState(22)
	in.SetFaultAddr(addr)
	var out guestcpu.State
	guestcpu.Run(guestcpu.EventFault, &in, &out)
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the SIGSEGV handler ran %d times, want 1", n)
	}
	f, err := guestcpu.CapturedFrame()
	if err != nil {
		return err
	}
	code := int32(segvMaperr)
	if permission {
		code = segvAccerr
	}
	if f.Signal() != syscall.SIGSEGV || f.Info.Code != code || f.Info.Addr != uint64(addr) {
		return fmt.Errorf("siginfo = {signo %d, code %d, addr %#x}, want {signo %d, code %d, addr %#x}",
			f.Info.Signo, f.Info.Code, f.Info.Addr, syscall.SIGSEGV, code, addr)
	}
	if err := checkContext(f); err != nil {
		return err
	}
	if err := inFunction(f.PC, "runFault"); err != nil {
		return err
	}
	if err := guestcpu.Compare(&in, &f.Regs); err != nil {
		return fmt.Errorf("the registers in the frame differ from the interrupted ones: %w", err)
	}
	if err := checkFaultFrame(f, uint64(addr), permission); err != nil {
		return err
	}
	// The handler moved the program counter over the store.
	return guestcpu.Compare(&in, &out)
}

// readCode returns the bytes of the code at addr.
func readCode(addr uint64, n int) ([]byte, error) {
	b, err := guestcpu.ReadMemory(uintptr(addr), n)
	if err != nil {
		return nil, fmt.Errorf("read the code at %#x: %w", addr, err)
	}
	return b, nil
}

func checkRestartedSyscall() error {
	restore, err := installCapture(syscall.SIGUSR1, true, guestcpu.ModeCapture)
	if err != nil {
		return err
	}
	defer restore()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	var buf [1]byte
	in := guestcpu.NewState(23)
	in.SetSyscall(syscall.SYS_READ, uintptr(fds[0]), uintptr(unsafe.Pointer(&buf[0])), 1)
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, func() {
		if _, err := syscall.Write(fds[1], []byte{0x5a}); err != nil {
			fmt.Println("write:", err)
		}
	})
	guestcpu.Run(guestcpu.EventSyscall, &in, &out)
	wait()
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	if out.Result() != 1 || buf[0] != 0x5a {
		return fmt.Errorf("read returned %d with byte %#x, want 1 with 0x5a", int64(out.Result()), buf[0])
	}
	f, err := guestcpu.CapturedFrame()
	if err != nil {
		return err
	}
	if err := checkTkill(f, syscall.SIGUSR1); err != nil {
		return err
	}
	// Linux undoes the system call before it builds the frame: the registers
	// are those before the call, and the program counter is on the call.
	if err := guestcpu.Compare(&in, &f.Regs, guestcpu.SyscallClobbers()...); err != nil {
		return fmt.Errorf("the registers in the frame differ from those before the call: %w", err)
	}
	if err := inFunction(f.PC, "runSyscall"); err != nil {
		return err
	}
	code, err := readCode(f.PC, syscallInsnLen)
	if err != nil {
		return err
	}
	if !isSyscallInsn(code) {
		return fmt.Errorf("the program counter %#x is not on the system call instruction: % x", f.PC, code)
	}
	return nil
}

func checkInterruptedSyscall() error {
	restore, err := installCapture(syscall.SIGUSR1, false, guestcpu.ModeCapture)
	if err != nil {
		return err
	}
	defer restore()
	req := syscall.Timespec{Nsec: int64(sleepLength)}
	var rem syscall.Timespec
	in := guestcpu.NewState(24)
	in.SetSyscall(syscall.SYS_NANOSLEEP, uintptr(unsafe.Pointer(&req)), uintptr(unsafe.Pointer(&rem)))
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, nil)
	guestcpu.Run(guestcpu.EventSyscall, &in, &out)
	wait()
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	f, err := guestcpu.CapturedFrame()
	if err != nil {
		return err
	}
	want := in
	want.SetResult(guestcpu.NegErrno(syscall.EINTR))
	if err := guestcpu.Compare(&want, &f.Regs, guestcpu.SyscallClobbers()...); err != nil {
		return fmt.Errorf("the registers in the frame differ from those after the call: %w", err)
	}
	if err := inFunction(f.PC-1, "runSyscall"); err != nil {
		return err
	}
	code, err := readCode(f.PC-syscallInsnLen, syscallInsnLen)
	if err != nil {
		return err
	}
	if !isSyscallInsn(code) {
		return fmt.Errorf("the program counter %#x is not behind the system call instruction: % x", f.PC, code)
	}
	return nil
}

func checkEditRegisters() error {
	restore, err := installCapture(syscall.SIGUSR1, false, guestcpu.ModeEdit)
	if err != nil {
		return err
	}
	defer restore()
	edit := guestcpu.NewEditState(26)
	guestcpu.SetEdit(&edit)
	in := guestcpu.NewState(25)
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, guestcpu.ReleaseSpin)
	guestcpu.Run(guestcpu.EventSpin, &in, &out)
	wait()
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	if guestcpu.SpinFlagAtHandler() != 0 {
		return fmt.Errorf("the signal handler ran after the loop ended")
	}
	want := edit
	want.ExpectSpinExit()
	if err := guestcpu.Compare(&want, &out); err != nil {
		return fmt.Errorf("the registers after the sigreturn differ from the edited frame: %w", err)
	}
	return nil
}

func checkEditPC() error {
	page, err := anonPage(syscall.PROT_NONE)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(page)
	restore, err := installCapture(syscall.SIGSEGV, false, guestcpu.ModeSkipFault)
	if err != nil {
		return err
	}
	defer restore()
	in := guestcpu.NewState(27)
	in.SetFaultAddr(uintptr(unsafe.Pointer(&page[0])))
	var out guestcpu.State
	guestcpu.Run(guestcpu.EventFault, &in, &out)
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the SIGSEGV handler ran %d times, want 1", n)
	}
	return guestcpu.Compare(&in, &out)
}
