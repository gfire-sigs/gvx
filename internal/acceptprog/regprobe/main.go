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

// Command regprobe verifies that a guest keeps its CPU state across the events
// that interrupt a thread. Each check fills every general purpose register,
// the vector registers, and the FP control registers with distinct values, lets
// an event happen, and compares the registers afterwards with the values that
// Linux preserves. The events are:
//
//   - a system call, a page fault that the kernel resolves, and a page fault
//     that a SIGSEGV handler resolves,
//   - a signal in user code, in a blocking system call that returns EINTR, in a
//     blocking system call that restarts, and in one that does not restart.
//
// The signal handler overwrites every register and the FP control state, so
// only a correct return from the handler restores the values. Each check
// prints "PASS name" or "FAIL name: reason", and the program prints
// "REGPROBE-OK" when all pass.
package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"syscall"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/guestcpu"
)

// sleepLength is the length of the sleep that a signal interrupts.
const sleepLength = 5 * time.Second

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
		{"syscall", checkSyscall},
		{"page-fault", checkPageFault},
		{"page-fault-handler", checkPageFaultHandler},
		{"signal-in-user-code", checkSignalInUserCode},
		{"signal-in-blocking-syscall", checkSignalInBlockingSyscall},
		{"signal-in-restarted-syscall", checkSignalInRestartedSyscall},
		{"signal-in-unrestarted-syscall", checkSignalInUnrestartedSyscall},
	}
	fmt.Printf("INFO vector registers: %d bytes\n", guestcpu.VectorBytes())
	failed := false
	for _, c := range checks {
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
	fmt.Println("REGPROBE-OK")
}

func checkSyscall() error {
	in := guestcpu.NewState(1)
	in.SetSyscall(syscall.SYS_GETPID)
	var out guestcpu.State
	guestcpu.Run(guestcpu.EventSyscall, &in, &out)
	want := in
	want.SetResult(uint64(os.Getpid()))
	return guestcpu.Compare(&want, &out, guestcpu.SyscallClobbers()...)
}

func anonPage(prot int) ([]byte, error) {
	return syscall.Mmap(-1, 0, syscall.Getpagesize(), prot, syscall.MAP_PRIVATE|syscall.MAP_ANONYMOUS)
}

func checkPageFault() error {
	page, err := anonPage(syscall.PROT_READ | syscall.PROT_WRITE)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(page)
	in := guestcpu.NewState(2)
	in.SetFaultAddr(uintptr(unsafe.Pointer(&page[0])))
	var out guestcpu.State
	guestcpu.Run(guestcpu.EventFault, &in, &out)
	return guestcpu.Compare(&in, &out)
}

func checkPageFaultHandler() error {
	page, err := anonPage(syscall.PROT_NONE)
	if err != nil {
		return fmt.Errorf("mmap: %w", err)
	}
	defer syscall.Munmap(page)
	restore, err := guestcpu.Install(syscall.SIGSEGV, false)
	if err != nil {
		return err
	}
	defer restore()
	guestcpu.ResetHandler()
	in := guestcpu.NewState(3)
	in.SetFaultAddr(uintptr(unsafe.Pointer(&page[0])))
	var out guestcpu.State
	guestcpu.Run(guestcpu.EventFault, &in, &out)
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the SIGSEGV handler ran %d times, want 1", n)
	}
	return guestcpu.Compare(&in, &out)
}

func checkSignalInUserCode() error {
	restore, err := guestcpu.Install(syscall.SIGUSR1, false)
	if err != nil {
		return err
	}
	defer restore()
	guestcpu.ResetHandler()
	in := guestcpu.NewState(4)
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, guestcpu.ReleaseSpin)
	guestcpu.Run(guestcpu.EventSpin, &in, &out)
	wait()
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	if guestcpu.SpinFlagAtHandler() != 0 {
		return errors.New("the signal handler ran after the loop ended")
	}
	want := in
	want.ExpectSpinExit()
	return guestcpu.Compare(&want, &out)
}

func checkSignalInBlockingSyscall() error {
	restore, err := guestcpu.Install(syscall.SIGUSR1, false)
	if err != nil {
		return err
	}
	defer restore()
	guestcpu.ResetHandler()
	// The State holds the addresses as integers, so the buffers must not move.
	reqVal := syscall.NsecToTimespec(int64(sleepLength))
	req := &reqVal
	rem := new(syscall.Timespec)
	in := guestcpu.NewState(5)
	in.SetSyscall(syscall.SYS_NANOSLEEP, uintptr(unsafe.Pointer(req)), uintptr(unsafe.Pointer(rem)))
	var out guestcpu.State
	wait := guestcpu.SignalLater(syscall.SIGUSR1, nil)
	guestcpu.Run(guestcpu.EventSyscall, &in, &out)
	wait()
	if n := guestcpu.HandlerCalls(); n != 1 {
		return fmt.Errorf("the signal handler ran %d times, want 1", n)
	}
	if left := time.Duration(rem.Nano()); left <= 0 || left >= sleepLength {
		return fmt.Errorf("nanosleep left %v of %v", left, sleepLength)
	}
	want := in
	want.SetResult(guestcpu.NegErrno(syscall.EINTR))
	return guestcpu.Compare(&want, &out, guestcpu.SyscallClobbers()...)
}

func checkSignalInRestartedSyscall() error {
	restore, err := guestcpu.Install(syscall.SIGUSR1, true)
	if err != nil {
		return err
	}
	defer restore()
	guestcpu.ResetHandler()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	// The State holds the address as an integer, so the buffer must not move.
	buf := new([1]byte)
	in := guestcpu.NewState(6)
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
	if buf[0] != 0x5a {
		return fmt.Errorf("read stored %#x, want 0x5a", buf[0])
	}
	want := in
	want.SetResult(1)
	return guestcpu.Compare(&want, &out, guestcpu.SyscallClobbers()...)
}

func checkSignalInUnrestartedSyscall() error {
	restore, err := guestcpu.Install(syscall.SIGUSR1, false)
	if err != nil {
		return err
	}
	defer restore()
	guestcpu.ResetHandler()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	defer syscall.Close(fds[1])
	buf := new([1]byte)
	in := guestcpu.NewState(7)
	in.SetSyscall(syscall.SYS_READ, uintptr(fds[0]), uintptr(unsafe.Pointer(&buf[0])), 1)
	var out guestcpu.State
	// A kernel that does not interrupt the read gets a byte, so the check fails
	// and does not wait for ever.
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
	want := in
	want.SetResult(guestcpu.NegErrno(syscall.EINTR))
	return guestcpu.Compare(&want, &out, guestcpu.SyscallClobbers()...)
}
