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

//go:build linux && amd64

// Command ptracegs checks that a guest keeps running after a tracer changes
// its GS base. The guest runs the syscall instruction of a thread in a loop. A
// Sentry that patches this instruction with a jump that uses GS must remove the
// patch when the tracer sets the GS base, as it does for arch_prctl. Each check
// prints "PASS name" or "FAIL name: reason". The last line is "DONE".
//
// Usage: ptracegs
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// childRuntime is the time that the child runs the syscall loop.
	childRuntime = 2 * time.Second
	// patchWait is the time that the child gets to run before the tracer
	// attaches. The Sentry patches the syscall instruction in this time.
	patchWait = 500 * time.Millisecond
	// junkGSBase is a canonical address that no mapping covers.
	junkGSBase = 0x123456000
	ntPrstatus = 1
)

// spin calls getpid n times with the instruction sequence that a Sentry
// patches: "mov $39, %eax; syscall".
func spin(n int)

func init() {
	// The tracer thread and the traced thread of the child are the thread
	// that runs main.
	runtime.LockOSThread()
}

// method changes the GS base of a stopped tracee.
type method struct {
	name string
	set  func(pid int, regs *unix.PtraceRegs) error
}

var methods = []method{
	{"setregs", func(pid int, regs *unix.PtraceRegs) error {
		regs.Gs_base = junkGSBase
		return unix.PtraceSetRegs(pid, regs)
	}},
	{"setregset", func(pid int, regs *unix.PtraceRegs) error {
		regs.Gs_base = junkGSBase
		iov := unix.Iovec{Base: (*byte)(unsafe.Pointer(regs))}
		iov.SetLen(int(unsafe.Sizeof(*regs)))
		_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SETREGSET, uintptr(pid), ntPrstatus, uintptr(unsafe.Pointer(&iov)), 0, 0)
		if errno != 0 {
			return errno
		}
		return nil
	}},
	{"pokeuser", func(pid int, regs *unix.PtraceRegs) error {
		var word [8]byte
		binary.LittleEndian.PutUint64(word[:], junkGSBase)
		_, err := unix.PtracePokeUser(pid, unsafe.Offsetof(regs.Gs_base), word[:])
		return err
	}},
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "child" {
		child()
		return
	}
	for _, m := range methods {
		if err := check(m); err != nil {
			fmt.Printf("FAIL %s: %v\n", m.name, err)
			continue
		}
		fmt.Printf("PASS %s\n", m.name)
	}
	fmt.Println("DONE")
}

// child runs the syscall loop and exits with 0.
func child() {
	start := time.Now()
	for time.Since(start) < childRuntime {
		spin(1000)
	}
}

// check runs a child, attaches to it after the Sentry patched its syscall
// instruction, changes its GS base with m, detaches, and waits for the exit.
func check(m method) error {
	cmd := exec.Command(os.Args[0], "child")
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the child: %w", err)
	}
	pid := cmd.Process.Pid
	defer unix.Kill(pid, unix.SIGKILL)
	time.Sleep(patchWait)

	if err := unix.PtraceAttach(pid); err != nil {
		return fmt.Errorf("PTRACE_ATTACH: %w", err)
	}
	for {
		var ws unix.WaitStatus
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			return fmt.Errorf("wait for the stop: %w", err)
		}
		if !ws.Stopped() {
			return fmt.Errorf("the child left before the stop: %v", describe(ws))
		}
		if ws.StopSignal() == unix.SIGSTOP {
			break
		}
		// Forward a signal of the runtime, for example SIGURG.
		if err := unix.PtraceCont(pid, int(ws.StopSignal())); err != nil {
			return fmt.Errorf("PTRACE_CONT: %w", err)
		}
	}

	var regs unix.PtraceRegs
	if err := unix.PtraceGetRegs(pid, &regs); err != nil {
		return fmt.Errorf("PTRACE_GETREGS: %w", err)
	}
	if err := m.set(pid, &regs); err != nil {
		return fmt.Errorf("set the GS base: %w", err)
	}
	if err := unix.PtraceDetach(pid); err != nil {
		return fmt.Errorf("PTRACE_DETACH: %w", err)
	}

	var ws unix.WaitStatus
	for {
		if _, err := unix.Wait4(pid, &ws, 0, nil); err != nil {
			return fmt.Errorf("wait for the exit: %w", err)
		}
		if ws.Exited() || ws.Signaled() {
			break
		}
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("the child did not exit with 0: %v", describe(ws))
	}
	return nil
}

func describe(ws unix.WaitStatus) string {
	switch {
	case ws.Exited():
		return fmt.Sprintf("exit status %d", ws.ExitStatus())
	case ws.Signaled():
		return fmt.Sprintf("killed by signal %d (%v)", int(ws.Signal()), ws.Signal())
	default:
		return fmt.Sprintf("wait status %#x", uint32(ws))
	}
}
