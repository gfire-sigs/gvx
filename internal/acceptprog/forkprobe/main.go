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

// Command forkprobe checks that the guest kernel gives a new process or a new
// thread the CPU state of its creator, and that it resets that state on
// execve. Each check fills every general purpose register, the vector
// registers, and the FP control state with distinct values, and then calls
// clone with the registers loaded. The child stores its registers before it
// runs any other code. The checks cover:
//
//   - fork: the child and the parent have every register of the call, and the
//     child runs on the stack that the call names,
//   - clone with CLONE_VM and CLONE_THREAD: the new thread has every register,
//     including the vector registers and the FP control state,
//   - fork and execve: the new program starts with the Linux defaults of the FP
//     control state (amd64: MXCSR 0x1f80 and x87 control word 0x37f; arm64:
//     FPCR 0).
//
// Each check prints "PASS name" or "FAIL name: reason", and the program prints
// "FORKPROBE-OK" when all pass.
//
// Usage:
//
//	forkprobe             run every check
//	forkprobe exec-child FD  print the FP control state to descriptor FD, started
//	                         by the exec check
package main

import (
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/acceptprog/guestcpu"
)

const waitLimit = 10 * time.Second

func main() {
	if len(os.Args) == 3 && os.Args[1] == "exec-child" {
		if err := execChild(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "exec-child:", err)
			os.Exit(1)
		}
		return
	}
	// The thread that runs the clone holds test values in registers. A garbage
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
		{"fork-state", checkFork},
		{"clone-thread-state", checkCloneThread},
		{"exec-resets-control-state", checkExec},
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
	fmt.Println("FORKPROBE-OK")
}

// execChild prints the FP control state that the program started with.
func execChild(fdArg string) error {
	fd, err := strconv.Atoi(fdArg)
	if err != nil {
		return err
	}
	first, second := guestcpu.ReadControl()
	_, err = syscall.Write(fd, []byte(fmt.Sprintf("control %#x %#x\n", first, second)))
	return err
}

// sharedPage is a page that a forked child and its parent share, or that a new
// thread and its creator share. The kernel and the child write to it while the
// parent runs, so it is not Go memory that can move.
type sharedPage struct {
	mem []byte
	// Tid is the word of CLONE_PARENT_SETTID and CLONE_CHILD_CLEARTID.
	Tid *uint32
	// State holds the registers that the child stores.
	State *guestcpu.State
}

func newSharedPage() (*sharedPage, error) {
	mem, err := syscall.Mmap(-1, 0, syscall.Getpagesize(), syscall.PROT_READ|syscall.PROT_WRITE,
		syscall.MAP_SHARED|syscall.MAP_ANONYMOUS)
	if err != nil {
		return nil, fmt.Errorf("mmap: %w", err)
	}
	return &sharedPage{
		mem:   mem,
		Tid:   (*uint32)(unsafe.Pointer(&mem[0])),
		State: (*guestcpu.State)(unsafe.Pointer(&mem[64])),
	}, nil
}

func (p *sharedPage) free() { _ = syscall.Munmap(p.mem) }

// compareChild verifies the registers of a new child and parent against in.
// The child has the result 0 of clone, and the parent has the ID of the child.
func compareChild(in, child, parent *guestcpu.State, childSP uintptr) error {
	if pid := int64(parent.Result()); pid <= 0 {
		return fmt.Errorf("clone returned %d", pid)
	}
	wantChild := *in
	wantChild.SetResult(0)
	wantChild.SetStackPointer(uint64(childSP))
	if err := guestcpu.Compare(&wantChild, child, guestcpu.SyscallClobbers()...); err != nil {
		return fmt.Errorf("the child differs from the registers of the call: %w", err)
	}
	wantParent := *in
	wantParent.SetResult(parent.Result())
	if err := guestcpu.Compare(&wantParent, parent, guestcpu.SyscallClobbers()...); err != nil {
		return fmt.Errorf("the parent differs from the registers of the call: %w", err)
	}
	return nil
}

func waitChild(pid int) error {
	var ws syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &ws, 0, nil); err != nil {
		return fmt.Errorf("wait4: %w", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		return fmt.Errorf("the child did not exit with status 0 (exited %v, status %d, signal %v)", ws.Exited(), ws.ExitStatus(), ws.Signal())
	}
	return nil
}

func checkFork() error {
	page, err := newSharedPage()
	if err != nil {
		return err
	}
	defer page.free()
	stack, err := guestcpu.NewChildStack(page.State)
	if err != nil {
		return fmt.Errorf("child stack: %w", err)
	}
	defer stack.Close()
	var unused uint32
	in := guestcpu.NewState(31)
	in.SetClone(uintptr(syscall.SIGCHLD), stack.SP(), uintptr(unsafe.Pointer(&unused)))
	var parent guestcpu.State
	guestcpu.Clone(&in, &parent)
	// The child stores its registers before it exits, so read them after wait4.
	var waitErr error
	if pid := int(int64(parent.Result())); pid > 0 {
		waitErr = waitChild(pid)
	}
	if err := compareChild(&in, page.State, &parent, stack.SP()); err != nil {
		return err
	}
	return waitErr
}

func checkCloneThread() error {
	page, err := newSharedPage()
	if err != nil {
		return err
	}
	defer page.free()
	stack, err := guestcpu.NewChildStack(page.State)
	if err != nil {
		return fmt.Errorf("child stack: %w", err)
	}
	defer stack.Close()
	// The word is not zero until the thread exits and the kernel clears it.
	atomic.StoreUint32(page.Tid, ^uint32(0))
	in := guestcpu.NewState(32)
	in.SetClone(guestcpu.CloneThreadFlags, stack.SP(), uintptr(unsafe.Pointer(page.Tid)))
	var parent guestcpu.State
	guestcpu.Clone(&in, &parent)
	if err := waitThread(page.Tid); err != nil {
		return err
	}
	return compareChild(&in, page.State, &parent, stack.SP())
}

// waitThread waits until the kernel clears the thread ID word at tid, which
// happens when the thread exits.
func waitThread(tid *uint32) error {
	const futexWait = 0
	deadline := time.Now().Add(waitLimit)
	for {
		v := atomic.LoadUint32(tid)
		if v == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("the thread did not exit within %v", waitLimit)
		}
		ts := syscall.NsecToTimespec(int64(100 * time.Millisecond))
		syscall.Syscall6(syscall.SYS_FUTEX, uintptr(unsafe.Pointer(tid)), futexWait, uintptr(v),
			uintptr(unsafe.Pointer(&ts)), 0, 0)
	}
}

// cStrings returns the addresses of NUL-terminated copies of strs in an array
// with a nil pointer at the end, and the memory that holds them.
func cStrings(strs []string) (uintptr, [][]byte, []*byte) {
	mem := make([][]byte, len(strs))
	ptrs := make([]*byte, len(strs)+1)
	for i, s := range strs {
		mem[i] = append([]byte(s), 0)
		ptrs[i] = &mem[i][0]
	}
	return uintptr(unsafe.Pointer(&ptrs[0])), mem, ptrs
}

func checkExec() error {
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		return fmt.Errorf("pipe: %w", err)
	}
	defer syscall.Close(fds[0])
	const exe = "/proc/self/exe"
	path := append([]byte(exe), 0)
	argv, argvMem, argvPtrs := cStrings([]string{exe, "exec-child", strconv.Itoa(fds[1])})
	envp, envMem, envPtrs := cStrings(os.Environ())
	// The child stores nothing, but the child stack names a State.
	stack, err := guestcpu.NewChildStack(new(guestcpu.State))
	if err != nil {
		return fmt.Errorf("child stack: %w", err)
	}
	defer stack.Close()
	stack.SetExec(uintptr(unsafe.Pointer(&path[0])), argv, envp)
	var unused uint32
	in := guestcpu.NewState(33)
	in.SetClone(uintptr(syscall.SIGCHLD), stack.SP(), uintptr(unsafe.Pointer(&unused)))
	var parent guestcpu.State
	guestcpu.Clone(&in, &parent)
	// Close the write end here, so that the read below ends at the end of the
	// report when the child never writes one.
	syscall.Close(fds[1])
	pid := int(int64(parent.Result()))
	if pid <= 0 {
		return fmt.Errorf("clone returned %d", pid)
	}
	err = waitChild(pid)
	runtime.KeepAlive(path)
	runtime.KeepAlive(argvMem)
	runtime.KeepAlive(argvPtrs)
	runtime.KeepAlive(envMem)
	runtime.KeepAlive(envPtrs)
	if err != nil {
		return err
	}
	buf := make([]byte, 64)
	n, err := syscall.Read(fds[0], buf)
	if err != nil {
		return fmt.Errorf("read the report: %w", err)
	}
	var first, second uint64
	if _, err := fmt.Sscanf(string(buf[:n]), "control %v %v", &first, &second); err != nil {
		return fmt.Errorf("parse the report %q: %w", buf[:n], err)
	}
	wantFirst, wantSecond := guestcpu.DefaultControl()
	maskFirst, maskSecond := guestcpu.ControlMasks()
	if first&maskFirst != wantFirst&maskFirst || second&maskSecond != wantSecond&maskSecond {
		return fmt.Errorf("the FP control registers of the new program are %#x and %#x, want %#x and %#x (compared under the masks %#x and %#x)",
			first, second, wantFirst, wantSecond, maskFirst, maskSecond)
	}
	return nil
}
