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

//go:build linux

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// The child modes run one host facility in a separate process, so a fatal
// result, such as a kill by SIGSYS, ends only that process.
const (
	childPtrace          = "child-ptrace"
	childSeccompTrap     = "child-seccomp-trap"
	childSeccompListener = "child-seccomp-listener"
)

// item is one line of the report: a facility, its result, and a detail.
type item struct {
	name   string
	ok     bool
	detail string
}

// report writes one line for each facility and returns 0 when every facility
// works.
func report(w io.Writer) int {
	items := []item{
		probeMMapMinAddr(),
		{name: "page_size", ok: true, detail: fmt.Sprint(os.Getpagesize())},
		{name: "task_size", ok: true, detail: fmt.Sprintf("%#x", linux.TaskSize)},
		probeMemfdExec(),
		probeMemfdExecFlag(),
		probeAnonExec(),
		probeChild("ptrace_singlestep", childPtrace, func(st syscall.WaitStatus) bool {
			return st.Exited() && st.ExitStatus() == 0
		}),
		probeChild("seccomp_trap", childSeccompTrap, func(st syscall.WaitStatus) bool {
			// SECCOMP_RET_TRAP without a handler kills the process by SIGSYS.
			return st.Signaled() && st.Signal() == syscall.SIGSYS
		}),
		probeChild("seccomp_listener", childSeccompListener, func(st syscall.WaitStatus) bool {
			return st.Exited() && st.ExitStatus() == 0
		}),
	}
	code := 0
	for _, it := range items {
		state := "ok"
		if !it.ok {
			state = "FAIL"
			code = 1
		}
		fmt.Fprintf(w, "%-18s %-4s %s\n", it.name, state, it.detail)
	}
	return code
}

// probeMMapMinAddr reads the lowest address that the host lets a process map.
// The Linux systrap engine panics at start when it cannot read this file.
func probeMMapMinAddr() item {
	b, err := os.ReadFile("/proc/sys/vm/mmap_min_addr")
	if err != nil {
		return item{name: "mmap_min_addr", detail: err.Error()}
	}
	return item{name: "mmap_min_addr", ok: true, detail: strings.TrimSpace(string(b))}
}

// probeMemfdExec maps a memfd with PROT_EXEC, as the systrap engine maps guest
// code from its memory file.
func probeMemfdExec() item {
	const name = "memfd_exec"
	fd, err := unix.MemfdCreate("androidprobe", unix.MFD_CLOEXEC)
	if err != nil {
		return item{name: name, detail: "memfd_create: " + err.Error()}
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(os.Getpagesize())); err != nil {
		return item{name: name, detail: "ftruncate: " + err.Error()}
	}
	b, err := unix.Mmap(fd, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_EXEC, unix.MAP_SHARED)
	if err != nil {
		return item{name: name, detail: "mmap PROT_EXEC: " + err.Error()}
	}
	_ = unix.Munmap(b)
	return item{name: name, ok: true, detail: "mapped"}
}

// describeStatus names how a child ended.
func describeStatus(st syscall.WaitStatus) string {
	switch {
	case st.Exited():
		return fmt.Sprintf("exit %d", st.ExitStatus())
	case st.Signaled():
		return "signal " + st.Signal().String()
	default:
		return fmt.Sprintf("status %#x", uint32(st))
	}
}

// probeMemfdExecFlag reports whether the kernel accepts MFD_EXEC, which the
// Android build passes so that vm.memfd_noexec=1 keeps the memory file
// executable.
func probeMemfdExecFlag() item {
	const name = "memfd_mfd_exec"
	fd, err := unix.MemfdCreate("androidprobe", unix.MFD_CLOEXEC|unix.MFD_EXEC)
	if err != nil {
		return item{name: name, detail: "memfd_create(MFD_EXEC): " + err.Error()}
	}
	unix.Close(fd)
	return item{name: name, ok: true, detail: "accepted"}
}

// probeAnonExec maps an anonymous page writable, then makes it read and
// execute only, as the copy mode of GVXIP-006 section 2.5 needs.
func probeAnonExec() item {
	const name = "anon_exec"
	b, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return item{name: name, detail: "mmap: " + err.Error()}
	}
	defer unix.Munmap(b)
	if err := unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC); err != nil {
		return item{name: name, detail: "mprotect PROT_EXEC: " + err.Error()}
	}
	return item{name: name, ok: true, detail: "read and execute"}
}

// probeChild runs this program in a child mode and judges its wait status.
func probeChild(name, mode string, judge func(syscall.WaitStatus) bool) item {
	exe, err := os.Executable()
	if err != nil {
		return item{name: name, detail: err.Error()}
	}
	out, err := exec.Command(exe, mode).CombinedOutput()
	var exitErr *exec.ExitError
	var st syscall.WaitStatus
	switch {
	case err == nil:
		st = 0
	case errors.As(err, &exitErr):
		st = exitErr.Sys().(syscall.WaitStatus)
	default:
		return item{name: name, detail: err.Error()}
	}
	ok, detail := judge(st), describeStatus(st)
	if msg := strings.TrimSpace(string(out)); msg != "" {
		detail += ": " + msg
	}
	return item{name: name, ok: ok, detail: detail}
}

// runChild runs one child mode and returns its exit code.
func runChild(mode string) int {
	var err error
	switch mode {
	case childPtrace:
		err = traceChild()
	case childSeccompTrap:
		err = installTrapFilter()
	case childSeccompListener:
		err = installListener()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// traceChild starts /system/bin/sh (or /bin/sh) under ptrace and single-steps
// it, as the systrap engine single-steps a stub thread.
func traceChild() error {
	shell := "/system/bin/sh"
	if _, err := os.Stat(shell); err != nil {
		shell = "/bin/sh"
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(shell, "-c", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start traced child: %w", err)
	}
	pid := cmd.Process.Pid
	defer cmd.Process.Kill()
	var st syscall.WaitStatus
	if _, err := syscall.Wait4(pid, &st, 0, nil); err != nil {
		return fmt.Errorf("wait for the exec stop: %w", err)
	}
	if !st.Stopped() {
		return fmt.Errorf("traced child did not stop: %v", st)
	}
	for i := range 16 {
		if err := syscall.PtraceSingleStep(pid); err != nil {
			return fmt.Errorf("PTRACE_SINGLESTEP %d: %w", i, err)
		}
		if _, err := syscall.Wait4(pid, &st, 0, nil); err != nil {
			return fmt.Errorf("wait for step %d: %w", i, err)
		}
		if !st.Stopped() || st.StopSignal() != syscall.SIGTRAP {
			return fmt.Errorf("step %d ended with %v", i, st)
		}
	}
	return nil
}

// sockFilter and sockFprog are the classic BPF program types of seccomp.
type sockFilter struct {
	code uint16
	jt   uint8
	jf   uint8
	k    uint32
}

type sockFprog struct {
	len    uint16
	filter *sockFilter
}

// installFilter installs a filter that returns action for getppid and allows
// every other system call. It sets no_new_privs first, as an unprivileged
// process must.
func installFilter(flags uintptr, action uint32) (uintptr, error) {
	const (
		bpfLdW    = 0x20 // BPF_LD | BPF_W | BPF_ABS
		bpfJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K
		bpfRetK   = 0x06 // BPF_RET | BPF_K
		nrOffset  = 0    // offsetof(struct seccomp_data, nr)
		retAllow  = 0x7fff0000
		seccompOp = 1 // SECCOMP_SET_MODE_FILTER
	)
	prog := []sockFilter{
		{code: bpfLdW, k: nrOffset},
		{code: bpfJeqK, jt: 0, jf: 1, k: uint32(unix.SYS_GETPPID)},
		{code: bpfRetK, k: action},
		{code: bpfRetK, k: retAllow},
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return 0, fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	fprog := sockFprog{len: uint16(len(prog)), filter: &prog[0]}
	r, _, errno := syscall.RawSyscall(unix.SYS_SECCOMP, seccompOp, flags, uintptr(unsafe.Pointer(&fprog)))
	runtime.KeepAlive(prog)
	if errno != 0 {
		return 0, fmt.Errorf("seccomp(SET_MODE_FILTER, %#x): %w", flags, errno)
	}
	return r, nil
}

// installTrapFilter installs SECCOMP_RET_TRAP for getppid and calls getppid.
// The Go runtime handles SIGSYS, so the child restores the default action
// first. The kernel then kills this process by SIGSYS, which the parent
// observes.
func installTrapFilter() error {
	runtime.LockOSThread()
	// struct kernel_sigaction of arm64 and amd64: handler, flags, restorer,
	// and mask. A zero handler is SIG_DFL.
	var dfl [4]uint64
	if _, _, errno := syscall.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(syscall.SIGSYS), uintptr(unsafe.Pointer(&dfl)), 0, 8, 0, 0); errno != 0 {
		return fmt.Errorf("rt_sigaction(SIGSYS, SIG_DFL): %w", errno)
	}
	if _, err := installFilter(unix.SECCOMP_FILTER_FLAG_TSYNC, unix.SECCOMP_RET_TRAP); err != nil {
		return err
	}
	syscall.RawSyscall(unix.SYS_GETPPID, 0, 0, 0)
	return errors.New("getppid returned under SECCOMP_RET_TRAP")
}

// installListener installs a filter with a user notification listener, as the
// systrap engine does for each stub thread.
func installListener() error {
	fd, err := installFilter(unix.SECCOMP_FILTER_FLAG_NEW_LISTENER, unix.SECCOMP_RET_USER_NOTIF)
	if err != nil {
		return err
	}
	return unix.Close(int(fd))
}
