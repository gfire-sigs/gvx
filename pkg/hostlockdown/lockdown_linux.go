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

package hostlockdown

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// probeExecPath names a file that does not exist. A filter that rejects
// execve returns EPERM before the kernel looks at the path. Without a filter
// the call returns ENOENT and starts nothing.
const probeExecPath = "/gvx-lockdown-probe/does-not-exist"

// applyOSLockdown installs the seccomp filter of the embedder and observes
// that the filter holds. The filter follows the model of the gVisor Sentry:
// an allowlist of system calls, with every other call killing the process.
// The caller adds EPERM rules for the calls that this function probes, so that
// the probes do not kill the process.
func applyOSLockdown(opts Options) (Status, error) {
	if opts.InstallSyscallFilter == nil {
		return Status{}, errors.New("hostlockdown: the Linux lockdown needs Options.InstallSyscallFilter")
	}
	// The root descriptor lets the open probe walk an absolute path through a
	// directory descriptor. It must exist before the filter rejects opens.
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Status{}, fmt.Errorf("hostlockdown: open the root directory for the probes: %w", err)
	}
	defer unix.Close(root)

	if err := opts.InstallSyscallFilter(); err != nil {
		return Status{}, fmt.Errorf("hostlockdown: install the syscall filter: %w", err)
	}

	st := Status{}
	if err := probeExecBlocked(); err != nil {
		return st, err
	}
	if err := probeForkBlocked(); err != nil {
		return st, err
	}
	st.SubprocessBlocked = true

	cwdBlocked, err := probeOpen(unix.AT_FDCWD, "/etc/passwd")
	if err != nil {
		return st, err
	}
	if !cwdBlocked {
		return st, errors.New("hostlockdown: the filter allows an open relative to the working directory")
	}
	dirfdBlocked, err := probeOpen(root, "etc/passwd")
	if err != nil {
		return st, err
	}
	if !dirfdBlocked && len(opts.Mounts) == 0 {
		return st, errors.New("hostlockdown: the filter allows an open through a directory descriptor, and no mount needs it")
	}
	st.UnboundFileOpenBlocked = dirfdBlocked

	if !opts.AllowOutboundNet {
		if err := probeSocketBlocked(); err != nil {
			return st, err
		}
		st.NetworkOutboundBlocked = true
	}
	return st, nil
}

// probeExecBlocked proves that execve fails with EPERM. The path does not
// exist, so a missing filter cannot replace the process image.
func probeExecBlocked() error {
	path, err := unix.BytePtrFromString(probeExecPath)
	if err != nil {
		return err
	}
	_, _, errno := unix.Syscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), 0, 0)
	if errno != unix.EPERM {
		return fmt.Errorf("hostlockdown: the execve probe returned %v, want EPERM", errnoOrNone(errno))
	}
	atFDCWD := unix.AT_FDCWD
	_, _, errno = unix.Syscall6(unix.SYS_EXECVEAT, uintptr(atFDCWD), uintptr(unsafe.Pointer(path)), 0, 0, 0, 0)
	if errno != unix.EPERM {
		return fmt.Errorf("hostlockdown: the execveat probe returned %v, want EPERM", errnoOrNone(errno))
	}
	return nil
}

// probeForkBlocked proves that clone fails with EPERM for flags other than the
// thread flags of the Go runtime. The probe passes CLONE_THREAD without
// CLONE_SIGHAND. The kernel rejects that with EINVAL, so a missing filter
// creates no thread and no process.
func probeForkBlocked() error {
	_, _, errno := unix.RawSyscall6(unix.SYS_CLONE, unix.CLONE_THREAD, 0, 0, 0, 0, 0)
	if errno != unix.EPERM {
		return fmt.Errorf("hostlockdown: the clone probe returned %v, want EPERM", errnoOrNone(errno))
	}
	return nil
}

// probeOpen reports whether the filter rejects opening path below dirfd. An
// EPERM result means rejected. Any other failure means that the call reached
// the kernel path lookup. A success closes the descriptor at once.
func probeOpen(dirfd int, path string) (blocked bool, err error) {
	fd, err := unix.Openat(dirfd, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	switch {
	case err == nil:
		_ = unix.Close(fd)
		return false, nil
	case errors.Is(err, unix.EPERM):
		return true, nil
	default:
		return false, nil
	}
}

// probeSocketBlocked proves that a new TCP socket fails with EPERM.
func probeSocketBlocked() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_ = unix.Close(fd)
		return errors.New("hostlockdown: the socket probe created a TCP socket")
	}
	if !errors.Is(err, unix.EPERM) {
		return fmt.Errorf("hostlockdown: the socket probe returned %v, want EPERM", err)
	}
	return nil
}

func errnoOrNone(errno unix.Errno) error {
	if errno == 0 {
		return errors.New("success")
	}
	return errno
}
