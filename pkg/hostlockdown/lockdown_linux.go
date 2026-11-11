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
	"runtime"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// probeExecPath names a file that does not exist. A filter that rejects
// execve returns EPERM before the kernel looks at the path. Without a filter
// the call returns ENOENT and starts nothing.
const probeExecPath = "/gvx-lockdown-probe/does-not-exist"

// applyOSLockdown applies Landlock path containment, installs the seccomp
// filter of the embedder, and observes that both boundaries hold. Landlock
// runs before Options.InstallSyscallFilter so the Landlock system calls remain
// outside the post-lockdown seccomp allowlist.
func applyOSLockdown(opts Options) (Status, error) {
	if opts.InstallSyscallFilter == nil {
		return Status{}, errors.New("hostlockdown: the Linux lockdown needs Options.InstallSyscallFilter")
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// The root descriptor lets the open probe walk paths below "/" through a
	// directory descriptor. Open it before Landlock and seccomp restrict opens.
	root, err := unix.Open("/", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return Status{}, fmt.Errorf("hostlockdown: open the root directory for the probes: %w", err)
	}
	defer unix.Close(root)

	mountsReal, err := applyLandlock(opts.Mounts)
	if err != nil {
		return Status{}, err
	}

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

	cwdBlocked, err := probeOpen(unix.AT_FDCWD, "/")
	if err != nil {
		return st, err
	}
	if !cwdBlocked {
		return st, errors.New("hostlockdown: the filter allows an open relative to the working directory")
	}
	dirfdBlocked, err := probeRootOpenBlocked(root, mountsReal)
	if err != nil {
		return st, err
	}
	if !dirfdBlocked && (runtime.GOOS != "android" || len(opts.Mounts) == 0) {
		return st, errors.New("hostlockdown: descriptor-relative open outside Options.Mounts succeeded after lockdown")
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

// probeRootOpenBlocked verifies that descriptor-relative opens outside
// mountsReal fail with EPERM or EACCES. Probing "." on root works even in an
// initramfs that lacks /etc/passwd, and validateMounts forbids mounting "/".
func probeRootOpenBlocked(root int, mountsReal []string) (bool, error) {
	rootBlocked, err := probeOpenFlags(root, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
	if err != nil || !rootBlocked {
		return false, err
	}
	if outsideAll("/etc/passwd", mountsReal) {
		fd, openErr := unix.Openat(root, "etc/passwd", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		switch {
		case openErr == nil:
			_ = unix.Close(fd)
			return false, nil
		case errors.Is(openErr, unix.EPERM), errors.Is(openErr, unix.EACCES), errors.Is(openErr, unix.ENOENT):
		default:
			return false, fmt.Errorf("hostlockdown: root openat probe for etc/passwd returned %w, want EPERM or EACCES", openErr)
		}
	}
	return true, nil
}

// probeOpen reports whether the kernel rejects opening path below dirfd with
// EPERM (seccomp) or EACCES (Landlock). A success closes the descriptor at once.
func probeOpen(dirfd int, path string) (blocked bool, err error) {
	return probeOpenFlags(dirfd, path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC)
}

func probeOpenFlags(dirfd int, path string, flags int) (blocked bool, err error) {
	fd, err := unix.Openat(dirfd, path, flags, 0)
	switch {
	case err == nil:
		_ = unix.Close(fd)
		return false, nil
	case errors.Is(err, unix.EPERM), errors.Is(err, unix.EACCES):
		return true, nil
	default:
		return false, fmt.Errorf("hostlockdown: openat probe for %q returned %w, want EPERM or EACCES", path, err)
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
