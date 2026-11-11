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
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const (
	landlockABIV1AccessFS = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM

	landlockDirReadAccessFS = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR

	landlockDirWriteAccessFS = landlockDirReadAccessFS |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
		unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
		unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM |
		unix.LANDLOCK_ACCESS_FS_REFER |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE

	landlockFileReadAccessFS = unix.LANDLOCK_ACCESS_FS_EXECUTE |
		unix.LANDLOCK_ACCESS_FS_READ_FILE

	landlockFileWriteAccessFS = landlockFileReadAccessFS |
		unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE
)

// landlockRulesetAttrFS holds only handled_access_fs (8 bytes). Kernels on
// every Landlock ABI version from v1 upward accept an 8-byte ruleset header.
type landlockRulesetAttrFS struct {
	handledAccessFS uint64
}

// landlockHandledAccessFS returns the filesystem access mask that the running
// Landlock ABI supports.
func landlockHandledAccessFS(abi int) uint64 {
	if abi < 1 {
		return 0
	}
	access := uint64(landlockABIV1AccessFS)
	if abi >= 2 {
		access |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		access |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		access |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return access
}

// landlockMountAccessFS returns the Landlock access rights for one host mount,
// masked to handled. A file mount receives only file-applicable bits so the
// kernel accepts the rule on a regular-file descriptor.
func landlockMountAccessFS(handled uint64, readOnly, isFile bool) uint64 {
	if isFile {
		if readOnly {
			return landlockFileReadAccessFS & handled
		}
		return landlockFileWriteAccessFS & handled
	}
	if readOnly {
		return landlockDirReadAccessFS & handled
	}
	return landlockDirWriteAccessFS & handled
}

// applyLandlock confines filesystem path lookups to mounts before seccomp
// blocks the Landlock system calls. It returns the symlink-resolved mount
// paths in order.
func applyLandlock(mounts []HostMount) ([]string, error) {
	mountsReal := make([]string, 0, len(mounts))
	for _, m := range mounts {
		_, real, err := resolveMountPath(m.Path)
		if err != nil {
			return nil, err
		}
		mountsReal = append(mountsReal, real)
	}

	// The untrusted_app seccomp policy of Android Zygote sends SIGSYS on
	// Landlock calls. Android confines the app with SELinux and mount
	// namespaces instead.
	if runtime.GOOS == "android" {
		return mountsReal, nil
	}

	abiRaw, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
	)
	if errno == unix.ENOSYS || errno == unix.EOPNOTSUPP {
		if len(mounts) == 0 {
			return mountsReal, nil
		}
		return nil, fmt.Errorf("%w: Linux host mounts require Landlock LSM: %w", ErrUnsupported, errno)
	}
	if errno != 0 {
		return nil, fmt.Errorf("hostlockdown: query Landlock ABI version: %w", errno)
	}

	handled := landlockHandledAccessFS(int(abiRaw))
	if handled == 0 {
		return nil, fmt.Errorf("hostlockdown: unsupported Landlock ABI version %d", int(abiRaw))
	}

	attr := landlockRulesetAttrFS{handledAccessFS: handled}
	fdRaw, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	runtime.KeepAlive(&attr)
	if errno != 0 {
		return nil, fmt.Errorf("hostlockdown: create Landlock ruleset: %w", errno)
	}
	rulesetFD := int(fdRaw)
	defer unix.Close(rulesetFD)

	for i, m := range mounts {
		if err := addLandlockMountRule(rulesetFD, mountsReal[i], handled, m.ReadOnly, m.File); err != nil {
			return nil, err
		}
	}

	if err := restrictProcessLandlock(rulesetFD); err != nil {
		return nil, err
	}
	return mountsReal, nil
}

func addLandlockMountRule(rulesetFD int, realPath string, handled uint64, readOnly, isFile bool) error {
	openFlags := unix.O_PATH | unix.O_CLOEXEC
	if !isFile {
		openFlags |= unix.O_DIRECTORY
	}
	pathFD, err := unix.Open(realPath, openFlags, 0)
	if err != nil {
		return fmt.Errorf("hostlockdown: open mount %q for Landlock: %w", realPath, err)
	}
	defer unix.Close(pathFD)

	rule := unix.LandlockPathBeneathAttr{
		Allowed_access: landlockMountAccessFS(handled, readOnly, isFile),
		Parent_fd:      int32(pathFD),
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_ADD_RULE,
		uintptr(rulesetFD),
		unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&rule)),
		0,
		0,
		0,
	)
	runtime.KeepAlive(&rule)
	if errno != 0 {
		return fmt.Errorf("hostlockdown: add Landlock rule for %q: %w", realPath, errno)
	}
	return nil
}

// restrictProcessLandlock applies rulesetFD to every OS thread in the process.
// It tries LANDLOCK_RESTRICT_SELF_TSYNC first and falls back to AllThreadsSyscall.
// Under cgo on kernels older than Linux 6.16, it signals every task in /proc/self/task.
func restrictProcessLandlock(rulesetFD int) error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("hostlockdown: set PR_SET_NO_NEW_PRIVS: %w", err)
	}
	_, _, errno := unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(rulesetFD),
		unix.LANDLOCK_RESTRICT_SELF_TSYNC,
		0,
	)
	if errno == 0 {
		return nil
	}
	if errno != unix.EINVAL {
		return fmt.Errorf("hostlockdown: restrict process with Landlock TSYNC: %w", errno)
	}

	if _, _, allErr := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_SET_NO_NEW_PRIVS, 1, 0); allErr == 0 {
		if _, _, rErr := syscall.AllThreadsSyscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), 0, 0); rErr != 0 {
			return fmt.Errorf("hostlockdown: restrict threads with Landlock: %w", rErr)
		}
		return nil
	} else if allErr != unix.ENOTSUP {
		return fmt.Errorf("hostlockdown: set PR_SET_NO_NEW_PRIVS on threads: %w", allErr)
	}

	return restrictCgoThreadsLandlock(rulesetFD)
}
