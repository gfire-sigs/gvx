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

// Package hostlockdown applies irreversible host OS self-containment to the
// current process after all required host handles are open. Windows uses a
// restricted token, Low integrity, a job object and no win32k. macOS uses a
// Seatbelt profile and RLIMIT_NPROC=0. A host mount is a directory or one
// regular file.
package hostlockdown

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// ErrUnsupported reports that the host OS has no lockdown implementation.
// Apply never returns a success Status when it enforces nothing.
var ErrUnsupported = errors.New("hostlockdown: unsupported host OS")

// ErrNotLockedDown reports that BindThread ran before a successful Apply.
var ErrNotLockedDown = errors.New("hostlockdown: Apply has not succeeded")

// HostMount names one host directory or one host regular file that the locked
// process may open. A directory mount allows every file below the directory.
// A file mount allows that one file only. The parent directory and the
// sibling files of a file mount stay closed by path.
type HostMount struct {
	// Path is the host directory, or the host file when File is true. It must
	// exist when Apply runs. The root of a file system, such as "/" or "C:\",
	// is refused.
	Path string

	// ReadOnly limits the locked process to read access to Path and, for a
	// directory mount, to everything below it.
	ReadOnly bool

	// File marks Path as one regular file. Apply refuses the mount when Path
	// is not a regular file. A symbolic link to a regular file is allowed.
	// The lockdown does not allow access to the parent directory by path.
	File bool
}

// Options configures the host OS lockdown boundary.
type Options struct {
	// Mounts lists the host directories and files that the locked process
	// may open. Duplicate and nested entries are allowed. A file mount below
	// a directory mount is allowed. The lockdown only adds allow rules, so a
	// path is writable when any entry that covers it is writable.
	Mounts []HostMount

	// AllowOutboundNet permits new outbound TCP and UDP connections and accept
	// on pre-bound listeners when Track A (-net=nat) is active. Apply
	// blocks all outbound traffic when AllowOutboundNet is false and
	// OutboundUDPPorts is empty.
	AllowOutboundNet bool

	// OutboundUDPPorts lists remote UDP ports that pre-bound UDP sockets may
	// send to and receive from. The -net=wg backend sets the WireGuard peer
	// port here. Seatbelt can match remote ports but not remote addresses.
	// Ignored when AllowOutboundNet is true.
	OutboundUDPPorts []uint16

	// CPUQuotaMillis caps the CPU time of the process, in thousandths of a CPU.
	// Zero means no cap. Only Windows enforces it, with a hard cap on the
	// containment job. Status.CPUQuotaEnforced reports whether Apply did.
	CPUQuotaMillis int64

	// TTYPath names the pre-opened host terminal device node (such as
	// "/dev/ttys001") that the locked process configures with ioctl to enter
	// and restore raw terminal mode. macOS grants file-ioctl on that literal
	// path without granting file-read or file-write.
	TTYPath string

	// InstallSyscallFilter installs the seccomp program of the embedder. Only
	// Linux uses it, and Apply fails there when it is nil. The caller builds the
	// program, because the allowlist depends on the Sentry platform, which this
	// package must not import. The function must install the program on every
	// thread of the process.
	InstallSyscallFilter func() error
}

// Status reports the containment primitives enforced by Apply. Apply sets a
// field only after the OS call succeeded. It also observes the effect with a
// self-probe in the locked process or by reading the OS state back.
type Status struct {
	Applied bool

	// SubprocessBlocked reports that the kernel rejects new child processes.
	// macOS: a spawn probe failed. Windows: the process belongs to a job
	// with an active process limit of one.
	SubprocessBlocked bool

	// UnboundFileOpenBlocked reports that opens outside every mount fail.
	// macOS: probe opens failed in the whole process. Windows: probe opens
	// failed on a thread that holds the restricted token, so only threads
	// that call BindThread have this property. Linux: the seccomp filter
	// rejects every open when no mount exists. With a mount, the filter
	// rejects opens relative to the working directory but must allow opens
	// relative to a directory descriptor, and seccomp cannot read the path. An
	// absolute path opened through such a descriptor still reaches the host
	// root, so the field stays false.
	UnboundFileOpenBlocked bool

	// CPUQuotaEnforced reports that the OS caps the CPU time of the process at
	// Options.CPUQuotaMillis. It is false when the option is zero and on a host
	// OS that has no such cap. Windows reads the cap back from the job.
	CPUQuotaEnforced bool

	// IntegrityDowngraded reports a Low integrity primary token. Windows only.
	IntegrityDowngraded bool

	// Win32kBlocked reports that win32k system calls are disabled. Windows only.
	Win32kBlocked bool

	// NetworkOutboundBlocked reports that a self-probe observed a rejected
	// outbound TCP connect. Apply leaves it false when the options allow
	// outbound traffic.
	NetworkOutboundBlocked bool

	SeatbeltProfile string
}

var (
	lockdownMu     sync.Mutex
	lockedDownFlag atomic.Bool
	lastStatus     Status
)

// Apply locks down the current host process using OS-native containment
// primitives. Apply is idempotent within a process.
//
// Apply returns an error when any required primitive fails to install or when
// a self-probe shows that the primitive does not hold. After an error the
// process can be partly locked and the caller must stop using it.
//
// Precondition: Open all hypervisor handles, cached .erofs layer descriptors,
// network listeners/sockets, and the os.Root handle of every host mount before
// calling Apply.
func Apply(opts Options) (Status, error) {
	lockdownMu.Lock()
	defer lockdownMu.Unlock()
	if lockedDownFlag.Load() {
		return lastStatus, nil
	}
	for _, port := range opts.OutboundUDPPorts {
		if port == 0 {
			return Status{}, errors.New("hostlockdown: OutboundUDPPorts contains port 0")
		}
	}
	if err := validateMounts(opts.Mounts); err != nil {
		return Status{}, err
	}
	st, err := applyOSLockdown(opts)
	if err != nil {
		return st, err
	}
	st.Applied = true
	lastStatus = st
	lockedDownFlag.Store(true)
	return st, nil
}

// validateMounts refuses an empty path and the root of a file system. A root
// mount would allow every host file. It also refuses a file mount whose path
// is missing or is not a regular file.
func validateMounts(mounts []HostMount) error {
	for i, m := range mounts {
		if m.Path == "" {
			return fmt.Errorf("hostlockdown: mount %d has an empty path", i)
		}
		abs, err := filepath.Abs(m.Path)
		if err != nil {
			return fmt.Errorf("hostlockdown: resolve mount %q: %w", m.Path, err)
		}
		if filepath.Dir(abs) == abs {
			return fmt.Errorf("hostlockdown: mount %q is the root of a file system and would allow every host file", m.Path)
		}
		if !m.File {
			continue
		}
		info, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("hostlockdown: stat file mount %q: %w", m.Path, err)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("hostlockdown: file mount %q is not a regular file", m.Path)
		}
	}
	return nil
}

// IsLockedDown reports whether Apply has succeeded in the current process.
func IsLockedDown() bool {
	return lockedDownFlag.Load()
}

// jobCPURate converts a CPU quota in thousandths of a CPU into the CpuRate of a
// Windows job object: hundredths of a percent of the total CPU time of the
// host, from 1 to 10000. A quota above the host capacity gives 10000.
func jobCPURate(quotaMillis int64, hostCPUs int) uint32 {
	hostCPUs = max(1, hostCPUs)
	rate := quotaMillis * 10000 / (int64(hostCPUs) * 1000)
	return uint32(min(10000, max(1, rate)))
}
