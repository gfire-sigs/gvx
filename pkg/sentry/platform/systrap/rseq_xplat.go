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

package systrap

import (
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/platform/systrap/rseqarea"
)

// rseqFlagUnregister is RSEQ_FLAG_UNREGISTER of linux/rseq.h.
const rseqFlagUnregister = 1

// createStubWithoutRseq is createStub for a thread without an rseq area.
//
// In a cgo build, the C library registers an rseq area for each thread, and a
// forked stub inherits the area of the forking thread. The stub unmaps the
// memory of the Sentry, which holds the area. The kernel then sends SIGSEGV on
// each return to user mode, so the platform never started. This function
// unregisters the area of the calling thread for the fork and registers it
// again after the fork. The stubs that the first stub clones inherit no area.
//
// Precondition: the runtime OS thread must be locked.
func createStubWithoutRseq() (*thread, error) {
	area, size := rseqarea.Thread()
	if size == 0 {
		return createStub()
	}
	n, errno := unregisterRseq(area, size)
	if errno != 0 {
		return nil, fmt.Errorf("unregister the rseq area of the thread: %w", errno)
	}
	t, err := createStub()
	if _, _, errno := unix.RawSyscall6(unix.SYS_RSEQ, area, n, 0, rseqSig, 0, 0); errno != 0 {
		// The C library reads a CPU number of -1 from an unregistered area,
		// and it then asks the kernel for the number.
		log.Warningf("systrap: register the rseq area of the thread again: %v", errno)
	}
	return t, err
}

// unregisterRseq unregisters the rseq area of the calling thread and returns
// the length of its registration. size is the feature size that the C library
// exports (__rseq_size). The kernel unregisters an area only with the length
// of its registration, which can be larger: glibc 2.40 exports 20 and
// registers 32. So the call tries the feature size and then each multiple of
// 32 up to 256. The kernel answers a wrong length with EINVAL.
func unregisterRseq(area uintptr, size uint32) (uintptr, unix.Errno) {
	n := uintptr(size)
	for {
		_, _, errno := unix.RawSyscall6(unix.SYS_RSEQ, area, n, rseqFlagUnregister, rseqSig, 0, 0)
		if errno != unix.EINVAL {
			return n, errno
		}
		if n = (n/32 + 1) * 32; n > 256 {
			return 0, errno
		}
	}
}
