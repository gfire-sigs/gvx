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

//go:build darwin

package ext4lite

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// osNativeGrow allocates n bytes behind the physical end of the file with
// fcntl(F_PREALLOCATE) and then moves the size of the file to off+n with
// ftruncate. F_PREALLOCATE does not change the size of the file.
//
// The call asks for contiguous space first. A volume that is too fragmented
// for that gets a second request without the contiguous flag. The second
// request is all or nothing, so a failed grow does not leave partial space.
func osNativeGrow(f *os.File, off, n int64) error {
	fd := f.Fd()
	defer runtime.KeepAlive(f)

	err := preallocate(fd, unix.F_ALLOCATECONTIG|unix.F_ALLOCATEALL, n)
	if err != nil {
		err = preallocate(fd, unix.F_ALLOCATEALL, n)
	}
	if err != nil {
		return err
	}
	for {
		err := unix.Ftruncate(int(fd), off+n)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// preallocate runs fcntl(F_PREALLOCATE) for n bytes from the physical end of
// the file. The pointer conversion stays inside the call expression, so the
// fstore_t value cannot move while the call runs.
func preallocate(fd uintptr, flags uint32, n int64) error {
	fs := unix.Fstore_t{
		Flags:   flags,
		Posmode: unix.F_PEOFPOSMODE,
		Length:  n,
	}
	for {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, unix.F_PREALLOCATE, uintptr(unsafe.Pointer(&fs)))
		switch errno {
		case 0:
			return nil
		case syscall.EINTR:
			continue
		default:
			return errno
		}
	}
}

// nativeUnsupported reports whether err means that the host volume does not
// support preallocation.
func nativeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EINVAL)
}
