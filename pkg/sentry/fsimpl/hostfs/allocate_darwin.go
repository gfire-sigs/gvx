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

package hostfs

import (
	"errors"
	"fmt"
	"os"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// allocateNative serves a fallocate request on macOS.
//
// Mode 0 and KEEP_SIZE reserve space with fcntl(F_PREALLOCATE) behind the
// physical end of the file. Mode 0 then moves the size of the file with
// ftruncate, because F_PREALLOCATE never changes the size. A punch uses
// F_PUNCHHOLE for the part of the range that covers whole host pages, and it
// writes zeros over the unaligned pieces at the ends of the range. A volume
// that refuses F_PUNCHHOLE gets zeros over the whole range.
func allocateNative(f *os.File, mode uint64, off, length int64) error {
	if err := withFileFD(f, func(fd int) error {
		if mode&linux.FALLOC_FL_PUNCH_HOLE != 0 {
			return punchHole(f, fd, mode, off, length)
		}
		return preallocate(fd, mode, off, length)
	}); err != nil {
		return fmt.Errorf("hostfs: fallocate: %w", err)
	}
	return nil
}

// preallocate reserves the space of [off, off+length) and grows the file for
// mode 0. A volume that cannot reserve space still grows the file, and the
// call then reports success for mode 0 only.
func preallocate(fd int, mode uint64, off, length int64) error {
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		return err
	}
	target := off + length
	if physical := st.Blocks * 512; target > physical {
		// Ask for contiguous space first. A fragmented volume gets a second
		// request without that flag. Both requests are all or nothing.
		err := fstore(fd, unix.F_ALLOCATECONTIG|unix.F_ALLOCATEALL, target-physical)
		if err != nil {
			err = fstore(fd, unix.F_ALLOCATEALL, target-physical)
		}
		if err != nil && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL) {
			return err
		}
	}
	if mode&linux.FALLOC_FL_KEEP_SIZE == 0 && target > st.Size {
		return retryEINTR(func() error { return unix.Ftruncate(fd, target) })
	}
	return nil
}

// fstore runs fcntl(F_PREALLOCATE) for n bytes from the physical end of the
// file.
func fstore(fd int, flags uint32, n int64) error {
	arg := unix.Fstore_t{Flags: flags, Posmode: unix.F_PEOFPOSMODE, Length: n}
	return retryEINTR(func() error { return unix.FcntlFstore(uintptr(fd), unix.F_PREALLOCATE, &arg) })
}

// punchHole removes the whole host pages inside [off, off+length) and writes
// zeros over the unaligned pieces. F_PUNCHHOLE needs page-aligned bounds, and
// a hole that covers part of a page would discard live neighbours.
func punchHole(f *os.File, fd int, mode uint64, off, length int64) error {
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		return err
	}
	end := min(off+length, st.Size)
	if off >= end {
		return nil
	}
	page := int64(unix.Getpagesize())
	lo := (off + page - 1) / page * page
	hi := end / page * page
	if lo >= hi {
		return zeroRange(f, off, end-off)
	}
	if err := unix.Fallocate(fd, uint32(mode), lo, hi-lo); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return zeroRange(f, off, end-off)
		}
		return err
	}
	if err := zeroRange(f, off, lo-off); err != nil {
		return err
	}
	return zeroRange(f, hi, end-hi)
}
