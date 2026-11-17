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

package ext4lite

import (
	"errors"
	"os"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func platformPunchGranularity() int64 {
	return blockSize
}

// osNativeGrow allocates the range [off, off+n) with fallocate in mode 0.
// Mode 0 also moves the size of the file to off+n when off+n exceeds the size.
func osNativeGrow(f *os.File, off, n int64) error {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	for {
		err := unix.Fallocate(fd, 0, off, n)
		if !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// osNativeAllocateRange allocates physical blocks for [off, off+n) without
// shrinking the file.
func osNativeAllocateRange(f *os.File, off, n int64) error {
	return osNativeGrow(f, off, n)
}

// osNativePunch releases physical backing in [off, off+n) while keeping the
// file size unchanged.
func osNativePunch(f *os.File, off, n int64) (int64, int64, error) {
	fd := int(f.Fd())
	defer runtime.KeepAlive(f)
	var st unix.Stat_t
	for {
		err := unix.Fstat(fd, &st)
		if !errors.Is(err, unix.EINTR) {
			if err != nil {
				return 0, 0, err
			}
			break
		}
	}
	end := min(off+n, st.Size)
	if off >= end {
		return 0, 0, nil
	}
	length := end - off
	for {
		err := unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, off, length)
		if !errors.Is(err, unix.EINTR) {
			if err != nil {
				return 0, 0, err
			}
			return off, length, nil
		}
	}
}

// nativeUnsupported reports whether err means that the host volume does not
// support preallocation.
func nativeUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS)
}

func punchUnsupported(err error) bool {
	return nativeUnsupported(err)
}
