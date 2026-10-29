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

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// osNativeGrow allocates the range [off, off+n) with fallocate in mode 0.
// Mode 0 also moves the size of the file to off+n.
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

// nativeUnsupported reports whether err means that the host volume does not
// support preallocation.
func nativeUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOSYS)
}
