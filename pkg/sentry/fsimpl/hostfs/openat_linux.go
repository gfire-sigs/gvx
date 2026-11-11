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

package hostfs

import (
	"errors"
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// hostOpenat opens name beneath dirfd using openat2 with RESOLVE_BENEATH and
// RESOLVE_NO_SYMLINKS. It falls back to single-component O_NOFOLLOW openat on
// Android (where the Zygote seccomp filter traps openat2) and on kernels that
// return ENOSYS for openat2.
func hostOpenat(dirfd int, name string, flags int, perm uint32) (int, error) {
	if runtime.GOOS != "android" {
		var mode uint64
		if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
			mode = uint64(perm) & 0o7777
		}
		how := unix.OpenHow{
			Flags:   uint64(uint32(flags)) | unix.O_LARGEFILE,
			Mode:    mode,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS,
		}
		var fd int
		var err error
		for range 32 {
			fd, err = unix.Openat2(dirfd, name, &how)
			if !errors.Is(err, unix.EAGAIN) {
				break
			}
		}
		switch {
		case errors.Is(err, unix.ENOSYS):
			// Fall through to single-component O_NOFOLLOW openat.
		case errors.Is(err, unix.EXDEV):
			return -1, ErrPathTraversal
		default:
			return fd, err
		}
	}
	return unix.Openat(dirfd, name, flags, perm)
}
