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

//go:build linux || darwin

package hoststorage

import (
	"os"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func openStorageDir(dir *os.File, name string, create bool, perm os.FileMode) (*os.File, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := openStorageAtSetup(dir.Fd(), name, flags, 0)
	if err == unix.ENOENT && create {
		if err = unix.Mkdirat(int(dir.Fd()), name, uint32(perm.Perm())); err == nil || err == unix.EEXIST {
			fd, err = openStorageAtSetup(dir.Fd(), name, flags, 0)
		}
	}
	if err != nil {
		return nil, &os.PathError{Op: "open directory", Path: name, Err: err}
	}
	return os.NewFile(fd, name), nil
}

func storageParent(dir *os.File) (*os.File, error) {
	for {
		fd, err := unix.Openat(int(dir.Fd()), "..", ancestryOpenFlags|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return nil, err
		}
		return os.NewFile(uintptr(fd), ".."), nil
	}
}
