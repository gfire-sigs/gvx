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

package hoststorage

import (
	"os"
	"strings"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const ancestryOpenFlags = unix.O_EVTONLY

// OpenIsolatedAt opens one component without crossing the directory's mount.
func OpenIsolatedAt(dir uintptr, name string, flags int, perm uint32) (uintptr, error) {
	if name == "" || name == ".." || strings.Contains(name, "/") {
		return 0, unix.EINVAL
	}
	// A truncation must use the descriptor after mount validation.
	if flags&unix.O_TRUNC != 0 {
		return 0, unix.EINVAL
	}
	var fd int
	for {
		var err error
		openFlags := flags
		if flags&unix.O_SYMLINK == 0 {
			openFlags |= unix.O_NOFOLLOW
		}
		fd, err = unix.Openat(int(dir), name, openFlags, perm)
		if err == unix.EINVAL && flags&unix.O_SYMLINK != 0 {
			fd, err = unix.Openat(int(dir), name, flags&^unix.O_SYMLINK|unix.O_NOFOLLOW, perm)
		}
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 0, err
		}
		break
	}
	var parent, child unix.Statfs_t
	err := unix.Fstatfs(int(dir), &parent)
	if err == nil {
		err = unix.Fstatfs(fd, &child)
	}
	if err == nil && (parent.Fsid != child.Fsid || parent.Mntonname != child.Mntonname || parent.Flags&unix.MNT_LOCAL == 0) {
		err = unix.EXDEV
	}
	if err != nil {
		_ = unix.Close(fd)
		return 0, err
	}
	return uintptr(fd), nil
}

func openStorageAtSetup(dir uintptr, name string, flags int, perm uint32) (uintptr, error) {
	return OpenIsolatedAt(dir, name, flags, perm)
}

func openStorageFile(dir *os.File, name string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := OpenIsolatedAt(dir.Fd(), name, flags|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(fd, name), nil
}

func statStorageFile(dir *os.File, name string) (StorageIdentity, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return StorageIdentity{}, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return StorageIdentity{}, os.ErrInvalid
	}
	id, err := IdentifyStorage(dir)
	if err != nil {
		return StorageIdentity{}, err
	}
	if id.Volume != uint64(uint32(st.Dev)) {
		return StorageIdentity{}, unix.EXDEV
	}
	id.File = [2]uint64{st.Ino}
	id.Links = uint32(st.Nlink)
	return id, nil
}

func storageFileIdentity(f *os.File) (StorageIdentity, error) {
	var st unix.Stat_t
	fd := int(f.Fd())
	if err := unix.Fstat(fd, &st); err != nil {
		return StorageIdentity{}, err
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return StorageIdentity{}, err
	}
	if fs.Flags&unix.MNT_LOCAL == 0 {
		return StorageIdentity{}, ErrUnsupported
	}
	return StorageIdentity{
		Volume: uint64(uint32(st.Dev)),
		Mount:  uint64(uint32(fs.Fsid.Val[0]))<<32 | uint64(uint32(fs.Fsid.Val[1])),
		File:   [2]uint64{st.Ino},
		Links:  uint32(st.Nlink),
	}, nil
}

// Local Darwin devices have distinct vnode and mount identities.
func storageVolumesDisjoint(_, _ *os.File) bool {
	return true
}
