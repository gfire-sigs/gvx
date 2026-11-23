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
	"runtime"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const ancestryOpenFlags = unix.O_PATH

// OpenIsolatedAt opens below dir without following links or crossing mounts.
func OpenIsolatedAt(dir uintptr, name string, flags int, perm uint32) (uintptr, error) {
	if runtime.GOOS == "android" {
		// The Android application seccomp filter traps openat2.
		return 0, ErrUnsupported
	}
	var mode uint64
	if flags&unix.O_CREAT != 0 || flags&unix.O_TMPFILE == unix.O_TMPFILE {
		mode = uint64(perm) & 0o7777
	}
	how := unix.OpenHow{
		Flags:   uint64(uint32(flags)) | unix.O_LARGEFILE,
		Mode:    mode,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_XDEV,
	}
	for {
		fd, err := unix.Openat2(int(dir), name, &how)
		if err != unix.EINTR {
			return uintptr(fd), err
		}
	}
}

func openStorageFile(dir *os.File, name string, flags int, perm os.FileMode) (*os.File, error) {
	fd, err := openStorageAtSetup(dir.Fd(), name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, uint32(perm.Perm()))
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(fd, name), nil
}

func openStorageAtSetup(dir uintptr, name string, flags int, perm uint32) (uintptr, error) {
	if runtime.GOOS != "android" {
		return OpenIsolatedAt(dir, name, flags, perm)
	}
	// Android setup opens only direct children with O_NOFOLLOW. The caller
	// verifies mount identity on the returned descriptor before any I/O.
	for {
		fd, err := unix.Openat(int(dir), name, flags, perm)
		if err != unix.EINTR {
			return uintptr(fd), err
		}
	}
}

func storageFileIdentity(f *os.File) (StorageIdentity, error) {
	return statStorage(int(f.Fd()), "", unix.AT_EMPTY_PATH, false)
}

func statStorageFile(dir *os.File, name string) (StorageIdentity, error) {
	return statStorage(int(dir.Fd()), name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT, true)
}

func statStorage(dir int, name string, flags int, regular bool) (StorageIdentity, error) {
	var st unix.Statx_t
	const mask = unix.STATX_MNT_ID | unix.STATX_INO | unix.STATX_NLINK | unix.STATX_TYPE
	if err := unix.Statx(dir, name, flags, mask, &st); err != nil {
		return StorageIdentity{}, err
	}
	if st.Mask&mask != mask {
		return StorageIdentity{}, ErrUnsupported
	}
	if regular && st.Mode&unix.S_IFMT != unix.S_IFREG {
		return StorageIdentity{}, os.ErrInvalid
	}
	return StorageIdentity{
		Volume: uint64(st.Dev_major)<<32 | uint64(st.Dev_minor),
		Mount:  st.Mnt_id,
		File:   [2]uint64{st.Ino},
		Links:  st.Nlink,
	}, nil
}

func storageVolumesDisjoint(a, b *os.File) bool {
	var left, right unix.Statfs_t
	return unix.Fstatfs(int(a.Fd()), &left) == nil &&
		unix.Fstatfs(int(b.Fd()), &right) == nil &&
		directStorageFilesystem(left.Type) && directStorageFilesystem(right.Type) &&
		left.Fsid != (unix.Fsid{}) && right.Fsid != (unix.Fsid{}) && left.Fsid != right.Fsid
}

func directStorageFilesystem(magic int64) bool {
	switch magic {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC:
		return true
	}
	return false
}
