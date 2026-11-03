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
	"os"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// pcCaseSensitive is _PC_CASE_SENSITIVE from XNU <sys/unistd.h>. The value is
// not exported by x/sys. fpathconf returns 0 on a case-insensitive volume.
const pcCaseSensitive = 11

// probeCaseInsensitive reports whether the volume holding the workspace folds
// name case. The default APFS volume does. hostfs must then reject lookups
// whose case differs from the stored name.
func probeCaseInsensitive(dir *os.File) (bool, error) {
	var sensitive int
	if err := withFileFD(dir, func(fd int) error {
		var err error
		sensitive, err = unix.Fpathconf(fd, pcCaseSensitive)
		return err
	}); err != nil {
		return false, err
	}
	return sensitive == 0, nil
}

// lstatatInfo reads the metadata of name inside the directory dirfd without
// following a link.
func lstatatInfo(dirfd int, name string) (hostInfo, error) {
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstatat(dirfd, name, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return hostInfo{}, err
	}
	return statToHostInfo(&st), nil
}

// fstatInfo reads the metadata of the open descriptor fd.
func fstatInfo(fd int) (hostInfo, error) {
	var st unix.Stat_t
	if err := retryEINTR(func() error { return unix.Fstat(fd, &st) }); err != nil {
		return hostInfo{}, err
	}
	return statToHostInfo(&st), nil
}

// statToHostInfo converts a stat result. The identity is the device and the
// inode number, without the birth time: APFS lowers the birth time of a file
// when a process sets an earlier modification time, as tar, cp -p, and git
// do, so the birth time would give the file a new identity. APFS never reuses
// an inode number, and HFS+ reuses one only after its 32-bit counter wraps. A
// zero birth time marks a volume that keeps none, which keeps no trustworthy
// inode numbers either.
func statToHostInfo(st *unix.Stat_t) hostInfo {
	btime := int64(st.Btim.Sec)*int64(time.Second) + int64(st.Btim.Nsec)
	return hostInfo{
		kind:   hostKindOfMode(st.Mode),
		id:     hostID{dev: uint64(st.Dev), ino: uint64(st.Ino)},
		fid:    fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)},
		fidOK:  btime != 0,
		size:   st.Size,
		blocks: st.Blocks,
		nlink:  uint32(st.Nlink),
		perm:   st.Mode & 0o7777,
		atime:  time.Unix(int64(st.Atim.Sec), int64(st.Atim.Nsec)),
		mtime:  time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)),
		ctime:  time.Unix(int64(st.Ctim.Sec), int64(st.Ctim.Nsec)),
		btime:  time.Unix(int64(st.Btim.Sec), int64(st.Btim.Nsec)),
	}
}
