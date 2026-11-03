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
	"os"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// probeCaseInsensitive reports false: the Linux development build runs on
// case-sensitive file systems. It exists so that the package builds on Linux.
func probeCaseInsensitive(*os.File) (bool, error) {
	return false, nil
}

// statxMask asks for the fields of stat and the birth time. The kernel clears
// STATX_BTIME in the result when the file system keeps no birth time.
const statxMask = unix.STATX_BASIC_STATS | unix.STATX_BTIME

// lstatatInfo reads the metadata of name inside the directory dirfd without
// following a link. The flags are the only value that the seccomp rule of the
// host file system allows for a call that names a path.
func lstatatInfo(dirfd int, name string) (hostInfo, error) {
	return statxInfo(dirfd, name, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
}

// fstatInfo reads the metadata of the open descriptor fd. The base seccomp rule
// allows statx on a descriptor with AT_EMPTY_PATH and an empty name.
func fstatInfo(fd int) (hostInfo, error) {
	return statxInfo(fd, "", unix.AT_EMPTY_PATH)
}

func statxInfo(dirfd int, name string, flags int) (hostInfo, error) {
	var st unix.Statx_t
	if err := retryEINTR(func() error { return unix.Statx(dirfd, name, flags, statxMask, &st) }); err != nil {
		return hostInfo{}, err
	}
	return statxToHostInfo(&st), nil
}

// statxToHostInfo converts a statx result. The device number has the glibc
// layout, which equals st_dev.
func statxToHostInfo(st *unix.Statx_t) hostInfo {
	dev := unix.Mkdev(st.Dev_major, st.Dev_minor)
	ctime := time.Unix(st.Ctime.Sec, int64(st.Ctime.Nsec))
	btime := st.Btime.Sec*int64(time.Second) + int64(st.Btime.Nsec)
	fidOK := st.Mask&unix.STATX_BTIME != 0 && btime != 0
	info := hostInfo{
		kind:   hostKindOfMode(uint32(st.Mode)),
		id:     hostID{dev: dev, ino: st.Ino},
		fid:    fileKey{dev: dev, ino: st.Ino, btime: btime},
		fidOK:  fidOK,
		size:   int64(st.Size),
		blocks: int64(st.Blocks),
		nlink:  st.Nlink,
		perm:   uint32(st.Mode) & 0o7777,
		atime:  time.Unix(st.Atime.Sec, int64(st.Atime.Nsec)),
		mtime:  time.Unix(st.Mtime.Sec, int64(st.Mtime.Nsec)),
		ctime:  ctime,
		btime:  ctime,
	}
	if fidOK {
		info.btime = time.Unix(st.Btime.Sec, int64(st.Btime.Nsec))
	}
	return info
}
