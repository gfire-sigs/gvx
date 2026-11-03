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
	"sync"
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

// volumeTrust decides which devices below the workspace root give their files
// identities that hostfs can key records on. The probe in volumeIDsTrusted
// admits the volume of the root only. A guest can mount another file system
// inside the workspace, such as a FAT or network volume, and its inode numbers
// can repeat or move. An entry of another device keeps its identity only when
// the file system of that device is APFS. Any other entry gets path records,
// as an entry without an identity does.
type volumeTrust struct {
	rootDev uint64
	// fsType returns the file system type name of the volume behind fd.
	fsType func(fd int) (string, error)

	mu sync.Mutex
	// apfs holds the verdict for each other device that a call proved. A call
	// that failed leaves no verdict, so the next one asks again. The device
	// number of a volume that the host unmounted and mounted again stays
	// valid for the verdict, because the kernel gives a mount a new number.
	apfs map[uint64]bool
}

func newVolumeTrust(root *os.File) (*volumeTrust, error) {
	var info hostInfo
	if err := withFileFD(root, func(fd int) error {
		var err error
		info, err = fstatInfo(fd)
		return err
	}); err != nil {
		return nil, err
	}
	return &volumeTrust{rootDev: info.id.dev, fsType: fsTypeOfFD, apfs: make(map[uint64]bool)}, nil
}

// fsTypeOfFD returns the file system type name of the volume behind fd.
func fsTypeOfFD(fd int) (string, error) {
	var st unix.Statfs_t
	if err := retryEINTR(func() error { return unix.Fstatfs(fd, &st) }); err != nil {
		return "", err
	}
	name := make([]byte, 0, len(st.Fstypename))
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return string(name), nil
}

// known returns the verdict for dev when one exists. The device of the root is
// always trusted.
func (v *volumeTrust) known(dev uint64) (trusted, ok bool) {
	if dev == v.rootDev {
		return true, true
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	trusted, ok = v.apfs[dev]
	return trusted, ok
}

// trusts reports whether the entries of the device dev keep their identity.
// fd is a descriptor on that volume, or negative when the caller has none. A
// call without a verdict and without a descriptor, or with an error from
// fstatfs, distrusts the device for this call only.
func (v *volumeTrust) trusts(dev uint64, fd int) bool {
	if trusted, ok := v.known(dev); ok {
		return trusted
	}
	if fd < 0 {
		return false
	}
	typ, err := v.fsType(fd)
	if err != nil {
		return false
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.apfs[dev] = typ == "apfs"
	return v.apfs[dev]
}

// markVolumeFD drops the identity of info when the entry that fd names lives
// on a device that hostfs does not trust.
func (h *hostRoot) markVolumeFD(info hostInfo, fd int) hostInfo {
	if info.fidOK && !h.vol.trusts(info.id.dev, fd) {
		info.fidOK = false
	}
	return info
}

// markVolumeAt is markVolumeFD for the entry name of the directory dirfd, which
// no descriptor names. An entry of an unknown device opens once so that
// fstatfs can name its volume. An entry that cannot open leaves the device
// without a verdict and counts as untrusted.
func (h *hostRoot) markVolumeAt(info hostInfo, dirfd int, name string) hostInfo {
	if !info.fidOK {
		return info
	}
	if trusted, ok := h.vol.known(info.id.dev); ok {
		info.fidOK = trusted
		return info
	}
	fd, err := openatRetry(dirfd, name, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_SYMLINK, 0)
	if err != nil {
		info.fidOK = false
		return info
	}
	defer func() { _ = unix.Close(fd) }()
	return h.markVolumeFD(info, fd)
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

// statToHostInfo converts a stat result. The identity holds the device and the
// inode number only. APFS lowers the birth time of a file when a process sets
// an earlier modification time, as tar, cp -p, and git do, so a birth time in
// the key would give the file a new identity. The inode numbers of an APFS
// volume come from a counter that never goes back, so no later file reuses
// one. The probe in volumeIDsTrusted admits only that volume. The birth time
// stays in btime for display.
func statToHostInfo(st *unix.Stat_t) hostInfo {
	return hostInfo{
		kind:   hostKindOfMode(st.Mode),
		id:     hostID{dev: uint64(st.Dev), ino: uint64(st.Ino)},
		fid:    fileKey{dev: uint64(st.Dev), ino: uint64(st.Ino)},
		fidOK:  st.Ino != 0,
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
