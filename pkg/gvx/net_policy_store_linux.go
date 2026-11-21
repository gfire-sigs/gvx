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

//go:build linux && !android

package gvx

import (
	"fmt"
	"os"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func statPolicyStorePath(fd int, _ bool) (unix.Stat_t, error) {
	var mount unix.Statfs_t
	if err := unix.Fstatfs(fd, &mount); err != nil {
		return unix.Stat_t{}, err
	}
	switch uint32(mount.Type) {
	case unix.AFS_FS_MAGIC, unix.AFS_SUPER_MAGIC, unix.CEPH_SUPER_MAGIC, unix.CIFS_SUPER_MAGIC,
		unix.CODA_SUPER_MAGIC, unix.EXFAT_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.MSDOS_SUPER_MAGIC,
		unix.NCP_SUPER_MAGIC, unix.NFS_SUPER_MAGIC, unix.SMB_SUPER_MAGIC, unix.SMB2_SUPER_MAGIC, unix.V9FS_MAGIC:
		return unix.Stat_t{}, fmt.Errorf("%w: filesystem does not guarantee local POSIX permissions", errPolicyStoreUnsafe)
	}
	// Linux POSIX ACLs expose the effective ACL mask in mode's group bits.
	var st unix.Stat_t
	err := unix.Fstat(fd, &st)
	return st, err
}

func syncPolicyStoreFile(f *os.File) error {
	return f.Sync()
}

func syncPolicyStoreName(dir int, _ *os.File) error {
	return unix.Fsync(dir)
}
