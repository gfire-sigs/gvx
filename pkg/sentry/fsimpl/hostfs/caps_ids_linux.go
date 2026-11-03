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
	"fmt"
	"os"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// Magic numbers of file systems whose inode numbers do not identify a file
// across a rename or a remount: the number comes from the position of the
// directory entry, or the server invents it.
const (
	fsMagicMSDOS = 0x4d44
	fsMagicExFAT = 0x2011bab0
	fsMagicNTFS  = 0x5346544e
	fsMagicNTFS3 = 0x7366746e
	fsMagicNFS   = 0x6969
	fsMagicSMB   = 0x517b
	fsMagicSMB2  = 0xfe534d42
	fsMagicCIFS  = 0xff534d42
	fsMagicFUSE  = 0x65735546
	fsMagic9P    = 0x01021997
)

// keysCarryBirthTime reports whether the identity that a stat returns holds the
// birth time. ext4 reuses an inode number at the next create, and utimensat
// never changes the birth time, so the Linux key holds it.
const keysCarryBirthTime = true

// reuseProbeRounds is the number of create and unlink rounds that the identity
// probe runs. ext4 reuses an inode number at the next create, and it stamps the
// birth time from a clock that can be coarse on an older kernel. Two files
// with one inode number and one birth time would share a key. A round costs
// four system calls: open, statx, close, and unlink.
const reuseProbeRounds = 64

// volumeIDsTrusted reports whether the volume of the workspace root gives its
// files identities that no later file repeats. It refuses a file system whose
// inode numbers are unstable, and it creates and removes probe files to see
// whether a reused inode number comes back with the same birth time.
func volumeIDsTrusted(host hostBackend, readOnly bool) bool {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(host.rootDir()), &st); err != nil {
		return false
	}
	switch uint64(st.Type) & 0xffffffff {
	case fsMagicMSDOS, fsMagicExFAT, fsMagicNTFS, fsMagicNTFS3, fsMagicNFS, fsMagicSMB, fsMagicSMB2, fsMagicCIFS, fsMagicFUSE, fsMagic9P:
		return false
	}
	return readOnly || noRepeatedKeys(host)
}

// noRepeatedKeys creates and removes probe files and reports whether every key
// is new. The probe runs once for each open of a writable workspace. A
// read-only workspace cannot create probe files, so it skips the loop. The
// probe files have an internal name that the guest never sees, and the sweep at
// the next open removes the file of a killed process.
func noRepeatedKeys(host hostBackend) bool {
	name := fmt.Sprintf("%sprobe.%x.%x", ephemeralTmpPrefix, os.Getpid(), time.Now().UnixNano())
	seen := make(map[fileKey]struct{}, reuseProbeRounds)
	for range reuseProbeRounds {
		f, remove, err := createProbeFile(host, name)
		if err != nil {
			return true
		}
		info, err := host.fstat(f)
		remove()
		if err != nil {
			return true
		}
		if _, dup := seen[info.fid]; dup {
			return false
		}
		seen[info.fid] = struct{}{}
	}
	return true
}
