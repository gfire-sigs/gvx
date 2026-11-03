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
	"bytes"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// keysCarryBirthTime reports whether the identity that a stat returns holds the
// birth time. APFS lowers the birth time of a file when a process sets an
// earlier modification time, so the macOS key holds the device and the inode
// number only.
const keysCarryBirthTime = false

// volumeIDsTrusted reports whether the volume of the workspace root gives its
// files inode numbers that outlive a rename and that no later file reuses.
// APFS does: its next object identifier only grows. HFS+ can reuse a number
// after its 32-bit counter wraps. FAT, exFAT, and network volumes derive the
// number from the directory entry or invent it. They all keep records by path.
func volumeIDsTrusted(host hostBackend, _ bool) bool {
	var st unix.Statfs_t
	if err := unix.Fstatfs(int(host.rootDir()), &st); err != nil {
		return false
	}
	name := make([]byte, 0, len(st.Fstypename))
	for _, c := range st.Fstypename {
		if c == 0 {
			break
		}
		name = append(name, byte(c))
	}
	return bytes.Equal(name, []byte("apfs"))
}
