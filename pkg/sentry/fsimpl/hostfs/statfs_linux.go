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

	"golang.org/x/sys/unix"
)

// statfs reads the volume of the pinned workspace directory with fstatfs. The
// seccomp allowlist of the host filesystem permits fstatfs on a descriptor.
// The counts of Linux are in units of the fragment size.
func (h *hostRoot) statfs() (hostVolume, error) {
	var st unix.Statfs_t
	if err := retryEINTR(func() error { return unix.Fstatfs(h.rootFD(), &st) }); err != nil {
		return hostVolume{}, fmt.Errorf("hostfs: fstatfs workspace root: %w", err)
	}
	unit := uint64(st.Frsize)
	if unit == 0 {
		unit = uint64(st.Bsize)
	}
	return hostVolume{
		blockSize: unit,
		blocks:    st.Blocks,
		free:      st.Bfree,
		avail:     st.Bavail,
		files:     st.Files,
		filesFree: st.Ffree,
	}, nil
}
