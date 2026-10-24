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

package hostfs

import (
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// hostfsMagic is the f_type that hostfs reports. It is the ASCII text "host".
// The value hides the type of the host file system from the guest: a guest
// tool that checks f_type must not depend on the file system of the host.
const hostfsMagic = 0x686f7374

// hostVolume is the capacity of the host volume that holds a workspace. Every
// count is in units of blockSize.
type hostVolume struct {
	// blockSize is the unit of the counts in bytes.
	blockSize uint64
	// blocks is the size of the volume.
	blocks uint64
	// free is the number of unused blocks.
	free uint64
	// avail is the number of unused blocks that this process may use.
	avail uint64
	// files is the number of file nodes, or zero when the volume has no fixed
	// limit that the host reports.
	files uint64
	// filesFree is the number of unused file nodes.
	filesFree uint64
}

// linuxStatfs maps the capacity of the host volume to the result of statfs(2).
func (v hostVolume) linuxStatfs(readOnly bool) linux.Statfs {
	st := linux.Statfs{
		Type:            hostfsMagic,
		BlockSize:       int64(v.blockSize),
		FragmentSize:    int64(v.blockSize),
		Blocks:          v.blocks,
		BlocksFree:      v.free,
		BlocksAvailable: v.avail,
		Files:           v.files,
		FilesFree:       v.filesFree,
		NameLength:      maxFilenameLen,
	}
	if readOnly {
		st.Flags |= linux.ST_RDONLY
	}
	return st
}

// statFS reports the capacity of the host volume. Every file of the workspace
// reports the same numbers, so the call needs no dentry.
func (fs *filesystem) statFS() (linux.Statfs, error) {
	v, err := fs.ws.host.statfs()
	if err != nil {
		return linux.Statfs{}, translateHostError(err)
	}
	return v.linuxStatfs(fs.ws.ReadOnly()), nil
}
