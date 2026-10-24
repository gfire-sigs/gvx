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

//go:build windows

package hostfs

import (
	"golang.org/x/sys/windows"
)

// windowsBlockSize is the unit of the block counts that hostfs reports on
// Windows. GetDiskFreeSpaceEx returns bytes, and NTFS has no fixed block count
// that the call exposes.
const windowsBlockSize = 4096

// finalDirPath returns the DOS path of the directory that handle names. The
// result has the prefix \\?\ and the stored case of every component.
func finalDirPath(handle windows.Handle) (string, error) {
	var stack [512]uint16
	buf := stack[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, int(n)+1)
	}
}

// statfs reads the volume of the workspace root with GetDiskFreeSpaceEx. The
// call needs a directory path. The path comes from the pinned handle of the
// root, so the call reaches the workspace directory and nothing else. NTFS
// has no fixed number of file nodes, so the node counts stay zero.
func (h *hostRoot) statfs() (hostVolume, error) {
	path, err := finalDirPath(h.handle)
	if err != nil {
		return hostVolume{}, hostError("statfs", ".", err)
	}
	name, err := windows.UTF16PtrFromString(path + `\`)
	if err != nil {
		return hostVolume{}, hostError("statfs", ".", err)
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(name, &avail, &total, &totalFree); err != nil {
		return hostVolume{}, hostError("statfs", ".", err)
	}
	return hostVolume{
		blockSize: windowsBlockSize,
		blocks:    total / windowsBlockSize,
		free:      totalFree / windowsBlockSize,
		avail:     avail / windowsBlockSize,
	}, nil
}
