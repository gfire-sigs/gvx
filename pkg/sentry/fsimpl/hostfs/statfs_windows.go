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
	"unsafe"

	"golang.org/x/sys/windows"
)

// windowsBlockSize is the unit of the block counts when the volume does not
// report its cluster size. GetDiskFreeSpaceEx returns bytes only.
const windowsBlockSize = 4096

// fileFsFullSizeInformation is the FileFsFullSizeInformation class of
// NtQueryVolumeInformationFile.
const fileFsFullSizeInformation = 7

// fileFsFullSizeInfo is FILE_FS_FULL_SIZE_INFORMATION.
type fileFsFullSizeInfo struct {
	TotalAllocationUnits           int64
	CallerAvailableAllocationUnits int64
	ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit       uint32
	BytesPerSector                 uint32
}

var procNtQueryVolumeInformationFile = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryVolumeInformationFile")

// statfs reads the volume of the pinned root directory. The first choice is
// NtQueryVolumeInformationFile on the root handle. It needs no path and no new
// access right, so it works after the lockdown and in single-file mode, where
// the restricted token has no list right on the pinned parent directory. When
// that call fails, the function falls back to GetDiskFreeSpaceEx with the path
// of the handle. NTFS has no fixed number of file nodes, so the node counts
// stay zero.
func (h *hostRoot) statfs() (hostVolume, error) {
	if v, ok := h.statfsByHandle(); ok {
		return v, nil
	}
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

// statfsByHandle queries the volume of the root handle. It reports false when
// the call fails.
func (h *hostRoot) statfsByHandle() (hostVolume, bool) {
	var info fileFsFullSizeInfo
	var iosb windows.IO_STATUS_BLOCK
	r1, _, _ := procNtQueryVolumeInformationFile.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&iosb)),
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		fileFsFullSizeInformation,
	)
	unit := uint64(info.SectorsPerAllocationUnit) * uint64(info.BytesPerSector)
	if int32(r1) < 0 || unit == 0 || info.TotalAllocationUnits < 0 {
		return hostVolume{}, false
	}
	return hostVolume{
		blockSize: unit,
		blocks:    uint64(info.TotalAllocationUnits),
		free:      uint64(info.ActualAvailableAllocationUnits),
		avail:     uint64(info.CallerAvailableAllocationUnits),
	}, true
}

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
