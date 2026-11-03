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
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// fileZeroDataInformation is FILE_ZERO_DATA_INFORMATION, the input of
// FSCTL_SET_ZERO_DATA.
type fileZeroDataInformation struct {
	FileOffset      int64
	BeyondFinalZero int64
}

// punchNative releases the clusters of [off, off+length) on a volume with
// sparse files. NTFS frees a cluster only in a sparse file, so the call marks
// the file sparse first. The file stays sparse afterwards, as it does after a
// growth that failed with ERROR_DISK_FULL (see setFileSize). The range ends at
// the end of file, because a punch keeps the size.
//
// FSCTL_SET_ZERO_DATA writes zeros, and it frees only whole clusters, so the
// bytes of a partial cluster at an edge read as zeros and stay allocated.
//
// A volume without sparse files, such as FAT or exFAT, and a file whose
// attribute list NTFS cannot extend report the call as unsupported. The caller
// then writes zeros. Many holes in one file fragment its attribute list. After
// about 256 KiB of list, NTFS refuses to split the file further with
// ERROR_FILE_SYSTEM_LIMITATION (see docs/gvxip/gvxip-002-ext4lite-volume-engine.md).
// That file keeps its holes and gets zero-filled ranges from then on.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_zero_data
func punchNative(f *os.File, off, length int64) error {
	err := withFileHandle(f, func(handle windows.Handle) error {
		return punchHandle(handle, off, length)
	})
	switch {
	case err == nil:
		return nil
	case sparseUnsupported(err):
		return fmt.Errorf("hostfs: fallocate: punch hole: %w", errors.Join(errHostUnsupported, err))
	}
	return fmt.Errorf("hostfs: fallocate: punch hole: %w", err)
}

// punchHandle marks the file of handle sparse and zeroes the range.
func punchHandle(handle windows.Handle, off, length int64) error {
	var info fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	end := min(off+length, info.EndOfFile)
	if off >= end {
		return nil
	}
	if err := setSparse(handle); err != nil {
		return err
	}
	zero := fileZeroDataInformation{FileOffset: off, BeyondFinalZero: end}
	var returned uint32
	return windows.DeviceIoControl(handle, windows.FSCTL_SET_ZERO_DATA,
		(*byte)(unsafe.Pointer(&zero)), uint32(unsafe.Sizeof(zero)), nil, 0, &returned, nil)
}

// sparseUnsupported reports whether err means that the volume or the file
// cannot take a hole: the volume has no sparse files, or the attribute list of
// the file has no room for another run.
func sparseUnsupported(err error) bool {
	return errors.Is(err, windows.ERROR_INVALID_FUNCTION) ||
		errors.Is(err, windows.ERROR_NOT_SUPPORTED) ||
		errors.Is(err, windows.ERROR_FILE_SYSTEM_LIMITATION)
}
