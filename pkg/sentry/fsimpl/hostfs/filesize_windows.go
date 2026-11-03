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
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// setFileSize sets the size of f with the Linux result.
//
// Linux extends a file with a hole, so a size above the free space succeeds.
// NTFS allocates the clusters of a file that is not sparse, and fails with
// ERROR_DISK_FULL when the volume cannot hold them. setFileSize then marks the
// file sparse and sets the size again, so the extension becomes a hole. A
// file stays dense until a growth fails, so fallocate keeps its reservation.
//
// NTFS rejects a size above its largest file (16 TiB minus 64 KiB with 4 KiB
// clusters) with ERROR_INVALID_PARAMETER. Linux reports EFBIG for that.
func setFileSize(f *os.File, size int64) error {
	err := f.Truncate(size)
	if errors.Is(err, windows.ERROR_DISK_FULL) {
		if serr := withFileHandle(f, setSparse); serr != nil {
			return errors.Join(err, serr)
		}
		err = f.Truncate(size)
	}
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return fmt.Errorf("hostfs: set size %d: %w", size, errFileTooLarge)
	}
	return err
}

// setSparse marks the file of handle sparse.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_sparse
func setSparse(handle windows.Handle) error {
	var returned uint32
	return windows.DeviceIoControl(handle, windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil)
}
