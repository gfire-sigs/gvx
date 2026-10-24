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
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// fileStandardInfo is FILE_STANDARD_INFO. The explicit layout matches the C
// structure: two 64-bit sizes, the link count, and two BOOLEAN fields.
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  uint8
	Directory      uint8
	_              [2]byte
}

// allocateNative serves a fallocate request on Windows. Mode 0 and KEEP_SIZE
// raise the allocation size of the handle, which reserves the clusters. Mode 0
// then raises the end of file. Neither call ever shrinks the file, because a
// smaller allocation size would truncate it. A punch needs a sparse file, so
// the host reports it as unsupported and the caller writes zeros.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_allocation_info
func allocateNative(f *os.File, mode uint64, off, length int64) error {
	if mode&linux.FALLOC_FL_PUNCH_HOLE != 0 {
		return fmt.Errorf("hostfs: fallocate: punch hole: %w", errHostUnsupported)
	}
	rc, err := f.SyscallConn()
	if err != nil {
		return fmt.Errorf("hostfs: fallocate: %w", err)
	}
	var callErr error
	if err := rc.Control(func(fd uintptr) {
		callErr = reserve(windows.Handle(fd), mode&linux.FALLOC_FL_KEEP_SIZE == 0, off+length)
	}); err != nil {
		return fmt.Errorf("hostfs: fallocate: %w", err)
	}
	if callErr != nil {
		return fmt.Errorf("hostfs: fallocate: %w", callErr)
	}
	return nil
}

// reserve raises the allocation size of the handle to target bytes. When grow
// is true, it raises the end of file to target as well.
func reserve(handle windows.Handle, grow bool, target int64) error {
	var info fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		return err
	}
	if target > info.AllocationSize {
		if err := windows.SetFileInformationByHandle(handle, windows.FileAllocationInfo,
			(*byte)(unsafe.Pointer(&target)), uint32(unsafe.Sizeof(target))); err != nil {
			return err
		}
	}
	if grow && target > info.EndOfFile {
		return windows.SetFileInformationByHandle(handle, windows.FileEndOfFileInfo,
			(*byte)(unsafe.Pointer(&target)), uint32(unsafe.Sizeof(target)))
	}
	return nil
}
