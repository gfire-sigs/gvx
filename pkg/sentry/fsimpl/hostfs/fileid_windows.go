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
	"encoding/binary"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// extendedFileIDType is ExtendedFileIdType of FILE_ID_TYPE. It selects the
// 128-bit file id of FILE_ID_INFO.
const extendedFileIDType = 2

// fileIDDescriptor is FILE_ID_DESCRIPTOR with the ExtendedFileId member of the
// union. The union has 8-byte alignment, so it starts at offset 8.
type fileIDDescriptor struct {
	size uint32
	typ  uint32
	id   [16]byte
}

// procOpenFileByID is OpenFileById. newHostRoot resolves it before the
// lockdown, because a restricted process cannot load a procedure later.
var procOpenFileByID = windows.NewLazySystemDLL("kernel32.dll").NewProc("OpenFileById")

// existsByID reports whether the volume of the workspace still holds a file
// with the key. It uses the pinned workspace directory as the volume hint, so
// the call needs no path and no list right on any ancestor directory.
//
// An id of a deleted file and an id that never existed both fail with
// ERROR_INVALID_PARAMETER, so that code means "absent". A file that denies the
// open or holds a sharing lock still exists.
func (h *hostRoot) existsByID(key fileKey) (bool, error) {
	if h.byIDErr != nil {
		return false, errHostUnsupported
	}
	desc := fileIDDescriptor{size: uint32(unsafe.Sizeof(fileIDDescriptor{})), typ: extendedFileIDType}
	binary.LittleEndian.PutUint64(desc.id[0:8], key.ino)
	binary.LittleEndian.PutUint64(desc.id[8:16], key.ino2)
	r1, _, callErr := procOpenFileByID.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&desc)),
		windows.FILE_READ_ATTRIBUTES,
		fileShareAll,
		0,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
	runtime.KeepAlive(&desc)
	if windows.Handle(r1) != windows.InvalidHandle {
		closeHandle(windows.Handle(r1))
		return true, nil
	}
	errno, _ := callErr.(syscall.Errno)
	switch errno {
	case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND,
		windows.ERROR_INVALID_PARAMETER, windows.ERROR_NOT_FOUND:
		return false, nil
	case windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION:
		return true, nil
	}
	return false, fmt.Errorf("hostfs: open file by id: %w", callErr)
}
