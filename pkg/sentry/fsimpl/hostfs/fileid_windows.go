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
	"errors"
	"fmt"
	"runtime"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/fd"
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

// rootLocation returns the volume serial number and the normalized path
// without volume of the directory that handle names. It reports zero and ""
// for a part that the host does not answer, and existsByID then skips the
// check of that part.
func rootLocation(handle windows.Handle) (volume uint64, path string) {
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &bhfi); err == nil {
		key, _ := fileIdentity(handle, bhfi)
		volume = key.dev
	}
	if buf, err := finalPathByHandle(handle, finalPathNormalizedNoVolume); err == nil {
		path = windows.UTF16ToString(buf)
	}
	return volume, path
}

// existsByID reports whether the workspace still holds a file with the key. It
// uses the pinned workspace directory as the volume hint, so the call needs no
// path and no list right on any ancestor directory.
//
// A key of another volume names nothing here, because OpenFileById resolves the
// id on the volume of the hint. The stored key has device 0 for the volume of
// the root, and the Workspace restores the serial number before it calls.
//
// An id of a deleted file and an id that never existed both fail with
// ERROR_INVALID_PARAMETER, so that code means "absent". A file that denies the
// open or holds a sharing lock still exists. A file that the open finds
// outside the workspace directory, for example in the Recycle Bin or after a
// move, is gone for this workspace.
func (h *hostRoot) existsByID(key fileKey) (bool, error) {
	if h.byIDErr != nil {
		return false, errHostUnsupported
	}
	if key.dev != 0 && h.volume != 0 && key.dev != h.volume {
		return false, nil
	}
	desc := fileIDDescriptor{size: uint32(unsafe.Sizeof(fileIDDescriptor{})), typ: extendedFileIDType}
	binary.LittleEndian.PutUint64(desc.id[0:8], key.ino)
	binary.LittleEndian.PutUint64(desc.id[8:16], key.ino2)
	if b := fd.ActiveWindowsFileBroker(); b != nil {
		return b.ExistsByID(h.handle, desc.id)
	}
	r1, _, callErr := procOpenFileByID.Call(
		uintptr(h.handle),
		uintptr(unsafe.Pointer(&desc)),
		windows.FILE_READ_ATTRIBUTES,
		fileShareAll,
		0,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
	)
	runtime.KeepAlive(&desc)
	if opened := windows.Handle(r1); opened != windows.InvalidHandle {
		defer closeHandle(opened)
		return h.belowRoot(opened)
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

// belowRoot reports whether the open file lies at or below the workspace
// directory. A denied query leaves the question open, so the file still counts
// as present. Any other failure is an error, and the caller keeps the record.
func (h *hostRoot) belowRoot(opened windows.Handle) (bool, error) {
	if h.rootPath == "" {
		return true, nil
	}
	buf, err := finalPathByHandle(opened, finalPathNormalizedNoVolume)
	switch {
	case err == nil:
		return pathAtOrBelow(windows.UTF16ToString(buf), h.rootPath), nil
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return true, nil
	}
	return false, fmt.Errorf("hostfs: final path of file opened by id: %w", err)
}

// pathAtOrBelow reports whether path names root or an entry below it. Both are
// normalized paths without volume. Windows compares names without case, and
// the match must end at a separator, so "\ws2" does not lie below "\ws".
func pathAtOrBelow(path, root string) bool {
	root = strings.TrimRight(root, `\`)
	for root != "" {
		if path == "" {
			return false
		}
		pr, pn := utf8.DecodeRuneInString(path)
		rr, rn := utf8.DecodeRuneInString(root)
		if pr != rr && !strings.EqualFold(path[:pn], root[:rn]) {
			return false
		}
		path, root = path[pn:], root[rn:]
	}
	return path == "" || path[0] == '\\'
}
