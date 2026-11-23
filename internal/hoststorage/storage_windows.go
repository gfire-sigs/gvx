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

package hoststorage

import (
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openStorageFile(dir *os.File, name string, flags int, perm os.FileMode) (*os.File, error) {
	return openStorageObject(dir, name, flags, perm, false)
}

func openStorageDir(dir *os.File, name string, create bool, perm os.FileMode) (*os.File, error) {
	var flags int
	if create {
		flags = os.O_CREATE
	}
	return openStorageObject(dir, name, flags, perm, true)
}

func openStorageObject(dir *os.File, name string, flags int, perm os.FileMode, directory bool) (*os.File, error) {
	if strings.ContainsAny(name, "<>\"|?*") || strings.TrimRight(name, " .") != name {
		return nil, windows.ERROR_INVALID_NAME
	}
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return nil, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory: windows.Handle(dir.Fd()),
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	access := uint32(windows.FILE_GENERIC_READ)
	if flags&(os.O_WRONLY|os.O_RDWR) != 0 {
		access |= windows.FILE_GENERIC_WRITE
	}
	fileAttrs := uint32(windows.FILE_ATTRIBUTE_NORMAL)
	if perm&0o200 == 0 {
		fileAttrs = windows.FILE_ATTRIBUTE_READONLY
	}
	disposition := uint32(windows.FILE_OPEN)
	if flags&os.O_CREATE != 0 {
		disposition = windows.FILE_OPEN_IF
		if flags&os.O_EXCL != 0 {
			disposition = windows.FILE_CREATE
		}
	}
	kind := uint32(windows.FILE_NON_DIRECTORY_FILE)
	if directory {
		kind = windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_TRAVERSE
		fileAttrs = windows.FILE_ATTRIBUTE_NORMAL
	}
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE
	err = windows.NtCreateFile(&handle, access, &attrs, &iosb, nil, fileAttrs, shareAll, disposition,
		kind|windows.FILE_SYNCHRONOUS_IO_NONALERT|windows.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		if err == windows.STATUS_OBJECT_NAME_NOT_FOUND || err == windows.STATUS_OBJECT_PATH_NOT_FOUND {
			err = os.ErrNotExist
		}
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	var info windows.ByHandleFileInformation
	err = windows.GetFileInformationByHandle(handle, &info)
	if err == nil && info.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		err = os.ErrPermission
	}
	if err == nil && flags&os.O_TRUNC != 0 {
		err = os.ErrInvalid
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	return os.NewFile(uintptr(handle), name), nil
}

func storageParent(dir *os.File) (*os.File, error) {
	// VOLUME_NAME_GUID avoids drive letters, junctions and substitute drives.
	const finalPathVolumeGUID = 1
	path, err := finalPath(windows.Handle(dir.Fd()), finalPathVolumeGUID)
	if err != nil {
		return nil, err
	}
	parent := filepath.Dir(path)
	if parent == path {
		return nil, nil
	}
	return os.Open(parent)
}

func finalPath(handle windows.Handle, flags uint32) (string, error) {
	var stack [512]uint16
	buf := stack[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), flags)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		buf = make([]uint16, int(n)+1)
	}
}

func statStorageFile(dir *os.File, name string) (StorageIdentity, error) {
	f, err := openStorageFile(dir, name, os.O_RDONLY, 0)
	if err != nil {
		return StorageIdentity{}, err
	}
	defer f.Close()
	return VerifyStorageFile(f)
}

func storageFileIdentity(f *os.File) (StorageIdentity, error) {
	h := windows.Handle(f.Fd())
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return StorageIdentity{}, err
	}
	var key struct {
		VolumeSerialNumber uint64
		FileID             [16]byte
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return StorageIdentity{}, ErrUnsupported
	}
	if err := windows.GetFileInformationByHandleEx(h, windows.FileIdInfo, (*byte)(unsafe.Pointer(&key)), uint32(unsafe.Sizeof(key))); err != nil {
		return StorageIdentity{}, err
	}
	var id [2]uint64
	for i, b := range key.FileID {
		id[i/8] |= uint64(b) << (8 * (i % 8))
	}
	return StorageIdentity{Volume: key.VolumeSerialNumber, Mount: key.VolumeSerialNumber, File: id, Links: info.NumberOfLinks}, nil
}

// Local Windows volumes have distinct file-ID scopes. StorageAncestry
// requires a volume GUID before it accepts a directory.
func storageVolumesDisjoint(_, _ *os.File) bool {
	return true
}
