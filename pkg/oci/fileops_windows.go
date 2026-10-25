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

package oci

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/fd"
)

const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// openShared opens path for reading and allows others to delete or replace the
// file while it stays open.
func openShared(path string) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	h, err := windows.CreateFile(name, windows.GENERIC_READ, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// readFileShared reads a whole file through openShared.
func readFileShared(path string) ([]byte, error) {
	f, err := openShared(path)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(f)
	if closeErr := f.Close(); readErr == nil {
		readErr = closeErr
	}
	return data, readErr
}

// replaceFile renames oldPath to newPath and replaces an existing newPath, even
// when another handle holds it open with FILE_SHARE_DELETE. A file system
// without POSIX rename semantics gets the plain os.Rename.
func replaceFile(oldPath, newPath string) error {
	absNew, err := filepath.Abs(newPath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	ntName := `\??\` + absNew
	if strings.HasPrefix(absNew, `\\`) {
		ntName = `\??\UNC\` + absNew[2:]
	}
	oldName, err := windows.UTF16PtrFromString(oldPath)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	src, err := windows.CreateFile(oldName, windows.DELETE|windows.SYNCHRONIZE, shareAll, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
	}
	defer windows.CloseHandle(src)

	const flags = windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS
	err = fd.SetFileTargetName(src, 0, ntName, flags, fd.FileRenameInformationEx)
	if err == nil {
		return nil
	}
	if st, ok := err.(windows.NTStatus); ok && (st == windows.STATUS_NOT_SUPPORTED || st == windows.STATUS_INVALID_PARAMETER || st == windows.STATUS_INVALID_INFO_CLASS) {
		return os.Rename(oldPath, newPath)
	}
	return &os.LinkError{Op: "rename", Old: oldPath, New: newPath, Err: err}
}
