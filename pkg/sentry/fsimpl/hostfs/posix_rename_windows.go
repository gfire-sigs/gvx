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

// This file implements unlink, rmdir, rename, and link with POSIX semantics.
// A POSIX delete or rename removes or replaces a name at once, even while
// other handles to the file stay open. Guests rely on this behavior, for
// example when "git rebase" replaces an open file. Every operation works on
// handles that resolve through the pinned workspace directory. No operation
// falls back to a path-based call, so an unsupported file system returns its
// real error and the guest sees it.

const (
	// fileLinkInformation is the FileLinkInformation class of
	// NtSetInformationFile. The x/sys constant with the same name holds the
	// value of FileLinkInformationEx (72). This code needs the plain class
	// (11), which Go's own Linkat uses and which every Windows version accepts.
	fileLinkInformation = 11

	// fileRenameInformationEx is the FileRenameInformationEx class of
	// NtSetInformationFile. The rename names its destination relative to a
	// root directory handle, so it stays inside the pinned workspace. The
	// Win32 call SetFileInformationByHandle with FileRenameInfoEx returned
	// ERROR_INVALID_PARAMETER for this layout on a hosted Windows runner.
	fileRenameInformationEx = 65

	// fileDispositionInfoExSize is sizeof(FILE_DISPOSITION_INFO_EX).
	fileDispositionInfoExSize = 4
)

// nameInfoHeader is the common layout of FILE_RENAME_INFO (the Ex form),
// FILE_RENAME_INFORMATION, and FILE_LINK_INFORMATION. The first field is a
// flag word for a rename, and a BOOLEAN ReplaceIfExists for a link.
type nameInfoHeader struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// newNameInfo builds a name information buffer that holds the simple name of
// the destination and the handle of the destination directory. The buffer has
// no terminating NUL, which the documentation allows. The buffer is at least
// sizeof(nameInfoHeader) long, because the kernel rejects a shorter one, and
// it has 8-byte alignment for the pointer-sized RootDirectory field. The
// caller MUST keep the returned slice alive until the call that uses it ends.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info
func newNameInfo(first uint32, root windows.Handle, name string) (buf []uint64, size uint32, err error) {
	units, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, 0, err
	}
	// Drop the NUL that UTF16FromString appends.
	units = units[:len(units)-1]
	const nameOffset = unsafe.Offsetof(nameInfoHeader{}.FileName)
	nameBytes := len(units) * 2
	total := max(int(unsafe.Sizeof(nameInfoHeader{})), int(nameOffset)+nameBytes)
	words := (total + 7) / 8
	buf = make([]uint64, words)
	header := (*nameInfoHeader)(unsafe.Pointer(&buf[0]))
	header.Flags = first
	header.RootDirectory = root
	header.FileNameLength = uint32(nameBytes)
	if len(units) > 0 {
		dst := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), nameOffset)), len(units))
		copy(dst, units)
	}
	return buf, uint32(words * 8), nil
}

func (h *hostRoot) unlink(rel string) error {
	return h.remove("unlink", rel, false)
}

func (h *hostRoot) rmdir(rel string) error {
	return h.remove("rmdir", rel, true)
}

// remove deletes the entry that rel names with POSIX semantics. A symbolic
// link or junction counts as a non-directory, as on Linux: unlink removes it
// and rmdir returns ENOTDIR. A plain directory returns EISDIR to unlink.
// The unlink open omits FILE_NON_DIRECTORY_FILE. Windows reports a directory
// symbolic link as a directory, so that flag would refuse to remove it. The
// attribute query on the same handle makes the type decision atomic with the
// delete.
//
// FileDispositionInfoEx with FILE_DISPOSITION_FLAG_POSIX_SEMANTICS removes the
// name from the namespace while other handles stay open. IGNORE_READONLY lets
// the delete remove a file with the read-only attribute, as unlink does on
// Linux. The handle needs DELETE access.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information_ex
func (h *hostRoot) remove(op, rel string, wantDir bool) error {
	if rel == "." {
		return hostError(op, rel, windows.ERROR_SHARING_VIOLATION)
	}
	parent, err := h.walkParent(op, rel)
	if err != nil {
		return err
	}
	defer parent.release()
	var options uint32
	if wantDir {
		options = windows.FILE_DIRECTORY_FILE
	}
	handle, err := openAt(parent.handle, parent.name, windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, options)
	if err != nil {
		return hostError(op, rel, err)
	}
	defer closeHandle(handle)
	attrs, _, err := queryAttributeTag(handle)
	if err != nil {
		return hostError(op, rel, err)
	}
	isLink := attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
	switch {
	case wantDir && isLink:
		return hostError(op, rel, windows.STATUS_NOT_A_DIRECTORY)
	case !wantDir && !isLink && attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return hostError(op, rel, windows.STATUS_FILE_IS_A_DIRECTORY)
	}
	disposition := uint32(windows.FILE_DISPOSITION_DELETE |
		windows.FILE_DISPOSITION_POSIX_SEMANTICS |
		windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE)
	if err := windows.SetFileInformationByHandle(handle, windows.FileDispositionInfoEx,
		(*byte)(unsafe.Pointer(&disposition)), fileDispositionInfoExSize); err != nil {
		return hostError(op, rel, err)
	}
	return nil
}

// rename moves oldRel to newRel and replaces an existing newRel. Both parent
// directories resolve through handles. The source handle takes the new name as
// a simple name relative to the destination directory handle, as the
// FILE_RENAME_INFO documentation describes for RootDirectory. The source open
// takes DELETE access, which a rename requires. The caller checks type
// compatibility of source and destination.
//
// FILE_RENAME_POSIX_SEMANTICS replaces a destination that other handles
// hold open. A destination with the read-only attribute still fails with an
// access error, which hostfs reports as EACCES.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
func (h *hostRoot) rename(oldRel, newRel string) error {
	return h.setTargetName(
		"rename",
		oldRel,
		newRel,
		windows.ERROR_SHARING_VIOLATION,
		windows.DELETE|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_RENAME_REPLACE_IF_EXISTS|windows.FILE_RENAME_POSIX_SEMANTICS,
		fileRenameInformationEx,
	)
}

// link creates a hard link newRel to the entry oldRel. The source open uses
// FILE_OPEN_REPARSE_POINT, so a link to a symbolic link names the link itself
// and not its target, as link does on Linux. NtSetInformationFile with
// FileLinkInformation takes the destination directory handle and the simple
// name of the new link. A file system without hard link support returns its
// own error, which hostErrno maps to EOPNOTSUPP. The function never copies.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information
func (h *hostRoot) link(oldRel, newRel string) error {
	// ReplaceIfExists stays zero: an existing destination returns EEXIST.
	return h.setTargetName(
		"link",
		oldRel,
		newRel,
		windows.ERROR_PRIVILEGE_NOT_HELD,
		windows.FILE_WRITE_ATTRIBUTES,
		0,
		fileLinkInformation,
	)
}

func (h *hostRoot) setTargetName(op, oldRel, newRel string, rootErr error, access, flags, infoClass uint32) error {
	if oldRel == "." || newRel == "." {
		return hostError2(op, oldRel, newRel, rootErr)
	}
	oldParent, err := h.walkParent(op, oldRel)
	if err != nil {
		return err
	}
	defer oldParent.release()
	newParent, err := h.walkParent(op, newRel)
	if err != nil {
		return err
	}
	defer newParent.release()
	src, err := openAt(oldParent.handle, oldParent.name, access,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0)
	if err != nil {
		return hostError2(op, oldRel, newRel, err)
	}
	defer closeHandle(src)
	buf, size, err := newNameInfo(flags, newParent.handle, newParent.name)
	if err != nil {
		return hostError2(op, oldRel, newRel, err)
	}
	var iosb windows.IO_STATUS_BLOCK
	if err := windows.NtSetInformationFile(src, &iosb, (*byte)(unsafe.Pointer(&buf[0])), size, infoClass); err != nil {
		return hostError2(op, oldRel, newRel, err)
	}
	return nil
}
