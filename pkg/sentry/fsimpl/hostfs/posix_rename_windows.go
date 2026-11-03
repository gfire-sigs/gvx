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
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/fd"
)

const (
	// fileLinkInformation is the FileLinkInformation class of
	// NtSetInformationFile.
	fileLinkInformation = 11

	// fileDispositionInfoExSize is sizeof(FILE_DISPOSITION_INFO_EX).
	fileDispositionInfoExSize = 4
)

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
	return removeIn(op, parent.handle, parent.name, rel, wantDir)
}

func (h *hostRoot) unlinkAt(dir hostDirHandle, name string) error {
	return h.removeAt("unlink", dir, name, false)
}

func (h *hostRoot) rmdirAt(dir hostDirHandle, name string) error {
	return h.removeAt("rmdir", dir, name, true)
}

func (h *hostRoot) removeAt(op string, dir hostDirHandle, name string, wantDir bool) error {
	if err := validateWindowsName(name); err != nil {
		return hostError(op, name, err)
	}
	return removeIn(op, windows.Handle(dir), name, name, wantDir)
}

// removeIn is remove for the entry name inside the directory handle dir. The
// path rel only labels errors.
func removeIn(op string, dir windows.Handle, name, rel string, wantDir bool) error {
	var options uint32
	if wantDir {
		options = windows.FILE_DIRECTORY_FILE
	}
	handle, err := openAt(dir, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES,
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
	return h.setTargetName("rename", oldRel, newRel, windows.ERROR_SHARING_VIOLATION, renameTarget)
}

// link creates a hard link newRel to the entry oldRel. The source open uses
// FILE_OPEN_REPARSE_POINT, so a link to a symbolic link names the link itself
// and not its target, as link does on Linux. NtSetInformationFile with
// FileLinkInformation takes the destination directory handle and the simple
// name of the new link. A file system without hard link support returns its
// own error, which hostErrno maps to EOPNOTSUPP. The function never copies.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_link_information
func (h *hostRoot) link(oldRel, newRel string) error {
	return h.setTargetName("link", oldRel, newRel, windows.ERROR_PRIVILEGE_NOT_HELD, linkTarget)
}

// targetOp describes one rename-like operation of setTargetName.
type targetOp struct {
	access    uint32
	flags     uint32
	infoClass uint32
}

var (
	// renameTarget replaces an existing destination.
	renameTarget = targetOp{
		access:    windows.DELETE | windows.FILE_READ_ATTRIBUTES,
		flags:     windows.FILE_RENAME_REPLACE_IF_EXISTS | windows.FILE_RENAME_POSIX_SEMANTICS,
		infoClass: fd.FileRenameInformationEx,
	}
	// linkTarget keeps ReplaceIfExists at zero: an existing destination
	// returns EEXIST.
	linkTarget = targetOp{
		access:    windows.FILE_WRITE_ATTRIBUTES,
		infoClass: fileLinkInformation,
	}
)

func (h *hostRoot) renameAt(oldDir hostDirHandle, oldName string, newDir hostDirHandle, newName string) error {
	return h.setTargetNameAt("rename", oldDir, oldName, newDir, newName, renameTarget)
}

func (h *hostRoot) linkAt(oldDir hostDirHandle, oldName string, newDir hostDirHandle, newName string) error {
	return h.setTargetNameAt("link", oldDir, oldName, newDir, newName, linkTarget)
}

func (h *hostRoot) setTargetNameAt(op string, oldDir hostDirHandle, oldName string, newDir hostDirHandle, newName string, t targetOp) error {
	if err := errors.Join(validateWindowsName(oldName), validateWindowsName(newName)); err != nil {
		return hostError2(op, oldName, newName, err)
	}
	return setTargetNameIn(op, oldName, newName,
		parentDir{handle: windows.Handle(oldDir), name: oldName},
		parentDir{handle: windows.Handle(newDir), name: newName}, t)
}

func (h *hostRoot) setTargetName(op, oldRel, newRel string, rootErr error, t targetOp) error {
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
	return setTargetNameIn(op, oldRel, newRel, oldParent, newParent, t)
}

// setTargetNameIn gives the entry oldParent.name the name newParent.name. The
// paths oldRel and newRel only label errors.
func setTargetNameIn(op, oldRel, newRel string, oldParent, newParent parentDir, t targetOp) error {
	src, err := openAt(oldParent.handle, oldParent.name, t.access,
		windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0)
	if err != nil {
		return hostError2(op, oldRel, newRel, err)
	}
	defer closeHandle(src)
	if err := fd.SetFileTargetName(src, newParent.handle, newParent.name, t.flags, t.infoClass); err != nil {
		return hostError2(op, oldRel, newRel, err)
	}
	return nil
}
