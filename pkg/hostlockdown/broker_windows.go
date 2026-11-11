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

package hostlockdown

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsFileBroker performs capability-checked file operations beneath host
// mount handles pinned before Apply.
type WindowsFileBroker interface {
	OpenAt(dir windows.Handle, name string, access, fileAttrs, disposition, options uint32) (windows.Handle, error)
	OpenWatchHandle(dir windows.Handle) (windows.Handle, error)
	RemoveAt(dir windows.Handle, name string, wantDir bool) error
	SetTargetNameAt(oldDir windows.Handle, oldName string, newDir windows.Handle, newName string, access, flags, infoClass uint32) error
	ExistsByID(root windows.Handle, id [16]byte) (bool, error)
	FinalPathLeaf(dir, handle windows.Handle) (string, error)
}

var activeFileBroker atomic.Pointer[winMountBroker]

// ActiveWindowsFileBroker returns the sealed file broker started by Apply, or
// nil before Apply succeeds.
func ActiveWindowsFileBroker() WindowsFileBroker {
	b := activeFileBroker.Load()
	if b == nil {
		return nil
	}
	return b
}

const (
	// fileDeleteChild is FILE_DELETE_CHILD (0x40).
	fileDeleteChild = 0x40

	// fileLinkInformationClass is FileLinkInformation (11) for NtSetInformationFile.
	fileLinkInformationClass = 11

	// fileRenameInformationExClass is FileRenameInformationEx (65) for NtSetInformationFile.
	fileRenameInformationExClass = 65

	// brokerDispositionInfoExSize is sizeof(FILE_DISPOSITION_INFO_EX).
	brokerDispositionInfoExSize = 4

	// extendedFileIDType selects the 128-bit NTFS/ReFS FileID in FILE_ID_DESCRIPTOR.
	extendedFileIDType = 2

	// forbiddenBrokerAccess blocks DACL, owner, SACL, and wildcard access requests.
	forbiddenBrokerAccess = uint32(
		windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.ACCESS_SYSTEM_SECURITY |
			windows.MAXIMUM_ALLOWED,
	)

	// writeBrokerAccess classifies access bits that mutate file data, attributes, or namespace.
	writeBrokerAccess = uint32(
		windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			fileDeleteChild |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.DELETE |
			windows.GENERIC_WRITE |
			windows.GENERIC_ALL,
	)

	// allowedBrokerOpenOptions lists the create-option flags that OpenAt accepts.
	allowedBrokerOpenOptions = uint32(windows.FILE_DIRECTORY_FILE | windows.FILE_NON_DIRECTORY_FILE)

	// allowedBrokerFileAttrs lists the file-attribute bits that OpenAt accepts.
	allowedBrokerFileAttrs = uint32(
		windows.FILE_ATTRIBUTE_NORMAL |
			windows.FILE_ATTRIBUTE_READONLY |
			windows.FILE_ATTRIBUTE_HIDDEN |
			windows.FILE_ATTRIBUTE_ARCHIVE,
	)

	// allowedBrokerTargetAccess lists the source-handle access bits that SetTargetNameAt accepts.
	allowedBrokerTargetAccess = uint32(
		windows.DELETE |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_WRITE_ATTRIBUTES |
			windows.SYNCHRONIZE,
	)

	// allowedBrokerRenameFlags lists the FileRenameInformationEx flags that SetTargetNameAt accepts.
	allowedBrokerRenameFlags = uint32(
		windows.FILE_RENAME_REPLACE_IF_EXISTS |
			windows.FILE_RENAME_POSIX_SEMANTICS,
	)
)

type brokerFileIDDescriptor struct {
	size uint32
	typ  uint32
	id   [16]byte
}

var procOpenFileByID = modKernel32.NewProc("OpenFileById")

// winMountBroker services capability-checked relative file operations on one
// permanently locked OS thread holding a privilege-stripped Medium-integrity
// impersonation token.
type winMountBroker struct {
	mounts    *sealedMountSet
	openByErr error
	reqCh     chan func()
}

type brokerStartResult struct {
	tid uint32
	err error
}

// startFileBroker spawns the dedicated locked OS thread for mounts, attaches a
// privilege-stripped impersonation copy of primary, and closes the token handle
// immediately so no handle to the broker token remains in the process.
func startFileBroker(primary windows.Token, mounts *sealedMountSet) (*winMountBroker, uint32, error) {
	openByErr := procOpenFileByID.Find()
	brokerTok, err := createBrokerImpersonationToken(primary)
	if err != nil {
		return nil, 0, err
	}
	b := &winMountBroker{
		mounts:    mounts,
		openByErr: openByErr,
		reqCh:     make(chan func()),
	}
	ready := make(chan brokerStartResult, 1)
	go func(tok windows.Token) {
		runtime.LockOSThread()
		tid := excludeCurrentThread()
		setErr := windows.SetThreadToken(nil, tok)
		_ = tok.Close()
		if setErr != nil {
			unexcludeThread(tid)
			ready <- brokerStartResult{err: fmt.Errorf("hostlockdown: SetThreadToken(file broker): %w", setErr)}
			return
		}
		ready <- brokerStartResult{tid: tid}
		for fn := range b.reqCh {
			fn()
		}
	}(brokerTok)

	res := <-ready
	if res.err != nil {
		return nil, 0, res.err
	}
	return b, res.tid, nil
}

func (b *winMountBroker) stop() {
	if b != nil {
		close(b.reqCh)
	}
}

func (b *winMountBroker) call(fn func() error) error {
	done := make(chan error, 1)
	b.reqCh <- func() {
		done <- fn()
	}
	return <-done
}

func classifyBrokerAccess(access, disposition uint32) (needWrite bool, err error) {
	if access&forbiddenBrokerAccess != 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	return access&writeBrokerAccess != 0 || disposition != windows.FILE_OPEN, nil
}

func validateBrokerOpenParams(access, fileAttrs, disposition, options uint32) (needWrite bool, err error) {
	if options&^allowedBrokerOpenOptions != 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if options&allowedBrokerOpenOptions == allowedBrokerOpenOptions {
		return false, windows.ERROR_ACCESS_DENIED
	}
	if fileAttrs&^allowedBrokerFileAttrs != 0 {
		return false, windows.ERROR_ACCESS_DENIED
	}
	switch disposition {
	case windows.FILE_OPEN, windows.FILE_CREATE, windows.FILE_OPEN_IF:
	default:
		return false, windows.ERROR_ACCESS_DENIED
	}
	return classifyBrokerAccess(access, disposition)
}

func validateBrokerTargetParams(access, flags, infoClass uint32) error {
	if access == 0 || access&^allowedBrokerTargetAccess != 0 {
		return windows.ERROR_ACCESS_DENIED
	}
	switch infoClass {
	case fileLinkInformationClass:
		if flags != 0 {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil
	case fileRenameInformationExClass:
		if flags&^allowedBrokerRenameFlags != 0 {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil
	default:
		return windows.ERROR_ACCESS_DENIED
	}
}

func sameDirIdentity(keyA fileIDKey, okA bool, ntA string, keyB fileIDKey, okB bool, ntB string) bool {
	if ntA != "" && ntB != "" {
		return ntPathAtOrBelow(ntA, ntB) && ntPathAtOrBelow(ntB, ntA)
	}
	return okA && okB && keyA == keyB
}

func (b *winMountBroker) isExactMountRoot(dirKey fileIDKey, dirKeyOK bool, dirNTPath string) bool {
	for i := range b.mounts.dirs {
		dm := &b.mounts.dirs[i]
		if sameDirIdentity(dirKey, dirKeyOK, dirNTPath, dm.rootKey, dm.rootKeyOK, dm.ntPath) {
			return true
		}
	}
	for i := range b.mounts.files {
		fm := &b.mounts.files[i]
		if sameDirIdentity(dirKey, dirKeyOK, dirNTPath, fm.parentKey, fm.parentKeyOK, fm.parentNTPath) {
			return true
		}
	}
	return false
}

type dirAuth struct {
	covered      bool
	writable     bool
	coveringIdxs []int
	key          fileIDKey
	keyOK        bool
	ntPath       string
}

func (b *winMountBroker) authorizeDir(dir windows.Handle) (dirAuth, error) {
	if dir == 0 || dir == windows.InvalidHandle {
		return dirAuth{}, windows.ERROR_ACCESS_DENIED
	}
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(dir, &bhfi); err != nil {
		return dirAuth{}, windows.ERROR_ACCESS_DENIED
	}
	if bhfi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
		return dirAuth{}, windows.ERROR_ACCESS_DENIED
	}
	dirKey, dirKeyOK := queryFileIDKey(dir, bhfi)
	dirNTPath, ntErr := queryFinalPath(dir, finalPathVolumeNT)
	if bhfi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		if !b.isExactMountRoot(dirKey, dirKeyOK, dirNTPath) {
			return dirAuth{}, windows.ERROR_ACCESS_DENIED
		}
	}

	auth := dirAuth{
		key:    dirKey,
		keyOK:  dirKeyOK,
		ntPath: dirNTPath,
	}
	for i := range b.mounts.dirs {
		dm := &b.mounts.dirs[i]
		var match bool
		switch {
		case ntErr == nil && dm.ntPath != "":
			match = ntPathAtOrBelow(dirNTPath, dm.ntPath)
		case dirKeyOK:
			_, match = dm.knownDirs[dirKey]
		}
		if match {
			auth.covered = true
			auth.coveringIdxs = append(auth.coveringIdxs, i)
			if !dm.readOnly {
				auth.writable = true
			}
		}
	}
	return auth, nil
}

func (b *winMountBroker) authorizeSingleFile(auth dirAuth, name string, disposition, options uint32) (covered, writable bool) {
	if name == "" || disposition != windows.FILE_OPEN || options&windows.FILE_DIRECTORY_FILE != 0 {
		return false, false
	}
	for i := range b.mounts.files {
		fm := &b.mounts.files[i]
		if !sameDirIdentity(auth.key, auth.keyOK, auth.ntPath, fm.parentKey, fm.parentKeyOK, fm.parentNTPath) {
			continue
		}
		if name == fm.leafName {
			covered = true
			if !fm.readOnly {
				writable = true
			}
		}
	}
	return covered, writable
}

func ntOpenAt(dir windows.Handle, name string, access, fileAttrs, disposition, createOptions uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attrs := windows.OBJECT_ATTRIBUTES{
		RootDirectory: dir,
		ObjectName:    objectName,
	}
	attrs.Length = uint32(unsafe.Sizeof(attrs))
	var handle windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	status := windows.NtCreateFile(
		&handle,
		access|windows.SYNCHRONIZE,
		&attrs,
		&iosb,
		nil,
		fileAttrs,
		brokerShareAll,
		disposition,
		createOptions|windows.FILE_OPEN_REPARSE_POINT,
		0,
		0,
	)
	if status != nil {
		return 0, status
	}
	return handle, nil
}

// OpenAt implements WindowsFileBroker.
func (b *winMountBroker) OpenAt(dir windows.Handle, name string, access, fileAttrs, disposition, options uint32) (windows.Handle, error) {
	if name == "." {
		name = ""
	}
	if name != "" {
		if err := validateBrokerName(name); err != nil {
			return 0, err
		}
	} else if disposition != windows.FILE_OPEN {
		return 0, windows.ERROR_ACCESS_DENIED
	}
	needWrite, err := validateBrokerOpenParams(access, fileAttrs, disposition, options)
	if err != nil {
		return 0, err
	}

	var out windows.Handle
	err = b.call(func() error {
		auth, err := b.authorizeDir(dir)
		if err != nil {
			return err
		}
		fileCov, fileRW := false, false
		if !auth.writable && name != "" {
			fileCov, fileRW = b.authorizeSingleFile(auth, name, disposition, options)
		}
		if !auth.covered && !fileCov {
			return windows.ERROR_ACCESS_DENIED
		}
		if needWrite && !(auth.writable || fileRW) {
			return windows.ERROR_ACCESS_DENIED
		}

		createOpts := options | windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT
		h, err := ntOpenAt(dir, name, access, fileAttrs, disposition, createOpts)
		if err != nil {
			return err
		}
		if (!auth.covered || (needWrite && !auth.writable)) && fileCov {
			var bhfi windows.ByHandleFileInformation
			if statErr := windows.GetFileInformationByHandle(h, &bhfi); statErr != nil ||
				bhfi.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
				_ = windows.CloseHandle(h)
				return windows.ERROR_ACCESS_DENIED
			}
		} else if len(auth.coveringIdxs) > 0 && name != "" {
			var bhfi windows.ByHandleFileInformation
			if windows.GetFileInformationByHandle(h, &bhfi) == nil &&
				bhfi.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 &&
				bhfi.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
				if childKey, ok := queryFileIDKey(h, bhfi); ok {
					for _, idx := range auth.coveringIdxs {
						b.mounts.dirs[idx].knownDirs[childKey] = struct{}{}
					}
				}
			}
		}
		out = h
		return nil
	})
	return out, err
}

// OpenWatchHandle implements WindowsFileBroker.
func (b *winMountBroker) OpenWatchHandle(dir windows.Handle) (windows.Handle, error) {
	var out windows.Handle
	err := b.call(func() error {
		auth, err := b.authorizeDir(dir)
		if err != nil || !auth.covered {
			return windows.ERROR_ACCESS_DENIED
		}
		createOpts := uint32(windows.FILE_DIRECTORY_FILE | windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT)
		h, err := ntOpenAt(dir, "", windows.FILE_LIST_DIRECTORY, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, createOpts)
		if err != nil {
			return err
		}
		out = h
		return nil
	})
	return out, err
}

// RemoveAt implements WindowsFileBroker.
func (b *winMountBroker) RemoveAt(dir windows.Handle, name string, wantDir bool) error {
	if err := validateBrokerName(name); err != nil {
		return err
	}
	return b.call(func() error {
		auth, err := b.authorizeDir(dir)
		if err != nil || !auth.covered || !auth.writable {
			return windows.ERROR_ACCESS_DENIED
		}
		createOpts := uint32(windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
		if wantDir {
			createOpts |= windows.FILE_DIRECTORY_FILE
		}
		h, err := ntOpenAt(dir, name, windows.DELETE|windows.FILE_READ_ATTRIBUTES, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, createOpts)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(h)

		attrs, _, err := queryAttrTag(h)
		if err != nil {
			return err
		}
		isLink := attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0
		switch {
		case wantDir && isLink:
			return windows.STATUS_NOT_A_DIRECTORY
		case !wantDir && !isLink && attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
			return windows.STATUS_FILE_IS_A_DIRECTORY
		}
		disp := uint32(
			windows.FILE_DISPOSITION_DELETE |
				windows.FILE_DISPOSITION_POSIX_SEMANTICS |
				windows.FILE_DISPOSITION_IGNORE_READONLY_ATTRIBUTE,
		)
		return windows.SetFileInformationByHandle(
			h,
			windows.FileDispositionInfoEx,
			(*byte)(unsafe.Pointer(&disp)),
			brokerDispositionInfoExSize,
		)
	})
}

type brokerNameInfoHeader struct {
	flags          uint32
	rootDirectory  windows.Handle
	fileNameLength uint32
	fileName       [1]uint16
}

func setBrokerTargetName(src, root windows.Handle, name string, flags, infoClass uint32) error {
	units, err := windows.UTF16FromString(name)
	if err != nil {
		return err
	}
	units = units[:len(units)-1]
	const nameOffset = unsafe.Offsetof(brokerNameInfoHeader{}.fileName)
	nameBytes := len(units) * 2
	total := max(int(unsafe.Sizeof(brokerNameInfoHeader{})), int(nameOffset)+nameBytes)
	words := (total + 7) / 8
	buf := make([]uint64, words)
	hdr := (*brokerNameInfoHeader)(unsafe.Pointer(&buf[0]))
	hdr.flags = flags
	hdr.rootDirectory = root
	hdr.fileNameLength = uint32(nameBytes)
	if len(units) > 0 {
		dst := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), nameOffset)), len(units))
		copy(dst, units)
	}
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(src, &iosb, (*byte)(unsafe.Pointer(&buf[0])), uint32(words*8), infoClass)
}

// SetTargetNameAt implements WindowsFileBroker.
func (b *winMountBroker) SetTargetNameAt(oldDir windows.Handle, oldName string, newDir windows.Handle, newName string, access, flags, infoClass uint32) error {
	if err := validateBrokerName(oldName); err != nil {
		return err
	}
	if err := validateBrokerName(newName); err != nil {
		return err
	}
	if err := validateBrokerTargetParams(access, flags, infoClass); err != nil {
		return err
	}
	return b.call(func() error {
		oldAuth, err := b.authorizeDir(oldDir)
		if err != nil || !oldAuth.covered || !oldAuth.writable {
			return windows.ERROR_ACCESS_DENIED
		}
		newAuth, err := b.authorizeDir(newDir)
		if err != nil || !newAuth.covered || !newAuth.writable {
			return windows.ERROR_ACCESS_DENIED
		}
		createOpts := uint32(windows.FILE_OPEN_FOR_BACKUP_INTENT | windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT)
		src, err := ntOpenAt(oldDir, oldName, access, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, createOpts)
		if err != nil {
			return err
		}
		defer windows.CloseHandle(src)
		return setBrokerTargetName(src, newDir, newName, flags, infoClass)
	})
}

// ExistsByID implements WindowsFileBroker.
func (b *winMountBroker) ExistsByID(root windows.Handle, id [16]byte) (bool, error) {
	if b.openByErr != nil {
		return false, b.openByErr
	}
	var present bool
	err := b.call(func() error {
		auth, err := b.authorizeDir(root)
		if err != nil || !auth.covered {
			return windows.ERROR_ACCESS_DENIED
		}
		desc := brokerFileIDDescriptor{
			size: uint32(unsafe.Sizeof(brokerFileIDDescriptor{})),
			typ:  extendedFileIDType,
			id:   id,
		}
		r1, _, callErr := procOpenFileByID.Call(
			uintptr(root),
			uintptr(unsafe.Pointer(&desc)),
			windows.FILE_READ_ATTRIBUTES,
			brokerShareAll,
			0,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		)
		runtime.KeepAlive(&desc)
		if opened := windows.Handle(r1); opened != windows.InvalidHandle {
			defer windows.CloseHandle(opened)
			ntPath, pathErr := queryFinalPath(opened, finalPathVolumeNT)
			switch {
			case pathErr == nil:
				for _, idx := range auth.coveringIdxs {
					dm := &b.mounts.dirs[idx]
					if dm.ntPath != "" && ntPathAtOrBelow(ntPath, dm.ntPath) {
						present = true
						break
					}
				}
				return nil
			case errors.Is(pathErr, windows.ERROR_ACCESS_DENIED),
				errors.Is(pathErr, windows.ERROR_FILE_NOT_FOUND),
				errors.Is(pathErr, windows.ERROR_PATH_NOT_FOUND):
				present = false
				return nil
			default:
				return fmt.Errorf("hostfs: final path of file opened by id: %w", pathErr)
			}
		}
		errno, _ := callErr.(syscall.Errno)
		switch errno {
		case windows.ERROR_FILE_NOT_FOUND, windows.ERROR_PATH_NOT_FOUND,
			windows.ERROR_INVALID_PARAMETER, windows.ERROR_NOT_FOUND,
			windows.ERROR_ACCESS_DENIED, windows.ERROR_SHARING_VIOLATION:
			present = false
			return nil
		default:
			return fmt.Errorf("hostfs: open file by id: %w", callErr)
		}
	})
	return present, err
}

// FinalPathLeaf implements WindowsFileBroker.
func (b *winMountBroker) FinalPathLeaf(dir, handle windows.Handle) (string, error) {
	var leaf string
	err := b.call(func() error {
		auth, err := b.authorizeDir(dir)
		if err != nil || !auth.covered {
			return windows.ERROR_ACCESS_DENIED
		}
		ntPath, err := queryFinalPath(handle, finalPathVolumeNT)
		if err != nil {
			return err
		}
		covered := false
		for _, idx := range auth.coveringIdxs {
			dm := &b.mounts.dirs[idx]
			if dm.ntPath != "" && ntPathAtOrBelow(ntPath, dm.ntPath) {
				covered = true
				break
			}
		}
		if !covered {
			return windows.ERROR_ACCESS_DENIED
		}
		trimmed := strings.TrimRight(ntPath, `\`)
		sep := strings.LastIndexByte(trimmed, '\\')
		if sep < 0 {
			leaf = trimmed
			return nil
		}
		leaf = trimmed[sep+1:]
		return nil
	})
	return leaf, err
}

var _ WindowsFileBroker = (*winMountBroker)(nil)
