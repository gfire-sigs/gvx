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
	"io/fs"
	"math"
	"os"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hostRoot performs every host file operation relative to a directory handle
// pinned before sandbox lockdown. It resolves a path one component at a time
// with NtCreateFile and refuses every reparse point (symbolic link, junction,
// mount point) on the way. It never builds an absolute path, so a concurrent
// rename or replacement of a parent directory cannot redirect an operation.
//
// The handle never changes after construction. Concurrent use is safe.
type hostRoot struct {
	// dir owns the handle. Closing dir closes handle.
	dir    *os.File
	handle windows.Handle
}

// fileShareAll lets other openers read, write, and delete the file while
// hostfs holds a handle. POSIX rename and unlink need this on every open.
const fileShareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

const (
	// finalPathNormalizedNoVolume selects FILE_NAME_NORMALIZED (0x0) and
	// VOLUME_NAME_NONE (0x4) for GetFinalPathNameByHandle. The result has no
	// drive prefix.
	finalPathNormalizedNoVolume = 0x4

	// symlinkFlagRelative is SYMLINK_FLAG_RELATIVE in a symbolic link
	// reparse buffer.
	symlinkFlagRelative = 0x1

	// reparseSymlinkHeaderSize is the size of the reparse buffer header
	// (8 bytes) plus the fixed symbolic link fields (12 bytes). The path
	// buffer starts at this offset.
	reparseSymlinkHeaderSize = 20

	// dirBufferSize is the buffer size for one directory listing call.
	dirBufferSize = 64 * 1024

	// Offsets of the FILE_FULL_DIR_INFO fields that readDir reads.
	dirInfoAttributesOffset = 56
	dirInfoNameLengthOffset = 60
	dirInfoEaSizeOffset     = 64
	dirInfoNameOffset       = 68

	// filetimeToUnixSeconds is the distance in seconds between the FILETIME
	// epoch (1601-01-01) and the Unix epoch.
	filetimeToUnixSeconds = 11644473600
	filetimeTicksPerSec   = 10_000_000
)

// fileAttributeTagInfo is FILE_ATTRIBUTE_TAG_INFO.
type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

// fileBasicInfo is FILE_BASIC_INFO. The explicit padding matches the C
// layout, where the structure ends on an 8-byte boundary.
type fileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// parentDir is the directory that holds the last component of a path. The
// handle is owned only when the path has a parent below the workspace root.
type parentDir struct {
	handle windows.Handle
	// name is the last component, or "." for the workspace root.
	name  string
	owned bool
}

func (p parentDir) release() {
	if p.owned {
		closeHandle(p.handle)
	}
}

func closeHandle(handle windows.Handle) {
	_ = windows.CloseHandle(handle)
}

func newHostRoot(root *os.Root) (*hostRoot, error) {
	// Root.Open(".") returns a handle to the directory object itself. The
	// handle stays valid after the caller closes the Root.
	dir, err := root.Open(".")
	if err != nil {
		return nil, fmt.Errorf("hostfs: pin workspace directory: %w", err)
	}
	return &hostRoot{dir: dir, handle: windows.Handle(dir.Fd())}, nil
}

func (h *hostRoot) close() error {
	return h.dir.Close()
}

// caseInsensitive returns false because lstat compares the stored name of
// every entry with the requested name, byte for byte.
func (h *hostRoot) caseInsensitive() bool {
	return false
}

// validateWindowsName rejects a path component that the Windows file system
// would store under another meaning. The colon rule blocks NTFS alternate
// data streams. The device name rule blocks names that Win32 maps to devices.
// Source: https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file
func validateWindowsName(name string) error {
	if name == "" || !utf8.ValidString(name) {
		return fmt.Errorf("%w: %q", errInvalidHostName, name)
	}
	for i := range len(name) {
		c := name[i]
		if c < 0x20 || strings.IndexByte(`\/:*?"<>|`, c) >= 0 {
			return fmt.Errorf("%w: %q", errInvalidHostName, name)
		}
	}
	if last := name[len(name)-1]; last == ' ' || last == '.' {
		return fmt.Errorf("%w: %q", errInvalidHostName, name)
	}
	if isReservedDeviceName(name) {
		return fmt.Errorf("%w: %q", errInvalidHostName, name)
	}
	return nil
}

// openAt opens one component relative to the directory handle dir. The name
// holds no separator. The empty name or "." opens dir itself again. Every open
// shares read, write, and delete access, never follows a reparse point, and
// uses backup intent so directories open without extra flags. The open omits
// OBJ_CASE_INSENSITIVE so that case-sensitive directories match exactly.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatefile
func openAt(dir windows.Handle, name string, access, fileAttrs, disposition, options uint32) (windows.Handle, error) {
	if name == "." {
		name = ""
	}
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
		fileShareAll,
		disposition,
		options|windows.FILE_OPEN_FOR_BACKUP_INTENT|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if status != nil {
		return 0, status
	}
	return handle, nil
}

// queryAttributeTag returns the file attributes and the reparse tag of an
// open handle. The reparse tag is zero for an entry without a reparse point.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_attribute_tag_info
func queryAttributeTag(handle windows.Handle) (attrs, tag uint32, err error) {
	var info fileAttributeTagInfo
	err = windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info)))
	if err != nil {
		return 0, 0, err
	}
	return info.FileAttributes, info.ReparseTag, nil
}

// rejectReparsePoint returns ErrPathTraversal when handle names a reparse
// point of any tag. A failed query returns the query error, so the check
// never passes by default.
func rejectReparsePoint(handle windows.Handle) error {
	attrs, _, err := queryAttributeTag(handle)
	if err != nil {
		return err
	}
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return ErrPathTraversal
	}
	return nil
}

// descend opens the directory that name denotes inside parent and rejects it
// when it is a reparse point. The returned handle is open on success only.
func descend(parent windows.Handle, name string) (windows.Handle, error) {
	if err := validateWindowsName(name); err != nil {
		return 0, err
	}
	// Microsoft recommends traverse and read-attribute access for a directory
	// handle that later serves as RootDirectory of a relative open or rename.
	handle, err := openAt(parent, name, windows.FILE_TRAVERSE|windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return 0, err
	}
	if err := rejectReparsePoint(handle); err != nil {
		closeHandle(handle)
		return 0, err
	}
	return handle, nil
}

// walkParent opens every directory on the path to rel except the last
// component and returns the last directory with that component. The caller
// MUST call release on the result. The walk keeps at most two handles open.
// It closes a directory as soon as its child is open. That is safe, because
// the child handle names the child object and not a path. The root itself
// yields the name ".".
func (h *hostRoot) walkParent(op, rel string) (parentDir, error) {
	if rel == "." {
		return parentDir{handle: h.handle, name: "."}, nil
	}
	cur := parentDir{handle: h.handle}
	rest := rel
	for {
		slash := strings.IndexByte(rest, '/')
		if slash < 0 {
			break
		}
		next, err := descend(cur.handle, rest[:slash])
		if err != nil {
			cur.release()
			return parentDir{}, hostError(op, rel, err)
		}
		cur.release()
		cur = parentDir{handle: next, owned: true}
		rest = rest[slash+1:]
	}
	if err := validateWindowsName(rest); err != nil {
		cur.release()
		return parentDir{}, hostError(op, rel, err)
	}
	cur.name = rest
	return cur, nil
}

// openAny opens the entry that rel names without a type restriction and
// without following a reparse point on the last component. The root "." opens
// the pinned directory again with the requested access.
func (h *hostRoot) openAny(op, rel string, access uint32) (windows.Handle, error) {
	parent, err := h.walkParent(op, rel)
	if err != nil {
		return 0, err
	}
	defer parent.release()
	handle, err := openAt(parent.handle, parent.name, access, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0)
	if err != nil {
		return 0, hostError(op, rel, err)
	}
	return handle, nil
}

// openDirHandle opens the directory that rel names. It returns
// ErrPathTraversal when the directory is a reparse point. The workspace root
// is exempt, because the host owner chose it.
func (h *hostRoot) openDirHandle(op, rel string, access uint32) (windows.Handle, error) {
	parent, err := h.walkParent(op, rel)
	if err != nil {
		return 0, err
	}
	defer parent.release()
	handle, err := openAt(parent.handle, parent.name, access, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_OPEN, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return 0, hostError(op, rel, err)
	}
	if rel != "." {
		if err := rejectReparsePoint(handle); err != nil {
			closeHandle(handle)
			return 0, hostError(op, rel, err)
		}
	}
	return handle, nil
}

// openRequest is the translation of Go open flags into NtCreateFile
// parameters.
type openRequest struct {
	access      uint32
	fileAttrs   uint32
	disposition uint32
	write       bool
	truncate    bool
}

// newOpenRequest validates flags and builds the NtCreateFile parameters. The
// name rel only labels errors.
func newOpenRequest(rel string, flags int, perm os.FileMode) (openRequest, error) {
	const supported = os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_EXCL | os.O_TRUNC
	if flags&^supported != 0 {
		return openRequest{}, fmt.Errorf("hostfs: open %q: flags %#x: %w", rel, flags, fs.ErrInvalid)
	}
	req := openRequest{access: windows.FILE_READ_ATTRIBUTES}
	switch flags & (os.O_WRONLY | os.O_RDWR) {
	case os.O_RDONLY:
		req.access |= windows.FILE_GENERIC_READ
	case os.O_WRONLY:
		req.access |= windows.FILE_GENERIC_WRITE
		req.write = true
	case os.O_RDWR:
		req.access |= windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE
		req.write = true
	default:
		return openRequest{}, fmt.Errorf("hostfs: open %q: flags %#x: %w", rel, flags, fs.ErrInvalid)
	}
	// FILE_OVERWRITE_IF would replace a read-only file, so O_TRUNC runs as a
	// truncation of the open handle, as the Go standard library does.
	req.truncate = req.write && flags&os.O_TRUNC != 0
	req.disposition = windows.FILE_OPEN
	switch {
	case flags&(os.O_CREATE|os.O_EXCL) == os.O_CREATE|os.O_EXCL:
		req.disposition = windows.FILE_CREATE
	case flags&os.O_CREATE != 0:
		req.disposition = windows.FILE_OPEN_IF
	}
	req.fileAttrs = windows.FILE_ATTRIBUTE_NORMAL
	if perm&0o200 == 0 {
		req.fileAttrs = windows.FILE_ATTRIBUTE_READONLY
	}
	return req, nil
}

func (h *hostRoot) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	if rel == "." {
		return nil, &ntError{op: "open", path: rel, status: windows.STATUS_FILE_IS_A_DIRECTORY}
	}
	req, err := newOpenRequest(rel, flags, perm)
	if err != nil {
		return nil, err
	}
	parent, err := h.walkParent("open", rel)
	if err != nil {
		return nil, err
	}
	defer parent.release()
	return openIn(parent.handle, parent.name, rel, req)
}

// openIn opens the file name inside the directory handle dir and refuses a
// reparse point. The path rel only labels errors.
func openIn(dir windows.Handle, name, rel string, req openRequest) (*os.File, error) {
	handle, err := openAt(dir, name, req.access, req.fileAttrs, req.disposition, windows.FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, hostError("open", rel, err)
	}
	if err := rejectReparsePoint(handle); err != nil {
		closeHandle(handle)
		return nil, hostError("open", rel, err)
	}
	if req.truncate {
		if err := syscall.Ftruncate(syscall.Handle(handle), 0); err != nil {
			closeHandle(handle)
			return nil, hostError("truncate", rel, err)
		}
	}
	// The relative name cannot reopen the file by path: it resolves against
	// the process directory, not the workspace.
	return os.NewFile(uintptr(handle), rel), nil
}

// hostDirHandle is an open directory handle. openDirAt returns one, and its
// caller closes it with closeDir.
type hostDirHandle windows.Handle

// caseVerified returns true because lstatAt and openDirAt compare the stored
// name of the entry with the requested name through finalPathLeaf.
func (h *hostRoot) caseVerified() bool {
	return true
}

func (h *hostRoot) rootDir() hostDirHandle {
	return hostDirHandle(h.handle)
}

// openDirAt opens the directory name inside dir with FILE_OPEN_REPARSE_POINT,
// rejects a reparse point, and verifies the stored case of the name.
func (h *hostRoot) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	handle, err := descend(windows.Handle(dir), name)
	if err != nil {
		return 0, hostInfo{}, hostError("open directory", name, err)
	}
	stored, err := finalPathLeaf(handle)
	if err != nil {
		closeHandle(handle)
		return 0, hostInfo{}, hostError("open directory", name, err)
	}
	if stored != name {
		closeHandle(handle)
		return 0, hostInfo{}, fmt.Errorf("hostfs: open directory %q: %w: %w", name, errNameMismatch, windows.ERROR_FILE_NOT_FOUND)
	}
	info, err := statHandle(handle)
	if err != nil {
		closeHandle(handle)
		return 0, hostInfo{}, hostError("open directory", name, err)
	}
	return hostDirHandle(handle), info, nil
}

func (h *hostRoot) closeDir(dir hostDirHandle) error {
	return windows.CloseHandle(windows.Handle(dir))
}

func (h *hostRoot) fstatDir(dir hostDirHandle) (hostInfo, error) {
	info, err := statHandle(windows.Handle(dir))
	if err != nil {
		return hostInfo{}, hostError("fstat", "directory", err)
	}
	return info, nil
}

func (h *hostRoot) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	if err := validateWindowsName(name); err != nil {
		return hostInfo{}, hostError("lstat", name, err)
	}
	return lstatIn(windows.Handle(dir), name, name)
}

func (h *hostRoot) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	req, err := newOpenRequest(name, flags, perm)
	if err != nil {
		return nil, err
	}
	if err := validateWindowsName(name); err != nil {
		return nil, hostError("open", name, err)
	}
	return openIn(windows.Handle(dir), name, name, req)
}

func (h *hostRoot) openDir(rel string) (*os.File, error) {
	handle, err := h.openDirHandle("open directory", rel, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(handle), rel), nil
}

// filetimeToTime converts a FILETIME tick count to a time. The conversion
// avoids int64 nanosecond arithmetic, which overflows for the year 1601.
func filetimeToTime(ticks uint64) time.Time {
	sec := int64(ticks/filetimeTicksPerSec) - filetimeToUnixSeconds
	nsec := int64(ticks%filetimeTicksPerSec) * 100
	return time.Unix(sec, nsec)
}

// timeToFiletime converts a time to a FILETIME. Times before 1601 or after
// the last representable instant return fs.ErrInvalid. A zero FILETIME would
// mean "leave unchanged" to SetFileTime, so the zero tick count is invalid too.
func timeToFiletime(t time.Time) (windows.Filetime, error) {
	sec := t.Unix() + filetimeToUnixSeconds
	if sec <= 0 || sec > math.MaxInt64/filetimeTicksPerSec-1 {
		return windows.Filetime{}, fs.ErrInvalid
	}
	ticks := uint64(sec)*filetimeTicksPerSec + uint64(t.Nanosecond()/100)
	return windows.Filetime{LowDateTime: uint32(ticks), HighDateTime: uint32(ticks >> 32)}, nil
}

// handleKind classifies an open handle from its attributes. Any reparse tag
// other than a symbolic link counts as "other", which covers junctions and
// mount points. A handle to a non-disk object counts as "other" too.
func handleKind(handle windows.Handle, attrs uint32) (hostKind, error) {
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_, tag, err := queryAttributeTag(handle)
		if err != nil {
			return 0, err
		}
		if tag == windows.IO_REPARSE_TAG_SYMLINK {
			return hostKindSymlink, nil
		}
		return hostKindOther, nil
	}
	if attrs&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return hostKindOther, nil
	}
	fileType, err := windows.GetFileType(handle)
	if err != nil {
		return 0, err
	}
	if fileType != windows.FILE_TYPE_DISK {
		return hostKindOther, nil
	}
	if attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return hostKindDir, nil
	}
	return hostKindRegular, nil
}

// statHandle reads the host metadata of an open handle. The handle needs
// FILE_READ_ATTRIBUTES access. The volume serial number and the file index
// identify the file. Hard links share both.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information
func statHandle(handle windows.Handle) (hostInfo, error) {
	var bhfi windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &bhfi); err != nil {
		return hostInfo{}, err
	}
	// ByHandleFileInformation has no change time. FILE_BASIC_INFO has it.
	var basic fileBasicInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileBasicInfo,
		(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return hostInfo{}, err
	}
	kind, err := handleKind(handle, bhfi.FileAttributes)
	if err != nil {
		return hostInfo{}, err
	}
	info := hostInfo{
		kind:  kind,
		id:    hostID{dev: uint64(bhfi.VolumeSerialNumber), ino: uint64(bhfi.FileIndexHigh)<<32 | uint64(bhfi.FileIndexLow)},
		nlink: bhfi.NumberOfLinks,
		perm:  0o644,
		atime: filetimeToTime(uint64(bhfi.LastAccessTime.HighDateTime)<<32 | uint64(bhfi.LastAccessTime.LowDateTime)),
		mtime: filetimeToTime(uint64(bhfi.LastWriteTime.HighDateTime)<<32 | uint64(bhfi.LastWriteTime.LowDateTime)),
		ctime: filetimeToTime(uint64(basic.ChangeTime)),
		btime: filetimeToTime(uint64(bhfi.CreationTime.HighDateTime)<<32 | uint64(bhfi.CreationTime.LowDateTime)),
	}
	if kind == hostKindDir {
		info.perm = 0o755
		// Callers add the "." and ".." links themselves.
		if info.nlink == 0 {
			info.nlink = 1
		}
	} else {
		info.size = int64(uint64(bhfi.FileSizeHigh)<<32 | uint64(bhfi.FileSizeLow))
		info.blocks = (info.size + 511) / 512
	}
	if bhfi.FileAttributes&windows.FILE_ATTRIBUTE_READONLY != 0 {
		info.perm &^= 0o222
	}
	return info, nil
}

// finalPathLeaf returns the last component of the normalized name of an open
// handle. The normalized name carries the stored case and the long form of
// the name. It differs from the requested name when the volume matched the
// request case-insensitively or through a short 8.3 name.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew
func finalPathLeaf(handle windows.Handle) (string, error) {
	var stack [512]uint16
	buf := stack[:]
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), finalPathNormalizedNoVolume)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			buf = buf[:n]
			break
		}
		// The result did not fit. n is the required size with the NUL.
		buf = make([]uint16, int(n)+1)
	}
	i := len(buf)
	for i > 0 && buf[i-1] != '\\' {
		i--
	}
	return windows.UTF16ToString(buf[i:]), nil
}

func (h *hostRoot) lstat(rel string) (hostInfo, error) {
	if rel == "." {
		info, err := statHandle(h.handle)
		if err != nil {
			return hostInfo{}, hostError("lstat", rel, err)
		}
		return info, nil
	}
	parent, err := h.walkParent("lstat", rel)
	if err != nil {
		return hostInfo{}, err
	}
	defer parent.release()
	return lstatIn(parent.handle, parent.name, rel)
}

// lstatIn reads the metadata of the entry name inside the directory handle
// dir without following a reparse point. It fails with errNameMismatch when
// the stored name differs from name in case or through a short alias. The
// path rel only labels errors.
func lstatIn(dir windows.Handle, name, rel string) (hostInfo, error) {
	handle, err := openAt(dir, name, windows.FILE_READ_ATTRIBUTES, windows.FILE_ATTRIBUTE_NORMAL, windows.FILE_OPEN, 0)
	if err != nil {
		return hostInfo{}, hostError("lstat", rel, err)
	}
	defer closeHandle(handle)
	stored, err := finalPathLeaf(handle)
	if err != nil {
		return hostInfo{}, hostError("lstat", rel, err)
	}
	if stored != name {
		return hostInfo{}, fmt.Errorf("hostfs: lstat %q: %w: %w", rel, errNameMismatch, windows.ERROR_FILE_NOT_FOUND)
	}
	info, err := statHandle(handle)
	if err != nil {
		return hostInfo{}, hostError("lstat", rel, err)
	}
	return info, nil
}

func (h *hostRoot) fstat(f *os.File) (hostInfo, error) {
	rc, err := f.SyscallConn()
	if err != nil {
		return hostInfo{}, hostError("fstat", f.Name(), err)
	}
	var info hostInfo
	var statErr error
	if err := rc.Control(func(fd uintptr) {
		info, statErr = statHandle(windows.Handle(fd))
	}); err != nil {
		return hostInfo{}, hostError("fstat", f.Name(), err)
	}
	if statErr != nil {
		return hostInfo{}, hostError("fstat", f.Name(), statErr)
	}
	return info, nil
}

func (h *hostRoot) mkdir(rel string) error {
	if rel == "." {
		return hostError("mkdir", rel, windows.ERROR_ALREADY_EXISTS)
	}
	parent, err := h.walkParent("mkdir", rel)
	if err != nil {
		return err
	}
	defer parent.release()
	handle, err := openAt(parent.handle, parent.name, windows.FILE_READ_ATTRIBUTES, windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_CREATE, windows.FILE_DIRECTORY_FILE)
	if err != nil {
		return hostError("mkdir", rel, err)
	}
	closeHandle(handle)
	return nil
}

// parseSymlinkReparse extracts the target of a symbolic link from the output
// of FSCTL_GET_REPARSE_POINT. It returns the substitute name with "/" as the
// separator. An absolute target always starts with "/", so that callers reject
// it as an escape. A buffer for another tag returns ERROR_NOT_A_REPARSE_POINT.
// Source: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_reparse_data_buffer
func parseSymlinkReparse(data []byte) (string, error) {
	if len(data) < 4 || binary.LittleEndian.Uint32(data) != windows.IO_REPARSE_TAG_SYMLINK {
		return "", windows.ERROR_NOT_A_REPARSE_POINT
	}
	if len(data) < reparseSymlinkHeaderSize {
		return "", windows.ERROR_INVALID_DATA
	}
	offset := int(binary.LittleEndian.Uint16(data[8:]))
	length := int(binary.LittleEndian.Uint16(data[10:]))
	flags := binary.LittleEndian.Uint32(data[16:])
	pathBuffer := data[reparseSymlinkHeaderSize:]
	if offset%2 != 0 || length%2 != 0 || offset+length > len(pathBuffer) {
		return "", windows.ERROR_INVALID_DATA
	}
	units := make([]uint16, length/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(pathBuffer[offset+2*i:])
	}
	target := windows.UTF16ToString(units)
	if flags&symlinkFlagRelative == 0 {
		// Strip the NT object prefix, as os.Readlink does.
		target = strings.TrimPrefix(target, `\??\`)
		if strings.HasPrefix(target, `UNC\`) {
			target = `\` + target[len("UNC"):]
		}
		target = strings.ReplaceAll(target, `\`, "/")
		if !strings.HasPrefix(target, "/") {
			target = "/" + target
		}
		return target, nil
	}
	return strings.ReplaceAll(target, `\`, "/"), nil
}

func (h *hostRoot) readlink(rel string) (string, error) {
	if rel == "." {
		return "", hostError("readlink", rel, windows.ERROR_NOT_A_REPARSE_POINT)
	}
	// FSCTL_GET_REPARSE_POINT needs no access beyond a valid handle (the
	// control code is FILE_ANY_ACCESS), so FILE_READ_ATTRIBUTES suffices.
	// Source: https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_get_reparse_point
	handle, err := h.openAny("readlink", rel, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return "", err
	}
	defer closeHandle(handle)
	buf := make([]byte, windows.MAXIMUM_REPARSE_DATA_BUFFER_SIZE)
	var returned uint32
	if err := windows.DeviceIoControl(handle, windows.FSCTL_GET_REPARSE_POINT, nil, 0,
		&buf[0], uint32(len(buf)), &returned, nil); err != nil {
		return "", hostError("readlink", rel, err)
	}
	target, err := parseSymlinkReparse(buf[:returned])
	if err != nil {
		return "", hostError("readlink", rel, err)
	}
	return target, nil
}

// errMalformedDirBuffer reports a directory listing buffer that violates the
// FILE_FULL_DIR_INFO layout. It has no Linux equivalent, so callers see EIO.
var errMalformedDirBuffer = errors.New("hostfs: malformed directory listing buffer")

// parseDirBuffer appends the entries of one FILE_FULL_DIR_INFO buffer to out.
// It skips "." and "..". It also skips names that validateWindowsName rejects,
// because hostfs refuses to resolve such a name and a guest could not use it.
// With FILE_ATTRIBUTE_REPARSE_POINT set, EaSize holds the reparse tag.
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/e8d926d1-3a22-4654-be9c-58317a85540b
func parseDirBuffer(buf []byte, out []hostDirEntry) ([]hostDirEntry, error) {
	off := 0
	for {
		if off < 0 || off+dirInfoNameOffset > len(buf) {
			return out, errMalformedDirBuffer
		}
		entry := buf[off:]
		next := int(binary.LittleEndian.Uint32(entry))
		attrs := binary.LittleEndian.Uint32(entry[dirInfoAttributesOffset:])
		nameLen := int(binary.LittleEndian.Uint32(entry[dirInfoNameLengthOffset:]))
		eaSize := binary.LittleEndian.Uint32(entry[dirInfoEaSizeOffset:])
		if nameLen%2 != 0 || dirInfoNameOffset+nameLen > len(entry) {
			return out, errMalformedDirBuffer
		}
		units := make([]uint16, nameLen/2)
		for i := range units {
			units[i] = binary.LittleEndian.Uint16(entry[dirInfoNameOffset+2*i:])
		}
		name := windows.UTF16ToString(units)
		if name != "." && name != ".." && validateWindowsName(name) == nil {
			out = append(out, hostDirEntry{name: name, kind: dirEntryKind(attrs, eaSize)})
		}
		if next == 0 {
			return out, nil
		}
		off += next
	}
}

// dirEntryKind classifies a directory entry from its attributes and, for a
// reparse point, from the tag in EaSize.
func dirEntryKind(attrs, eaSize uint32) hostKind {
	switch {
	case attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		if eaSize == windows.IO_REPARSE_TAG_SYMLINK {
			return hostKindSymlink
		}
		return hostKindOther
	case attrs&windows.FILE_ATTRIBUTE_DEVICE != 0:
		return hostKindOther
	case attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0:
		return hostKindDir
	}
	return hostKindRegular
}

func (h *hostRoot) readDir(rel string) ([]hostDirEntry, error) {
	handle, err := h.openDirHandle("read directory", rel, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return nil, err
	}
	defer closeHandle(handle)
	// The kernel requires an 8-byte aligned buffer. A large Go allocation
	// meets this, and the explicit uint64 backing makes the guarantee local.
	backing := make([]uint64, dirBufferSize/8)
	buf := unsafe.Slice((*byte)(unsafe.Pointer(&backing[0])), dirBufferSize)
	var out []hostDirEntry
	class := uint32(windows.FileFullDirectoryRestartInfo)
	for {
		err := windows.GetFileInformationByHandleEx(handle, class, &buf[0], uint32(len(buf)))
		if err == windows.ERROR_NO_MORE_FILES {
			break
		}
		// Some file systems answer the first query of an empty directory with
		// ERROR_FILE_NOT_FOUND instead of listing "." and "..".
		if err == windows.ERROR_FILE_NOT_FOUND && class == windows.FileFullDirectoryRestartInfo {
			break
		}
		if err != nil {
			return nil, hostError("read directory", rel, err)
		}
		class = windows.FileFullDirectoryInfo
		if out, err = parseDirBuffer(buf, out); err != nil {
			return nil, hostError("read directory", rel, err)
		}
	}
	return out, nil
}

// syncDir proves that the directory exists and is not a reparse point. It
// cannot flush: FlushFileBuffers needs a handle with GENERIC_WRITE and does
// not accept directory handles, and Windows offers no other directory flush
// call. NTFS journals directory entry changes, but this function does not
// claim durability beyond that.
// Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers
func (h *hostRoot) syncDir(rel string) error {
	handle, err := h.openDirHandle("sync directory", rel, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	closeHandle(handle)
	return nil
}

func (h *hostRoot) chtimes(rel string, atime, mtime *time.Time) error {
	var atimeFT, mtimeFT *windows.Filetime
	if atime != nil {
		ft, err := timeToFiletime(*atime)
		if err != nil {
			return hostError("set times", rel, err)
		}
		atimeFT = &ft
	}
	if mtime != nil {
		ft, err := timeToFiletime(*mtime)
		if err != nil {
			return hostError("set times", rel, err)
		}
		mtimeFT = &ft
	}
	handle, err := h.openAny("set times", rel, windows.FILE_WRITE_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer closeHandle(handle)
	// A nil pointer leaves that time unchanged. The creation time stays as is.
	// Source: https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-setfiletime
	if err := windows.SetFileTime(handle, nil, atimeFT, mtimeFT); err != nil {
		return hostError("set times", rel, err)
	}
	return nil
}
