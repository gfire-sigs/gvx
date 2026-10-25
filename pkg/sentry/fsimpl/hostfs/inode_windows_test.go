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
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fd"
)

// winTestHost returns a hostRoot over a fresh temporary directory and the
// absolute path of that directory. The path serves only to create host
// objects that hostRoot cannot create, such as symbolic links.
func winTestHost(t *testing.T) (*hostRoot, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot(%q) = %v", dir, err)
	}
	t.Cleanup(func() { _ = root.Close() })
	h, err := newHostRoot(root)
	if err != nil {
		t.Fatalf("newHostRoot() = %v", err)
	}
	t.Cleanup(func() {
		if err := h.close(); err != nil {
			t.Errorf("hostRoot.close() = %v", err)
		}
	})
	return h, dir
}

func winTestWrite(t *testing.T, h *hostRoot, rel, content string) {
	t.Helper()
	f, err := h.open(rel, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open(%q, create) = %v", rel, err)
	}
	if _, err := f.WriteString(content); err != nil {
		_ = f.Close()
		t.Fatalf("write %q = %v", rel, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %q = %v", rel, err)
	}
}

func winTestRead(t *testing.T, h *hostRoot, rel string) string {
	t.Helper()
	f, err := h.open(rel, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open(%q) = %v", rel, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read %q = %v", rel, err)
	}
	return string(data)
}

func winTestErrno(t *testing.T, err error, want error) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %v", want)
	}
	got, ok := hostErrno(err)
	if !ok || got != want {
		t.Fatalf("hostErrno(%v) = (%v, %v), want (%v, true)", err, got, ok, want)
	}
}

func TestWindowsHostValidateName(t *testing.T) {
	valid := []string{
		"a", "file.txt", ".gitignore", "a b", "COM10", "COM", "LPT", "CONSOLE",
		"nullable", "\u00fcn\u00ef", "a.b.c", "x$", "CON1",
	}
	invalid := []string{
		"", ".", "..", "a:b", "a:b:$DATA", `a\b`, "a/b", "a*", "a?", `a"`, "a<", "a>", "a|",
		"a\x01", "a\x1f", "a ", "a.", "CON", "con", "Prn", "AUX", "NUL", "NUL.txt", "aux.tar.gz",
		"COM0", "COM1", "COM9", "lpt1", "LPT9", "COM\u00b9", "LPT\u00b3", "nul .txt", "CONIN$",
		"CONOUT$", "bad\xffutf8",
	}
	for _, name := range valid {
		if err := validateWindowsName(name); err != nil {
			t.Errorf("validateWindowsName(%q) = %v, want nil", name, err)
		}
	}
	for _, name := range invalid {
		if err := validateWindowsName(name); !errors.Is(err, errInvalidHostName) {
			t.Errorf("validateWindowsName(%q) = %v, want errInvalidHostName", name, err)
		}
	}
}

func winTestSymlinkBuffer(tag uint32, substitute string, flags uint32) []byte {
	units := utf16.Encode([]rune(substitute))
	pathBytes := len(units) * 2
	buf := make([]byte, reparseSymlinkHeaderSize+2*pathBytes)
	binary.LittleEndian.PutUint32(buf[0:], tag)
	binary.LittleEndian.PutUint16(buf[4:], uint16(12+2*pathBytes))
	binary.LittleEndian.PutUint16(buf[8:], 0)
	binary.LittleEndian.PutUint16(buf[10:], uint16(pathBytes))
	binary.LittleEndian.PutUint16(buf[12:], uint16(pathBytes))
	binary.LittleEndian.PutUint16(buf[14:], uint16(pathBytes))
	binary.LittleEndian.PutUint32(buf[16:], flags)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[reparseSymlinkHeaderSize+2*i:], u)
		binary.LittleEndian.PutUint16(buf[reparseSymlinkHeaderSize+pathBytes+2*i:], u)
	}
	return buf
}

func TestWindowsHostParseSymlinkReparse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		want    string
		wantErr error
	}{
		{name: "relative", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, `..\a\b`, symlinkFlagRelative), want: "../a/b"},
		{name: "relative single", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, "target", symlinkFlagRelative), want: "target"},
		{name: "absolute drive", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, `\??\C:\x\y`, 0), want: "/C:/x/y"},
		{name: "absolute unc", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, `\??\UNC\srv\sh\f`, 0), want: "//srv/sh/f"},
		{name: "mount point", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_MOUNT_POINT, `\??\C:\x`, 0), wantErr: windows.ERROR_NOT_A_REPARSE_POINT},
		{name: "empty", data: nil, wantErr: windows.ERROR_NOT_A_REPARSE_POINT},
		{name: "short header", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, "a", 0)[:12], wantErr: windows.ERROR_INVALID_DATA},
		{name: "truncated path", data: winTestSymlinkBuffer(windows.IO_REPARSE_TAG_SYMLINK, "abcdef", 0)[:reparseSymlinkHeaderSize+4], wantErr: windows.ERROR_INVALID_DATA},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseSymlinkReparse(tc.data)
			if !errors.Is(err, tc.wantErr) && err != tc.wantErr {
				t.Fatalf("parseSymlinkReparse() error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr == nil && got != tc.want {
				t.Fatalf("parseSymlinkReparse() = %q, want %q", got, tc.want)
			}
		})
	}
}

func winTestDirEntry(attrs, eaSize uint32, name string, last bool) []byte {
	units := utf16.Encode([]rune(name))
	nameBytes := len(units) * 2
	size := (dirInfoNameOffset + nameBytes + 7) &^ 7
	buf := make([]byte, size)
	if !last {
		binary.LittleEndian.PutUint32(buf[0:], uint32(size))
	}
	binary.LittleEndian.PutUint32(buf[dirInfoAttributesOffset:], attrs)
	binary.LittleEndian.PutUint32(buf[dirInfoNameLengthOffset:], uint32(nameBytes))
	binary.LittleEndian.PutUint32(buf[dirInfoEaSizeOffset:], eaSize)
	for i, u := range units {
		binary.LittleEndian.PutUint16(buf[dirInfoNameOffset+2*i:], u)
	}
	return buf
}

func TestWindowsHostParseDirBuffer(t *testing.T) {
	const (
		reparse = windows.FILE_ATTRIBUTE_REPARSE_POINT
		dirAttr = windows.FILE_ATTRIBUTE_DIRECTORY
	)
	var buf []byte
	buf = append(buf, winTestDirEntry(dirAttr, 0, ".", false)...)
	buf = append(buf, winTestDirEntry(dirAttr, 0, "..", false)...)
	buf = append(buf, winTestDirEntry(windows.FILE_ATTRIBUTE_ARCHIVE, 0, "a.txt", false)...)
	buf = append(buf, winTestDirEntry(dirAttr, 7, "dir", false)...)
	buf = append(buf, winTestDirEntry(reparse, windows.IO_REPARSE_TAG_SYMLINK, "link", false)...)
	buf = append(buf, winTestDirEntry(reparse|dirAttr, windows.IO_REPARSE_TAG_SYMLINK, "dirlink", false)...)
	buf = append(buf, winTestDirEntry(reparse|dirAttr, windows.IO_REPARSE_TAG_MOUNT_POINT, "junction", false)...)
	buf = append(buf, winTestDirEntry(0, 0, "bad:name", false)...)
	buf = append(buf, winTestDirEntry(0, 0, "NUL", false)...)
	buf = append(buf, winTestDirEntry(0, 0, "tail", true)...)

	got, err := parseDirBuffer(buf, nil)
	if err != nil {
		t.Fatalf("parseDirBuffer() = %v", err)
	}
	want := []hostDirEntry{
		{name: "a.txt", kind: hostKindRegular},
		{name: "dir", kind: hostKindDir},
		{name: "link", kind: hostKindSymlink},
		{name: "dirlink", kind: hostKindSymlink},
		{name: "junction", kind: hostKindOther},
		{name: "tail", kind: hostKindRegular},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("parseDirBuffer() = %v, want %v", got, want)
	}

	lastSize := len(winTestDirEntry(0, 0, "tail", true))
	for _, cut := range []int{10, dirInfoNameOffset + 1, len(buf) - lastSize + dirInfoNameOffset + 3} {
		if _, err := parseDirBuffer(buf[:cut], nil); !errors.Is(err, errMalformedDirBuffer) {
			t.Errorf("parseDirBuffer(buf[:%d]) = %v, want errMalformedDirBuffer", cut, err)
		}
	}
}

func TestWindowsHostNameInfoLayout(t *testing.T) {
	var header fd.NameInfoHeader
	ptrSize := unsafe.Sizeof(uintptr(0))
	if got := unsafe.Offsetof(header.RootDirectory); got != ptrSize {
		t.Errorf("offset of RootDirectory = %d, want %d", got, ptrSize)
	}
	if got, want := unsafe.Offsetof(header.FileName), 2*ptrSize+4; got != want {
		t.Errorf("offset of FileName = %d, want %d", got, want)
	}

	buf, size, err := fd.NewNameInfo(0x3, 0x1234, "ab")
	if err != nil {
		t.Fatalf("NewNameInfo() = %v", err)
	}
	if size%8 != 0 || uintptr(size) < unsafe.Sizeof(header) || int(size) != len(buf)*8 {
		t.Errorf("NewNameInfo() size = %d for %d words, want a multiple of 8 not below %d", size, len(buf), unsafe.Sizeof(header))
	}
	got := (*fd.NameInfoHeader)(unsafe.Pointer(&buf[0]))
	if got.Flags != 0x3 || got.RootDirectory != 0x1234 || got.FileNameLength != 4 {
		t.Errorf("header = %+v, want Flags=3 RootDirectory=0x1234 FileNameLength=4", *got)
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&buf[0])), size)
	offset := unsafe.Offsetof(header.FileName)
	if name := windows.UTF16ToString(unsafe.Slice((*uint16)(unsafe.Pointer(&raw[offset])), 2)); name != "ab" {
		t.Errorf("FileName = %q, want %q", name, "ab")
	}

	long := strings.Repeat("x", 300)
	buf, size, err = fd.NewNameInfo(0, 1, long)
	if err != nil {
		t.Fatalf("NewNameInfo(long) = %v", err)
	}
	if want := (int(offset) + 600 + 7) / 8 * 8; int(size) != want {
		t.Errorf("NewNameInfo(long) size = %d, want %d", size, want)
	}
	if got := (*fd.NameInfoHeader)(unsafe.Pointer(&buf[0])); got.FileNameLength != 600 {
		t.Errorf("FileNameLength = %d, want 600", got.FileNameLength)
	}
}

func TestWindowsHostTimeConversion(t *testing.T) {
	want := time.Date(2024, 5, 17, 13, 45, 9, 123456700, time.UTC)
	ft, err := timeToFiletime(want)
	if err != nil {
		t.Fatalf("timeToFiletime() = %v", err)
	}
	ticks := uint64(ft.HighDateTime)<<32 | uint64(ft.LowDateTime)
	if got := filetimeToTime(ticks); !got.Equal(want) {
		t.Errorf("filetimeToTime(timeToFiletime(%v)) = %v", want, got)
	}
	if got, wantEpoch := filetimeToTime(0), time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC); !got.Equal(wantEpoch) {
		t.Errorf("filetimeToTime(0) = %v, want %v", got, wantEpoch)
	}
	if _, err := timeToFiletime(time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("timeToFiletime(1600) = %v, want fs.ErrInvalid", err)
	}
	if _, err := timeToFiletime(time.Date(40000, 1, 1, 0, 0, 0, 0, time.UTC)); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("timeToFiletime(40000) = %v, want fs.ErrInvalid", err)
	}
}

func TestWindowsHostErrnoMapping(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want error
	}{
		{"file not found", windows.ERROR_FILE_NOT_FOUND, linuxerr.ENOENT},
		{"path not found", windows.ERROR_PATH_NOT_FOUND, linuxerr.ENOENT},
		{"invalid name", windows.ERROR_INVALID_NAME, linuxerr.ENOENT},
		{"access denied", windows.ERROR_ACCESS_DENIED, linuxerr.EACCES},
		{"sharing violation", windows.ERROR_SHARING_VIOLATION, linuxerr.EBUSY},
		{"lock violation", windows.ERROR_LOCK_VIOLATION, linuxerr.EBUSY},
		{"dir not empty", windows.ERROR_DIR_NOT_EMPTY, linuxerr.ENOTEMPTY},
		{"directory", windows.ERROR_DIRECTORY, linuxerr.ENOTDIR},
		{"already exists", windows.ERROR_ALREADY_EXISTS, linuxerr.EEXIST},
		{"file exists", windows.ERROR_FILE_EXISTS, linuxerr.EEXIST},
		{"not same device", windows.ERROR_NOT_SAME_DEVICE, linuxerr.EXDEV},
		{"disk full", windows.ERROR_DISK_FULL, linuxerr.ENOSPC},
		{"handle disk full", windows.ERROR_HANDLE_DISK_FULL, linuxerr.ENOSPC},
		{"too many links", windows.ERROR_TOO_MANY_LINKS, linuxerr.EMLINK},
		{"not supported", windows.ERROR_NOT_SUPPORTED, linuxerr.EOPNOTSUPP},
		{"name too long", windows.ERROR_FILENAME_EXCED_RANGE, linuxerr.ENAMETOOLONG},
		{"buffer overflow", windows.ERROR_BUFFER_OVERFLOW, linuxerr.ENAMETOOLONG},
		{"write protect", windows.ERROR_WRITE_PROTECT, linuxerr.EROFS},
		{"privilege", windows.ERROR_PRIVILEGE_NOT_HELD, linuxerr.EPERM},
		{"not a reparse point", windows.ERROR_NOT_A_REPARSE_POINT, linuxerr.EINVAL},
		{"status not a directory", windows.STATUS_NOT_A_DIRECTORY, linuxerr.ENOTDIR},
		{"status is a directory", windows.STATUS_FILE_IS_A_DIRECTORY, linuxerr.EISDIR},
		{"status collision", windows.STATUS_OBJECT_NAME_COLLISION, linuxerr.EEXIST},
		{"status not supported", windows.STATUS_NOT_SUPPORTED, linuxerr.EOPNOTSUPP},
		{"status invalid device request", windows.STATUS_INVALID_DEVICE_REQUEST, linuxerr.EOPNOTSUPP},
		{"status name not found", windows.STATUS_OBJECT_NAME_NOT_FOUND, linuxerr.ENOENT},
		{"status directory not empty", windows.STATUS_DIRECTORY_NOT_EMPTY, linuxerr.ENOTEMPTY},
		{"status access denied", windows.STATUS_ACCESS_DENIED, linuxerr.EACCES},
		{"wrapped native error", &ntError{op: "unlink", path: "d", status: windows.STATUS_FILE_IS_A_DIRECTORY}, linuxerr.EISDIR},
		{"wrapped path error", &fs.PathError{Op: "x", Path: "p", Err: windows.ERROR_DIR_NOT_EMPTY}, linuxerr.ENOTEMPTY},
		{"wrapped fmt error", fmt.Errorf("outer: %w", fmt.Errorf("inner: %w", windows.ERROR_NOT_SAME_DEVICE)), linuxerr.EXDEV},
		{"invalid host name", fmt.Errorf("x: %w", errInvalidHostName), linuxerr.EINVAL},
		{"unsupported", fmt.Errorf("x: %w", errHostUnsupported), linuxerr.EOPNOTSUPP},
		{"invalid argument", fs.ErrInvalid, linuxerr.EINVAL},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			winTestErrno(t, tc.err, tc.want)
		})
	}
	for _, err := range []error{
		nil,
		errors.New("unrelated"),
		windows.ERROR_INVALID_PARAMETER,
		windows.ERROR_INVALID_FUNCTION,
		windows.ERROR_CANT_ACCESS_FILE,
		windows.STATUS_INVALID_PARAMETER,
	} {
		if got, ok := hostErrno(err); ok {
			t.Errorf("hostErrno(%v) = (%v, true), want unrecognized", err, got)
		}
	}
	if err := error(&ntError{op: "lstat", path: "p", status: windows.STATUS_OBJECT_NAME_NOT_FOUND}); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("errors.Is(ntError(NAME_NOT_FOUND), fs.ErrNotExist) = false, want true")
	}
	if err := error(&ntError{op: "mkdir", path: "p", status: windows.STATUS_OBJECT_NAME_COLLISION}); !errors.Is(err, fs.ErrExist) {
		t.Errorf("errors.Is(ntError(NAME_COLLISION), fs.ErrExist) = false, want true")
	}
}

func TestWindowsHostBasicOperations(t *testing.T) {
	h, _ := winTestHost(t)

	if h.caseInsensitive() {
		t.Errorf("caseInsensitive() = true, want false")
	}
	info, err := h.lstat(".")
	if err != nil {
		t.Fatalf("lstat(.) = %v", err)
	}
	if info.kind != hostKindDir || info.nlink < 1 || info.perm != 0o755 {
		t.Errorf("lstat(.) = %+v, want directory with nlink >= 1 and perm 0755", info)
	}

	if err := h.mkdir("d"); err != nil {
		t.Fatalf("mkdir(d) = %v", err)
	}
	winTestErrno(t, h.mkdir("d"), linuxerr.EEXIST)
	winTestErrno(t, h.mkdir("."), linuxerr.EEXIST)
	winTestErrno(t, h.mkdir("missing/child"), linuxerr.ENOENT)

	winTestWrite(t, h, "d/f.txt", "hello")
	if _, err := h.open("d/f.txt", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		t.Fatalf("open(O_EXCL) on existing file succeeded")
	} else {
		winTestErrno(t, err, linuxerr.EEXIST)
	}
	if _, err := h.open("d", os.O_RDONLY, 0); err == nil {
		t.Fatalf("open on directory succeeded")
	} else {
		winTestErrno(t, err, linuxerr.EISDIR)
	}
	if _, err := h.open("d/f.txt/x", os.O_RDONLY, 0); err == nil {
		t.Fatalf("open below a file succeeded")
	} else {
		winTestErrno(t, err, linuxerr.ENOTDIR)
	}
	if _, err := h.open("d/f.txt", os.O_RDONLY|os.O_APPEND, 0); !errors.Is(err, fs.ErrInvalid) {
		t.Errorf("open(O_APPEND) = %v, want fs.ErrInvalid", err)
	}

	info, err = h.lstat("d/f.txt")
	if err != nil {
		t.Fatalf("lstat(d/f.txt) = %v", err)
	}
	if info.kind != hostKindRegular || info.size != 5 || info.blocks != 1 || info.nlink != 1 || info.perm != 0o644 {
		t.Errorf("lstat(d/f.txt) = %+v, want regular size 5 blocks 1 nlink 1 perm 0644", info)
	}
	if info.mtime.IsZero() || info.btime.IsZero() || info.ctime.IsZero() || info.atime.IsZero() {
		t.Errorf("lstat(d/f.txt) times = %v %v %v %v, want all set", info.atime, info.mtime, info.ctime, info.btime)
	}

	// O_TRUNC truncates the open handle, and it works through fstat.
	f, err := h.open("d/f.txt", os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("open(O_TRUNC) = %v", err)
	}
	finfo, err := h.fstat(f)
	if err != nil {
		t.Fatalf("fstat() = %v", err)
	}
	if finfo.size != 0 || finfo.kind != hostKindRegular || finfo.id != info.id {
		t.Errorf("fstat() = %+v, want empty regular file with id %+v", finfo, info.id)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close = %v", err)
	}

	entries, err := h.readDir(".")
	if err != nil {
		t.Fatalf("readDir(.) = %v", err)
	}
	if want := []hostDirEntry{{name: "d", kind: hostKindDir}}; !slices.Equal(entries, want) {
		t.Errorf("readDir(.) = %v, want %v", entries, want)
	}
	entries, err = h.readDir("d")
	if err != nil {
		t.Fatalf("readDir(d) = %v", err)
	}
	if want := []hostDirEntry{{name: "f.txt", kind: hostKindRegular}}; !slices.Equal(entries, want) {
		t.Errorf("readDir(d) = %v, want %v", entries, want)
	}
	if _, err := h.readDir("d/f.txt"); err == nil {
		t.Errorf("readDir on a file succeeded")
	} else {
		winTestErrno(t, err, linuxerr.ENOTDIR)
	}

	winTestErrno(t, h.rmdir("d"), linuxerr.ENOTEMPTY)
	winTestErrno(t, h.unlink("d"), linuxerr.EISDIR)
	winTestErrno(t, h.rmdir("d/f.txt"), linuxerr.ENOTDIR)
	winTestErrno(t, h.unlink("."), linuxerr.EBUSY)
	winTestErrno(t, h.rmdir("."), linuxerr.EBUSY)
	if err := h.unlink("d/f.txt"); err != nil {
		t.Fatalf("unlink(d/f.txt) = %v", err)
	}
	if err := h.rmdir("d"); err != nil {
		t.Fatalf("rmdir(d) = %v", err)
	}
	if _, err := h.lstat("d"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lstat(d) after rmdir = %v, want not-exist", err)
	} else {
		winTestErrno(t, err, linuxerr.ENOENT)
	}

	if err := h.syncDir("."); err != nil {
		t.Errorf("syncDir(.) = %v", err)
	}
	winTestErrno(t, h.syncDir("missing"), linuxerr.ENOENT)
}

func TestWindowsHostRefusesInvalidNames(t *testing.T) {
	h, _ := winTestHost(t)
	for _, rel := range []string{"NUL", "nul.txt", "a:stream", "a:b:$DATA", "trailing.", "trailing ", `back\slash`, "q?", "COM1"} {
		if _, err := h.open(rel, os.O_CREATE|os.O_WRONLY, 0o600); !errors.Is(err, errInvalidHostName) {
			t.Errorf("open(%q) = %v, want errInvalidHostName", rel, err)
		}
		if _, err := h.lstat(rel); !errors.Is(err, errInvalidHostName) {
			t.Errorf("lstat(%q) = %v, want errInvalidHostName", rel, err)
		}
		if err := h.mkdir(rel); !errors.Is(err, errInvalidHostName) {
			t.Errorf("mkdir(%q) = %v, want errInvalidHostName", rel, err)
		}
	}
	winTestWrite(t, h, "ok", "x")
	if err := h.rename("ok", "NUL"); !errors.Is(err, errInvalidHostName) {
		t.Errorf("rename(ok, NUL) = %v, want errInvalidHostName", err)
	}
	if err := h.link("ok", "x:y"); !errors.Is(err, errInvalidHostName) {
		t.Errorf("link(ok, x:y) = %v, want errInvalidHostName", err)
	}
	if _, err := h.lstat("ok"); err != nil {
		t.Errorf("lstat(ok) = %v after refused operations", err)
	}
}

func TestWindowsHostPOSIXRenameOverOpenFile(t *testing.T) {
	h, _ := winTestHost(t)
	winTestWrite(t, h, "src", "new")
	winTestWrite(t, h, "dst", "old")
	held, err := h.open("dst", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open(dst) = %v", err)
	}
	defer held.Close()

	if err := h.rename("src", "dst"); err != nil {
		t.Fatalf("rename(src, dst) over an open file = %v", err)
	}
	if _, err := h.lstat("src"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lstat(src) after rename = %v, want not-exist", err)
	}
	if got := winTestRead(t, h, "dst"); got != "new" {
		t.Errorf("dst content after rename = %q, want %q", got, "new")
	}
	// The old handle keeps the replaced data.
	if _, err := held.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("seek = %v", err)
	}
	if data, err := io.ReadAll(held); err != nil || string(data) != "old" {
		t.Errorf("read through held handle = %q, %v, want %q", data, err, "old")
	}
}

func TestWindowsHostPOSIXRenameOfOpenFileAndAcrossDirs(t *testing.T) {
	h, _ := winTestHost(t)
	if err := h.mkdir("a"); err != nil {
		t.Fatalf("mkdir(a) = %v", err)
	}
	if err := h.mkdir("b"); err != nil {
		t.Fatalf("mkdir(b) = %v", err)
	}
	winTestWrite(t, h, "a/f", "data")
	held, err := h.open("a/f", os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open(a/f) = %v", err)
	}
	defer held.Close()
	if err := h.rename("a/f", "b/g"); err != nil {
		t.Fatalf("rename of an open file across directories = %v", err)
	}
	if got := winTestRead(t, h, "b/g"); got != "data" {
		t.Errorf("b/g content = %q, want %q", got, "data")
	}
	if _, err := held.Seek(0, io.SeekEnd); err != nil {
		t.Fatalf("seek = %v", err)
	}
	if _, err := held.WriteString("+more"); err != nil {
		t.Fatalf("write through the handle after rename = %v", err)
	}
	if err := held.Sync(); err != nil {
		t.Fatalf("sync = %v", err)
	}
	if got := winTestRead(t, h, "b/g"); got != "data+more" {
		t.Errorf("b/g content = %q, want %q", got, "data+more")
	}
}

func TestWindowsHostPOSIXUnlinkOfOpenFile(t *testing.T) {
	h, _ := winTestHost(t)
	winTestWrite(t, h, "f", "payload")
	held, err := h.open("f", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open(f) = %v", err)
	}
	defer held.Close()

	if err := h.unlink("f"); err != nil {
		t.Fatalf("unlink of an open file = %v", err)
	}
	if _, err := h.lstat("f"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("lstat(f) after unlink = %v, want not-exist", err)
	}
	data, err := io.ReadAll(held)
	if err != nil || string(data) != "payload" {
		t.Errorf("read through held handle = %q, %v, want %q", data, err, "payload")
	}
	// The name is free at once, so a new file can take it.
	winTestWrite(t, h, "f", "second")
	if got := winTestRead(t, h, "f"); got != "second" {
		t.Errorf("recreated f = %q, want %q", got, "second")
	}
}

func TestWindowsHostHardLinkIdentity(t *testing.T) {
	h, _ := winTestHost(t)
	winTestWrite(t, h, "orig", "shared")
	if err := h.link("orig", "alias"); err != nil {
		if got, ok := hostErrno(err); ok && (got == linuxerr.EOPNOTSUPP || got == linuxerr.EPERM) {
			t.Skipf("volume does not support hard links: %v", err)
		}
		t.Fatalf("link(orig, alias) = %v", err)
	}
	a, err := h.lstat("orig")
	if err != nil {
		t.Fatalf("lstat(orig) = %v", err)
	}
	b, err := h.lstat("alias")
	if err != nil {
		t.Fatalf("lstat(alias) = %v", err)
	}
	if a.id != b.id || a.nlink != 2 || b.nlink != 2 {
		t.Errorf("after link: orig = %+v, alias = %+v, want equal id and nlink 2", a, b)
	}
	if got := winTestRead(t, h, "alias"); got != "shared" {
		t.Errorf("alias content = %q, want %q", got, "shared")
	}
	winTestErrno(t, h.link("orig", "alias"), linuxerr.EEXIST)
	if err := h.unlink("orig"); err != nil {
		t.Fatalf("unlink(orig) = %v", err)
	}
	b, err = h.lstat("alias")
	if err != nil {
		t.Fatalf("lstat(alias) after unlink = %v", err)
	}
	if b.nlink != 1 {
		t.Errorf("alias nlink after unlink = %d, want 1", b.nlink)
	}
}

func TestWindowsHostCaseMismatchIsNotExist(t *testing.T) {
	h, _ := winTestHost(t)
	if err := h.mkdir("Dir"); err != nil {
		t.Fatalf("mkdir(Dir) = %v", err)
	}
	winTestWrite(t, h, "Dir/Case.txt", "x")
	for _, rel := range []string{"dir", "DIR", "Dir/case.txt", "Dir/CASE.TXT"} {
		_, err := h.lstat(rel)
		if !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("lstat(%q) = %v, want not-exist", rel, err)
			continue
		}
		winTestErrno(t, err, linuxerr.ENOENT)
	}
	if _, err := h.lstat("Dir/Case.txt"); err != nil {
		t.Errorf("lstat(Dir/Case.txt) = %v, want nil", err)
	}
	entries, err := h.readDir("Dir")
	if err != nil {
		t.Fatalf("readDir(Dir) = %v", err)
	}
	if want := []hostDirEntry{{name: "Case.txt", kind: hostKindRegular}}; !slices.Equal(entries, want) {
		t.Errorf("readDir(Dir) = %v, want %v", entries, want)
	}
}

func TestWindowsHostChtimes(t *testing.T) {
	h, _ := winTestHost(t)
	winTestWrite(t, h, "f", "x")
	if err := h.mkdir("d"); err != nil {
		t.Fatalf("mkdir(d) = %v", err)
	}
	atime := time.Date(2020, 1, 2, 3, 4, 5, 600, time.UTC)
	mtime := time.Date(2021, 6, 7, 8, 9, 10, 700, time.UTC)
	for _, rel := range []string{"f", "d"} {
		before, err := h.lstat(rel)
		if err != nil {
			t.Fatalf("lstat(%q) = %v", rel, err)
		}
		if err := h.chtimes(rel, nil, &mtime); err != nil {
			t.Fatalf("chtimes(%q, nil, mtime) = %v", rel, err)
		}
		after, err := h.lstat(rel)
		if err != nil {
			t.Fatalf("lstat(%q) = %v", rel, err)
		}
		if !after.mtime.Equal(mtime) {
			t.Errorf("mtime of %q = %v, want %v", rel, after.mtime, mtime)
		}
		if !after.btime.Equal(before.btime) {
			t.Errorf("btime of %q changed from %v to %v", rel, before.btime, after.btime)
		}
		if err := h.chtimes(rel, &atime, nil); err != nil {
			t.Fatalf("chtimes(%q, atime, nil) = %v", rel, err)
		}
		after, err = h.lstat(rel)
		if err != nil {
			t.Fatalf("lstat(%q) = %v", rel, err)
		}
		if !after.atime.Equal(atime) || !after.mtime.Equal(mtime) {
			t.Errorf("times of %q = %v, %v, want %v, %v", rel, after.atime, after.mtime, atime, mtime)
		}
	}
	winTestErrno(t, h.chtimes("missing", &atime, &mtime), linuxerr.ENOENT)
}

func winTestSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symbolic link (privilege or developer mode missing): %v", err)
	}
}

func winTestJunction(t *testing.T, link, target string) {
	t.Helper()
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("cannot create junction: %v: %s", err, out)
	}
}

func TestWindowsHostRefusesReparseComponents(t *testing.T) {
	for _, kind := range []string{"symlink", "junction"} {
		t.Run(kind, func(t *testing.T) {
			h, dir := winTestHost(t)
			if err := h.mkdir("real"); err != nil {
				t.Fatalf("mkdir(real) = %v", err)
			}
			winTestWrite(t, h, "real/file.txt", "inside")
			link := filepath.Join(dir, "via")
			if kind == "symlink" {
				winTestSymlink(t, filepath.Join(dir, "real"), link)
			} else {
				winTestJunction(t, link, filepath.Join(dir, "real"))
			}

			wantKind := hostKindSymlink
			if kind == "junction" {
				wantKind = hostKindOther
			}
			info, err := h.lstat("via")
			if err != nil {
				t.Fatalf("lstat(via) = %v", err)
			}
			if info.kind != wantKind {
				t.Errorf("lstat(via).kind = %v, want %v", info.kind, wantKind)
			}
			entries, err := h.readDir(".")
			if err != nil {
				t.Fatalf("readDir(.) = %v", err)
			}
			if want := []hostDirEntry{{name: "real", kind: hostKindDir}, {name: "via", kind: wantKind}}; !slices.Equal(entries, want) {
				t.Errorf("readDir(.) = %v, want %v", entries, want)
			}

			operations := map[string]func() error{
				"lstat":    func() error { _, err := h.lstat("via/file.txt"); return err },
				"open":     func() error { _, err := h.open("via/file.txt", os.O_RDONLY, 0); return err },
				"create":   func() error { _, err := h.open("via/new.txt", os.O_CREATE|os.O_WRONLY, 0o600); return err },
				"mkdir":    func() error { return h.mkdir("via/sub") },
				"readDir":  func() error { _, err := h.readDir("via"); return err },
				"openDir":  func() error { _, err := h.openDir("via"); return err },
				"syncDir":  func() error { return h.syncDir("via") },
				"unlink":   func() error { return h.unlink("via/file.txt") },
				"rmdir":    func() error { return h.rmdir("via/sub") },
				"renameFr": func() error { return h.rename("via/file.txt", "moved") },
				"renameTo": func() error { return h.rename("real/file.txt", "via/moved") },
				"linkFrom": func() error { return h.link("via/file.txt", "alias") },
				"linkTo":   func() error { return h.link("real/file.txt", "via/alias") },
				"chtimes":  func() error { now := time.Now(); return h.chtimes("via/file.txt", &now, &now) },
				"readlink": func() error { _, err := h.readlink("via/file.txt"); return err },
			}
			for name, op := range operations {
				if err := op(); !errors.Is(err, ErrPathTraversal) {
					t.Errorf("%s through a %s = %v, want ErrPathTraversal", name, kind, err)
				}
			}
			// The final component may be a reparse point for the operations
			// that name the link itself, but open refuses it.
			if _, err := h.open("via", os.O_RDONLY, 0); err == nil {
				t.Errorf("open(via) on a %s succeeded", kind)
			}
			if got := winTestRead(t, h, "real/file.txt"); got != "inside" {
				t.Errorf("real/file.txt = %q after refused operations, want %q", got, "inside")
			}
			if _, err := h.lstat("moved"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("lstat(moved) = %v, want not-exist", err)
			}
			winTestErrno(t, h.rmdir("via"), linuxerr.ENOTDIR)
			if kind == "symlink" {
				if err := h.unlink("via"); err != nil {
					t.Errorf("unlink(via) on a directory symbolic link = %v", err)
				}
				if got := winTestRead(t, h, "real/file.txt"); got != "inside" {
					t.Errorf("target changed by unlink of the link: %q", got)
				}
			}
		})
	}
}

func TestWindowsHostFileSymlink(t *testing.T) {
	h, dir := winTestHost(t)
	if err := h.mkdir("real"); err != nil {
		t.Fatalf("mkdir(real) = %v", err)
	}
	winTestWrite(t, h, "real/file.txt", "inside")
	winTestSymlink(t, `real\file.txt`, filepath.Join(dir, "flink"))

	info, err := h.lstat("flink")
	if err != nil {
		t.Fatalf("lstat(flink) = %v", err)
	}
	if info.kind != hostKindSymlink {
		t.Errorf("lstat(flink).kind = %v, want hostKindSymlink", info.kind)
	}
	if _, err := h.open("flink", os.O_RDONLY, 0); !errors.Is(err, ErrPathTraversal) {
		t.Errorf("open(flink) = %v, want ErrPathTraversal", err)
	}
	target, err := h.readlink("flink")
	if err != nil {
		t.Fatalf("readlink(flink) = %v", err)
	}
	if target != "real/file.txt" {
		t.Errorf("readlink(flink) = %q, want %q", target, "real/file.txt")
	}
	if _, err := h.readlink("real/file.txt"); err == nil {
		t.Errorf("readlink on a regular file succeeded")
	} else {
		winTestErrno(t, err, linuxerr.EINVAL)
	}
	if err := h.unlink("flink"); err != nil {
		t.Fatalf("unlink(flink) = %v", err)
	}
	if got := winTestRead(t, h, "real/file.txt"); got != "inside" {
		t.Errorf("target = %q after unlink of the link, want %q", got, "inside")
	}
}
