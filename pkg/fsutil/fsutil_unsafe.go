// Copyright 2018 The gVisor Authors.
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

package fsutil

import (
	"bytes"
	"encoding/binary"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/syserr"
)

// UnixDirentMaxSize is the maximum size of unix.Dirent in bytes.
var UnixDirentMaxSize = int(unsafe.Sizeof(unix.Dirent{}))

// Utimensat is a convenience wrapper to make the utimensat(2) syscall. It
// additionally handles empty name.
func Utimensat(dirFd int, name string, times [2]unix.Timespec, flags int) error {
	// utimensat(2) doesn't accept empty name, instead name must be nil to make it
	// operate directly on 'dirFd' unlike other *at syscalls.
	var namePtr unsafe.Pointer
	if name != "" {
		nameBytes, err := unix.BytePtrFromString(name)
		if err != nil {
			return err
		}
		namePtr = unsafe.Pointer(nameBytes)
	}

	timesPtr := unsafe.Pointer(&times[0])

	if _, _, errno := unix.Syscall6(
		unix.SYS_UTIMENSAT,
		uintptr(dirFd),
		uintptr(namePtr),
		uintptr(timesPtr),
		uintptr(flags),
		0,
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

// RenameAt2 is a convenience wrapper to make the renameat syscall.
func RenameAt2(oldDirFD int, oldName string, newDirFD int, newName string, flags uint32) error {
	var oldNamePtr unsafe.Pointer
	if oldName != "" {
		nameBytes, err := unix.BytePtrFromString(oldName)
		if err != nil {
			return err
		}
		oldNamePtr = unsafe.Pointer(nameBytes)
	}
	var newNamePtr unsafe.Pointer
	if newName != "" {
		nameBytes, err := unix.BytePtrFromString(newName)
		if err != nil {
			return err
		}
		newNamePtr = unsafe.Pointer(nameBytes)
	}

	if _, _, errno := unix.Syscall6(
		unix.SYS_RENAMEAT2,
		uintptr(oldDirFD),
		uintptr(oldNamePtr),
		uintptr(newDirFD),
		uintptr(newNamePtr),
		uintptr(flags),
		0); errno != 0 {

		return syserr.FromHost(errno).ToError()
	}
	return nil
}

// ParseDirents parses dirents from buf. buf must have been populated by
// getdents64(2) syscall. It calls the handleDirent callback for each dirent.
func ParseDirents(buf []byte, handleDirent DirentHandler) {
	const (
		inoOff    = unsafe.Offsetof(unix.Dirent{}.Ino)
		offOff    = unsafe.Offsetof(unix.Dirent{}.Off)
		reclenOff = unsafe.Offsetof(unix.Dirent{}.Reclen)
		typeOff   = unsafe.Offsetof(unix.Dirent{}.Type)
		nameOff   = unsafe.Offsetof(unix.Dirent{}.Name)

		_ uint = uint(nameOff) - uint(inoOff+8)
		_ uint = uint(nameOff) - uint(offOff+8)
		_ uint = uint(nameOff) - uint(reclenOff+2)
		_ uint = uint(nameOff) - uint(typeOff+1)
	)
	for uintptr(len(buf)) >= nameOff {
		// Decode fixed header fields from buf[:nameOff] without dereferencing
		// a full unix.Dirent struct past the end of buf.
		hdr := buf[:nameOff]
		reclen := binary.NativeEndian.Uint16(hdr[reclenOff:])
		if reclen == 0 || uintptr(reclen) < nameOff || int(reclen) > len(buf) {
			break
		}
		ino := binary.NativeEndian.Uint64(hdr[inoOff:])
		off := int64(binary.NativeEndian.Uint64(hdr[offOff:]))
		ftype := hdr[typeOff]

		// Extract the null-terminated name within the record bounds.
		nameBuf := buf[nameOff:reclen]
		if nameLen := bytes.IndexByte(nameBuf, 0); nameLen >= 0 {
			nameBuf = nameBuf[:nameLen]
		}
		name := string(nameBuf)

		// Advance buf for the next dirent.
		buf = buf[reclen:]

		// Skip `.` and `..` entries. It is anyways ignored by the client. We also
		// don't want to leak information about `..`.
		if name == "." || name == ".." {
			continue
		}

		// Deliver results to caller.
		handleDirent(ino, off, ftype, name, reclen)
	}
}
