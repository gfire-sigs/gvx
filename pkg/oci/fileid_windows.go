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
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	publishViaOpenTempHandle = false

	winFiletimeTicksPerSec   = 10_000_000
	winFiletimeToUnixSeconds = 11644473600
)

// ociFileIDInfo matches Win32 FILE_ID_INFO.
type ociFileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

// ociFileBasicInfo matches Win32 FILE_BASIC_INFO with explicit trailing
// alignment padding to match the 40-byte C layout.
type ociFileBasicInfo struct {
	CreationTime   int64
	LastAccessTime int64
	LastWriteTime  int64
	ChangeTime     int64
	FileAttributes uint32
	_              uint32
}

// fileIdentity returns the Windows file identity of f from FileIdInfo and
// FileBasicInfo. Volumes that do not support 128-bit FileIdInfo (such as FAT,
// exFAT, or network shares) or report zero timestamps return ok=false so
// verification falls back to full SHA-256 hashing.
func fileIdentity(f *os.File) (fileID, bool) {
	rc, err := f.SyscallConn()
	if err != nil {
		return fileID{}, false
	}
	var (
		idInfo   ociFileIDInfo
		basic    ociFileBasicInfo
		queryErr error
	)
	if err := rc.Control(func(fd uintptr) {
		h := windows.Handle(fd)
		if err := windows.GetFileInformationByHandleEx(
			h, windows.FileIdInfo,
			(*byte)(unsafe.Pointer(&idInfo)), uint32(unsafe.Sizeof(idInfo)),
		); err != nil {
			queryErr = err
			return
		}
		if err := windows.GetFileInformationByHandleEx(
			h, windows.FileBasicInfo,
			(*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic)),
		); err != nil {
			queryErr = err
			return
		}
	}); err != nil || queryErr != nil {
		return fileID{}, false
	}
	runtime.KeepAlive(f)

	if idInfo.FileID == ([16]byte{}) || basic.LastWriteTime <= 0 || basic.ChangeTime <= 0 {
		return fileID{}, false
	}
	idLo := binary.LittleEndian.Uint64(idInfo.FileID[0:8])
	idHi := binary.LittleEndian.Uint64(idInfo.FileID[8:16])
	changeTicks := uint64(basic.ChangeTime)
	changeTime := time.Unix(
		int64(changeTicks/winFiletimeTicksPerSec)-winFiletimeToUnixSeconds,
		int64(changeTicks%winFiletimeTicksPerSec)*100,
	)
	return fileID{
		token:      fmt.Sprintf("w1:%x:%x:%x:%d:%d", idInfo.VolumeSerialNumber, idLo, idHi, basic.LastWriteTime, basic.ChangeTime),
		handleKey:  fmt.Sprintf("w1:%x:%x:%x", idInfo.VolumeSerialNumber, idLo, idHi),
		writeStamp: strconv.FormatInt(basic.LastWriteTime, 10),
		coarse:     basic.LastWriteTime%winFiletimeTicksPerSec == 0 && basic.ChangeTime%winFiletimeTicksPerSec == 0,
		changeTime: changeTime,
	}, true
}
