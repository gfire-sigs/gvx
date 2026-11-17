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

package gvx

import (
	"errors"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const invalidFileSizeLow = 0xFFFFFFFF

var procGetCompressedFileSizeW = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetCompressedFileSizeW")

func fileAllocatedBytes(path string, info os.FileInfo) int64 {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return info.Size()
	}
	var high uint32
	low, _, callErr := procGetCompressedFileSizeW.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&high)),
	)
	low32 := uint32(low)
	if low32 == invalidFileSizeLow && callErr != nil && !errors.Is(callErr, syscall.Errno(0)) {
		return info.Size()
	}
	return int64((uint64(high) << 32) | uint64(low32))
}
