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

package unix

import (
	"runtime"
	"unsafe"
)

//go:cgo_import_dynamic libc_futimens futimens "/usr/lib/libSystem.B.dylib"

var libc_futimens_trampoline_addr uintptr

// Futimens sets access and modification times on fd at nanosecond precision.
func Futimens(fd int, times *[2]Timespec) error {
	_, _, errno := syscall_syscall(libc_futimens_trampoline_addr, uintptr(fd), uintptr(unsafe.Pointer(times)), 0)
	runtime.KeepAlive(times)
	if errno != 0 {
		return errnoErr(errno)
	}
	return nil
}
