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

//go:build darwin

package hostlockdown

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const (
	sandboxExtClassRead      = "com.apple.app-sandbox.read"
	sandboxExtClassReadWrite = "com.apple.app-sandbox.read-write"
)

func sandboxExtIssueFileTrampoline()
func addrOfSandboxExtIssueFile() uintptr
func sandboxExtConsumeTrampoline()
func addrOfSandboxExtConsume() uintptr
func sandboxExtReleaseTrampoline()
func addrOfSandboxExtRelease() uintptr
func libcFreeTrampoline()
func addrOfLibcFree() uintptr

// IssueFileExtension issues a macOS Seatbelt file extension token for path.
// Callers invoke this from an unlocked client process before delegating a
// directory or file descriptor to a locked sandbox over SCM_RIGHTS.
func IssueFileExtension(path string, readOnly bool) (string, error) {
	if path == "" {
		return "", errors.New("hostlockdown: empty path for sandbox file extension")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: resolve extension path %q: %w", path, err)
	}
	realPath, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: eval symlinks %q: %w", abs, err)
	}
	if filepath.Dir(realPath) == realPath {
		return "", fmt.Errorf("hostlockdown: refusing sandbox file extension on filesystem root %q", realPath)
	}

	extClass := sandboxExtClassReadWrite
	if readOnly {
		extClass = sandboxExtClassRead
	}
	classBytes, err := unix.ByteSliceFromString(extClass)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: encode extension class: %w", err)
	}
	pathBytes, err := unix.ByteSliceFromString(realPath)
	if err != nil {
		return "", fmt.Errorf("hostlockdown: encode extension path: %w", err)
	}
	ptr, _, errno := darwinSyscall6(
		addrOfSandboxExtIssueFile(),
		uintptr(unsafe.Pointer(&classBytes[0])),
		uintptr(unsafe.Pointer(&pathBytes[0])),
		0,
		0,
		0,
		0,
	)
	runtime.KeepAlive(classBytes)
	runtime.KeepAlive(pathBytes)
	if ptr == 0 {
		if errno != 0 {
			return "", fmt.Errorf("hostlockdown: sandbox_extension_issue_file(%q): %w", realPath, errno)
		}
		return "", fmt.Errorf("hostlockdown: sandbox_extension_issue_file(%q) failed", realPath)
	}
	// Copy token into Go memory before freeing the C heap buffer. Reading the
	// C pointer through &ptr satisfies go vet's unsafeptr check.
	cStr := *(**byte)(unsafe.Pointer(&ptr))
	token := unix.BytePtrToString(cStr)
	darwinSyscall6(addrOfLibcFree(), ptr, 0, 0, 0, 0, 0)
	if token == "" {
		return "", fmt.Errorf("hostlockdown: sandbox_extension_issue_file(%q) returned empty token", realPath)
	}
	return token, nil
}

// ConsumeFileExtension activates a macOS Seatbelt file extension token in the
// current locked process and returns the handle to pass to ReleaseFileExtension.
func ConsumeFileExtension(token string) (int64, error) {
	if token == "" {
		return -1, errors.New("hostlockdown: empty sandbox file extension token")
	}
	tokBytes, err := unix.ByteSliceFromString(token)
	if err != nil {
		return -1, fmt.Errorf("hostlockdown: encode extension token: %w", err)
	}
	r1, _, errno := darwinSyscall6(
		addrOfSandboxExtConsume(),
		uintptr(unsafe.Pointer(&tokBytes[0])),
		0,
		0,
		0,
		0,
		0,
	)
	runtime.KeepAlive(tokBytes)
	handle := int64(r1)
	if handle < 0 {
		return -1, fmt.Errorf("hostlockdown: sandbox_extension_consume: %w", errno)
	}
	return handle, nil
}

// ReleaseFileExtension revokes a previously consumed macOS Seatbelt file
// extension handle. Negative handles are ignored.
func ReleaseFileExtension(handle int64) error {
	if handle < 0 {
		return nil
	}
	r1, _, errno := darwinSyscall6(
		addrOfSandboxExtRelease(),
		uintptr(handle),
		0,
		0,
		0,
		0,
		0,
	)
	if int32(r1) != 0 {
		return fmt.Errorf("hostlockdown: sandbox_extension_release(%d): %w", handle, errno)
	}
	return nil
}

//go:cgo_import_dynamic libc_sandbox_extension_issue_file sandbox_extension_issue_file "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sandbox_extension_consume sandbox_extension_consume "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_sandbox_extension_release sandbox_extension_release "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_free free "/usr/lib/libSystem.B.dylib"
