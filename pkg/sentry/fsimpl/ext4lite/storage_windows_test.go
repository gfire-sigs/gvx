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

package ext4lite

import (
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// testUnsupportedErrors are the errors that mean "no allocation change".
var testUnsupportedErrors = []error{
	windows.ERROR_NOT_SUPPORTED,
	windows.ERROR_INVALID_PARAMETER,
	windows.STATUS_NOT_SUPPORTED,
}

// testFatalErrors are errors that the storage layer must return unchanged.
var testFatalErrors = []error{
	windows.ERROR_DISK_FULL,
	windows.ERROR_ACCESS_DENIED,
	windows.ERROR_LOCK_VIOLATION,
}

func TestStorageWindowsFileStaysDense(t *testing.T) {
	f := openTestFile(t, filepath.Join(t.TempDir(), "volume.ext4"))
	h, err := newHostFile(f)
	if err != nil {
		f.Close()
		t.Fatalf("newHostFile() failed: %v", err)
	}
	defer h.Close()

	if err := h.EnsureSize(16 * mib); err != nil {
		t.Fatalf("EnsureSize(16 MiB) failed: %v", err)
	}
	if h.Tier() == tierFallback {
		t.Skip("the temporary volume does not support allocation changes")
	}
	if got := mustSize(t, h); got != 16*mib {
		t.Errorf("Size() = %d, want %d", got, 16*mib)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info); err != nil {
		t.Fatalf("GetFileInformationByHandle() failed: %v", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_SPARSE_FILE != 0 {
		t.Error("the file has the sparse attribute, want a dense file")
	}
}
