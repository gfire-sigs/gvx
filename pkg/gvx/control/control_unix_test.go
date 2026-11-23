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

//go:build unix

package control

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestControlUnixSecurityAndErrnos(t *testing.T) {
	// Reject symlinked socket directory.
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	symDir := filepath.Join(base, "sym")
	if err := os.Symlink(realDir, symDir); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureSocketDir(symDir); err == nil {
		t.Fatal("ensureSecureSocketDir accepted symlink directory")
	}

	// Reject world-writable socket directory.
	openDir := filepath.Join(base, "open")
	if err := os.Mkdir(openDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(openDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureSocketDir(openDir); err == nil {
		t.Fatal("ensureSecureSocketDir accepted mode 0777 directory")
	}

	// Verify Unix errno translations including specific errnos that also match os.Err*.
	for _, tc := range []struct {
		err  error
		want int
	}{
		{nil, 0},
		{os.ErrNotExist, LinuxENOENT},
		{syscall.ENOENT, LinuxENOENT},
		{os.ErrExist, LinuxEEXIST},
		{syscall.EEXIST, LinuxEEXIST},
		{os.ErrPermission, LinuxEACCES},
		{syscall.EACCES, LinuxEACCES},
		{syscall.EPERM, LinuxEPERM},
		{syscall.EBUSY, LinuxEBUSY},
		{syscall.EXDEV, LinuxEXDEV},
		{syscall.ENOTDIR, LinuxENOTDIR},
		{syscall.EISDIR, LinuxEISDIR},
		{syscall.ENAMETOOLONG, LinuxENAMETOOLONG},
		{syscall.ENOTEMPTY, LinuxENOTEMPTY},
		{syscall.ELOOP, LinuxELOOP},
		{syscall.EINVAL, LinuxEINVAL},
		{syscall.EROFS, LinuxEROFS},
		{syscall.ENOSPC, LinuxENOSPC},
		{syscall.EOPNOTSUPP, LinuxEOPNOTSUPP},
		{errors.New("unmapped unix error"), LinuxEIO},
	} {
		if got := HostErrorToLinuxErrno(tc.err); got != tc.want {
			t.Errorf("HostErrorToLinuxErrno(%v) = %d, want %d", tc.err, got, tc.want)
		}
	}
}
