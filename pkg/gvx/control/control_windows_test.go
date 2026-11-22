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

package control

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsTokenFileDACLAndSocketDirChecks(t *testing.T) {
	base := t.TempDir()

	// ensureSecureSocketDir creates a missing directory and rejects a regular file.
	subDir := filepath.Join(base, "sockdir")
	if err := ensureSecureSocketDir(subDir); err != nil {
		t.Fatalf("ensureSecureSocketDir(new dir): %v", err)
	}
	notDir := filepath.Join(base, "file.txt")
	if err := os.WriteFile(notDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ensureSecureSocketDir(notDir); err == nil {
		t.Fatal("ensureSecureSocketDir accepted a regular file")
	}

	// writeTokenFilePlatform writes the token with a protected owner-only DACL.
	tokPath := filepath.Join(subDir, "ctrl.token")
	if err := writeTokenFilePlatform(tokPath, "win-secret-token"); err != nil {
		t.Fatalf("writeTokenFilePlatform: %v", err)
	}
	raw, err := os.ReadFile(tokPath)
	if err != nil || string(raw) != "win-secret-token\n" {
		t.Fatalf("token file content = (%q, %v), want %q", raw, err, "win-secret-token\n")
	}

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("GetTokenUser: %v", err)
	}
	ownerSID := user.User.Sid.String()

	sd, err := windows.GetNamedSecurityInfo(
		tokPath,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		t.Fatalf("GetNamedSecurityInfo(%q): %v", tokPath, err)
	}
	sddl := sd.String()
	if !strings.Contains(sddl, "D:P") {
		t.Fatalf("token file SDDL %q lacks protected DACL (D:P)", sddl)
	}
	if !strings.Contains(sddl, ownerSID) && !(ownerSID == "S-1-5-18" && strings.Contains(sddl, ";SY)")) {
		t.Fatalf("token file SDDL %q does not grant access to owner SID %s", sddl, ownerSID)
	}
	for _, forbidden := range []string{";WD)", ";BU)", ";AU)", "S-1-1-0", "S-1-5-32-545", "S-1-5-11"} {
		if strings.Contains(sddl, forbidden) {
			t.Fatalf("token file SDDL %q contains forbidden broad ACE %q", sddl, forbidden)
		}
	}

	// Rewriting replaces the stale token cleanly with the same DACL protection.
	if err := writeTokenFilePlatform(tokPath, "rotated-token"); err != nil {
		t.Fatalf("writeTokenFilePlatform(rewrite): %v", err)
	}
	raw2, err := os.ReadFile(tokPath)
	if err != nil || string(raw2) != "rotated-token\n" {
		t.Fatalf("rewritten token content = (%q, %v), want rotated-token", raw2, err)
	}
}

func TestWindowsHostErrorToLinuxErrnoMappings(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, 0},
		{"not-exist", os.ErrNotExist, LinuxENOENT},
		{"exist", os.ErrExist, LinuxEEXIST},
		{"permission", os.ErrPermission, LinuxEACCES},
		{"eperm", syscall.EPERM, LinuxEPERM},
		{"busy", winErrBusy, LinuxEBUSY},
		{"sharing-violation", winErrSharingViol, LinuxEBUSY},
		{"lock-violation", winErrLockViol, LinuxEBUSY},
		{"not-same-device", winErrNotSameDevice, LinuxEXDEV},
		{"not-dir", winErrDirectory, LinuxENOTDIR},
		{"is-dir", syscall.EISDIR, LinuxEISDIR},
		{"name-too-long", winErrNameTooLong, LinuxENAMETOOLONG},
		{"dir-not-empty", winErrDirNotEmpty, LinuxENOTEMPTY},
		{"cant-resolve", winErrCantResolve, LinuxELOOP},
		{"invalid-param", winErrInvalidParam, LinuxEINVAL},
		{"write-protect", winErrWriteProtect, LinuxEROFS},
		{"disk-full", winErrDiskFull, LinuxENOSPC},
		{"not-supported", winErrNotSupported, LinuxEOPNOTSUPP},
		{"fallback-eio", errors.New("unmapped windows error"), LinuxEIO},
	}
	for _, tc := range cases {
		if got := HostErrorToLinuxErrno(tc.err); got != tc.want {
			t.Errorf("%s: HostErrorToLinuxErrno(%v) = %d, want %d", tc.name, tc.err, got, tc.want)
		}
	}
}
