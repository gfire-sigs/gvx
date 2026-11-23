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

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCheckpointReadsOwnerAndSystemInheritedToken(t *testing.T) {
	dir := t.TempDir()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	owner := user.User.Sid.String()
	sddl := "D:P(A;OICI;FA;;;" + owner + ")"
	if !user.User.Sid.IsWellKnown(windows.WinLocalSystemSid) {
		sddl += "(A;OICI;FA;;;SY)"
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	acl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
	address := filepath.Join(dir, "checkpoint.sock")
	path := address + ".token"
	want := strings.Repeat("e1", controlTokenBytes)
	if err := os.WriteFile(path, []byte(want+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if token, err := readCheckpointControlToken("unix", address); err != nil || token != want {
		t.Fatalf("read checkpoint token: match = %t, err = %v", token == want, err)
	}
	if _, err := readControlToken("unix", address); !errors.Is(err, errUnsafeControlDACL) {
		t.Errorf("strict reader accepted an inherited ACL: %v", err)
	}
}
