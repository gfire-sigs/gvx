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
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func privatePolicyStoreDir(t testing.TB) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	path := filepath.Join(parent, "private")
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatalf("encode temporary directory name: %v", err)
	}
	sa := windows.SecurityAttributes{SecurityDescriptor: policyTestWindowsSecurity(t, "")}
	sa.Length = uint32(unsafe.Sizeof(sa))
	if err := windows.CreateDirectory(name, &sa); err != nil {
		t.Fatalf("create private temporary directory: %v", err)
	}
	return path
}

func policyTestWindowsSecurity(t testing.TB, extra string) *windows.SECURITY_DESCRIPTOR {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatalf("get current Windows account SID: %v", err)
	}
	owner := user.User.Sid.String()
	sd, err := windows.SecurityDescriptorFromString("O:" + owner + "D:P(A;;FA;;;" + owner + ")(A;;FA;;;SY)(A;;FA;;;BA)" + extra)
	if err != nil {
		t.Fatalf("create test security descriptor: %v", err)
	}
	return sd
}

func TestNetPolicyStoreRejectsWindowsDACLGrant(t *testing.T) {
	for _, directory := range []bool{false, true} {
		name := "file"
		if directory {
			name = "parent"
		}
		t.Run(name, func(t *testing.T) {
			dir := privatePolicyStoreDir(t)
			path := filepath.Join(dir, "policy")
			seed := policyStoreTestConfig("ACCEPT")
			mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
			sd := policyTestWindowsSecurity(t, "(A;;GR;;;WD)")
			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatalf("read test DACL: %v", err)
			}
			target := path
			if directory {
				target = dir
			}
			if err := windows.SetNamedSecurityInfo(target, windows.SE_FILE_OBJECT,
				windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
				t.Fatalf("make %s publicly readable: %v", name, err)
			}
			requirePolicyStoreRejection(t, path, nil, errPolicyStoreUnsafe)
		})
	}
}

func TestNetPolicyStoreRejectsWindowsReparsePoint(t *testing.T) {
	dir := privatePolicyStoreDir(t)
	path := filepath.Join(dir, "policy")
	seed := policyStoreTestConfig("ACCEPT")
	mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
	for _, tc := range []struct {
		name   string
		target string
	}{
		{name: "file", target: path},
		{name: "ancestor", target: dir},
	} {
		t.Run(tc.name, func(t *testing.T) {
			link := filepath.Join(privatePolicyStoreDir(t), "link")
			if err := os.Symlink(tc.target, link); err != nil {
				if errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD) {
					t.Skip("host does not permit symbolic link creation")
				}
				t.Fatalf("create reparse point: %v", err)
			}
			if tc.name == "ancestor" {
				link = filepath.Join(link, "policy")
			}
			requirePolicyStoreRejection(t, link, nil, nil)
		})
	}
}
