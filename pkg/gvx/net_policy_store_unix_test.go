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

//go:build (linux && !android) || (darwin && !ios)

package gvx

import (
	"os"
	"path/filepath"
	"testing"
)

func privatePolicyStoreDir(t testing.TB) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary directory: %v", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("make temporary directory private: %v", err)
	}
	return dir
}

func TestNetPolicyStoreRejectsPOSIXPermissions(t *testing.T) {
	for _, tc := range []struct {
		name string
		perm os.FileMode
		file bool
	}{
		{name: "parent readable by group", perm: 0o750},
		{name: "file readable by group", perm: 0o640, file: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := privatePolicyStoreDir(t)
			path := filepath.Join(dir, "policy")
			seed := policyStoreTestConfig("ACCEPT")
			mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
			target := dir
			if tc.file {
				target = path
			}
			if err := os.Chmod(target, tc.perm); err != nil {
				t.Fatalf("make %s group-readable: %v", target, err)
			}
			requirePolicyStoreRejection(t, path, nil, errPolicyStoreUnsafe)
		})
	}
}

func TestNetPolicyStoreRejectsPOSIXSymlinks(t *testing.T) {
	dir := privatePolicyStoreDir(t)
	path := filepath.Join(dir, "policy")
	seed := policyStoreTestConfig("ACCEPT")
	mustClosePolicyStore(t, mustOpenPolicyStore(t, path, &seed))
	fileLink := filepath.Join(dir, "policy-link")
	if err := os.Symlink(path, fileLink); err != nil {
		t.Fatalf("create file symlink: %v", err)
	}
	requirePolicyStoreRejection(t, fileLink, nil, errPolicyStoreUnsafe)

	dirLink := filepath.Join(privatePolicyStoreDir(t), "dir-link")
	if err := os.Symlink(dir, dirLink); err != nil {
		t.Fatalf("create parent symlink: %v", err)
	}
	requirePolicyStoreRejection(t, filepath.Join(dirLink, "policy"), nil, nil)
}
