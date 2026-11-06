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

package hostfs

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// TestNewFilesTakeTheFilesystemIDs checks that a new node takes the fsuid and
// the fsgid of the caller, as inode_init_owner does in Linux. An overlay upper
// layer on the workspace creates files with the effective IDs of root and the
// filesystem IDs of the caller (ovl_override_creds).
func TestNewFilesTakeTheFilesystemIDs(t *testing.T) {
	e := newEnv(t)
	creds := e.creds.Fork()
	creds.FilesystemKUID = 70
	creds.FilesystemKGID = 70
	ops := []struct {
		name string
		do   func(p string) error
	}{
		{"open with O_CREAT", func(p string) error {
			fd, err := e.vfsObj.OpenAt(e.ctx, creds, e.fpop(p), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
			if err == nil {
				fd.DecRef(e.ctx)
			}
			return err
		}},
		{"mkdir", func(p string) error {
			return e.vfsObj.MkdirAt(e.ctx, creds, e.pop(p), &vfs.MkdirOptions{Mode: 0o755})
		}},
		{"symlink", func(p string) error {
			return e.vfsObj.SymlinkAt(e.ctx, creds, e.pop(p), "target")
		}},
	}
	for i, op := range ops {
		p := string(rune('a' + i))
		if err := op.do(p); err != nil {
			t.Fatalf("%s: %v", op.name, err)
		}
		st, err := e.lstat(p)
		if err != nil {
			t.Fatalf("%s: lstat: %v", op.name, err)
		}
		if st.UID != 70 || st.GID != 70 {
			t.Errorf("%s: owner %d:%d, want the fsuid and fsgid 70:70", op.name, st.UID, st.GID)
		}
	}

	// The caller owns the new file, so it may change its mode.
	user := auth.NewUserCredentials(70, 70, nil, nil, e.creds.UserNamespace)
	err := e.vfsObj.SetStatAt(e.ctx, user, e.fpop("a"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}})
	if err != nil {
		t.Fatalf("chmod of the new file by its creator: %v", err)
	}
}
