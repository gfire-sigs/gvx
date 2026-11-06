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

package ext4lite

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// overlayCreateCreds returns the credentials that overlayfs uses to create a
// file in its upper layer for a caller with fsuid uid and fsgid gid: the root
// credentials of the mounter with the filesystem IDs of the caller, as
// ovl_override_creds does.
func overlayCreateCreds(uid auth.KUID, gid auth.KGID) *auth.Credentials {
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace()).Fork()
	creds.FilesystemKUID = uid
	creds.FilesystemKGID = gid
	return creds
}

// TestNewFilesTakeTheFilesystemIDs checks that a new node takes the fsuid and
// the fsgid of the caller, as inode_init_owner does in Linux. An overlay upper
// layer on the volume creates files with the effective IDs of root and the
// filesystem IDs of the caller.
func TestNewFilesTakeTheFilesystemIDs(t *testing.T) {
	e := newEnv(t)
	creds := overlayCreateCreds(70, 70)
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
		{"mknod of a FIFO", func(p string) error {
			return e.vfsObj.MknodAt(e.ctx, creds, e.pop(p), &vfs.MknodOptions{Mode: linux.S_IFIFO | 0o600})
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

	// The caller owns the new file, so it may change its mode, as PostgreSQL
	// does for its socket right after it creates it.
	user := userCreds(70, 70)
	err := e.vfsObj.SetStatAt(e.ctx, user, e.fpop("a"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}})
	if err != nil {
		t.Fatalf("chmod of the new file by its creator: %v", err)
	}
}

// TestNewFileInSetGIDDirectoryTakesTheGroupOfTheDirectory checks that a
// set-group-ID directory still gives its group, and the fsuid gives the user.
func TestNewFileInSetGIDDirectoryTakesTheGroupOfTheDirectory(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("shared")
	if err := e.setStat("shared", linux.Statx{Mask: linux.STATX_GID | linux.STATX_MODE, GID: 50, Mode: linux.S_IFDIR | linux.ModeSetGID | 0o777}); err != nil {
		t.Fatal(err)
	}
	creds := overlayCreateCreds(1000, 1000)
	fd, err := e.vfsObj.OpenAt(e.ctx, creds, e.fpop("shared/f"), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	fd.DecRef(e.ctx)
	if st := e.mustStat("shared/f"); st.UID != 1000 || st.GID != 50 {
		t.Errorf("owner %d:%d, want 1000:50", st.UID, st.GID)
	}
}
