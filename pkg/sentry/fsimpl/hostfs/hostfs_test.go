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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func TestWorkspaceMetaPersistenceAndSymlinkContainment(t *testing.T) {
	wsDir := t.TempDir()
	ws, err := OpenWorkspace(wsDir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace failed: %v", err)
	}

	if err := ws.MkdirAll("scripts/bin", 0o755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	if err := ws.WriteFile("scripts/bin/run.sh", []byte("#!/bin/sh\necho ok\n"), 0o755); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if err := ws.Chown("scripts/bin/run.sh", 1001, 1002); err != nil {
		t.Fatalf("Chown failed: %v", err)
	}
	if err := ws.Symlink("run.sh", "scripts/bin/current.sh"); err != nil {
		t.Fatalf("Symlink(intra-workspace) failed: %v", err)
	}

	// A guest symlink lives only in .gvx_meta, so every target is valid. The
	// guest VFS resolves the target in the guest namespace.
	for link, target := range map[string]string{
		"scripts/bin/escape.sh":     "../../../etc/passwd",
		"scripts/bin/abs_escape.sh": "/etc/passwd",
	} {
		if err := ws.Symlink(target, link); err != nil {
			t.Fatalf("Symlink(%q -> %q) = %v, want success", link, target, err)
		}
		if got, err := ws.Readlink(link); err != nil || got != target {
			t.Fatalf("Readlink(%q) = (%q, %v), want %q", link, got, err, target)
		}
	}
	if err := ws.Symlink("", "scripts/bin/empty.sh"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Symlink(empty target) = %v, want ErrNotExist", err)
	}
	if _, err := ws.OpenFile("../outside.txt", os.O_RDONLY, 0); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("OpenFile(../outside.txt) = %v, want ErrPathTraversal", err)
	}

	// Plant a host-level symlink pointing outside the workspace and verify
	// O_NOFOLLOW / FILE_OPEN_REPARSE_POINT rejects opening it.
	hostEscapeLink := filepath.Join(wsDir, "host_escape_link")
	if sErr := os.Symlink("/etc/hosts", hostEscapeLink); sErr == nil {
		if _, openErr := ws.OpenFile("host_escape_link", os.O_RDONLY, 0); openErr == nil {
			t.Fatalf("OpenFile on host symlink pointing outside workspace succeeded, want rejection")
		}
		if _, _, statErr := ws.Stat("host_escape_link"); !errors.Is(statErr, ErrPathTraversal) {
			t.Fatalf("Stat on host symlink pointing outside workspace = %v, want ErrPathTraversal", statErr)
		}
	}

	if err := ws.Close(); err != nil {
		t.Fatalf("ws.Close() failed: %v", err)
	}

	// Reopen workspace in read-only mode and verify .gvx_meta persisted mode, uid/gid, and symlink.
	wsRO, err := OpenWorkspace(wsDir, true)
	if err != nil {
		t.Fatalf("OpenWorkspace(readOnly) failed: %v", err)
	}
	defer func() {
		_ = wsRO.Close()
	}()

	attr, size, err := wsRO.Stat("scripts/bin/run.sh")
	if err != nil {
		t.Fatalf("Stat(run.sh) failed: %v", err)
	}
	if attr.Mode != (linux.S_IFREG|0o755) || attr.UID != 1001 || attr.GID != 1002 || size == 0 {
		t.Fatalf("Stat(run.sh) = (%+v, %d), want Mode=0100755 UID=1001 GID=1002", attr, size)
	}

	linkTarget, err := wsRO.Readlink("scripts/bin/current.sh")
	if err != nil || linkTarget != "run.sh" {
		t.Fatalf("Readlink(current.sh) = (%q, %v), want (\"run.sh\", nil)", linkTarget, err)
	}

	if err := wsRO.WriteFile("blocked.txt", []byte("no"), 0o644); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("WriteFile on readOnly workspace = %v, want ErrReadOnly", err)
	}
}

func TestPOSIXRenameAndUnlinkOnOpenFile(t *testing.T) {
	ws, err := OpenWorkspace(t.TempDir(), false)
	if err != nil {
		t.Fatalf("OpenWorkspace failed: %v", err)
	}
	defer func() {
		_ = ws.Close()
	}()

	if err := ws.WriteFile("index.lock", []byte("git-staged-tree-v2"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.lock) failed: %v", err)
	}
	if err := ws.WriteFile("index", []byte("git-staged-tree-v1"), 0o644); err != nil {
		t.Fatalf("WriteFile(index) failed: %v", err)
	}

	// Hold an open file descriptor on "index" while replacing it via Rename("index.lock", "index").
	openTarget, err := ws.OpenFile("index", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(index) failed: %v", err)
	}
	defer func() {
		_ = openTarget.Close()
	}()

	if err := ws.Rename("index.lock", "index"); err != nil {
		t.Fatalf("Rename(index.lock -> index) while target is open failed: %v", err)
	}

	got, err := ws.ReadFile("index")
	if err != nil || !bytes.Equal(got, []byte("git-staged-tree-v2")) {
		t.Fatalf("ReadFile(index) after POSIX rename = (%q, %v), want git-staged-tree-v2", got, err)
	}

	// Hold an open file descriptor on "temp.pack" while unlinking it.
	if err := ws.WriteFile("temp.pack", []byte("pack-data"), 0o600); err != nil {
		t.Fatalf("WriteFile(temp.pack) failed: %v", err)
	}
	openPack, err := ws.OpenFile("temp.pack", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile(temp.pack) failed: %v", err)
	}
	defer func() {
		_ = openPack.Close()
	}()

	if err := ws.Unlink("temp.pack"); err != nil {
		t.Fatalf("Unlink(temp.pack) while file is open failed: %v", err)
	}
}

func TestHostFSVFS2MountAndFileOperations(t *testing.T) {
	wsDir := t.TempDir()
	ws, err := OpenWorkspace(wsDir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace failed: %v", err)
	}
	defer func() {
		_ = ws.Close()
	}()

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())

	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init failed: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{Workspace: ws},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(hostfs) failed: %v", err)
	}
	defer mntns.DecRef(ctx)

	root := mntns.Root(ctx)
	defer root.DecRef(ctx)

	// 1. Create directory /sub via VFS2 MkdirAt.
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("sub"),
	}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt(sub) failed: %v", err)
	}

	// 2. Create and write /sub/hello.txt via VFS2 OpenAt + Write.
	fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("sub/hello.txt"),
	}, &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o644,
	})
	if err != nil {
		t.Fatalf("OpenAt(sub/hello.txt) failed: %v", err)
	}
	payload := []byte("vfs2-direct-hostfs")
	n, err := fd.Write(ctx, usermem.BytesIOSequence(payload), vfs.WriteOptions{})
	if err != nil || int(n) != len(payload) {
		fd.DecRef(ctx)
		t.Fatalf("fd.Write = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	fd.DecRef(ctx)

	// 3. Verify file was written directly to the host workspace without intermediate copy.
	hostRaw, err := os.ReadFile(filepath.Join(wsDir, "sub", "hello.txt"))
	if err != nil || !bytes.Equal(hostRaw, payload) {
		t.Fatalf("host file content = (%q, %v), want %q", hostRaw, err, payload)
	}

	// 4. Create intra-workspace symlink and readlink via VFS2.
	if err := vfsObj.SymlinkAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("sub/link.txt"),
	}, "hello.txt"); err != nil {
		t.Fatalf("SymlinkAt(sub/link.txt) failed: %v", err)
	}
	target, err := vfsObj.ReadlinkAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("sub/link.txt"),
	})
	if err != nil || target != "hello.txt" {
		t.Fatalf("ReadlinkAt(sub/link.txt) = (%q, %v), want (\"hello.txt\", nil)", target, err)
	}

	// 5. The guest VFS accepts a target that climbs out of the workspace. It
	// resolves the target in the guest namespace and never on the host.
	if err := vfsObj.SymlinkAt(ctx, creds, &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("sub/escape.txt"),
	}, "../../../etc/passwd"); err != nil {
		t.Fatalf("SymlinkAt(escape) = %v, want success", err)
	}
	if _, err := os.Lstat(filepath.Join(wsDir, "sub", "escape.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the escaping link reached the host: %v", err)
	}
}
