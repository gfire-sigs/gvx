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
	goContext "context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
)

// TestCompleteRestoreRejectsHostKindChange saves a checkpoint with an open
// file, replaces the host entry with an entry of another kind, and restores.
// CompleteRestore must report corruption. A silent refresh would leave an inode
// whose kind and whose host mode disagree.
func TestCompleteRestoreRejectsHostKindChange(t *testing.T) {
	cases := []struct {
		name    string
		saved   func(t *testing.T, path string)
		changed func(t *testing.T, path string)
		flags   uint32
	}{
		{
			name:    "file replaced by directory",
			saved:   func(t *testing.T, p string) { writeHostFile(t, p) },
			changed: func(t *testing.T, p string) { replaceHostEntry(t, p, func() error { return os.Mkdir(p, 0o755) }) },
			flags:   linux.O_RDONLY,
		},
		{
			name:  "directory replaced by file",
			saved: func(t *testing.T, p string) { mkdirHost(t, p) },
			changed: func(t *testing.T, p string) {
				replaceHostEntry(t, p, func() error { return os.WriteFile(p, []byte("now a file"), 0o644) })
			},
			flags: linux.O_RDONLY | linux.O_DIRECTORY,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			tc.saved(t, filepath.Join(dir, "entry"))

			ws, err := OpenWorkspace(dir, false)
			if err != nil {
				t.Fatalf("OpenWorkspace: %v", err)
			}
			baseCtx := gvcontext.Background()
			creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
			vfsObj := &vfs.VirtualFilesystem{}
			if err := vfsObj.Init(baseCtx); err != nil {
				t.Fatalf("vfsObj.Init: %v", err)
			}
			vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
			mountID := checkpoint.ResourceID{ContainerName: "sandbox-kind", Path: "/workspace"}
			mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
				GetFilesystemOptions: vfs.GetFilesystemOptions{
					InternalData: InternalFilesystemOptions{Workspace: ws, UniqueID: mountID},
				},
			}, testNSFS{})
			if err != nil {
				t.Fatalf("NewMountNamespace: %v", err)
			}
			root := mntns.Root(baseCtx)
			ctx := cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}

			fd, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("entry"), FollowFinalSymlink: true}, &vfs.OpenOptions{Flags: tc.flags})
			if err != nil {
				t.Fatalf("OpenAt(entry): %v", err)
			}
			if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
				t.Fatalf("PrepareSave: %v", err)
			}
			var buf bytes.Buffer
			if _, err := state.Save(goContext.Background(), &buf, &checkpointBundle{vfsObj: vfsObj, mntns: mntns, root: root, regFD: fd}); err != nil {
				t.Fatalf("state.Save: %v", err)
			}
			fd.DecRef(ctx)
			root.DecRef(ctx)
			mntns.DecRef(baseCtx)
			vfsObj.Release(baseCtx)
			if err := ws.Close(); err != nil {
				t.Fatalf("ws.Close: %v", err)
			}

			tc.changed(t, filepath.Join(dir, "entry"))

			restoredWS, err := OpenWorkspaceForRestore(dir, false)
			if err != nil {
				t.Fatalf("OpenWorkspaceForRestore: %v", err)
			}
			defer func() { _ = restoredWS.Close() }()
			var restored checkpointBundle
			if _, err := state.Load(WithRestoreWorkspace(goContext.Background(), mountID, restoredWS), bytes.NewReader(buf.Bytes()), &restored); err != nil {
				t.Fatalf("state.Load: %v", err)
			}
			restoreBaseCtx := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, restoredWS)
			restoreCtx := cookieContext{vfs.WithMountNamespace(restoreBaseCtx, restored.mntns)}
			defer func() {
				restored.regFD.DecRef(restoreCtx)
				restored.root.DecRef(restoreCtx)
				restored.mntns.DecRef(restoreBaseCtx)
				restored.vfsObj.Release(restoreBaseCtx)
			}()

			err = restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{})
			var corrupt vfs.ErrCorruption
			if !errors.As(err, &corrupt) {
				t.Fatalf("CompleteRestore after a host kind change = %v, want vfs.ErrCorruption", err)
			}
		})
	}
}

func writeHostFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("original"), 0o644); err != nil {
		t.Fatalf("WriteFile(%s): %v", path, err)
	}
}

func mkdirHost(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o755); err != nil {
		t.Fatalf("Mkdir(%s): %v", path, err)
	}
}

func replaceHostEntry(t *testing.T, path string, create func() error) {
	t.Helper()
	if err := os.RemoveAll(path); err != nil {
		t.Fatalf("RemoveAll(%s): %v", path, err)
	}
	if err := create(); err != nil {
		t.Fatalf("create replacement of %s: %v", path, err)
	}
}
