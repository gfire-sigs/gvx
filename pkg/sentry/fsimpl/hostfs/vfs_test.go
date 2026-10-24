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
	"io"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	gverrors "z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// env is a hostfs mount driven through the VFS layer, the way the guest
// kernel drives it.
type env struct {
	t      *testing.T
	ctx    gvcontext.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	ws     *Workspace
	dir    string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	return newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow})
}

func newEnvOpts(t *testing.T, opts workspaceOptions) *env {
	t.Helper()
	dir := t.TempDir()
	// Resolve symlinks such as /var -> /private/var, so that path comparisons
	// with host-side results hold.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	ws, err := openWorkspace(dir, false, opts)
	if err != nil {
		t.Fatalf("openWorkspace: %v", err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		if err := ws.Close(); err != nil {
			t.Errorf("Workspace.Close: %v", err)
		}
	})
	return e
}

func mountEnv(t *testing.T, ws *Workspace, dir string) *env {
	t.Helper()
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{Workspace: ws},
		},
	}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(ctx)
	e := &env{
		t:      t,
		ctx:    cookieContext{vfs.WithMountNamespace(ctx, mntns)},
		creds:  creds,
		vfsObj: vfsObj,
		root:   root,
		ws:     ws,
		dir:    dir,
	}
	// The mount namespace outlives the test body; the cleanup of the caller
	// drops the root reference, and this drops the namespace.
	t.Cleanup(func() { mntns.DecRef(ctx) })
	return e
}

// cookieContext supplies the inotify cookie and the resource limits that the
// kernel task context normally supplies.
type cookieContext struct {
	gvcontext.Context
}

var (
	testLimits = limits.NewLimitSet()
	testCreds  = auth.NewRootCredentials(auth.NewRootUserNamespace())
)

// Value implements context.Context.Value.
func (c cookieContext) Value(key any) any {
	switch key {
	case uniqueid.CtxInotifyCookie:
		return uint32(1)
	case limits.CtxLimits:
		return testLimits
	case auth.CtxCredentials:
		return testCreds
	}
	return c.Context.Value(key)
}

// pop names a path without following a final symbolic link, as creation,
// deletion, and rename require.
func (e *env) pop(p string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse(p)}
}

// fpop names a path and follows a final symbolic link.
func (e *env) fpop(p string) *vfs.PathOperation {
	pop := e.pop(p)
	pop.FollowFinalSymlink = true
	return pop
}

func (e *env) host(p string) string {
	return filepath.Join(e.dir, filepath.FromSlash(p))
}

func (e *env) mkdir(p string) error {
	return e.vfsObj.MkdirAt(e.ctx, e.creds, e.pop(p), &vfs.MkdirOptions{Mode: 0o755})
}

func (e *env) mustMkdir(p string) {
	e.t.Helper()
	if err := e.mkdir(p); err != nil {
		e.t.Fatalf("mkdir %q: %v", p, err)
	}
}

func (e *env) open(p string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return e.vfsObj.OpenAt(e.ctx, e.creds, e.fpop(p), &vfs.OpenOptions{Flags: flags, Mode: mode})
}

func (e *env) mustOpen(p string, flags uint32) *vfs.FileDescription {
	e.t.Helper()
	fd, err := e.open(p, flags, 0o644)
	if err != nil {
		e.t.Fatalf("open %q: %v", p, err)
	}
	return fd
}

func (e *env) writeFile(p string, data []byte) {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_CREAT|linux.O_WRONLY|linux.O_TRUNC)
	defer fd.DecRef(e.ctx)
	if n, err := fd.Write(e.ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{}); err != nil || int(n) != len(data) {
		e.t.Fatalf("write %q = (%d, %v), want %d bytes", p, n, err, len(data))
	}
}

func (e *env) readAll(fd *vfs.FileDescription) []byte {
	e.t.Helper()
	var out []byte
	buf := make([]byte, 4096)
	for off := int64(0); ; {
		n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
		out = append(out, buf[:n]...)
		off += n
		if errors.Is(err, io.EOF) || (err == nil && n == 0) {
			return out
		}
		if err != nil {
			e.t.Fatalf("read: %v", err)
		}
	}
}

func (e *env) readFile(p string) []byte {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	return e.readAll(fd)
}

func (e *env) stat(p string) (linux.Statx, error) {
	return e.vfsObj.StatAt(e.ctx, e.creds, e.fpop(p), &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
}

func (e *env) mustStat(p string) linux.Statx {
	e.t.Helper()
	st, err := e.stat(p)
	if err != nil {
		e.t.Fatalf("stat %q: %v", p, err)
	}
	return st
}

func (e *env) lstat(p string) (linux.Statx, error) {
	return e.vfsObj.StatAt(e.ctx, e.creds, e.pop(p), &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
}

func (e *env) unlink(p string) error {
	return e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop(p))
}

func (e *env) rename(oldPath, newPath string) error {
	return e.vfsObj.RenameAt(e.ctx, e.creds, e.pop(oldPath), e.pop(newPath), &vfs.RenameOptions{})
}

func (e *env) link(oldPath, newPath string) error {
	return e.vfsObj.LinkAt(e.ctx, e.creds, e.pop(oldPath), e.pop(newPath))
}

func (e *env) readdir(p string) []string {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	var names []string
	err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			names = append(names, d.Name)
		}
		return nil
	}))
	if err != nil {
		e.t.Fatalf("readdir %q: %v", p, err)
	}
	sort.Strings(names)
	return names
}

func wantErrno(t *testing.T, what string, err error, want *gverrors.Error) {
	t.Helper()
	if !linuxerr.Equals(want, err) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func TestEnvSmoke(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("sub")
	e.writeFile("sub/a.txt", []byte("hello"))
	if got := e.readFile("sub/a.txt"); !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("read = %q", got)
	}
	raw, err := os.ReadFile(e.host("sub/a.txt"))
	if err != nil || string(raw) != "hello" {
		t.Fatalf("host content = (%q, %v)", raw, err)
	}
	if got := e.readdir("sub"); len(got) != 1 || got[0] != "a.txt" {
		t.Fatalf("readdir = %v", got)
	}
}
