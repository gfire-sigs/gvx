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

package ext4lite_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type extCookieContext struct {
	gvcontext.Context
}

var (
	extTestLimits = limits.NewLimitSet()
	extTestCreds  = auth.NewRootCredentials(auth.NewRootUserNamespace())
)

func (c extCookieContext) Value(key any) any {
	switch key {
	case uniqueid.CtxInotifyCookie:
		return uint32(1)
	case limits.CtxLimits:
		return extTestLimits
	case auth.CtxCredentials:
		return extTestCreds
	}
	return c.Context.Value(key)
}

type vfsFixture struct {
	t      *testing.T
	ctx    gvcontext.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	mntns  *vfs.MountNamespace
}

func newVFSFixture(t *testing.T) *vfsFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vol.ext4")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{})
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(ext4lite.Name, ext4lite.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	var mopts vfs.MountOptions
	mopts.GetFilesystemOptions.InternalData = ext4lite.InternalFilesystemOptions{Volume: vol}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", ext4lite.Name, &mopts, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(ctx)
	fx := &vfsFixture{
		t:      t,
		ctx:    extCookieContext{vfs.WithMountNamespace(ctx, mntns)},
		creds:  creds,
		vfsObj: vfsObj,
		root:   root,
		mntns:  mntns,
	}
	t.Cleanup(func() {
		root.DecRef(fx.ctx)
		mntns.DecRef(fx.ctx)
	})
	return fx
}

func (fx *vfsFixture) pop(p string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: fx.root, Start: fx.root, Path: fspath.Parse(p)}
}

func (fx *vfsFixture) fpop(p string) *vfs.PathOperation {
	pop := fx.pop(p)
	pop.FollowFinalSymlink = true
	return pop
}

// TestReadlinkDoesNotTakeMountLockUnderFilesystemMutex checks the lock order
// of the VFS mount lock and fs.mu. A mount operation holds the mount lock and
// calls IsDescendant, which takes fs.mu. ReadlinkAt must therefore not take
// the mount lock, which Mount.Options takes, while it holds fs.mu. Otherwise
// the readlink waits for the mount operation, the mount operation waits for
// the readlink, and every other call that needs fs.mu waits behind them,
// including the background flush.
func TestReadlinkDoesNotTakeMountLockUnderFilesystemMutex(t *testing.T) {
	fx := newVFSFixture(t)
	if err := fx.vfsObj.MkdirAt(fx.ctx, fx.creds, fx.pop("a"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt a: %v", err)
	}
	if err := fx.vfsObj.MkdirAt(fx.ctx, fx.creds, fx.pop("b"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt b: %v", err)
	}
	const links = 16
	for i := range links {
		name := fmt.Sprintf("l%d", i)
		if err := fx.vfsObj.SymlinkAt(fx.ctx, fx.creds, fx.pop(name), "target"); err != nil {
			t.Fatalf("SymlinkAt %s: %v", name, err)
		}
	}
	// The mount at b makes the mount operation below call IsDescendant of
	// this filesystem.
	if err := fx.vfsObj.BindAt(fx.ctx, fx.creds, fx.pop("a"), fx.pop("b"), false); err != nil {
		t.Fatalf("BindAt: %v", err)
	}

	const rounds = 200
	start := make(chan struct{})
	errCh := make(chan error, 8)
	var wg sync.WaitGroup
	for g := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			<-start
			for i := range rounds {
				name := fmt.Sprintf("l%d", (id+i)%links)
				if _, err := fx.vfsObj.ReadlinkAt(fx.ctx, fx.creds, fx.pop(name)); err != nil {
					errCh <- fmt.Errorf("ReadlinkAt(%s): %w", name, err)
					return
				}
			}
		}(g)
	}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range rounds {
				if err := fx.vfsObj.CheckClonePrivateMount(fx.ctx, fx.creds, fx.root); err != nil {
					errCh <- fmt.Errorf("CheckClonePrivateMount: %w", err)
					return
				}
			}
		}()
	}
	close(start)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ReadlinkAt and CheckClonePrivateMount deadlocked on the mount lock and fs.mu")
	}
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}
