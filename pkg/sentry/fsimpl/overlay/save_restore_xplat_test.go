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

package overlay

import (
	"bytes"
	goContext "context"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
)

type testUniqueIDProvider struct {
	next uint64
}

func (p *testUniqueIDProvider) UniqueID() uint64 {
	p.next++
	return p.next
}

func newSavableOverlayContext(t *testing.T, mf *pgalloc.MemoryFile, creds *auth.Credentials) (gvcontext.Context, goContext.Context) {
	t.Helper()
	clock := &ktime.SyntheticClock{}
	clock.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
	uidProvider := &testUniqueIDProvider{}
	values := map[any]any{
		pgalloc.CtxMemoryFile:              mf,
		ktime.CtxRealtimeClock:             clock,
		auth.CtxCredentials:                creds,
		uniqueid.CtxGlobalUniqueID:         uint64(1),
		uniqueid.CtxGlobalUniqueIDProvider: uidProvider,
	}
	gvCtx := gvcontext.WithValues(gvcontext.Background(), values)
	goCtx := goContext.Background()
	for k, v := range values {
		goCtx = goContext.WithValue(goCtx, k, v)
	}
	return gvCtx, goCtx
}

func newSavableMemoryFile(t *testing.T) *pgalloc.MemoryFile {
	t.Helper()
	const name = "overlay-state-test"
	memFD, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), name), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	mf.MarkSavable()
	t.Cleanup(mf.Destroy)
	return mf
}

func mountDisconnectedRoot(t *testing.T, ctx gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, fsName string, opts *vfs.MountOptions) vfs.VirtualDentry {
	t.Helper()
	mnt, err := vfsObj.MountDisconnected(ctx, creds, "", fsName, opts)
	if err != nil {
		t.Fatalf("MountDisconnected(%s): %v", fsName, err)
	}
	vd := vfs.MakeVirtualDentry(mnt, mnt.Root())
	vd.IncRef()
	t.Cleanup(func() { mnt.DecRef(ctx) })
	return vd
}

func TestOverlaySaveLoadPreservesDirDevAndDrainsUnusedCache(t *testing.T) {
	mf := newSavableMemoryFile(t)
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx, goCtx := newSavableOverlayContext(t, mf, creds)

	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	lowerRoot := mountDisconnectedRoot(t, ctx, &vfsObj, creds, tmpfs.Name, &vfs.MountOptions{})
	defer lowerRoot.DecRef(ctx)
	upperRoot := mountDisconnectedRoot(t, ctx, &vfsObj, creds, tmpfs.Name, &vfs.MountOptions{})
	defer upperRoot.DecRef(ctx)

	for _, dir := range []string{"dir", "dir/sub"} {
		if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{
			Root:  lowerRoot,
			Start: lowerRoot,
			Path:  fspath.Parse(dir),
		}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
			t.Fatalf("MkdirAt(%s): %v", dir, err)
		}
	}
	lowerFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse("dir/sub/note.txt"),
	}, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_RDWR, Mode: 0o644})
	if err != nil {
		t.Fatalf("OpenAt(dir/sub/note.txt): %v", err)
	}
	lowerFD.DecRef(ctx)

	const (
		wantMajor = uint32(254)
		wantMinor = uint32(7)
	)
	lowerRef := lowerRoot
	lowerRef.IncRef()
	upperRef := upperRoot
	upperRef.IncRef()
	ovlMnt, err := vfsObj.MountDisconnected(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOptions{
				UpperRoot:   upperRef,
				LowerRoots:  []vfs.VirtualDentry{lowerRef},
				DirDevMajor: wantMajor,
				DirDevMinor: wantMinor,
			},
		},
	})
	if err != nil {
		lowerRef.DecRef(ctx)
		upperRef.DecRef(ctx)
		t.Fatalf("MountDisconnected(overlay): %v", err)
	}
	defer ovlMnt.DecRef(ctx)

	ovlRoot := vfs.MakeVirtualDentry(ovlMnt, ovlMnt.Root())
	ovlRoot.IncRef()
	defer ovlRoot.DecRef(ctx)
	ovlFS := ovlMnt.Filesystem().Impl().(*filesystem)

	// Resolve a deep path and drop the leaf reference so intermediate directories
	// and the leaf populate fs.unused.
	vd, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
		Root:  ovlRoot,
		Start: ovlRoot,
		Path:  fspath.Parse("dir/sub/note.txt"),
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(dir/sub/note.txt): %v", err)
	}
	vd.DecRef(ctx)

	ovlFS.renameMu.RLock()
	cachedBefore := ovlFS.unused.len
	ovlFS.renameMu.RUnlock()
	if cachedBefore == 0 {
		t.Fatal("expected unused dentry cache to hold entries after lookup")
	}

	assertDirDev := func(v *vfs.VirtualFilesystem, root vfs.VirtualDentry, rel string) {
		t.Helper()
		st, err := v.StatAt(ctx, creds, &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(rel),
		}, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
		if err != nil {
			t.Fatalf("StatAt(%q): %v", rel, err)
		}
		if st.DevMajor != wantMajor || st.DevMinor != wantMinor {
			t.Errorf("StatAt(%q) st_dev = %d:%d, want %d:%d", rel, st.DevMajor, st.DevMinor, wantMajor, wantMinor)
		}
	}
	for _, p := range []string{"", "dir", "dir/sub"} {
		assertDirDev(&vfsObj, ovlRoot, p)
	}

	// PrepareSave drains zero-reference cached dentries without closing the cache
	// permanently when execution resumes.
	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave (first): %v", err)
	}
	ovlFS.renameMu.RLock()
	cachedAfterDrain := ovlFS.unused.len
	cacheClosed := ovlFS.unused.closed
	ovlFS.renameMu.RUnlock()
	if cachedAfterDrain != 0 || cacheClosed {
		t.Fatalf("after PrepareSave: unused.len=%d closed=%t, want len=0 closed=false", cachedAfterDrain, cacheClosed)
	}

	vfsObj.BeforeResume(ctx)
	assertDirDev(&vfsObj, ovlRoot, "dir/sub")
	ovlFS.renameMu.RLock()
	recached := ovlFS.unused.len
	ovlFS.renameMu.RUnlock()
	if recached == 0 {
		t.Fatal("expected lookup after BeforeResume to populate unused cache again")
	}

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave (second): %v", err)
	}

	var buf bytes.Buffer
	if _, err := state.Save(goCtx, &buf, &ovlMnt); err != nil {
		t.Fatalf("state.Save(ovlMnt): %v", err)
	}

	var restoredMnt *vfs.Mount
	if _, err := state.Load(goCtx, bytes.NewReader(buf.Bytes()), &restoredMnt); err != nil {
		t.Fatalf("state.Load(ovlMnt): %v", err)
	}
	restoredVFS := restoredMnt.Filesystem().VirtualFilesystem()
	if err := restoredVFS.CompleteRestore(ctx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	restoredRoot := vfs.MakeVirtualDentry(restoredMnt, restoredMnt.Root())
	restoredRoot.IncRef()
	defer func() {
		restoredRoot.DecRef(ctx)
		restoredMnt.DecRef(ctx)
		restoredVFS.Release(ctx)
	}()

	for _, p := range []string{"", "dir", "dir/sub"} {
		assertDirDev(restoredVFS, restoredRoot, p)
	}
	if err := restoredVFS.MkdirAt(ctx, creds, &vfs.PathOperation{
		Root:  restoredRoot,
		Start: restoredRoot,
		Path:  fspath.Parse("dir/created_after_restore"),
	}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt after restore: %v", err)
	}
	assertDirDev(restoredVFS, restoredRoot, "dir/created_after_restore")
}

func TestOverlayPrepareSavePreservesZeroRefWatchedDentry(t *testing.T) {
	mf := newSavableMemoryFile(t)
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx, goCtx := newSavableOverlayContext(t, mf, creds)

	var vfsObj vfs.VirtualFilesystem
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	t.Cleanup(func() { vfsObj.Release(ctx) })
	vfsObj.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	lowerRoot := mountDisconnectedRoot(t, ctx, &vfsObj, creds, tmpfs.Name, &vfs.MountOptions{})
	defer lowerRoot.DecRef(ctx)
	upperRoot := mountDisconnectedRoot(t, ctx, &vfsObj, creds, tmpfs.Name, &vfs.MountOptions{})
	defer upperRoot.DecRef(ctx)

	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse("dir"),
	}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt(dir): %v", err)
	}
	lowerFD, err := vfsObj.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  lowerRoot,
		Start: lowerRoot,
		Path:  fspath.Parse("dir/watched.txt"),
	}, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_RDWR, Mode: 0o644})
	if err != nil {
		t.Fatalf("OpenAt(dir/watched.txt): %v", err)
	}
	lowerFD.DecRef(ctx)

	lowerRef := lowerRoot
	lowerRef.IncRef()
	upperRef := upperRoot
	upperRef.IncRef()
	ovlMnt, err := vfsObj.MountDisconnected(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: FilesystemOptions{
				UpperRoot:  upperRef,
				LowerRoots: []vfs.VirtualDentry{lowerRef},
			},
		},
	})
	if err != nil {
		lowerRef.DecRef(ctx)
		upperRef.DecRef(ctx)
		t.Fatalf("MountDisconnected(overlay): %v", err)
	}
	defer ovlMnt.DecRef(ctx)

	ovlRoot := vfs.MakeVirtualDentry(ovlMnt, ovlMnt.Root())
	ovlRoot.IncRef()
	defer ovlRoot.DecRef(ctx)
	ovlFS := ovlMnt.Filesystem().Impl().(*filesystem)

	// Step 1: Lookup and drop reference so dir/watched.txt enters fs.unused with refs == 0.
	vd, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
		Root:  ovlRoot,
		Start: ovlRoot,
		Path:  fspath.Parse("dir/watched.txt"),
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(dir/watched.txt): %v", err)
	}
	vd.DecRef(ctx)

	// Step 2: Attach an inotify watch to dir/watched.txt and drop the temporary lookup ref.
	ifd, err := vfs.NewInotifyFD(ctx, &vfsObj, linux.IN_NONBLOCK)
	if err != nil {
		t.Fatalf("NewInotifyFD: %v", err)
	}
	defer ifd.DecRef(ctx)
	inotifyImpl := ifd.Impl().(*vfs.Inotify)

	vd2, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
		Root:  ovlRoot,
		Start: ovlRoot,
		Path:  fspath.Parse("dir/watched.txt"),
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(dir/watched.txt) for watch: %v", err)
	}
	wd := inotifyImpl.AddWatch(vd2.Dentry(), linux.IN_MODIFY|linux.IN_DELETE_SELF)
	vd2.DecRef(ctx)

	ovlFS.renameMu.RLock()
	unusedAfterWatch := ovlFS.unused.len
	ovlFS.renameMu.RUnlock()
	if unusedAfterWatch != 0 {
		t.Fatalf("unused.len after watching leaf = %d, want 0", unusedAfterWatch)
	}

	// Step 3: Run PrepareSave and verify no spurious IN_DELETE_SELF or IN_IGNORED events were queued.
	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	const readableMask = 1 // waiter.EventIn
	if got := inotifyImpl.Readiness(readableMask); got != 0 {
		t.Fatalf("inotify Readiness after PrepareSave = %v, want 0 (no spurious deletion events)", got)
	}

	// Step 4: Save and restore the mount together with the Inotify FD, then modify dir/watched.txt.
	var buf bytes.Buffer
	origGraph := &[2]any{ovlMnt, ifd}
	if _, err := state.Save(goCtx, &buf, origGraph); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	vfsObj.BeforeResume(ctx)

	var restoredGraph [2]any
	if _, err := state.Load(goCtx, bytes.NewReader(buf.Bytes()), &restoredGraph); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredMnt := restoredGraph[0].(*vfs.Mount)
	restoredIFD := restoredGraph[1].(*vfs.FileDescription)
	restoredInotify := restoredIFD.Impl().(*vfs.Inotify)
	restoredVFS := restoredMnt.Filesystem().VirtualFilesystem()
	if err := restoredVFS.CompleteRestore(ctx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	restoredRoot := vfs.MakeVirtualDentry(restoredMnt, restoredMnt.Root())
	restoredRoot.IncRef()
	defer func() {
		restoredRoot.DecRef(ctx)
		restoredIFD.DecRef(ctx)
		restoredMnt.DecRef(ctx)
		restoredVFS.Release(ctx)
	}()

	if got := restoredInotify.Readiness(readableMask); got != 0 {
		t.Fatalf("restoredInotify Readiness before modification = %v, want 0", got)
	}

	// Truncating dir/watched.txt via OpenAt(O_TRUNC) triggers InotifyWithParent(IN_MODIFY).
	wfd, err := restoredVFS.OpenAt(ctx, creds, &vfs.PathOperation{
		Root:  restoredRoot,
		Start: restoredRoot,
		Path:  fspath.Parse("dir/watched.txt"),
	}, &vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_TRUNC})
	if err != nil {
		t.Fatalf("OpenAt(dir/watched.txt, O_TRUNC) after restore: %v", err)
	}
	wfd.DecRef(ctx)

	if got := restoredInotify.Readiness(readableMask); got == 0 {
		t.Fatalf("restoredInotify Readiness after O_TRUNC = 0, want readable IN_MODIFY event for wd=%d", wd)
	}
}
