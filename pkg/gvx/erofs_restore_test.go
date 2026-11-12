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

package gvx

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/erofs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/overlay"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

func buildTestTarLayer(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("WriteHeader(%q): %v", name, err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("Close tar: %v", err)
	}
	return buf.Bytes()
}

func newTestMemoryFile(t *testing.T, name string) *pgalloc.MemoryFile {
	t.Helper()
	memFD, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), name), pgalloc.MemoryFileOpts{
		Accounting: usage.NewMemoryLocked(),
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	mf.MarkSavable()
	t.Cleanup(mf.Destroy)
	return mf
}

func newTestSentryContext(t *testing.T, mf *pgalloc.MemoryFile, clock ktime.Clock, creds *auth.Credentials) gvcontext.Context {
	t.Helper()
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatalf("NewLinuxLimitSet: %v", err)
	}
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	return gvcontext.WithValues(gvcontext.Background(), map[any]any{
		pgalloc.CtxMemoryFile:  mf,
		ktime.CtxRealtimeClock: clock,
		auth.CtxCredentials:    creds,
		limits.CtxLimits:       ls,
	})
}

type erofsVFSSaveRoot struct {
	VFS     *vfs.VirtualFilesystem
	Root    vfs.VirtualDentry
	Extra   vfs.VirtualDentry
	OpenFD0 *vfs.FileDescription
	OpenFD1 *vfs.FileDescription
	ExtraFD *vfs.FileDescription
	Clock   *ktime.SyntheticClock
	Creds   *auth.Credentials
}

func (r *erofsVFSSaveRoot) StateTypeName() string {
	return "pkg/gvx.erofsVFSSaveRoot"
}

func (r *erofsVFSSaveRoot) StateFields() []string {
	return []string{"VFS", "Root", "Extra", "OpenFD0", "OpenFD1", "ExtraFD", "Clock", "Creds"}
}

func (r *erofsVFSSaveRoot) StateSave(sink state.Sink) {
	sink.Save(0, &r.VFS)
	sink.Save(1, &r.Root)
	sink.Save(2, &r.Extra)
	sink.Save(3, &r.OpenFD0)
	sink.Save(4, &r.OpenFD1)
	sink.Save(5, &r.ExtraFD)
	sink.Save(6, &r.Clock)
	sink.Save(7, &r.Creds)
}

func (r *erofsVFSSaveRoot) StateLoad(_ context.Context, src state.Source) {
	src.Load(0, &r.VFS)
	src.Load(1, &r.Root)
	src.Load(2, &r.Extra)
	src.Load(3, &r.OpenFD0)
	src.Load(4, &r.OpenFD1)
	src.Load(5, &r.ExtraFD)
	src.Load(6, &r.Clock)
	src.Load(7, &r.Creds)
}

func init() {
	state.RegisterNoHooks((*erofsVFSSaveRoot)(nil))
}

func readVFSFD(t *testing.T, ctx gvcontext.Context, vfd *vfs.FileDescription, n int) string {
	t.Helper()
	buf := make([]byte, n)
	got, err := vfd.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("FileDescription.Read: %v", err)
	}
	return string(buf[:got])
}

func preadVFSFD(t *testing.T, ctx gvcontext.Context, vfd *vfs.FileDescription, off int64, n int) string {
	t.Helper()
	buf := make([]byte, n)
	got, err := vfd.PRead(ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
	if err != nil && err != io.EOF {
		t.Fatalf("FileDescription.PRead: %v", err)
	}
	return string(buf[:got])
}

func TestEROFSUniqueIDDeterminismAndNormalization(t *testing.T) {
	idWithPrefix := EROFSUniqueID("/", 0, "SHA256:ABCDEF0123456789")
	idTrimmed := EROFSUniqueID("", 0, "abcdef0123456789")
	if !idWithPrefix.Ok() {
		t.Fatal("EROFSUniqueID returned empty ResourceID")
	}
	if idWithPrefix != idTrimmed {
		t.Fatalf("EROFSUniqueID mismatch across normalization: %q vs %q", idWithPrefix, idTrimmed)
	}

	idLayer1 := EROFSUniqueID("/", 1, "abcdef0123456789")
	if idLayer1 == idTrimmed {
		t.Fatalf("distinct layer indices collided on %q", idLayer1)
	}

	idOtherTarget := EROFSUniqueID("/opt/bundle/", 0, "abcdef0123456789")
	if idOtherTarget == idTrimmed {
		t.Fatalf("distinct mount targets collided on %q", idOtherTarget)
	}
}

func TestEROFSVFSMountSaveRestorePreservesOpenFileDescriptors(t *testing.T) {
	initRuntimeGlobals()
	cacheDir := t.TempDir()
	cache, err := NewLayerCache(cacheDir)
	if err != nil {
		t.Fatalf("NewLayerCache: %v", err)
	}

	const (
		layer0File = "etc/base.conf"
		layer0Body = "base-layer-0-immutable-payload-0123456789"
		layer1File = "app/config.json"
		layer1Body = `{"service":"gvx","tier":"erofs-layer-1"}`
		extraFile  = "bundle.txt"
		extraBody  = "standalone-direct-erofs-mount-contents"
	)

	rawLayer0 := buildTestTarLayer(t, map[string]string{layer0File: layer0Body})
	rawLayer1 := buildTestTarLayer(t, map[string]string{layer1File: layer1Body})
	rawExtra := buildTestTarLayer(t, map[string]string{extraFile: extraBody})

	extraPath, extraStats, err := cache.CompileAndStore("", bytes.NewReader(rawExtra))
	if err != nil {
		t.Fatalf("CompileAndStore extra layer: %v", err)
	}
	extraHH, err := fd.OpenHostPath(extraPath, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenHostPath extra layer: %v", err)
	}
	t.Cleanup(func() { _ = extraHH.Close() })

	// Initialize Sandbox OCI layers directly so initOCILayers + mountGuestRoot
	// assign deterministic EROFS UniqueIDs without requiring a hypervisor.
	sb := &Sandbox{
		cfg: Config{
			OCICacheDir:  cacheDir,
			OCILayerTars: [][]byte{rawLayer0, rawLayer1},
			Entrypoint:   []string{"/bin/true"},
		},
	}
	t.Cleanup(func() { _ = sb.Close() })
	if err := sb.initOCILayers(context.Background()); err != nil {
		t.Fatalf("initOCILayers: %v", err)
	}
	rootLayers := sb.EROFSLayerMounts()
	if len(rootLayers) != 2 {
		t.Fatalf("len(EROFSLayerMounts) = %d, want 2", len(rootLayers))
	}
	if rootLayers[0].Digest == "" || rootLayers[1].Digest == "" || rootLayers[0].Digest == rootLayers[1].Digest {
		t.Fatalf("unexpected layer digests: %+v", rootLayers)
	}

	mfPre := newTestMemoryFile(t, "erofs-sr-pre")
	clockPre := &ktime.SyntheticClock{}
	clockPre.Store(ktime.FromNanoseconds(1_700_000_000_000_000_000))
	credsPre := auth.NewRootCredentials(auth.NewRootUserNamespace())
	sctxPre := newTestSentryContext(t, mfPre, clockPre, credsPre)

	vfsPre := &vfs.VirtualFilesystem{}
	if err := vfsPre.Init(sctxPre); err != nil {
		t.Fatalf("vfsPre.Init: %v", err)
	}
	vfsPre.MustRegisterFilesystemType("erofs", erofs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsPre.MustRegisterFilesystemType("overlay", overlay.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsPre.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	rootMnt, err := sb.mountGuestRoot(sctxPre, vfsPre, credsPre)
	if err != nil {
		t.Fatalf("mountGuestRoot: %v", err)
	}
	rootVD := vfs.MakeVirtualDentry(rootMnt, rootMnt.Root())
	rootVD.IncRef()

	// Also mount a direct single-layer EROFS filesystem at /mnt/extra.
	extraDup, err := extraHH.Dup()
	if err != nil {
		t.Fatalf("extraHH.Dup: %v", err)
	}
	extraRawFD, err := extraDup.Release()
	if err != nil {
		_ = extraDup.Close()
		t.Fatalf("extraDup.Release: %v", err)
	}
	extraUniqueID := EROFSUniqueID("/mnt/extra", 0, extraStats.SHA256Hex)
	extraFS, extraRootDentry, err := erofs.FilesystemType{}.GetFilesystem(sctxPre, vfsPre, credsPre, "", vfs.GetFilesystemOptions{
		Data:         fmt.Sprintf("ifd=%d", int(extraRawFD)),
		InternalData: erofs.InternalFilesystemOptions{UniqueID: extraUniqueID},
	})
	if err != nil {
		t.Fatalf("mount direct EROFS: %v", err)
	}
	extraMnt := vfsPre.NewDisconnectedMount(extraFS, extraRootDentry, &vfs.MountOptions{ReadOnly: true})
	extraFS.DecRef(sctxPre)
	extraVD := vfs.MakeVirtualDentry(extraMnt, extraRootDentry)

	openAt := func(root vfs.VirtualDentry, relPath string) *vfs.FileDescription {
		t.Helper()
		pop := &vfs.PathOperation{
			Root:  root,
			Start: root,
			Path:  fspath.Parse(relPath),
		}
		vfd, oErr := vfsPre.OpenAt(sctxPre, credsPre, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if oErr != nil {
			t.Fatalf("OpenAt(%q): %v", relPath, oErr)
		}
		return vfd
	}

	openFD0 := openAt(rootVD, "/"+layer0File)
	openFD1 := openAt(rootVD, "/"+layer1File)
	extraFD := openAt(extraVD, "/"+extraFile)

	// Advance openFD0 halfway before checkpoint to verify cursor persistence.
	const splitAt = 15
	if got := readVFSFD(t, sctxPre, openFD0, splitAt); got != layer0Body[:splitAt] {
		t.Fatalf("pre-save partial read = %q, want %q", got, layer0Body[:splitAt])
	}
	vdaPre := blockdev.Of(vfsPre).Find("vda")
	if vdaPre == nil || vdaPre.Stats == nil {
		t.Fatalf("pre-save blockdev.Of(vfsPre).Find(vda) = %+v, want non-nil disk with Stats", vdaPre)
	}
	preSnap := vdaPre.Stats.Snapshot()
	if preSnap.ReadsCompleted != 1 || preSnap.SectorsRead == 0 {
		t.Fatalf("pre-save vda.Stats = %+v, want ReadsCompleted=1 with non-zero SectorsRead", preSnap)
	}
	wantSectors := vdaPre.Sectors()

	if err := vfsPre.PrepareSave(sctxPre, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("vfsPre.PrepareSave: %v", err)
	}

	var memStream bytes.Buffer
	if err := mfPre.SaveTo(context.Background(), &memStream, &pgalloc.SaveOpts{}); err != nil {
		t.Fatalf("mfPre.SaveTo: %v", err)
	}

	saveRoot := &erofsVFSSaveRoot{
		VFS:     vfsPre,
		Root:    rootVD,
		Extra:   extraVD,
		OpenFD0: openFD0,
		OpenFD1: openFD1,
		ExtraFD: extraFD,
		Clock:   clockPre,
		Creds:   credsPre,
	}
	var stateStream bytes.Buffer
	if _, err := state.Save(sctxPre, &stateStream, saveRoot); err != nil {
		t.Fatalf("state.Save VFS: %v", err)
	}

	// Tear down pre-save references so restored reads prove complete independence.
	openFD0.DecRef(sctxPre)
	openFD1.DecRef(sctxPre)
	extraFD.DecRef(sctxPre)
	extraVD.DecRef(sctxPre)
	rootVD.DecRef(sctxPre)
	vfsPre.Release(sctxPre)

	// Restore twice from the same Sandbox HostHandles to prove Dup() preserves caller handles.
	for attempt := range 2 {
		mfPost := newTestMemoryFile(t, fmt.Sprintf("erofs-sr-post-%d", attempt))
		if err := mfPost.LoadFrom(context.Background(), bytes.NewReader(memStream.Bytes()), &pgalloc.LoadOpts{}); err != nil {
			t.Fatalf("attempt %d: mfPost.LoadFrom: %v", attempt, err)
		}

		baseRestoreCtx := gvcontext.WithValue(gvcontext.Background(), pgalloc.CtxMemoryFile, mfPost)
		withRootMap, err := sb.WithRestoreEROFSFDMap(baseRestoreCtx)
		if err != nil {
			t.Fatalf("attempt %d: sb.WithRestoreEROFSFDMap: %v", attempt, err)
		}
		fullRestoreCtx, err := WithRestoreEROFSFDMap(withRootMap, []EROFSLayerMount{{
			MountTarget: "/mnt/extra",
			LayerIndex:  0,
			Digest:      extraStats.SHA256Hex,
			Handle:      extraHH,
		}})
		if err != nil {
			t.Fatalf("attempt %d: WithRestoreEROFSFDMap(extra): %v", attempt, err)
		}
		restoreSctx, ok := fullRestoreCtx.(gvcontext.Context)
		if !ok {
			t.Fatalf("attempt %d: WithRestoreEROFSFDMap did not preserve pkg/context.Context", attempt)
		}
		fdMap := vfs.RestoreFilesystemFDMapFromContext(restoreSctx)
		if len(fdMap) != 3 {
			t.Fatalf("attempt %d: len(RestoreFilesystemFDMap) = %d, want 3 (%v)", attempt, len(fdMap), fdMap)
		}

		var restored erofsVFSSaveRoot
		if _, err := state.Load(restoreSctx, bytes.NewReader(stateStream.Bytes()), &restored); err != nil {
			t.Fatalf("attempt %d: state.Load VFS: %v", attempt, err)
		}
		if len(fdMap) != 0 {
			t.Fatalf("attempt %d: restore left %d unclaimed FDs in RestoreFilesystemFDMap, want 0 (%v)", attempt, len(fdMap), fdMap)
		}
		if err := restored.VFS.CompleteRestore(restoreSctx, &vfs.CompleteRestoreOptions{}); err != nil {
			t.Fatalf("attempt %d: CompleteRestore: %v", attempt, err)
		}

		vdaPost := blockdev.Of(restored.VFS).Find("vda")
		if vdaPost == nil || vdaPost.Stats == nil {
			t.Fatalf("attempt %d: post-restore blockdev.Of(restored.VFS).Find(vda) = %+v, want non-nil disk with Stats", attempt, vdaPost)
		}
		if got := vdaPost.Sectors(); got != wantSectors {
			t.Fatalf("attempt %d: post-restore vda.Sectors() = %d, want %d", attempt, got, wantSectors)
		}
		postLoadSnap := vdaPost.Stats.Snapshot()
		if postLoadSnap.ReadsCompleted != preSnap.ReadsCompleted || postLoadSnap.SectorsRead != preSnap.SectorsRead {
			t.Fatalf("attempt %d: post-restore vda.Stats = %+v, want %+v", attempt, postLoadSnap, preSnap)
		}

		readCtx := newTestSentryContext(t, mfPost, restored.Clock, restored.Creds)

		if gotTail := readVFSFD(t, readCtx, restored.OpenFD0, len(layer0Body)); gotTail != layer0Body[splitAt:] {
			t.Fatalf("attempt %d: restored OpenFD0 remaining bytes = %q, want %q", attempt, gotTail, layer0Body[splitAt:])
		}
		if gotFull0 := preadVFSFD(t, readCtx, restored.OpenFD0, 0, len(layer0Body)); gotFull0 != layer0Body {
			t.Fatalf("attempt %d: restored OpenFD0 PRead(0) = %q, want %q", attempt, gotFull0, layer0Body)
		}
		// Reading the already-claimed page of layer0 must not increment vda.Stats.
		if afterLayer0Snap := vdaPost.Stats.Snapshot(); afterLayer0Snap.ReadsCompleted != preSnap.ReadsCompleted || afterLayer0Snap.SectorsRead != preSnap.SectorsRead {
			t.Fatalf("attempt %d: reading already-touched layer0 page recounted vda.Stats: got %+v, want %+v", attempt, afterLayer0Snap, preSnap)
		}
		if gotFull1 := readVFSFD(t, readCtx, restored.OpenFD1, len(layer1Body)); gotFull1 != layer1Body {
			t.Fatalf("attempt %d: restored OpenFD1 Read = %q, want %q", attempt, gotFull1, layer1Body)
		}
		// Reading the untouched page of layer1 must advance vda.Stats.
		if afterLayer1Snap := vdaPost.Stats.Snapshot(); afterLayer1Snap.ReadsCompleted != preSnap.ReadsCompleted+1 || afterLayer1Snap.SectorsRead <= preSnap.SectorsRead {
			t.Fatalf("attempt %d: reading untouched layer1 page did not advance vda.Stats: got %+v, pre-save %+v", attempt, afterLayer1Snap, preSnap)
		}
		if gotExtra := readVFSFD(t, readCtx, restored.ExtraFD, len(extraBody)); gotExtra != extraBody {
			t.Fatalf("attempt %d: restored ExtraFD Read = %q, want %q", attempt, gotExtra, extraBody)
		}

		// Open a fresh descriptor through the restored overlay root as well.
		reopened, err := restored.VFS.OpenAt(readCtx, restored.Creds, &vfs.PathOperation{
			Root:  restored.Root,
			Start: restored.Root,
			Path:  fspath.Parse("/" + layer0File),
		}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
		if err != nil {
			t.Fatalf("attempt %d: post-restore OpenAt: %v", attempt, err)
		}
		if got := readVFSFD(t, readCtx, reopened, len(layer0Body)); got != layer0Body {
			t.Fatalf("attempt %d: reopened layer0 Read = %q, want %q", attempt, got, layer0Body)
		}
		reopened.DecRef(readCtx)

		restored.OpenFD0.DecRef(readCtx)
		restored.OpenFD1.DecRef(readCtx)
		restored.ExtraFD.DecRef(readCtx)
		restored.Extra.DecRef(readCtx)
		restored.Root.DecRef(readCtx)
		restored.VFS.Release(readCtx)
	}

	// Colliding with an existing UniqueID already in ctx must fail without leaking FDs.
	ctx1, err := sb.WithRestoreEROFSFDMap(context.Background())
	if err != nil {
		t.Fatalf("first sb.WithRestoreEROFSFDMap: %v", err)
	}
	defer func() {
		_ = closeRestoreFDMap(vfs.RestoreFilesystemFDMapFromContext(ctx1))
	}()
	if _, err := sb.WithRestoreEROFSFDMap(ctx1); err == nil {
		t.Fatal("duplicate sb.WithRestoreEROFSFDMap on same context succeeded, want collision error")
	}
}

func TestCloseRestoreFDMapClosesAndClearsUnclaimedDescriptors(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache: %v", err)
	}
	path, stats, err := cache.CompileAndStore("", bytes.NewReader(buildTestTarLayer(t, map[string]string{"a.txt": "a"})))
	if err != nil {
		t.Fatalf("CompileAndStore: %v", err)
	}
	hh, err := fd.OpenHostPath(path, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenHostPath: %v", err)
	}
	t.Cleanup(func() { _ = hh.Close() })

	fdMap, err := BuildRestoreEROFSFDMap([]EROFSLayerMount{{MountTarget: "/", Digest: stats.SHA256Hex, Handle: hh}})
	if err != nil {
		t.Fatalf("BuildRestoreEROFSFDMap: %v", err)
	}
	if err := closeRestoreFDMap(fdMap); err != nil {
		t.Fatalf("closeRestoreFDMap: %v", err)
	}
	if len(fdMap) != 0 {
		t.Fatalf("closeRestoreFDMap left %d entries, want 0", len(fdMap))
	}
	// A second call must not close the (possibly reused) descriptor number again.
	if err := closeRestoreFDMap(fdMap); err != nil {
		t.Fatalf("second closeRestoreFDMap: %v", err)
	}
	if _, err := hh.Dup(); err != nil {
		t.Fatalf("original handle is unusable after cleanup: %v", err)
	}
}
