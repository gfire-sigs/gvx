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
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/refs"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

// savableMappingSpace implements memmap.MappingSpace and state.Type for unit tests.
type savableMappingSpace struct {
	invalidations int64
}

func (s *savableMappingSpace) Invalidate(_ hostarch.AddrRange, _ memmap.InvalidateOpts) {
	s.invalidations++
}

func (s *savableMappingSpace) StateTypeName() string {
	return "pkg/sentry/fsimpl/hostfs.savableMappingSpace"
}

func (s *savableMappingSpace) StateFields() []string {
	return []string{"invalidations"}
}

func (s *savableMappingSpace) StateSave(sink state.Sink) {
	sink.SaveInt64(0, &s.invalidations)
}

func (s *savableMappingSpace) StateLoad(_ goContext.Context, src state.Source) {
	src.LoadInt64(0, &s.invalidations)
}

// savableNSRefs implements refs.TryRefCounter and state.Type for test MountNamespaces.
type savableNSRefs struct {
	count atomic.Int64
	ns    vfs.Namespace
}

func (r *savableNSRefs) IncRef() {
	r.count.Add(1)
}

func (r *savableNSRefs) TryIncRef() bool {
	for {
		cur := r.count.Load()
		if cur <= 0 {
			return false
		}
		if r.count.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

func (r *savableNSRefs) DecRef(ctx gvcontext.Context) {
	if r.count.Add(-1) == 0 && r.ns != nil {
		r.ns.Destroy(ctx)
	}
}

func (r *savableNSRefs) StateTypeName() string {
	return "pkg/sentry/fsimpl/hostfs.savableNSRefs"
}

func (r *savableNSRefs) StateFields() []string {
	return []string{"count", "ns"}
}

func (r *savableNSRefs) StateSave(sink state.Sink) {
	v := r.count.Load()
	sink.SaveInt64(0, &v)
	sink.Save(1, &r.ns)
}

func (r *savableNSRefs) StateLoad(_ goContext.Context, src state.Source) {
	var v int64
	src.LoadInt64(0, &v)
	r.count.Store(v)
	src.Load(1, &r.ns)
}

type testNSFS struct{}

func (testNSFS) GetNamespaceInode(_ gvcontext.Context, ns vfs.Namespace) refs.TryRefCounter {
	r := &savableNSRefs{ns: ns}
	r.count.Store(1)
	return r
}

// checkpointBundle groups the VFS graph roots saved and restored in hostfs tests.
type checkpointBundle struct {
	vfsObj     *vfs.VirtualFilesystem
	mntns      *vfs.MountNamespace
	root       vfs.VirtualDentry
	regFD      *vfs.FileDescription
	dirFD      *vfs.FileDescription
	unlinkedFD *vfs.FileDescription
	inotifyFD  *vfs.FileDescription
	mappable   memmap.Mappable
	mapSpace   *savableMappingSpace
}

func (b *checkpointBundle) StateTypeName() string {
	return "pkg/sentry/fsimpl/hostfs.checkpointBundle"
}

func (b *checkpointBundle) StateFields() []string {
	return []string{
		"vfsObj",
		"mntns",
		"root",
		"regFD",
		"dirFD",
		"unlinkedFD",
		"inotifyFD",
		"mappable",
		"mapSpace",
	}
}

func (b *checkpointBundle) StateSave(sink state.Sink) {
	sink.Save(0, &b.vfsObj)
	sink.Save(1, &b.mntns)
	sink.Save(2, &b.root)
	sink.Save(3, &b.regFD)
	sink.Save(4, &b.dirFD)
	sink.Save(5, &b.unlinkedFD)
	sink.Save(6, &b.inotifyFD)
	sink.Save(7, &b.mappable)
	sink.Save(8, &b.mapSpace)
}

func (b *checkpointBundle) StateLoad(_ goContext.Context, src state.Source) {
	src.Load(0, &b.vfsObj)
	src.Load(1, &b.mntns)
	src.Load(2, &b.root)
	src.Load(3, &b.regFD)
	src.Load(4, &b.dirFD)
	src.Load(5, &b.unlinkedFD)
	src.Load(6, &b.inotifyFD)
	src.Load(7, &b.mappable)
	src.Load(8, &b.mapSpace)
}

func init() {
	state.RegisterNoHooks((*savableMappingSpace)(nil))
	state.RegisterNoHooks((*savableNSRefs)(nil))
	state.RegisterNoHooks((*checkpointBundle)(nil))
}

type stopAfterDirentCallback struct {
	names     []string
	stopAfter int
}

func (c *stopAfterDirentCallback) Handle(dirent vfs.Dirent) error {
	if c.stopAfter > 0 && len(c.names) >= c.stopAfter {
		return linuxerr.EINTR
	}
	c.names = append(c.names, dirent.Name)
	return nil
}

func listStagedEphemeralFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	var out []string
	for _, ent := range ents {
		name := ent.Name()
		if isEphemeralName(name) {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func TestSaveRestoreRoundTrip(t *testing.T) {
	dir := resolvedTempDir(t)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatalf("Chmod: %v", err)
		}
	}

	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	saveMem := newTestChunkMemory(t).(testChunkMemory)
	ws.SetChunkMemory(saveMem)

	baseCtx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mountID := checkpoint.ResourceID{ContainerName: "sandbox-sr", Path: "/workspace"}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Workspace: ws,
				UniqueID:  mountID,
			},
		},
	}, testNSFS{})
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(baseCtx)
	ctx := cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}

	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: true}
	}
	noFollowPop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p)}
	}

	// 1. Seed .gvx_meta POSIX mode, uid, gid, and xattr on meta.txt.
	metaFD, err := vfsObj.OpenAt(ctx, creds, pop("meta.txt"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o644,
	})
	if err != nil {
		t.Fatalf("OpenAt(meta.txt): %v", err)
	}
	if _, err := metaFD.Write(ctx, usermem.BytesIOSequence([]byte("meta-payload")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(meta.txt): %v", err)
	}
	metaFD.DecRef(ctx)
	if err := vfsObj.SetStatAt(ctx, creds, pop("meta.txt"), &vfs.SetStatOptions{
		Stat: linux.Statx{
			Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
			Mode: 0o750,
			UID:  1001,
			GID:  1002,
		},
	}); err != nil {
		t.Fatalf("SetStatAt(meta.txt): %v", err)
	}
	if err := vfsObj.SetXattrAt(ctx, creds, pop("meta.txt"), &vfs.SetXattrOptions{
		Name:  "user.tag",
		Value: "persisted-value",
	}); err != nil {
		t.Fatalf("SetXattrAt(meta.txt): %v", err)
	}

	// 2. Open regular file reg.txt, write bytes, and leave seek offset at 6.
	regFD, err := vfsObj.OpenAt(ctx, creds, pop("reg.txt"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o640,
	})
	if err != nil {
		t.Fatalf("OpenAt(reg.txt): %v", err)
	}
	if _, err := regFD.Write(ctx, usermem.BytesIOSequence([]byte("hello-world")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(reg.txt): %v", err)
	}
	if off, err := regFD.Seek(ctx, 6, linux.SEEK_SET); err != nil || off != 6 {
		t.Fatalf("Seek(reg.txt) = (%d, %v), want (6, nil)", off, err)
	}

	// 3. Create mapped.txt, map it writable, and dirty chunkcache pages via MapInternal.
	mappedFD, err := vfsObj.OpenAt(ctx, creds, pop("mapped.txt"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o600,
	})
	if err != nil {
		t.Fatalf("OpenAt(mapped.txt): %v", err)
	}
	initialMapped := bytes.Repeat([]byte("A"), hostarch.PageSize)
	if _, err := mappedFD.Write(ctx, usermem.BytesIOSequence(initialMapped), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(mapped.txt): %v", err)
	}
	mmapOpts := &memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Offset:   0,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	}
	if err := mappedFD.ConfigureMMap(ctx, mmapOpts); err != nil {
		t.Fatalf("ConfigureMMap(mapped.txt): %v", err)
	}
	mapSpace := &savableMappingSpace{}
	mapAR := hostarch.AddrRange{Start: 0x40000, End: 0x40000 + hostarch.PageSize}
	if err := mmapOpts.Mappable.AddMapping(ctx, mapSpace, mapAR, 0, true); err != nil {
		t.Fatalf("AddMapping(mapped.txt): %v", err)
	}
	mappedFD.DecRef(ctx)
	if mmapOpts.MappingIdentity != nil {
		mmapOpts.MappingIdentity.DecRef(ctx)
	}
	reqRange := memmap.MappableRange{Start: 0, End: hostarch.PageSize}
	ts, err := mmapOpts.Mappable.Translate(ctx, reqRange, reqRange, hostarch.ReadWrite)
	if err != nil || len(ts) == 0 {
		t.Fatalf("Translate(mapped.txt) before save = (%v, %v)", ts, err)
	}
	bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + hostarch.PageSize}, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(mapped.txt) before save: %v", err)
	}
	const dirtyPrefix = "DIRTY-MMAP-CHECKPOINT!"
	copy(bs.Head().ToSlice(), dirtyPrefix)

	// 4. Open directory listingdir and advance cursor past ".", "..", and "a.txt".
	if err := vfsObj.MkdirAt(ctx, creds, noFollowPop("listingdir"), &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt(listingdir): %v", err)
	}
	for _, leaf := range []string{"a.txt", "b.txt", "c.txt"} {
		f, fErr := vfsObj.OpenAt(ctx, creds, pop("listingdir/"+leaf), &vfs.OpenOptions{
			Flags: linux.O_CREAT | linux.O_WRONLY | linux.O_TRUNC,
			Mode:  0o644,
		})
		if fErr != nil {
			t.Fatalf("OpenAt(listingdir/%s): %v", leaf, fErr)
		}
		f.DecRef(ctx)
	}
	dirFD, err := vfsObj.OpenAt(ctx, creds, pop("listingdir"), &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_DIRECTORY,
	})
	if err != nil {
		t.Fatalf("OpenAt(listingdir): %v", err)
	}
	cbBefore := &stopAfterDirentCallback{stopAfter: 3}
	if err := dirFD.IterDirents(ctx, cbBefore); !linuxerr.Equals(linuxerr.EINTR, err) {
		t.Fatalf("IterDirents partial error = %v, want EINTR", err)
	}
	if want := []string{".", "..", "a.txt"}; !slices.Equal(cbBefore.names, want) {
		t.Fatalf("IterDirents before save = %v, want %v", cbBefore.names, want)
	}

	// 5. Open unlinked.txt, write payload, unlink it while keeping FD open, and seek to offset 9.
	unlinkedFD, err := vfsObj.OpenAt(ctx, creds, pop("unlinked.txt"), &vfs.OpenOptions{
		Flags: linux.O_CREAT | linux.O_RDWR | linux.O_TRUNC,
		Mode:  0o600,
	})
	if err != nil {
		t.Fatalf("OpenAt(unlinked.txt): %v", err)
	}
	if _, err := unlinkedFD.Write(ctx, usermem.BytesIOSequence([]byte("unlinked-before-save")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(unlinked.txt): %v", err)
	}
	if err := vfsObj.UnlinkAt(ctx, creds, noFollowPop("unlinked.txt")); err != nil {
		t.Fatalf("UnlinkAt(unlinked.txt): %v", err)
	}
	if off, err := unlinkedFD.Seek(ctx, 9, linux.SEEK_SET); err != nil || off != 9 {
		t.Fatalf("Seek(unlinked.txt) = (%d, %v), want (9, nil)", off, err)
	}

	// 6. Seed a stale unclaimed .gvx_tmp_orphan file on the host workspace.
	orphanPath := filepath.Join(dir, ".gvx_tmp_orphan")
	if err := os.WriteFile(orphanPath, []byte("stale-orphan"), 0o600); err != nil {
		t.Fatalf("WriteFile(.gvx_tmp_orphan): %v", err)
	}

	// 7. Run PrepareSave and verify dirty mapped pages flushed and MemoryFile chunks released.
	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	if saveMem.releases.Load() < 1 {
		t.Fatalf("PrepareSave released %d chunks, want >= 1", saveMem.releases.Load())
	}
	if mapSpace.invalidations < 1 {
		t.Fatalf("PrepareSave invalidated %d mappings, want >= 1", mapSpace.invalidations)
	}
	flushedOnHost, err := os.ReadFile(filepath.Join(dir, "mapped.txt"))
	if err != nil {
		t.Fatalf("ReadFile(mapped.txt) after PrepareSave: %v", err)
	}
	if !strings.HasPrefix(string(flushedOnHost), dirtyPrefix) {
		t.Fatalf("mapped.txt prefix after PrepareSave = %q, want %q", string(flushedOnHost[:len(dirtyPrefix)]), dirtyPrefix)
	}

	// 8. Serialize the VFS graph with state.Save.
	origBundle := &checkpointBundle{
		vfsObj:     vfsObj,
		mntns:      mntns,
		root:       root,
		regFD:      regFD,
		dirFD:      dirFD,
		unlinkedFD: unlinkedFD,
		mappable:   mmapOpts.Mappable,
		mapSpace:   mapSpace,
	}
	var stateBuf bytes.Buffer
	if _, err := state.Save(goContext.Background(), &stateBuf, origBundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	// 9. Tear down the saving VFS and verify staged unlinked backing file survives teardown.
	mmapOpts.Mappable.RemoveMapping(ctx, mapSpace, mapAR, 0, true)
	regFD.DecRef(ctx)
	dirFD.DecRef(ctx)
	unlinkedFD.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(baseCtx)
	vfsObj.Release(baseCtx)
	if err := ws.Close(); err != nil {
		t.Fatalf("saving Workspace.Close: %v", err)
	}

	ephemeralBeforeOpen := listStagedEphemeralFiles(t, dir)
	if !slices.Contains(ephemeralBeforeOpen, ".gvx_tmp_orphan") || len(ephemeralBeforeOpen) < 2 {
		t.Fatalf("ephemeral files after saving teardown = %v, want .gvx_tmp_orphan plus staged unlinked backing", ephemeralBeforeOpen)
	}

	// 10. OpenWorkspaceForRestore preserves both .gvx_tmp_orphan and the staged unlinked backing file.
	restoredWS, err := OpenWorkspaceForRestore(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore: %v", err)
	}
	defer func() {
		if closeErr := restoredWS.Close(); closeErr != nil {
			t.Errorf("restoredWS.Close: %v", closeErr)
		}
	}()
	restoreMem := newTestChunkMemory(t).(testChunkMemory)
	restoredWS.SetChunkMemory(restoreMem)

	ephemeralAfterOpen := listStagedEphemeralFiles(t, dir)
	if !slices.Equal(ephemeralAfterOpen, ephemeralBeforeOpen) {
		t.Fatalf("OpenWorkspaceForRestore altered ephemeral files: got %v, want %v", ephemeralAfterOpen, ephemeralBeforeOpen)
	}

	// 11. Deserialize via state.Load and run CompleteRestore with the pre-opened workspace.
	var restored checkpointBundle
	loadGoCtx := WithRestoreWorkspace(goContext.Background(), mountID, restoredWS)
	if _, err := state.Load(loadGoCtx, bytes.NewReader(stateBuf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoreBaseCtx := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, restoredWS)
	restoreCtx := cookieContext{vfs.WithMountNamespace(restoreBaseCtx, restored.mntns)}
	defer func() {
		if restored.mappable != nil {
			restored.mappable.RemoveMapping(restoreCtx, restored.mapSpace, mapAR, 0, true)
		}
		if restored.regFD != nil {
			restored.regFD.DecRef(restoreCtx)
		}
		if restored.dirFD != nil {
			restored.dirFD.DecRef(restoreCtx)
		}
		if restored.unlinkedFD != nil {
			restored.unlinkedFD.DecRef(restoreCtx)
		}
		restored.root.DecRef(restoreCtx)
		restored.mntns.DecRef(restoreBaseCtx)
		restored.vfsObj.Release(restoreBaseCtx)
	}()

	if err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	// 12. Verify .gvx_tmp_orphan was swept while the claimed unlinked backing file survived.
	if _, err := os.Stat(orphanPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Stat(.gvx_tmp_orphan) after CompleteRestore = %v, want ErrNotExist", err)
	}
	claimedAfterRestore := listStagedEphemeralFiles(t, dir)
	if len(claimedAfterRestore) != 1 {
		t.Fatalf("claimed ephemeral files after CompleteRestore = %v, want 1 live unlinked backing", claimedAfterRestore)
	}

	// 13. Verify open regular FD offset and read/write accuracy.
	regBuf := make([]byte, 32)
	n, err := restored.regFD.Read(restoreCtx, usermem.BytesIOSequence(regBuf), vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("restored regFD.Read: %v", err)
	}
	if got := string(regBuf[:n]); got != "world" {
		t.Fatalf("restored regFD.Read from saved offset = %q, want %q", got, "world")
	}
	if _, err := restored.regFD.Write(restoreCtx, usermem.BytesIOSequence([]byte("-after")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored regFD.Write: %v", err)
	}
	hostRegBytes, err := os.ReadFile(filepath.Join(dir, "reg.txt"))
	if err != nil || string(hostRegBytes) != "hello-world-after" {
		t.Fatalf("host reg.txt after post-restore write = (%q, %v), want %q", hostRegBytes, err, "hello-world-after")
	}

	// 14. Verify open unlinked FD offset, read/write accuracy, Nlink == 0, and cleanup on close.
	unlinkedBuf := make([]byte, 32)
	n, err = restored.unlinkedFD.Read(restoreCtx, usermem.BytesIOSequence(unlinkedBuf), vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("restored unlinkedFD.Read: %v", err)
	}
	if got := string(unlinkedBuf[:n]); got != "before-save" {
		t.Fatalf("restored unlinkedFD.Read from saved offset = %q, want %q", got, "before-save")
	}
	if _, err := restored.unlinkedFD.Write(restoreCtx, usermem.BytesIOSequence([]byte("+post")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("restored unlinkedFD.Write: %v", err)
	}
	fullUnlinked := make([]byte, 64)
	n, err = restored.unlinkedFD.PRead(restoreCtx, usermem.BytesIOSequence(fullUnlinked), 0, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("restored unlinkedFD.PRead: %v", err)
	}
	if got := string(fullUnlinked[:n]); got != "unlinked-before-save+post" {
		t.Fatalf("restored unlinkedFD.PRead(0) = %q, want %q", got, "unlinked-before-save+post")
	}
	unlinkedStat, err := restored.unlinkedFD.Stat(restoreCtx, vfs.StatOptions{Mask: linux.STATX_NLINK})
	if err != nil || unlinkedStat.Nlink != 0 {
		t.Fatalf("restored unlinkedFD.Stat Nlink = (%d, %v), want (0, nil)", unlinkedStat.Nlink, err)
	}

	// 15. Verify mapped Translate succeeds without BusError and uses the restored ChunkMemory.
	postTS, err := restored.mappable.Translate(restoreCtx, reqRange, reqRange, hostarch.ReadWrite)
	if err != nil || len(postTS) == 0 {
		t.Fatalf("post-restore Translate(mapped.txt) = (%v, %v)", postTS, err)
	}
	if postTS[0].File != memmap.File(restoreMem) {
		t.Fatalf("post-restore translation File = %T, want restored ChunkMemory", postTS[0].File)
	}
	postBS, err := postTS[0].File.MapInternal(memmap.FileRange{Start: postTS[0].Offset, End: postTS[0].Offset + uint64(len(dirtyPrefix))}, hostarch.Read)
	if err != nil {
		t.Fatalf("post-restore MapInternal: %v", err)
	}
	if got := string(postBS.Head().ToSlice()); got != dirtyPrefix {
		t.Fatalf("post-restore mapped bytes = %q, want %q", got, dirtyPrefix)
	}

	// 16. Verify directory FD resumes at saved cursor offset without repeating ".", "..", or "a.txt".
	cbAfter := &stopAfterDirentCallback{}
	if err := restored.dirFD.IterDirents(restoreCtx, cbAfter); err != nil {
		t.Fatalf("post-restore dirFD.IterDirents: %v", err)
	}
	if want := []string{"b.txt", "c.txt"}; !slices.Equal(cbAfter.names, want) {
		t.Fatalf("post-restore dirFD remaining entries = %v, want %v", cbAfter.names, want)
	}

	// 17. Verify .gvx_meta mode, uid, gid, and xattr persisted on meta.txt.
	rPop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: restored.root, Start: restored.root, Path: fspath.Parse(p), FollowFinalSymlink: true}
	}
	metaStat, err := restored.vfsObj.StatAt(restoreCtx, creds, rPop("meta.txt"), &vfs.StatOptions{
		Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID,
	})
	if err != nil {
		t.Fatalf("post-restore StatAt(meta.txt): %v", err)
	}
	if metaStat.Mode&0o7777 != 0o750 || metaStat.UID != 1001 || metaStat.GID != 1002 {
		t.Fatalf("post-restore StatAt(meta.txt) = (mode=%o uid=%d gid=%d), want (0750, 1001, 1002)",
			metaStat.Mode&0o7777, metaStat.UID, metaStat.GID)
	}
	gotXattr, err := restored.vfsObj.GetXattrAt(restoreCtx, creds, rPop("meta.txt"), &vfs.GetXattrOptions{
		Name: "user.tag",
		Size: 64,
	})
	if err != nil || gotXattr != "persisted-value" {
		t.Fatalf("post-restore GetXattrAt(meta.txt) = (%q, %v), want (%q, nil)", gotXattr, err, "persisted-value")
	}

	// 18. Closing the restored unlinked FD removes its staged backing file from disk.
	restored.unlinkedFD.DecRef(restoreCtx)
	restored.unlinkedFD = nil
	if rem := listStagedEphemeralFiles(t, dir); len(rem) != 0 {
		t.Fatalf("ephemeral files after closing restored unlinkedFD = %v, want empty", rem)
	}
}

func TestSaveRestoreSingleFileMount(t *testing.T) {
	hostDir := resolvedTempDir(t)
	filePath := filepath.Join(hostDir, "bound.conf")
	if err := os.WriteFile(filePath, []byte("alpha=1\nbeta=2\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	ws, err := OpenWorkspace(filePath, false)
	if err != nil {
		t.Fatalf("OpenWorkspace(single): %v", err)
	}

	baseCtx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mountID := checkpoint.ResourceID{ContainerName: "sandbox-single", Path: "/etc/bound.conf"}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Workspace: ws,
				UniqueID:  mountID,
			},
		},
	}, testNSFS{})
	if err != nil {
		t.Fatalf("NewMountNamespace(single): %v", err)
	}
	root := mntns.Root(baseCtx)
	ctx := cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}

	rootPop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(""), FollowFinalSymlink: true}
	if err := vfsObj.SetStatAt(ctx, creds, rootPop, &vfs.SetStatOptions{
		Stat: linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID, Mode: 0o600, UID: 2000},
	}); err != nil {
		t.Fatalf("SetStatAt(single): %v", err)
	}
	regFD, err := vfsObj.OpenAt(ctx, creds, rootPop, &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		t.Fatalf("OpenAt(single): %v", err)
	}
	if _, err := regFD.Seek(ctx, 8, linux.SEEK_SET); err != nil {
		t.Fatalf("Seek(single): %v", err)
	}

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave(single): %v", err)
	}
	var buf bytes.Buffer
	orig := &checkpointBundle{vfsObj: vfsObj, mntns: mntns, root: root, regFD: regFD}
	if _, err := state.Save(goContext.Background(), &buf, orig); err != nil {
		t.Fatalf("state.Save(single): %v", err)
	}

	regFD.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(baseCtx)
	vfsObj.Release(baseCtx)
	if err := ws.Close(); err != nil {
		t.Fatalf("ws.Close(single): %v", err)
	}

	restoredWS, err := OpenWorkspaceForRestore(filePath, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore(single): %v", err)
	}
	defer func() { _ = restoredWS.Close() }()

	var restored checkpointBundle
	if _, err := state.Load(WithRestoreWorkspace(goContext.Background(), mountID, restoredWS), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load(single): %v", err)
	}
	restoreBaseCtx := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, restoredWS)
	restoreCtx := cookieContext{vfs.WithMountNamespace(restoreBaseCtx, restored.mntns)}
	defer func() {
		restored.regFD.DecRef(restoreCtx)
		restored.root.DecRef(restoreCtx)
		restored.mntns.DecRef(restoreBaseCtx)
		restored.vfsObj.Release(restoreBaseCtx)
	}()

	if err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore(single): %v", err)
	}

	readBuf := make([]byte, 16)
	n, err := restored.regFD.Read(restoreCtx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
	if err != nil || string(readBuf[:n]) != "beta=2\n" {
		t.Fatalf("post-restore single Read = (%q, %v), want (%q, nil)", readBuf[:n], err, "beta=2\n")
	}
	st, err := restored.regFD.Stat(restoreCtx, vfs.StatOptions{Mask: linux.STATX_MODE | linux.STATX_UID})
	if err != nil || st.Mode&0o7777 != 0o600 || st.UID != 2000 {
		t.Fatalf("post-restore single Stat = (mode=%o uid=%d err=%v), want (0600, 2000, nil)", st.Mode&0o7777, st.UID, err)
	}
}

func TestSaveRestoreRearmsDirectoryWatcher(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	ws.watch.factory = pollFactory
	ws.watch.setPollInterval(time.Hour)

	baseCtx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mountID := checkpoint.ResourceID{ContainerName: "sandbox-watch", Path: "/workspace"}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Workspace: ws,
				UniqueID:  mountID,
			},
		},
	}, testNSFS{})
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(baseCtx)
	ctx := idContext{Context: cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}, next: new(atomic.Uint64)}

	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("watched")}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt(watched): %v", err)
	}
	inFD, err := vfs.NewInotifyFD(ctx, vfsObj, linux.O_NONBLOCK)
	if err != nil {
		t.Fatalf("NewInotifyFD: %v", err)
	}
	vd, err := vfsObj.GetDentryAt(ctx, creds, &vfs.PathOperation{
		Root:               root,
		Start:              root,
		Path:               fspath.Parse("watched"),
		FollowFinalSymlink: true,
	}, &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatalf("GetDentryAt(watched): %v", err)
	}
	inFD.Impl().(*vfs.Inotify).AddWatch(vd.Dentry(), linux.IN_CREATE|linux.IN_DELETE)
	vd.DecRef(ctx)
	ws.watch.rescanAll()

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	var buf bytes.Buffer
	orig := &checkpointBundle{vfsObj: vfsObj, mntns: mntns, root: root, inotifyFD: inFD}
	if _, err := state.Save(goContext.Background(), &buf, orig); err != nil {
		t.Fatalf("state.Save: %v", err)
	}

	inFD.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(baseCtx)
	vfsObj.Release(baseCtx)
	if err := ws.Close(); err != nil {
		t.Fatalf("ws.Close: %v", err)
	}

	restoredWS, err := OpenWorkspaceForRestore(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore: %v", err)
	}
	restoredWS.watch.factory = pollFactory
	restoredWS.watch.setPollInterval(time.Hour)
	defer func() { _ = restoredWS.Close() }()

	var restored checkpointBundle
	if _, err := state.Load(WithRestoreWorkspace(goContext.Background(), mountID, restoredWS), bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoreBaseCtx := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, restoredWS)
	restoreCtx := idContext{Context: cookieContext{vfs.WithMountNamespace(restoreBaseCtx, restored.mntns)}, next: new(atomic.Uint64)}
	defer func() {
		restored.inotifyFD.DecRef(restoreCtx)
		restored.root.DecRef(restoreCtx)
		restored.mntns.DecRef(restoreBaseCtx)
		restored.vfsObj.Release(restoreBaseCtx)
	}()

	if err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	// Create a file on the host after restore and verify the re-armed watcher delivers IN_CREATE.
	if err := os.WriteFile(filepath.Join(dir, "watched", "after_restore.txt"), []byte("event"), 0o644); err != nil {
		t.Fatalf("WriteFile(after_restore.txt): %v", err)
	}
	restoredWS.watch.rescanAll()

	wEnv := &watchEnv{
		env: &env{t: t, ctx: restoreCtx, creds: creds, vfsObj: restored.vfsObj, root: restored.root, ws: restoredWS, dir: dir},
		ctx: restoreCtx,
		in:  restored.inotifyFD,
		ino: restored.inotifyFD.Impl().(*vfs.Inotify),
	}
	events := wEnv.drain()
	if !slices.Contains(eventNames(events), "CREATE after_restore.txt") {
		t.Fatalf("post-restore inotify events = %v, want CREATE after_restore.txt", eventNames(events))
	}
}

func TestSaveRestoreUnlinkedMappedWithoutFDAndLinkableTmpfile(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(filepath.Join(dir, "unlinked_map.txt"), []byte("initial-mapped-content\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(unlinked_map.txt): %v", err)
	}

	ws, err := OpenWorkspace(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspace: %v", err)
	}
	ws.SetChunkMemory(newTestChunkMemory(t))

	baseCtx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(baseCtx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mountID := checkpoint.ResourceID{ContainerName: "sandbox-live-inodes", Path: "/workspace"}
	mntns, err := vfsObj.NewMountNamespace(baseCtx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Workspace: ws,
				UniqueID:  mountID,
			},
		},
	}, testNSFS{})
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(baseCtx)
	ctx := cookieContext{vfs.WithMountNamespace(baseCtx, mntns)}
	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: true}
	}
	noFollowPop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p), FollowFinalSymlink: false}
	}

	// 1. Open unlinked_map.txt, establish a MAP_SHARED mapping, unlink it, and close its FD.
	// Only the memmap.Mappable holds a reference to the inode.
	mapFD, err := vfsObj.OpenAt(ctx, creds, pop("unlinked_map.txt"), &vfs.OpenOptions{Flags: linux.O_RDWR})
	if err != nil {
		t.Fatalf("OpenAt(unlinked_map.txt): %v", err)
	}
	mmapOpts := &memmap.MMapOpts{
		Length:   hostarch.PageSize,
		Offset:   0,
		Perms:    hostarch.ReadWrite,
		MaxPerms: hostarch.ReadWrite,
	}
	if err := mapFD.ConfigureMMap(ctx, mmapOpts); err != nil {
		t.Fatalf("ConfigureMMap: %v", err)
	}
	mapSpace := &savableMappingSpace{}
	mapAR := hostarch.AddrRange{Start: 0x300000, End: 0x300000 + hostarch.PageSize}
	reqRange := memmap.MappableRange{Start: 0, End: hostarch.PageSize}
	if err := mmapOpts.Mappable.AddMapping(ctx, mapSpace, mapAR, 0, true); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}
	if mmapOpts.MappingIdentity != nil {
		mmapOpts.MappingIdentity.DecRef(ctx)
	}
	if err := vfsObj.UnlinkAt(ctx, creds, noFollowPop("unlinked_map.txt")); err != nil {
		t.Fatalf("UnlinkAt(unlinked_map.txt): %v", err)
	}
	mapFD.DecRef(ctx)

	ts1, err := mmapOpts.Mappable.Translate(ctx, reqRange, reqRange, hostarch.ReadWrite)
	if err != nil || len(ts1) == 0 {
		t.Fatalf("Translate cycle 1: (%v, %v)", ts1, err)
	}
	bs1, err := ts1[0].File.MapInternal(memmap.FileRange{Start: ts1[0].Offset, End: ts1[0].Offset + 8}, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal cycle 1: %v", err)
	}
	copy(bs1.Head().ToSlice(), "CYCLE-1!")

	// 2. Open a linkable O_TMPFILE.
	tmpFD, err := vfsObj.OpenAt(ctx, creds, pop(""), &vfs.OpenOptions{
		Flags: linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_RDWR,
		Mode:  0o600,
	})
	if err != nil {
		t.Fatalf("OpenAt(O_TMPFILE): %v", err)
	}
	if _, err := tmpFD.Write(ctx, usermem.BytesIOSequence([]byte("tmpfile-data")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("tmpFD.Write: %v", err)
	}

	// 3. Save and restore cycle 1.
	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave 1: %v", err)
	}
	var buf1 bytes.Buffer
	orig1 := &checkpointBundle{
		vfsObj:     vfsObj,
		mntns:      mntns,
		root:       root,
		unlinkedFD: tmpFD,
		mappable:   mmapOpts.Mappable,
		mapSpace:   mapSpace,
	}
	if _, err := state.Save(goContext.Background(), &buf1, orig1); err != nil {
		t.Fatalf("state.Save 1: %v", err)
	}

	mmapOpts.Mappable.RemoveMapping(ctx, mapSpace, mapAR, 0, true)
	tmpFD.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(baseCtx)
	vfsObj.Release(baseCtx)
	if err := ws.Close(); err != nil {
		t.Fatalf("ws.Close 1: %v", err)
	}

	ws2, err := OpenWorkspaceForRestore(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore 1: %v", err)
	}
	ws2.SetChunkMemory(newTestChunkMemory(t))

	var restored1 checkpointBundle
	if _, err := state.Load(WithRestoreWorkspace(goContext.Background(), mountID, ws2), bytes.NewReader(buf1.Bytes()), &restored1); err != nil {
		t.Fatalf("state.Load 1: %v", err)
	}
	restoreBaseCtx1 := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, ws2)
	restoreCtx1 := cookieContext{vfs.WithMountNamespace(restoreBaseCtx1, restored1.mntns)}
	if err := restored1.vfsObj.CompleteRestore(restoreCtx1, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore 1: %v", err)
	}

	// 4. Materialize the restored O_TMPFILE via LinkAt, then unlink its visible name so it becomes an unlinked file.
	rNoFollowPop1 := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: restored1.root, Start: restored1.root, Path: fspath.Parse(p), FollowFinalSymlink: false}
	}
	tmpVD := restored1.unlinkedFD.VirtualDentry()
	if err := restored1.vfsObj.LinkAt(restoreCtx1, creds, &vfs.PathOperation{
		Root:               tmpVD,
		Start:              tmpVD,
		Path:               fspath.Parse(""),
		FollowFinalSymlink: true,
	}, rNoFollowPop1("linked_tmp.txt")); err != nil {
		t.Fatalf("LinkAt(O_TMPFILE): %v", err)
	}
	if err := restored1.vfsObj.UnlinkAt(restoreCtx1, creds, rNoFollowPop1("linked_tmp.txt")); err != nil {
		t.Fatalf("UnlinkAt(linked_tmp.txt): %v", err)
	}

	// 5. Dirty the unlinked mapped file again in cycle 1 and run a second checkpoint/restore cycle.
	ts2, err := restored1.mappable.Translate(restoreCtx1, reqRange, reqRange, hostarch.ReadWrite)
	if err != nil || len(ts2) == 0 {
		t.Fatalf("Translate after restore 1: (%v, %v)", ts2, err)
	}
	bs2, err := ts2[0].File.MapInternal(memmap.FileRange{Start: ts2[0].Offset, End: ts2[0].Offset + 8}, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal after restore 1: %v", err)
	}
	if got := string(bs2.Head().ToSlice()); got != "CYCLE-1!" {
		t.Fatalf("restored mapped prefix after cycle 1 = %q, want %q", got, "CYCLE-1!")
	}
	copy(bs2.Head().ToSlice(), "CYCLE-2!")

	if err := restored1.vfsObj.PrepareSave(restoreCtx1, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave 2: %v", err)
	}
	var buf2 bytes.Buffer
	if _, err := state.Save(goContext.Background(), &buf2, &restored1); err != nil {
		t.Fatalf("state.Save 2: %v", err)
	}

	restored1.mappable.RemoveMapping(restoreCtx1, restored1.mapSpace, mapAR, 0, true)
	restored1.unlinkedFD.DecRef(restoreCtx1)
	restored1.root.DecRef(restoreCtx1)
	restored1.mntns.DecRef(restoreBaseCtx1)
	restored1.vfsObj.Release(restoreBaseCtx1)
	if err := ws2.Close(); err != nil {
		t.Fatalf("ws2.Close: %v", err)
	}

	ws3, err := OpenWorkspaceForRestore(dir, false)
	if err != nil {
		t.Fatalf("OpenWorkspaceForRestore 2: %v", err)
	}
	defer func() { _ = ws3.Close() }()
	ws3.SetChunkMemory(newTestChunkMemory(t))

	var restored2 checkpointBundle
	if _, err := state.Load(WithRestoreWorkspace(goContext.Background(), mountID, ws3), bytes.NewReader(buf2.Bytes()), &restored2); err != nil {
		t.Fatalf("state.Load 2: %v", err)
	}
	restoreBaseCtx2 := WithRestoreWorkspaceContext(gvcontext.Background(), mountID, ws3)
	restoreCtx2 := cookieContext{vfs.WithMountNamespace(restoreBaseCtx2, restored2.mntns)}
	defer func() {
		if restored2.mappable != nil {
			restored2.mappable.RemoveMapping(restoreCtx2, restored2.mapSpace, mapAR, 0, true)
		}
		if restored2.unlinkedFD != nil {
			restored2.unlinkedFD.DecRef(restoreCtx2)
		}
		restored2.root.DecRef(restoreCtx2)
		restored2.mntns.DecRef(restoreBaseCtx2)
		restored2.vfsObj.Release(restoreBaseCtx2)
	}()

	if err := restored2.vfsObj.CompleteRestore(restoreCtx2, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore 2: %v", err)
	}

	ts3, err := restored2.mappable.Translate(restoreCtx2, reqRange, reqRange, hostarch.Read)
	if err != nil || len(ts3) == 0 {
		t.Fatalf("Translate after restore 2: (%v, %v)", ts3, err)
	}
	bs3, err := ts3[0].File.MapInternal(memmap.FileRange{Start: ts3[0].Offset, End: ts3[0].Offset + 8}, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal after restore 2: %v", err)
	}
	if got := string(bs3.Head().ToSlice()); got != "CYCLE-2!" {
		t.Fatalf("restored mapped prefix after cycle 2 = %q, want %q", got, "CYCLE-2!")
	}

	tmpReadBuf := make([]byte, 32)
	n, err := restored2.unlinkedFD.PRead(restoreCtx2, usermem.BytesIOSequence(tmpReadBuf), 0, vfs.ReadOptions{})
	if err != nil || string(tmpReadBuf[:n]) != "tmpfile-data" {
		t.Fatalf("restored linked-then-unlinked tmpFD PRead = (%q, %v), want (%q, nil)", tmpReadBuf[:n], err, "tmpfile-data")
	}
}
