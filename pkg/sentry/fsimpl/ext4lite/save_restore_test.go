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
	"bytes"
	stdctx "context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/refs"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

func init() {
	state.Register((*savedMappingSpace)(nil))
	state.Register((*checkpointBundle)(nil))
	state.Register((*testNamespaceRefs)(nil))
}

type testNamespaceGetter struct{}

func (testNamespaceGetter) GetNamespaceInode(_ gvcontext.Context, ns vfs.Namespace) refs.TryRefCounter {
	r := &testNamespaceRefs{ns: ns}
	r.refs.Store(1)
	return r
}

type testNamespaceRefs struct {
	refs atomicbitops.Int64
	ns   vfs.Namespace
}

func (r *testNamespaceRefs) IncRef() {
	r.refs.Add(1)
}

func (r *testNamespaceRefs) TryIncRef() bool {
	return chunkcache.TryIncRef(&r.refs)
}

func (r *testNamespaceRefs) DecRef(ctx gvcontext.Context) {
	if r.refs.Add(-1) == 0 {
		r.ns.Destroy(ctx)
	}
}

func (r *testNamespaceRefs) StateTypeName() string {
	return "pkg/sentry/fsimpl/ext4lite.testNamespaceRefs"
}

func (r *testNamespaceRefs) StateFields() []string {
	return []string{"refs", "ns"}
}

func (r *testNamespaceRefs) StateSave(sink state.Sink) {
	sink.Save(0, &r.refs)
	sink.Save(1, &r.ns)
}

func (r *testNamespaceRefs) StateLoad(_ stdctx.Context, src state.Source) {
	src.Load(0, &r.refs)
	src.Load(1, &r.ns)
}

// savedMappingSpace implements a savable memmap.MappingSpace that records
// invalidations across save and restore without a full MM.
type savedMappingSpace struct {
	mu           sync.Mutex
	invalidated  []hostarch.AddrRange
	persistedTag string
}

func (s *savedMappingSpace) Invalidate(ar hostarch.AddrRange, _ memmap.InvalidateOpts) {
	s.mu.Lock()
	s.invalidated = append(s.invalidated, ar)
	s.mu.Unlock()
}

func (s *savedMappingSpace) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.invalidated)
}

func (s *savedMappingSpace) StateTypeName() string {
	return "pkg/sentry/fsimpl/ext4lite.savedMappingSpace"
}

func (s *savedMappingSpace) StateFields() []string {
	return []string{"persistedTag"}
}

func (s *savedMappingSpace) StateSave(sink state.Sink) {
	sink.SaveString(0, &s.persistedTag)
}

func (s *savedMappingSpace) StateLoad(_ stdctx.Context, src state.Source) {
	src.LoadString(0, &s.persistedTag)
}

// checkpointBundle groups the VFS graph roots that state.Save serializes.
type checkpointBundle struct {
	vfsObj   *vfs.VirtualFilesystem
	mntns    *vfs.MountNamespace
	root     vfs.VirtualDentry
	creds    *auth.Credentials
	fds      []*vfs.FileDescription
	mappable memmap.Mappable
	mapIdent memmap.MappingIdentity
	mapSpace *savedMappingSpace
	mapRange hostarch.AddrRange
}

func (b *checkpointBundle) StateTypeName() string {
	return "pkg/sentry/fsimpl/ext4lite.checkpointBundle"
}

func (b *checkpointBundle) StateFields() []string {
	return []string{
		"vfsObj",
		"mntns",
		"root",
		"creds",
		"fds",
		"mappable",
		"mapIdent",
		"mapSpace",
		"mapRange",
	}
}

func (b *checkpointBundle) StateSave(sink state.Sink) {
	sink.Save(0, &b.vfsObj)
	sink.Save(1, &b.mntns)
	sink.Save(2, &b.root)
	sink.Save(3, &b.creds)
	sink.Save(4, &b.fds)
	sink.Save(5, &b.mappable)
	sink.Save(6, &b.mapIdent)
	sink.Save(7, &b.mapSpace)
	sink.Save(8, &b.mapRange)
}

func (b *checkpointBundle) StateLoad(_ stdctx.Context, src state.Source) {
	src.Load(0, &b.vfsObj)
	src.Load(1, &b.mntns)
	src.Load(2, &b.root)
	src.Load(3, &b.creds)
	src.Load(4, &b.fds)
	src.Load(5, &b.mappable)
	src.Load(6, &b.mapIdent)
	src.Load(7, &b.mapSpace)
	src.Load(8, &b.mapRange)
}

func newNamedEnv(t *testing.T, path, uniqueID string, vopts VolumeOptions) *env {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	vol, err := OpenVolume(f, vopts)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	vol.v.now = fakeClock()
	vol.v.assertGate.Store(true)

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	mopts := vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{
				Volume:   vol,
				UniqueID: uniqueID,
			},
		},
	}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &mopts, testNamespaceGetter{})
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
		mntns:  mntns,
		vol:    vol,
		fs:     root.Mount().Filesystem().Impl().(*filesystem),
		path:   path,
	}
	t.Cleanup(e.unmount)
	return e
}

func saveBundle(t *testing.T, ctx gvcontext.Context, bundle *checkpointBundle) []byte {
	t.Helper()
	if err := bundle.vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	var buf bytes.Buffer
	if _, err := state.Save(ctx, &buf, bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	return buf.Bytes()
}

func restoreBundle(t *testing.T, data []byte, volumes map[string]*Volume) (*env, *checkpointBundle, error) {
	t.Helper()
	baseCtx := gvcontext.Background()
	restoreCtx := WithRestoreVolumeMap(baseCtx, volumes)
	var restored checkpointBundle
	if _, err := state.Load(restoreCtx, bytes.NewReader(data), &restored); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	err := restored.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{})
	e := &env{
		t:      t,
		ctx:    cookieContext{vfs.WithMountNamespace(baseCtx, restored.mntns)},
		creds:  restored.creds,
		vfsObj: restored.vfsObj,
		root:   restored.root,
		mntns:  restored.mntns,
		fs:     restored.root.Mount().Filesystem().Impl().(*filesystem),
	}
	if err == nil {
		e.vol = e.fs.vol
	}
	t.Cleanup(func() {
		for _, fd := range restored.fds {
			if fd != nil {
				fd.DecRef(e.ctx)
			}
		}
		if restored.mappable != nil {
			restored.mappable.RemoveMapping(e.ctx, restored.mapSpace, restored.mapRange, 0, true)
		}
		if restored.mapIdent != nil {
			restored.mapIdent.DecRef(e.ctx)
		}
		e.unmount()
	})
	return e, &restored, err
}

func readTranslated(t *testing.T, ctx gvcontext.Context, m memmap.Mappable, start, end uint64) []byte {
	t.Helper()
	r := memmap.MappableRange{Start: start, End: end}
	ts, err := m.Translate(ctx, r, r, hostarch.Read)
	if err != nil {
		t.Fatalf("Translate read: %v", err)
	}
	var out []byte
	for _, tr := range ts {
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + tr.Source.Length()}, hostarch.Read)
		if err != nil {
			t.Fatalf("MapInternal read: %v", err)
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			out = append(out, bs.Head().ToSlice()...)
		}
	}
	return out
}

func writeTranslated(t *testing.T, ctx gvcontext.Context, m memmap.Mappable, off uint64, payload []byte) {
	t.Helper()
	r := memmap.MappableRange{Start: off, End: off + uint64(len(payload))}
	ts, err := m.Translate(ctx, r, r, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("Translate write: %v", err)
	}
	done := 0
	for _, tr := range ts {
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + tr.Source.Length()}, hostarch.ReadWrite)
		if err != nil {
			t.Fatalf("MapInternal write: %v", err)
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			done += copy(bs.Head().ToSlice(), payload[done:])
		}
	}
	if done != len(payload) {
		t.Fatalf("mapped write copied %d bytes, want %d", done, len(payload))
	}
}

type countingChunkMemory struct {
	testChunkMemory
	allocs *atomic.Int64
}

func newCountingChunkMemory(t *testing.T) countingChunkMemory {
	t.Helper()
	return countingChunkMemory{
		testChunkMemory: newTestChunkMemory(t),
		allocs:          new(atomic.Int64),
	}
}

func (m countingChunkMemory) AllocateChunk(length uint64) (memmap.FileRange, error) {
	fr, err := m.testChunkMemory.AllocateChunk(length)
	if err == nil {
		m.allocs.Add(1)
	}
	return fr, err
}

func volFreeInodes(vol *Volume) uint64 {
	vol.v.mu.Lock()
	defer vol.v.mu.Unlock()
	return vol.v.freeInodesTotal
}

func volFreeBlocks(vol *Volume) uint64 {
	vol.v.mu.Lock()
	defer vol.v.mu.Unlock()
	return vol.v.freeBlocksTotal
}

var errStopDirents = errors.New("stop dirents")

type oneDirentCallback struct {
	names []string
	limit int
}

func (c *oneDirentCallback) Handle(d vfs.Dirent) error {
	if c.limit > 0 && len(c.names) >= c.limit {
		return errStopDirents
	}
	c.names = append(c.names, d.Name)
	return nil
}

func TestSaveRestoreRegularDirAndMMap(t *testing.T) {
	for _, useMemFile := range []bool{false, true} {
		modeName := "heap"
		if useMemFile {
			modeName = "memfile"
		}
		t.Run(modeName, func(t *testing.T) {
			imgPath := filepath.Join(t.TempDir(), "vol.ext4")
			const mountID = "ext4-main"
			e := newNamedEnv(t, imgPath, mountID, VolumeOptions{})

			var saveMem countingChunkMemory
			if useMemFile {
				saveMem = newCountingChunkMemory(t)
				e.vol.SetChunkMemory(saveMem)
			}

			e.mustMkdir("work")
			e.writeFile("work/alpha", []byte("alpha"))
			e.writeFile("work/beta", []byte("beta"))
			if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("work/sym"), "alpha"); err != nil {
				t.Fatalf("SymlinkAt: %v", err)
			}

			initial := []byte(strings.Repeat("x", 2*hostarch.PageSize+64))
			e.writeFile("work/data", initial)
			regFD := e.mustOpen("work/data", linux.O_RDWR)

			// Write buffered bytes and position the file description at a non-zero offset.
			e.pwrite(regFD, []byte("BUFFERED"), 32)
			const savedOffset = 19
			if pos, err := regFD.Seek(e.ctx, savedOffset, linux.SEEK_SET); err != nil || pos != savedOffset {
				t.Fatalf("Seek = (%d, %v), want %d", pos, err, savedOffset)
			}

			// Map the file and dirty a mapped page without calling fsync.
			mapLen := uint64(2 * hostarch.PageSize)
			mopts := &memmap.MMapOpts{
				Length:   mapLen,
				Offset:   0,
				Perms:    hostarch.ReadWrite,
				MaxPerms: hostarch.ReadWrite,
			}
			if err := regFD.ConfigureMMap(e.ctx, mopts); err != nil {
				t.Fatalf("ConfigureMMap: %v", err)
			}
			ms := &savedMappingSpace{persistedTag: "space-1"}
			ar := hostarch.AddrRange{Start: 0x20000, End: 0x20000 + hostarch.Addr(mapLen)}
			if err := mopts.Mappable.AddMapping(e.ctx, ms, ar, 0, true); err != nil {
				t.Fatalf("AddMapping: %v", err)
			}
			writeTranslated(t, e.ctx, mopts.Mappable, uint64(hostarch.PageSize+8), []byte("MAPPED-DIRTY"))

			if useMemFile {
				if got := saveMem.allocs.Load() - saveMem.releases.Load(); got <= 0 {
					t.Fatalf("live MemoryFile chunks before save = %d, want > 0", got)
				}
			}

			// Open directory FD and advance halfway through its entries.
			dirFD := e.mustOpen("work", linux.O_RDONLY|linux.O_DIRECTORY)
			firstBatch := &oneDirentCallback{limit: 3}
			if err := dirFD.IterDirents(e.ctx, firstBatch); !errors.Is(err, errStopDirents) {
				t.Fatalf("IterDirents before save = %v, want errStopDirents", err)
			}
			if len(firstBatch.names) != 3 {
				t.Fatalf("read %d dirents before save, want 3", len(firstBatch.names))
			}

			bundle := &checkpointBundle{
				vfsObj:   e.vfsObj,
				mntns:    e.mntns,
				root:     e.root,
				creds:    e.creds,
				fds:      []*vfs.FileDescription{regFD, dirFD},
				mappable: mopts.Mappable,
				mapIdent: mopts.MappingIdentity,
				mapSpace: ms,
				mapRange: ar,
			}
			rawState := saveBundle(t, e.ctx, bundle)

			// PrepareSave must drop all MemoryFile chunk allocations and invalidate mappings.
			if useMemFile {
				if live := saveMem.allocs.Load() - saveMem.releases.Load(); live != 0 {
					t.Fatalf("live MemoryFile chunks after PrepareSave = %d (allocs=%d, releases=%d), want 0",
						live, saveMem.allocs.Load(), saveMem.releases.Load())
				}
			}
			if ms.count() == 0 {
				t.Fatal("expected PrepareSave to invalidate active mappings before releasing chunks")
			}

			// Tear down the saved instance completely so the file lock releases.
			regFD.DecRef(e.ctx)
			dirFD.DecRef(e.ctx)
			mopts.Mappable.RemoveMapping(e.ctx, ms, ar, 0, true)
			mopts.MappingIdentity.DecRef(e.ctx)
			e.unmount()

			// Re-open the volume with DeferOrphanCleanup and attach a fresh MemoryFile.
			rf, err := os.OpenFile(imgPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatalf("reopen %s: %v", imgPath, err)
			}
			restoredVol, err := OpenVolume(rf, VolumeOptions{DeferOrphanCleanup: true})
			if err != nil {
				t.Fatalf("OpenVolume restore: %v", err)
			}
			restoredVol.v.now = fakeClock()
			restoredVol.v.assertGate.Store(true)
			var restoreMem countingChunkMemory
			if useMemFile {
				restoreMem = newCountingChunkMemory(t)
				restoredVol.SetChunkMemory(restoreMem)
			}

			re, rb, err := restoreBundle(t, rawState, map[string]*Volume{mountID: restoredVol})
			if err != nil {
				t.Fatalf("CompleteRestore: %v", err)
			}

			restoredRegFD := rb.fds[0]
			restoredDirFD := rb.fds[1]

			// Verify file offset survived save/restore and reads continue from savedOffset.
			curOff, err := restoredRegFD.Seek(re.ctx, 0, linux.SEEK_CUR)
			if err != nil || curOff != savedOffset {
				t.Fatalf("restored Seek(SEEK_CUR) = (%d, %v), want %d", curOff, err, savedOffset)
			}
			readBuf := make([]byte, 32)
			n, err := restoredRegFD.Read(re.ctx, usermem.BytesIOSequence(readBuf), vfs.ReadOptions{})
			if err != nil || int(n) != len(readBuf) {
				t.Fatalf("Read after restore = (%d, %v), want %d", n, err, len(readBuf))
			}
			want := append([]byte(nil), initial...)
			copy(want[32:], "BUFFERED")
			copy(want[hostarch.PageSize+8:], "MAPPED-DIRTY")
			if !bytes.Equal(readBuf, want[savedOffset:savedOffset+32]) {
				t.Fatalf("Read slice from saved offset = %q, want %q", readBuf, want[savedOffset:savedOffset+32])
			}

			// Continue writing from the advanced offset (savedOffset + 32 = 51).
			re.write(restoredRegFD, []byte("-AFTER-RESTORE"))
			copy(want[savedOffset+32:], "-AFTER-RESTORE")

			// Verify restored Mappable faults chunks into restoreMem and sees coherent data.
			mappedGot := readTranslated(t, re.ctx, rb.mappable, 0, mapLen)
			if !bytes.Equal(mappedGot, want[:mapLen]) {
				t.Fatalf("translated bytes after restore mismatch at page 0/1")
			}
			if useMemFile {
				if got := restoreMem.allocs.Load(); got == 0 {
					t.Fatal("expected restored Translate to allocate chunks from restored MemoryFile")
				}
			}
			writeTranslated(t, re.ctx, rb.mappable, 4, []byte("POSTMAP"))
			copy(want[4:], "POSTMAP")
			if gotFile := re.readAll(restoredRegFD); !bytes.Equal(gotFile, want) {
				t.Fatalf("full file content after post-restore mapped store mismatch")
			}

			// Verify restored dirFD resumes from its saved cursor without repeating entries.
			restBatch := &oneDirentCallback{}
			if err := restoredDirFD.IterDirents(re.ctx, restBatch); err != nil {
				t.Fatalf("IterDirents after restore: %v", err)
			}
			combined := append(append([]string(nil), firstBatch.names...), restBatch.names...)
			slices.Sort(combined)
			wantNames := []string{".", "..", "alpha", "beta", "data", "sym"}
			if !slices.Equal(combined, wantNames) {
				t.Fatalf("combined dirents across save/restore = %v, want %v", combined, wantNames)
			}

			// Verify ReadlinkAt reloads the symlink target after restore resets targetOnce.
			target, err := re.vfsObj.ReadlinkAt(re.ctx, re.creds, re.pop("work/sym"))
			if err != nil || target != "alpha" {
				t.Fatalf("ReadlinkAt after restore = (%q, %v), want \"alpha\"", target, err)
			}
		})
	}
}

func TestSaveRestoreOpenUnlinkedAndTmpfileWithDeferredOrphanCleanup(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "orphan.ext4")
	const mountID = "orphan-vol"
	e := newNamedEnv(t, imgPath, mountID, VolumeOptions{})

	// 1. Open regular file, write payload, then unlink while FD remains open.
	unlinkedPayload := []byte(strings.Repeat("UnlinkedPayload!", 512)) // 8 KiB (2 blocks)
	e.writeFile("gone.bin", unlinkedPayload)
	unlinkedFD := e.mustOpen("gone.bin", linux.O_RDWR)
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("gone.bin")); err != nil {
		t.Fatalf("UnlinkAt gone.bin: %v", err)
	}

	// 2. Open an exclusive O_TMPFILE|O_EXCL and write payload.
	exclTmpFD, err := e.openTmpfile(".", linux.O_EXCL|linux.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("openTmpfile O_EXCL: %v", err)
	}
	exclPayload := []byte(strings.Repeat("TmpExclData#", 512))
	e.write(exclTmpFD, exclPayload)

	// 3. Open a linkable O_TMPFILE (without O_EXCL) and write payload.
	linkTmpFD, err := e.openTmpfile(".", linux.O_RDWR, 0o640)
	if err != nil {
		t.Fatalf("openTmpfile linkable: %v", err)
	}
	linkPayload := []byte("linkable-tmpfile-survives-restore")
	e.write(linkTmpFD, linkPayload)

	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
		fds:    []*vfs.FileDescription{unlinkedFD, exclTmpFD, linkTmpFD},
	}
	rawState := saveBundle(t, e.ctx, bundle)

	unlinkedFD.DecRef(e.ctx)
	exclTmpFD.DecRef(e.ctx)
	linkTmpFD.DecRef(e.ctx)
	e.unmount()

	// Verify CompleteRestore rejects a volume opened with DeferOrphanCleanup=false
	// when the checkpoint contains open orphan inodes.
	{
		badFile, err := os.OpenFile(imgPath, os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("open readonly copy: %v", err)
		}
		snapshotBytes, err := os.ReadFile(imgPath)
		_ = badFile.Close()
		if err != nil {
			t.Fatalf("ReadFile snapshot: %v", err)
		}
		badPath := filepath.Join(t.TempDir(), "no_defer.ext4")
		if err := os.WriteFile(badPath, snapshotBytes, 0o600); err != nil {
			t.Fatalf("WriteFile badPath: %v", err)
		}
		bf, err := os.OpenFile(badPath, os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("open badPath: %v", err)
		}
		badVol, err := OpenVolume(bf, VolumeOptions{DeferOrphanCleanup: false})
		if err != nil {
			t.Fatalf("OpenVolume without DeferOrphanCleanup: %v", err)
		}
		_, _, rerr := restoreBundle(t, rawState, map[string]*Volume{mountID: badVol})
		_ = badVol.Close()
		if rerr == nil {
			t.Fatal("expected CompleteRestore to fail when DeferOrphanCleanup was false")
		}
	}

	// Re-open the saved image with DeferOrphanCleanup: true and restore.
	rf, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", imgPath, err)
	}
	restoredVol, err := OpenVolume(rf, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatalf("OpenVolume(DeferOrphanCleanup): %v", err)
	}
	restoredVol.v.now = fakeClock()
	restoredVol.v.assertGate.Store(true)

	re, rb, err := restoreBundle(t, rawState, map[string]*Volume{mountID: restoredVol})
	if err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	rUnlinked := rb.fds[0]
	rExclTmp := rb.fds[1]
	rLinkTmp := rb.fds[2]

	// All three zero-link open FDs must read back their exact payloads and report Nlink == 0.
	if got := re.readAll(rUnlinked); !bytes.Equal(got, unlinkedPayload) {
		t.Fatalf("restored unlinked FD payload len=%d, want %d", len(got), len(unlinkedPayload))
	}
	if st, err := rUnlinked.Stat(re.ctx, vfs.StatOptions{Mask: linux.STATX_NLINK}); err != nil || st.Nlink != 0 {
		t.Fatalf("restored unlinked FD Nlink = (%d, %v), want 0", st.Nlink, err)
	}

	if got := re.readAll(rExclTmp); !bytes.Equal(got, exclPayload) {
		t.Fatalf("restored O_TMPFILE|O_EXCL payload len=%d, want %d", len(got), len(exclPayload))
	}
	if st, err := rExclTmp.Stat(re.ctx, vfs.StatOptions{Mask: linux.STATX_NLINK}); err != nil || st.Nlink != 0 {
		t.Fatalf("restored O_TMPFILE|O_EXCL Nlink = (%d, %v), want 0", st.Nlink, err)
	}

	if got := re.readAll(rLinkTmp); !bytes.Equal(got, linkPayload) {
		t.Fatalf("restored linkable O_TMPFILE payload = %q, want %q", got, linkPayload)
	}

	// Link the restored linkable O_TMPFILE into the namespace and verify O_EXCL tmpfile still refuses LinkAt.
	if err := re.linkDescription(rExclTmp, "should-fail"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("LinkAt on restored O_TMPFILE|O_EXCL = %v, want ENOENT", err)
	}
	if err := re.linkDescription(rLinkTmp, "materialized.txt"); err != nil {
		t.Fatalf("LinkAt on restored linkable O_TMPFILE: %v", err)
	}

	inodesBeforeClose := volFreeInodes(restoredVol)
	blocksBeforeClose := volFreeBlocks(restoredVol)

	// Close the restored unlinked FD and O_TMPFILE|O_EXCL FD, then verify free counts.
	rb.fds[0] = nil
	rb.fds[1] = nil
	rUnlinked.DecRef(re.ctx)
	rExclTmp.DecRef(re.ctx)
	if err := re.fs.Sync(re.ctx); err != nil {
		t.Fatalf("Sync after closing orphan FDs: %v", err)
	}

	inodesAfterClose := volFreeInodes(restoredVol)
	blocksAfterClose := volFreeBlocks(restoredVol)
	if inodesAfterClose != inodesBeforeClose+2 {
		t.Fatalf("free inodes after closing 2 orphan FDs = %d, want %d", inodesAfterClose, inodesBeforeClose+2)
	}
	if blocksAfterClose < blocksBeforeClose+4 {
		t.Fatalf("free blocks after closing 2 orphan FDs = %d, want >= %d", blocksAfterClose, blocksBeforeClose+4)
	}
	if head := restoredVol.v.sbU32(sbLastOrphan); head != 0 {
		t.Fatalf("s_last_orphan after closing remaining orphans = %d, want 0", head)
	}

	// Cleanly unmount and remount normally to prove on-disk consistency.
	rb.fds[2] = nil
	rLinkTmp.DecRef(re.ctx)
	re.unmount()

	finalEnv := openEnv(t, imgPath, VolumeOptions{}, vfs.MountOptions{})
	if got := finalEnv.readFile("materialized.txt"); !bytes.Equal(got, linkPayload) {
		t.Fatalf("materialized.txt after remount = %q, want %q", got, linkPayload)
	}
}

func TestSaveRestoreSweepsUnreferencedDeferredOrphans(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "sweep.ext4")
	const mountID = "sweep-vol"
	e := newNamedEnv(t, imgPath, mountID, VolumeOptions{})

	// Keep one open unlinked file in the checkpoint.
	keptPayload := []byte("kept-open-orphan")
	e.writeFile("kept", keptPayload)
	keptFD := e.mustOpen("kept", linux.O_RDWR)
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("kept")); err != nil {
		t.Fatalf("UnlinkAt kept: %v", err)
	}

	// Open a second unlinked file during PrepareSave so the on-disk orphan list
	// records it, then omit it from the serialized checkpoint bundle.
	staleFD := e.mustOpen("stale", linux.O_CREAT|linux.O_RDWR)
	e.write(staleFD, []byte(strings.Repeat("S", 4*blockSize)))
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("stale")); err != nil {
		t.Fatalf("UnlinkAt stale: %v", err)
	}
	staleIno := staleFD.Dentry().Impl().(*dentry).inode.ino

	// Delete staleIno from fs.inodes after PrepareSave checkpoints both orphans,
	// then serialize fs with only keptFD open.
	if err := e.vfsObj.PrepareSave(e.ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	staleFD.DecRef(e.ctx)
	e.fs.mu.Lock()
	delete(e.fs.inodes, staleIno)
	e.fs.mu.Unlock()

	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
		fds:    []*vfs.FileDescription{keptFD},
	}
	var buf bytes.Buffer
	if _, err := state.Save(e.ctx, &buf, bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	keptFD.DecRef(e.ctx)
	e.unmount()

	rf, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open %s: %v", imgPath, err)
	}
	restoredVol, err := OpenVolume(rf, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	restoredVol.v.now = fakeClock()
	restoredVol.v.assertGate.Store(true)
	freeBeforeRestore := volFreeInodes(restoredVol)
	blocksBeforeRestore := volFreeBlocks(restoredVol)

	re, rb, err := restoreBundle(t, buf.Bytes(), map[string]*Volume{mountID: restoredVol})
	if err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}

	// CompleteRestore must have swept staleIno while keeping keptFD alive.
	freeAfterRestore := volFreeInodes(restoredVol)
	blocksAfterRestore := volFreeBlocks(restoredVol)
	if freeAfterRestore != freeBeforeRestore+1 {
		t.Fatalf("free inodes after CompleteRestore = %d, want %d (swept unreferenced orphan)", freeAfterRestore, freeBeforeRestore+1)
	}
	if blocksAfterRestore < blocksBeforeRestore+4 {
		t.Fatalf("free blocks after CompleteRestore = %d, want >= %d", blocksAfterRestore, blocksBeforeRestore+4)
	}
	if got := re.readAll(rb.fds[0]); !bytes.Equal(got, keptPayload) {
		t.Fatalf("kept orphan payload = %q, want %q", got, keptPayload)
	}
}

func TestSaveRestoreBeforeResumeContinuesCleanly(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "resume.ext4")
	e := newNamedEnv(t, imgPath, "resume-vol", VolumeOptions{})
	e.writeFile("before.txt", []byte("before-save"))

	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
	}
	_ = saveBundle(t, e.ctx, bundle)
	e.vfsObj.BeforeResume(e.ctx)

	// Mutate the live filesystem after BeforeResume and verify durability across remount.
	e.writeFile("after.txt", []byte("after-resume"))
	e.unmount()

	reopened := openEnv(t, imgPath, VolumeOptions{}, vfs.MountOptions{})
	if got := reopened.readFile("before.txt"); string(got) != "before-save" {
		t.Fatalf("before.txt = %q, want \"before-save\"", got)
	}
	if got := reopened.readFile("after.txt"); string(got) != "after-resume" {
		t.Fatalf("after.txt = %q, want \"after-resume\"", got)
	}
}

func TestSaveRestoreRejectsTamperedVolume(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "base.ext4")
	const mountID = "tamper-vol"
	e := newNamedEnv(t, imgPath, mountID, VolumeOptions{})
	e.writeFile("secret.txt", []byte("immutable-across-checkpoint"))
	fd := e.mustOpen("secret.txt", linux.O_RDONLY)

	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
		fds:    []*vfs.FileDescription{fd},
	}
	rawState := saveBundle(t, e.ctx, bundle)
	fd.DecRef(e.ctx)
	e.unmount()

	origImage, err := os.ReadFile(imgPath)
	if err != nil {
		t.Fatalf("ReadFile base image: %v", err)
	}

	writeCopy := func(t *testing.T) string {
		t.Helper()
		p := filepath.Join(t.TempDir(), "copy.ext4")
		if err := os.WriteFile(p, origImage, 0o600); err != nil {
			t.Fatalf("WriteFile copy: %v", err)
		}
		return p
	}

	t.Run("mutated_uuid", func(t *testing.T) {
		p := writeCopy(t)
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		var b0 [blockSize]byte
		if _, err := f.ReadAt(b0[:], 0); err != nil {
			t.Fatal(err)
		}
		b0[superOffset+sbUUID] ^= 0xff
		if _, err := f.WriteAt(b0[:], 0); err != nil {
			t.Fatal(err)
		}
		vol, err := OpenVolume(f, VolumeOptions{DeferOrphanCleanup: true})
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		defer vol.Close()

		_, _, rerr := restoreBundle(t, rawState, map[string]*Volume{mountID: vol})
		if rerr == nil {
			t.Fatal("expected CompleteRestore to reject mutated superblock UUID")
		}
		var corruptErr vfs.ErrCorruption
		if !errors.As(rerr, &corruptErr) {
			t.Fatalf("expected vfs.ErrCorruption, got %T: %v", rerr, rerr)
		}
		if !strings.Contains(rerr.Error(), "UUID mismatch") {
			t.Fatalf("error %q does not mention UUID mismatch", rerr.Error())
		}
	})

	t.Run("mutated_journal_sequence", func(t *testing.T) {
		p := writeCopy(t)
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		volProbe, err := OpenVolume(f, VolumeOptions{ReadOnly: true})
		if err != nil {
			t.Fatalf("probe OpenVolume: %v", err)
		}
		jBlk := volProbe.v.j.extents[0].pblk
		js := volProbe.v.j.super
		_ = volProbe.Close()

		js.sequence += 7
		f, err = os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteAt(js.encode(), int64(jBlk)*blockSize); err != nil {
			t.Fatal(err)
		}
		vol, err := OpenVolume(f, VolumeOptions{DeferOrphanCleanup: true})
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		defer vol.Close()

		_, _, rerr := restoreBundle(t, rawState, map[string]*Volume{mountID: vol})
		if rerr == nil {
			t.Fatal("expected CompleteRestore to reject mutated journal sequence")
		}
		var corruptErr vfs.ErrCorruption
		if !errors.As(rerr, &corruptErr) {
			t.Fatalf("expected vfs.ErrCorruption, got %T: %v", rerr, rerr)
		}
		if !strings.Contains(rerr.Error(), "journal sequence mismatch") {
			t.Fatalf("error %q does not mention journal sequence mismatch", rerr.Error())
		}
	})

	t.Run("out_of_band_mount_generation_mismatch", func(t *testing.T) {
		p := writeCopy(t)
		// Open and cleanly close the image out-of-band, advancing its mount count and wtime.
		oobEnv := openEnv(t, p, VolumeOptions{}, vfs.MountOptions{})
		oobEnv.writeFile("intruder.txt", []byte("tampered"))
		oobEnv.unmount()

		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		vol, err := OpenVolume(f, VolumeOptions{DeferOrphanCleanup: true})
		if err != nil {
			t.Fatalf("OpenVolume: %v", err)
		}
		defer vol.Close()

		_, _, rerr := restoreBundle(t, rawState, map[string]*Volume{mountID: vol})
		if rerr == nil {
			t.Fatal("expected CompleteRestore to reject out-of-band modified volume")
		}
		var corruptErr vfs.ErrCorruption
		if !errors.As(rerr, &corruptErr) {
			t.Fatalf("expected vfs.ErrCorruption, got %T: %v", rerr, rerr)
		}
		if !strings.Contains(rerr.Error(), "sequence mismatch") && !strings.Contains(rerr.Error(), "generation mismatch") {
			t.Fatalf("unexpected error message: %v", rerr)
		}
	})

	t.Run("missing_volume_in_context", func(t *testing.T) {
		_, _, rerr := restoreBundle(t, rawState, nil)
		if rerr == nil || !strings.Contains(rerr.Error(), "CtxRestoreVolumeMap") {
			t.Fatalf("expected CtxRestoreVolumeMap error, got %v", rerr)
		}
	})
}

func TestSaveRestorePreservesMultiVolumeBlockdevIdentityAndStats(t *testing.T) {
	dir := t.TempDir()
	imgA := filepath.Join(dir, "vol_a.ext4")
	imgB := filepath.Join(dir, "vol_b.ext4")

	fA, err := os.OpenFile(imgA, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	volA, err := OpenVolume(fA, VolumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	fB, err := os.OpenFile(imgB, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	volB, err := OpenVolume(fB, VolumeOptions{})
	if err != nil {
		t.Fatal(err)
	}

	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	// Pre-populate vda (simulating an EROFS root disk) before mounting two ext4lite volumes (vdb, vdc).
	reg := blockdev.Of(vfsObj)
	rootDisk, err := reg.Add(blockdev.Options{
		Stats:        blockdev.NewStats(nil),
		SectorsCount: 2048,
		ReadOnly:     true,
	})
	if err != nil || rootDisk.Name != "vda" {
		t.Fatalf("reg.Add rootDisk = (%+v, %v), want vda", rootDisk, err)
	}

	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "/mnt/a", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{Volume: volA, UniqueID: "/mnt/a"},
		},
	}, testNamespaceGetter{})
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	ctx = cookieContext{vfs.WithMountNamespace(ctx, mntns)}
	root := mntns.Root(ctx)
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("b")}, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
		t.Fatalf("MkdirAt b: %v", err)
	}
	if _, err := vfsObj.MountAt(ctx, creds, "", &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("b")}, Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: InternalFilesystemOptions{Volume: volB, UniqueID: "/mnt/b"},
		},
	}); err != nil {
		t.Fatalf("MountAt b: %v", err)
	}

	e := &env{
		t:      t,
		ctx:    ctx,
		creds:  creds,
		vfsObj: vfsObj,
		root:   root,
		mntns:  mntns,
		vol:    volA,
		fs:     root.Mount().Filesystem().Impl().(*filesystem),
	}
	e.writeFile("file_a.txt", []byte(strings.Repeat("A", 8192)))
	e.writeFile("b/file_b.txt", []byte(strings.Repeat("B", 8192)))
	fdA := e.mustOpen("file_a.txt", linux.O_RDWR)
	fdB := e.mustOpen("b/file_b.txt", linux.O_RDWR)

	stA, err := fdA.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	stB, err := fdB.Stat(ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	if stA.DevMajor != blockdev.Major || stA.DevMinor != 16 {
		t.Fatalf("volA st_dev = %d:%d, want %d:16 (vdb)", stA.DevMajor, stA.DevMinor, blockdev.Major)
	}
	if stB.DevMajor != blockdev.Major || stB.DevMinor != 32 {
		t.Fatalf("volB st_dev = %d:%d, want %d:32 (vdc)", stB.DevMajor, stB.DevMinor, blockdev.Major)
	}

	bundle := &checkpointBundle{
		vfsObj: vfsObj,
		mntns:  mntns,
		root:   root,
		creds:  creds,
		fds:    []*vfs.FileDescription{fdA, fdB},
	}
	rawState := saveBundle(t, ctx, bundle)
	snapABefore := reg.Find("vdb").Stats.Snapshot()
	snapBBefore := reg.Find("vdc").Stats.Snapshot()
	if snapABefore.WritesCompleted == 0 || snapBBefore.WritesCompleted == 0 {
		t.Fatalf("expected non-zero writes before save: vdb=%d vdc=%d", snapABefore.WritesCompleted, snapBBefore.WritesCompleted)
	}

	fdA.DecRef(ctx)
	fdB.DecRef(ctx)
	root.DecRef(ctx)
	mntns.DecRef(ctx)
	vfsObj.Release(ctx)

	rfA, err := os.OpenFile(imgA, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	rVolA, err := OpenVolume(rfA, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	rfB, err := os.OpenFile(imgB, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	rVolB, err := OpenVolume(rfB, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	vmap, err := BuildRestoreVolumeMap([]RestoreVolumeMount{
		{UniqueID: "/mnt/a", Volume: rVolA},
		{UniqueID: "/mnt/b", Volume: rVolB},
	})
	if err != nil {
		t.Fatalf("BuildRestoreVolumeMap: %v", err)
	}

	re, rb, err := restoreBundle(t, rawState, vmap)
	if err != nil {
		t.Fatalf("restoreBundle: %v", err)
	}
	rStA, err := rb.fds[0].Stat(re.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	rStB, err := rb.fds[1].Stat(re.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	if rStA.DevMajor != stA.DevMajor || rStA.DevMinor != stA.DevMinor {
		t.Fatalf("restored volA st_dev = %d:%d, want %d:%d", rStA.DevMajor, rStA.DevMinor, stA.DevMajor, stA.DevMinor)
	}
	if rStB.DevMajor != stB.DevMajor || rStB.DevMinor != stB.DevMinor {
		t.Fatalf("restored volB st_dev = %d:%d, want %d:%d", rStB.DevMajor, rStB.DevMinor, stB.DevMajor, stB.DevMinor)
	}
	rReg := blockdev.Of(re.vfsObj)
	if rReg.Find("vda") == nil || rReg.Find("vdb") == nil || rReg.Find("vdc") == nil {
		t.Fatalf("restored blockdev registry missing vda/vdb/vdc: %+v", rReg.Devices())
	}
	snapAAfter := rReg.Find("vdb").Stats.Snapshot()
	snapBAfter := rReg.Find("vdc").Stats.Snapshot()
	if snapAAfter.WritesCompleted < snapABefore.WritesCompleted || snapAAfter.SectorsWritten < snapABefore.SectorsWritten {
		t.Fatalf("vdb stats regressed across restore: got %+v, want >= %+v", snapAAfter, snapABefore)
	}
	if snapBAfter.WritesCompleted < snapBBefore.WritesCompleted || snapBAfter.SectorsWritten < snapBBefore.SectorsWritten {
		t.Fatalf("vdc stats regressed across restore: got %+v, want >= %+v", snapBAfter, snapBBefore)
	}
}

func TestSaveRestorePreservesDeferredWritebackErrorAndRollbackSafety(t *testing.T) {
	imgPath := filepath.Join(t.TempDir(), "wberr.ext4")
	const mountID = "wberr-vol"
	e := newNamedEnv(t, imgPath, mountID, VolumeOptions{})

	// Reject mounting a DeferOrphanCleanup volume via GetFilesystem.
	deferImg := filepath.Join(t.TempDir(), "defer_mount.ext4")
	df, err := os.OpenFile(deferImg, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	initVol, err := OpenVolume(df, VolumeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = initVol.Close()
	df2, err := os.OpenFile(deferImg, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	deferVol, err := OpenVolume(df2, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	defer deferVol.Close()
	if _, _, err := (FilesystemType{}).GetFilesystem(e.ctx, e.vfsObj, e.creds, "", vfs.GetFilesystemOptions{
		InternalData: InternalFilesystemOptions{Volume: deferVol, UniqueID: "bad"},
	}); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("GetFilesystem(DeferOrphanCleanup=true) = %v, want EINVAL", err)
	}

	// Record a deferred write-back error on an open unlinked file, checkpoint,
	// verify a failed restore rollback does not destroy the orphan on disk, then
	// restore and verify Sync surfaces the preserved write-back error.
	e.writeFile("unlinked_wb.bin", []byte(strings.Repeat("W", 4096)))
	fd := e.mustOpen("unlinked_wb.bin", linux.O_RDWR)
	if err := e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop("unlinked_wb.bin")); err != nil {
		t.Fatal(err)
	}
	ino := fd.Dentry().Impl().(*dentry).inode
	ino.data.NoteWritebackErr(linuxerr.ENOSPC)

	bundle := &checkpointBundle{
		vfsObj: e.vfsObj,
		mntns:  e.mntns,
		root:   e.root,
		creds:  e.creds,
		fds:    []*vfs.FileDescription{fd},
	}
	rawState := saveBundle(t, e.ctx, bundle)
	fd.DecRef(e.ctx)
	e.unmount()

	// Force a CompleteRestore rollback after rebindNode by corrupting a higher
	// inode's saved kind in memory before CompleteRestore runs.
	rf1, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	vol1, err := OpenVolume(rf1, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	baseCtx := gvcontext.Background()
	restoreCtx := WithRestoreVolumeMap(baseCtx, map[string]*Volume{mountID: vol1})
	var broken checkpointBundle
	if _, err := state.Load(restoreCtx, bytes.NewReader(rawState), &broken); err != nil {
		t.Fatal(err)
	}
	rfs := broken.root.Mount().Filesystem().Impl().(*filesystem)
	rfs.inodes[999999] = &inode{ino: 999999, kind: modeRegular}
	if err := broken.vfsObj.CompleteRestore(restoreCtx, &vfs.CompleteRestoreOptions{}); err == nil {
		t.Fatal("expected CompleteRestore to fail on missing inode 999999")
	}
	_ = vol1.Close()

	// Now reopen the exact same image file and verify the open unlinked orphan
	// was not destroyed by the rollback and still restores with its deferred ENOSPC.
	rf2, err := os.OpenFile(imgPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	vol2, err := OpenVolume(rf2, VolumeOptions{DeferOrphanCleanup: true})
	if err != nil {
		t.Fatal(err)
	}
	re, rb, err := restoreBundle(t, rawState, map[string]*Volume{mountID: vol2})
	if err != nil {
		t.Fatalf("restoreBundle after rollback: %v", err)
	}
	if got := re.readAll(rb.fds[0]); len(got) != 4096 {
		t.Fatalf("orphan read after rollback = %d bytes, want 4096", len(got))
	}
	if err := rb.fds[0].Sync(re.ctx); !linuxerr.Equals(linuxerr.ENOSPC, err) {
		t.Fatalf("restored Sync() = %v, want ENOSPC from preserved WBErr", err)
	}
}
