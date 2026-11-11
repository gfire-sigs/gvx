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

package chunkcache

import (
	"bytes"
	stdcontext "context"
	"errors"
	"io"
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
)

// testMappingSpace records invalidations issued by MappingSet.InvalidateAll.
type testMappingSpace struct {
	ID          uint64
	invalidated []hostarch.AddrRange
}

func (ms *testMappingSpace) Invalidate(ar hostarch.AddrRange, _ memmap.InvalidateOpts) {
	ms.invalidated = append(ms.invalidated, ar)
}

func (ms *testMappingSpace) StateTypeName() string {
	return "pkg/sentry/fsimpl/chunkcache.testMappingSpace"
}

func (ms *testMappingSpace) StateFields() []string {
	return []string{"ID"}
}

func (ms *testMappingSpace) StateSave(sink state.Sink) {
	sink.SaveUint64(0, &ms.ID)
}

func (ms *testMappingSpace) StateLoad(_ stdcontext.Context, src state.Source) {
	src.LoadUint64(0, &ms.ID)
}

func init() {
	state.RegisterNoHooks((*testMappingSpace)(nil))
}

// rwSliceBackend backs a Cache with an in-memory file image and tracks dirty
// write-backs and DropBackendLocked calls.
type rwSliceBackend struct {
	cache    *Cache
	mem      ChunkMemory
	disk     []byte
	writable bool
	prepared int
	dropped  int
	flushErr error
}

func (b *rwSliceBackend) ChunkMemory() ChunkMemory       { return b.mem }
func (b *rwSliceBackend) FileSizeLocked() uint64         { return uint64(len(b.disk)) }
func (b *rwSliceBackend) TranslateError(err error) error { return err }

func (b *rwSliceBackend) CanTranslateLocked(write bool) error {
	if b.cache.Chunks == nil {
		return errors.New("chunks inactive")
	}
	if write && !b.writable {
		return errors.New("backend read-only")
	}
	return nil
}

func (b *rwSliceBackend) PrepareAddMappingLocked() error {
	b.prepared++
	if b.cache.Chunks == nil {
		b.cache.Chunks = make(map[uint64]*Chunk)
	}
	b.cache.Active.Store(true)
	return nil
}

func (b *rwSliceBackend) ReadChunkAtLocked(dst []byte, off int64) error {
	if off >= int64(len(b.disk)) {
		return io.EOF
	}
	n := copy(dst, b.disk[off:])
	if n < len(dst) {
		return io.EOF
	}
	return nil
}

func (b *rwSliceBackend) FlushLocked(start, end uint64) error {
	if b.flushErr != nil {
		return b.flushErr
	}
	for idx, ch := range b.cache.Chunks {
		base := idx << ChunkShift
		if !ch.Dirty || base >= end || base+ChunkSize <= start {
			continue
		}
		if base < uint64(len(b.disk)) {
			copy(b.disk[base:], ch.Buf[:min(uint64(ChunkSize), uint64(len(b.disk))-base)])
		}
		ch.Dirty = b.cache.WritableMaps > 0
	}
	return nil
}

func (b *rwSliceBackend) DropBackendLocked() {
	b.dropped++
}

type testChunkSaveRoot struct {
	Cache *Cache
	Space *testMappingSpace
}

func (r *testChunkSaveRoot) StateTypeName() string {
	return "pkg/sentry/fsimpl/chunkcache.testChunkSaveRoot"
}

func (r *testChunkSaveRoot) StateFields() []string {
	return []string{"Cache", "Space"}
}

func (r *testChunkSaveRoot) StateSave(sink state.Sink) {
	sink.Save(0, &r.Cache)
	sink.Save(1, &r.Space)
}

func (r *testChunkSaveRoot) StateLoad(_ stdcontext.Context, src state.Source) {
	src.Load(0, &r.Cache)
	src.Load(1, &r.Space)
}

func init() {
	state.RegisterNoHooks((*testChunkSaveRoot)(nil))
}

func newAccountingMemoryFile(t *testing.T, name string) *pgalloc.MemoryFile {
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

func TestCachePrepareSaveZeroMemoryFileLeakAndCompleteRestoreFaults(t *testing.T) {
	ctx := context.Background()
	stdCtx := stdcontext.Background()

	mfPre := newAccountingMemoryFile(t, "chunkcache-sr-pre")
	memPre := &memoryFileChunks{MemoryFile: mfPre}

	diskImage := make([]byte, 2*ChunkSize)
	for i := range diskImage {
		diskImage[i] = byte((i/4096 + 1) & 0xff)
	}

	var origCache Cache
	backendPre := &rwSliceBackend{
		cache:    &origCache,
		mem:      memPre,
		disk:     diskImage,
		writable: true,
	}
	origCache.Init(backendPre)

	ms := &testMappingSpace{ID: 77}
	vmaRange := hostarch.AddrRange{Start: 0x400000, End: 0x400000 + 2*ChunkSize}
	if err := origCache.AddMapping(ctx, ms, vmaRange, 0, true); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}

	// Fault chunk 0 for write and chunk 1 for read.
	writeMR := memmap.MappableRange{Start: 0, End: ChunkSize}
	tsWrite, err := origCache.Translate(ctx, writeMR, writeMR, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("pre-save write Translate: %v", err)
	}
	readMR := memmap.MappableRange{Start: ChunkSize, End: 2 * ChunkSize}
	if _, err := origCache.Translate(ctx, readMR, readMR, hostarch.Read); err != nil {
		t.Fatalf("pre-save read Translate: %v", err)
	}

	// Mutate mapped shared pages directly in MemoryFile to simulate guest stores.
	const dirtyPayload = "dirty-mmap-payload-before-checkpoint"
	mappedSeq, err := tsWrite[0].File.MapInternal(
		memmap.FileRange{Start: tsWrite[0].Offset, End: tsWrite[0].Offset + uint64(len(dirtyPayload))},
		hostarch.ReadWrite,
	)
	if err != nil {
		t.Fatalf("MapInternal pre-save: %v", err)
	}
	if _, err := safemem.CopySeq(mappedSeq, safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte(dirtyPayload)))); err != nil {
		t.Fatalf("write dirty payload: %v", err)
	}

	if memPre.held != 2 {
		t.Fatalf("held chunks before PrepareSave = %d, want 2", memPre.held)
	}
	var liveMemBuf bytes.Buffer
	if err := mfPre.SaveTo(stdCtx, &liveMemBuf, &pgalloc.SaveOpts{}); err != nil {
		t.Fatalf("SaveTo with live chunks: %v", err)
	}
	if liveMemBuf.Len() < 2*ChunkSize {
		t.Fatalf("SaveTo with 2 live chunks = %d bytes, want at least %d", liveMemBuf.Len(), 2*ChunkSize)
	}

	// PrepareSave: flush dirty chunks, invalidate mappings, and drop all MemoryFile chunks.
	origCache.MapsMu.Lock()
	origCache.DataMu.Lock()
	if err := origCache.FlushAndDropLocked(); err != nil {
		origCache.DataMu.Unlock()
		origCache.MapsMu.Unlock()
		t.Fatalf("FlushAndDropLocked: %v", err)
	}
	origCache.DataMu.Unlock()
	origCache.MapsMu.Unlock()

	if got := string(diskImage[:len(dirtyPayload)]); got != dirtyPayload {
		t.Fatalf("flushed diskImage prefix = %q, want %q", got, dirtyPayload)
	}
	if len(ms.invalidated) != 1 || ms.invalidated[0] != vmaRange {
		t.Fatalf("MappingSpace invalidations = %v, want [%v]", ms.invalidated, vmaRange)
	}
	if memPre.held != 0 {
		t.Fatalf("held chunks after FlushAndDropLocked = %d, want 0", memPre.held)
	}

	var memBuf bytes.Buffer
	if err := mfPre.SaveTo(stdCtx, &memBuf, &pgalloc.SaveOpts{}); err != nil {
		t.Fatalf("MemoryFile.SaveTo: %v", err)
	}
	if memBuf.Len() >= hostarch.PageSize {
		t.Fatalf("MemoryFile.SaveTo after FlushAndDropLocked serialized %d bytes, want < %d (zero leaked pages)", memBuf.Len(), hostarch.PageSize)
	}

	var stateBuf bytes.Buffer
	saveRoot := &testChunkSaveRoot{Cache: &origCache, Space: ms}
	if _, err := state.Save(stdCtx, &stateBuf, saveRoot); err != nil {
		t.Fatalf("state.Save Cache: %v", err)
	}

	// Restore into a brand-new MemoryFile and Cache.
	mfPost := newAccountingMemoryFile(t, "chunkcache-sr-post")
	if err := mfPost.LoadFrom(stdCtx, bytes.NewReader(memBuf.Bytes()), &pgalloc.LoadOpts{}); err != nil {
		t.Fatalf("MemoryFile.LoadFrom: %v", err)
	}
	probeFR, err := mfPost.Allocate(uint64(hostarch.PageSize), pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("probe Allocate on restored MemoryFile: %v", err)
	}
	mfPost.DecRef(probeFR)
	if probeFR.Start != 0 {
		t.Fatalf("probe allocation after restore started at %#x, want 0 (leaked range before %#x)", probeFR.Start, probeFR.Start)
	}

	var loadRoot testChunkSaveRoot
	if _, err := state.Load(stdCtx, bytes.NewReader(stateBuf.Bytes()), &loadRoot); err != nil {
		t.Fatalf("state.Load Cache: %v", err)
	}
	restoredCache := loadRoot.Cache
	if restoredCache.Mappings.IsEmpty() {
		t.Fatal("restored Cache lost active Mappings")
	}
	if restoredCache.WritableMaps != 1 {
		t.Fatalf("restored WritableMaps = %d, want 1", restoredCache.WritableMaps)
	}

	memPost := &memoryFileChunks{MemoryFile: mfPost}
	restoredDisk := bytes.Clone(diskImage)
	backendPost := &rwSliceBackend{
		cache:    restoredCache,
		mem:      memPost,
		disk:     restoredDisk,
		writable: true,
	}

	// CompleteRestore: re-arm mapped Cache with restored MemoryFile and backend.
	restoredCache.MapsMu.Lock()
	restoredCache.DataMu.Lock()
	if err := restoredCache.RearmMappedLocked(backendPost); err != nil {
		restoredCache.DataMu.Unlock()
		restoredCache.MapsMu.Unlock()
		t.Fatalf("RearmMappedLocked: %v", err)
	}
	restoredCache.DataMu.Unlock()
	restoredCache.MapsMu.Unlock()

	// Subsequent guest read and write page faults must serve restored bytes without BusError.
	tsPostRead, err := restoredCache.Translate(ctx, readMR, readMR, hostarch.Read)
	if err != nil {
		t.Fatalf("post-restore read Translate raised error (expected no BusError): %v", err)
	}
	readSeq, err := tsPostRead[0].File.MapInternal(
		memmap.FileRange{Start: tsPostRead[0].Offset, End: tsPostRead[0].Offset + 16},
		hostarch.Read,
	)
	if err != nil {
		t.Fatalf("post-restore read MapInternal: %v", err)
	}
	gotChunk1 := make([]byte, 16)
	if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(gotChunk1)), readSeq); err != nil {
		t.Fatalf("copy chunk 1 bytes: %v", err)
	}
	if !bytes.Equal(gotChunk1, restoredDisk[ChunkSize:ChunkSize+16]) {
		t.Fatalf("post-restore chunk 1 bytes = %x, want %x", gotChunk1, restoredDisk[ChunkSize:ChunkSize+16])
	}

	tsPostWrite, err := restoredCache.Translate(ctx, writeMR, writeMR, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("post-restore write Translate raised error (expected no BusError): %v", err)
	}
	writeSeq, err := tsPostWrite[0].File.MapInternal(
		memmap.FileRange{Start: tsPostWrite[0].Offset, End: tsPostWrite[0].Offset + 64},
		hostarch.ReadWrite,
	)
	if err != nil {
		t.Fatalf("post-restore write MapInternal: %v", err)
	}
	gotPrefix := make([]byte, len(dirtyPayload))
	if _, err := safemem.CopySeq(safemem.BlockSeqOf(safemem.BlockFromSafeSlice(gotPrefix)), writeSeq.TakeFirst(len(dirtyPayload))); err != nil {
		t.Fatalf("read pre-save dirty payload after restore: %v", err)
	}
	if string(gotPrefix) != dirtyPayload {
		t.Fatalf("post-restore chunk 0 payload = %q, want %q", string(gotPrefix), dirtyPayload)
	}

	const postPayload = "post-restore-mmap-write-persisted!"
	if _, err := safemem.CopySeq(writeSeq.TakeFirst(len(postPayload)), safemem.BlockSeqOf(safemem.BlockFromSafeSlice([]byte(postPayload)))); err != nil {
		t.Fatalf("write post-restore payload: %v", err)
	}
	if err := restoredCache.SyncData(); err != nil {
		t.Fatalf("post-restore SyncData: %v", err)
	}
	if got := string(restoredDisk[:len(postPayload)]); got != postPayload {
		t.Fatalf("restoredDisk after post-restore SyncData = %q, want %q", got, postPayload)
	}

	restoredCache.RemoveMapping(ctx, loadRoot.Space, vmaRange, 0, true)
	if memPost.held != 0 {
		t.Fatalf("held chunks after RemoveMapping = %d, want 0", memPost.held)
	}
}

func TestFlushAndDropLockedPropagatesWritebackError(t *testing.T) {
	ctx := context.Background()
	var c Cache
	wantErr := errors.New("disk full")
	b := &rwSliceBackend{
		cache:    &c,
		disk:     make([]byte, ChunkSize),
		writable: true,
		flushErr: wantErr,
	}
	c.Init(b)
	ms := &testMappingSpace{ID: 1}
	if err := c.AddMapping(ctx, ms, hostarch.AddrRange{Start: 0x10000, End: 0x10000 + ChunkSize}, 0, true); err != nil {
		t.Fatalf("AddMapping: %v", err)
	}
	mr := memmap.MappableRange{Start: 0, End: ChunkSize}
	if _, err := c.Translate(ctx, mr, mr, hostarch.ReadWrite); err != nil {
		t.Fatalf("Translate: %v", err)
	}

	c.MapsMu.Lock()
	c.DataMu.Lock()
	err := c.FlushAndDropLocked()
	c.DataMu.Unlock()
	c.MapsMu.Unlock()
	if !errors.Is(err, wantErr) {
		t.Fatalf("FlushAndDropLocked err = %v, want %v", err, wantErr)
	}
	if len(c.Chunks) == 0 {
		t.Fatal("FlushAndDropLocked dropped dirty chunks after writeback failure")
	}
}

type sliceDirentCollector struct {
	stopAfter int
	got       []vfs.Dirent
}

func (s *sliceDirentCollector) Handle(d vfs.Dirent) error {
	if s.stopAfter > 0 && len(s.got) >= s.stopAfter {
		return errors.New("buffer full")
	}
	s.got = append(s.got, d)
	return nil
}

func TestDirCursorStateRoundTrip(t *testing.T) {
	stdCtx := stdcontext.Background()
	entries := []vfs.Dirent{
		{Name: ".", Type: linux.DT_DIR, Ino: 1, NextOff: 1},
		{Name: "..", Type: linux.DT_DIR, Ino: 1, NextOff: 2},
		{Name: "alpha", Type: linux.DT_REG, Ino: 10, NextOff: 3},
		{Name: "beta", Type: linux.DT_REG, Ino: 11, NextOff: 4},
	}

	var cur DirCursor
	loadCalls := 0
	loadFn := func() ([]vfs.Dirent, error) {
		loadCalls++
		return entries, nil
	}

	first := &sliceDirentCollector{stopAfter: 2}
	if err := cur.IterDirents(first, loadFn); err == nil {
		t.Fatal("expected partial stop error after 2 dirents")
	}
	if len(first.got) != 2 || first.got[0].Name != "." || first.got[1].Name != ".." {
		t.Fatalf("pre-save dirents = %+v", first.got)
	}

	var buf bytes.Buffer
	if _, err := state.Save(stdCtx, &buf, &cur); err != nil {
		t.Fatalf("state.Save DirCursor: %v", err)
	}

	var restored DirCursor
	if _, err := state.Load(stdCtx, bytes.NewReader(buf.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load DirCursor: %v", err)
	}

	rest := &sliceDirentCollector{}
	if err := restored.IterDirents(rest, func() ([]vfs.Dirent, error) {
		t.Fatal("restored DirCursor reloaded snapshot unexpectedly before rewind")
		return nil, nil
	}); err != nil {
		t.Fatalf("post-restore IterDirents: %v", err)
	}
	if len(rest.got) != 2 || rest.got[0].Name != "alpha" || rest.got[1].Name != "beta" {
		t.Fatalf("post-restore remaining dirents = %+v, want [alpha beta]", rest.got)
	}

	if off, err := restored.SeekDir(0, linux.SEEK_SET); err != nil || off != 0 {
		t.Fatalf("SeekDir(0) = (%d, %v), want (0, nil)", off, err)
	}
	rewound := &sliceDirentCollector{}
	if err := restored.IterDirents(rewound, loadFn); err != nil {
		t.Fatalf("IterDirents after rewind: %v", err)
	}
	if loadCalls != 2 || len(rewound.got) != 4 {
		t.Fatalf("after rewind: loadCalls=%d len=%d, want loadCalls=2 len=4", loadCalls, len(rewound.got))
	}
}
