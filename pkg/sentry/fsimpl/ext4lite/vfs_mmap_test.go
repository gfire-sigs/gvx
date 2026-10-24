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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// recordingSpace is a memmap.MappingSpace that records invalidations.
type recordingSpace struct {
	mu          sync.Mutex
	invalidated []hostarch.AddrRange

	// onInvalidate runs inside Invalidate, before the call returns. Tests use
	// it to observe the state of the file cache at that moment.
	onInvalidate func()
}

func (s *recordingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	s.mu.Lock()
	s.invalidated = append(s.invalidated, ar)
	hook := s.onInvalidate
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

// mapping is a memory mapping that a test sets up without a memory manager.
type mapping struct {
	e        *env
	m        memmap.Mappable
	ms       *recordingSpace
	ar       hostarch.AddrRange
	id       memmap.MappingIdentity
	writable bool
}

// mapFile maps the first length bytes of fd. The mapping holds a reference on
// the file description until remove runs, as a vma does.
func (e *env) mapFile(fd *vfs.FileDescription, length uint64, writable bool) *mapping {
	e.t.Helper()
	opts := &memmap.MMapOpts{Length: length, Offset: 0, Perms: hostarch.ReadWrite, MaxPerms: hostarch.ReadWrite}
	if err := fd.ConfigureMMap(e.ctx, opts); err != nil {
		e.t.Fatalf("ConfigureMMap: %v", err)
	}
	mp := &mapping{e: e, m: opts.Mappable, ms: &recordingSpace{}, id: opts.MappingIdentity, writable: writable,
		ar: hostarch.AddrRange{Start: 0x10000, End: 0x10000 + hostarch.Addr(length)}}
	if err := mp.m.AddMapping(e.ctx, mp.ms, mp.ar, 0, writable); err != nil {
		e.t.Fatalf("AddMapping: %v", err)
	}
	return mp
}

// remove ends the mapping and drops its reference on the file description.
func (mp *mapping) remove() {
	mp.m.RemoveMapping(mp.e.ctx, mp.ms, mp.ar, 0, mp.writable)
	mp.id.DecRef(mp.e.ctx)
}

// read returns the bytes of the file range [start, end) as the guest sees them
// through the mapping.
func (mp *mapping) read(start, end uint64) []byte {
	mp.e.t.Helper()
	r := memmap.MappableRange{Start: start, End: end}
	ts, err := mp.m.Translate(mp.e.ctx, r, r, hostarch.Read)
	if err != nil {
		mp.e.t.Fatalf("Translate: %v", err)
	}
	var out []byte
	for _, tr := range ts {
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + tr.Source.Length()}, hostarch.Read)
		if err != nil {
			mp.e.t.Fatalf("MapInternal: %v", err)
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			out = append(out, bs.Head().ToSlice()...)
		}
	}
	return out
}

// store writes data into the mapped memory at file offset off, as a guest
// store through the mapping does.
func (mp *mapping) store(off uint64, data []byte) {
	mp.e.t.Helper()
	r := memmap.MappableRange{Start: off, End: off + uint64(len(data))}
	ts, err := mp.m.Translate(mp.e.ctx, r, r, hostarch.ReadWrite)
	if err != nil {
		mp.e.t.Fatalf("Translate for write: %v", err)
	}
	done := 0
	for _, tr := range ts {
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + tr.Source.Length()}, hostarch.ReadWrite)
		if err != nil {
			mp.e.t.Fatalf("MapInternal: %v", err)
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			done += copy(bs.Head().ToSlice(), data[done:])
		}
	}
	if done != len(data) {
		mp.e.t.Fatalf("wrote %d of %d bytes through the mapping", done, len(data))
	}
}

// testChunkMemory backs chunks with a pgalloc.MemoryFile, the way pkg/gvx does
// on Linux. It counts the references that ext4lite drops.
type testChunkMemory struct {
	*pgalloc.MemoryFile
	releases *atomic.Int64
}

func (m testChunkMemory) DecRef(fr memmap.FileRange) {
	m.releases.Add(1)
	m.MemoryFile.DecRef(fr)
}

func (m testChunkMemory) AllocateChunk(length uint64) (memmap.FileRange, error) {
	return m.Allocate(length, pgalloc.AllocOpts{Kind: usage.Anonymous})
}

func newTestChunkMemory(t *testing.T) testChunkMemory {
	t.Helper()
	const name = "ext4lite-chunk-test"
	memFD, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), name), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return testChunkMemory{MemoryFile: mf, releases: new(atomic.Int64)}
}

// forEachChunkMode runs fn twice: with chunks on the Go heap, which the
// hardware backends and the macOS systrap engine map by host pointer, and with
// chunks in a memory file, which the Linux systrap platform maps by descriptor.
func forEachChunkMode(t *testing.T, fn func(t *testing.T, e *env)) {
	t.Run("heap", func(t *testing.T) { fn(t, newEnv(t)) })
	t.Run("memfile", func(t *testing.T) {
		e := newEnv(t)
		e.vol.SetChunkMemory(newTestChunkMemory(t))
		fn(t, e)
	})
}

func TestMappedPagesWriteBackAndStayCoherent(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		content := []byte(strings.Repeat("a", 3*hostarch.PageSize+100))
		e.writeFile("m", content)
		fd := e.mustOpen("m", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		mp := e.mapFile(fd, uint64(len(content)), true)

		wantBytes(t, "mapped content", mp.read(0, uint64(len(content)))[:len(content)], content)

		// A store through the mapping reaches read(2) before any fsync.
		mp.store(100, []byte("MAPPED"))
		want := append([]byte(nil), content...)
		copy(want[100:], "MAPPED")
		wantBytes(t, "read after a mapped store", e.readAll(fd), want)

		// A write(2) shows in the mapped pages.
		e.pwrite(fd, []byte("syscall"), 2000)
		copy(want[2000:], "syscall")
		wantBytes(t, "mapped content after pwrite", mp.read(0, uint64(len(content)))[:len(content)], want)

		// fsync writes the dirty chunk to the volume, and a crash clone has it.
		mp.store(3000, []byte("durable"))
		copy(want[3000:], "durable")
		if err := fd.Sync(e.ctx); err != nil {
			t.Fatal(err)
		}
		c := crashClone(t, e)
		wantBytes(t, "mapped store in the crash clone", c.readFile("m"), want)

		// A store after the last fsync reaches the volume at unmap.
		mp.store(3500, []byte("unmapped"))
		copy(want[3500:], "unmapped")
		mp.remove()
		wantBytes(t, "content after unmap", e.readFile("m"), want)
		if err := fd.OnClose(e.ctx); err != nil {
			t.Fatalf("OnClose: %v", err)
		}
	})
}

// TestMappedStoreSurvivesUnmapAndRelease unmaps a file after a store, closes
// every reference, and mounts the image again.
func TestMappedStoreSurvivesUnmapAndRelease(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("m", make([]byte, 2*blockSize))
		fd := e.mustOpen("m", linux.O_RDWR)
		mp := e.mapFile(fd, 2*blockSize, true)
		mp.store(blockSize+10, []byte("never synced"))
		mp.remove()
		fd.DecRef(e.ctx)
		e = e.remount()
		got := e.readFile("m")
		if len(got) != 2*blockSize || string(got[blockSize+10:blockSize+22]) != "never synced" {
			t.Fatalf("content after release: %d bytes, %q", len(got), got[blockSize+10:blockSize+22])
		}
	})
}

// TestReleaseFlushesDirtyChunks drops the cache of an inode that keeps a dirty
// chunk, as the last dentry reference does. The data must reach the volume,
// except for a file that no name reaches any more.
func TestReleaseFlushesDirtyChunks(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("kept", make([]byte, blockSize))
		fd := e.mustOpen("kept", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		mp := e.mapFile(fd, blockSize, true)
		mp.store(7, []byte("flushed at release"))
		data := &fd.Impl().(*regularFD).dentry.inode.data
		if err := data.release(true); err != nil {
			t.Fatalf("release: %v", err)
		}
		if got := e.readFile("kept"); string(got[7:25]) != "flushed at release" {
			t.Fatalf("content after release = %q", got[7:25])
		}
		mp.remove()
	})
}

func TestMappedHolesStayHoles(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		fd := e.mustOpen("sparse", linux.O_CREAT|linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 1 << 20}}); err != nil {
			t.Fatal(err)
		}
		mp := e.mapFile(fd, 1<<20, true)
		// A load from a hole reads zeros. One store allocates one block.
		if got := mp.read(0, 4*blockSize); !isZero(got) {
			t.Fatal("a hole does not read as zeros through the mapping")
		}
		mp.store(200*blockSize, []byte("island"))
		if err := fd.Sync(e.ctx); err != nil {
			t.Fatal(err)
		}
		if st := e.mustStat("sparse"); st.Blocks != blockSize/512 {
			t.Fatalf("a sparse file with one stored page owns %d sectors, want %d", st.Blocks, blockSize/512)
		}
		if pos, err := fd.Seek(e.ctx, 0, linux.SEEK_DATA); err != nil || pos != 200*blockSize {
			t.Fatalf("SEEK_DATA = (%d, %v), want %d", pos, err, 200*blockSize)
		}
		mp.remove()
	})
}

// TestTruncateInvalidatesBeforeItReleasesChunkMemory checks the order that
// makes shared chunk memory safe. A mapping may hold a translation that it has
// not yet referenced, so the filesystem must stop the mapping before it drops
// its own reference. Invalidate also calls into the memory manager, so it must
// run without the data lock.
func TestTruncateInvalidatesBeforeItReleasesChunkMemory(t *testing.T) {
	mem := newTestChunkMemory(t)
	e := newEnv(t)
	e.vol.SetChunkMemory(mem)
	e.writeFile("t", make([]byte, 3*chunkSize))
	fd := e.mustOpen("t", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	mp := e.mapFile(fd, 3*chunkSize, true)
	data := &fd.Impl().(*regularFD).dentry.inode.data
	full := memmap.MappableRange{Start: 0, End: 3 * chunkSize}
	if _, err := mp.m.Translate(e.ctx, full, full, hostarch.ReadWrite); err != nil {
		t.Fatalf("Translate: %v", err)
	}

	var releasesAtInvalidate int64 = -1
	var dataLockHeld bool
	mp.ms.onInvalidate = func() {
		releasesAtInvalidate = mem.releases.Load()
		if data.dataMu.TryLock() {
			data.dataMu.Unlock()
		} else {
			dataLockHeld = true
		}
	}
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: chunkSize / 2}}); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if releasesAtInvalidate != 0 {
		t.Errorf("released %d chunks before the invalidation of the mappings, want 0", releasesAtInvalidate)
	}
	if dataLockHeld {
		t.Error("Invalidate ran with the data lock held")
	}
	if got := mem.releases.Load(); got != 2 {
		t.Errorf("released %d chunks after truncating to half a chunk, want 2", got)
	}
	mp.remove()
}

func TestChunkMemoryTranslationsSpanChunks(t *testing.T) {
	mem := newTestChunkMemory(t)
	e := newEnv(t)
	e.vol.SetChunkMemory(mem)
	content := make([]byte, 3*chunkSize)
	for i := range content {
		content[i] = byte(i / chunkSize)
	}
	e.writeFile("big", content)
	fd := e.mustOpen("big", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	mp := e.mapFile(fd, uint64(len(content)), false)
	ts, err := mp.m.Translate(e.ctx,
		memmap.MappableRange{Start: chunkSize - 4096, End: chunkSize + 4096},
		memmap.MappableRange{Start: 0, End: 3 * chunkSize}, hostarch.Read)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	if len(ts) < 2 {
		t.Fatalf("Translate over a chunk boundary returned %d translations, want one per chunk", len(ts))
	}
	for _, tr := range ts {
		if tr.File != memmap.File(mem) {
			t.Fatalf("translation file = %T, want the chunk memory", tr.File)
		}
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: tr.Offset, End: tr.Offset + tr.Source.Length()}, hostarch.Read)
		if err != nil {
			t.Fatalf("MapInternal: %v", err)
		}
		got := bs.Head().ToSlice()
		for i := 0; i < len(got); i += 4096 {
			if want := byte((tr.Source.Start + uint64(i)) / chunkSize); got[i] != want {
				t.Fatalf("byte at file offset %d = %d, want %d", tr.Source.Start+uint64(i), got[i], want)
			}
		}
	}
	mp.remove()
}

func TestMapBeyondEndOfFile(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("short", []byte("0123456789"))
		fd := e.mustOpen("short", linux.O_RDONLY)
		defer fd.DecRef(e.ctx)
		mp := e.mapFile(fd, 3*hostarch.PageSize, false)
		r := memmap.MappableRange{Start: hostarch.PageSize, End: 2 * hostarch.PageSize}
		_, err := mp.m.Translate(e.ctx, r, r, hostarch.Read)
		if _, ok := err.(*memmap.BusError); !ok {
			t.Fatalf("Translate beyond the last page = %v, want a bus error", err)
		}
		mp.remove()
	})
}

func TestGrowthAndPunchKeepMappedPagesCoherent(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("g", []byte(strings.Repeat("x", 2*blockSize)))
		fd := e.mustOpen("g", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		mp := e.mapFile(fd, 4*blockSize, true)
		// A store beyond the end of the file but inside the last mapped page
		// must not show after the file grows.
		mp.store(2*blockSize-10, []byte("0123456789"))
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: blockSize + 5}}); err != nil {
			t.Fatal(err)
		}
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 3 * blockSize}}); err != nil {
			t.Fatal(err)
		}
		got := mp.read(0, 3*blockSize)
		if !isZero(got[blockSize+5 : 3*blockSize]) {
			t.Fatal("the region between the old and the new end of the file does not read as zeros")
		}
		// Punching a hole zeroes the mapped pages too.
		punch := uint64(linux.FALLOC_FL_PUNCH_HOLE | linux.FALLOC_FL_KEEP_SIZE)
		if err := fd.Allocate(e.ctx, punch, 0, blockSize); err != nil {
			t.Fatal(err)
		}
		if got := mp.read(0, blockSize); !isZero(got) {
			t.Fatal("a punched page does not read as zeros through the mapping")
		}
		mp.remove()
	})
}

// TestStoreBeyondEndIsDiscardedWhenFileGrows stores bytes into the last mapped
// page beyond the end of the file. The file never holds them, so a later
// growth of the file must read zeros there, through read(2) and through the
// mapping.
func TestStoreBeyondEndIsDiscardedWhenFileGrows(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("g", []byte(strings.Repeat("x", 100)))
		fd := e.mustOpen("g", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		mp := e.mapFile(fd, blockSize, true)
		mp.store(3000, []byte("STALE"))
		if err := fd.Sync(e.ctx); err != nil {
			t.Fatal(err)
		}
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 2 * blockSize}}); err != nil {
			t.Fatal(err)
		}
		got := e.readAll(fd)
		if len(got) != 2*blockSize || !isZero(got[100:]) {
			t.Fatalf("read(2) after growth: %d bytes, first stale byte at %d", len(got), 100+firstNonZero(got[100:]))
		}
		if viaMap := mp.read(0, blockSize); !isZero(viaMap[100:]) {
			t.Fatalf("mapped read after growth: first stale byte at %d", 100+firstNonZero(viaMap[100:]))
		}
		// A write(2) that leaves a gap clears the gap in the mapped page too.
		mp.store(200, []byte("JUNK"))
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 150}}); err != nil {
			t.Fatal(err)
		}
		e.pwrite(fd, []byte("end"), 300)
		if viaMap := mp.read(0, blockSize); !isZero(viaMap[150:300]) || string(viaMap[300:303]) != "end" {
			t.Fatalf("mapped page after a write beyond the end: gap is zero %v, tail %q", isZero(viaMap[150:300]), viaMap[300:303])
		}
		mp.remove()
	})
}

func firstNonZero(p []byte) int {
	for i, b := range p {
		if b != 0 {
			return i
		}
	}
	return -1
}

func TestStoreThroughOneMappingIsVisibleToReadOnAnotherDescriptor(t *testing.T) {
	e := newEnv(t)
	e.writeFile("shared", []byte(strings.Repeat("-", 2*blockSize)))
	w := e.mustOpen("shared", linux.O_RDWR)
	defer w.DecRef(e.ctx)
	mp := e.mapFile(w, 2*blockSize, true)
	mp.store(5, []byte("via mmap"))
	// A second descriptor reads the store without an fsync.
	got := e.readFile("shared")
	if string(got[5:13]) != "via mmap" {
		t.Fatalf("second descriptor reads %q", got[5:13])
	}
	mp.remove()
}
