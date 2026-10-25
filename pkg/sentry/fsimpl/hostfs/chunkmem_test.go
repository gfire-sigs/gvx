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
	"os"
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

// testChunkMemory backs chunks with a pgalloc.MemoryFile, the way pkg/gvx does
// on Linux. It counts the references that hostfs drops.
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

func newTestChunkMemory(t *testing.T) ChunkMemory {
	t.Helper()
	const name = "hostfs-chunk-test"
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
		mem := newTestChunkMemory(t)
		e := newEnv(t)
		e.ws.SetChunkMemory(mem)
		fn(t, e)
	})
}

func TestChunkMemoryTranslationsSpanChunks(t *testing.T) {
	mem := newTestChunkMemory(t)
	e := newEnv(t)
	e.ws.SetChunkMemory(mem)
	content := make([]byte, 3*chunkSize)
	for i := range content {
		content[i] = byte(i / chunkSize)
	}
	e.writeFile("big", content)
	fd := e.mustOpen("big", 0)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, uint64(len(content)), false)

	ts, err := m.Translate(e.ctx,
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
	m.RemoveMapping(e.ctx, ms, ar, 0, false)
}

// TestTruncateInvalidatesBeforeItReleasesChunkMemory checks the order that
// makes shared chunk memory safe. A mapping may hold a translation that it has
// not yet referenced, so hostfs must stop the mapping before it drops its own
// reference. Invalidate also calls into the memory manager, so it must run
// without the data lock.
func TestTruncateInvalidatesBeforeItReleasesChunkMemory(t *testing.T) {
	mem := newTestChunkMemory(t).(testChunkMemory)
	e := newEnv(t)
	e.ws.SetChunkMemory(mem)
	e.writeFile("t", make([]byte, 3*chunkSize))
	fd := e.mustOpen("t", 2)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, 3*chunkSize, true)
	data := &fd.Impl().(*regularFD).dentry.inode.data
	if _, err := m.Translate(e.ctx,
		memmap.MappableRange{Start: 0, End: 3 * chunkSize},
		memmap.MappableRange{Start: 0, End: 3 * chunkSize}, hostarch.ReadWrite); err != nil {
		t.Fatalf("Translate: %v", err)
	}

	var releasesAtInvalidate int64 = -1
	var dataLockHeld bool
	ms.onInvalidate = func() {
		releasesAtInvalidate = mem.releases.Load()
		if data.DataMu.TryLock() {
			data.DataMu.Unlock()
		} else {
			dataLockHeld = true
		}
	}
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: chunkSize / 2}}); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if releasesAtInvalidate != 0 {
		t.Errorf("hostfs released %d chunks before it invalidated the mappings, want 0", releasesAtInvalidate)
	}
	if dataLockHeld {
		t.Error("Invalidate ran with the data lock held")
	}
	if got := mem.releases.Load(); got != 2 {
		t.Errorf("hostfs released %d chunks after truncating to half a chunk, want 2", got)
	}
	m.RemoveMapping(e.ctx, ms, ar, 0, true)
}
