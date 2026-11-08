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
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// memoryFileChunks is the chunk memory of pkg/gvx on Linux and Windows. It
// counts the chunk allocations that are not yet released.
type memoryFileChunks struct {
	*pgalloc.MemoryFile
	held int
}

func (m *memoryFileChunks) AllocateChunk(length uint64) (memmap.FileRange, error) {
	fr, err := m.Allocate(length, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err == nil {
		m.held++
	}
	return fr, err
}

func (m *memoryFileChunks) DecRef(fr memmap.FileRange) {
	m.held--
	m.MemoryFile.DecRef(fr)
}

func newMemoryFile(t *testing.T) *pgalloc.MemoryFile {
	t.Helper()
	const name = "chunkcache-test"
	memFD, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), name), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return mf
}

// fileBackend is a mapped file of size bytes whose byte at offset off is
// byte(off/ChunkSize + 1).
type fileBackend struct {
	mem  ChunkMemory
	size uint64
}

func (b *fileBackend) ChunkMemory() ChunkMemory         { return b.mem }
func (b *fileBackend) FileSizeLocked() uint64           { return b.size }
func (b *fileBackend) CanTranslateLocked(bool) error    { return nil }
func (b *fileBackend) PrepareAddMappingLocked() error   { return nil }
func (b *fileBackend) FlushLocked(uint64, uint64) error { return nil }
func (b *fileBackend) DropBackendLocked()               {}
func (b *fileBackend) TranslateError(err error) error   { return err }

func (b *fileBackend) ReadChunkAtLocked(dst []byte, off int64) error {
	for i := range dst {
		dst[i] = byte(uint64(off+int64(i))/ChunkSize + 1)
	}
	return nil
}

// TestTranslateAcrossAMemoryFileMappingBoundary places the lowest free range
// of a memory file across the 1 GiB boundary of its internal mappings. There,
// MapInternal returns two blocks for a 64 KiB range, and Translate failed with
// a bus error. A guest that faulted on a page of a mapped file got SIGBUS, and
// a system call that read the page got EFAULT.
func TestTranslateAcrossAMemoryFileMappingBoundary(t *testing.T) {
	mf := newMemoryFile(t)
	const boundary = 1 << 30
	filler, err := mf.Allocate(boundary-ChunkSize/2, pgalloc.AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate filler: %v", err)
	}
	defer mf.DecRef(filler)
	if filler.End <= boundary-ChunkSize || filler.End >= boundary {
		t.Fatalf("filler = %v; the next chunk would not cross the boundary %#x", filler, boundary)
	}

	const chunks = 3
	mem := &memoryFileChunks{MemoryFile: mf}
	var c Cache
	c.Init(&fileBackend{mem: mem, size: chunks * ChunkSize})
	c.Chunks = make(map[uint64]*Chunk)
	drop := func() {
		c.MapsMu.Lock()
		c.DataMu.Lock()
		c.DropLocked()
		c.DataMu.Unlock()
		c.MapsMu.Unlock()
	}
	for i := range uint64(chunks) {
		mr := memmap.MappableRange{Start: i * ChunkSize, End: (i + 1) * ChunkSize}
		ts, err := c.Translate(context.Background(), mr, mr, hostarch.Read)
		if err != nil {
			t.Fatalf("Translate(%v): %v", mr, err)
		}
		if len(ts) != 1 || ts[0].Source != mr {
			t.Fatalf("Translate(%v) = %v, want one translation of the range", mr, ts)
		}
		fr := ts[0].FileRange()
		if fr.Start < boundary && fr.End > boundary {
			t.Fatalf("chunk %d at %v crosses the boundary %#x", i, fr, boundary)
		}
		bs, err := ts[0].File.MapInternal(fr, hostarch.Read)
		if err != nil || bs.NumBlocks() != 1 {
			t.Fatalf("MapInternal(%v) = (%d blocks, %v), want one block", fr, bs.NumBlocks(), err)
		}
		got := bs.Head().ToSlice()
		if want := byte(i + 1); got[0] != want || got[ChunkSize-1] != want {
			t.Fatalf("chunk %d holds bytes %d and %d, want %d", i, got[0], got[ChunkSize-1], want)
		}
	}
	if mem.held != chunks {
		t.Errorf("%d chunk allocations are held, want %d: a skipped range leaked", mem.held, chunks)
	}
	drop()
	if mem.held != 0 {
		t.Errorf("%d chunk allocations are held after the drop, want 0", mem.held)
	}
}
