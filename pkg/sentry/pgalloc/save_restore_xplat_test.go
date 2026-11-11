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

package pgalloc

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/compressio"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/state/stateio"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func newTestMemoryFile(t *testing.T, opts MemoryFileOpts) *MemoryFile {
	t.Helper()
	fd, err := memutil.CreateMemFD("pgalloc-sr", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "gvx-pgalloc-sr")
	opts.DisableIMAWorkAround = true
	opts.UseHostMemcgPressure = false
	if opts.Accounting == nil && !opts.DisableMemoryAccounting {
		opts.Accounting = &usage.MemoryLocked{}
	}
	mf, err := NewMemoryFile(f, opts)
	if err != nil {
		_ = f.Close()
		t.Fatalf("NewMemoryFile: %v", err)
	}
	return mf
}

func awaitDestroy(t *testing.T, mf *MemoryFile) {
	t.Helper()
	mf.Destroy()
	mf.mu.Lock()
	for !mf.saveRestore.destroyDone {
		mf.releaseCond.Wait()
	}
	unmapErr := mf.saveRestore.destroyUnmapErr
	mf.mu.Unlock()
	if unmapErr != nil {
		t.Fatalf("MemoryFile.Destroy unmap failed: %v", unmapErr)
	}
}

func writePattern(t *testing.T, mf *MemoryFile, fr memmap.FileRange, seed byte) []byte {
	t.Helper()
	want := make([]byte, fr.Length())
	for i := range want {
		want[i] = byte((uint64(seed)*131 + uint64(i)*17 + (uint64(i) >> 12)) & 0xFF)
		if want[i] == 0 {
			want[i] = seed | 1
		}
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(%v, ReadWrite): %v", fr, err)
	}
	copied := 0
	for !bs.IsEmpty() {
		dst := bs.Head().ToSlice()
		copied += copy(dst, want[copied:])
		bs = bs.Tail()
	}
	if uint64(copied) != fr.Length() {
		t.Fatalf("copied %d bytes into %v, want %d", copied, fr, fr.Length())
	}
	return want
}

func readRangeBytes(t *testing.T, mf *MemoryFile, fr memmap.FileRange) []byte {
	t.Helper()
	bs, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(%v, Read): %v", fr, err)
	}
	got := make([]byte, 0, fr.Length())
	for !bs.IsEmpty() {
		got = append(got, bs.Head().ToSlice()...)
		bs = bs.Tail()
	}
	if uint64(len(got)) != fr.Length() {
		t.Fatalf("read %d bytes from %v, want %d", len(got), fr, fr.Length())
	}
	return got
}

func assertRangeEquals(t *testing.T, mf *MemoryFile, label string, fr memmap.FileRange, want []byte) {
	t.Helper()
	got := readRangeBytes(t, mf, fr)
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s offset %#x (byte %d): got %#x, want %#x", label, fr.Start+uint64(i), i, got[i], want[i])
			}
		}
		t.Fatalf("%s length mismatch: got %d, want %d", label, len(got), len(want))
	}
}

type multiChunkFixture struct {
	mf       *MemoryFile
	c0Small  memmap.FileRange
	c0Large  memmap.FileRange
	c0ZeroC  memmap.FileRange
	c0ZeroU  memmap.FileRange
	c1Huge   memmap.FileRange
	c1Small  memmap.FileRange
	c1Large  memmap.FileRange
	c1ZeroA  memmap.FileRange
	c1ZeroB  memmap.FileRange
	wantC0S  []byte
	wantC0L  []byte
	wantC1S  []byte
	wantC1L  []byte
	allAlloc []memmap.FileRange
}

// buildMultiChunkFixture creates a sparse 2 GiB MemoryFile spanning chunk 0
// and chunk 1 while committing less than 256 KiB of physical pages.
func buildMultiChunkFixture(t *testing.T) multiChunkFixture {
	t.Helper()
	page := uint64(hostarch.PageSize)
	mf := newTestMemoryFile(t, MemoryFileOpts{
		ExpectHugepages: true,
	})

	c0Small, err := mf.Allocate(page, AllocOpts{Kind: usage.Anonymous, Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate c0Small: %v", err)
	}
	c0Large, err := mf.Allocate(16*page, AllocOpts{Kind: usage.Anonymous, Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate c0Large: %v", err)
	}
	c0ZeroC, err := mf.Allocate(2*page, AllocOpts{Kind: usage.Anonymous, Mode: AllocateAndCommit})
	if err != nil {
		t.Fatalf("Allocate c0ZeroC: %v", err)
	}
	c0ZeroU, err := mf.Allocate(2*page, AllocOpts{Kind: usage.Anonymous, Mode: AllocateUncommitted})
	if err != nil {
		t.Fatalf("Allocate c0ZeroU: %v", err)
	}
	// Take a second reference on c0Small to verify reference counts across save and restore.
	mf.IncRef(c0Small, 0)

	// An uncommitted hugepage allocation requires a hugepage chunk and extends
	// the MemoryFile into chunk 1 without committing 1 GiB of RAM.
	c1Huge, err := mf.Allocate(uint64(hostarch.HugePageSize), AllocOpts{
		Kind: usage.Anonymous,
		Mode: AllocateUncommitted,
		Huge: true,
	})
	if err != nil {
		t.Fatalf("Allocate c1Huge: %v", err)
	}
	if c0Small.End > chunkSize || c0Large.End > chunkSize {
		t.Fatalf("chunk 0 allocations %v, %v exceeded first 1 GiB chunk", c0Small, c0Large)
	}
	if c1Huge.Start < chunkSize {
		t.Fatalf("chunk 1 allocation %v started below 1 GiB", c1Huge)
	}
	if got := mf.TotalSize(); got < 2*chunkSize {
		t.Fatalf("TotalSize() = %#x, want >= %#x (2 GiB)", got, uint64(2*chunkSize))
	}

	c1ZeroA := memmap.FileRange{Start: c1Huge.Start, End: c1Huge.Start + page}
	c1Small := memmap.FileRange{Start: c1Huge.Start + page, End: c1Huge.Start + 2*page}
	c1Large := memmap.FileRange{Start: c1Huge.Start + 32*page, End: c1Huge.Start + 48*page}
	c1ZeroB := memmap.FileRange{Start: c1Huge.Start + 64*page, End: c1Huge.End}

	wantC0S := writePattern(t, mf, c0Small, 0x13)
	wantC0L := writePattern(t, mf, c0Large, 0x57)
	wantC1S := writePattern(t, mf, c1Small, 0x9B)
	wantC1L := writePattern(t, mf, c1Large, 0xDF)

	mf.MarkSavable()
	return multiChunkFixture{
		mf:       mf,
		c0Small:  c0Small,
		c0Large:  c0Large,
		c0ZeroC:  c0ZeroC,
		c0ZeroU:  c0ZeroU,
		c1Huge:   c1Huge,
		c1Small:  c1Small,
		c1Large:  c1Large,
		c1ZeroA:  c1ZeroA,
		c1ZeroB:  c1ZeroB,
		wantC0S:  wantC0S,
		wantC0L:  wantC0L,
		wantC1S:  wantC1S,
		wantC1L:  wantC1L,
		allAlloc: []memmap.FileRange{c0Small, c0Large, c0ZeroC, c0ZeroU, c1Huge},
	}
}

func (fx *multiChunkFixture) verifyMemoryFile(t *testing.T, mf *MemoryFile) {
	t.Helper()
	if got := mf.TotalSize(); got != fx.mf.TotalSize() {
		t.Fatalf("restored TotalSize() = %#x, want %#x", got, fx.mf.TotalSize())
	}
	if mf.HasUniqueRef(fx.c0Small) {
		t.Fatalf("HasUniqueRef(c0Small %v) = true, want false for refcount 2", fx.c0Small)
	}
	if !mf.HasUniqueRef(fx.c0Large) {
		t.Fatalf("HasUniqueRef(c0Large %v) = false, want true for refcount 1", fx.c0Large)
	}
	assertRangeEquals(t, mf, "c0Small", fx.c0Small, fx.wantC0S)
	assertRangeEquals(t, mf, "c0Large", fx.c0Large, fx.wantC0L)
	assertRangeEquals(t, mf, "c0ZeroC", fx.c0ZeroC, make([]byte, fx.c0ZeroC.Length()))
	assertRangeEquals(t, mf, "c0ZeroU", fx.c0ZeroU, make([]byte, fx.c0ZeroU.Length()))
	assertRangeEquals(t, mf, "c1ZeroA", fx.c1ZeroA, make([]byte, fx.c1ZeroA.Length()))
	assertRangeEquals(t, mf, "c1Small", fx.c1Small, fx.wantC1S)
	assertRangeEquals(t, mf, "c1Large", fx.c1Large, fx.wantC1L)
	assertRangeEquals(t, mf, "c1ZeroB", fx.c1ZeroB, make([]byte, fx.c1ZeroB.Length()))
}

func (fx *multiChunkFixture) releaseAndDestroy(t *testing.T, mf *MemoryFile) {
	t.Helper()
	mf.DecRef(fx.c0Small)
	for _, fr := range fx.allAlloc {
		mf.DecRef(fr)
	}
	awaitDestroy(t, mf)
}

type nopBufferCloser struct {
	*bytes.Buffer
}

func (nopBufferCloser) Close() error { return nil }

func TestSaveRestoreMultiChunkSyncAndAsync(t *testing.T) {
	ctx := context.Background()

	t.Run("SyncBufioAndSimpleReader", func(t *testing.T) {
		for _, excludeZero := range []bool{false, true} {
			fx := buildMultiChunkFixture(t)
			var raw bytes.Buffer
			key := []byte("0123456789abcdef0123456789abcdef")
			sw := compressio.NewSimpleWriter(&raw, key, 64*1024)
			bwc := stateio.NewBufioWriteCloser(sw)
			if err := fx.mf.SaveTo(ctx, bwc, &SaveOpts{
				ExcludeCommittedZeroPages: excludeZero,
			}); err != nil {
				t.Fatalf("SaveTo(excludeZero=%v): %v", excludeZero, err)
			}
			if err := bwc.Close(); err != nil {
				t.Fatalf("BufioWriteCloser.Close: %v", err)
			}

			sr := compressio.NewSimpleReader(io.NopCloser(bytes.NewReader(raw.Bytes())), key)
			brc := stateio.NewBufioReadCloser(sr)
			restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
			if err := restored.LoadFrom(ctx, brc, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom(excludeZero=%v): %v", excludeZero, err)
			}
			if err := brc.Close(); err != nil {
				t.Fatalf("BufioReadCloser.Close: %v", err)
			}

			fx.verifyMemoryFile(t, restored)
			fx.releaseAndDestroy(t, restored)
			fx.releaseAndDestroy(t, fx.mf)
		}
	})

	t.Run("AsyncPagesFileIOWriterAndBufWriter", func(t *testing.T) {
		fx := buildMultiChunkFixture(t)

		var pagesBuf bytes.Buffer
		pagesAW := stateio.NewIOWriter(nopBufferCloser{&pagesBuf}, 1<<20, 64, 4)
		saveDone := make(chan error, 1)
		apfs, err := StartAsyncPagesFileSave(pagesAW, func(err error) {
			saveDone <- err
		})
		if err != nil {
			t.Fatalf("StartAsyncPagesFileSave: %v", err)
		}

		var metaBuf bytes.Buffer
		metaAW := stateio.NewIOWriter(nopBufferCloser{&metaBuf}, 1<<20, 16, 1)
		metaBW, err := stateio.NewBufWriter(metaAW, 256<<10)
		if err != nil {
			apfs.MemoryFilesDone()
			<-saveDone
			t.Fatalf("NewBufWriter: %v", err)
		}

		if err := fx.mf.SaveTo(ctx, metaBW, &SaveOpts{
			ExcludeCommittedZeroPages: true,
			PagesFile:                 apfs,
		}); err != nil {
			_ = metaBW.Close()
			apfs.MemoryFilesDone()
			<-saveDone
			t.Fatalf("SaveTo(async IO): %v", err)
		}
		apfs.MemoryFilesDone()
		if err := <-saveDone; err != nil {
			_ = metaBW.Close()
			t.Fatalf("AsyncPagesFileSave failed: %v", err)
		}
		if err := metaBW.Close(); err != nil {
			t.Fatalf("BufWriter.Close: %v", err)
		}

		pagesBytes := pagesBuf.Bytes()
		pagesAR := stateio.NewIOReader(struct {
			*bytes.Reader
			io.Closer
		}{bytes.NewReader(pagesBytes), io.NopCloser(nil)}, 1<<20, 64, 4)
		loadDone := make(chan error, 1)
		apfl, err := StartAsyncPagesFileLoad(pagesAR, func(err error) {
			loadDone <- err
		}, nil, AsyncPagesFileLoadOpts{})
		if err != nil {
			t.Fatalf("StartAsyncPagesFileLoad: %v", err)
		}

		metaBytes := metaBuf.Bytes()
		metaAR := stateio.NewIOReader(struct {
			*bytes.Reader
			io.Closer
		}{bytes.NewReader(metaBytes), io.NopCloser(nil)}, 1<<20, 16, 1)
		metaBR, err := stateio.NewBufReader(metaAR, 256<<10)
		if err != nil {
			apfl.MemoryFilesDone()
			<-loadDone
			t.Fatalf("NewBufReader: %v", err)
		}

		restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
		loadOpts := LoadOpts{PagesFile: apfl}
		if err := restored.LoadFrom(ctx, metaBR, &loadOpts); err != nil {
			_ = metaBR.Close()
			apfl.MemoryFilesDone()
			<-loadDone
			t.Fatalf("LoadFrom(async IO): %v", err)
		}
		apfl.MemoryFilesDone()
		if err := restored.AwaitLoadAll(); err != nil {
			t.Fatalf("AwaitLoadAll: %v", err)
		}
		if err := <-loadDone; err != nil {
			t.Fatalf("AsyncPagesFileLoad failed: %v", err)
		}
		if err := metaBR.Close(); err != nil {
			t.Fatalf("BufReader.Close: %v", err)
		}

		fx.verifyMemoryFile(t, restored)
		fx.releaseAndDestroy(t, restored)
		fx.releaseAndDestroy(t, fx.mf)
	})

	t.Run("AsyncPagesFileFDWriterAndFDReader", func(t *testing.T) {
		fx := buildMultiChunkFixture(t)

		pagesFile, err := os.CreateTemp(t.TempDir(), "gvx-pages-*.bin")
		if err != nil {
			t.Fatalf("CreateTemp: %v", err)
		}
		defer pagesFile.Close()

		writeFD, err := unix.Dup(int(pagesFile.Fd()))
		if err != nil {
			t.Fatalf("Dup(writeFD): %v", err)
		}
		fdWriter := stateio.NewPagesFileFDWriterDefault(int32(writeFD))
		saveDone := make(chan error, 1)
		apfs, err := StartAsyncPagesFileSave(fdWriter, func(err error) {
			saveDone <- err
		})
		if err != nil {
			t.Fatalf("StartAsyncPagesFileSave(FDWriter): %v", err)
		}

		var metaBuf bytes.Buffer
		if err := fx.mf.SaveTo(ctx, &metaBuf, &SaveOpts{
			ExcludeCommittedZeroPages: true,
			PagesFile:                 apfs,
		}); err != nil {
			apfs.MemoryFilesDone()
			<-saveDone
			t.Fatalf("SaveTo(FDWriter): %v", err)
		}
		apfs.MemoryFilesDone()
		if err := <-saveDone; err != nil {
			t.Fatalf("AsyncPagesFileSave(FDWriter) failed: %v", err)
		}

		readFD, err := unix.Dup(int(pagesFile.Fd()))
		if err != nil {
			t.Fatalf("Dup(readFD): %v", err)
		}
		fdReader := stateio.NewPagesFileFDReaderDefault(int32(readFD), runtime.GOMAXPROCS(0))
		loadDone := make(chan error, 1)
		apfl, err := StartAsyncPagesFileLoad(fdReader, func(err error) {
			loadDone <- err
		}, nil, AsyncPagesFileLoadOpts{})
		if err != nil {
			t.Fatalf("StartAsyncPagesFileLoad(FDReader): %v", err)
		}

		restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
		loadOpts := LoadOpts{PagesFile: apfl}
		if err := restored.LoadFrom(ctx, bytes.NewReader(metaBuf.Bytes()), &loadOpts); err != nil {
			apfl.MemoryFilesDone()
			<-loadDone
			t.Fatalf("LoadFrom(FDReader): %v", err)
		}
		apfl.MemoryFilesDone()
		if err := restored.AwaitLoadAll(); err != nil {
			t.Fatalf("AwaitLoadAll(FDReader): %v", err)
		}
		if err := <-loadDone; err != nil {
			t.Fatalf("AsyncPagesFileLoad(FDReader) failed: %v", err)
		}

		fx.verifyMemoryFile(t, restored)
		fx.releaseAndDestroy(t, restored)
		fx.releaseAndDestroy(t, fx.mf)
	})
}

func TestSaveRestoreSeekDataUnsupportedFallback(t *testing.T) {
	ctx := context.Background()

	unsupportedErrs := []struct {
		name string
		err  error
	}{
		{name: "EINVAL", err: unix.EINVAL},
		{name: "ENOSYS", err: unix.ENOSYS},
		{name: "ENOTSUP", err: unix.ENOTSUP},
		{name: "EOPNOTSUPP", err: unix.EOPNOTSUPP},
	}

	for _, tc := range unsupportedErrs {
		t.Run(tc.name, func(t *testing.T) {
			fx := buildMultiChunkFixture(t)
			seekCalls := 0
			fx.mf.saveRestore.seekFn = func(_ int, _ int64, whence int) (int64, error) {
				if whence == unix.SEEK_DATA || whence == unix.SEEK_HOLE {
					seekCalls++
					return 0, tc.err
				}
				return 0, unix.EINVAL
			}

			var buf bytes.Buffer
			if err := fx.mf.SaveTo(ctx, &buf, &SaveOpts{
				ExcludeCommittedZeroPages: true,
				ExitAfterSaving:           true,
			}); err != nil {
				t.Fatalf("SaveTo with SEEK_DATA %s failed: %v", tc.name, err)
			}
			if seekCalls != 1 {
				t.Fatalf("seekCalls = %d, want 1 before fallback disables dataSeeker", seekCalls)
			}

			restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
			if err := restored.LoadFrom(ctx, &buf, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom after %s fallback failed: %v", tc.name, err)
			}
			fx.verifyMemoryFile(t, restored)
			fx.releaseAndDestroy(t, restored)
			fx.releaseAndDestroy(t, fx.mf)
		})
	}

	t.Run("MidScanFallbackInSecondChunk", func(t *testing.T) {
		fx := buildMultiChunkFixture(t)
		fx.mf.saveRestore.seekFn = func(fd int, offset int64, whence int) (int64, error) {
			if offset >= chunkSize {
				return 0, unix.ENOTSUP
			}
			if runtime.GOOS == "windows" {
				// Simulate a seeker that reports chunk 0 as data and rejects chunk 1.
				if whence == unix.SEEK_DATA {
					return offset, nil
				}
				return chunkSize, nil
			}
			return unix.Seek(fd, offset, whence)
		}

		var buf bytes.Buffer
		if err := fx.mf.SaveTo(ctx, &buf, &SaveOpts{
			ExcludeCommittedZeroPages: false,
			ExitAfterSaving:           true,
		}); err != nil {
			t.Fatalf("SaveTo mid-scan fallback failed: %v", err)
		}

		restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
		if err := restored.LoadFrom(ctx, &buf, &LoadOpts{}); err != nil {
			t.Fatalf("LoadFrom mid-scan fallback failed: %v", err)
		}
		fx.verifyMemoryFile(t, restored)
		fx.releaseAndDestroy(t, restored)
		fx.releaseAndDestroy(t, fx.mf)
	})

	if runtime.GOOS == "windows" {
		t.Run("WindowsNativeSeekDataReturnsEINVAL", func(t *testing.T) {
			mf := newTestMemoryFile(t, MemoryFileOpts{})
			defer awaitDestroy(t, mf)
			fr, err := mf.Allocate(uint64(hostarch.PageSize), AllocOpts{Kind: usage.Anonymous})
			if err != nil {
				t.Fatalf("Allocate: %v", err)
			}
			defer mf.DecRef(fr)
			if _, err := unix.Seek(mf.FD(), 0, unix.SEEK_DATA); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("unix.Seek(SEEK_DATA) = %v, want EINVAL", err)
			}
			if _, err := unix.Seek(mf.FD(), 0, unix.SEEK_HOLE); !errors.Is(err, unix.EINVAL) {
				t.Fatalf("unix.Seek(SEEK_HOLE) = %v, want EINVAL", err)
			}
		})
	}
}

// TestSaveRestoreSubHostPageDecommitPreservesSiblings verifies that SaveTo
// decommits zero 4 KB sub-pages without zeroing sibling 4 KB sub-pages inside
// a 16 KB host page.
func TestSaveRestoreSubHostPageDecommitPreservesSiblings(t *testing.T) {
	ctx := context.Background()
	page := uint64(hostarch.PageSize)

	for _, forceFallback := range []bool{false, true} {
		name := "NativeSeeker"
		if forceFallback {
			name = "FallbackScan"
		}
		t.Run(name, func(t *testing.T) {
			mf := newTestMemoryFile(t, MemoryFileOpts{})
			if forceFallback {
				mf.saveRestore.seekFn = func(_ int, _ int64, _ int) (int64, error) {
					return 0, unix.ENOTSUP
				}
			}

			// Allocate 16 uncommitted guest pages (64 KB) so SaveTo scans them and
			// invokes decommitNow on zero pages.
			region, err := mf.Allocate(16*page, AllocOpts{
				Kind: usage.Anonymous,
				Mode: AllocateUncommitted,
			})
			if err != nil {
				t.Fatalf("Allocate(64KB): %v", err)
			}

			sub := func(idx uint64, count uint64) memmap.FileRange {
				return memmap.FileRange{
					Start: region.Start + idx*page,
					End:   region.Start + (idx+count)*page,
				}
			}

			// Dirty and clear pages [4..12) so the host commits [16 KB, 48 KB)
			// before SaveTo punches holes.
			bsMid, err := mf.MapInternal(sub(4, 8), hostarch.ReadWrite)
			if err != nil {
				t.Fatalf("MapInternal middle: %v", err)
			}
			for !bsMid.IsEmpty() {
				s := bsMid.Head().ToSlice()
				for i := range s {
					s[i] = 0xEE
				}
				clear(s)
				bsMid = bsMid.Tail()
			}

			// Write non-zero patterns to 4 KB sub-pages that share the first and
			// fourth 16 KB host pages with adjacent zero sub-pages.
			want0 := writePattern(t, mf, sub(0, 1), 0xA5)
			want2 := writePattern(t, mf, sub(2, 1), 0x5A)
			want13 := writePattern(t, mf, sub(13, 1), 0xCC)
			want15 := writePattern(t, mf, sub(15, 1), 0x33)

			mf.MarkSavable()
			var buf bytes.Buffer
			if err := mf.SaveTo(ctx, &buf, &SaveOpts{
				ExcludeCommittedZeroPages: true,
			}); err != nil {
				t.Fatalf("SaveTo: %v", err)
			}

			// Verify that the source MemoryFile kept every sibling sub-page intact after decommitNow.
			verifyLayout := func(target *MemoryFile, tag string) {
				assertRangeEquals(t, target, tag+" sub(0)", sub(0, 1), want0)
				assertRangeEquals(t, target, tag+" sub(1)", sub(1, 1), make([]byte, page))
				assertRangeEquals(t, target, tag+" sub(2)", sub(2, 1), want2)
				assertRangeEquals(t, target, tag+" sub(3..12)", sub(3, 10), make([]byte, 10*page))
				assertRangeEquals(t, target, tag+" sub(13)", sub(13, 1), want13)
				assertRangeEquals(t, target, tag+" sub(14)", sub(14, 1), make([]byte, page))
				assertRangeEquals(t, target, tag+" sub(15)", sub(15, 1), want15)
			}
			verifyLayout(mf, "source")

			restored := newTestMemoryFile(t, MemoryFileOpts{})
			if err := restored.LoadFrom(ctx, &buf, &LoadOpts{}); err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			verifyLayout(restored, "restored")

			restored.DecRef(region)
			awaitDestroy(t, restored)
			mf.DecRef(region)
			awaitDestroy(t, mf)
		})
	}
}

func TestMultiChunkSingleExtendAndDestroy(t *testing.T) {
	mf := newTestMemoryFile(t, MemoryFileOpts{
		DisableMemoryAccounting: true,
		DecommitOnDestroy:       false,
	})
	mf.mu.Lock()
	err := mf.extendChunksLocked(&allocState{
		length: chunkSize + uint64(hostarch.PageSize),
	})
	chunks := append([]chunkInfo(nil), mf.chunksLoad()...)
	mf.mu.Unlock()
	if err != nil {
		t.Fatalf("extendChunksLocked(2 chunks): %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("len(chunks) = %d, want 2", len(chunks))
	}
	for i, c := range chunks {
		if c.mapping == 0 {
			t.Fatalf("chunks[%d].mapping = 0, want mapped view", i)
		}
	}
	awaitDestroy(t, mf)
}
