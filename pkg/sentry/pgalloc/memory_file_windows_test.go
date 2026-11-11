//go:build windows

package pgalloc

import (
	"bytes"
	"context"
	"errors"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

func TestSharedPagesAliasAndDecommit(t *testing.T) {
	t.Parallel()
	pages, err := AllocateSharedPages(16384)
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			t.Errorf("ReleaseSharedPages: %v", err)
		}
	}()
	for i := range pages {
		pages[i] = 0x5A
	}
	alias, err := RemapSharedPages(pages)
	if err != nil {
		t.Fatalf("RemapSharedPages: %v", err)
	}
	if alias[0] != 0x5A || alias[len(alias)-1] != 0x5A {
		t.Fatalf("alias bytes = %#x..%#x, want 0x5A", alias[0], alias[len(alias)-1])
	}
	// DiscardVirtualMemory can return ERROR_INVALID_PARAMETER on mapped section views,
	// while DecommitSharedPages must still zero the shared backing pages.
	if err := DecommitSharedPages(pages); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			t.Fatalf("DecommitSharedPages returned non-Errno error: %v", err)
		}
		t.Fatalf("DecommitSharedPages = %v, want nil or ERROR_INVALID_PARAMETER", err)
	}
	for i, b := range pages {
		if b != 0 {
			t.Fatalf("pages[%d] = %#x after DecommitSharedPages, want 0", i, b)
		}
	}
	for i, b := range alias {
		if b != 0 {
			t.Fatalf("alias[%d] = %#x after DecommitSharedPages, want 0", i, b)
		}
	}
	// Verify that both views remain coherent after decommit.
	alias[0] = 0xA5
	alias[len(alias)-1] = 0x3C
	if pages[0] != 0xA5 || pages[len(pages)-1] != 0x3C {
		t.Fatalf("pages bytes after alias write = %#x..%#x, want 0xA5..0x3C", pages[0], pages[len(pages)-1])
	}
}

func TestDecommitSharedPagesKeepsNeighbours(t *testing.T) {
	t.Parallel()
	pages, err := AllocateSharedPages(3 * 4096)
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			t.Errorf("ReleaseSharedPages: %v", err)
		}
	}()
	for i := range pages {
		pages[i] = 0xC3
	}
	const page = 4096
	if err := DecommitSharedPages(pages[page : 2*page]); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		t.Fatalf("DecommitSharedPages: %v", err)
	}
	for i, b := range pages {
		want := byte(0xC3)
		if i >= page && i < 2*page {
			want = 0
		}
		if b != want {
			t.Fatalf("pages[%d] = %#x, want %#x", i, b, want)
		}
	}
}

func TestDecommitSharedPagesRejectsEmptyRegion(t *testing.T) {
	t.Parallel()
	if err := DecommitSharedPages(nil); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("DecommitSharedPages(nil) = %v, want EINVAL", err)
	}
}

func TestDefaultMemoryFileDecommitZeroesPages(t *testing.T) {
	t.Parallel()
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		t.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	const allocSize = uint64(2 * hostarch.PageSize)
	fr, err := mf.Allocate(allocSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if fr.Length() != allocSize {
		t.Fatalf("fr.Length() = %d, want %d", fr.Length(), allocSize)
	}
	if !mf.HasUniqueRef(fr) {
		t.Fatalf("HasUniqueRef(%v) = false, want true", fr)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
	}
	if uint64(bs.NumBytes()) != allocSize {
		t.Fatalf("MapInternal NumBytes = %d, want %d", bs.NumBytes(), allocSize)
	}
	slice := bs.Head().ToSlice()
	for i := range slice {
		slice[i] = 0x7F
	}
	// NTFS refuses to zero a range that a view maps, so Decommit may take its manual-zero path.
	mf.Decommit(fr)
	for i, b := range slice {
		if b != 0 {
			t.Fatalf("slice[%d] = %#x after Decommit, want 0", i, b)
		}
	}
	// Verify that the mapping remains writable and visible across a second MapInternal call.
	slice[0] = 0x42
	slice[len(slice)-1] = 0x99
	bs2, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("second MapInternal: %v", err)
	}
	slice2 := bs2.Head().ToSlice()
	if slice2[0] != 0x42 || slice2[len(slice2)-1] != 0x99 {
		t.Fatalf("second MapInternal bytes = %#x..%#x, want 0x42..0x99", slice2[0], slice2[len(slice2)-1])
	}
	mf.DecRef(fr)
}

func BenchmarkAllocateAndDecommitSharedPages(b *testing.B) {
	const regionSize = 16 * 4096
	pages, err := AllocateSharedPages(regionSize)
	if err != nil {
		b.Fatalf("AllocateSharedPages: %v", err)
	}
	defer func() {
		if err := ReleaseSharedPages(pages); err != nil {
			b.Fatalf("ReleaseSharedPages: %v", err)
		}
	}()
	b.SetBytes(regionSize)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pages[0] = byte(i)
		pages[len(pages)-1] = byte(i)
		if err := DecommitSharedPages(pages); err != nil && !errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			b.Fatalf("DecommitSharedPages: %v", err)
		}
	}
}

func BenchmarkMemoryFileAllocateMapDecommit(b *testing.B) {
	mf, err := NewDefaultMemoryFile(MemoryFileOpts{DisableMemoryAccounting: true})
	if err != nil {
		b.Fatalf("NewDefaultMemoryFile: %v", err)
	}
	defer mf.Destroy()

	const allocSize = uint64(4 * hostarch.PageSize)
	b.SetBytes(int64(allocSize))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		fr, err := mf.Allocate(allocSize, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			b.Fatalf("Allocate: %v", err)
		}
		bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
		if err != nil {
			b.Fatalf("MapInternal: %v", err)
		}
		head := bs.Head().ToSlice()
		head[0] = byte(i)
		mf.Decommit(fr)
		mf.DecRef(fr)
	}
}

func TestWindowsMultiChunkLoadFromAndDestroyReleasesKernelViews(t *testing.T) {
	ctx := context.Background()
	fx := buildMultiChunkFixture(t)

	var buf bytes.Buffer
	if err := fx.mf.SaveTo(ctx, &buf, &SaveOpts{ExcludeCommittedZeroPages: true}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}

	restored := newTestMemoryFile(t, MemoryFileOpts{ExpectHugepages: true})
	if err := restored.LoadFrom(ctx, &buf, &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}
	chunks := append([]chunkInfo(nil), restored.chunksLoad()...)
	if len(chunks) < 2 {
		t.Fatalf("len(chunks) = %d, want >= 2", len(chunks))
	}
	for i, c := range chunks {
		var info windows.MemoryBasicInformation
		if err := windows.VirtualQuery(c.mapping, &info, unsafe.Sizeof(info)); err != nil {
			t.Fatalf("VirtualQuery(chunk %d at %#x): %v", i, c.mapping, err)
		}
		if info.State != windows.MEM_COMMIT {
			t.Fatalf("chunk %d State = %#x before Destroy, want MEM_COMMIT", i, info.State)
		}
	}

	fx.verifyMemoryFile(t, restored)
	fx.releaseAndDestroy(t, restored)
	fx.releaseAndDestroy(t, fx.mf)

	const winMemFree = 0x10000 // MEM_FREE from winnt.h
	for i, c := range chunks {
		var info windows.MemoryBasicInformation
		if err := windows.VirtualQuery(c.mapping, &info, unsafe.Sizeof(info)); err != nil {
			t.Fatalf("VirtualQuery(chunk %d at %#x after Destroy): %v", i, c.mapping, err)
		}
		if info.State != winMemFree {
			t.Fatalf("chunk %d State = %#x after Destroy, want %#x (MEM_FREE)", i, info.State, winMemFree)
		}
	}
}
