//go:build windows

package pgalloc

import (
	"errors"
	"syscall"
	"testing"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
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
	// DiscardVirtualMemory can refuse section views. The zeroing must hold either way.
	if err := DecommitSharedPages(pages); err != nil {
		var errno syscall.Errno
		if !errors.As(err, &errno) {
			t.Fatalf("DecommitSharedPages: %v", err)
		}
		t.Logf("DecommitSharedPages reported a missed reclaim: %v", err)
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
}

func TestDecommitSharedPagesKeepsNeighbours(t *testing.T) {
	t.Parallel()
	pages, err := AllocateSharedPages(3 * 4096)
	if err != nil {
		t.Fatalf("AllocateSharedPages: %v", err)
	}
	defer ReleaseSharedPages(pages)
	for i := range pages {
		pages[i] = 0xC3
	}
	const page = 4096
	_ = DecommitSharedPages(pages[page : 2*page])
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

	fr, err := mf.Allocate(uint64(hostarch.PageSize), AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal: %v", err)
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
	mf.DecRef(fr)
}
