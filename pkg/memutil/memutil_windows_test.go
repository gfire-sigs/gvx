//go:build windows

package memutil

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

// isCommitted reports whether the page at addr is committed memory.
func isCommitted(addr uintptr) bool {
	var info windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &info, unsafe.Sizeof(info)); err != nil {
		return false
	}
	return info.State == windows.MEM_COMMIT
}

func mustArena(t *testing.T, size int) []byte {
	t.Helper()
	arena, err := AllocateAnonymousArena(size)
	if err != nil {
		t.Fatalf("AllocateAnonymousArena(%d): %v", size, err)
	}
	return arena
}

func TestAnonymousArenaRejectsBadSizes(t *testing.T) {
	t.Parallel()
	for _, size := range []int{-4096, 0, 1, 4095, 6144} {
		if arena, err := AllocateAnonymousArena(size); !errors.Is(err, errUnalignedSize) {
			t.Errorf("AllocateAnonymousArena(%d) = (%d bytes, %v), want errUnalignedSize", size, len(arena), err)
		}
	}
}

func TestRemapAnonymousViewAliasesArena(t *testing.T) {
	t.Parallel()
	arena := mustArena(t, 3*allocGranularity)
	defer func() {
		if err := UnmapView(arena); err != nil {
			t.Errorf("UnmapView(arena): %v", err)
		}
	}()

	// The offset is 4KB-aligned but not 64KB-aligned, so the view must start below it.
	offset := allocGranularity + pageSize4K
	view, err := RemapAnonymousView(arena, offset, pageSize4K)
	if err != nil {
		t.Fatalf("RemapAnonymousView: %v", err)
	}
	if len(view) != pageSize4K {
		t.Fatalf("len(view) = %d, want %d", len(view), pageSize4K)
	}
	if uintptr(unsafe.Pointer(&view[0])) == uintptr(unsafe.Pointer(&arena[offset])) {
		t.Fatalf("view reuses the arena address %p, want a distinct alias", &view[0])
	}
	view[0] = 0x5A
	if arena[offset] != 0x5A {
		t.Fatalf("arena[%d] = %#x after write through view, want 0x5A", offset, arena[offset])
	}
	arena[offset+1] = 0xA5
	if view[1] != 0xA5 {
		t.Fatalf("view[1] = %#x after write through arena, want 0xA5", view[1])
	}
}

func TestRemapAnonymousViewAcceptsArenaSubslice(t *testing.T) {
	t.Parallel()
	arena := mustArena(t, 3*allocGranularity)
	defer func() { _ = UnmapView(arena) }()

	tail := arena[allocGranularity:]
	view, err := RemapAnonymousView(tail, pageSize4K, pageSize4K)
	if err != nil {
		t.Fatalf("RemapAnonymousView(subslice): %v", err)
	}
	view[0] = 0x3C
	if got := arena[allocGranularity+pageSize4K]; got != 0x3C {
		t.Fatalf("arena byte = %#x after write through subslice view, want 0x3C", got)
	}
}

func TestRemapAnonymousViewRejectsUnknownArena(t *testing.T) {
	t.Parallel()
	foreign := make([]byte, 2*pageSize4K)
	if view, err := RemapAnonymousView(foreign, 0, pageSize4K); !errors.Is(err, ErrNotArena) {
		t.Fatalf("RemapAnonymousView(Go heap slice) = (%d bytes, %v), want ErrNotArena", len(view), err)
	}
}

func TestRemapAnonymousViewRejectsBadRanges(t *testing.T) {
	t.Parallel()
	arena := mustArena(t, allocGranularity)
	defer func() { _ = UnmapView(arena) }()
	for _, tc := range []struct{ offset, size int }{
		{-pageSize4K, pageSize4K},
		{0, 0},
		{1, pageSize4K},
		{0, pageSize4K + 1},
		{allocGranularity, pageSize4K},
	} {
		if view, err := RemapAnonymousView(arena, tc.offset, tc.size); err == nil {
			t.Errorf("RemapAnonymousView(offset=%d, size=%d) = %d bytes, want error", tc.offset, tc.size, len(view))
		}
	}
}

// TestUnmapViewDetachesViewFromArena proves that releasing one view removes it
// from the arena. A later arena release must not free an unrelated allocation at the same address.
func TestUnmapViewDetachesViewFromArena(t *testing.T) {
	// This test is not parallel: another test could map memory at an address this test unmapped.
	arena := mustArena(t, 2*allocGranularity)
	view, err := RemapAnonymousView(arena, 0, allocGranularity)
	if err != nil {
		t.Fatalf("RemapAnonymousView: %v", err)
	}
	viewBase := uintptr(unsafe.Pointer(&view[0]))
	if err := UnmapView(view); err != nil {
		t.Fatalf("UnmapView(view): %v", err)
	}
	if isCommitted(viewBase) {
		t.Fatal("view is still mapped after UnmapView")
	}

	got, err := windows.VirtualAlloc(viewBase, allocGranularity, windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)
	if err != nil || got != viewBase {
		t.Fatalf("VirtualAlloc(%#x) = (%#x, %v), want the freed view address", viewBase, got, err)
	}
	defer windows.VirtualFree(viewBase, 0, windows.MEM_RELEASE)
	*(*byte)(pointerFromAddr(viewBase)) = 0x77

	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if !isCommitted(viewBase) || *(*byte)(pointerFromAddr(viewBase)) != 0x77 {
		t.Fatal("arena release freed a bystander allocation that reused a view address")
	}
}

func TestUnmapArenaReleasesLiveViews(t *testing.T) {
	// This test is not parallel: another test could map memory at an address this test unmapped.
	arena := mustArena(t, 2*allocGranularity)
	view, err := RemapAnonymousView(arena, 0, allocGranularity)
	if err != nil {
		t.Fatalf("RemapAnonymousView: %v", err)
	}
	viewStart := uintptr(unsafe.Pointer(&view[0]))
	arenaStart := uintptr(unsafe.Pointer(&arena[0]))
	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if isCommitted(viewStart) || isCommitted(arenaStart) {
		t.Fatal("arena release left the arena or a view mapped")
	}
	if err := UnmapView(view); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("UnmapView(view after arena release) = %v, want ErrNotMapped", err)
	}
}

func TestUnmapViewRejectsForeignAndRepeatedUnmap(t *testing.T) {
	// This test is not parallel: another test could map memory at an address this test unmapped.
	if err := UnmapView(nil); err != nil {
		t.Fatalf("UnmapView(nil) = %v, want nil", err)
	}
	if err := UnmapView(make([]byte, 16)); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("UnmapView(Go heap slice) = %v, want ErrNotMapped", err)
	}
	arena := mustArena(t, allocGranularity)
	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if err := UnmapView(arena); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("second UnmapView(arena) = %v, want ErrNotMapped", err)
	}
}

// TestCreateMemFDHandleSurvivesGC verifies that CreateMemFD returns an owned handle.
// A handle that an unreferenced os.File owns would close during collection.
func TestCreateMemFDHandleSurvivesGC(t *testing.T) {
	t.Parallel()
	fd, err := CreateMemFD("gc", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	runtime.GC()
	runtime.GC()
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	if _, err := f.WriteAt([]byte("memfd"), 0); err != nil {
		t.Fatalf("WriteAt after GC: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := f.ReadAt(buf, 0); err != nil || string(buf) != "memfd" {
		t.Fatalf("ReadAt = (%q, %v), want memfd", buf, err)
	}
}

func TestMapSliceHonoursUnalignedFileOffset(t *testing.T) {
	t.Parallel()
	fd, err := CreateMemFD("map", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	const fileSize = 2 * allocGranularity
	if err := f.Truncate(fileSize); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	const offset = allocGranularity + pageSize4K
	if _, err := f.WriteAt([]byte{0x11}, offset); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	mapping, err := MapSlice(0, pageSize4K, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(fd), offset)
	if err != nil {
		t.Fatalf("MapSlice at unaligned offset: %v", err)
	}
	if mapping[0] != 0x11 {
		t.Fatalf("mapping[0] = %#x, want the byte at file offset %#x", mapping[0], offset)
	}
	mapping[1] = 0x22
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, offset+1); err != nil || buf[0] != 0x22 {
		t.Fatalf("ReadAt after write through mapping = (%#x, %v), want 0x22", buf[0], err)
	}
	if err := UnmapSlice(mapping); err != nil {
		t.Fatalf("UnmapSlice: %v", err)
	}
	if isCommitted(uintptr(unsafe.Pointer(&mapping[0]))) {
		t.Fatal("mapping is still committed after UnmapSlice")
	}
}

func TestMapFileRejectsUnsupportedRequests(t *testing.T) {
	t.Parallel()
	fd, err := CreateMemFD("reject", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	if err := f.Truncate(allocGranularity); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	rw := uintptr(unix.PROT_READ | unix.PROT_WRITE)
	for name, tc := range map[string]struct{ flags uintptr }{
		"MAP_FIXED":       {unix.MAP_SHARED | unix.MAP_FIXED},
		"no sharing flag": {0},
		"both sharing":    {unix.MAP_SHARED | unix.MAP_PRIVATE},
		"unknown flag":    {unix.MAP_SHARED | unix.MAP_POPULATE},
	} {
		if addr, err := MapFile(0, pageSize4K, rw, tc.flags, uintptr(fd), 0); err == nil {
			t.Errorf("MapFile(%s) = %#x, want error", name, addr)
			_ = windows.UnmapViewOfFile(addr)
		}
	}
	if addr, err := MapFile(0, 0, rw, unix.MAP_SHARED, uintptr(fd), 0); err == nil {
		t.Errorf("MapFile(size 0) = %#x, want error", addr)
	}
}

func TestMapFilePrivateWriteDoesNotReachFile(t *testing.T) {
	t.Parallel()
	fd, err := CreateMemFD("private", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	f := os.NewFile(uintptr(fd), "memfd")
	defer f.Close()
	if err := f.Truncate(allocGranularity); err != nil {
		t.Fatalf("Truncate: %v", err)
	}
	if _, err := f.WriteAt([]byte{0x01}, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	mapping, err := MapSlice(0, pageSize4K, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE, uintptr(fd), 0)
	if err != nil {
		t.Fatalf("MapSlice(MAP_PRIVATE): %v", err)
	}
	defer func() { _ = UnmapSlice(mapping) }()
	mapping[0] = 0x99
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, 0); err != nil || buf[0] != 0x01 {
		t.Fatalf("file byte after private write = (%#x, %v), want 0x01", buf[0], err)
	}
}
