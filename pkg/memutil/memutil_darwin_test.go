//go:build darwin

package memutil

import (
	"errors"
	"sync"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// isMapped reports whether every page of b is a mapped, writable range.
// mprotect fails with ENOMEM when any page of the range is unmapped.
func isMapped(b []byte) bool {
	return unix.Mprotect(b, unix.PROT_READ|unix.PROT_WRITE) == nil
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
	arena := mustArena(t, 4*hostPageSize())
	defer func() {
		if err := UnmapView(arena); err != nil {
			t.Errorf("UnmapView(arena): %v", err)
		}
	}()

	offset := hostPageSize() + pageSize4K
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
	arena := mustArena(t, 4*hostPageSize())
	defer func() { _ = UnmapView(arena) }()

	tail := arena[2*hostPageSize():]
	view, err := RemapAnonymousView(tail, pageSize4K, pageSize4K)
	if err != nil {
		t.Fatalf("RemapAnonymousView(subslice): %v", err)
	}
	view[0] = 0x3C
	if got := arena[2*hostPageSize()+pageSize4K]; got != 0x3C {
		t.Fatalf("arena byte = %#x after write through subslice view, want 0x3C", got)
	}
}

func TestRemapAnonymousViewRejectsUnknownArena(t *testing.T) {
	t.Parallel()
	foreign := make([]byte, 2*hostPageSize())
	if view, err := RemapAnonymousView(foreign, 0, pageSize4K); !errors.Is(err, ErrNotArena) {
		t.Fatalf("RemapAnonymousView(Go heap slice) = (%d bytes, %v), want ErrNotArena", len(view), err)
	}

	arena := mustArena(t, hostPageSize())
	defer func() { _ = UnmapView(arena) }()
	// A range that runs past the registered mapping is not part of the arena.
	overrun := unsafe.Slice(&arena[0], 2*hostPageSize())
	if view, err := RemapAnonymousView(overrun, hostPageSize(), pageSize4K); !errors.Is(err, ErrNotArena) {
		t.Fatalf("RemapAnonymousView(past arena end) = (%d bytes, %v), want ErrNotArena", len(view), err)
	}
}

func TestRemapAnonymousViewRejectsBadRanges(t *testing.T) {
	t.Parallel()
	arena := mustArena(t, 2*hostPageSize())
	defer func() { _ = UnmapView(arena) }()
	for _, tc := range []struct{ offset, size int }{
		{-pageSize4K, pageSize4K},
		{0, 0},
		{1, pageSize4K},
		{0, pageSize4K + 1},
		{hostPageSize(), 2 * hostPageSize()},
	} {
		if view, err := RemapAnonymousView(arena, tc.offset, tc.size); err == nil {
			t.Errorf("RemapAnonymousView(offset=%d, size=%d) = %d bytes, want error", tc.offset, tc.size, len(view))
		}
	}
}

// TestUnmapViewDetachesViewFromArena proves that releasing one alias removes it
// from the arena. A later arena release must not unmap an unrelated mapping at the same address.
func TestUnmapViewDetachesViewFromArena(t *testing.T) {
	// This test is not parallel: another test could map memory at an address this test unmapped.
	arena := mustArena(t, 2*hostPageSize())
	view, err := RemapAnonymousView(arena, 0, hostPageSize())
	if err != nil {
		t.Fatalf("RemapAnonymousView: %v", err)
	}
	viewBase := uintptr(unsafe.Pointer(&view[0]))
	if err := UnmapView(view); err != nil {
		t.Fatalf("UnmapView(view): %v", err)
	}
	if isMapped(unsafe.Slice((*byte)(unsafe.Pointer(&view[0])), 1)) {
		t.Fatal("alias is still mapped after UnmapView")
	}

	// Map an unrelated page at the address the alias used.
	got, _, errno := unix.RawSyscall6(unix.SYS_MMAP, viewBase, uintptr(hostPageSize()),
		unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE|unix.MAP_FIXED, ^uintptr(0), 0)
	if errno != 0 || got != viewBase {
		t.Fatalf("mmap(MAP_FIXED, %#x) = (%#x, %v)", viewBase, got, errno)
	}
	defer unix.RawSyscall(unix.SYS_MUNMAP, viewBase, uintptr(hostPageSize()), 0)
	bystander := unsafe.Slice((*byte)(pointerFromAddr(viewBase)), hostPageSize())
	bystander[0] = 0x77

	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if !isMapped(bystander) || bystander[0] != 0x77 {
		t.Fatal("arena release unmapped a bystander mapping that reused an alias address")
	}
}

func TestUnmapArenaReleasesLiveViews(t *testing.T) {
	// This test is not parallel: another test could map memory at an address this test unmapped.
	arena := mustArena(t, 2*hostPageSize())
	view, err := RemapAnonymousView(arena, 0, hostPageSize())
	if err != nil {
		t.Fatalf("RemapAnonymousView: %v", err)
	}
	viewStart := unsafe.Slice(&view[0], 1)
	arenaStart := unsafe.Slice(&arena[0], 1)
	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if isMapped(viewStart) || isMapped(arenaStart) {
		t.Fatal("arena release left the arena or an alias mapped")
	}
	if err := UnmapView(view); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("UnmapView(alias after arena release) = %v, want ErrNotMapped", err)
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
	arena := mustArena(t, hostPageSize())
	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
	if err := UnmapView(arena); !errors.Is(err, ErrNotMapped) {
		t.Fatalf("second UnmapView(arena) = %v, want ErrNotMapped", err)
	}
}

func TestConcurrentRemapAndUnmapKeepsRegistryConsistent(t *testing.T) {
	t.Parallel()
	arena := mustArena(t, 8*hostPageSize())
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				view, err := RemapAnonymousView(arena, (i%8)*hostPageSize(), hostPageSize())
				if err != nil {
					t.Errorf("RemapAnonymousView: %v", err)
					return
				}
				view[0] = byte(i)
				if err := UnmapView(view); err != nil {
					t.Errorf("UnmapView(view): %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	registry.mu.Lock()
	remaining := len(registry.arenas[uintptr(unsafe.Pointer(&arena[0]))].views)
	registry.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("arena tracks %d views after all were unmapped, want 0", remaining)
	}
	if err := UnmapView(arena); err != nil {
		t.Fatalf("UnmapView(arena): %v", err)
	}
}

func TestCreateMemFD(t *testing.T) {
	t.Parallel()
	fd, err := CreateMemFD("test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	defer unix.Close(fd)

	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Errorf("fd flags = %#x, want FD_CLOEXEC", flags)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	if st.Nlink != 0 {
		t.Errorf("Nlink = %d, want 0 (unlinked file)", st.Nlink)
	}
	if _, err := unix.Pwrite(fd, []byte("memfd"), 0); err != nil {
		t.Fatalf("Pwrite: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := unix.Pread(fd, buf, 0); err != nil || string(buf) != "memfd" {
		t.Fatalf("Pread = (%q, %v), want memfd", buf, err)
	}
}

func TestMapSliceSharesFileContents(t *testing.T) {
	// This test is not parallel: another test could map memory at the address this test unmaps.
	fd, err := CreateMemFD("map", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	defer unix.Close(fd)
	if err := unix.Ftruncate(fd, int64(hostPageSize())); err != nil {
		t.Fatalf("Ftruncate: %v", err)
	}
	mapping, err := MapSlice(0, uintptr(hostPageSize()), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED, uintptr(fd), 0)
	if err != nil {
		t.Fatalf("MapSlice: %v", err)
	}
	mapping[7] = 0x42
	buf := make([]byte, 1)
	if _, err := unix.Pread(fd, buf, 7); err != nil || buf[0] != 0x42 {
		t.Fatalf("Pread after write through mapping = (%#x, %v), want 0x42", buf[0], err)
	}
	// UnmapSlice returns a typed Errno even on success, so the test reads only the mapping state.
	_ = UnmapSlice(mapping)
	if isMapped(mapping) {
		t.Fatal("mapping is still mapped after UnmapSlice")
	}
}
