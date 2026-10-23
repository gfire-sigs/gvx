//go:build windows

package unix_test

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
	"golang.org/x/sys/windows"
)

func gvxTempFile(t *testing.T, size int64) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "gvx-overlay-*")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	if size > 0 {
		if err := f.Truncate(size); err != nil {
			t.Fatalf("Truncate: %v", err)
		}
	}
	return f
}

func gvxFileSize(t *testing.T, f *os.File) int64 {
	t.Helper()
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	return fi.Size()
}

func gvxProtection(t *testing.T, addr uintptr) uint32 {
	t.Helper()
	var info windows.MemoryBasicInformation
	if err := windows.VirtualQuery(addr, &info, unsafe.Sizeof(info)); err != nil {
		t.Fatalf("VirtualQuery: %v", err)
	}
	return info.Protect
}

func TestGvxFallocateExtendsButNeverShrinks(t *testing.T) {
	f := gvxTempFile(t, 0)
	fd := int(f.Fd())
	if err := unix.Fallocate(fd, 0, 4096, 4096); err != nil {
		t.Fatalf("Fallocate extend: %v", err)
	}
	if got := gvxFileSize(t, f); got != 8192 {
		t.Fatalf("size after extend = %d, want 8192", got)
	}
	if err := unix.Fallocate(fd, 0, 0, 4096); err != nil {
		t.Fatalf("Fallocate inside file: %v", err)
	}
	if got := gvxFileSize(t, f); got != 8192 {
		t.Fatalf("size after Fallocate of a lower range = %d, want 8192 (never shrinks)", got)
	}
	if err := unix.Fallocate(fd, unix.FALLOC_FL_KEEP_SIZE, 0, 4096); !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("Fallocate(FALLOC_FL_KEEP_SIZE) = %v, want ENOTSUP", err)
	}
}

func TestGvxFallocatePunchHoleIsUnsupported(t *testing.T) {
	const size = 128 * 1024
	f := gvxTempFile(t, size)
	data := make([]byte, size)
	for i := range data {
		data[i] = 0xAA
	}
	if _, err := f.WriteAt(data, 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	const mode = unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE
	if err := unix.Fallocate(int(f.Fd()), mode, 65536, 65536); !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("Fallocate(PUNCH_HOLE) = %v, want ENOTSUP, so that the caller zeroes the range", err)
	}
	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, 0); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	for i, b := range buf {
		if b != 0xAA {
			t.Fatalf("file[%d] = %#x after the refused punch, want 0xaa", i, b)
		}
	}
}

func TestGvxMprotectChangesPageProtection(t *testing.T) {
	mem, err := unix.Mmap(-1, 0, 8192, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mem)
	addr := uintptr(unsafe.Pointer(&mem[0]))
	if got := gvxProtection(t, addr); got != windows.PAGE_READWRITE {
		t.Fatalf("initial protection = %#x, want PAGE_READWRITE", got)
	}
	if err := unix.Mprotect(mem[4096:], unix.PROT_READ); err != nil {
		t.Fatalf("Mprotect(PROT_READ): %v", err)
	}
	if got := gvxProtection(t, addr+4096); got != windows.PAGE_READONLY {
		t.Fatalf("protection after Mprotect = %#x, want PAGE_READONLY", got)
	}
	if got := gvxProtection(t, addr); got != windows.PAGE_READWRITE {
		t.Fatalf("neighbour protection = %#x, want PAGE_READWRITE", got)
	}
	if err := unix.Mprotect(mem[1:], unix.PROT_READ); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Mprotect(unaligned) = %v, want EINVAL", err)
	}
}

func TestGvxMmapHonoursProtectionAndFileOffset(t *testing.T) {
	const size = 2 * 65536
	f := gvxTempFile(t, size)
	if _, err := f.WriteAt([]byte{0x11}, 65536+4096); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	ro, err := unix.Mmap(int(f.Fd()), 65536+4096, 4096, unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap(read-only, unaligned offset): %v", err)
	}
	if ro[0] != 0x11 {
		t.Fatalf("mapping[0] = %#x, want the byte at file offset 69632", ro[0])
	}
	if got := gvxProtection(t, uintptr(unsafe.Pointer(&ro[0]))); got != windows.PAGE_READONLY {
		t.Fatalf("read-only mapping protection = %#x, want PAGE_READONLY", got)
	}
	if err := unix.Munmap(ro); err != nil {
		t.Fatalf("Munmap(unaligned view): %v", err)
	}

	private, err := unix.Mmap(int(f.Fd()), 0, 4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap(private): %v", err)
	}
	private[0] = 0x99
	buf := make([]byte, 1)
	if _, err := f.ReadAt(buf, 0); err != nil || buf[0] != 0 {
		t.Fatalf("file byte after private write = (%#x, %v), want 0", buf[0], err)
	}
	if err := unix.Munmap(private[:2048]); !errors.Is(err, unix.ENOTSUP) {
		t.Fatalf("Munmap(part of mapping) = %v, want ENOTSUP", err)
	}
	if err := unix.Munmap(private); err != nil {
		t.Fatalf("Munmap: %v", err)
	}
}

func TestGvxMadviseSemantics(t *testing.T) {
	mem, err := unix.Mmap(-1, 0, 8192, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mem)
	for _, advice := range []int{unix.MADV_HUGEPAGE, unix.MADV_NOHUGEPAGE, unix.MADV_DONTNEED, unix.MADV_DONTFORK, unix.MADV_REMOVE} {
		if err := unix.Madvise(mem, advice); !errors.Is(err, unix.ENOTSUP) {
			t.Errorf("Madvise(advice=%d) = %v, want ENOTSUP", advice, err)
		}
	}
	if err := unix.Madvise(mem, unix.MADV_POPULATE_WRITE); !errors.Is(err, unix.EINVAL) {
		t.Errorf("Madvise(MADV_POPULATE_WRITE) = %v, want EINVAL", err)
	}
	if err := unix.Madvise(mem, unix.MADV_FREE); err != nil {
		t.Errorf("Madvise(MADV_FREE) = %v, want success on private memory", err)
	}
}

func TestGvxOwnershipCallsAreUnsupported(t *testing.T) {
	f := gvxTempFile(t, 0)
	checks := map[string]error{
		"Fchmod":   unix.Fchmod(int(f.Fd()), 0o600),
		"Fchmodat": unix.Fchmodat(-1, "x", 0o600, 0),
		"Fchown":   unix.Fchown(int(f.Fd()), 0, 0),
		"Fchownat": unix.Fchownat(-1, "x", 0, 0, 0),
		"Chown":    unix.Chown("x", 0, 0),
		"Lchown":   unix.Lchown("x", 0, 0),
	}
	for name, err := range checks {
		if !errors.Is(err, unix.ENOTSUP) {
			t.Errorf("%s = %v, want ENOTSUP", name, err)
		}
	}
}

func TestGvxMincoreReportsWorkingSetResidency(t *testing.T) {
	mem, err := unix.Mmap(-1, 0, 4*4096, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mem)
	mem[0] = 1
	vec := make([]byte, 4)
	if _, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mem[0])), uintptr(len(mem)), uintptr(unsafe.Pointer(&vec[0]))); errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	if vec[0]&1 == 0 {
		t.Fatalf("vec[0] = %#x, want resident for the touched page", vec[0])
	}
	if vec[3]&1 != 0 {
		t.Fatalf("vec[3] = %#x, want non-resident for an untouched committed page", vec[3])
	}
}
