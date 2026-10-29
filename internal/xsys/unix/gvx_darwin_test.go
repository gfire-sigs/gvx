//go:build darwin

package unix_test

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
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
	if err := unix.Fallocate(fd, 0, -1, 4096); !errors.Is(err, unix.EINVAL) {
		t.Fatalf("Fallocate(negative offset) = %v, want EINVAL", err)
	}
}

func TestGvxFallocatePunchHoleZeroesMappedRange(t *testing.T) {
	const size = 64 * 1024
	f := gvxTempFile(t, size)
	fd := int(f.Fd())
	mapping, err := unix.Mmap(fd, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	for i := range mapping {
		mapping[i] = 0xAA
	}

	const mode = unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE
	err = unix.Fallocate(fd, mode, 16384, 16384)
	if errors.Is(err, unix.ENOTSUP) {
		t.Skipf("temporary directory file system lacks F_PUNCHHOLE: %v", err)
	}
	if err != nil {
		t.Fatalf("Fallocate(PUNCH_HOLE): %v", err)
	}
	if got := gvxFileSize(t, f); got != size {
		t.Fatalf("size after punch = %d, want %d (KEEP_SIZE)", got, size)
	}
	for i, b := range mapping {
		want := byte(0xAA)
		if i >= 16384 && i < 32768 {
			want = 0
		}
		if b != want {
			t.Fatalf("mapping[%d] = %#x after punch, want %#x", i, b, want)
		}
	}

	// A range that splits a host page would discard live neighbours, so Fallocate refuses it.
	if hostPage := unix.Getpagesize(); hostPage > 4096 {
		if err := unix.Fallocate(fd, mode, 4096, 4096); !errors.Is(err, unix.ENOTSUP) {
			t.Fatalf("Fallocate(PUNCH_HOLE inside a host page) = %v, want ENOTSUP", err)
		}
	}

	// A range past the end of the file must not extend it.
	if err := unix.Fallocate(fd, mode, size, int64(unix.Getpagesize())); err != nil {
		t.Fatalf("Fallocate(PUNCH_HOLE past end): %v", err)
	}
	if got := gvxFileSize(t, f); got != size {
		t.Fatalf("size after punch past end = %d, want %d", got, size)
	}
}

func TestGvxMincoreReportsKernelResidency(t *testing.T) {
	hostPage := unix.Getpagesize()
	const linuxPage = unix.MincorePageSize
	mapping, err := unix.Mmap(-1, 0, 4*hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	// Touch only the first host page.
	mapping[0] = 1

	vec := make([]byte, len(mapping)/linuxPage)
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(len(mapping)), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	perHost := hostPage / linuxPage
	for i := 0; i < perHost; i++ {
		if vec[i]&1 == 0 {
			t.Fatalf("vec[%d] = %#x, want resident for the touched host page", i, vec[i])
		}
	}
	// The kernel reports one answer per host page, so all entries of a host page must agree.
	for first := 0; first < len(vec); first += perHost {
		for i := first + 1; i < first+perHost; i++ {
			if vec[i] != vec[first] {
				t.Fatalf("vec[%d] = %#x but vec[%d] = %#x inside one host page, want equal", i, vec[i], first, vec[first])
			}
		}
	}

	// A page-aligned start inside a host page reports the enclosing host page.
	if hostPage > linuxPage {
		sub := make([]byte, 1)
		_, _, errno = unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[linuxPage])), linuxPage, uintptr(unsafe.Pointer(&sub[0])))
		if errno != 0 || sub[0]&1 == 0 {
			t.Fatalf("mincore(sub-host-page) = (%#x, %v), want resident", sub[0], errno)
		}
	}
	// Linux rejects an address that is not page-aligned.
	_, _, errno = unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[1])), linuxPage, uintptr(unsafe.Pointer(&vec[0])))
	if errno != unix.EINVAL {
		t.Fatalf("mincore(unaligned) = %v, want EINVAL", errno)
	}
}

func TestGvxMincoreDoesNotReportUnmappedRangeResident(t *testing.T) {
	hostPage := unix.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	addr := uintptr(unsafe.Pointer(&mapping[0]))
	if err := unix.Munmap(mapping); err != nil {
		t.Fatalf("Munmap: %v", err)
	}
	vec := make([]byte, max(hostPage/unix.MincorePageSize, 1))
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, addr, uintptr(hostPage), uintptr(unsafe.Pointer(&vec[0])))
	// Darwin reports an unmapped range as non-resident, while Linux fails with
	// ENOMEM. Either answer is honest. Reporting residency would be wrong.
	if errno != 0 && errno != unix.ENOMEM {
		t.Fatalf("mincore(unmapped) = %v, want success or ENOMEM", errno)
	}
	if errno == 0 {
		for i, b := range vec {
			if b&1 != 0 {
				t.Fatalf("vec[%d] = %#x for an unmapped page, want non-resident", i, b)
			}
		}
	}
}

// A caller sizes the result vector with one byte per MincorePageSize page. An
// entry written past that length corrupts the heap object behind the vector.
func TestGvxMincoreWritesExactlyOneEntryPerPage(t *testing.T) {
	hostPage := unix.Getpagesize()
	const pages = 8
	size := pages * max(hostPage, unix.MincorePageSize)
	mapping, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	for i := 0; i < len(mapping); i += hostPage {
		mapping[i] = 1
	}

	entries := size / unix.MincorePageSize
	const guard = 4096
	const poison = 0xEE
	vec := make([]byte, entries+guard)
	for i := range vec {
		vec[i] = poison
	}
	_, _, errno := unix.Syscall(unix.SYS_MINCORE, uintptr(unsafe.Pointer(&mapping[0])), uintptr(size), uintptr(unsafe.Pointer(&vec[0])))
	if errno != 0 {
		t.Fatalf("mincore: %v", errno)
	}
	for i := range entries {
		if vec[i]&1 == 0 {
			t.Errorf("vec[%d] = %#x for a touched page, want resident", i, vec[i])
		}
	}
	for i := entries; i < len(vec); i++ {
		if vec[i] != poison {
			t.Fatalf("vec[%d] = %#x beyond the %d entries of the caller vector, want the untouched %#x", i, vec[i], entries, poison)
		}
	}
}

func TestGvxMadviseRejectsLinuxOnlyAdvice(t *testing.T) {
	hostPage := unix.Getpagesize()
	mapping, err := unix.Mmap(-1, 0, hostPage, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer unix.Munmap(mapping)
	addr := uintptr(unsafe.Pointer(&mapping[0]))
	for _, advice := range []int{unix.MADV_HUGEPAGE, unix.MADV_NOHUGEPAGE, unix.MADV_DONTFORK, unix.MADV_REMOVE} {
		if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(advice)); errno != unix.ENOTSUP {
			t.Errorf("madvise(advice=%d) = %v, want ENOTSUP", advice, errno)
		}
	}
	for _, advice := range []int{unix.MADV_POPULATE_READ, unix.MADV_POPULATE_WRITE} {
		if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(advice)); errno != unix.EINVAL {
			t.Errorf("madvise(advice=%d) = %v, want EINVAL", advice, errno)
		}
	}
	if _, _, errno := unix.Syscall(unix.SYS_MADVISE, addr, uintptr(hostPage), uintptr(unix.MADV_FREE)); errno != 0 {
		t.Errorf("madvise(MADV_FREE) = %v, want success", errno)
	}
}
