//go:build windows

package unix

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file maps the Linux memory and file-space calls that Sentry code issues
// through Syscall6 onto Win32. A call that Win32 cannot express returns ENOTSUP
// or ENOSYS. It never reports success without an effect.

const (
	winPageSize    = 4096
	winAllocGrain  = 65536
	winMemDecommit = 0x4000
)

var (
	modKernel32Mem             = windows.NewLazySystemDLL("kernel32.dll")
	procDiscardVirtualMemoryUx = modKernel32Mem.NewProc("DiscardVirtualMemory")
	procQueryWorkingSetExUx    = modKernel32Mem.NewProc("K32QueryWorkingSetEx")
	procGetHandleInformationUx = modKernel32Mem.NewProc("GetHandleInformation")
)

// winErrno maps a Win32 error to the closest Linux errno. Callers compare
// the result with ENOMEM, EINVAL and similar values, as they do on Linux.
// Errors without a close match keep their Win32 value.
func winErrno(err error) Errno {
	if err == nil {
		return 0
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return EINVAL
	}
	switch errno {
	case windows.ERROR_NOT_ENOUGH_MEMORY, windows.ERROR_OUTOFMEMORY, windows.ERROR_COMMITMENT_LIMIT, windows.ERROR_WORKING_SET_QUOTA:
		return ENOMEM
	case windows.ERROR_INVALID_PARAMETER, windows.ERROR_INVALID_ADDRESS:
		return EINVAL
	case windows.ERROR_ACCESS_DENIED:
		return EACCES
	case windows.ERROR_INVALID_HANDLE:
		return EBADF
	case windows.ERROR_FILE_NOT_FOUND:
		return ENOENT
	case windows.ERROR_DISK_FULL:
		return ENOSPC
	case windows.ERROR_USER_MAPPED_FILE:
		return EBUSY
	case windows.ERROR_NOT_SUPPORTED, windows.ERROR_CALL_NOT_IMPLEMENTED:
		return ENOTSUP
	}
	return errno
}

// winError is winErrno for a function that returns an error. A nil error stays
// nil, where a zero Errno in an error would report a failure.
func winError(err error) error {
	if errno := winErrno(err); errno != 0 {
		return errno
	}
	return nil
}

// winMapping describes one mapping that mmap created.
type winMapping struct {
	base    uintptr // Address that UnmapViewOfFile or VirtualFree needs.
	length  uintptr // Page-rounded length that the caller requested.
	view    bool    // File view when true, VirtualAlloc region when false.
	private bool    // Copy-on-write view.
}

// winMappings indexes mappings by the address that mmap returned. A file view
// starts below that address when the file offset is not a multiple of 64KB.
var winMappings struct {
	mu     sync.Mutex
	byAddr map[uintptr]winMapping
}

func winRecordMapping(addr uintptr, m winMapping) {
	winMappings.mu.Lock()
	defer winMappings.mu.Unlock()
	if winMappings.byAddr == nil {
		winMappings.byAddr = make(map[uintptr]winMapping)
	}
	winMappings.byAddr[addr] = m
}

// winMappingAt returns the mapping that contains addr.
func winMappingAt(addr uintptr) (start uintptr, m winMapping, ok bool) {
	winMappings.mu.Lock()
	defer winMappings.mu.Unlock()
	for start, m := range winMappings.byAddr {
		if addr >= start && addr < start+m.length {
			return start, m, true
		}
	}
	return 0, winMapping{}, false
}

func winRoundUp(v, unit uintptr) uintptr { return (v + unit - 1) &^ (unit - 1) }

// winPageProtect returns the PAGE_* value for POSIX protection bits.
// Windows has no write-only pages, so PROT_WRITE implies read access.
// A copy-on-write view needs the WRITECOPY variants for writable pages.
func winPageProtect(prot uintptr, copyOnWrite bool) uint32 {
	write := prot&PROT_WRITE != 0
	exec := prot&PROT_EXEC != 0
	switch {
	case write && exec && copyOnWrite:
		return windows.PAGE_EXECUTE_WRITECOPY
	case write && exec:
		return windows.PAGE_EXECUTE_READWRITE
	case write && copyOnWrite:
		return windows.PAGE_WRITECOPY
	case write:
		return windows.PAGE_READWRITE
	case exec && prot&PROT_READ != 0:
		return windows.PAGE_EXECUTE_READ
	case exec:
		return windows.PAGE_EXECUTE
	case prot&PROT_READ != 0:
		return windows.PAGE_READONLY
	}
	return windows.PAGE_NOACCESS
}

// winMmap implements mmap(2) for anonymous memory and for file views.
func winMmap(addr, length, prot, flags, fd, offset uintptr) (uintptr, Errno) {
	if length == 0 {
		return 0, EINVAL
	}
	const advisory = MAP_NORESERVE | MAP_POPULATE | MAP_STACK
	if flags&^(MAP_SHARED|MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS|MAP_FILE|advisory) != 0 {
		return 0, ENOTSUP
	}
	private := flags&MAP_PRIVATE != 0
	if (flags&MAP_SHARED != 0) == private {
		return 0, EINVAL
	}
	length = winRoundUp(length, winPageSize)

	if flags&MAP_ANONYMOUS != 0 || int64(fd) < 0 {
		return winMmapAnonymous(addr, length, prot, flags)
	}
	if flags&MAP_FIXED != 0 {
		// Windows cannot replace an existing mapping with a file view.
		return 0, ENOTSUP
	}
	return winMmapFile(length, prot, private, windows.Handle(fd), uint64(offset))
}

func winMmapAnonymous(addr, length, prot, flags uintptr) (uintptr, Errno) {
	protect := winPageProtect(prot, false)
	const allocType = windows.MEM_RESERVE | windows.MEM_COMMIT
	got, err := windows.VirtualAlloc(addr, length, allocType, protect)
	if err != nil && addr != 0 && flags&MAP_FIXED == 0 {
		// Without MAP_FIXED the address is only a hint.
		got, err = windows.VirtualAlloc(0, length, allocType, protect)
	}
	if err != nil {
		return 0, winErrno(err)
	}
	winRecordMapping(got, winMapping{base: got, length: length})
	return got, 0
}

func winMmapFile(length, prot uintptr, private bool, file windows.Handle, offset uint64) (uintptr, Errno) {
	write := prot&PROT_WRITE != 0
	exec := prot&PROT_EXEC != 0

	var sectionProtect, access uint32
	var maxSize uint64 // Zero maps the file as it is.
	switch {
	case write && private && exec:
		sectionProtect, access = windows.PAGE_EXECUTE_WRITECOPY, windows.FILE_MAP_COPY|windows.FILE_MAP_EXECUTE
	case write && private:
		sectionProtect, access = windows.PAGE_WRITECOPY, windows.FILE_MAP_COPY
	case write && exec:
		sectionProtect, access = windows.PAGE_EXECUTE_READWRITE, windows.FILE_MAP_WRITE|windows.FILE_MAP_EXECUTE
		maxSize = offset + uint64(length)
	case write:
		// A shared writable view grows the file to cover the view, as Windows requires.
		sectionProtect, access = windows.PAGE_READWRITE, windows.FILE_MAP_WRITE
		maxSize = offset + uint64(length)
	case exec:
		sectionProtect, access = windows.PAGE_EXECUTE_READ, windows.FILE_MAP_READ|windows.FILE_MAP_EXECUTE
	default:
		sectionProtect, access = windows.PAGE_READONLY, windows.FILE_MAP_READ
	}
	section, err := windows.CreateFileMapping(file, nil, sectionProtect, uint32(maxSize>>32), uint32(maxSize), nil)
	if err != nil {
		return 0, winErrno(err)
	}
	// The view keeps the section alive, so the handle closes on every path.
	defer windows.CloseHandle(section)

	// View offsets are multiples of the allocation granularity. A smaller offset
	// maps from the previous boundary, and the caller gets the requested byte.
	baseOffset := offset &^ (winAllocGrain - 1)
	delta := uintptr(offset - baseOffset)
	viewLength := winRoundUp(delta+length, winPageSize)
	base, err := windows.MapViewOfFile(section, access, uint32(baseOffset>>32), uint32(baseOffset), viewLength)
	if err != nil {
		return 0, winErrno(err)
	}
	if prot&(PROT_READ|PROT_WRITE|PROT_EXEC) == 0 {
		var old uint32
		if err := windows.VirtualProtect(base, viewLength, windows.PAGE_NOACCESS, &old); err != nil {
			_ = windows.UnmapViewOfFile(base)
			return 0, winErrno(err)
		}
	}
	start := base + delta
	winRecordMapping(start, winMapping{base: base, length: length, view: true, private: private && write})
	return start, 0
}

// winMunmap implements munmap(2). Windows releases a whole allocation or view
// at once, so a range that covers part of a mapping returns ENOTSUP.
func winMunmap(addr, length uintptr) Errno {
	winMappings.mu.Lock()
	m, ok := winMappings.byAddr[addr]
	if ok && winRoundUp(length, winPageSize) == m.length {
		delete(winMappings.byAddr, addr)
	}
	winMappings.mu.Unlock()
	if !ok {
		return winMunmapUnknown(addr)
	}
	if winRoundUp(length, winPageSize) != m.length {
		return ENOTSUP
	}
	if m.view {
		return winErrno(windows.UnmapViewOfFile(m.base))
	}
	return winErrno(windows.VirtualFree(m.base, 0, windows.MEM_RELEASE))
}

// winMunmapUnknown releases a mapping that another package created.
// UnmapViewOfFile needs the view base. VirtualFree needs the allocation base.
func winMunmapUnknown(addr uintptr) Errno {
	if err := windows.UnmapViewOfFile(addr); err == nil {
		return 0
	}
	return winErrno(windows.VirtualFree(addr, 0, windows.MEM_RELEASE))
}

// winMprotect implements mprotect(2) with VirtualProtect.
func winMprotect(addr, length, prot uintptr) Errno {
	if addr&(winPageSize-1) != 0 {
		return EINVAL
	}
	if length == 0 {
		return 0
	}
	_, m, _ := winMappingAt(addr)
	var old uint32
	err := windows.VirtualProtect(addr, winRoundUp(length, winPageSize), winPageProtect(prot, m.private), &old)
	return winErrno(err)
}

// winMlock implements mlock(2) with VirtualLock and munlock(2) with VirtualUnlock.
func winMlock(addr, length uintptr, lock bool) Errno {
	if length == 0 {
		return 0
	}
	start := addr &^ (winPageSize - 1)
	span := winRoundUp(addr+length-start, winPageSize)
	if lock {
		return winErrno(windows.VirtualLock(start, span))
	}
	return winErrno(windows.VirtualUnlock(start, span))
}

// winMadvise implements the madvise(2) advice that has a Win32 counterpart.
// MADV_FREE maps to DiscardVirtualMemory, which leaves the contents undefined
// exactly as MADV_FREE does. MADV_DONTNEED guarantees zero-filled pages, which
// no Win32 call gives for section views, so it returns ENOTSUP.
// The access-pattern hints change no behaviour on Linux either, so they succeed.
func winMadvise(addr, length uintptr, advice int) Errno {
	switch advice {
	case MADV_NORMAL, MADV_RANDOM, MADV_SEQUENTIAL, MADV_WILLNEED:
		return 0
	case MADV_POPULATE_READ, MADV_POPULATE_WRITE:
		// Callers read EINVAL as "prefaulting is unavailable".
		return EINVAL
	case MADV_FREE:
		if addr&(winPageSize-1) != 0 {
			return EINVAL
		}
		if length == 0 {
			return 0
		}
		// DiscardVirtualMemory returns a Win32 error code, not a BOOL.
		code, _, _ := procDiscardVirtualMemoryUx.Call(addr, winRoundUp(length, winPageSize))
		if code != 0 {
			return winErrno(syscall.Errno(code))
		}
		return 0
	}
	return ENOTSUP
}

// winMincore implements mincore(2) with QueryWorkingSetEx. A page counts as
// resident when it is valid in the process working set. A page that Windows trimmed
// from the working set but still holds in memory reports as not resident.
func winMincore(addr, length, vecAddr uintptr) Errno {
	if addr&(winPageSize-1) != 0 {
		return EINVAL
	}
	if length == 0 {
		return 0
	}
	if err := procQueryWorkingSetExUx.Find(); err != nil {
		return ENOSYS
	}
	pages := int(winRoundUp(length, winPageSize) / winPageSize)
	vec := unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&vecAddr))), pages)

	// PSAPI_WORKING_SET_EX_INFORMATION: the address, then the attribute word.
	// Bit 0 of the attribute word is Valid.
	type workingSetExInfo struct {
		virtualAddress    uintptr
		virtualAttributes uintptr
	}
	const batch = 4096
	infos := make([]workingSetExInfo, min(pages, batch))
	process := uintptr(windows.CurrentProcess())
	for done := 0; done < pages; {
		n := min(pages-done, batch)
		for i := 0; i < n; i++ {
			infos[i] = workingSetExInfo{virtualAddress: addr + uintptr(done+i)*winPageSize}
		}
		r1, _, callErr := procQueryWorkingSetExUx.Call(process, uintptr(unsafe.Pointer(&infos[0])), uintptr(n)*unsafe.Sizeof(infos[0]))
		if r1 == 0 {
			return winErrno(callErr)
		}
		for i := 0; i < n; i++ {
			vec[done+i] = byte(infos[i].virtualAttributes & 1)
		}
		done += n
	}
	return 0
}

// Mmap maps a file or anonymous memory, as mmap(2) does.
func Mmap(fd int, offset int64, length int, prot int, flags int) ([]byte, error) {
	if length <= 0 {
		return nil, EINVAL
	}
	addr, errno := winMmap(0, uintptr(length), uintptr(prot), uintptr(flags), uintptr(fd), uintptr(offset))
	if errno != 0 {
		return nil, errno
	}
	return unsafe.Slice((*byte)(*(*unsafe.Pointer)(unsafe.Pointer(&addr))), length), nil
}

// Munmap releases a mapping from Mmap, as munmap(2) does.
func Munmap(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if errno := winMunmap(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b))); errno != 0 {
		return errno
	}
	return nil
}

// Madvise applies advice to b, as madvise(2) does.
func Madvise(b []byte, advice int) error {
	if len(b) == 0 {
		return nil
	}
	if errno := winMadvise(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), advice); errno != 0 {
		return errno
	}
	return nil
}

// Mprotect changes the protection of b, as mprotect(2) does.
func Mprotect(b []byte, prot int) error {
	if len(b) == 0 {
		return nil
	}
	if errno := winMprotect(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), uintptr(prot)); errno != 0 {
		return errno
	}
	return nil
}

// Fallocate extends a file, as far as Windows allows.
// Mode 0 grows the file to off+length and never shrinks it.
// FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE returns ENOTSUP, and the caller
// zeroes the range itself. A hole makes the file sparse, and the first write to
// each hole of a sparse file waits for NTFS to allocate a cluster. A guest that
// wrote to a mapped sparse memory file ran 10 to 20 times slower.
func Fallocate(fd int, mode uint32, off int64, length int64) error {
	if off < 0 || length <= 0 {
		return EINVAL
	}
	var st Stat_t
	if err := Fstat(fd, &st); err != nil {
		return winErrno(err)
	}
	handle := windows.Handle(uintptr(fd))
	switch mode {
	case 0:
		if target := off + length; target > st.Size {
			return winError(windows.Ftruncate(handle, target))
		}
		return nil
	}
	return ENOTSUP
}
