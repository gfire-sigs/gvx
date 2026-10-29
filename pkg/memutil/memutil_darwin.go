//go:build darwin

package memutil

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

const pageSize4K = 4096

var errUnalignedSize = errors.New("memory size must be a positive multiple of 4096 bytes")

//go:linkname darwinSyscall6 syscall.syscall6
func darwinSyscall6(fn, a1, a2, a3, a4, a5, a6 uintptr) (r1, r2 uintptr, err syscall.Errno)

func taskSelfTrapTrampoline()
func addrOfTaskSelfTrap() uintptr

func machVMRemapWrapperTrampoline()
func addrOfMachVMRemapWrapper() uintptr

//go:cgo_import_dynamic libc_task_self_trap task_self_trap "/usr/lib/libSystem.B.dylib"
//go:cgo_import_dynamic libc_mach_vm_remap mach_vm_remap "/usr/lib/libSystem.B.dylib"

// hostPageSize returns the macOS VM page size, which is 16KB on Apple silicon.
func hostPageSize() int {
	return max(unix.Getpagesize(), pageSize4K)
}

// CreateMemFD creates an unlinked anonymous temporary file on macOS and returns its file descriptor.
// The caller owns the descriptor and closes it with unix.Close.
func CreateMemFD(name string, _ int) (int, error) {
	f, err := os.CreateTemp("", "gvx-memfd-"+name+"-*")
	if err != nil {
		return -1, fmt.Errorf("create temp memfd %s: %w", name, err)
	}
	// Dup through F_DUPFD_CLOEXEC so no window exists in which a concurrent
	// fork and exec inherits the descriptor. The dup also drops the os.File
	// finalizer, which would close the descriptor behind the caller's back.
	dupFD, dupErr := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	rmErr := os.Remove(f.Name())
	closeErr := f.Close()
	if dupErr != nil {
		return -1, fmt.Errorf("dup memfd %s: %w", name, dupErr)
	}
	if err := errors.Join(rmErr, closeErr); err != nil {
		_ = unix.Close(dupFD)
		return -1, fmt.Errorf("finish memfd %s: %w", name, err)
	}
	return dupFD, nil
}

// AllocateAnonymousArena allocates a shared anonymous mapping on macOS.
// The size must be a positive multiple of 4096 bytes. The mapping covers whole host pages.
func AllocateAnonymousArena(size int) ([]byte, error) {
	if size <= 0 || size%pageSize4K != 0 {
		return nil, fmt.Errorf("%w: got %d", errUnalignedSize, size)
	}
	hostPage := hostPageSize()
	allocSize := (size + hostPage - 1) &^ (hostPage - 1)
	raw, err := unix.Mmap(-1, 0, allocSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap anonymous arena (%d bytes): %w", allocSize, err)
	}
	registerArena(&arenaRecord{
		base:   uintptr(unsafe.Pointer(&raw[0])),
		length: uintptr(allocSize),
	})
	return raw[:size], nil
}

// RemapAnonymousView creates a secondary virtual memory alias over arena[offset:offset+size]
// using mach_vm_remap on the current Mach task.
//
// The alias covers whole host pages, so it also exposes the bytes that share
// a 16KB page with the requested range. The arena can be any slice inside a
// mapping that AllocateAnonymousArena returned.
//
//go:nocheckptr
func RemapAnonymousView(arena []byte, offset, size int) ([]byte, error) {
	if offset < 0 || size <= 0 || offset%pageSize4K != 0 || size%pageSize4K != 0 || offset+size > len(arena) {
		return nil, fmt.Errorf("%w: offset=%d size=%d len=%d", errUnalignedSize, offset, size, len(arena))
	}
	if len(arena) == 0 {
		return nil, fmt.Errorf("%w: empty slice", ErrNotArena)
	}
	arenaStart := uintptr(unsafe.Pointer(&arena[0]))
	owner, ok := findArena(arenaStart, uintptr(offset+size))
	if !ok {
		return nil, fmt.Errorf("%w: %#x", ErrNotArena, arenaStart)
	}

	hostPage := uintptr(hostPageSize())
	start := arenaStart + uintptr(offset)
	srcAddr := start &^ (hostPage - 1)
	subPageOffset := start - srcAddr
	remapSize := (subPageOffset + uintptr(size) + hostPage - 1) &^ (hostPage - 1)

	taskPort, _, _ := darwinSyscall6(addrOfTaskSelfTrap(), 0, 0, 0, 0, 0, 0)
	if taskPort == 0 {
		return nil, errors.New("task_self_trap returned MACH_PORT_NULL")
	}
	var targetAddr uint64
	var curProt int32
	var maxProt int32
	rc, _, _ := darwinSyscall6(
		addrOfMachVMRemapWrapper(),
		taskPort,
		uintptr(unsafe.Pointer(&targetAddr)),
		remapSize,
		srcAddr,
		uintptr(unsafe.Pointer(&curProt)),
		uintptr(unsafe.Pointer(&maxProt)),
	)
	if int32(rc) != 0 || targetAddr == 0 {
		return nil, fmt.Errorf("mach_vm_remap (src=%#x size=%d): kern_return_t=%d", srcAddr, remapSize, int32(rc))
	}

	base := uintptr(targetAddr)
	viewStart := base + subPageOffset
	rec := &viewRecord{arena: owner, base: base, length: remapSize}
	if !registerView(owner, viewStart, rec) {
		// UnmapView released the arena while this call mapped the alias.
		if err := munmap(base, remapSize); err != nil {
			return nil, fmt.Errorf("arena unmapped during remap, and releasing the alias failed: %w", err)
		}
		return nil, fmt.Errorf("%w: arena was unmapped during remap", ErrNotArena)
	}
	return unsafe.Slice((*byte)(pointerFromAddr(viewStart)), size), nil
}

// UnmapView releases a mapping from AllocateAnonymousArena or RemapAnonymousView.
// Releasing an arena also releases every alias that is still mapped over it.
// Slices from other sources return ErrNotMapped and stay mapped.
func UnmapView(view []byte) error {
	if len(view) == 0 {
		return nil
	}
	start := uintptr(unsafe.Pointer(&view[0]))
	if arena, aliases, ok := takeArena(start); ok {
		var errs []error
		for _, alias := range aliases {
			if err := munmap(alias.base, alias.length); err != nil {
				errs = append(errs, fmt.Errorf("munmap alias (%d bytes): %w", alias.length, err))
			}
		}
		if err := munmap(arena.base, arena.length); err != nil {
			errs = append(errs, fmt.Errorf("munmap arena (%d bytes): %w", arena.length, err))
		}
		return errors.Join(errs...)
	}
	if rec, ok := takeView(start); ok {
		if err := munmap(rec.base, rec.length); err != nil {
			return fmt.Errorf("munmap remapped view (%d bytes): %w", rec.length, err)
		}
		return nil
	}
	return fmt.Errorf("%w: %#x", ErrNotMapped, start)
}

func munmap(addr, length uintptr) error {
	if _, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, addr, length, 0); errno != 0 {
		return errno
	}
	return nil
}
