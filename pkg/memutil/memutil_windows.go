//go:build windows

package memutil

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

const (
	pageSize4K = 4096

	// allocGranularity is the Windows allocation granularity.
	// Section offsets and view base addresses are multiples of it.
	allocGranularity = 65536
)

var (
	errUnalignedSize = errors.New("memory size must be a positive multiple of 4096 bytes")

	// MapViewOfFile3 lives in kernelbase.dll on Windows 10 version 1803 and later.
	// Older hosts lack the export, and mapSection then uses MapViewOfFile.
	modKernelbase      = windows.NewLazySystemDLL("kernelbase.dll")
	procMapViewOfFile3 = modKernelbase.NewProc("MapViewOfFile3")
)

// mapProtection holds the three Win32 views of one POSIX protection request.
type mapProtection struct {
	section uint32 // Page protection for CreateFileMapping.
	view    uint32 // Page protection for MapViewOfFile3.
	access  uint32 // Desired access for the MapViewOfFile fallback.
	none    bool   // PROT_NONE: the view is mapped readable and then set to PAGE_NOACCESS.
}

// protectionFor translates mmap protection and sharing flags. Windows has no
// write-only pages, so PROT_WRITE implies read access, as it does on x86 Linux.
func protectionFor(prot uintptr, private bool) mapProtection {
	write := prot&unix.PROT_WRITE != 0
	exec := prot&unix.PROT_EXEC != 0
	var p mapProtection
	switch {
	case write && exec:
		p = mapProtection{windows.PAGE_EXECUTE_READWRITE, windows.PAGE_EXECUTE_READWRITE, windows.FILE_MAP_WRITE | windows.FILE_MAP_EXECUTE, false}
	case write:
		p = mapProtection{windows.PAGE_READWRITE, windows.PAGE_READWRITE, windows.FILE_MAP_WRITE, false}
	case exec:
		p = mapProtection{windows.PAGE_EXECUTE_READ, windows.PAGE_EXECUTE_READ, windows.FILE_MAP_READ | windows.FILE_MAP_EXECUTE, false}
	case prot&unix.PROT_READ != 0:
		p = mapProtection{windows.PAGE_READONLY, windows.PAGE_READONLY, windows.FILE_MAP_READ, false}
	default:
		p = mapProtection{windows.PAGE_READONLY, windows.PAGE_READONLY, windows.FILE_MAP_READ, true}
	}
	if private && write {
		// A private writable view is copy-on-write over the same section.
		p.access = p.access&^windows.FILE_MAP_WRITE | windows.FILE_MAP_COPY
		if exec {
			p.view = windows.PAGE_EXECUTE_WRITECOPY
		} else {
			p.view = windows.PAGE_WRITECOPY
		}
	}
	return p
}

// mapSection maps [offset, offset+size) of section into the current process.
// The offset is a multiple of the allocation granularity and the size is a multiple of the page size.
func mapSection(section windows.Handle, offset uint64, size uintptr, p mapProtection) (uintptr, error) {
	var addr uintptr
	if err := procMapViewOfFile3.Find(); err == nil {
		r1, _, callErr := procMapViewOfFile3.Call(
			uintptr(section),
			uintptr(windows.CurrentProcess()), // The pseudo-handle selects this process.
			0,                                 // BaseAddress: the system picks one.
			uintptr(offset),
			size,
			0, // AllocationType
			uintptr(p.view),
			0, // ExtendedParameters
			0, // ParameterCount
		)
		if r1 == 0 {
			return 0, fmt.Errorf("MapViewOfFile3 (%d bytes at section offset %#x): %w", size, offset, callErr)
		}
		addr = r1
	} else {
		var mapErr error
		addr, mapErr = windows.MapViewOfFile(section, p.access, uint32(offset>>32), uint32(offset), size)
		if mapErr != nil {
			return 0, fmt.Errorf("MapViewOfFile (%d bytes at section offset %#x): %w", size, offset, mapErr)
		}
	}
	if p.none {
		var old uint32
		if err := windows.VirtualProtect(addr, size, windows.PAGE_NOACCESS, &old); err != nil {
			_ = windows.UnmapViewOfFile(addr)
			return 0, fmt.Errorf("VirtualProtect(PAGE_NOACCESS): %w", err)
		}
	}
	return addr, nil
}

// CreateMemFD creates an anonymous temporary backing file on Windows and returns its handle.
// The file opens with FILE_FLAG_DELETE_ON_CLOSE, so Windows deletes it when the last handle closes.
// The caller owns the handle and closes it with windows.CloseHandle or os.NewFile.
func CreateMemFD(name string, _ int) (int, error) {
	safe := []byte(name)
	for i, c := range safe {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			safe[i] = '_'
		}
	}
	dir := os.TempDir()
	const attempts = 8
	for range attempts {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return -1, fmt.Errorf("random memfd name: %w", err)
		}
		path, err := windows.UTF16PtrFromString(filepath.Join(dir, fmt.Sprintf("gvx-memfd-%s-%x", safe, suffix)))
		if err != nil {
			return -1, fmt.Errorf("memfd path %s: %w", name, err)
		}
		// Every later open of the file must share DELETE, so the sharing mode includes it.
		handle, err := windows.CreateFile(
			path,
			windows.GENERIC_READ|windows.GENERIC_WRITE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
			nil,
			windows.CREATE_NEW,
			windows.FILE_ATTRIBUTE_TEMPORARY|windows.FILE_FLAG_DELETE_ON_CLOSE,
			0,
		)
		if err == nil {
			return int(handle), nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return -1, fmt.Errorf("create temp memfd %s: %w", name, err)
		}
	}
	return -1, fmt.Errorf("create temp memfd %s: no unused file name after %d attempts", name, attempts)
}

// MapFile maps a file or anonymous pagefile section into memory on Windows.
// It honours prot and the MAP_SHARED, MAP_PRIVATE, MAP_FILE, MAP_ANON and
// MAP_NORESERVE flags. A file offset that is not a multiple of 64KB maps from
// the previous 64KB boundary and returns the address of the requested byte.
// MAP_FIXED and PROT_NONE views on top of existing memory are not available.
func MapFile(addr, size, prot, flags, fd, offset uintptr) (uintptr, error) {
	if size == 0 {
		return 0, fmt.Errorf("MapFile: %w", windows.ERROR_INVALID_PARAMETER)
	}
	if flags&unix.MAP_FIXED != 0 {
		return 0, fmt.Errorf("MapFile at %#x: MAP_FIXED: %w", addr, windows.ERROR_NOT_SUPPORTED)
	}
	const supported = unix.MAP_SHARED | unix.MAP_PRIVATE | unix.MAP_FILE | unix.MAP_ANON | unix.MAP_NORESERVE
	if unsupported := flags &^ supported; unsupported != 0 {
		return 0, fmt.Errorf("MapFile: flags %#x: %w", unsupported, windows.ERROR_NOT_SUPPORTED)
	}
	private := flags&unix.MAP_PRIVATE != 0
	if shared := flags&unix.MAP_SHARED != 0; shared == private {
		return 0, fmt.Errorf("MapFile: exactly one of MAP_SHARED and MAP_PRIVATE is required: %w", windows.ERROR_INVALID_PARAMETER)
	}
	p := protectionFor(prot, private)

	handle := windows.InvalidHandle
	if flags&unix.MAP_ANON == 0 && fd != ^uintptr(0) {
		handle = windows.Handle(fd)
	} else if offset != 0 {
		return 0, fmt.Errorf("MapFile: anonymous mapping at offset %#x: %w", offset, windows.ERROR_INVALID_PARAMETER)
	}

	baseOffset := uint64(offset) &^ (allocGranularity - 1)
	delta := uintptr(uint64(offset) - baseOffset)
	viewSize := (delta + size + pageSize4K - 1) &^ (pageSize4K - 1)

	// Writable sections cover the whole view so that a file shorter than the
	// view grows, which MapViewOfFile needs: a view larger than the section is
	// refused, even when the view only rounds the size up to a page. Read-only
	// sections map the file as it is.
	var maxSize uint64
	if handle == windows.InvalidHandle || p.section != windows.PAGE_READONLY && p.section != windows.PAGE_EXECUTE_READ {
		maxSize = baseOffset + uint64(viewSize)
	}
	section, err := windows.CreateFileMapping(handle, nil, p.section, uint32(maxSize>>32), uint32(maxSize), nil)
	if err != nil {
		return 0, fmt.Errorf("CreateFileMapping (%d bytes): %w", size, err)
	}
	// The view keeps the section alive, so the handle closes on every path.
	defer windows.CloseHandle(section)

	base, err := mapSection(section, baseOffset, viewSize, p)
	if err != nil {
		return 0, err
	}
	start := base + delta
	registerView(nil, start, &viewRecord{base: base, length: viewSize})
	return start, nil
}

// MapSlice maps a file or anonymous section and returns a byte slice.
func MapSlice(addr, size, prot, flags, fd, offset uintptr) ([]byte, error) {
	mapped, err := MapFile(addr, size, prot, flags, fd, offset)
	if err != nil {
		return nil, err
	}
	return unsafe.Slice((*byte)(pointerFromAddr(mapped)), int(size)), nil
}

// UnmapSlice unmaps a slice returned by MapSlice. It also accepts slices that
// UnmapView accepts. Other slices must start at the base of a view.
func UnmapSlice(slice []byte) error {
	if len(slice) == 0 {
		return nil
	}
	err := UnmapView(slice)
	if !errors.Is(err, ErrNotMapped) {
		return err
	}
	if err := windows.UnmapViewOfFile(uintptr(unsafe.Pointer(unsafe.SliceData(slice)))); err != nil {
		return fmt.Errorf("UnmapViewOfFile: %w", err)
	}
	return nil
}

// AllocateAnonymousArena allocates a pagefile-backed shared memory arena on Windows
// through CreateFileMappingW and MapViewOfFile3. The size must be a positive
// multiple of 4096 bytes. The mapping covers whole 64KB allocation units.
func AllocateAnonymousArena(size int) ([]byte, error) {
	if size <= 0 || size%pageSize4K != 0 {
		return nil, fmt.Errorf("%w: got %d", errUnalignedSize, size)
	}
	allocSize := (uint64(size) + allocGranularity - 1) &^ (allocGranularity - 1)
	section, err := windows.CreateFileMapping(windows.InvalidHandle, nil, windows.PAGE_READWRITE, uint32(allocSize>>32), uint32(allocSize), nil)
	if err != nil {
		return nil, fmt.Errorf("CreateFileMapping (%d bytes): %w", allocSize, err)
	}
	addr, err := mapSection(section, 0, uintptr(allocSize), protectionFor(unix.PROT_READ|unix.PROT_WRITE, false))
	if err != nil {
		_ = windows.CloseHandle(section)
		return nil, err
	}
	registerArena(&arenaRecord{base: addr, length: uintptr(allocSize), section: uintptr(section)})
	return unsafe.Slice((*byte)(pointerFromAddr(addr)), size), nil
}

// RemapAnonymousView creates a secondary shared view over arena[offset:offset+size]
// through MapViewOfFile3 on the arena's section handle.
//
// A view starts at a 64KB boundary of the section. It also exposes the bytes
// that share the 64KB unit with the requested range. The arena can be any
// slice inside a mapping that AllocateAnonymousArena returned.
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

	// The section handle closes while the arena is unmapped. The read lock keeps
	// the handle valid until the mapping call returns.
	owner.mu.RLock()
	defer owner.mu.RUnlock()

	sectionOffset := uint64(arenaStart-owner.base) + uint64(offset)
	baseOffset := sectionOffset &^ (allocGranularity - 1)
	subOffset := uintptr(sectionOffset - baseOffset)
	remapSize := (subOffset + uintptr(size) + pageSize4K - 1) &^ (pageSize4K - 1)
	base, err := mapSection(windows.Handle(owner.section), baseOffset, remapSize, protectionFor(unix.PROT_READ|unix.PROT_WRITE, false))
	if err != nil {
		return nil, err
	}
	viewStart := base + subOffset
	if !registerView(owner, viewStart, &viewRecord{arena: owner, base: base, length: remapSize}) {
		// UnmapView released the arena while this call mapped the view.
		if err := windows.UnmapViewOfFile(base); err != nil {
			return nil, fmt.Errorf("arena unmapped during remap, and releasing the view failed: %w", err)
		}
		return nil, fmt.Errorf("%w: arena was unmapped during remap", ErrNotArena)
	}
	return unsafe.Slice((*byte)(pointerFromAddr(viewStart)), size), nil
}

// UnmapView releases a mapping from AllocateAnonymousArena, RemapAnonymousView or MapFile.
// Releasing an arena also releases every view that is still mapped over it.
// Slices from other sources return ErrNotMapped and stay mapped.
func UnmapView(view []byte) error {
	if len(view) == 0 {
		return nil
	}
	start := uintptr(unsafe.Pointer(&view[0]))
	if arena, views, ok := takeArena(start); ok {
		// Wait for remaps that already hold the section handle.
		arena.mu.Lock()
		defer arena.mu.Unlock()
		var errs []error
		for _, v := range views {
			if err := windows.UnmapViewOfFile(v.base); err != nil {
				errs = append(errs, fmt.Errorf("UnmapViewOfFile (view %#x): %w", v.base, err))
			}
		}
		if err := windows.UnmapViewOfFile(arena.base); err != nil {
			errs = append(errs, fmt.Errorf("UnmapViewOfFile (arena %#x): %w", arena.base, err))
		}
		if err := windows.CloseHandle(windows.Handle(arena.section)); err != nil {
			errs = append(errs, fmt.Errorf("CloseHandle (section): %w", err))
		}
		return errors.Join(errs...)
	}
	if rec, ok := takeView(start); ok {
		if err := windows.UnmapViewOfFile(rec.base); err != nil {
			return fmt.Errorf("UnmapViewOfFile (view %#x): %w", rec.base, err)
		}
		return nil
	}
	return fmt.Errorf("%w: %#x", ErrNotMapped, start)
}
