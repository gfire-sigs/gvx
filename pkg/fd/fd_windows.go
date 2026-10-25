//go:build windows

package fd

import (
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var errClosedHostHandle = errors.New("host handle is closed")

// HostHandle wraps a Windows syscall.Handle with explicit single-owner Close and Release semantics.
type HostHandle struct {
	raw    uintptr
	closed atomic.Bool
}

// NewHostHandle wraps an open Windows handle.
func NewHostHandle(handle uintptr) (*HostHandle, error) {
	if handle == 0 || windows.Handle(handle) == windows.InvalidHandle {
		return nil, errClosedHostHandle
	}
	return &HostHandle{raw: handle}, nil
}

// OpenHostPath opens a host path on Windows with CreateFileW and returns an owned HostHandle.
func OpenHostPath(path string, flags int, _ uint32) (*HostHandle, error) {
	utf16Path, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("utf16 path %s: %w", path, err)
	}
	access := uint32(windows.GENERIC_READ)
	if flags&(syscall.O_WRONLY|syscall.O_RDWR) != 0 {
		access |= windows.GENERIC_WRITE
	}
	if flags&syscall.O_APPEND != 0 {
		// ReadAt and WriteAt take explicit offsets, which O_APPEND cannot honour.
		return nil, fmt.Errorf("open host path %s: O_APPEND: %w", path, windows.ERROR_NOT_SUPPORTED)
	}
	if flags&syscall.O_TRUNC != 0 {
		access |= windows.GENERIC_WRITE
	}
	var disposition uint32
	switch {
	case flags&(syscall.O_CREAT|syscall.O_EXCL) == syscall.O_CREAT|syscall.O_EXCL:
		disposition = windows.CREATE_NEW
	case flags&(syscall.O_CREAT|syscall.O_TRUNC) == syscall.O_CREAT|syscall.O_TRUNC:
		disposition = windows.CREATE_ALWAYS
	case flags&syscall.O_CREAT != 0:
		disposition = windows.OPEN_ALWAYS
	case flags&syscall.O_TRUNC != 0:
		disposition = windows.TRUNCATE_EXISTING
	default:
		disposition = windows.OPEN_EXISTING
	}
	handle, err := windows.CreateFile(
		utf16Path,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("CreateFile %s: %w", path, err)
	}
	return NewHostHandle(uintptr(handle))
}

// RawHandle returns the underlying Windows handle as uintptr.
func (h *HostHandle) RawHandle() (uintptr, error) {
	if h == nil || h.closed.Load() {
		return 0, errClosedHostHandle
	}
	return atomic.LoadUintptr(&h.raw), nil
}

// ReadAt reads from the handle at off using an Overlapped structure.
// Like pread(2), it returns a short count and a nil error at end of file.
func (h *HostHandle) ReadAt(p []byte, off int64) (int, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return 0, err
	}
	var overlapped windows.Overlapped
	overlapped.Offset = uint32(uint64(off) & 0xffffffff)
	overlapped.OffsetHigh = uint32(uint64(off) >> 32)
	var done uint32
	if err := windows.ReadFile(windows.Handle(raw), p, &done, &overlapped); err != nil {
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return int(done), nil
		}
		return int(done), fmt.Errorf("ReadFile at %d: %w", off, err)
	}
	return int(done), nil
}

// WriteAt writes to the handle at off using an Overlapped structure.
func (h *HostHandle) WriteAt(p []byte, off int64) (int, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return 0, err
	}
	var overlapped windows.Overlapped
	overlapped.Offset = uint32(uint64(off) & 0xffffffff)
	overlapped.OffsetHigh = uint32(uint64(off) >> 32)
	var done uint32
	if err := windows.WriteFile(windows.Handle(raw), p, &done, &overlapped); err != nil {
		return int(done), fmt.Errorf("WriteFile at %d: %w", off, err)
	}
	return int(done), nil
}

// Release transfers ownership of the underlying Windows handle to the caller without closing it.
func (h *HostHandle) Release() (uintptr, error) {
	if h == nil || h.closed.Swap(true) {
		return 0, errClosedHostHandle
	}
	raw := atomic.SwapUintptr(&h.raw, uintptr(windows.InvalidHandle))
	return raw, nil
}

// Dup duplicates the underlying Windows handle and returns a new owned HostHandle.
func (h *HostHandle) Dup() (*HostHandle, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return nil, err
	}
	proc := windows.CurrentProcess()
	var dup windows.Handle
	if err := windows.DuplicateHandle(proc, windows.Handle(raw), proc, &dup, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, fmt.Errorf("DuplicateHandle: %w", err)
	}
	return NewHostHandle(uintptr(dup))
}

// Close closes the underlying Windows handle idempotently.
func (h *HostHandle) Close() error {
	if h == nil || h.closed.Swap(true) {
		return nil
	}
	raw := atomic.SwapUintptr(&h.raw, uintptr(windows.InvalidHandle))
	if raw == 0 || windows.Handle(raw) == windows.InvalidHandle {
		return nil
	}
	if err := windows.CloseHandle(windows.Handle(raw)); err != nil {
		return fmt.Errorf("CloseHandle: %w", err)
	}
	return nil
}

// FileRenameInformationEx is the FileRenameInformationEx class of NtSetInformationFile.
const FileRenameInformationEx = 65

// NameInfoHeader is the common header of FILE_RENAME_INFORMATION_EX and FILE_LINK_INFORMATION.
type NameInfoHeader struct {
	Flags          uint32
	RootDirectory  windows.Handle
	FileNameLength uint32
	FileName       [1]uint16
}

// NewNameInfo builds an 8-byte-aligned FILE_RENAME_INFORMATION_EX or FILE_LINK_INFORMATION buffer.
func NewNameInfo(flags uint32, root windows.Handle, name string) (buf []uint64, size uint32, err error) {
	units, err := windows.UTF16FromString(name)
	if err != nil {
		return nil, 0, err
	}
	units = units[:len(units)-1]
	const nameOffset = unsafe.Offsetof(NameInfoHeader{}.FileName)
	nameBytes := len(units) * 2
	total := max(int(unsafe.Sizeof(NameInfoHeader{})), int(nameOffset)+nameBytes)
	words := (total + 7) / 8
	buf = make([]uint64, words)
	header := (*NameInfoHeader)(unsafe.Pointer(&buf[0]))
	header.Flags = flags
	header.RootDirectory = root
	header.FileNameLength = uint32(nameBytes)
	if len(units) > 0 {
		dst := unsafe.Slice((*uint16)(unsafe.Add(unsafe.Pointer(&buf[0]), nameOffset)), len(units))
		copy(dst, units)
	}
	return buf, uint32(words * 8), nil
}

// SetFileTargetName invokes NtSetInformationFile on src with a name-information buffer.
func SetFileTargetName(src, root windows.Handle, name string, flags, infoClass uint32) error {
	buf, size, err := NewNameInfo(flags, root, name)
	if err != nil {
		return err
	}
	var iosb windows.IO_STATUS_BLOCK
	return windows.NtSetInformationFile(src, &iosb, (*byte)(unsafe.Pointer(&buf[0])), size, infoClass)
}
