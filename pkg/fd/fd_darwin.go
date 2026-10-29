//go:build darwin

package fd

import (
	"errors"
	"fmt"
	"sync/atomic"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

var errClosedHostHandle = errors.New("host handle is closed")

// HostHandle wraps a macOS file descriptor with explicit single-owner Close and Release semantics.
type HostHandle struct {
	raw    int64
	closed atomic.Bool
}

// NewHostHandle wraps an open macOS file descriptor.
func NewHostHandle(fd int) (*HostHandle, error) {
	if fd < 0 {
		return nil, fmt.Errorf("%w: fd=%d", errClosedHostHandle, fd)
	}
	return &HostHandle{raw: int64(fd)}, nil
}

// OpenHostPath opens a host path on macOS with O_CLOEXEC and returns an owned HostHandle.
func OpenHostPath(path string, flags int, mode uint32) (*HostHandle, error) {
	fd, err := unix.Open(path, flags|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, fmt.Errorf("open host path %s: %w", path, err)
	}
	return NewHostHandle(fd)
}

// RawHandle returns the underlying file descriptor as uintptr.
func (h *HostHandle) RawHandle() (uintptr, error) {
	if h == nil || h.closed.Load() {
		return 0, errClosedHostHandle
	}
	return uintptr(atomic.LoadInt64(&h.raw)), nil
}

// ReadAt reads from the descriptor at offset without mutating file seek state.
func (h *HostHandle) ReadAt(p []byte, off int64) (int, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return 0, err
	}
	return unix.Pread(int(raw), p, off)
}

// WriteAt writes to the descriptor at offset without mutating file seek state.
func (h *HostHandle) WriteAt(p []byte, off int64) (int, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return 0, err
	}
	return unix.Pwrite(int(raw), p, off)
}

// Release transfers ownership of the underlying descriptor to the caller without closing it.
func (h *HostHandle) Release() (uintptr, error) {
	if h == nil || h.closed.Swap(true) {
		return 0, errClosedHostHandle
	}
	raw := atomic.SwapInt64(&h.raw, -1)
	return uintptr(raw), nil
}

// Dup duplicates the underlying macOS file descriptor with F_DUPFD_CLOEXEC and returns a new owned HostHandle.
func (h *HostHandle) Dup() (*HostHandle, error) {
	raw, err := h.RawHandle()
	if err != nil {
		return nil, err
	}
	// F_DUPFD_CLOEXEC sets close-on-exec atomically, so a concurrent fork and
	// exec never inherits the new descriptor.
	dupFD, err := unix.FcntlInt(raw, unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("fcntl(F_DUPFD_CLOEXEC) fd %d: %w", raw, err)
	}
	return NewHostHandle(dupFD)
}

// Close closes the underlying macOS file descriptor idempotently.
func (h *HostHandle) Close() error {
	if h == nil || h.closed.Swap(true) {
		return nil
	}
	raw := atomic.SwapInt64(&h.raw, -1)
	if raw < 0 {
		return nil
	}
	if err := unix.Close(int(raw)); err != nil {
		return fmt.Errorf("close fd %d: %w", raw, err)
	}
	return nil
}
