//go:build darwin

package fdnotifier

import (
	"unsafe"

	"z.gfire.dev/gvx/pkg/waiter"
	"z.gfire.dev/gvx/internal/xsys/unix"
)

// NonBlockingPoll polls the given FD in non-blocking fashion.
func NonBlockingPoll(fd int32, mask waiter.EventMask) waiter.EventMask {
	e := struct {
		fd      int32
		events  int16
		revents int16
	}{
		fd:     fd,
		events: int16(mask.ToLinux()),
	}
	for {
		n, _, err := unix.RawSyscall(unix.SYS_POLL, uintptr(unsafe.Pointer(&e)), 1, 0)
		if err == unix.EINTR {
			continue
		}
		if err != 0 {
			return mask
		}
		if n == 0 {
			return 0
		}
		return waiter.EventMaskFromLinux(uint32(e.revents))
	}
}
