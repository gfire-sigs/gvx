//go:build darwin

package fdnotifier

import (
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/waiter"
)

// The poll(2) event bits of macOS. They differ from the Linux bits that the
// waiter package uses: POLLWRNORM is POLLOUT, and POLLWRBAND is 0x100. The
// system has no POLLRDHUP.
const (
	darwinPollIn     = 0x1
	darwinPollPri    = 0x2
	darwinPollOut    = 0x4
	darwinPollErr    = 0x8
	darwinPollHUp    = 0x10
	darwinPollRdNorm = 0x40
)

// toDarwinPoll translates the events that a caller asks for into macOS poll(2)
// bits. EventRdHUp has no macOS bit, so it is not requested.
func toDarwinPoll(mask waiter.EventMask) int16 {
	var ev int16
	if mask&waiter.EventIn != 0 {
		ev |= darwinPollIn
	}
	if mask&waiter.EventPri != 0 {
		ev |= darwinPollPri
	}
	if mask&(waiter.EventOut|waiter.EventWrNorm) != 0 {
		ev |= darwinPollOut
	}
	if mask&waiter.EventRdNorm != 0 {
		ev |= darwinPollRdNorm
	}
	return ev
}

// fromDarwinPoll translates macOS revents into waiter events. A readiness bit
// reports every requested event that shares the bit, as Linux does for
// POLLOUT with POLLWRNORM. EventErr and EventHUp report without a request.
func fromDarwinPoll(revents int16, mask waiter.EventMask) waiter.EventMask {
	var out waiter.EventMask
	if revents&darwinPollIn != 0 {
		out |= mask & waiter.EventIn
	}
	if revents&darwinPollPri != 0 {
		out |= mask & waiter.EventPri
	}
	if revents&darwinPollOut != 0 {
		out |= mask & (waiter.EventOut | waiter.EventWrNorm)
	}
	if revents&darwinPollRdNorm != 0 {
		out |= mask & waiter.EventRdNorm
	}
	if revents&darwinPollErr != 0 {
		out |= waiter.EventErr
	}
	if revents&darwinPollHUp != 0 {
		out |= waiter.EventHUp
	}
	return out
}

// NonBlockingPoll polls the given FD in non-blocking fashion.
func NonBlockingPoll(fd int32, mask waiter.EventMask) waiter.EventMask {
	e := struct {
		fd      int32
		events  int16
		revents int16
	}{
		fd:     fd,
		events: toDarwinPoll(mask),
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
		return fromDarwinPoll(e.revents, mask)
	}
}
