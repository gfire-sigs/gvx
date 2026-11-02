//go:build linux

package sync

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

// These are FUTEX_WAIT and FUTEX_WAKE with FUTEX_PRIVATE_FLAG from <linux/futex.h>.
// pkg/abi/linux imports pkg/sync, so this file cannot import that package.
const (
	futexWaitPrivate = 0 | 128
	futexWakePrivate = 1 | 128
)

// FutexWait parks the caller while *addr equals val.
// A negative timeout blocks without limit. It returns nil after a wake,
// ErrFutexAgain if *addr differs from val, and ErrFutexTimedOut on timeout.
func FutexWait(addr *uint32, val uint32, timeout time.Duration) error {
	if addr == nil {
		return errNilFutexAddr
	}
	var ts *unix.Timespec
	var rel unix.Timespec
	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
		rel = unix.NsecToTimespec(timeout.Nanoseconds())
		ts = &rel
	}
	for {
		_, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), futexWaitPrivate, uintptr(val), uintptr(unsafe.Pointer(ts)), 0, 0)
		switch e {
		case 0:
			return nil
		case syscall.EAGAIN:
			return ErrFutexAgain
		case syscall.ETIMEDOUT:
			return ErrFutexTimedOut
		case syscall.EINTR:
			// WHY: Linux ends a FUTEX_WAIT that has a timeout with EINTR when a
			// signal handler runs, such as the SIGURG of Go preemption. The
			// kernel does not restart it. Park again for the time that is left,
			// so the caller sees no wake that nobody issued.
			if ts != nil {
				left := time.Until(deadline)
				if left <= 0 {
					return ErrFutexTimedOut
				}
				rel = unix.NsecToTimespec(left.Nanoseconds())
			}
		default:
			return fmt.Errorf("futex wait: %w", e)
		}
	}
}

// FutexWake wakes up to count threads parked on addr and returns the number woken.
func FutexWake(addr *uint32, count int) int {
	if addr == nil || count <= 0 {
		return 0
	}
	count = min(count, maxFutexWake)
	n, _, e := unix.Syscall6(unix.SYS_FUTEX, uintptr(unsafe.Pointer(addr)), futexWakePrivate, uintptr(count), 0, 0, 0)
	if e != 0 {
		// EFAULT and EINVAL mean addr is not a valid aligned word, which is a caller bug.
		panic(fmt.Sprintf("futex wake(%p): %v", addr, e))
	}
	return int(n)
}

// FutexWakeAll wakes every thread parked on addr and returns the number woken.
func FutexWakeAll(addr *uint32) int {
	return FutexWake(addr, maxFutexWake)
}

// maxFutexWake is the largest wake count that the futex(2) ABI accepts.
const maxFutexWake = 1<<31 - 1
