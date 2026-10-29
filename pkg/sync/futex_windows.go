//go:build windows

package sync

import (
	"fmt"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modSynch             = windows.NewLazySystemDLL("api-ms-win-core-synch-l1-2-0.dll")
	procWaitOnAddress    = modSynch.NewProc("WaitOnAddress")
	procWakeByAddrSingle = modSynch.NewProc("WakeByAddressSingle")
	procWakeByAddrAll    = modSynch.NewProc("WakeByAddressAll")
)

// maxWaitMillis is the largest finite WaitOnAddress timeout. The value
// INFINITE (0xFFFFFFFF) selects an unbounded wait, so it cannot be a bounded chunk.
const maxWaitMillis = windows.INFINITE - 1

// futexWaiterShards spreads the waiter counters over independent locks.
const futexWaiterShards = 64

// futexWord holds the state of one address that has waiters.
type futexWord struct {
	// waiters counts the threads parked on the address.
	waiters int
	// wakes counts the wake-ups that FutexWake and FutexWakeAll issued for the
	// address and that no waiter has used yet.
	wakes int
}

// futexWaiters tracks the threads parked per address. WakeByAddress* does not
// report how many threads it woke. FutexWake uses the counters to wake no more
// than the requested number of threads and to report an upper bound. The wake
// counters tell a real wake from a spurious return of WaitOnAddress.
var futexWaiters [futexWaiterShards]struct {
	mu    Mutex
	words map[*uint32]*futexWord
}

func futexShard(addr *uint32) int {
	return int(uintptr(unsafe.Pointer(addr))>>2) % futexWaiterShards
}

// futexRegister counts one more waiter on addr.
func futexRegister(addr *uint32) {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.words == nil {
		s.words = make(map[*uint32]*futexWord)
	}
	w := s.words[addr]
	if w == nil {
		w = &futexWord{}
		s.words[addr] = w
	}
	w.waiters++
}

// futexUnregister removes one waiter. A wake-up that nobody used cannot outlast
// the waiters, so the counter never exceeds the waiters that remain.
func futexUnregister(addr *uint32) {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.words[addr]
	if w == nil {
		return
	}
	w.waiters--
	if w.waiters <= 0 {
		delete(s.words, addr)
		return
	}
	w.wakes = min(w.wakes, w.waiters)
}

// futexClaimWake uses one wake-up that FutexWake issued for addr. It reports
// false when none is pending.
func futexClaimWake(addr *uint32) bool {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.words[addr]
	if w == nil || w.wakes == 0 {
		return false
	}
	w.wakes--
	return true
}

// futexIssueWake records up to count wake-ups for addr, before the caller wakes
// the threads, and returns how many it recorded: the number of waiters, capped
// by count.
func futexIssueWake(addr *uint32, count int) int {
	s := &futexWaiters[futexShard(addr)]
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.words[addr]
	if w == nil {
		return 0
	}
	n := min(count, w.waiters)
	w.wakes = min(w.wakes+n, w.waiters)
	return n
}

// FutexWait parks the caller while *addr equals val.
// A negative timeout blocks without limit. It returns nil after a wake,
// ErrFutexAgain if *addr differs from val, and ErrFutexTimedOut on timeout.
func FutexWait(addr *uint32, val uint32, timeout time.Duration) error {
	if addr == nil {
		return errNilFutexAddr
	}
	if atomic.LoadUint32(addr) != val {
		return ErrFutexAgain
	}
	// The waiter registers before it calls WaitOnAddress. A waker that stored a new
	// value before FutexWake either sees the registration or WaitOnAddress sees the new value.
	futexRegister(addr)
	defer futexUnregister(addr)

	var deadline time.Time
	if timeout >= 0 {
		deadline = time.Now().Add(timeout)
	}
	compareVal := val
	for {
		millis := uint32(windows.INFINITE)
		if timeout >= 0 {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				return ErrFutexTimedOut
			}
			millis = uint32(min((remaining+time.Millisecond-1)/time.Millisecond, maxWaitMillis))
		}
		r1, _, e1 := procWaitOnAddress.Call(
			uintptr(unsafe.Pointer(addr)),
			uintptr(unsafe.Pointer(&compareVal)),
			unsafe.Sizeof(compareVal),
			uintptr(millis),
		)
		if r1 != 0 {
			// WaitOnAddress also returns TRUE when no wake reached this address:
			// the wait table of the kernel is hashed, and a wake for another word
			// that shares the bucket releases this thread. A real return has one of
			// two causes: the value changed, or FutexWake issued a wake-up that no
			// other waiter used.
			if atomic.LoadUint32(addr) != val || futexClaimWake(addr) {
				return nil
			}
			continue
		}
		if e1 != syscall.Errno(windows.ERROR_TIMEOUT) {
			return fmt.Errorf("WaitOnAddress: %w", e1)
		}
		// ERROR_TIMEOUT also marks a clamped chunk of a very long wait.
		// The loop tests the deadline again.
	}
}

// FutexWake wakes up to count threads parked on addr.
// WakeByAddressSingle does not report whether a thread woke, so the result is
// the number of wake calls issued for registered waiters. It is an upper bound.
// A waiter that already woke but has not deregistered yet still counts.
func FutexWake(addr *uint32, count int) int {
	if addr == nil || count <= 0 {
		return 0
	}
	n := futexIssueWake(addr, count)
	for range n {
		procWakeByAddrSingle.Call(uintptr(unsafe.Pointer(addr)))
	}
	return n
}

// FutexWakeAll wakes every thread parked on addr. It returns the number of
// registered waiters at the time of the call, which is an upper bound.
func FutexWakeAll(addr *uint32) int {
	if addr == nil {
		return 0
	}
	n := futexIssueWake(addr, int(^uint(0)>>1))
	if n > 0 {
		procWakeByAddrAll.Call(uintptr(unsafe.Pointer(addr)))
	}
	return n
}
