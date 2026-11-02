//go:build linux

package sync

import (
	"errors"
	"runtime"
	"syscall"
	"testing"
	"time"
)

// A signal handler that runs during FUTEX_WAIT with a timeout makes Linux
// return EINTR. FutexWait must park again and report the timeout, not a wake.
// The test sends SIGURG, which the Go runtime handles for preemption, to the
// waiting thread several times during one wait.
func TestFutexWaitTimesOutAcrossSignals(t *testing.T) {
	word := newFutexWord(7)
	const timeout = 200 * time.Millisecond
	tids := make(chan int, 1)
	result := make(chan error, 1)
	elapsed := make(chan time.Duration, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- syscall.Gettid()
		start := time.Now()
		result <- FutexWait(word, 7, timeout)
		elapsed <- time.Since(start)
	}()
	tid := <-tids
	pid := syscall.Getpid()
	for range 10 {
		time.Sleep(10 * time.Millisecond)
		if err := syscall.Tgkill(pid, tid, syscall.SIGURG); err != nil {
			t.Fatalf("tgkill: %v", err)
		}
	}
	if err := <-result; !errors.Is(err, ErrFutexTimedOut) {
		t.Fatalf("FutexWait with signals = %v, want %v", err, ErrFutexTimedOut)
	}
	if took := <-elapsed; took < timeout {
		t.Errorf("FutexWait returned after %v, want at least the timeout %v", took, timeout)
	}
}
