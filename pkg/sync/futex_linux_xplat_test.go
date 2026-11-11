//go:build linux

package sync

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

func waitThreadSleeping(t *testing.T, tid int) {
	t.Helper()
	statPath := fmt.Sprintf("/proc/self/task/%d/stat", tid)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(statPath)
		if err == nil {
			if idx := strings.LastIndexByte(string(data), ')'); idx >= 0 && idx+2 < len(data) && data[idx+2] == 'S' {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("thread %d did not enter interruptible sleep within 5s", tid)
}

// A signal handler that runs during FUTEX_WAIT with a timeout makes Linux
// return EINTR. FutexWait must park again and report the timeout, not a wake.
// The test sends SIGURG, which the Go runtime handles for preemption, to the
// waiting thread several times during one wait.
func TestFutexWaitTimesOutAcrossSignals(t *testing.T) {
	word := newFutexWord(7)
	const timeout = 200 * time.Millisecond
	tids := make(chan int, 1)
	releaseThread := make(chan struct{})
	type waitResult struct {
		err     error
		elapsed time.Duration
	}
	result := make(chan waitResult, 1)
	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		tids <- syscall.Gettid()
		start := time.Now()
		err := FutexWait(word, 7, timeout)
		result <- waitResult{err: err, elapsed: time.Since(start)}
		// Hold the OS thread alive until the caller stops sending Tgkill.
		<-releaseThread
	}()
	defer close(releaseThread)

	tid := <-tids
	waitThreadSleeping(t, tid)
	pid := syscall.Getpid()
	if err := syscall.Tgkill(pid, tid, syscall.SIGURG); err != nil {
		t.Fatalf("initial tgkill: %v", err)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(10 * time.Second)
	var got waitResult
	for {
		select {
		case got = <-result:
			if !errors.Is(got.err, ErrFutexTimedOut) {
				t.Fatalf("FutexWait with signals = %v, want %v", got.err, ErrFutexTimedOut)
			}
			if got.elapsed < timeout {
				t.Errorf("FutexWait returned after %v, want at least the timeout %v", got.elapsed, timeout)
			}
			return
		case <-ticker.C:
			if err := syscall.Tgkill(pid, tid, syscall.SIGURG); err != nil {
				t.Fatalf("tgkill: %v", err)
			}
		case <-deadline:
			t.Fatal("FutexWait did not complete within 10s")
		}
	}
}
