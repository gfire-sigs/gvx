//go:build linux || darwin || windows

package sync

import (
	"errors"
	"fmt"
	"runtime"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"
)

// newFutexWord returns a heap word so that its address stays stable across threads.
func newFutexWord(v uint32) *uint32 {
	w := new(uint32)
	*w = v
	return w
}

func TestFutexWaitReportsValueMismatch(t *testing.T) {
	t.Parallel()
	word := newFutexWord(7)
	if err := FutexWait(word, 99, time.Second); !errors.Is(err, ErrFutexAgain) {
		t.Fatalf("FutexWait mismatch err = %v, want %v", err, ErrFutexAgain)
	}
}

func TestFutexWaitNilAddress(t *testing.T) {
	t.Parallel()
	if err := FutexWait(nil, 0, time.Second); err == nil {
		t.Fatal("FutexWait(nil) err = nil, want error")
	}
	if n := FutexWake(nil, 1); n != 0 {
		t.Fatalf("FutexWake(nil) = %d, want 0", n)
	}
	if n := FutexWakeAll(nil); n != 0 {
		t.Fatalf("FutexWakeAll(nil) = %d, want 0", n)
	}
}

func TestFutexWaitTimeout(t *testing.T) {
	t.Parallel()
	word := newFutexWord(7)
	for _, timeout := range []time.Duration{0, time.Nanosecond, 3 * time.Millisecond} {
		start := time.Now()
		err := FutexWait(word, 7, timeout)
		if !errors.Is(err, ErrFutexTimedOut) {
			t.Fatalf("FutexWait(timeout=%v) err = %v, want %v", timeout, err, ErrFutexTimedOut)
		}
		if elapsed := time.Since(start); elapsed < timeout {
			t.Fatalf("FutexWait(timeout=%v) returned after %v, want at least the timeout", timeout, elapsed)
		}
	}
}

func TestFutexWakeWithoutWaitersReturnsZero(t *testing.T) {
	t.Parallel()
	word := newFutexWord(0)
	if n := FutexWake(word, 1); n != 0 {
		t.Fatalf("FutexWake(no waiters) = %d, want 0", n)
	}
	if n := FutexWake(word, 0); n != 0 {
		t.Fatalf("FutexWake(count=0) = %d, want 0", n)
	}
	if n := FutexWakeAll(word); n != 0 {
		t.Fatalf("FutexWakeAll(no waiters) = %d, want 0", n)
	}
}

// releaseWaiters wakes waiters until all of them return and reports each result.
// Waiters park at an unknown time, so the loop retries FutexWake until the
// results arrive. The loop ends only when no wakeup is lost.
func releaseWaiters(t *testing.T, wake func() int, results <-chan error, waiters int) {
	t.Helper()
	watchdog := time.After(30 * time.Second)
	for returned := 0; returned < waiters; {
		select {
		case err := <-results:
			if err != nil {
				t.Fatalf("FutexWait after wake err = %v, want nil", err)
			}
			returned++
			continue
		case <-watchdog:
			t.Fatalf("%d of %d waiters stayed parked: a futex wakeup was lost", waiters-returned, waiters)
		default:
		}
		wake()
		runtime.Gosched()
	}
}

func TestFutexWakeReleasesWaiters(t *testing.T) {
	t.Parallel()
	const waiters, batch = 6, 2
	word := newFutexWord(0)
	results := make(chan error, waiters)
	for range waiters {
		go func() { results <- FutexWait(word, 0, -1) }()
	}
	releaseWaiters(t, func() int {
		n := FutexWake(word, batch)
		if n > batch {
			t.Errorf("FutexWake(count=%d) = %d, want at most the count", batch, n)
		}
		return n
	}, results, waiters)
	if n := FutexWake(word, 1); n != 0 {
		t.Fatalf("FutexWake after all waiters returned = %d, want 0", n)
	}
	if n := FutexWakeAll(word); n != 0 {
		t.Fatalf("FutexWakeAll after all waiters returned = %d, want 0", n)
	}
}

func TestFutexWakeAllReleasesWaiters(t *testing.T) {
	t.Parallel()
	const waiters = 4
	word := newFutexWord(0)
	results := make(chan error, waiters)
	for range waiters {
		go func() { results <- FutexWait(word, 0, -1) }()
	}
	releaseWaiters(t, func() int { return FutexWakeAll(word) }, results, waiters)
}

func TestFutexHugeTimeoutDoesNotOverflow(t *testing.T) {
	t.Parallel()
	word := newFutexWord(0)
	results := make(chan error, 1)
	go func() { results <- FutexWait(word, 0, time.Duration(1<<62)) }()
	releaseWaiters(t, func() int { return FutexWake(word, 1) }, results, 1)
}

// TestFutexPingPongOrdering alternates two goroutines on one word. A lost
// wakeup deadlocks the exchange and trips the watchdog.
func TestFutexPingPongOrdering(t *testing.T) {
	t.Parallel()
	const rounds = 2000
	word := newFutexWord(0)

	turn := func(self, other uint32) {
		for i := 0; i < rounds; i++ {
			for atomic.LoadUint32(word) != self {
				if err := FutexWait(word, other, 20*time.Second); err != nil && !errors.Is(err, ErrFutexAgain) {
					t.Errorf("FutexWait: %v", err)
					return
				}
			}
			atomic.StoreUint32(word, other)
			FutexWake(word, 1)
		}
	}
	finished := make(chan struct{}, 2)
	go func() { turn(0, 1); finished <- struct{}{} }()
	go func() { turn(1, 0); finished <- struct{}{} }()
	watchdog := time.After(60 * time.Second)
	for range 2 {
		select {
		case <-finished:
		case <-watchdog:
			t.Fatal("ping-pong deadlocked: a futex wakeup was lost")
		}
	}
}

// A waiter must return only after a wake for its word or a new value. WaitOnAddress
// on Windows can return for a wake of another word, because the kernel hashes the
// addresses of its wait table. The test parks probe threads on words that nobody
// wakes, while other threads wake unrelated words without pause.
func TestFutexWaitReturnsOnlyForItsOwnWake(t *testing.T) {
	t.Parallel()
	const probes, noisy = 8, 8
	stop := make(chan struct{})
	var noise gosync.WaitGroup
	for range noisy {
		word := newFutexWord(7)
		noise.Add(1)
		go func() {
			defer noise.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				done := make(chan struct{})
				go func() {
					_ = FutexWait(word, 7, 200*time.Microsecond)
					close(done)
				}()
				FutexWake(word, 1)
				<-done
			}
		}()
	}
	errs := make(chan error, probes)
	var wg gosync.WaitGroup
	for range probes {
		word := newFutexWord(7)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				if err := FutexWait(word, 7, time.Millisecond); !errors.Is(err, ErrFutexTimedOut) {
					errs <- fmt.Errorf("FutexWait returned %v with no wake for its word, want %v", err, ErrFutexTimedOut)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(stop)
	noise.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
