package fd

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"testing/synctest"
)

func openGuardTemp(t *testing.T, name string) *HostHandle {
	t.Helper()
	h, err := OpenHostPath(filepath.Join(t.TempDir(), name), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("OpenHostPath: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

// TestGuardShutWaitsForAdmittedCalls checks that shut blocks while a call that
// enter admitted still runs. The close of the OS handle must not overlap such
// a call, or the OS can give the closed number to another object that the late
// call then reads.
func TestGuardShutWaitsForAdmittedCalls(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var g handleGuard
		if !g.enter() {
			t.Fatal("enter on a new guard = false, want true")
		}
		shutDone, owner := make(chan struct{}), false
		go func() {
			owner = g.shut()
			close(shutDone)
		}()
		synctest.Wait()
		select {
		case <-shutDone:
			t.Fatal("shut returned while a call was in flight")
		default:
		}
		if g.enter() {
			t.Error("enter after shut started = true, want false")
		}
		if !g.isClosed() {
			t.Error("isClosed = false after shut started")
		}
		g.exit()
		synctest.Wait()
		select {
		case <-shutDone:
		default:
			t.Fatal("shut did not return after the last call left")
		}
		if !owner {
			t.Error("the first shut did not own the close")
		}
		if g.shut() {
			t.Error("the second shut owned the close again")
		}
	})
}

// TestGuardSecondShutDoesNotWait checks that a repeated Close or Release does
// not block behind a call in flight. Only the first shut owns the close.
func TestGuardSecondShutDoesNotWait(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var g handleGuard
		g.enter()
		first := make(chan bool)
		go func() { first <- g.shut() }()
		synctest.Wait()
		if g.shut() {
			t.Error("the second shut returned true, want false")
		}
		g.exit()
		if !<-first {
			t.Error("the first shut did not own the close")
		}
	})
}

// TestHostHandleCloseNeverLetsACallReachAReusedDescriptor closes a handle while
// readers call ReadAt and Dup. After each Close, the test opens another file,
// which usually receives the number that Close freed. A reader that used the
// freed number would read the marker of the new file or fail to match the
// marker of the old one.
func TestHostHandleCloseNeverLetsACallReachAReusedDescriptor(t *testing.T) {
	const rounds, readers = 200, 8
	for round := range rounds {
		old := openGuardTemp(t, "old.bin")
		if _, err := old.WriteAt([]byte("OLD!"), 0); err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
		var wg sync.WaitGroup
		start := make(chan struct{})
		bad := make(chan string, readers)
		for range readers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				buf := make([]byte, 4)
				for {
					n, err := old.ReadAt(buf, 0)
					if err != nil {
						return
					}
					if got := string(buf[:n]); got != "OLD!" {
						bad <- got
						return
					}
					if d, err := old.Dup(); err == nil {
						d.Close()
					}
				}
			}()
		}
		close(start)
		if err := old.Close(); err != nil {
			t.Fatalf("round %d: Close: %v", round, err)
		}
		// The freed number can go to this file at once.
		next := openGuardTemp(t, "new.bin")
		if _, err := next.WriteAt([]byte("NEW!"), 0); err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
		wg.Wait()
		close(bad)
		for got := range bad {
			t.Fatalf("round %d: a call after Close read %q from a reused descriptor", round, got)
		}
	}
}
