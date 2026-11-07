package gvxshim

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// wedgedListener models go-winio v0.6.2 after its listener routine took one
// close request without recording it: Close blocks until it was called need
// times, and Accept returns a raw error as go-winio does for a canceled connect.
type wedgedListener struct {
	mu      sync.Mutex
	calls   int
	need    int
	release chan struct{}
	once    sync.Once
}

func newWedgedListener(need int) *wedgedListener {
	return &wedgedListener{need: need, release: make(chan struct{})}
}

func (w *wedgedListener) Close() error {
	w.mu.Lock()
	w.calls++
	if w.calls >= w.need {
		w.once.Do(func() { close(w.release) })
	}
	w.mu.Unlock()
	<-w.release
	return nil
}

func (w *wedgedListener) Accept() (net.Conn, error) {
	<-w.release
	return nil, errors.New("raw connect error")
}

func (w *wedgedListener) Addr() net.Addr { return nil }

func (w *wedgedListener) callCount() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.calls
}

func TestPipeListenerCloseRepeatsUntilListenerRoutineExits(t *testing.T) {
	wedged := newWedgedListener(3)
	listener := newPipeListener(wedged)
	listener.retry = time.Millisecond
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if wedged.callCount() < 3 {
		t.Fatalf("Close returned after %d inner calls", wedged.callCount())
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Accept after Close returned %v, want net.ErrClosed", err)
	}
}

func TestPipeListenerCloseHasUpperBound(t *testing.T) {
	wedged := newWedgedListener(1 << 30)
	defer wedged.once.Do(func() { close(wedged.release) })
	listener := newPipeListener(wedged)
	listener.retry = time.Millisecond
	listener.timeout = 50 * time.Millisecond
	if err := listener.Close(); !errors.Is(err, errPipeListenerCloseTimeout) {
		t.Fatalf("Close returned %v, want errPipeListenerCloseTimeout", err)
	}
}

func TestWindowsLogSinkCloseDoesNotWaitForStuckListener(t *testing.T) {
	wedged := newWedgedListener(1 << 30)
	defer wedged.once.Do(func() { close(wedged.release) })
	listener := newPipeListener(wedged)
	listener.retry = time.Millisecond
	listener.timeout = 50 * time.Millisecond
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "diagnostics.log"), os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	sink := &windowsLogSink{listener: listener, diagnostics: file, timeout: time.Second, done: make(chan struct{}), abandoned: make(chan struct{})}
	closed := make(chan error, 1)
	go func() { closed <- sink.Close() }()
	select {
	case err := <-closed:
		if !errors.Is(err, errPipeListenerCloseTimeout) {
			t.Fatalf("Close returned %v, want errPipeListenerCloseTimeout", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("sink Close waited for a stuck accept goroutine")
	}
}

// TestWindowsPipeListenerCloseRacesPendingConnect uses the real go-winio
// listener. Without pipeListener, a Close call can stay blocked in
// win32PipeListener.Close. The run name makes each pipe name unique, so a
// listener that a failed iteration leaks does not fail the next run.
func TestWindowsPipeListenerCloseRacesPendingConnect(t *testing.T) {
	const iterations = 3000
	const bound = 30 * time.Second
	run := time.Now().UnixNano()
	for i := range iterations {
		address := fmt.Sprintf(`\\.\pipe\gvx-shim-close-race-%d-%d-%d`, os.Getpid(), run, i)
		listener, err := listenProtectedPipe(address)
		if err != nil {
			t.Fatal(err)
		}
		acceptDone := make(chan error, 1)
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					acceptDone <- err
					return
				}
				conn.Close()
			}
		}()
		// Most rounds close at once: the close request then waits while the
		// listener routine creates its first pipe instance and starts its connect.
		if i%10 == 0 {
			client, err := dialLocal(t.Context(), address)
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
		}
		closed := make(chan error, 1)
		go func() { closed <- listener.Close() }()
		select {
		case err := <-closed:
			if err != nil {
				t.Fatalf("iteration %d: Close: %v", i, err)
			}
		case <-time.After(bound):
			t.Fatalf("iteration %d: Close did not return", i)
		}
		select {
		case err := <-acceptDone:
			if !errors.Is(err, net.ErrClosed) {
				t.Fatalf("iteration %d: Accept returned %v, want net.ErrClosed", i, err)
			}
		case <-time.After(bound):
			t.Fatalf("iteration %d: Accept did not return after Close", i)
		}
	}
}
