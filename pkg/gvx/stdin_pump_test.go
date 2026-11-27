// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gvx

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

type observedDeadlineReader struct {
	r           io.Reader
	startedOnce sync.Once
	exitedOnce  sync.Once
	started     chan struct{}
	exited      chan struct{}
}

func newObservedDeadlineReader(r io.Reader) *observedDeadlineReader {
	return &observedDeadlineReader{
		r:       r,
		started: make(chan struct{}),
		exited:  make(chan struct{}),
	}
}

func (o *observedDeadlineReader) Read(p []byte) (int, error) {
	o.startedOnce.Do(func() { close(o.started) })
	defer o.exitedOnce.Do(func() { close(o.exited) })
	return o.r.Read(p)
}

func (o *observedDeadlineReader) SetReadDeadline(t time.Time) error {
	if d, ok := o.r.(readDeadlineSetter); ok {
		return d.SetReadDeadline(t)
	}
	return nil
}

func TestStdinPumpStopUnblocksDeadlineReaderWithoutPoisoningStream(t *testing.T) {
	t.Run("os_pipe", func(t *testing.T) {
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		defer w.Close()
		if err := r.SetReadDeadline(time.Time{}); errors.Is(err, os.ErrNoDeadline) {
			t.Skipf("os.Pipe on %s lacks read deadlines: %v", runtime.GOOS, err)
		}
		verifyStdinPumpTeardown(t, r, w)
	})

	t.Run("net_pipe", func(t *testing.T) {
		r, w := net.Pipe()
		defer r.Close()
		defer w.Close()
		verifyStdinPumpTeardown(t, r, w)
	})
}

func verifyStdinPumpTeardown(t *testing.T, r io.Reader, w io.Writer) {
	t.Helper()
	observed := newObservedDeadlineReader(r)
	pump := newStdinPump(observed)

	we, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents | waiter.EventHUp)
	pump.register(&we)
	defer pump.wq.EventUnregister(&we)

	var scratch [64]byte
	if _, err := pump.read(gvcontext.Background(), usermem.BytesIOSequence(scratch[:])); !errors.Is(err, linuxerr.ErrWouldBlock) {
		t.Fatalf("initial pump.read error = %v, want ErrWouldBlock", err)
	}

	select {
	case <-observed.started:
	case <-time.After(time.Second):
		t.Fatal("pump did not start a background host read")
	}

	start := time.Now()
	pump.stop()
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("pump.stop() took %v, want prompt wakeup", elapsed)
	}

	select {
	case <-observed.exited:
	case <-time.After(time.Second):
		t.Fatal("stdinPump helper goroutine remained blocked in Read after stop()")
	}

	select {
	case <-notifyCh:
	case <-time.After(time.Second):
		t.Fatal("stdinPump did not notify waiters on stop()")
	}

	if mask := pump.readiness(); mask&(waiter.ReadableEvents|waiter.EventHUp) != waiter.ReadableEvents|waiter.EventHUp {
		t.Fatalf("pump.readiness() = %#x, want ReadableEvents|EventHUp", mask)
	}
	if _, err := pump.read(gvcontext.Background(), usermem.BytesIOSequence(scratch[:])); !errors.Is(err, io.EOF) {
		t.Fatalf("pump.read after stop() = %v, want io.EOF", err)
	}

	// Verify stop() reset the read deadline on the underlying stream so caller reads succeed.
	const payload = "caller-owned-after-run"
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(w, payload)
		writeDone <- err
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("caller stream remained poisoned after stop(): %v", err)
	}
	if err := <-writeDone; err != nil {
		t.Fatalf("write to caller stream: %v", err)
	}
	if string(got) != payload {
		t.Fatalf("caller read %q, want %q", got, payload)
	}
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestConcurrentSandboxDebugLogSinksDoNotClobber(t *testing.T) {
	initRuntimeGlobals()
	var sinkA, sinkB syncBuffer
	detachA := attachDebugLogSink(&sinkA)
	detachB := attachDebugLogSink(&sinkB)
	defer detachB()

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			log.Warningf("gvx-mux-shared-%d", idx)
		}(i)
	}
	wg.Wait()

	for _, s := range []*syncBuffer{&sinkA, &sinkB} {
		out := s.String()
		if !strings.Contains(out, "gvx-mux-shared-0") {
			t.Fatalf("sink missed multiplexed log output: %q", out)
		}
	}

	detachA()
	log.Warningf("gvx-mux-only-b")

	if strings.Contains(sinkA.String(), "gvx-mux-only-b") {
		t.Fatal("detached sink A still received log lines")
	}
	if !strings.Contains(sinkB.String(), "gvx-mux-only-b") {
		t.Fatal("active sink B lost log lines after sink A detached")
	}
}

func TestStdinPumpQuiesceSerializesStateSaveUnderRace(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()

	observed := newObservedDeadlineReader(r)
	pump := newStdinPump(observed)
	defer pump.stop()

	// Use a savable NoopListener entry so state.Save exercises saving pump.wq
	// concurrently with host read completions.
	var savedEntry waiter.Entry
	savedEntry.Init(&waiter.NoopListener{}, waiter.ReadableEvents)
	pump.register(&savedEntry)
	defer pump.wq.EventUnregister(&savedEntry)

	select {
	case <-observed.started:
	case <-time.After(5 * time.Second):
		t.Fatal("stdinPump did not start initial host read")
	}

	// Quiesce while a host write completes; delivery must park until ResumeAfterSave.
	pump.QuiesceForSave()
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(w, "held-during-save")
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("host write during quiesce: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("host write blocked even though host reader was already in r.Read")
	}

	select {
	case <-observed.exited:
	case <-time.After(5 * time.Second):
		t.Fatal("host r.Read did not return during quiesce")
	}

	pump.mu.Lock()
	readDone := pump.readDone
	pump.mu.Unlock()
	if readDone == nil {
		t.Fatal("readDone cleared before ResumeAfterSave; delivery did not park behind save barrier")
	}
	if mask := pump.readiness(); mask != 0 {
		t.Fatalf("pump.readiness() while quiesced = %#x, want 0 before ResumeAfterSave", mask)
	}

	var saved bytes.Buffer
	if _, err := state.Save(context.Background(), &saved, pump); err != nil {
		_ = pump.ResumeAfterSave()
		t.Fatalf("state.Save(stdinPump) while quiesced: %v", err)
	}
	if err := pump.ResumeAfterSave(); err != nil {
		t.Fatalf("ResumeAfterSave: %v", err)
	}

	select {
	case <-readDone:
	case <-time.After(5 * time.Second):
		t.Fatal("stdinPump helper goroutine did not finish after ResumeAfterSave")
	}
	var dst [64]byte
	n, err := pump.read(gvcontext.Background(), usermem.BytesIOSequence(dst[:]))
	if err != nil {
		t.Fatalf("pump.read after resume: %v", err)
	}
	if got := string(dst[:n]); got != "held-during-save" {
		t.Fatalf("pump.read = %q, want %q", got, "held-during-save")
	}

	// Stress concurrent host writes, guest reads, and quiesced state.Save under -race.
	const rounds = 20
	errCh := make(chan error, 1)
	go func() {
		for range rounds {
			if _, wErr := io.WriteString(w, "x"); wErr != nil {
				errCh <- wErr
				return
			}
		}
		errCh <- nil
	}()

	var collected strings.Builder
	deadline := time.Now().Add(10 * time.Second)
	for collected.Len() < rounds {
		if time.Now().After(deadline) {
			t.Fatalf("timed out draining concurrent writes (got %d/%d)", collected.Len(), rounds)
		}
		pump.QuiesceForSave()
		var snap bytes.Buffer
		if _, sErr := state.Save(context.Background(), &snap, pump); sErr != nil {
			_ = pump.ResumeAfterSave()
			t.Fatalf("state.Save during concurrent writes: %v", sErr)
		}
		if rErr := pump.ResumeAfterSave(); rErr != nil {
			t.Fatalf("ResumeAfterSave: %v", rErr)
		}

		n, rErr := pump.read(gvcontext.Background(), usermem.BytesIOSequence(dst[:]))
		if errors.Is(rErr, linuxerr.ErrWouldBlock) {
			runtime.Gosched()
			continue
		}
		if rErr != nil {
			t.Fatalf("pump.read during stress loop: %v", rErr)
		}
		collected.Write(dst[:n])
	}
	if wErr := <-errCh; wErr != nil {
		t.Fatalf("writer goroutine: %v", wErr)
	}
}

func TestStdinPumpActivateRestoredWakesPollWaiter(t *testing.T) {
	oldR, oldW := net.Pipe()
	defer oldR.Close()
	defer oldW.Close()

	pump := newStdinPump(oldR)
	defer pump.stop()

	var savedEntry waiter.Entry
	savedEntry.Init(&waiter.NoopListener{}, waiter.ReadableEvents)
	pump.wq.EventRegister(&savedEntry)

	pump.QuiesceForSave()
	var saved bytes.Buffer
	if _, err := state.Save(context.Background(), &saved, pump); err != nil {
		_ = pump.ResumeAfterSave()
		t.Fatalf("state.Save(stdinPump): %v", err)
	}
	_ = pump.ResumeAfterSave()

	newR, newW := net.Pipe()
	defer newR.Close()
	defer newW.Close()

	loadCtx := WithRestoreStdio(context.Background(), RestoreStdio{Stdin: newR})
	var restored stdinPump
	if _, err := state.Load(loadCtx, bytes.NewReader(saved.Bytes()), &restored); err != nil {
		t.Fatalf("state.Load(stdinPump): %v", err)
	}
	defer restored.stop()

	if restored.wq.IsEmpty() {
		t.Fatal("restored stdinPump lost its saved waiter entry")
	}

	// Attach a live channel waiter alongside the restored waiter and activate the pump.
	liveEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	restored.wq.EventRegister(&liveEntry)
	defer restored.wq.EventUnregister(&liveEntry)

	restored.activateRestored()

	// Without activateRestored starting a background read, writing to an unbuffered
	// net.Pipe blocks forever because no guest read() has been issued yet.
	writeDone := make(chan error, 1)
	go func() {
		_, err := io.WriteString(newW, "restored-poll-input")
		writeDone <- err
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write to restored stdin pipe: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activateRestored did not start host reader for restored poll waiter")
	}

	select {
	case <-notifyCh:
	case <-time.After(5 * time.Second):
		t.Fatal("restored poll waiter was not notified on host input")
	}

	var dst [64]byte
	n, err := restored.read(gvcontext.Background(), usermem.BytesIOSequence(dst[:]))
	if err != nil {
		t.Fatalf("restored.read: %v", err)
	}
	if got := string(dst[:n]); got != "restored-poll-input" {
		t.Fatalf("restored.read = %q, want %q", got, "restored-poll-input")
	}

	t.Run("nil_stdin_notifies_eof", func(t *testing.T) {
		loadNilCtx := WithRestoreStdio(context.Background(), RestoreStdio{Stdin: nil})
		var restoredNil stdinPump
		if _, err := state.Load(loadNilCtx, bytes.NewReader(saved.Bytes()), &restoredNil); err != nil {
			t.Fatalf("state.Load(stdinPump, nil stdin): %v", err)
		}
		defer restoredNil.stop()

		eofEntry, eofNotify := waiter.NewChannelEntry(waiter.ReadableEvents)
		restoredNil.wq.EventRegister(&eofEntry)
		defer restoredNil.wq.EventUnregister(&eofEntry)

		restoredNil.activateRestored()
		select {
		case <-eofNotify:
		case <-time.After(5 * time.Second):
			t.Fatal("activateRestored did not notify restored poll waiter for nil Stdin EOF")
		}
	})
}

type blockingEchoWriter struct {
	startedOnce sync.Once
	started     chan struct{}
	release     chan struct{}
}

func (w *blockingEchoWriter) Write(p []byte) (int, error) {
	w.startedOnce.Do(func() { close(w.started) })
	<-w.release
	return len(p), nil
}

func TestTTYStateQuiesceSerializesStateSaveUnderRace(t *testing.T) {
	t.Run("raw_input_and_winsize_under_race", func(t *testing.T) {
		r, w := net.Pipe()
		defer r.Close()
		defer w.Close()

		var out syncBuffer
		tty := newTTYState(r, &out, true, 24, 80)
		var savedEntry waiter.Entry
		savedEntry.Init(&waiter.NoopListener{}, waiter.ReadableEvents)
		tty.wq.EventRegister(&savedEntry)
		defer tty.wq.EventUnregister(&savedEntry)

		tty.startPump()
		defer tty.stop()

		done := make(chan struct{})
		writerErr := make(chan error, 1)
		go func() {
			for i := range 32 {
				select {
				case <-done:
					writerErr <- nil
					return
				default:
				}
				if _, err := io.WriteString(w, "a\r"); err != nil {
					writerErr <- err
					return
				}
				if i == 16 {
					runtime.Gosched()
				}
			}
			writerErr <- nil
		}()

		winchDone := make(chan struct{})
		go func() {
			defer close(winchDone)
			for i := uint16(0); ; i++ {
				select {
				case <-done:
					return
				default:
				}
				tty.deliverWinsize(linux.Winsize{Row: 24 + (i % 10), Col: 80 + (i % 20)})
				runtime.Gosched()
			}
		}()

		for range 16 {
			tty.QuiesceForSave()
			var snap bytes.Buffer
			if _, err := state.Save(context.Background(), &snap, tty); err != nil {
				_ = tty.ResumeAfterSave()
				close(done)
				<-winchDone
				t.Fatalf("state.Save(ttyState) while quiesced: %v", err)
			}
			if err := tty.ResumeAfterSave(); err != nil {
				close(done)
				<-winchDone
				t.Fatalf("ttyState.ResumeAfterSave: %v", err)
			}
			runtime.Gosched()
		}
		close(done)
		<-winchDone
		if err := <-writerErr; err != nil {
			t.Fatalf("tty writer: %v", err)
		}
	})

	t.Run("blocked_echo_does_not_deadlock_quiesce", func(t *testing.T) {
		r, w := net.Pipe()
		defer r.Close()
		defer w.Close()

		echoOut := &blockingEchoWriter{
			started: make(chan struct{}),
			release: make(chan struct{}),
		}
		defer close(echoOut.release)

		tty := newTTYState(r, echoOut, true, 24, 80)
		tty.startPump()
		defer tty.stop()

		writeErr := make(chan error, 1)
		go func() {
			_, err := io.WriteString(w, "x")
			writeErr <- err
		}()
		select {
		case err := <-writeErr:
			if err != nil {
				t.Fatalf("write raw tty input: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("raw tty input write timed out")
		}
		select {
		case <-echoOut.started:
		case <-time.After(5 * time.Second):
			t.Fatal("tty echo write did not start")
		}

		// QuiesceForSave and state.Save must succeed while echoOut.Write is blocked.
		quiesceDone := make(chan error, 1)
		go func() {
			tty.QuiesceForSave()
			var snap bytes.Buffer
			_, err := state.Save(context.Background(), &snap, tty)
			rErr := tty.ResumeAfterSave()
			quiesceDone <- errors.Join(err, rErr)
		}()
		select {
		case err := <-quiesceDone:
			if err != nil {
				t.Fatalf("quiesced save while echo blocked: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("QuiesceForSave deadlocked on blocked host echo write")
		}
	})
}

func TestSandboxStateStringWaitsForKernelStart(t *testing.T) {
	t.Run("success_transitions_to_running", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			startDone := make(chan struct{})
			sb := &Sandbox{
				runDone:         make(chan struct{}),
				activeKernel:    &kernel.Kernel{},
				kernelStartDone: startDone,
			}

			gotCh := make(chan string, 1)
			go func() {
				gotCh <- sb.sandboxStateString()
			}()

			synctest.Wait()
			select {
			case st := <-gotCh:
				t.Fatalf("sandboxStateString returned %q before kernelStartDone closed", st)
			default:
			}

			close(startDone)
			synctest.Wait()
			select {
			case st := <-gotCh:
				if st != "running" {
					t.Fatalf("sandboxStateString = %q, want %q", st, "running")
				}
			default:
				t.Fatal("sandboxStateString did not unblock after kernelStartDone closed")
			}
		})
	})

	t.Run("start_failure_reports_exited_before_runDone_closes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			startDone := make(chan struct{})
			runDone := make(chan struct{})
			sb := &Sandbox{
				runDone:         runDone,
				activeKernel:    &kernel.Kernel{},
				kernelStartDone: startDone,
			}

			gotCh := make(chan string, 1)
			go func() {
				gotCh <- sb.sandboxStateString()
			}()

			synctest.Wait()
			// Mirror production executeActiveKernel failure order: clearActiveKernel
			// and close(startDone) happen before defer closeRunDone() executes.
			sb.clearActiveKernel()
			close(startDone)
			synctest.Wait()

			select {
			case st := <-gotCh:
				if st != "exited" {
					t.Fatalf("sandboxStateString after failed start = %q, want %q", st, "exited")
				}
			default:
				t.Fatal("sandboxStateString did not unblock after failed start")
			}
		})
	})
}
