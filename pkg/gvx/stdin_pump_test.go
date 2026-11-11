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
	"errors"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/log"
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
	if elapsed := time.Since(start); elapsed > time.Second {
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
