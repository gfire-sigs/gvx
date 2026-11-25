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

//go:build darwin

package gpurender_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/client"
	"z.gfire.dev/gvx/ext/extensions/gpu/client/gpurendertest"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
)

type fenceEvent struct {
	ctxID   uint32
	ringIdx uint32
	fenceID uint64
	at      time.Time
}

type recordingSink struct {
	fenceDone    chan fenceEvent
	ctxLost      chan uint32
	rendererLost chan error
}

func newRecordingSink() *recordingSink {
	return &recordingSink{
		fenceDone:    make(chan fenceEvent, 64),
		ctxLost:      make(chan uint32, 64),
		rendererLost: make(chan error, 64),
	}
}

func (s *recordingSink) FenceDone(ctxID, ringIdx uint32, fenceID uint64) {
	select {
	case s.fenceDone <- fenceEvent{ctxID: ctxID, ringIdx: ringIdx, fenceID: fenceID, at: time.Now()}:
	default:
	}
}

func (s *recordingSink) ContextLost(ctxID uint32) {
	select {
	case s.ctxLost <- ctxID:
	default:
	}
}

func (s *recordingSink) RendererLost(err error) {
	select {
	case s.rendererLost <- err:
	default:
	}
}

func assertStatusError(t *testing.T, err error, wantStatus gpuproto.Status) {
	t.Helper()
	var se *gpuproto.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v (%T), want *gpuproto.StatusError", err, err)
	}
	if se.Status != wantStatus {
		t.Fatalf("StatusError.Status = %s, want %s", se.Status, wantStatus)
	}
}

func TestHandshakeCachesVenusCapset(t *testing.T) {
	c := gpurendertest.New(t)
	if got := c.Mode(); got != gpuproto.ModeVenus {
		t.Fatalf("Mode() = %v, want %v", got, gpuproto.ModeVenus)
	}

	data, ok := c.Capset(gpuproto.CapsetVenus, 0)
	if !ok {
		t.Fatal("Capset(CapsetVenus, 0) ok = false, want true")
	}
	if len(data) == 0 || len(data)%4 != 0 {
		t.Fatalf("len(Capset(CapsetVenus, 0)) = %d, want positive multiple of 4", len(data))
	}
	if wireFormat := binary.LittleEndian.Uint32(data[0:4]); wireFormat != 1 {
		t.Fatalf("venus wire format = %d, want 1", wireFormat)
	}

	if _, ok := c.Capset(gpuproto.CapsetVenus, 1); ok {
		t.Fatal("Capset(CapsetVenus, 1) ok = true, want false")
	}
	if _, ok := c.Capset(99, 0); ok {
		t.Fatal("Capset(99, 0) ok = true, want false")
	}

	data[0] ^= 0xff
	data2, ok := c.Capset(gpuproto.CapsetVenus, 0)
	if !ok {
		t.Fatal("second Capset(CapsetVenus, 0) ok = false, want true")
	}
	if wireFormat := binary.LittleEndian.Uint32(data2[0:4]); wireFormat != 1 {
		t.Fatalf("mutating returned slice modified cache: got wire format %d, want 1", wireFormat)
	}

	if !strings.HasPrefix(c.Build(), "gvx-gpu-renderer ") {
		t.Fatalf("Build() = %q, want prefix %q", c.Build(), "gvx-gpu-renderer ")
	}
}

func TestContextCreateDestroy(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, "test"); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, "")
	assertStatusError(t, err, gpuproto.StatusExists)
	var se *gpuproto.StatusError
	errors.As(err, &se)
	if se.Errno() != 17 {
		t.Fatalf("StatusExists.Errno() = %d, want 17", se.Errno())
	}

	err = c.CreateContext(ctx, 2, 99, "")
	assertStatusError(t, err, gpuproto.StatusInvalid)

	if err := c.DestroyContext(1); err != nil {
		t.Fatalf("DestroyContext(1): %v", err)
	}
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1) after DestroyContext: %v", err)
	}
}

func TestBlobDescriptorIsSharedMemory(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	req := gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     10,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      12388,
	}
	blob, err := c.CreateBlob(ctx, req)
	if err != nil {
		t.Fatalf("CreateBlob(10): %v", err)
	}
	if blob.Shm == nil {
		t.Fatal("CreateBlob(10) returned nil Shm")
	}
	defer blob.Shm.Close()

	if blob.HostSize < req.Size {
		t.Fatalf("HostSize = %d, want >= %d", blob.HostSize, req.Size)
	}
	if blob.HostSize%gpuproto.HostBlobAlign != 0 {
		t.Fatalf("HostSize = %d, want multiple of %d", blob.HostSize, gpuproto.HostBlobAlign)
	}

	rawFD, err := blob.Shm.RawHandle()
	if err != nil {
		t.Fatalf("RawHandle: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(rawFD), &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	if uint64(st.Size) != blob.HostSize {
		t.Fatalf("fstat size = %d, want %d", st.Size, blob.HostSize)
	}

	fdFlags, err := unix.FcntlInt(rawFD, unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("F_GETFD = %#x, want FD_CLOEXEC set", fdFlags)
	}

	m1, err := unix.Mmap(int(rawFD), 0, int(blob.HostSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("first Mmap: %v", err)
	}
	m2, err := unix.Mmap(int(rawFD), 0, int(blob.HostSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = unix.Munmap(m1)
		t.Fatalf("second Mmap: %v", err)
	}

	pattern := []byte("gvx-gpu-shm-pattern-0123456789")
	copy(m1[4096:], pattern)
	if !bytes.Equal(m2[4096:4096+len(pattern)], pattern) {
		_ = unix.Munmap(m1)
		_ = unix.Munmap(m2)
		t.Fatalf("second mapping read %q, want %q", m2[4096:4096+len(pattern)], pattern)
	}

	if err := unix.Munmap(m1); err != nil {
		t.Fatalf("Munmap(m1): %v", err)
	}
	if err := unix.Munmap(m2); err != nil {
		t.Fatalf("Munmap(m2): %v", err)
	}
	if err := blob.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close: %v", err)
	}
	if err := c.UnrefResource(1, 10); err != nil {
		t.Fatalf("UnrefResource(1, 10): %v", err)
	}
	if err := c.DestroyContext(1); err != nil {
		t.Fatalf("DestroyContext(1): %v", err)
	}

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("recreate context 1: %v", err)
	}
	blob2, err := c.CreateBlob(ctx, req)
	if err != nil {
		t.Fatalf("second CreateBlob(10) after unref: %v", err)
	}
	_ = blob2.Shm.Close()
}

func TestFenceRetiresWithin100ms(t *testing.T) {
	c := gpurendertest.New(t)
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	if err := c.Submit(1, nil, &gpuproto.Fence{RingIdx: 0, ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	submittedAt := time.Now()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case ev := <-sink.fenceDone:
		if ev.ctxID != 1 || ev.ringIdx != 0 || ev.fenceID != 1 {
			t.Fatalf("FenceDone = (%d, %d, %d), want (1, 0, 1)", ev.ctxID, ev.ringIdx, ev.fenceID)
		}
		if elapsed := ev.at.Sub(submittedAt); elapsed >= 100*time.Millisecond {
			t.Fatalf("fence retired in %s, want < 100ms", elapsed)
		}
	case <-timer.C:
		t.Fatal("no FENCE_DONE")
	}
}

func TestSubmitRefusesBadInputWithoutIO(t *testing.T) {
	c := gpurendertest.New(t)

	badCalls := []struct {
		name  string
		ctxID uint32
		cmd   []byte
		fence *gpuproto.Fence
	}{
		{name: "unaligned command length", ctxID: 1, cmd: make([]byte, 6)},
		{name: "oversized command", ctxID: 1, cmd: make([]byte, gpuproto.MaxSubmitBytes+4)},
		{name: "ring index at limit", ctxID: 1, fence: &gpuproto.Fence{RingIdx: 64, ID: 1}},
		{name: "zero fence id", ctxID: 1, fence: &gpuproto.Fence{ID: 0}},
		{name: "zero ctx id", ctxID: 0},
	}

	for _, tc := range badCalls {
		t.Run(tc.name, func(t *testing.T) {
			err := c.Submit(tc.ctxID, tc.cmd, tc.fence)
			assertStatusError(t, err, gpuproto.StatusInvalid)
		})
	}

	if err := c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1) after refused submits: %v", err)
	}
}

func TestBrokenCommandStreamLosesContext(t *testing.T) {
	c := gpurendertest.New(t)
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	bad := bytes.Repeat([]byte{0xff}, 16)
	if err := c.Submit(1, bad, nil); err != nil {
		t.Fatalf("first Submit: %v", err)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	gotLost := false
	for !gotLost {
		select {
		case lostCtx := <-sink.ctxLost:
			if lostCtx == 1 {
				gotLost = true
			}
		case <-ticker.C:
			if err := c.Submit(1, bad, nil); err != nil {
				t.Fatalf("repeat Submit: %v", err)
			}
		case <-deadline.C:
			t.Fatal("timed out waiting for ContextLost(1)")
		}
	}

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(2) after context 1 lost: %v", err)
	}
}

func TestStallFencesSuppressesFenceDone(t *testing.T) {
	c := gpurendertest.NewWithOptions(t, gpurender.Options{StallFences: true})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}
	if err := c.Submit(1, nil, &gpuproto.Fence{ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	timer := time.NewTimer(300 * time.Millisecond)
	defer timer.Stop()
	select {
	case ev := <-sink.fenceDone:
		t.Fatalf("unexpected FenceDone while StallFences is enabled: %+v", ev)
	case <-timer.C:
	}

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(2): %v", err)
	}
}

type doneCountingContext struct {
	context.Context
	target int32
	calls  atomic.Int32
	once   sync.Once
	hit    chan struct{}
}

func newWaitForDoneContext(parent context.Context, target int32) (*doneCountingContext, context.CancelFunc) {
	ctx, cancel := context.WithCancel(parent)
	return &doneCountingContext{
		Context: ctx,
		target:  target,
		hit:     make(chan struct{}),
	}, cancel
}

func (c *doneCountingContext) Done() <-chan struct{} {
	if c.calls.Add(1) >= c.target {
		c.once.Do(func() { close(c.hit) })
	}
	return c.Context.Done()
}

func TestCancelledCreateContextIsUndone(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()
	pid := c.PID()
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGCONT) })

	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP: %v", err)
	}

	// Done() is called first in acquireWriteSem and second in roundTrip after
	// frame.WriteTo has returned, so waiting on hit guarantees the frame is on
	// the socket before cancellation.
	cctx, cancel := newWaitForDoneContext(ctx, 2)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- c.CreateContext(cctx, 7, gpuproto.CapsetVenus, "")
	}()

	sendTimer := time.NewTimer(5 * time.Second)
	defer sendTimer.Stop()
	select {
	case <-cctx.hit:
		cancel()
	case <-sendTimer.C:
		t.Fatal("CreateContext did not reach post-write wait within 5s")
	}

	waitTimer := time.NewTimer(time.Second)
	defer waitTimer.Stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled CreateContext error = %v, want context.Canceled", err)
		}
	case <-waitTimer.C:
		t.Fatal("cancelled CreateContext did not return within 1s")
	}

	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		t.Fatalf("SIGCONT: %v", err)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	var lastErr error
	for {
		lastErr = c.CreateContext(ctx, 7, gpuproto.CapsetVenus, "")
		if lastErr == nil {
			return
		}
		var se *gpuproto.StatusError
		if !errors.As(lastErr, &se) || se.Status != gpuproto.StatusExists {
			t.Fatalf("retry CreateContext(7) unexpected error: %v", lastErr)
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("CreateContext(7) still failed after undo wait: %v", lastErr)
		}
	}
}

func TestCancelledCreateBlobIsUndone(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	pid := c.PID()
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGCONT) })
	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP: %v", err)
	}

	req := gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     20,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      4096,
	}

	cctx, cancel := newWaitForDoneContext(ctx, 2)
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		blob, err := c.CreateBlob(cctx, req)
		if blob.Shm != nil {
			_ = blob.Shm.Close()
		}
		errCh <- err
	}()

	sendTimer := time.NewTimer(5 * time.Second)
	defer sendTimer.Stop()
	select {
	case <-cctx.hit:
		cancel()
	case <-sendTimer.C:
		t.Fatal("CreateBlob did not reach post-write wait within 5s")
	}

	waitTimer := time.NewTimer(time.Second)
	defer waitTimer.Stop()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled CreateBlob error = %v, want context.Canceled", err)
		}
	case <-waitTimer.C:
		t.Fatal("cancelled CreateBlob did not return within 1s")
	}

	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		t.Fatalf("SIGCONT: %v", err)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	var lastErr error
	for {
		blob, err := c.CreateBlob(ctx, req)
		if err == nil {
			_ = blob.Shm.Close()
			return
		}
		lastErr = err
		var se *gpuproto.StatusError
		if !errors.As(err, &se) || (se.Status != gpuproto.StatusExists && se.Status != gpuproto.StatusInvalid) {
			t.Fatalf("retry CreateBlob(20) unexpected error: %v", err)
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("CreateBlob(20) still failed after undo wait: %v", lastErr)
		}
	}
}

func TestHungRendererIsLost(t *testing.T) {
	c := gpurendertest.NewWithOptions(t, gpurender.Options{RequestTimeout: 300 * time.Millisecond})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	pid := c.PID()
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGCONT) })
	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP: %v", err)
	}

	start := time.Now()
	err := c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, "")
	elapsed := time.Since(start)
	if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.Is(err, gpurender.ErrRendererHung) {
		t.Fatalf("CreateContext error = %v, want ErrRendererLost and ErrRendererHung", err)
	}
	if elapsed < 300*time.Millisecond || elapsed >= 3*time.Second {
		t.Fatalf("hung timeout elapsed = %s, want [300ms, 3s)", elapsed)
	}

	lostTimer := time.NewTimer(2 * time.Second)
	defer lostTimer.Stop()
	select {
	case lostErr := <-sink.rendererLost:
		if !errors.Is(lostErr, gpuproto.ErrRendererLost) {
			t.Fatalf("RendererLost error = %v, want ErrRendererLost", lostErr)
		}
		var ee *gpurender.ExitError
		if errors.As(lostErr, &ee) {
			t.Fatalf("hung loss unexpectedly wrapped ExitError: %+v", ee)
		}
	case <-lostTimer.C:
		t.Fatal("timed out waiting for RendererLost")
	}

	repeatTimer := time.NewTimer(200 * time.Millisecond)
	defer repeatTimer.Stop()
	select {
	case extra := <-sink.rendererLost:
		t.Fatalf("unexpected second RendererLost: %v", extra)
	case <-repeatTimer.C:
	}

	if err := c.DestroyContext(1); !errors.Is(err, gpuproto.ErrRendererLost) {
		t.Fatalf("DestroyContext after loss = %v, want ErrRendererLost", err)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("Kill(%d, 0) after Close = %v, want ESRCH", pid, err)
	}
}

func TestKilledRendererFailsPendingAndLaterCalls(t *testing.T) {
	c := gpurendertest.New(t)
	sink := newRecordingSink()
	c.SetEventSink(sink)

	pid := c.PID()
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGCONT) })
	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		t.Fatalf("SIGSTOP: %v", err)
	}

	if err := c.DestroyContext(5); err != nil {
		t.Fatalf("DestroyContext(5): %v", err)
	}

	const nWorkers = 4
	errs := make(chan error, nWorkers)
	workerCtxs := make([]*doneCountingContext, nWorkers)
	var wg sync.WaitGroup
	wg.Add(nWorkers)
	for i := range nWorkers {
		ctxID := uint32(10 + i)
		wctx, cancel := newWaitForDoneContext(context.Background(), 2)
		defer cancel()
		workerCtxs[i] = wctx
		go func() {
			defer wg.Done()
			errs <- c.CreateContext(wctx, ctxID, gpuproto.CapsetVenus, "")
		}()
	}

	readyTimer := time.NewTimer(5 * time.Second)
	defer readyTimer.Stop()
	for i, wctx := range workerCtxs {
		select {
		case <-wctx.hit:
		case <-readyTimer.C:
			t.Fatalf("worker %d did not enter pending wait before SIGKILL", i)
		}
	}

	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}

	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	waitTimer := time.NewTimer(5 * time.Second)
	defer waitTimer.Stop()
	select {
	case <-doneCh:
	case <-waitTimer.C:
		t.Fatal("pending CreateContext calls did not finish within 5s after SIGKILL")
	}
	close(errs)
	for err := range errs {
		if !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Fatalf("pending CreateContext error = %v, want ErrRendererLost", err)
		}
	}

	lostTimer := time.NewTimer(2 * time.Second)
	defer lostTimer.Stop()
	select {
	case lostErr := <-sink.rendererLost:
		if !errors.Is(lostErr, gpuproto.ErrRendererLost) {
			t.Fatalf("RendererLost error = %v, want ErrRendererLost", lostErr)
		}
		var ee *gpurender.ExitError
		if errors.As(lostErr, &ee) {
			t.Fatalf("SIGKILL loss unexpectedly wrapped ExitError: %+v", ee)
		}
	case <-lostTimer.C:
		t.Fatal("timed out waiting for RendererLost")
	}

	repeatTimer := time.NewTimer(200 * time.Millisecond)
	defer repeatTimer.Stop()
	select {
	case extra := <-sink.rendererLost:
		t.Fatalf("unexpected second RendererLost: %v", extra)
	case <-repeatTimer.C:
	}

	blobReq := gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      4096,
	}
	if _, err := c.CreateBlob(context.Background(), blobReq); !errors.Is(err, gpuproto.ErrRendererLost) {
		t.Fatalf("CreateBlob after kill = %v, want ErrRendererLost", err)
	}
	if err := c.Submit(1, nil, nil); !errors.Is(err, gpuproto.ErrRendererLost) {
		t.Fatalf("Submit after kill = %v, want ErrRendererLost", err)
	}
	if err := c.UnrefResource(1, 1); !errors.Is(err, gpuproto.ErrRendererLost) {
		t.Fatalf("UnrefResource after kill = %v, want ErrRendererLost", err)
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	closeTimer := time.NewTimer(5 * time.Second)
	defer closeTimer.Stop()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-closeTimer.C:
		t.Fatal("Close did not return within 5s")
	}

	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("Kill(%d, 0) after Close = %v, want ESRCH", pid, err)
	}
}

func TestSetEventSinkAfterLossReportsOnce(t *testing.T) {
	c := gpurendertest.New(t)
	if err := unix.Kill(c.PID(), unix.SIGKILL); err != nil {
		t.Fatalf("SIGKILL: %v", err)
	}

	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		err := c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, "")
		if errors.Is(err, gpuproto.ErrRendererLost) {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatalf("timed out waiting for ErrRendererLost; last err = %v", err)
		}
	}

	sink := newRecordingSink()
	c.SetEventSink(sink)

	lostTimer := time.NewTimer(2 * time.Second)
	defer lostTimer.Stop()
	select {
	case lostErr := <-sink.rendererLost:
		if !errors.Is(lostErr, gpuproto.ErrRendererLost) {
			t.Fatalf("RendererLost error = %v, want ErrRendererLost", lostErr)
		}
	case <-lostTimer.C:
		t.Fatal("timed out waiting for RendererLost after SetEventSink")
	}

	repeatTimer := time.NewTimer(200 * time.Millisecond)
	defer repeatTimer.Stop()
	select {
	case extra := <-sink.rendererLost:
		t.Fatalf("unexpected second RendererLost: %v", extra)
	case <-repeatTimer.C:
	}
}

func TestSetEventSinkTwicePanics(t *testing.T) {
	c := gpurendertest.New(t)

	assertPanics := func(name string, fn func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Fatalf("%s did not panic", name)
			}
		}()
		fn()
	}

	assertPanics("SetEventSink(nil)", func() {
		c.SetEventSink(nil)
	})

	c.SetEventSink(newRecordingSink())

	assertPanics("second SetEventSink", func() {
		c.SetEventSink(newRecordingSink())
	})
}

func TestConcurrentCallsMatchReplies(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()

	const (
		goroutines = 16
		iterations = 50
	)
	// Contexts are created once and destroyed at the end because concurrent
	// context teardown triggers EINVAL in virglrenderer sendmsg on macOS.
	for g := range goroutines {
		ctxID := uint32(g + 1)
		if err := c.CreateContext(ctx, ctxID, gpuproto.CapsetVenus, ""); err != nil {
			t.Fatalf("CreateContext(%d): %v", ctxID, err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := range goroutines {
		go func() {
			defer wg.Done()
			ctxID := uint32(g + 1)
			for i := range iterations {
				resID := uint32(1000*(g+1) + i)
				blob, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
					CtxID:     ctxID,
					ResID:     resID,
					BlobMem:   gpuproto.BlobMemHost3D,
					BlobFlags: gpuproto.BlobFlagMappable,
					Size:      4096,
				})
				if err != nil {
					t.Errorf("g=%d i=%d CreateBlob(%d, %d): %v", g, i, ctxID, resID, err)
					return
				}
				if err := blob.Shm.Close(); err != nil {
					t.Errorf("g=%d i=%d Shm.Close: %v", g, i, err)
					return
				}
				if err := c.UnrefResource(ctxID, resID); err != nil {
					t.Errorf("g=%d i=%d UnrefResource(%d, %d): %v", g, i, ctxID, resID, err)
					return
				}
			}
		}()
	}
	wg.Wait()

	for g := range goroutines {
		ctxID := uint32(g + 1)
		if err := c.DestroyContext(ctxID); err != nil {
			t.Fatalf("DestroyContext(%d): %v", ctxID, err)
		}
	}
}

func TestTwoClientsAreIndependent(t *testing.T) {
	c1 := gpurendertest.New(t)
	c2 := gpurendertest.New(t)
	if c1.PID() == c2.PID() {
		t.Fatalf("both clients share PID %d", c1.PID())
	}

	ctx := context.Background()
	req10 := gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     10,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      4096,
	}
	for name, c := range map[string]*gpurender.Client{"c1": c1, "c2": c2} {
		if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
			t.Fatalf("%s CreateContext(1): %v", name, err)
		}
		blob, err := c.CreateBlob(ctx, req10)
		if err != nil {
			t.Fatalf("%s CreateBlob(10): %v", name, err)
		}
		_ = blob.Shm.Close()
	}

	if err := unix.Kill(c1.PID(), unix.SIGKILL); err != nil {
		t.Fatalf("SIGKILL c1: %v", err)
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		if err := c1.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); errors.Is(err, gpuproto.ErrRendererLost) {
			break
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("timed out waiting for c1 loss")
		}
	}

	if err := c2.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("c2 CreateContext(2) after c1 kill: %v", err)
	}
	blob, err := c2.CreateBlob(ctx, gpuproto.BlobCreate{
		CtxID:     2,
		ResID:     11,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      4096,
	})
	if err != nil {
		t.Fatalf("c2 CreateBlob(11) after c1 kill: %v", err)
	}
	_ = blob.Shm.Close()
}

func TestCloseReapsRendererAndIsIdempotent(t *testing.T) {
	c, err := gpurender.Start(context.Background(), gpurender.Options{Path: gpurendertest.Path(t)})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	pid := c.PID()

	closeDone := make(chan error, 1)
	go func() { closeDone <- c.Close() }()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("first Close: %v", err)
		}
	case <-timer.C:
		t.Fatal("Close did not return within 5s")
	}

	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("Kill(%d, 0) after Close = %v, want ESRCH", pid, err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	postCloseErr := c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, "")
	if !errors.Is(postCloseErr, gpuproto.ErrRendererLost) {
		t.Fatalf("CreateContext after Close = %v, want ErrRendererLost", postCloseErr)
	}
	var ee *gpurender.ExitError
	if errors.As(postCloseErr, &ee) {
		t.Fatalf("CreateContext after Close wrapped ExitError %+v, want none", ee)
	}
}

func copyFile(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
	}
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		t.Fatalf("copy %s -> %s: %v", src, dst, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", dst, err)
	}
}

func TestStartReportsMissingDriver(t *testing.T) {
	realBin := gpurendertest.Path(t)
	realBundle := filepath.Dir(filepath.Dir(realBin))

	tmpBundle := t.TempDir()
	dstBin := filepath.Join(tmpBundle, "bin", "gvx-gpu-renderer")
	copyFile(t, realBin, dstBin, 0o755)

	realLibDir := filepath.Join(realBundle, "lib")
	entries, err := os.ReadDir(realLibDir)
	if err != nil {
		t.Fatalf("ReadDir(%s): %v", realLibDir, err)
	}
	for _, ent := range entries {
		if ent.IsDir() || ent.Name() == "libvulkan_kosmickrisp.dylib" {
			continue
		}
		copyFile(t, filepath.Join(realLibDir, ent.Name()), filepath.Join(tmpBundle, "lib", ent.Name()), 0o755)
	}

	c, err := gpurender.Start(context.Background(), gpurender.Options{Path: dstBin})
	if c != nil {
		_ = c.Close()
		t.Fatal("Start succeeded without libvulkan_kosmickrisp.dylib")
	}
	var se *gpurender.StartError
	if !errors.As(err, &se) {
		t.Fatalf("Start error = %v (%T), want *gpurender.StartError", err, err)
	}
	if se.ExitCode != gpuproto.ExitInit {
		t.Fatalf("StartError.ExitCode = %d, want %d (%v)", se.ExitCode, gpuproto.ExitInit, se)
	}
	found := false
	for _, line := range se.Stderr {
		if strings.Contains(line, "libvulkan_kosmickrisp.dylib") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("StartError.Stderr = %v, want a line containing libvulkan_kosmickrisp.dylib", se.Stderr)
	}
}

func TestRendererRaisesDescriptorLimit(t *testing.T) {
	var saved syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &saved); err != nil {
		t.Fatalf("Getrlimit(RLIMIT_NOFILE): %v", err)
	}

	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &saved); err != nil {
			t.Errorf("restore RLIMIT_NOFILE: %v", err)
		}
	}
	t.Cleanup(restore)

	// Lower soft RLIMIT_NOFILE through syscall.Setrlimit so Go hands 256 to
	// the child renderer process.
	low := saved
	if low.Cur > 256 {
		low.Cur = 256
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &low); err != nil {
		t.Fatalf("Setrlimit(RLIMIT_NOFILE, 256): %v", err)
	}

	c := gpurendertest.New(t)
	restore()

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	const blobCount = 1000
	for i := range blobCount {
		resID := uint32(i + 1)
		blob, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
			CtxID:     1,
			ResID:     resID,
			BlobMem:   gpuproto.BlobMemHost3D,
			BlobFlags: gpuproto.BlobFlagMappable,
			Size:      4096,
		})
		if err != nil {
			t.Fatalf("CreateBlob(resID=%d): %v", resID, err)
		}
		if err := blob.Shm.Close(); err != nil {
			t.Fatalf("Shm.Close(resID=%d): %v", resID, err)
		}
	}
}

func TestStartRejectsBadPath(t *testing.T) {
	ctx := context.Background()

	t.Run("relative path", func(t *testing.T) {
		c, err := gpurender.Start(ctx, gpurender.Options{Path: "relative/gvx-gpu-renderer"})
		if c != nil {
			_ = c.Close()
			t.Fatal("Start accepted relative path")
		}
		var se *gpurender.StartError
		if !errors.As(err, &se) {
			t.Fatalf("Start error = %v (%T), want *gpurender.StartError", err, err)
		}
		if se.ExitCode != -1 {
			t.Fatalf("StartError.ExitCode = %d, want -1", se.ExitCode)
		}
	})

	t.Run("non-executable regular file", func(t *testing.T) {
		plain := filepath.Join(t.TempDir(), "not-exec")
		if err := os.WriteFile(plain, []byte("hello"), 0o644); err != nil {
			t.Fatalf("write %s: %v", plain, err)
		}
		c, err := gpurender.Start(ctx, gpurender.Options{Path: plain})
		if c != nil {
			_ = c.Close()
			t.Fatal("Start accepted non-executable file")
		}
		var se *gpurender.StartError
		if !errors.As(err, &se) {
			t.Fatalf("Start error = %v (%T), want *gpurender.StartError", err, err)
		}
		if se.ExitCode != -1 {
			t.Fatalf("StartError.ExitCode = %d, want -1", se.ExitCode)
		}
	})

	t.Run("already cancelled context", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		c, err := gpurender.Start(cctx, gpurender.Options{Path: gpurendertest.Path(t)})
		if c != nil {
			_ = c.Close()
			t.Fatal("Start succeeded with cancelled context")
		}
		var se *gpurender.StartError
		if !errors.As(err, &se) {
			t.Fatalf("Start error = %v (%T), want *gpurender.StartError", err, err)
		}
		if se.ExitCode != -1 {
			t.Fatalf("StartError.ExitCode = %d, want -1", se.ExitCode)
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Start error = %v, want context.Canceled", err)
		}
	})
}

func TestWatchdogExitsAboveThreshold(t *testing.T) {
	var (
		logMu    sync.Mutex
		logLines []string
	)
	c := gpurendertest.NewWithOptions(t, gpurender.Options{
		TestWatchdogBytes: 1 << 20,
		Log: func(line string) {
			logMu.Lock()
			logLines = append(logLines, line)
			logMu.Unlock()
			t.Log("renderer: " + line)
		},
	})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	// Start completed before the server armed the watchdog; CreateContext sends
	// the first non-handshake request and arms enforcement.
	if err := c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, ""); err != nil {
		var ee *gpurender.ExitError
		if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.As(err, &ee) || ee.Code != gpuproto.ExitMemoryLimit {
			t.Fatalf("CreateContext(1) error = %v, want nil or ExitMemoryLimit", err)
		}
	}

	lossTimer := time.NewTimer(2 * time.Second)
	defer lossTimer.Stop()
	select {
	case lostErr := <-sink.rendererLost:
		if !errors.Is(lostErr, gpuproto.ErrRendererLost) {
			t.Fatalf("RendererLost error = %v, want ErrRendererLost", lostErr)
		}
		var ee *gpurender.ExitError
		if !errors.As(lostErr, &ee) {
			t.Fatalf("RendererLost error = %v, want *gpurender.ExitError", lostErr)
		}
		if ee.Code != gpuproto.ExitMemoryLimit {
			t.Fatalf("ExitError.Code = %d, want %d", ee.Code, gpuproto.ExitMemoryLimit)
		}
	case <-lossTimer.C:
		t.Fatal("timed out waiting for watchdog RendererLost")
	}

	err := c.CreateContext(context.Background(), 2, gpuproto.CapsetVenus, "")
	if !errors.Is(err, gpuproto.ErrRendererLost) {
		t.Fatalf("CreateContext(2) error = %v, want ErrRendererLost", err)
	}
	var ee *gpurender.ExitError
	if !errors.As(err, &ee) || ee.Code != gpuproto.ExitMemoryLimit {
		t.Fatalf("CreateContext(2) ExitError = %v (err=%v), want ExitMemoryLimit (%d)", ee, err, gpuproto.ExitMemoryLimit)
	}

	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	logMu.Lock()
	lines := append([]string(nil), logLines...)
	logMu.Unlock()
	foundFootprint := false
	for _, line := range lines {
		if strings.Contains(line, "memory footprint") && strings.Contains(line, "exceeds") {
			foundFootprint = true
			break
		}
	}
	if !foundFootprint {
		t.Fatalf("renderer stderr lines = %v, want footprint limit line", lines)
	}
}

func TestWatchdogQuietBelowThreshold(t *testing.T) {
	c := gpurendertest.NewWithOptions(t, gpurender.Options{
		MemoryLimit: 4 << 30,
	})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}
	blob, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      16384,
	})
	if err != nil {
		t.Fatalf("CreateBlob(1): %v", err)
	}
	if err := blob.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close: %v", err)
	}
	if err := c.UnrefResource(1, 1); err != nil {
		t.Fatalf("UnrefResource(1, 1): %v", err)
	}
	if err := c.Submit(1, nil, &gpuproto.Fence{RingIdx: 0, ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	fenceTimer := time.NewTimer(2 * time.Second)
	defer fenceTimer.Stop()
	select {
	case ev := <-sink.fenceDone:
		if ev.ctxID != 1 || ev.fenceID != 1 {
			t.Fatalf("FenceDone = %+v, want ctx=1 fence=1", ev)
		}
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	case <-fenceTimer.C:
		t.Fatal("timed out waiting for FenceDone")
	}

	// Keep the renderer running across four 250 ms watchdog sampling periods.
	quietTimer := time.NewTimer(time.Second)
	defer quietTimer.Stop()
	select {
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost below threshold: %v", lostErr)
	case <-quietTimer.C:
	}

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(2) after quiet window: %v", err)
	}
}

func runRendererExpectExit(t *testing.T, args, env []string) int {
	t.Helper()
	cmd := exec.Command(gpurendertest.Path(t), args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("renderer %v exited 0 (output: %s), want non-zero exit", args, out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("renderer %v failed with %v (output: %s)", args, err, out)
	}
	return exitErr.ExitCode()
}

func TestStartRejectsTestWatchdogWithoutTestMode(t *testing.T) {
	code := runRendererExpectExit(t, []string{gpuproto.ArgTestWatchdogBytes + "1"}, []string{})
	if code != gpuproto.ExitUsage {
		t.Fatalf("exit code = %d, want ExitUsage (%d)", code, gpuproto.ExitUsage)
	}
}

func TestMemoryLimitArgument(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "non-numeric", args: []string{gpuproto.ArgMemoryLimit + "abc"}},
		{name: "empty value", args: []string{gpuproto.ArgMemoryLimit}},
		{name: "negative", args: []string{gpuproto.ArgMemoryLimit + "-1"}},
		{name: "overflow", args: []string{gpuproto.ArgMemoryLimit + "18446744073709551616"}},
		{name: "repeated", args: []string{gpuproto.ArgMemoryLimit + "1024", gpuproto.ArgMemoryLimit + "2048"}},
		{name: "with selftest", args: []string{gpuproto.ArgSelftest, gpuproto.ArgMemoryLimit + "1024"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code := runRendererExpectExit(t, tc.args, []string{})
			if code != gpuproto.ExitUsage {
				t.Fatalf("args %v exit code = %d, want ExitUsage (%d)", tc.args, code, gpuproto.ExitUsage)
			}
		})
	}
}

func TestWatchdogStartFailureIsReported(t *testing.T) {
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devNull.Close()

	cmd := exec.Command(gpurendertest.Path(t), gpuproto.ArgTestWatchdogBytes+"1")
	cmd.Env = []string{gpuproto.EnvTestMode + "=1"}
	cmd.ExtraFiles = []*os.File{devNull}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("renderer exited 0 with non-socket fd 3 (output: %s), want ExitUsage", out)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("renderer failed with %v (output: %s)", err, out)
	}
	if exitErr.ExitCode() != gpuproto.ExitUsage {
		t.Fatalf("exit code = %d, want ExitUsage (%d); output: %s", exitErr.ExitCode(), gpuproto.ExitUsage, out)
	}
}

func TestGPURendererConfinement(t *testing.T) {
	c := gpurendertest.NewWithOptions(t, gpurender.Options{TestOps: true})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if data, ok := c.Capset(gpuproto.CapsetVenus, 0); !ok || len(data) == 0 {
		t.Fatalf("Capset(CapsetVenus, 0) = (%d bytes, %v), want non-empty ok", len(data), ok)
	}
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, "confine"); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	blob1, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     1,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      16384,
	})
	if err != nil {
		t.Fatalf("first CreateBlob(1): %v", err)
	}
	rawFD, err := blob1.Shm.RawHandle()
	if err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("RawHandle: %v", err)
	}
	mapped, err := unix.Mmap(int(rawFD), 0, int(blob1.HostSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("Mmap: %v", err)
	}
	binary.LittleEndian.PutUint32(mapped[0:4], 0x5a5a5a5a)
	if got := binary.LittleEndian.Uint32(mapped[0:4]); got != 0x5a5a5a5a {
		_ = unix.Munmap(mapped)
		_ = blob1.Shm.Close()
		t.Fatalf("mapped word = %#x, want 0x5a5a5a5a", got)
	}
	if err := unix.Munmap(mapped); err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("Munmap: %v", err)
	}
	if err := blob1.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close(1): %v", err)
	}
	if err := c.UnrefResource(1, 1); err != nil {
		t.Fatalf("UnrefResource(1, 1): %v", err)
	}

	if err := c.Submit(1, nil, &gpuproto.Fence{RingIdx: 0, ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	fenceTimer := time.NewTimer(2 * time.Second)
	defer fenceTimer.Stop()
	select {
	case ev := <-sink.fenceDone:
		if ev.ctxID != 1 || ev.fenceID != 1 {
			t.Fatalf("FenceDone = %+v, want ctx=1 fence=1", ev)
		}
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost before TestConfinement: %v", lostErr)
	case <-fenceTimer.C:
		t.Fatal("timed out waiting for FenceDone")
	}

	// TEST_CONFINE is a non-HELLO/non-GET_CAPSET request and also arms the
	// memory watchdog if MemoryLimit is set; here MemoryLimit is 0.
	rep, err := c.TestConfinement(ctx)
	if err != nil {
		if errors.Is(err, gpuproto.ErrRendererLost) {
			t.Fatalf("exec allowed (renderer replaced): %v", err)
		}
		t.Fatalf("TestConfinement: %v", err)
	}
	if rep.Checks != gpuproto.ConfineChecks {
		t.Fatalf("TestConfinement Checks = %d, want %d", rep.Checks, gpuproto.ConfineChecks)
	}

	checkNames := [gpuproto.ConfineChecks]string{
		gpuproto.ConfineCheckFork:    "fork",
		gpuproto.ConfineCheckExec:    "exec",
		gpuproto.ConfineCheckRead:    "read",
		gpuproto.ConfineCheckCreate:  "create",
		gpuproto.ConfineCheckConnect: "connect",
	}
	for i, name := range checkNames {
		res := gpuproto.ConfineResult(rep.Results[i])
		switch res {
		case gpuproto.ConfineDenied:
		case gpuproto.ConfineAllowed:
			t.Fatalf("%s allowed", name)
		case gpuproto.ConfineUnexpected:
			t.Fatalf("%s unexpected errno", name)
		default:
			t.Fatalf("%s invalid result %d", name, res)
		}
	}

	blob2, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     2,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      16384,
	})
	if err != nil {
		t.Fatalf("second CreateBlob(2) after TestConfinement: %v", err)
	}
	if err := blob2.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close(2): %v", err)
	}
	if err := c.UnrefResource(1, 2); err != nil {
		t.Fatalf("UnrefResource(1, 2): %v", err)
	}
	if err := c.DestroyContext(1); err != nil {
		t.Fatalf("DestroyContext(1): %v", err)
	}

	createPath := "/private/tmp/gvx-gpu-selftest-" + strconv.Itoa(c.PID())
	if _, statErr := os.Lstat(createPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Lstat(%s) after TestConfinement = %v, want os.ErrNotExist", createPath, statErr)
	}

	pgrepOut, pgrepErr := exec.Command("pgrep", "-P", strconv.Itoa(c.PID())).CombinedOutput()
	if pgrepErr == nil {
		if len(bytes.TrimSpace(pgrepOut)) > 0 {
			t.Fatalf("renderer PID %d has child processes: %s", c.PID(), strings.TrimSpace(string(pgrepOut)))
		}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(pgrepErr, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("pgrep -P %d failed: %v (output: %s)", c.PID(), pgrepErr, strings.TrimSpace(string(pgrepOut)))
		}
	}
}

func TestGPURendererTestOpsOffByDefault(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()

	_, err := c.TestConfinement(ctx)
	assertStatusError(t, err, gpuproto.StatusNotSupported)

	if data, ok := c.Capset(gpuproto.CapsetVenus, 0); !ok || len(data) == 0 {
		t.Fatalf("Capset(CapsetVenus, 0) after refused TEST_CONFINE = (%d bytes, %v), want non-empty ok", len(data), ok)
	}
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1) after refused TEST_CONFINE: %v", err)
	}
}

func countOpenFDs(limit int) int {
	n := 0
	for fd := range limit {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			n++
		}
	}
	return n
}

func TestVirglHandshakeCachesCapsets(t *testing.T) {
	c := gpurendertest.NewVirgl(t)

	if got := c.Mode(); got != gpuproto.ModeVirgl {
		t.Fatalf("Mode() = %v, want %v", got, gpuproto.ModeVirgl)
	}

	for v := uint32(0); v <= 1; v++ {
		data, ok := c.Capset(gpuproto.CapsetVirgl, v)
		if !ok {
			t.Fatalf("Capset(CapsetVirgl, %d) ok = false, want true", v)
		}
		if len(data) == 0 || len(data)%4 != 0 {
			t.Fatalf("len(Capset(CapsetVirgl, %d)) = %d, want positive multiple of 4", v, len(data))
		}
	}
	if _, ok := c.Capset(gpuproto.CapsetVirgl, 2); ok {
		t.Fatal("Capset(CapsetVirgl, 2) ok = true, want false")
	}

	for v := uint32(0); v <= 2; v++ {
		data, ok := c.Capset(gpuproto.CapsetVirgl2, v)
		if !ok {
			t.Fatalf("Capset(CapsetVirgl2, %d) ok = false, want true", v)
		}
		if len(data) == 0 || len(data)%4 != 0 {
			t.Fatalf("len(Capset(CapsetVirgl2, %d)) = %d, want positive multiple of 4", v, len(data))
		}
		if got := binary.LittleEndian.Uint32(data[0:4]); got != 2 {
			t.Fatalf("Capset(CapsetVirgl2, %d) first word = %d, want 2", v, got)
		}
	}
	if _, ok := c.Capset(gpuproto.CapsetVirgl2, 3); ok {
		t.Fatal("Capset(CapsetVirgl2, 3) ok = true, want false")
	}
	if _, ok := c.Capset(gpuproto.CapsetVenus, 0); ok {
		t.Fatal("Capset(CapsetVenus, 0) ok = true, want false")
	}
}

func TestVirglContextCapsets(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl, "virgl1"); err != nil {
		t.Fatalf("CreateContext(1, CapsetVirgl): %v", err)
	}
	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVirgl2, "virgl2"); err != nil {
		t.Fatalf("CreateContext(2, CapsetVirgl2): %v", err)
	}
	err := c.CreateContext(ctx, 3, gpuproto.CapsetVenus, "venus")
	assertStatusError(t, err, gpuproto.StatusInvalid)
}

func TestVirglResourceRoundTrip(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, "rt"); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	const size = 65536
	blob, err := c.CreateResource(ctx, gpuproto.ResourceCreate{
		CtxID:     1,
		ResID:     10,
		Target:    0,      // PIPE_BUFFER
		Format:    64,     // VIRGL_FORMAT_R8_UNORM
		Bind:      1 << 4, // VIRGL_BIND_VERTEX_BUFFER
		Width:     size,
		Height:    1,
		Depth:     1,
		ArraySize: 1,
		Size:      size,
	})
	if err != nil {
		t.Fatalf("CreateResource(10): %v", err)
	}
	if blob.Shm == nil {
		t.Fatal("CreateResource(10) returned nil Shm")
	}
	defer blob.Shm.Close()

	if blob.HostSize != size {
		t.Fatalf("HostSize = %d, want %d", blob.HostSize, size)
	}

	rawFD, err := blob.Shm.RawHandle()
	if err != nil {
		t.Fatalf("RawHandle: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(rawFD), &st); err != nil {
		t.Fatalf("Fstat: %v", err)
	}
	if st.Size != size {
		t.Fatalf("fstat size = %d, want %d", st.Size, size)
	}
	fdFlags, err := unix.FcntlInt(rawFD, unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("F_GETFD: %v", err)
	}
	if fdFlags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("F_GETFD = %#x, want FD_CLOEXEC set", fdFlags)
	}

	mapped, err := unix.Mmap(int(rawFD), 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		t.Fatalf("Mmap: %v", err)
	}
	defer func() { _ = unix.Munmap(mapped) }()

	pattern := make([]byte, size)
	for i := range pattern {
		pattern[i] = byte(i*7 + 3)
	}
	copy(mapped, pattern)

	box := gpuproto.Box{W: size, H: 1, D: 1}
	if err := c.Transfer(ctx, gpuproto.Transfer{
		CtxID:     1,
		ResID:     10,
		Direction: gpuproto.TransferToHost,
		Box:       box,
	}); err != nil {
		t.Fatalf("TransferToHost: %v", err)
	}

	clear(mapped)

	if err := c.Transfer(ctx, gpuproto.Transfer{
		CtxID:     1,
		ResID:     10,
		Direction: gpuproto.TransferFromHost,
		Box:       box,
	}); err != nil {
		t.Fatalf("TransferFromHost: %v", err)
	}

	if !bytes.Equal(mapped, pattern) {
		t.Fatal("TransferFromHost data did not match written pattern")
	}

	if err := c.UnrefResource(1, 10); err != nil {
		t.Fatalf("UnrefResource(1, 10): %v", err)
	}
	if err := c.DestroyContext(1); err != nil {
		t.Fatalf("DestroyContext(1): %v", err)
	}
}

func TestVirglResourceBadArguments(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	blob, err := c.CreateResource(ctx, gpuproto.ResourceCreate{
		CtxID:     1,
		ResID:     10,
		Target:    99,
		Format:    64,
		Bind:      1 << 4,
		Width:     4096,
		Height:    1,
		Depth:     1,
		ArraySize: 1,
		Size:      4096,
	})
	if blob.Shm != nil {
		_ = blob.Shm.Close()
	}
	assertStatusError(t, err, gpuproto.StatusInvalid)

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(2) after bad CreateResource: %v", err)
	}
}

func TestVirglBlobCreateNotSupported(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	blob, err := c.CreateBlob(ctx, gpuproto.BlobCreate{
		CtxID:     1,
		ResID:     10,
		BlobMem:   gpuproto.BlobMemHost3D,
		BlobFlags: gpuproto.BlobFlagMappable,
		Size:      4096,
	})
	if blob.Shm != nil {
		_ = blob.Shm.Close()
	}
	assertStatusError(t, err, gpuproto.StatusNotSupported)

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(2) after refused CreateBlob: %v", err)
	}
}

func TestVenusRefusesVirglRequests(t *testing.T) {
	c := gpurendertest.New(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	blob, err := c.CreateResource(ctx, gpuproto.ResourceCreate{
		CtxID:     1,
		ResID:     10,
		Target:    0,
		Format:    64,
		Bind:      1 << 4,
		Width:     4096,
		Height:    1,
		Depth:     1,
		ArraySize: 1,
		Size:      4096,
	})
	if blob.Shm != nil {
		_ = blob.Shm.Close()
	}
	assertStatusError(t, err, gpuproto.StatusNotSupported)

	err = c.Transfer(ctx, gpuproto.Transfer{
		CtxID:     1,
		ResID:     10,
		Direction: gpuproto.TransferToHost,
		Box:       gpuproto.Box{W: 4096, H: 1, D: 1},
	})
	assertStatusError(t, err, gpuproto.StatusNotSupported)

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVenus, ""); err != nil {
		t.Fatalf("CreateContext(2) after refused virgl requests: %v", err)
	}
}

func TestVirglFenceRetires(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	if err := c.Submit(1, nil, &gpuproto.Fence{RingIdx: 0, ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	submittedAt := time.Now()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case ev := <-sink.fenceDone:
		if ev.ctxID != 1 || ev.ringIdx != 0 || ev.fenceID != 1 {
			t.Fatalf("FenceDone = (%d, %d, %d), want (1, 0, 1)", ev.ctxID, ev.ringIdx, ev.fenceID)
		}
		if elapsed := ev.at.Sub(submittedAt); elapsed >= 100*time.Millisecond {
			t.Fatalf("fence retired in %s, want < 100ms", elapsed)
		}
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	case <-timer.C:
		t.Fatal("no FENCE_DONE")
	}
}

func TestVirglBrokenStreamLosesContext(t *testing.T) {
	c := gpurendertest.NewVirgl(t)
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	// Single command header word: length 0, object type 0, unknown command 0xff.
	bad := []byte{0xff, 0x00, 0x00, 0x00}
	if err := c.Submit(1, bad, nil); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	select {
	case lostCtx := <-sink.ctxLost:
		if lostCtx != 1 {
			t.Fatalf("ContextLost = %d, want 1", lostCtx)
		}
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	case <-deadline.C:
		t.Fatal("timed out waiting for ContextLost(1)")
	}

	if err := c.CreateContext(ctx, 2, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(2) after context 1 lost: %v", err)
	}
}

func TestVirglUnrefThenReuseID(t *testing.T) {
	const fdScanLimit = 4096
	c := gpurendertest.NewVirgl(t)
	ctx := context.Background()

	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, ""); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	before := countOpenFDs(fdScanLimit)
	for i := range 200 {
		resID := uint32(i + 1)
		blob, err := c.CreateResource(ctx, gpuproto.ResourceCreate{
			CtxID:     1,
			ResID:     resID,
			Target:    0,
			Format:    64,
			Bind:      1 << 4,
			Width:     4096,
			Height:    1,
			Depth:     1,
			ArraySize: 1,
			Size:      4096,
		})
		if err != nil {
			t.Fatalf("round %d CreateResource(%d): %v", i, resID, err)
		}
		if err := blob.Shm.Close(); err != nil {
			t.Fatalf("round %d Shm.Close(%d): %v", i, resID, err)
		}
		if err := c.UnrefResource(1, resID); err != nil {
			t.Fatalf("round %d UnrefResource(%d): %v", i, resID, err)
		}
	}

	after := countOpenFDs(fdScanLimit)
	if after > before {
		t.Fatalf("open descriptor count grew from %d to %d across 200 rounds", before, after)
	}
}

func TestVirglConfinement(t *testing.T) {
	c := gpurendertest.NewWithOptions(t, gpurender.Options{
		Mode:    gpuproto.ModeVirgl,
		TestOps: true,
	})
	sink := newRecordingSink()
	c.SetEventSink(sink)

	ctx := context.Background()
	if data, ok := c.Capset(gpuproto.CapsetVirgl2, 0); !ok || len(data) == 0 {
		t.Fatalf("Capset(CapsetVirgl2, 0) = (%d bytes, %v), want non-empty ok", len(data), ok)
	}
	if err := c.CreateContext(ctx, 1, gpuproto.CapsetVirgl2, "confine"); err != nil {
		t.Fatalf("CreateContext(1): %v", err)
	}

	resReq := func(resID uint32) gpuproto.ResourceCreate {
		return gpuproto.ResourceCreate{
			CtxID:     1,
			ResID:     resID,
			Target:    0,
			Format:    64,
			Bind:      1 << 4,
			Width:     16384,
			Height:    1,
			Depth:     1,
			ArraySize: 1,
			Size:      16384,
		}
	}

	blob1, err := c.CreateResource(ctx, resReq(1))
	if err != nil {
		t.Fatalf("first CreateResource(1): %v", err)
	}
	rawFD, err := blob1.Shm.RawHandle()
	if err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("RawHandle: %v", err)
	}
	mapped, err := unix.Mmap(int(rawFD), 0, int(blob1.HostSize), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("Mmap: %v", err)
	}
	binary.LittleEndian.PutUint32(mapped[0:4], 0x5a5a5a5a)
	if got := binary.LittleEndian.Uint32(mapped[0:4]); got != 0x5a5a5a5a {
		_ = unix.Munmap(mapped)
		_ = blob1.Shm.Close()
		t.Fatalf("mapped word = %#x, want 0x5a5a5a5a", got)
	}
	if err := unix.Munmap(mapped); err != nil {
		_ = blob1.Shm.Close()
		t.Fatalf("Munmap: %v", err)
	}
	if err := blob1.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close(1): %v", err)
	}
	if err := c.UnrefResource(1, 1); err != nil {
		t.Fatalf("UnrefResource(1, 1): %v", err)
	}

	if err := c.Submit(1, nil, &gpuproto.Fence{RingIdx: 0, ID: 1}); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	fenceTimer := time.NewTimer(2 * time.Second)
	defer fenceTimer.Stop()
	select {
	case ev := <-sink.fenceDone:
		if ev.ctxID != 1 || ev.fenceID != 1 {
			t.Fatalf("FenceDone = %+v, want ctx=1 fence=1", ev)
		}
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost before TestConfinement: %v", lostErr)
	case <-fenceTimer.C:
		t.Fatal("timed out waiting for FenceDone")
	}

	rep, err := c.TestConfinement(ctx)
	if err != nil {
		if errors.Is(err, gpuproto.ErrRendererLost) {
			t.Fatalf("exec allowed (renderer replaced): %v", err)
		}
		t.Fatalf("TestConfinement: %v", err)
	}
	if rep.Checks != gpuproto.ConfineChecks {
		t.Fatalf("TestConfinement Checks = %d, want %d", rep.Checks, gpuproto.ConfineChecks)
	}

	checkNames := [gpuproto.ConfineChecks]string{
		gpuproto.ConfineCheckFork:    "fork",
		gpuproto.ConfineCheckExec:    "exec",
		gpuproto.ConfineCheckRead:    "read",
		gpuproto.ConfineCheckCreate:  "create",
		gpuproto.ConfineCheckConnect: "connect",
	}
	for i, name := range checkNames {
		res := gpuproto.ConfineResult(rep.Results[i])
		switch res {
		case gpuproto.ConfineDenied:
		case gpuproto.ConfineAllowed:
			t.Fatalf("%s allowed", name)
		case gpuproto.ConfineUnexpected:
			t.Fatalf("%s unexpected errno", name)
		default:
			t.Fatalf("%s invalid result %d", name, res)
		}
	}

	blob2, err := c.CreateResource(ctx, resReq(2))
	if err != nil {
		t.Fatalf("second CreateResource(2) after TestConfinement: %v", err)
	}
	if err := blob2.Shm.Close(); err != nil {
		t.Fatalf("Shm.Close(2): %v", err)
	}
	if err := c.UnrefResource(1, 2); err != nil {
		t.Fatalf("UnrefResource(1, 2): %v", err)
	}
	if err := c.DestroyContext(1); err != nil {
		t.Fatalf("DestroyContext(1): %v", err)
	}

	createPath := "/private/tmp/gvx-gpu-selftest-" + strconv.Itoa(c.PID())
	if _, statErr := os.Lstat(createPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("Lstat(%s) after TestConfinement = %v, want os.ErrNotExist", createPath, statErr)
	}

	pgrepOut, pgrepErr := exec.Command("pgrep", "-P", strconv.Itoa(c.PID())).CombinedOutput()
	if pgrepErr == nil {
		if len(bytes.TrimSpace(pgrepOut)) > 0 {
			t.Fatalf("renderer PID %d has child processes: %s", c.PID(), strings.TrimSpace(string(pgrepOut)))
		}
	} else {
		var exitErr *exec.ExitError
		if !errors.As(pgrepErr, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("pgrep -P %d failed: %v (output: %s)", c.PID(), pgrepErr, strings.TrimSpace(string(pgrepOut)))
		}
	}
}
