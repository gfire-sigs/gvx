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

package gpurender

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"
	"testing/synctest"
	"time"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
)

func newDeadlineTestClient(t *testing.T, reqTimeout, submitTimeout time.Duration) (*Client, int, *wireTestSink, func()) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	if err := unix.SetNonblock(fds[0], true); err != nil {
		_ = unix.Close(fds[0])
		_ = unix.Close(fds[1])
		t.Fatalf("SetNonblock: %v", err)
	}
	parentFile := os.NewFile(uintptr(fds[0]), "deadline-test-client")
	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = unix.Close(fds[1])
		t.Fatalf("FileConn: %v", err)
	}
	uc := conn.(*net.UnixConn)
	raw, err := uc.SyscallConn()
	if err != nil {
		_ = uc.Close()
		_ = unix.Close(fds[1])
		t.Fatalf("SyscallConn: %v", err)
	}

	opts := Options{
		RequestTimeout: reqTimeout,
		SubmitTimeout:  submitTimeout,
	}.withDefaults()
	exited := make(chan struct{})
	close(exited)
	c := &Client{
		opts:     opts,
		conn:     uc,
		raw:      raw,
		readOOB:  make([]byte, unix.CmsgSpace(maxControlFDs*4)),
		proc:     &process{exited: exited},
		capsets:  make(map[capsetKey][]byte),
		writeSem: make(chan struct{}, 1),
		failed:   make(chan struct{}),
		done:     make(chan struct{}),
		nextSeq:  1,
		pending:  make(map[uint32]*call),
	}
	sink := newWireTestSink()
	c.SetEventSink(sink)

	c.wg.Add(2)
	go c.readLoop()
	go c.deadlineLoop()

	peerFD := fds[1]
	peerClosed := false
	cleanup := func() {
		if !peerClosed {
			peerClosed = true
			_ = unix.Close(peerFD)
		}
		c.lose(errClosed, false)
		c.wg.Wait()
	}
	t.Cleanup(cleanup)
	return c, peerFD, sink, cleanup
}

func writePeerOKReply(t *testing.T, peerFD int, req gpuproto.Header, sink *wireTestSink) {
	t.Helper()
	rep := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:  gpuproto.Magic,
		Op:     req.Op,
		Flags:  gpuproto.FlagReply,
		Seq:    req.Seq,
		CtxID:  req.CtxID,
		Status: gpuproto.StatusOK,
	})
	if _, err := unix.Write(peerFD, rep); err != nil {
		select {
		case lostErr := <-sink.rendererLost:
			t.Fatalf("Write %s reply (seq %d): %v (client already lost: %v)", req.Op, req.Seq, err, lostErr)
		default:
			t.Fatalf("Write %s reply (seq %d): %v", req.Op, req.Seq, err)
		}
	}
}

func TestDeadlineSlowHeadDoesNotExpireQueuedRequests(t *testing.T) {
	const (
		reqTimeout    = 1000 * time.Millisecond
		submitTimeout = 3600 * time.Millisecond
		headWork      = 2000 * time.Millisecond
	)
	c, peerFD, sink, cleanup := newDeadlineTestClient(t, reqTimeout, submitTimeout)
	defer cleanup()

	if err := c.Submit(1, nil, nil); err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if err := c.UnrefResource(1, 10); err != nil {
		t.Fatalf("UnrefResource: %v", err)
	}
	createErrCh := make(chan error, 1)
	go func() {
		createErrCh <- c.CreateContext(context.Background(), 2, gpuproto.CapsetVenus, "")
	}()

	// Read all three frames before delaying so every request is already written.
	submitHdr, _ := readPeerFrame(t, peerFD)
	unrefHdr, _ := readPeerFrame(t, peerFD)
	createHdr, _ := readPeerFrame(t, peerFD)
	if submitHdr.Op != gpuproto.OpSubmit || unrefHdr.Op != gpuproto.OpResUnref || createHdr.Op != gpuproto.OpCtxCreate {
		t.Fatalf("received ops (%s, %s, %s), want (SUBMIT, RES_UNREF, CTX_CREATE)", submitHdr.Op, unrefHdr.Op, createHdr.Op)
	}

	time.Sleep(headWork)
	writePeerOKReply(t, peerFD, submitHdr, sink)
	writePeerOKReply(t, peerFD, unrefHdr, sink)
	writePeerOKReply(t, peerFD, createHdr, sink)

	select {
	case err := <-createErrCh:
		if err != nil {
			t.Fatalf("CreateContext behind slow Submit failed: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("CreateContext did not return within 2s")
	}

	select {
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	default:
	}

	// Verify the client stays usable after draining the queued batch.
	followErrCh := make(chan error, 1)
	go func() {
		followErrCh <- c.CreateContext(context.Background(), 3, gpuproto.CapsetVenus, "")
	}()
	followHdr, _ := readPeerFrame(t, peerFD)
	writePeerOKReply(t, peerFD, followHdr, sink)
	if err := <-followErrCh; err != nil {
		t.Fatalf("follow-up CreateContext failed: %v", err)
	}
}

func TestDeadlineBackToBackSubmitsExceedSingleBudget(t *testing.T) {
	const (
		reqTimeout    = 1000 * time.Millisecond
		submitTimeout = 2400 * time.Millisecond
		perSubmitWork = 1400 * time.Millisecond
		submitCount   = 3
	)
	c, peerFD, sink, cleanup := newDeadlineTestClient(t, reqTimeout, submitTimeout)
	defer cleanup()

	for i := range submitCount {
		if err := c.Submit(1, nil, nil); err != nil {
			t.Fatalf("Submit %d: %v", i, err)
		}
	}

	submitHdrs := make([]gpuproto.Header, submitCount)
	for i := range submitCount {
		hdr, _ := readPeerFrame(t, peerFD)
		if hdr.Op != gpuproto.OpSubmit {
			t.Fatalf("frame %d op = %s, want SUBMIT", i, hdr.Op)
		}
		submitHdrs[i] = hdr
	}

	// Total work (1050ms) exceeds one submitTimeout (600ms), while each submit
	// finishes well inside its own 600ms budget.
	for _, hdr := range submitHdrs {
		time.Sleep(perSubmitWork)
		writePeerOKReply(t, peerFD, hdr, sink)
	}

	// Send a follow-up request after all submits finish to verify no loss.
	barrierErrCh := make(chan error, 1)
	go func() {
		barrierErrCh <- c.CreateContext(context.Background(), 2, gpuproto.CapsetVenus, "")
	}()
	barrierHdr, _ := readPeerFrame(t, peerFD)
	if barrierHdr.Op != gpuproto.OpCtxCreate {
		t.Fatalf("barrier op = %s, want CTX_CREATE", barrierHdr.Op)
	}
	writePeerOKReply(t, peerFD, barrierHdr, sink)

	select {
	case err := <-barrierErrCh:
		if err != nil {
			t.Fatalf("CreateContext after back-to-back Submits failed: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("CreateContext did not return within 2s")
	}

	select {
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	default:
	}
}

func TestDeadlineHungHeadLosesRenderer(t *testing.T) {
	t.Run("unanswered head", func(t *testing.T) {
		const (
			reqTimeout    = 1000 * time.Millisecond
			submitTimeout = 3600 * time.Millisecond
		)
		c, peerFD, sink, cleanup := newDeadlineTestClient(t, reqTimeout, submitTimeout)
		defer cleanup()

		start := time.Now()
		errCh := make(chan error, 1)
		go func() {
			errCh <- c.CreateContext(context.Background(), 1, gpuproto.CapsetVenus, "")
		}()

		reqHdr, _ := readPeerFrame(t, peerFD)
		if reqHdr.Op != gpuproto.OpCtxCreate {
			t.Fatalf("peer op = %s, want CTX_CREATE", reqHdr.Op)
		}

		select {
		case err := <-errCh:
			elapsed := time.Since(start)
			if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.Is(err, ErrRendererHung) {
				t.Fatalf("CreateContext error = %v, want ErrRendererLost and ErrRendererHung", err)
			}
			if elapsed < reqTimeout || elapsed >= 8*time.Second {
				t.Fatalf("hung elapsed = %s, want [%s, 2s)", elapsed, reqTimeout)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("hung CreateContext did not time out within 2s")
		}

		lostErr := waitRendererLost(t, sink)
		if !errors.Is(lostErr, ErrRendererHung) {
			t.Fatalf("RendererLost error = %v, want ErrRendererHung", lostErr)
		}
	})

	t.Run("unanswered follower after slow head", func(t *testing.T) {
		const (
			reqTimeout    = 1200 * time.Millisecond
			submitTimeout = 3600 * time.Millisecond
			headWork      = 2000 * time.Millisecond
		)
		c, peerFD, sink, cleanup := newDeadlineTestClient(t, reqTimeout, submitTimeout)
		defer cleanup()

		if err := c.Submit(1, nil, nil); err != nil {
			t.Fatalf("Submit: %v", err)
		}
		errCh := make(chan error, 1)
		go func() {
			errCh <- c.CreateContext(context.Background(), 2, gpuproto.CapsetVenus, "")
		}()

		submitHdr, _ := readPeerFrame(t, peerFD)
		createHdr, _ := readPeerFrame(t, peerFD)
		if submitHdr.Op != gpuproto.OpSubmit || createHdr.Op != gpuproto.OpCtxCreate {
			t.Fatalf("peer ops = (%s, %s), want (SUBMIT, CTX_CREATE)", submitHdr.Op, createHdr.Op)
		}

		time.Sleep(headWork)
		submitRepliedAt := time.Now()
		writePeerOKReply(t, peerFD, submitHdr, sink)

		select {
		case err := <-errCh:
			afterHead := time.Since(submitRepliedAt)
			if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.Is(err, ErrRendererHung) {
				t.Fatalf("CreateContext error = %v, want ErrRendererLost and ErrRendererHung", err)
			}
			if afterHead < reqTimeout || afterHead >= 8*time.Second {
				t.Fatalf("follower elapsed after head reply = %s, want [%s, 2s)", afterHead, reqTimeout)
			}
		case <-time.After(8 * time.Second):
			t.Fatal("hung follower CreateContext did not time out within 2s")
		}

		lostErr := waitRendererLost(t, sink)
		if !errors.Is(lostErr, ErrRendererHung) {
			t.Fatalf("RendererLost error = %v, want ErrRendererHung", lostErr)
		}
	})
}

func TestDeadlineStartsAtWriteCompletion(t *testing.T) {
	const (
		reqTimeout    = 1200 * time.Millisecond
		submitTimeout = 3200 * time.Millisecond
		writeDelay    = 1600 * time.Millisecond
		serviceWork   = 2200 * time.Millisecond
	)
	c, peerFD, sink, cleanup := newDeadlineTestClient(t, reqTimeout, submitTimeout)
	defer cleanup()

	// Shrink socket buffers so a 64 KiB SUBMIT blocks inside writeFrameLocked
	// until the peer drains it.
	if err := unix.SetsockoptInt(peerFD, unix.SOL_SOCKET, unix.SO_RCVBUF, 4096); err != nil {
		t.Fatalf("SetsockoptInt(SO_RCVBUF): %v", err)
	}
	if err := c.conn.SetWriteBuffer(4096); err != nil {
		t.Fatalf("SetWriteBuffer: %v", err)
	}

	submitErrCh := make(chan error, 1)
	go func() {
		submitErrCh <- c.Submit(1, make([]byte, 64*1024), nil)
	}()

	time.Sleep(writeDelay)
	select {
	case err := <-submitErrCh:
		t.Fatalf("Submit returned before peer drained socket (err=%v); test did not block write", err)
	default:
	}

	submitHdr, _ := readPeerFrame(t, peerFD)
	if submitHdr.Op != gpuproto.OpSubmit {
		t.Fatalf("peer op = %s, want SUBMIT", submitHdr.Op)
	}
	select {
	case err := <-submitErrCh:
		if err != nil {
			t.Fatalf("Submit failed after peer drained socket: %v", err)
		}
	case <-time.After(8 * time.Second):
		t.Fatal("Submit did not return after peer drained socket")
	}

	// Delay past writeDelay+serviceWork (950ms > 800ms submitTimeout) from
	// registration, while staying inside 800ms from write completion (550ms).
	time.Sleep(serviceWork)
	writePeerOKReply(t, peerFD, submitHdr, sink)

	followErrCh := make(chan error, 1)
	go func() {
		followErrCh <- c.CreateContext(context.Background(), 2, gpuproto.CapsetVenus, "")
	}()
	followHdr, _ := readPeerFrame(t, peerFD)
	writePeerOKReply(t, peerFD, followHdr, sink)
	if err := <-followErrCh; err != nil {
		t.Fatalf("follow-up CreateContext failed: %v", err)
	}

	select {
	case lostErr := <-sink.rendererLost:
		t.Fatalf("unexpected RendererLost: %v", lostErr)
	default:
	}
}

func newSynctestDeadlineClient(t *testing.T) (*Client, func()) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	unix.CloseOnExec(fds[0])
	unix.CloseOnExec(fds[1])
	parentFile := os.NewFile(uintptr(fds[0]), "synctest-deadline-client")
	conn, err := net.FileConn(parentFile)
	_ = parentFile.Close()
	if err != nil {
		_ = unix.Close(fds[1])
		t.Fatalf("FileConn: %v", err)
	}
	uc := conn.(*net.UnixConn)
	exited := make(chan struct{})
	close(exited)
	c := &Client{
		opts:     Options{}.withDefaults(),
		conn:     uc,
		proc:     &process{exited: exited},
		capsets:  make(map[capsetKey][]byte),
		writeSem: make(chan struct{}, 1),
		failed:   make(chan struct{}),
		done:     make(chan struct{}),
		nextSeq:  1,
		pending:  make(map[uint32]*call),
	}
	c.wg.Add(1)
	go c.deadlineLoop()
	return c, func() {
		c.lose(errClosed, false)
		c.wg.Wait()
		_ = unix.Close(fds[1])
	}
}

func TestDeadlineProductionBudgetsSynctest(t *testing.T) {
	t.Run("25s submit followed by 10s unref and create", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, cleanup := newSynctestDeadlineClient(t)
			defer cleanup()

			submitCall := &call{op: gpuproto.OpSubmit, ctxID: 1, timeout: DefaultSubmitTimeout}
			unrefCall := &call{op: gpuproto.OpResUnref, ctxID: 1, timeout: DefaultRequestTimeout}
			createCall := &call{op: gpuproto.OpCtxCreate, ctxID: 2, timeout: DefaultRequestTimeout, done: make(chan result, 1)}

			submitSeq, err := c.register(submitCall)
			if err != nil {
				t.Fatalf("register SUBMIT: %v", err)
			}
			c.markWritten(submitCall)

			unrefSeq, err := c.register(unrefCall)
			if err != nil {
				t.Fatalf("register RES_UNREF: %v", err)
			}
			c.markWritten(unrefCall)

			createSeq, err := c.register(createCall)
			if err != nil {
				t.Fatalf("register CTX_CREATE: %v", err)
			}
			c.markWritten(createCall)

			time.Sleep(25 * time.Second)
			synctest.Wait()
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost at 25s of 30s head budget: %v", err)
			}

			okReply := func(op gpuproto.Op, seq, ctxID uint32) {
				t.Helper()
				hdr := gpuproto.Header{
					Magic:  gpuproto.Magic,
					Op:     op,
					Flags:  gpuproto.FlagReply,
					Seq:    seq,
					CtxID:  ctxID,
					Status: gpuproto.StatusOK,
				}
				if !c.dispatchReply(hdr, nil, nil) {
					t.Fatalf("dispatchReply(%s seq %d) returned false", op, seq)
				}
			}

			okReply(gpuproto.OpSubmit, submitSeq, 1)
			okReply(gpuproto.OpResUnref, unrefSeq, 1)
			okReply(gpuproto.OpCtxCreate, createSeq, 2)

			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost after FIFO replies: %v", err)
			}
			select {
			case r := <-createCall.done:
				if r.err != nil {
					t.Fatalf("CTX_CREATE result error = %v, want nil", r.err)
				}
			default:
				t.Fatal("CTX_CREATE did not receive reply")
			}
		})
	})

	t.Run("three 20s submits total 60s without loss", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, cleanup := newSynctestDeadlineClient(t)
			defer cleanup()

			seqs := make([]uint32, 3)
			for i := range seqs {
				cl := &call{op: gpuproto.OpSubmit, ctxID: 1, timeout: DefaultSubmitTimeout}
				seq, err := c.register(cl)
				if err != nil {
					t.Fatalf("register SUBMIT %d: %v", i, err)
				}
				c.markWritten(cl)
				seqs[i] = seq
			}

			for i, seq := range seqs {
				time.Sleep(20 * time.Second)
				synctest.Wait()
				if err := c.lostErr(); err != nil {
					t.Fatalf("client lost during SUBMIT %d at 20s: %v", i, err)
				}
				hdr := gpuproto.Header{
					Magic:  gpuproto.Magic,
					Op:     gpuproto.OpSubmit,
					Flags:  gpuproto.FlagReply,
					Seq:    seq,
					CtxID:  1,
					Status: gpuproto.StatusOK,
				}
				if !c.dispatchReply(hdr, nil, nil) {
					t.Fatalf("dispatchReply(SUBMIT seq %d) returned false", seq)
				}
			}
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost after three 20s submits: %v", err)
			}
		})
	})

	t.Run("unanswered head loses renderer after its own budget", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, cleanup := newSynctestDeadlineClient(t)
			defer cleanup()

			submitCall := &call{op: gpuproto.OpSubmit, ctxID: 1, timeout: DefaultSubmitTimeout}
			if _, err := c.register(submitCall); err != nil {
				t.Fatalf("register SUBMIT: %v", err)
			}
			c.markWritten(submitCall)

			time.Sleep(DefaultSubmitTimeout - 200*time.Millisecond)
			synctest.Wait()
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost before 30s budget: %v", err)
			}

			time.Sleep(400 * time.Millisecond)
			synctest.Wait()
			err := c.lostErr()
			if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.Is(err, ErrRendererHung) {
				t.Fatalf("lostErr = %v, want ErrRendererLost and ErrRendererHung", err)
			}
		})
	})

	t.Run("write completion starts budget clock", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, cleanup := newSynctestDeadlineClient(t)
			defer cleanup()

			submitCall := &call{op: gpuproto.OpSubmit, ctxID: 1, timeout: DefaultSubmitTimeout}
			seq, err := c.register(submitCall)
			if err != nil {
				t.Fatalf("register SUBMIT: %v", err)
			}

			// Simulate a 20s write before markWritten runs, then 25s of server work.
			time.Sleep(20 * time.Second)
			synctest.Wait()
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost before write completed: %v", err)
			}
			c.markWritten(submitCall)

			time.Sleep(25 * time.Second)
			synctest.Wait()
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost 25s after write completion: %v", err)
			}
			hdr := gpuproto.Header{
				Magic:  gpuproto.Magic,
				Op:     gpuproto.OpSubmit,
				Flags:  gpuproto.FlagReply,
				Seq:    seq,
				CtxID:  1,
				Status: gpuproto.StatusOK,
			}
			if !c.dispatchReply(hdr, nil, nil) {
				t.Fatal("dispatchReply returned false")
			}
		})
	})

	t.Run("follower budget starts when previous head finishes", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			c, cleanup := newSynctestDeadlineClient(t)
			defer cleanup()

			submitCall := &call{op: gpuproto.OpSubmit, ctxID: 1, timeout: DefaultSubmitTimeout}
			createCall := &call{op: gpuproto.OpCtxCreate, ctxID: 2, timeout: DefaultRequestTimeout, done: make(chan result, 1)}

			submitSeq, err := c.register(submitCall)
			if err != nil {
				t.Fatalf("register SUBMIT: %v", err)
			}
			c.markWritten(submitCall)
			if _, err := c.register(createCall); err != nil {
				t.Fatalf("register CTX_CREATE: %v", err)
			}
			c.markWritten(createCall)

			time.Sleep(25 * time.Second)
			synctest.Wait()
			hdr := gpuproto.Header{
				Magic:  gpuproto.Magic,
				Op:     gpuproto.OpSubmit,
				Flags:  gpuproto.FlagReply,
				Seq:    submitSeq,
				CtxID:  1,
				Status: gpuproto.StatusOK,
			}
			if !c.dispatchReply(hdr, nil, nil) {
				t.Fatal("dispatchReply(SUBMIT) returned false")
			}

			// CTX_CREATE now gets its full 10s budget starting at 25s.
			time.Sleep(DefaultRequestTimeout - 200*time.Millisecond)
			synctest.Wait()
			if err := c.lostErr(); err != nil {
				t.Fatalf("client lost before follower 10s budget: %v", err)
			}

			time.Sleep(400 * time.Millisecond)
			synctest.Wait()
			err = c.lostErr()
			if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.Is(err, ErrRendererHung) {
				t.Fatalf("lostErr = %v, want ErrRendererLost and ErrRendererHung", err)
			}
		})
	})
}
