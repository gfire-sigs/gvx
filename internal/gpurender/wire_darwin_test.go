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
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

type wireTestSink struct {
	fenceDone    chan uint64
	ctxLost      chan uint32
	rendererLost chan error
}

func newWireTestSink() *wireTestSink {
	return &wireTestSink{
		fenceDone:    make(chan uint64, 16),
		ctxLost:      make(chan uint32, 16),
		rendererLost: make(chan error, 16),
	}
}

func (s *wireTestSink) FenceDone(_, _ uint32, fenceID uint64) {
	select {
	case s.fenceDone <- fenceID:
	default:
	}
}

func (s *wireTestSink) ContextLost(ctxID uint32) {
	select {
	case s.ctxLost <- ctxID:
	default:
	}
}

func (s *wireTestSink) RendererLost(err error) {
	select {
	case s.rendererLost <- err:
	default:
	}
}

// snapshotOpenFDs returns every open descriptor below limit without opening
// any extra descriptor itself.
func snapshotOpenFDs(limit int) map[int]struct{} {
	open := make(map[int]struct{})
	for fd := range limit {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
			open[fd] = struct{}{}
		}
	}
	return open
}

func assertNoFDLeaks(t *testing.T, before map[int]struct{}, limit int) {
	t.Helper()
	after := snapshotOpenFDs(limit)
	var leaked []int
	for fd := range after {
		if _, existed := before[fd]; !existed {
			leaked = append(leaked, fd)
		}
	}
	if len(leaked) > 0 {
		t.Fatalf("leaked open descriptors: %v", leaked)
	}
}

func newWireTestClient(t *testing.T, reqTimeout time.Duration) (*Client, int, *wireTestSink, func()) {
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
	parentFile := os.NewFile(uintptr(fds[0]), "wire-test-client")
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

	opts := Options{RequestTimeout: reqTimeout}.withDefaults()
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

	c.wg.Add(1)
	go c.readLoop()

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

func waitRendererLost(t *testing.T, sink *wireTestSink) error {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case err := <-sink.rendererLost:
		if !errors.Is(err, gpuproto.ErrRendererLost) {
			t.Fatalf("RendererLost error = %v, want ErrRendererLost", err)
		}
		return err
	case <-timer.C:
		t.Fatal("timed out waiting for RendererLost")
		return nil
	}
}

func openDevNullFDs(t *testing.T, count int) ([]int, func()) {
	t.Helper()
	fds := make([]int, 0, count)
	closeAll := func() {
		for _, f := range fds {
			_ = unix.Close(f)
		}
		fds = nil
	}
	for range count {
		f, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			closeAll()
			t.Fatalf("open /dev/null: %v", err)
		}
		fds = append(fds, f)
	}
	return fds, closeAll
}

func TestReadRejectsMultipleDescriptorsWithoutLeak(t *testing.T) {
	const fdScanLimit = 4096
	for _, count := range []int{2, 5, 254} {
		t.Run(fmt.Sprintf("%d_fds", count), func(t *testing.T) {
			before := snapshotOpenFDs(fdScanLimit)
			_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

			sendFDs, closeSendFDs := openDevNullFDs(t, count)
			hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
				Magic:  gpuproto.Magic,
				Op:     gpuproto.OpBlobCreate,
				Flags:  gpuproto.FlagReply | gpuproto.FlagFD,
				Seq:    1,
				CtxID:  1,
				Status: gpuproto.StatusOK,
			})
			oob := unix.UnixRights(sendFDs...)
			if err := unix.Sendmsg(peerFD, hdr, oob, nil, 0); err != nil {
				closeSendFDs()
				cleanup()
				t.Fatalf("Sendmsg(%d fds): %v", count, err)
			}
			closeSendFDs()

			err := waitRendererLost(t, sink)
			if !strings.Contains(err.Error(), "protocol error") {
				t.Fatalf("RendererLost error = %v, want protocol error", err)
			}
			cleanup()
			assertNoFDLeaks(t, before, fdScanLimit)
		})
	}
}

func TestReadRejectsDescriptorAfterHeaderByteZero(t *testing.T) {
	const fdScanLimit = 4096
	before := snapshotOpenFDs(fdScanLimit)
	_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

	hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:  gpuproto.Magic,
		Op:     gpuproto.OpBlobCreate,
		Flags:  gpuproto.FlagReply | gpuproto.FlagFD,
		Seq:    1,
		CtxID:  1,
		Status: gpuproto.StatusOK,
	})
	if _, err := unix.Write(peerFD, hdr[:12]); err != nil {
		cleanup()
		t.Fatalf("Write first 12 header bytes: %v", err)
	}
	sendFDs, closeSendFDs := openDevNullFDs(t, 1)
	if err := unix.Sendmsg(peerFD, hdr[12:], unix.UnixRights(sendFDs...), nil, 0); err != nil {
		closeSendFDs()
		cleanup()
		t.Fatalf("Sendmsg tail header bytes with fd: %v", err)
	}
	closeSendFDs()

	err := waitRendererLost(t, sink)
	if !strings.Contains(err.Error(), "after byte 0") {
		t.Fatalf("RendererLost error = %v, want descriptor-after-byte-0 protocol error", err)
	}
	cleanup()
	assertNoFDLeaks(t, before, fdScanLimit)
}

func TestReadRejectsDescriptorOnPayloadWithoutLeak(t *testing.T) {
	const fdScanLimit = 4096
	for _, count := range []int{1, 5} {
		t.Run(fmt.Sprintf("%d_payload_fds", count), func(t *testing.T) {
			before := snapshotOpenFDs(fdScanLimit)
			_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

			payload := gpuproto.AppendPayload(nil, gpuproto.FenceDoneEvent{RingIdx: 0, FenceID: 7})
			hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpFenceDone,
				Flags:      gpuproto.FlagEvent,
				Seq:        0,
				CtxID:      1,
				PayloadLen: uint32(len(payload)),
				Status:     gpuproto.StatusOK,
			})
			if _, err := unix.Write(peerFD, hdr); err != nil {
				cleanup()
				t.Fatalf("Write header: %v", err)
			}
			sendFDs, closeSendFDs := openDevNullFDs(t, count)
			if err := unix.Sendmsg(peerFD, payload, unix.UnixRights(sendFDs...), nil, 0); err != nil {
				closeSendFDs()
				cleanup()
				t.Fatalf("Sendmsg payload with %d fds: %v", count, err)
			}
			closeSendFDs()

			err := waitRendererLost(t, sink)
			if !strings.Contains(err.Error(), "payload") {
				t.Fatalf("RendererLost error = %v, want payload descriptor protocol error", err)
			}
			cleanup()
			assertNoFDLeaks(t, before, fdScanLimit)
		})
	}
}

func TestReadRejectsFlagFDMismatchWithoutLeak(t *testing.T) {
	const fdScanLimit = 4096

	t.Run("FlagFD set without descriptor", func(t *testing.T) {
		before := snapshotOpenFDs(fdScanLimit)
		_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:  gpuproto.Magic,
			Op:     gpuproto.OpBlobCreate,
			Flags:  gpuproto.FlagReply | gpuproto.FlagFD,
			Seq:    1,
			CtxID:  1,
			Status: gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, hdr); err != nil {
			cleanup()
			t.Fatalf("Write header: %v", err)
		}

		err := waitRendererLost(t, sink)
		if !strings.Contains(err.Error(), "FlagFD") {
			t.Fatalf("RendererLost error = %v, want FlagFD mismatch", err)
		}
		cleanup()
		assertNoFDLeaks(t, before, fdScanLimit)
	})

	t.Run("FlagFD clear with descriptor", func(t *testing.T) {
		before := snapshotOpenFDs(fdScanLimit)
		_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:  gpuproto.Magic,
			Op:     gpuproto.OpCtxCreate,
			Flags:  gpuproto.FlagReply,
			Seq:    1,
			CtxID:  1,
			Status: gpuproto.StatusOK,
		})
		sendFDs, closeSendFDs := openDevNullFDs(t, 1)
		if err := unix.Sendmsg(peerFD, hdr, unix.UnixRights(sendFDs...), nil, 0); err != nil {
			closeSendFDs()
			cleanup()
			t.Fatalf("Sendmsg header with unexpected fd: %v", err)
		}
		closeSendFDs()

		err := waitRendererLost(t, sink)
		if !strings.Contains(err.Error(), "FlagFD") {
			t.Fatalf("RendererLost error = %v, want FlagFD mismatch", err)
		}
		cleanup()
		assertNoFDLeaks(t, before, fdScanLimit)
	})
}

func TestExtractAndCloexecFDsRecoversTruncatedRights(t *testing.T) {
	// Open 4 descriptors without O_CLOEXEC to verify extractAndCloexecFDs
	// both extracts them from a truncated SCM_RIGHTS buffer and sets FD_CLOEXEC.
	var fds []int
	for range 4 {
		f, err := unix.Open("/dev/null", unix.O_RDONLY, 0)
		if err != nil {
			for _, openFD := range fds {
				_ = unix.Close(openFD)
			}
			t.Fatalf("open /dev/null: %v", err)
		}
		fds = append(fds, f)
	}
	defer func() {
		for _, f := range fds {
			_ = unix.Close(f)
		}
	}()

	// Build a 5-fd SCM_RIGHTS control message and truncate the last fd to mimic
	// XNU MSG_CTRUNC where cmsg_len exceeds len(oob).
	full := unix.UnixRights(fds[0], fds[1], fds[2], fds[3], fds[3])
	truncated := full[:unix.CmsgLen(4*4)]

	got, err := extractAndCloexecFDs(truncated, nil)
	if err == nil {
		t.Fatal("extractAndCloexecFDs(truncated) error = nil, want error")
	}
	if len(got) != 4 {
		t.Fatalf("recovered %d descriptors (%v), want 4", len(got), got)
	}
	for i, f := range got {
		if f != fds[i] {
			t.Fatalf("recovered[%d] = %d, want %d", i, f, fds[i])
		}
		flags, ferr := unix.FcntlInt(uintptr(f), unix.F_GETFD, 0)
		if ferr != nil {
			t.Fatalf("F_GETFD(%d): %v", f, ferr)
		}
		if flags&unix.FD_CLOEXEC == 0 {
			t.Fatalf("fd %d missing FD_CLOEXEC after recovery", f)
		}
	}
}

func TestReadMidFrameStallTriggersRendererHung(t *testing.T) {
	t.Run("partial header stall", func(t *testing.T) {
		_, peerFD, sink, cleanup := newWireTestClient(t, 150*time.Millisecond)
		defer cleanup()

		payloadLen := uint32(len(gpuproto.AppendPayload(nil, gpuproto.FenceDoneEvent{})))
		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpFenceDone,
			Flags:      gpuproto.FlagEvent,
			CtxID:      1,
			PayloadLen: payloadLen,
			Status:     gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, hdr[:10]); err != nil {
			t.Fatalf("Write partial header: %v", err)
		}

		err := waitRendererLost(t, sink)
		if !errors.Is(err, ErrRendererHung) {
			t.Fatalf("RendererLost error = %v, want ErrRendererHung", err)
		}
	})

	t.Run("partial payload stall", func(t *testing.T) {
		_, peerFD, sink, cleanup := newWireTestClient(t, 150*time.Millisecond)
		defer cleanup()

		payload := gpuproto.AppendPayload(nil, gpuproto.FenceDoneEvent{RingIdx: 0, FenceID: 9})
		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpFenceDone,
			Flags:      gpuproto.FlagEvent,
			CtxID:      1,
			PayloadLen: uint32(len(payload)),
			Status:     gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, append(hdr, payload[:4]...)); err != nil {
			t.Fatalf("Write header + partial payload: %v", err)
		}

		err := waitRendererLost(t, sink)
		if !errors.Is(err, ErrRendererHung) {
			t.Fatalf("RendererLost error = %v, want ErrRendererHung", err)
		}
	})

	t.Run("idle frame boundary does not time out", func(t *testing.T) {
		_, peerFD, sink, cleanup := newWireTestClient(t, 100*time.Millisecond)
		defer cleanup()

		// Verify idle wait longer than RequestTimeout does not lose the client.
		idleTimer := time.NewTimer(200 * time.Millisecond)
		defer idleTimer.Stop()
		select {
		case err := <-sink.rendererLost:
			t.Fatalf("unexpected RendererLost during idle frame boundary: %v", err)
		case <-idleTimer.C:
		}

		payload := gpuproto.AppendPayload(nil, gpuproto.FenceDoneEvent{RingIdx: 0, FenceID: 42})
		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpFenceDone,
			Flags:      gpuproto.FlagEvent,
			CtxID:      1,
			PayloadLen: uint32(len(payload)),
			Status:     gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, append(hdr, payload...)); err != nil {
			t.Fatalf("Write FENCE_DONE after idle: %v", err)
		}

		waitTimer := time.NewTimer(time.Second)
		defer waitTimer.Stop()
		select {
		case fid := <-sink.fenceDone:
			if fid != 42 {
				t.Fatalf("FenceDone = %d, want 42", fid)
			}
		case err := <-sink.rendererLost:
			t.Fatalf("unexpected RendererLost: %v", err)
		case <-waitTimer.C:
			t.Fatal("timed out waiting for FenceDone after idle")
		}
	})
}

func TestReadRejectsProtocolErrorsWithoutDeadlock(t *testing.T) {
	t.Run("unknown reply seq", func(t *testing.T) {
		_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)
		defer cleanup()

		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:  gpuproto.Magic,
			Op:     gpuproto.OpCtxCreate,
			Flags:  gpuproto.FlagReply,
			Seq:    99,
			CtxID:  1,
			Status: gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, hdr); err != nil {
			t.Fatalf("Write unsolicited reply: %v", err)
		}

		err := waitRendererLost(t, sink)
		if !strings.Contains(err.Error(), "unexpected reply seq 99") {
			t.Fatalf("RendererLost error = %v, want unexpected reply seq 99", err)
		}
	})

	t.Run("mismatched reply op and ctx", func(t *testing.T) {
		c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)
		defer cleanup()

		cl := &call{
			op:      gpuproto.OpCtxCreate,
			ctxID:   1,
			timeout: 2 * time.Second,
			done:    make(chan result, 1),
		}
		seq, err := c.register(cl)
		if err != nil {
			t.Fatalf("register: %v", err)
		}

		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:  gpuproto.Magic,
			Op:     gpuproto.OpCtxDestroy,
			Flags:  gpuproto.FlagReply,
			Seq:    seq,
			CtxID:  2,
			Status: gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, hdr); err != nil {
			t.Fatalf("Write mismatched reply: %v", err)
		}

		err = waitRendererLost(t, sink)
		if !strings.Contains(err.Error(), "does not match call") {
			t.Fatalf("RendererLost error = %v, want call mismatch error", err)
		}
	})

	t.Run("unknown CTX_LOST reason", func(t *testing.T) {
		_, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)
		defer cleanup()

		payload := gpuproto.AppendPayload(nil, gpuproto.CtxLostEvent{Reason: 99})
		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpCtxLost,
			Flags:      gpuproto.FlagEvent,
			CtxID:      1,
			PayloadLen: uint32(len(payload)),
			Status:     gpuproto.StatusOK,
		})
		if _, err := unix.Write(peerFD, append(hdr, payload...)); err != nil {
			t.Fatalf("Write bad CTX_LOST: %v", err)
		}

		err := waitRendererLost(t, sink)
		if !strings.Contains(err.Error(), "CTX_LOST unknown reason 99") {
			t.Fatalf("RendererLost error = %v, want unknown CTX_LOST reason", err)
		}
	})

	t.Run("malformed TEST_CONFINE reply", func(t *testing.T) {
		badReplies := []struct {
			name string
			rep  gpuproto.TestConfineReply
		}{
			{
				name: "wrong check count",
				rep: gpuproto.TestConfineReply{
					Checks:  gpuproto.ConfineChecks + 1,
					Results: [8]uint8{1, 1, 1, 1, 1},
				},
			},
			{
				name: "counted check not run",
				rep: gpuproto.TestConfineReply{
					Checks:  gpuproto.ConfineChecks,
					Results: [8]uint8{1, 1, 0, 1, 1},
				},
			},
			{
				name: "non-zero unused result slot",
				rep: gpuproto.TestConfineReply{
					Checks:  gpuproto.ConfineChecks,
					Results: [8]uint8{1, 1, 1, 1, 1, 1},
				},
			},
		}
		for _, tc := range badReplies {
			t.Run(tc.name, func(t *testing.T) {
				c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)
				defer cleanup()

				cl := &call{
					op:      gpuproto.OpTestConfine,
					timeout: 2 * time.Second,
					done:    make(chan result, 1),
				}
				seq, err := c.register(cl)
				if err != nil {
					t.Fatalf("register: %v", err)
				}
				payload := gpuproto.AppendPayload(nil, tc.rep)
				hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
					Magic:      gpuproto.Magic,
					Op:         gpuproto.OpTestConfine,
					Flags:      gpuproto.FlagReply,
					Seq:        seq,
					CtxID:      0,
					PayloadLen: uint32(len(payload)),
					Status:     gpuproto.StatusOK,
				})
				if _, err := unix.Write(peerFD, append(hdr, payload...)); err != nil {
					t.Fatalf("Write bad TEST_CONFINE reply: %v", err)
				}
				err = waitRendererLost(t, sink)
				if !strings.Contains(err.Error(), "protocol error") {
					t.Fatalf("RendererLost error = %v, want protocol error", err)
				}
			})
		}
	})
}

func TestRendererEnvironment(t *testing.T) {
	const exe = "/opt/gvx/bin/gvx-gpu-renderer"
	wantDefault := append([]string(nil), defaultDriverEnv...)
	wantWithTest := append(append([]string(nil), defaultDriverEnv...), gpuproto.EnvTestMode+"=1")

	t.Run("default options", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe})
		if !slices.Equal(args, []string{exe}) {
			t.Fatalf("args = %v, want [%s]", args, exe)
		}
		if env == nil {
			t.Fatal("default env is nil; must stay non-nil to scrub host environment")
		}
		if !slices.Equal(env, wantDefault) {
			t.Fatalf("env = %v, want %v", env, wantDefault)
		}
		for _, kv := range env {
			if strings.HasPrefix(kv, gpuproto.EnvTestMode+"=") {
				t.Fatalf("default env unexpectedly contains %s", kv)
			}
		}
	})

	t.Run("TestOps adds env without argv", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, TestOps: true})
		if !slices.Equal(args, []string{exe}) {
			t.Fatalf("args = %v, want [%s]", args, exe)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("StallFences adds arg and env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, StallFences: true})
		if !slices.Equal(args, []string{exe, gpuproto.ArgStallFences}) {
			t.Fatalf("args = %v, want [%s %s]", args, exe, gpuproto.ArgStallFences)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("TestWatchdogBytes adds arg and env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, TestWatchdogBytes: 1048576})
		wantArg := gpuproto.ArgTestWatchdogBytes + "1048576"
		if !slices.Equal(args, []string{exe, wantArg}) {
			t.Fatalf("args = %v, want [%s %s]", args, exe, wantArg)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("MemoryLimit adds arg without test env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, MemoryLimit: 4 << 30})
		wantArg := gpuproto.ArgMemoryLimit + "4294967296"
		if !slices.Equal(args, []string{exe, wantArg}) {
			t.Fatalf("args = %v, want [%s %s]", args, exe, wantArg)
		}
		if !slices.Equal(env, wantDefault) {
			t.Fatalf("env = %v, want %v", env, wantDefault)
		}
	})
}

func TestPeerClosePreservesExitError(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("exit %d", gpuproto.ExitMemoryLimit))
	_ = cmd.Run()
	exitState := cmd.ProcessState
	if exitState == nil || !exitState.Exited() || exitState.ExitCode() != gpuproto.ExitMemoryLimit {
		t.Fatalf("helper process state = %v, want exited with %d", exitState, gpuproto.ExitMemoryLimit)
	}

	newClientWithDelayedExit := func(t *testing.T, startReadLoop bool) (*Client, int, *wireTestSink, chan struct{}) {
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
		parentFile := os.NewFile(uintptr(fds[0]), "peer-close-test")
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

		exited := make(chan struct{})
		c := &Client{
			opts:     Options{RequestTimeout: time.Second}.withDefaults(),
			conn:     uc,
			raw:      raw,
			readOOB:  make([]byte, unix.CmsgSpace(maxControlFDs*4)),
			proc:     &process{exited: exited, state: exitState},
			capsets:  make(map[capsetKey][]byte),
			writeSem: make(chan struct{}, 1),
			failed:   make(chan struct{}),
			done:     make(chan struct{}),
			nextSeq:  1,
			pending:  make(map[uint32]*call),
		}
		sink := newWireTestSink()
		c.SetEventSink(sink)
		if startReadLoop {
			c.wg.Add(1)
			go c.readLoop()
		}
		t.Cleanup(func() {
			c.lose(errClosed, false)
			c.wg.Wait()
		})
		return c, fds[1], sink, exited
	}

	t.Run("unexpected EOF mid-payload", func(t *testing.T) {
		_, peerFD, sink, exited := newClientWithDelayedExit(t, true)
		hdr := gpuproto.AppendHeader(nil, gpuproto.Header{
			Magic:      gpuproto.Magic,
			Op:         gpuproto.OpFenceDone,
			Flags:      gpuproto.FlagEvent,
			CtxID:      1,
			PayloadLen: 16,
		})
		partial := append(hdr, 1, 2, 3, 4)
		if _, err := unix.Write(peerFD, partial); err != nil {
			_ = unix.Close(peerFD)
			t.Fatalf("Write partial frame: %v", err)
		}
		_ = unix.Close(peerFD)
		time.AfterFunc(15*time.Millisecond, func() { close(exited) })

		lostErr := waitRendererLost(t, sink)
		var ee *ExitError
		if !errors.Is(lostErr, gpuproto.ErrRendererLost) || !errors.As(lostErr, &ee) || ee.Code != gpuproto.ExitMemoryLimit {
			t.Fatalf("RendererLost = %v, want *ExitError{Code:%d}", lostErr, gpuproto.ExitMemoryLimit)
		}
	})

	t.Run("EPIPE on writeFrameLocked", func(t *testing.T) {
		c, peerFD, _, exited := newClientWithDelayedExit(t, false)
		_ = unix.Close(peerFD)
		time.AfterFunc(15*time.Millisecond, func() { close(exited) })

		err := c.Submit(1, make([]byte, 128), nil)
		var ee *ExitError
		if !errors.Is(err, gpuproto.ErrRendererLost) || !errors.As(err, &ee) || ee.Code != gpuproto.ExitMemoryLimit {
			t.Fatalf("Submit error = %v, want *ExitError{Code:%d}", err, gpuproto.ExitMemoryLimit)
		}
	})
}
