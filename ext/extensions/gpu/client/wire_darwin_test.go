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
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"z.gfire.dev/gvx/ext/extensions/gpu/gpuproto"
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
	const defaultModeArg = gpuproto.ArgMode + gpuproto.ModeNameVenus
	wantDefault := append([]string(nil), defaultDriverEnv...)
	wantWithTest := append(append([]string(nil), defaultDriverEnv...), gpuproto.EnvTestMode+"=1")

	t.Run("default options", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe})
		if !slices.Equal(args, []string{exe, defaultModeArg}) {
			t.Fatalf("args = %v, want [%s %s]", args, exe, defaultModeArg)
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
		if !slices.Equal(args, []string{exe, defaultModeArg}) {
			t.Fatalf("args = %v, want [%s %s]", args, exe, defaultModeArg)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("StallFences adds arg and env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, StallFences: true})
		if !slices.Equal(args, []string{exe, defaultModeArg, gpuproto.ArgStallFences}) {
			t.Fatalf("args = %v, want [%s %s %s]", args, exe, defaultModeArg, gpuproto.ArgStallFences)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("TestWatchdogBytes adds arg and env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, TestWatchdogBytes: 1048576})
		wantArg := gpuproto.ArgTestWatchdogBytes + "1048576"
		if !slices.Equal(args, []string{exe, defaultModeArg, wantArg}) {
			t.Fatalf("args = %v, want [%s %s %s]", args, exe, defaultModeArg, wantArg)
		}
		if !slices.Equal(env, wantWithTest) {
			t.Fatalf("env = %v, want %v", env, wantWithTest)
		}
	})

	t.Run("MemoryLimit adds arg without test env", func(t *testing.T) {
		args, env := rendererCommandLine(Options{Path: exe, MemoryLimit: 4 << 30})
		wantArg := gpuproto.ArgMemoryLimit + "4294967296"
		if !slices.Equal(args, []string{exe, defaultModeArg, wantArg}) {
			t.Fatalf("args = %v, want [%s %s %s]", args, exe, defaultModeArg, wantArg)
		}
		if !slices.Equal(env, wantDefault) {
			t.Fatalf("env = %v, want %v", env, wantDefault)
		}
	})
}

func TestRendererCommandLineHasMode(t *testing.T) {
	const exe = "/opt/gvx/bin/gvx-gpu-renderer"

	args, _ := rendererCommandLine(Options{Path: exe})
	wantVenus := []string{exe, gpuproto.ArgMode + gpuproto.ModeNameVenus}
	if !slices.Equal(args, wantVenus) {
		t.Fatalf("default args = %v, want %v", args, wantVenus)
	}

	args, _ = rendererCommandLine(Options{Path: exe, Mode: gpuproto.ModeVenus})
	if !slices.Equal(args, wantVenus) {
		t.Fatalf("venus args = %v, want %v", args, wantVenus)
	}

	args, _ = rendererCommandLine(Options{Path: exe, Mode: gpuproto.ModeVirgl})
	wantVirgl := []string{exe, gpuproto.ArgMode + gpuproto.ModeNameVirgl}
	if !slices.Equal(args, wantVirgl) {
		t.Fatalf("virgl args = %v, want %v", args, wantVirgl)
	}

	args, _ = rendererCommandLine(Options{Path: exe, Mode: gpuproto.ModeVirgl, MemoryLimit: 1024})
	wantVirglMem := []string{exe, gpuproto.ArgMode + gpuproto.ModeNameVirgl, gpuproto.ArgMemoryLimit + "1024"}
	if !slices.Equal(args, wantVirglMem) {
		t.Fatalf("virgl+memory args = %v, want %v", args, wantVirglMem)
	}
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

const (
	fakePeerScenarioEnv = "GVX_GPU_TEST_FAKE_PEER"
	fakePeerPIDFileEnv  = "GVX_GPU_TEST_FAKE_PEER_PIDFILE"
)

// TestFakePeerHelper runs the fake peer child process when a scripted Start
// handshake test sets GVX_GPU_TEST_FAKE_PEER.
func TestFakePeerHelper(t *testing.T) {
	scenario := os.Getenv(fakePeerScenarioEnv)
	if scenario == "" {
		return
	}
	if pidFile := os.Getenv(fakePeerPIDFileEnv); pidFile != "" {
		_ = os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0o600)
	}

	sock := os.NewFile(uintptr(gpuproto.SocketFD), "fake-peer-sock")
	if sock == nil {
		os.Exit(11)
	}
	defer sock.Close()

	var hdrBuf [gpuproto.HeaderSize]byte
	if _, err := io.ReadFull(sock, hdrBuf[:]); err != nil {
		os.Exit(12)
	}
	hdr, err := gpuproto.ParseHeader(hdrBuf[:], gpuproto.ToRenderer)
	if err != nil || hdr.Op != gpuproto.OpHello {
		os.Exit(13)
	}
	reqPayload := make([]byte, hdr.PayloadLen)
	if _, err := io.ReadFull(sock, reqPayload); err != nil {
		os.Exit(14)
	}

	var hello gpuproto.HelloInfo
	switch scenario {
	case "mode_mismatch":
		hello = gpuproto.HelloInfo{
			Mode:  gpuproto.ModeVenus,
			Build: "fake-peer",
			Caps:  []gpuproto.CapsetInfo{{ID: gpuproto.CapsetVenus, MaxVersion: 0, MaxSize: 64}},
		}
	case "foreign_capset":
		hello = gpuproto.HelloInfo{
			Mode:  gpuproto.ModeVirgl,
			Build: "fake-peer",
			Caps: []gpuproto.CapsetInfo{
				{ID: gpuproto.CapsetVirgl2, MaxVersion: 0, MaxSize: 64},
				{ID: gpuproto.CapsetVenus, MaxVersion: 0, MaxSize: 64},
			},
		}
	case "duplicate_capset":
		hello = gpuproto.HelloInfo{
			Mode:  gpuproto.ModeVirgl,
			Build: "fake-peer",
			Caps: []gpuproto.CapsetInfo{
				{ID: gpuproto.CapsetVirgl2, MaxVersion: 0, MaxSize: 64},
				{ID: gpuproto.CapsetVirgl2, MaxVersion: 0, MaxSize: 64},
			},
		}
	case "missing_primary":
		hello = gpuproto.HelloInfo{
			Mode:  gpuproto.ModeVirgl,
			Build: "fake-peer",
			Caps:  []gpuproto.CapsetInfo{{ID: gpuproto.CapsetVirgl, MaxVersion: 1, MaxSize: 308}},
		}
	default:
		os.Exit(15)
	}

	repPayload, err := gpuproto.AppendHello(nil, hello)
	if err != nil {
		os.Exit(16)
	}
	repHdr := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:      gpuproto.Magic,
		Op:         gpuproto.OpHello,
		Flags:      gpuproto.FlagReply,
		Seq:        hdr.Seq,
		PayloadLen: uint32(len(repPayload)),
		Status:     gpuproto.StatusOK,
	})
	if _, err := sock.Write(append(repHdr, repPayload...)); err != nil {
		os.Exit(17)
	}
	// Hold open until the client closes or kills the peer so Start proves reaping.
	var drain [16]byte
	_, _ = sock.Read(drain[:])
	os.Exit(0)
}

func writeFakePeerScript(t *testing.T, scenario string) (scriptPath, pidFile string) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	dir := t.TempDir()
	pidFile = filepath.Join(dir, "peer.pid")
	scriptPath = filepath.Join(dir, "fake-peer.sh")
	script := fmt.Sprintf("#!/bin/sh\n%s=%q %s=%q exec %q -test.run=^TestFakePeerHelper$\n",
		fakePeerScenarioEnv, scenario, fakePeerPIDFileEnv, pidFile, exe)
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake peer script: %v", err)
	}
	return scriptPath, pidFile
}

func assertFakePeerReaped(t *testing.T, pidFile string) {
	t.Helper()
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read fake peer pid file %s: %v", pidFile, err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid fake peer pid %q: %v", string(raw), err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("Kill(%d, 0) after Start failure = %v, want ESRCH (process not reaped)", pid, err)
	}
}

func readPeerFrame(t *testing.T, peerFD int) (gpuproto.Header, []byte) {
	t.Helper()
	readExact := func(buf []byte) {
		t.Helper()
		got := 0
		for got < len(buf) {
			n, err := unix.Read(peerFD, buf[got:])
			if err == unix.EINTR {
				continue
			}
			if err != nil {
				t.Fatalf("peer Read: %v", err)
			}
			if n == 0 {
				t.Fatalf("peer Read: unexpected EOF at %d/%d", got, len(buf))
			}
			got += n
		}
	}
	var hdrBuf [gpuproto.HeaderSize]byte
	readExact(hdrBuf[:])
	hdr, err := gpuproto.ParseHeader(hdrBuf[:], gpuproto.ToRenderer)
	if err != nil {
		t.Fatalf("peer ParseHeader: %v", err)
	}
	var payload []byte
	if hdr.PayloadLen > 0 {
		payload = make([]byte, hdr.PayloadLen)
		readExact(payload)
	}
	return hdr, payload
}

func TestStartRejectsModeMismatch(t *testing.T) {
	t.Run("unknown mode starts no process", func(t *testing.T) {
		c, err := Start(context.Background(), Options{Path: "/nonexistent/gvx-gpu-renderer", Mode: 99})
		if c != nil {
			_ = c.Close()
			t.Fatal("Start accepted unknown mode 99")
		}
		var se *StartError
		if !errors.As(err, &se) {
			t.Fatalf("Start error = %v (%T), want *StartError", err, err)
		}
		if se.ExitCode != -1 {
			t.Fatalf("StartError.ExitCode = %d, want -1", se.ExitCode)
		}
		if !strings.Contains(err.Error(), "unknown renderer mode 99") {
			t.Fatalf("Start error = %q, want unknown renderer mode 99", err.Error())
		}
	})

	t.Run("HELLO replies venus to virgl start", func(t *testing.T) {
		script, pidFile := writeFakePeerScript(t, "mode_mismatch")
		c, err := Start(context.Background(), Options{
			Path:         script,
			Mode:         gpuproto.ModeVirgl,
			StartTimeout: 5 * time.Second,
		})
		if c != nil {
			_ = c.Close()
			t.Fatal("Start succeeded despite HELLO mode mismatch")
		}
		var se *StartError
		if !errors.As(err, &se) {
			t.Fatalf("Start error = %v (%T), want *StartError", err, err)
		}
		if !strings.Contains(err.Error(), gpuproto.ModeVenus.String()) || !strings.Contains(err.Error(), gpuproto.ModeVirgl.String()) {
			t.Fatalf("Start error = %q, want both %q and %q", err.Error(), gpuproto.ModeVenus, gpuproto.ModeVirgl)
		}
		assertFakePeerReaped(t, pidFile)
	})
}

func TestStartRejectsForeignCapset(t *testing.T) {
	for _, tc := range []struct {
		name     string
		scenario string
		wantText string
	}{
		{name: "venus capset in virgl start", scenario: "foreign_capset", wantText: "capset 4"},
		{name: "duplicate capset in virgl start", scenario: "duplicate_capset", wantText: "capset 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			script, pidFile := writeFakePeerScript(t, tc.scenario)
			c, err := Start(context.Background(), Options{
				Path:         script,
				Mode:         gpuproto.ModeVirgl,
				StartTimeout: 5 * time.Second,
			})
			if c != nil {
				_ = c.Close()
				t.Fatalf("Start succeeded for %s", tc.name)
			}
			var se *StartError
			if !errors.As(err, &se) {
				t.Fatalf("Start error = %v (%T), want *StartError", err, err)
			}
			if !strings.Contains(err.Error(), tc.wantText) || !strings.Contains(err.Error(), gpuproto.ModeVirgl.String()) {
				t.Fatalf("Start error = %q, want %q and %q", err.Error(), tc.wantText, gpuproto.ModeVirgl)
			}
			assertFakePeerReaped(t, pidFile)
		})
	}
}

func TestStartRejectsMissingPrimaryCapset(t *testing.T) {
	script, pidFile := writeFakePeerScript(t, "missing_primary")
	c, err := Start(context.Background(), Options{
		Path:         script,
		Mode:         gpuproto.ModeVirgl,
		StartTimeout: 5 * time.Second,
	})
	if c != nil {
		_ = c.Close()
		t.Fatal("Start succeeded without primary virgl capset")
	}
	var se *StartError
	if !errors.As(err, &se) {
		t.Fatalf("Start error = %v (%T), want *StartError", err, err)
	}
	if !strings.Contains(err.Error(), "no capset 2") || !strings.Contains(err.Error(), gpuproto.ModeVirgl.String()) {
		t.Fatalf("Start error = %q, want missing capset 2 for mode virgl", err.Error())
	}
	assertFakePeerReaped(t, pidFile)
}

func TestResCreateReplyWithoutFDLosesRenderer(t *testing.T) {
	const fdScanLimit = 4096
	before := snapshotOpenFDs(fdScanLimit)
	c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

	errCh := make(chan error, 1)
	go func() {
		blob, err := c.CreateResource(context.Background(), gpuproto.ResourceCreate{
			CtxID: 1,
			ResID: 10,
			Size:  16384,
		})
		if blob.Shm != nil {
			_ = blob.Shm.Close()
		}
		errCh <- err
	}()

	reqHdr, _ := readPeerFrame(t, peerFD)
	if reqHdr.Op != gpuproto.OpResCreate {
		cleanup()
		t.Fatalf("peer got op %s, want RES_CREATE", reqHdr.Op)
	}

	repPayload := gpuproto.AppendPayload(nil, gpuproto.ResCreateReply{
		HostSize: 16384,
		FDType:   gpuproto.FDTypeShm,
	})
	repHdr := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:      gpuproto.Magic,
		Op:         gpuproto.OpResCreate,
		Flags:      gpuproto.FlagReply, // missing FlagFD and descriptor
		Seq:        reqHdr.Seq,
		CtxID:      reqHdr.CtxID,
		PayloadLen: uint32(len(repPayload)),
		Status:     gpuproto.StatusOK,
	})
	if _, err := unix.Write(peerFD, append(repHdr, repPayload...)); err != nil {
		cleanup()
		t.Fatalf("Write RES_CREATE reply without FD: %v", err)
	}

	callErr := <-errCh
	if !errors.Is(callErr, gpuproto.ErrRendererLost) {
		cleanup()
		t.Fatalf("CreateResource error = %v, want ErrRendererLost", callErr)
	}
	lostErr := waitRendererLost(t, sink)
	if !strings.Contains(lostErr.Error(), "FlagFD") {
		cleanup()
		t.Fatalf("RendererLost error = %v, want FlagFD protocol error", lostErr)
	}
	cleanup()
	assertNoFDLeaks(t, before, fdScanLimit)
}

func TestResCreateReplyShortHostSizeLosesRenderer(t *testing.T) {
	const fdScanLimit = 4096
	cases := []struct {
		name    string
		reqSize uint64
		rep     gpuproto.ResCreateReply
	}{
		{
			name:    "host size below requested size",
			reqSize: 32768,
			rep:     gpuproto.ResCreateReply{HostSize: 16384, FDType: gpuproto.FDTypeShm},
		},
		{
			name:    "unaligned host size",
			reqSize: 4096,
			rep:     gpuproto.ResCreateReply{HostSize: 20480, FDType: gpuproto.FDTypeShm},
		},
		{
			name:    "host size above max",
			reqSize: 16384,
			rep:     gpuproto.ResCreateReply{HostSize: gpuproto.MaxBlobBytes + gpuproto.HostBlobAlign, FDType: gpuproto.FDTypeShm},
		},
		{
			name:    "wrong fd type",
			reqSize: 16384,
			rep:     gpuproto.ResCreateReply{HostSize: 16384, FDType: 1},
		},
		{
			name:    "non-zero reserved",
			reqSize: 16384,
			rep:     gpuproto.ResCreateReply{HostSize: 16384, FDType: gpuproto.FDTypeShm, Reserved: 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := snapshotOpenFDs(fdScanLimit)
			c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

			errCh := make(chan error, 1)
			go func() {
				blob, err := c.CreateResource(context.Background(), gpuproto.ResourceCreate{
					CtxID: 1,
					ResID: 10,
					Size:  tc.reqSize,
				})
				if blob.Shm != nil {
					_ = blob.Shm.Close()
				}
				errCh <- err
			}()

			reqHdr, _ := readPeerFrame(t, peerFD)
			repPayload := gpuproto.AppendPayload(nil, tc.rep)
			repHdr := gpuproto.AppendHeader(nil, gpuproto.Header{
				Magic:      gpuproto.Magic,
				Op:         gpuproto.OpResCreate,
				Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
				Seq:        reqHdr.Seq,
				CtxID:      reqHdr.CtxID,
				PayloadLen: uint32(len(repPayload)),
				Status:     gpuproto.StatusOK,
			})
			sendFDs, closeSendFDs := openDevNullFDs(t, 1)
			if err := unix.Sendmsg(peerFD, append(repHdr, repPayload...), unix.UnixRights(sendFDs...), nil, 0); err != nil {
				closeSendFDs()
				cleanup()
				t.Fatalf("Sendmsg RES_CREATE reply: %v", err)
			}
			closeSendFDs()

			callErr := <-errCh
			if !errors.Is(callErr, gpuproto.ErrRendererLost) {
				cleanup()
				t.Fatalf("CreateResource error = %v, want ErrRendererLost", callErr)
			}
			lostErr := waitRendererLost(t, sink)
			if !strings.Contains(lostErr.Error(), "protocol error") {
				cleanup()
				t.Fatalf("RendererLost error = %v, want protocol error", lostErr)
			}
			cleanup()
			assertNoFDLeaks(t, before, fdScanLimit)
		})
	}
}

func TestTransferReplyWithPayloadLosesRenderer(t *testing.T) {
	c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)
	defer cleanup()

	errCh := make(chan error, 1)
	go func() {
		errCh <- c.Transfer(context.Background(), gpuproto.Transfer{
			CtxID:     1,
			ResID:     10,
			Direction: gpuproto.TransferToHost,
			Box:       gpuproto.Box{W: 64, H: 1, D: 1},
		})
	}()

	reqHdr, _ := readPeerFrame(t, peerFD)
	if reqHdr.Op != gpuproto.OpTransfer {
		t.Fatalf("peer got op %s, want TRANSFER", reqHdr.Op)
	}

	repHdr := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:      gpuproto.Magic,
		Op:         gpuproto.OpTransfer,
		Flags:      gpuproto.FlagReply,
		Seq:        reqHdr.Seq,
		CtxID:      reqHdr.CtxID,
		PayloadLen: 4,
		Status:     gpuproto.StatusOK,
	})
	if _, err := unix.Write(peerFD, append(repHdr, 0, 0, 0, 0)); err != nil {
		t.Fatalf("Write TRANSFER reply with payload: %v", err)
	}

	callErr := <-errCh
	if !errors.Is(callErr, gpuproto.ErrRendererLost) {
		t.Fatalf("Transfer error = %v, want ErrRendererLost", callErr)
	}
	lostErr := waitRendererLost(t, sink)
	if !strings.Contains(lostErr.Error(), "payload length 4") {
		t.Fatalf("RendererLost error = %v, want payload length protocol error", lostErr)
	}
}

func TestCancelledCreateResourceIsUndone(t *testing.T) {
	const fdScanLimit = 4096
	before := snapshotOpenFDs(fdScanLimit)
	c, peerFD, sink, cleanup := newWireTestClient(t, 2*time.Second)

	const (
		ctxID = uint32(7)
		resID = uint32(42)
	)
	cctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		blob, err := c.CreateResource(cctx, gpuproto.ResourceCreate{
			CtxID: ctxID,
			ResID: resID,
			Size:  16384,
		})
		if blob.Shm != nil {
			_ = blob.Shm.Close()
		}
		errCh <- err
	}()

	reqHdr, _ := readPeerFrame(t, peerFD)
	if reqHdr.Op != gpuproto.OpResCreate || reqHdr.CtxID != ctxID {
		cleanup()
		t.Fatalf("peer got (%s, ctx %d), want (RES_CREATE, ctx %d)", reqHdr.Op, reqHdr.CtxID, ctxID)
	}

	cancel()
	select {
	case err := <-errCh:
		if !errors.Is(err, context.Canceled) {
			cleanup()
			t.Fatalf("cancelled CreateResource error = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		cleanup()
		t.Fatal("cancelled CreateResource did not return within 2s")
	}

	repPayload := gpuproto.AppendPayload(nil, gpuproto.ResCreateReply{
		HostSize: 16384,
		FDType:   gpuproto.FDTypeShm,
	})
	repHdr := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:      gpuproto.Magic,
		Op:         gpuproto.OpResCreate,
		Flags:      gpuproto.FlagReply | gpuproto.FlagFD,
		Seq:        reqHdr.Seq,
		CtxID:      ctxID,
		PayloadLen: uint32(len(repPayload)),
		Status:     gpuproto.StatusOK,
	})
	sendFDs, closeSendFDs := openDevNullFDs(t, 1)
	if err := unix.Sendmsg(peerFD, append(repHdr, repPayload...), unix.UnixRights(sendFDs...), nil, 0); err != nil {
		closeSendFDs()
		cleanup()
		t.Fatalf("Sendmsg delayed RES_CREATE OK reply: %v", err)
	}
	closeSendFDs()

	undoHdr, undoPayload := readPeerFrame(t, peerFD)
	if undoHdr.Op != gpuproto.OpResUnref || undoHdr.CtxID != ctxID {
		cleanup()
		t.Fatalf("undo frame = (%s, ctx %d), want (RES_UNREF, ctx %d)", undoHdr.Op, undoHdr.CtxID, ctxID)
	}
	unrefReq, err := gpuproto.DecodePayload[gpuproto.ResUnrefRequest](undoPayload)
	if err != nil {
		cleanup()
		t.Fatalf("DecodePayload(ResUnrefRequest): %v", err)
	}
	if unrefReq.ResID != resID {
		cleanup()
		t.Fatalf("undo ResUnrefRequest.ResID = %d, want %d", unrefReq.ResID, resID)
	}

	unrefReply := gpuproto.AppendHeader(nil, gpuproto.Header{
		Magic:  gpuproto.Magic,
		Op:     gpuproto.OpResUnref,
		Flags:  gpuproto.FlagReply,
		Seq:    undoHdr.Seq,
		CtxID:  ctxID,
		Status: gpuproto.StatusOK,
	})
	if _, err := unix.Write(peerFD, unrefReply); err != nil {
		cleanup()
		t.Fatalf("Write RES_UNREF reply: %v", err)
	}

	select {
	case lostErr := <-sink.rendererLost:
		cleanup()
		t.Fatalf("unexpected RendererLost during undo: %v", lostErr)
	default:
	}

	cleanup()
	assertNoFDLeaks(t, before, fdScanLimit)
}
