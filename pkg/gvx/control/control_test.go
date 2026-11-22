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

package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testHandler struct {
	mu               sync.Mutex
	legacyReqs       []LegacyCheckpointRequest
	streamHandler    func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error
	legacyHandlerErr error
}

func (h *testHandler) HandleStream(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
	if h.streamHandler != nil {
		return h.streamHandler(ctx, stream, req, fds)
	}
	closeFDs(fds)
	return stream.Reply(map[string]string{"method": req.Method})
}

func (h *testHandler) HandleLegacyCheckpoint(ctx context.Context, req LegacyCheckpointRequest) error {
	h.mu.Lock()
	h.legacyReqs = append(h.legacyReqs, req)
	err := h.legacyHandlerErr
	h.mu.Unlock()
	return err
}

func startTestServer(t *testing.T, addr string, opts ListenOptions, cfg ServerConfig) (*Endpoint, *Server, context.CancelFunc) {
	t.Helper()
	ep, err := Listen(addr, opts)
	if err != nil {
		t.Fatalf("Listen(%q): %v", addr, err)
	}
	if cfg.Token == "" {
		cfg.Token = ep.Token
	}
	if len(cfg.Capabilities) == 0 {
		cfg.Capabilities = []string{
			CapPing, CapInspect, CapCheckpointLocal, CapFSExport, CapFSImport, CapMountVolumeAttach, CapExec,
		}
	}
	srv := NewServer(ep.Listener, cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = srv.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
		<-done
		if ep.Cleanup != nil {
			ep.Cleanup()
		}
	})
	return ep, srv, cancel
}

func TestV2HandshakeAuthAndPolicy(t *testing.T) {
	handler := &testHandler{
		streamHandler: func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
			closeFDs(fds)
			if req.Method == MethodPing {
				return stream.Reply(PingResponse{Version: ProtocolVersion, SandboxID: "sbx-1", State: "running"})
			}
			return stream.Reply(nil)
		},
	}

	// Bind on TCP so a per-run token is automatically generated and enforced.
	caps := FilterCapabilities(
		[]string{CapPing, CapInspect, CapExec, CapFSExport, CapFSImport},
		PolicyReadOnly,
		[]string{"fs"},
	)
	ep, _, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:    "sbx-1",
		Capabilities: caps,
		Handler:      handler,
	})

	// Reject wrong token.
	if _, err := Dial(context.Background(), DialOptions{
		Endpoint: ep.Address,
		Token:    "wrong-token",
	}); !IsCode(err, CodeUnauthorized) {
		t.Fatalf("wrong token Dial error = %v, want UNAUTHORIZED", err)
	}

	// Connect with automatic token discovery from the token file.
	client, err := Dial(context.Background(), DialOptions{
		Endpoint: ep.Address,
	})
	if err != nil {
		t.Fatalf("Dial with auto token: %v", err)
	}
	defer client.Close()

	if client.SandboxID() != "sbx-1" {
		t.Fatalf("SandboxID = %q, want sbx-1", client.SandboxID())
	}
	if !client.HasCapability(CapPing) || client.HasCapability(CapExec) || client.HasCapability(CapFSExport) {
		t.Fatalf("unexpected capabilities after readonly+disable(fs): %v", client.Capabilities())
	}

	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("wire Ping: %v", err)
	}

	var pingResp PingResponse
	if err := client.Call(context.Background(), MethodPing, nil, &pingResp); err != nil {
		t.Fatalf("Call(system.ping): %v", err)
	}
	if pingResp.SandboxID != "sbx-1" || pingResp.State != "running" {
		t.Fatalf("unexpected PingResponse: %+v", pingResp)
	}

	// Disabled method must fail with FORBIDDEN_BY_POLICY.
	err = client.Call(context.Background(), MethodExecStart, ExecStartRequest{Argv: []string{"/bin/true"}}, nil)
	if !IsCode(err, CodeForbiddenByPolicy) {
		t.Fatalf("Call(exec.start) error = %v, want FORBIDDEN_BY_POLICY", err)
	}
}

func TestLegacyV1CheckpointCompatibility(t *testing.T) {
	handler := &testHandler{}
	ep, _, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:    "sbx-v1",
		Capabilities: []string{CapPing, CapCheckpointLocal},
		Handler:      handler,
	})

	sendLegacy := func(req LegacyCheckpointRequest) LegacyCheckpointResponse {
		conn, err := net.Dial("tcp", ep.Address)
		if err != nil {
			t.Fatalf("dial legacy: %v", err)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		// Real v1 clients send one JSON object without calling CloseWrite()
		// and immediately read the JSON reply.
		if err := json.NewEncoder(conn).Encode(req); err != nil {
			t.Fatalf("write legacy: %v", err)
		}
		var resp LegacyCheckpointResponse
		if err := json.NewDecoder(conn).Decode(&resp); err != nil {
			t.Fatalf("decode legacy: %v", err)
		}
		return resp
	}

	bad := sendLegacy(LegacyCheckpointRequest{Dir: "/tmp/cp", Token: "bad"})
	if bad.OK {
		t.Fatalf("expected unauthorized rejection for bad token")
	}

	ok := sendLegacy(LegacyCheckpointRequest{Dir: "/tmp/cp", LeaveRunning: true, Token: ep.Token})
	if !ok.OK {
		t.Fatalf("expected legacy v1 checkpoint OK, got error: %s", ok.Error)
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if len(handler.legacyReqs) != 1 || handler.legacyReqs[0].Dir != "/tmp/cp" || !handler.legacyReqs[0].LeaveRunning {
		t.Fatalf("unexpected legacy requests: %+v", handler.legacyReqs)
	}
}

func TestMultiplexedFlowControlAndCompression(t *testing.T) {
	// Transfer 3 MiB (> 3x InitialStreamWindow) concurrently across two streams
	// with zstd compression enabled on one and disabled on the other.
	const payloadSize = 3 << 20
	want := bytes.Repeat([]byte("gvx-ctrl-v2-flow-control-test-payload-0123456789\n"), payloadSize/49+1)[:payloadSize]

	handler := &testHandler{
		streamHandler: func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
			closeFDs(fds)
			switch req.Method {
			case MethodFSExport:
				var p FSExportRequest
				_ = json.Unmarshal(req.Params, &p)
				if err := stream.SendResponse(FSExportResponse{Stat: FSStatResponse{Exists: true, Size: int64(len(want))}}); err != nil {
					return err
				}
				w := stream.ChannelWriter(ctx, ChannelGeneric, p.Compress)
				if _, err := w.Write(want); err != nil {
					return err
				}
				return w.Close()

			case MethodFSImport:
				data, err := io.ReadAll(stream.ChannelReader(ctx, ChannelGeneric))
				if err != nil {
					return err
				}
				if !bytes.Equal(data, want) {
					return NewError(CodeInternal, "imported payload mismatch")
				}
				return stream.Reply(FSImportResponse{FilesWritten: 1, BytesWritten: int64(len(data))})
			}
			return NewError(CodeUnsupported, "unknown method")
		},
	}

	ep, _, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:     "sbx-stream",
		Capabilities:  []string{CapFSExport, CapFSImport},
		MaxFrameBytes: 64 << 10,
		Handler:       handler,
	})

	client, err := Dial(context.Background(), DialOptions{Endpoint: ep.Address})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 3)

	// Stream 1: compressed export (server -> client).
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := client.OpenStream(context.Background(), MethodFSExport, FSExportRequest{Path: "/a", Compress: true})
		if err != nil {
			errs <- err
			return
		}
		defer s.Close()
		var meta FSExportResponse
		if err := s.WaitResponse(context.Background(), &meta); err != nil {
			errs <- err
			return
		}
		got, err := io.ReadAll(s.ChannelReader(context.Background(), ChannelGeneric))
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, want) {
			errs <- errors.New("compressed export payload mismatch")
		}
	}()

	// Stream 2: uncompressed export (server -> client).
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := client.OpenStream(context.Background(), MethodFSExport, FSExportRequest{Path: "/b", Compress: false})
		if err != nil {
			errs <- err
			return
		}
		defer s.Close()
		if err := s.WaitResponse(context.Background(), nil); err != nil {
			errs <- err
			return
		}
		got, err := io.ReadAll(s.ChannelReader(context.Background(), ChannelGeneric))
		if err != nil {
			errs <- err
			return
		}
		if !bytes.Equal(got, want) {
			errs <- errors.New("raw export payload mismatch")
		}
	}()

	// Stream 3: request-stream-first import (client -> server, then server replies).
	wg.Add(1)
	go func() {
		defer wg.Done()
		s, err := client.OpenStream(context.Background(), MethodFSImport, FSImportRequest{DestPath: "/tmp", Compress: true})
		if err != nil {
			errs <- err
			return
		}
		defer s.Close()
		w := s.ChannelWriter(context.Background(), ChannelGeneric, true)
		if _, err := w.Write(want); err != nil {
			errs <- err
			return
		}
		if err := w.Close(); err != nil {
			errs <- err
			return
		}
		var resp FSImportResponse
		if err := s.WaitResponse(context.Background(), &resp); err != nil {
			errs <- err
			return
		}
		if resp.BytesWritten != int64(len(want)) {
			errs <- errors.New("unexpected BytesWritten")
		}
	}()

	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}

func TestOversizedCompressedFrameRejected(t *testing.T) {
	// Highly compressible 512 KiB buffer compresses well below 64 KiB on the wire,
	// but ReadFrame must reject it because decompressed length exceeds maxPayload.
	big := bytes.Repeat([]byte("A"), 512<<10)
	var wire bytes.Buffer
	if err := WriteFrame(&wire, Frame{
		Type:     FrameData,
		Flags:    FlagCompressedZstd,
		StreamID: 1,
		Payload:  big,
	}, 512<<10); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	if _, err := ReadFrame(&wire, 64<<10); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame decompressed bomb error = %v, want ErrFrameTooLarge", err)
	}
}

func TestUnixSocketSCMRightsAndLiveConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("SCM_RIGHTS is Unix-only")
	}
	dir, err := os.MkdirTemp("/tmp", "gvx-ctrl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "c.sock")

	var gotContent atomic.Value
	handler := &testHandler{
		streamHandler: func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
			if len(fds) != 1 {
				closeFDs(fds)
				return NewError(CodeInvalidArgument, "expected 1 fd")
			}
			f := os.NewFile(uintptr(fds[0]), "received")
			defer f.Close()
			data, err := io.ReadAll(f)
			if err != nil {
				return err
			}
			gotContent.Store(string(data))
			return stream.Reply(map[string]int{"bytes": len(data)})
		},
	}

	_, _, _ = startTestServer(t, sockPath, ListenOptions{}, ServerConfig{
		SandboxID:    "sbx-unix",
		Capabilities: []string{CapMountVolumeAttach},
		AllowFDs:     true,
		Handler:      handler,
	})

	// Second Listen on the same live socket must fail without unlinking it.
	if _, err := Listen(sockPath, ListenOptions{}); err == nil {
		t.Fatalf("expected Listen conflict on active Unix socket")
	}

	client, err := Dial(context.Background(), DialOptions{Endpoint: sockPath})
	if err != nil {
		t.Fatalf("Dial unix: %v", err)
	}
	defer client.Close()

	tmpFile := filepath.Join(t.TempDir(), "vol.img")
	if err := os.WriteFile(tmpFile, []byte("ext4lite-backing-payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var resp map[string]int
	if err := client.Call(context.Background(), MethodMountAdd, MountAddRequest{
		Type:   "volume",
		Target: "/data",
	}, &resp, int(f.Fd())); err != nil {
		t.Fatalf("Call with SCM_RIGHTS: %v", err)
	}
	if v, _ := gotContent.Load().(string); v != "ext4lite-backing-payload" {
		t.Fatalf("received FD content = %q, want ext4lite-backing-payload", v)
	}
}

func TestSupportsControlFDsPlatforms(t *testing.T) {
	for _, goos := range []string{"linux", "android", "darwin"} {
		if !supportsControlFDs(goos) {
			t.Errorf("supportsControlFDs(%q) = false, want true", goos)
		}
	}
	if supportsControlFDs("windows") {
		t.Errorf("supportsControlFDs(windows) = true, want false")
	}
}

func TestShutdownDrainsInFlightAndClosesIdle(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	handler := &testHandler{
		streamHandler: func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
			closeFDs(fds)
			close(started)
			<-release
			return stream.Reply(PingResponse{SandboxID: "drained"})
		},
	}

	ep, srv, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:    "sbx-drain",
		Capabilities: []string{CapPing},
		Handler:      handler,
	})

	idleClient, err := Dial(context.Background(), DialOptions{Endpoint: ep.Address})
	if err != nil {
		t.Fatalf("Dial idle: %v", err)
	}
	defer idleClient.Close()

	busyClient, err := Dial(context.Background(), DialOptions{Endpoint: ep.Address})
	if err != nil {
		t.Fatalf("Dial busy: %v", err)
	}
	defer busyClient.Close()

	callDone := make(chan error, 1)
	var resp PingResponse
	go func() {
		callDone <- busyClient.Call(context.Background(), MethodPing, nil, &resp)
	}()

	<-started

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- srv.Shutdown(ctx)
	}()

	// Idle connection should be closed promptly while busy call is still running.
	select {
	case <-idleClient.Done():
	case <-time.After(time.Second):
		t.Fatalf("idle connection was not closed during Shutdown")
	}

	close(release)
	if err := <-callDone; err != nil {
		t.Fatalf("in-flight call failed during graceful shutdown: %v", err)
	}
	if resp.SandboxID != "drained" {
		t.Fatalf("unexpected drained response: %+v", resp)
	}
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}
}

func TestControlFrameSecurityAndLimits(t *testing.T) {
	// WriteFrame must reject an uncompressed payload exceeding maxPayload even when zstd could shrink it.
	var wire bytes.Buffer
	big := bytes.Repeat([]byte("Z"), 128<<10)
	if err := WriteFrame(&wire, Frame{
		Type:     FrameData,
		Flags:    FlagCompressedZstd,
		StreamID: 1,
		Payload:  big,
	}, 64<<10); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("WriteFrame oversized compressible payload = %v, want ErrFrameTooLarge", err)
	}

	// ReadFrame must reject FlagCompressedZstd on non-DATA frames (such as pre-auth HELLO).
	var badHello bytes.Buffer
	hdr := make([]byte, FrameHeaderSize)
	hdr[0] = byte(FrameHello)
	hdr[1] = byte(FlagCompressedZstd)
	hdr[11] = 2
	badHello.Write(hdr)
	badHello.WriteString("{}")
	if _, err := ReadFrame(&badHello, HandshakeMaxFrameBytes); err == nil {
		t.Fatal("ReadFrame accepted FlagCompressedZstd on FrameHello, want error")
	}

	// Server with AllowFDs=false must reject FlagHasFDs frames cleanly without calling RecvFDs.
	ep, _, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:    "sbx-nofd",
		Capabilities: []string{CapPing},
		AllowFDs:     false,
		Handler:      &testHandler{},
	})
	rawConn, err := net.DialTimeout("tcp", ep.Address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := rawConn.Write([]byte(Preface)); err != nil {
		t.Fatal(err)
	}
	helloPayload, _ := json.Marshal(HelloRequest{Version: ProtocolVersion, Token: ep.Token})
	if err := WriteFrame(rawConn, Frame{Type: FrameHello, Payload: helloPayload}, HandshakeMaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(rawConn, HandshakeMaxFrameBytes); err != nil {
		t.Fatalf("read HELLO reply: %v", err)
	}
	// Send FramePing with FlagHasFDs set; server must close connection cleanly.
	if err := WriteFrame(rawConn, Frame{Type: FramePing, Flags: FlagHasFDs}, DefaultMaxFrameBytes); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFrame(rawConn, DefaultMaxFrameBytes); err == nil {
		t.Fatal("expected server to reject FlagHasFDs when AllowFDs=false")
	}
}

func TestControlMaxConnectionsHandshakeTimeoutAndCancel(t *testing.T) {
	ctxCanceled := make(chan struct{})
	started := make(chan struct{})
	handler := &testHandler{
		streamHandler: func(ctx context.Context, stream *Stream, req RequestEnvelope, fds []int) error {
			closeFDs(fds)
			if req.Method == MethodEvents {
				close(started)
				<-ctx.Done()
				close(ctxCanceled)
				return ctx.Err()
			}
			return stream.Reply(PingResponse{Version: ProtocolVersion, SandboxID: "sbx-lim", State: "running"})
		},
	}

	ep, _, _ := startTestServer(t, "127.0.0.1:0", ListenOptions{}, ServerConfig{
		SandboxID:        "sbx-lim",
		Capabilities:     []string{CapPing, CapInspect, CapEvents},
		MaxConnections:   1,
		HandshakeTimeout: 200 * time.Millisecond,
		Handler:          handler,
	})

	// 1. Stalled raw connection times out after HandshakeTimeout and frees the slot.
	stalled, err := net.DialTimeout("tcp", ep.Address, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer stalled.Close()
	_ = stalled.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := stalled.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected stalled handshake connection to be closed")
	}

	// 2. First active client occupies MaxConnections=1; second client fails to connect.
	// Poll briefly because the server releases its semaphore slot in a defer right
	// after closing the timed-out raw connection.
	var c1 *Client
	deadline := time.Now().Add(2 * time.Second)
	for {
		c1, err = Dial(context.Background(), DialOptions{Endpoint: ep.Address})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Dial c1 after HandshakeTimeout slot release: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	defer c1.Close()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), time.Second)
	defer dialCancel()
	if c2, err := Dial(dialCtx, DialOptions{Endpoint: ep.Address}); err == nil {
		_ = c2.Close()
		t.Fatal("second client succeeded while MaxConnections=1 was occupied")
	}

	// 3. Stream.Cancel propagates FrameCancel to cancel the server handler context.
	st, err := c1.OpenStream(context.Background(), MethodEvents, nil)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("server handler did not start for MethodEvents")
	}
	st.Cancel(errors.New("client stop"))
	select {
	case <-ctxCanceled:
	case <-time.After(3 * time.Second):
		t.Fatal("server handler context was not canceled after FrameCancel")
	}
}

func TestControlEndpointsTokensAndValidation(t *testing.T) {
	// Single-character sandbox name must be accepted by NamedSocketPath.
	if p, err := NamedSocketPath("a"); err != nil || p == "" {
		t.Fatalf("NamedSocketPath(\"a\") = (%q, %v), want valid path", p, err)
	}
	if _, err := NamedSocketPath("../bad"); err == nil {
		t.Fatal("NamedSocketPath accepted traversal name")
	}

	// IPv4 and IPv6 loopback tokens on the same port must use distinct token files.
	p4, err := DefaultTokenPath("tcp", "127.0.0.1:4567")
	if err != nil {
		t.Fatalf("DefaultTokenPath ipv4: %v", err)
	}
	p6, err := DefaultTokenPath("tcp", "[::1]:4567")
	if err != nil {
		t.Fatalf("DefaultTokenPath ipv6: %v", err)
	}
	if p4 == p6 {
		t.Fatalf("IPv4 and IPv6 token paths collided: %q", p4)
	}

	// ValidateDisableList accepts known groups/capabilities and rejects typos.
	if err := ValidateDisableList([]string{"exec", "net.dial", "mount", CapKernelLogClear}); err != nil {
		t.Fatalf("ValidateDisableList valid: %v", err)
	}
	if err := ValidateDisableList([]string{"exce"}); err == nil {
		t.Fatal("ValidateDisableList accepted unknown capability typo")
	}

	// FilterCapabilities under readonly must exclude kernel.log_clear.
	ro := FilterCapabilities([]string{CapKernelLog, CapKernelLogClear, CapPing}, PolicyReadOnly, nil)
	for _, c := range ro {
		if c == CapKernelLogClear {
			t.Fatalf("PolicyReadOnly unexpectedly kept %q", CapKernelLogClear)
		}
	}

	// Portable HostErrorToLinuxErrno checks.
	if got := HostErrorToLinuxErrno(os.ErrNotExist); got != LinuxENOENT {
		t.Fatalf("HostErrorToLinuxErrno(ErrNotExist) = %d, want %d", got, LinuxENOENT)
	}
	if got := HostErrorToLinuxErrno(os.ErrExist); got != LinuxEEXIST {
		t.Fatalf("HostErrorToLinuxErrno(ErrExist) = %d, want %d", got, LinuxEEXIST)
	}
	if got := HostErrorToLinuxErrno(os.ErrPermission); got != LinuxEACCES {
		t.Fatalf("HostErrorToLinuxErrno(ErrPermission) = %d, want %d", got, LinuxEACCES)
	}
}
