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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

// fakeCheckpointer records Checkpoint calls. When gate is not nil, Checkpoint
// waits for it to close.
type fakeCheckpointer struct {
	calls   atomic.Int32
	started chan struct{}
	gate    chan struct{}
}

func (f *fakeCheckpointer) Checkpoint(_ context.Context, _ gvx.CheckpointOptions) error {
	f.calls.Add(1)
	if f.started != nil {
		f.started <- struct{}{}
	}
	if f.gate != nil {
		<-f.gate
	}
	return nil
}

type fakeControlHandler struct {
	cp *fakeCheckpointer
}

func (h *fakeControlHandler) HandleStream(ctx context.Context, stream *control.Stream, req control.RequestEnvelope, fds []int) error {
	for _, fd := range fds {
		_ = os.NewFile(uintptr(fd), "unused").Close()
	}
	if req.Method != control.MethodCheckpoint {
		return control.NewError(control.CodeUnsupported, "unsupported method")
	}
	var p control.CheckpointRequest
	if len(req.Params) > 0 {
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return control.NewError(control.CodeInvalidArgument, err.Error())
		}
	}
	if err := h.cp.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: p.LeaveRunning, Force: p.Force}); err != nil {
		return err
	}
	return stream.Reply(map[string]any{"dir": p.Dir, "ok": true})
}

func (h *fakeControlHandler) HandleLegacyCheckpoint(ctx context.Context, req control.LegacyCheckpointRequest) error {
	return h.cp.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: req.LeaveRunning})
}

// isolateControlTokenDir points the user cache directory at a temporary
// directory, so TCP token files stay inside the test.
func isolateControlTokenDir(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	t.Setenv("LocalAppData", filepath.Join(dir, "cache"))
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback TCP is unavailable: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startFakeControl binds a real control.Server endpoint and serves it with cp.
func startFakeControl(t *testing.T, raw string, cp *fakeCheckpointer, handshakeTimeout time.Duration) (*control.Endpoint, func()) {
	t.Helper()
	ep, err := control.Listen(raw, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen(%q): %v", raw, err)
	}
	t.Cleanup(ep.Cleanup)

	srv := control.NewServer(ep.Listener, control.ServerConfig{
		SandboxID:        "fake-sbx",
		Token:            ep.Token,
		HandshakeTimeout: handshakeTimeout,
		Capabilities:     []string{control.CapPing, control.CapCheckpointLocal},
		Handler:          &fakeControlHandler{cp: cp},
	})
	ctx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		defer close(serveDone)
		_ = srv.Serve(ctx)
	}()

	var stopped atomic.Bool
	stop := func() {
		if !stopped.CompareAndSwap(false, true) {
			return
		}
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = srv.Shutdown(drainCtx)
		drainCancel()
		cancel()
		_ = srv.Close()
		<-serveDone
	}
	t.Cleanup(stop)
	return ep, stop
}

func dialRaw(t *testing.T, network, address string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout(network, address, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s %s: %v", network, address, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func exchangeLegacyV1(t *testing.T, conn net.Conn, req control.LegacyCheckpointRequest) control.LegacyCheckpointResponse {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("send request: %v", err)
	}
	var resp control.LegacyCheckpointResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestControlTCPRequiresTokenAndCLIClientSendsIt(t *testing.T) {
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	cp := &fakeCheckpointer{}
	ep, _ := startFakeControl(t, "tcp://"+addr, cp, 0)

	if ep.Token == "" {
		t.Fatal("TCP control endpoint has no token")
	}
	tokenPath, err := control.DefaultTokenPath("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("token file: %v", err)
	}
	if runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Errorf("token file mode = %#o, want 0600", st.Mode().Perm())
	}

	for name, token := range map[string]string{"missing": "", "wrong": strings.Repeat("0", len(ep.Token))} {
		resp := exchangeLegacyV1(t, dialRaw(t, "tcp", addr), control.LegacyCheckpointRequest{Dir: "ckpt", Token: token})
		if resp.OK || !strings.Contains(resp.Error, "unauthorized") {
			t.Fatalf("%s token: response = %+v, want unauthorized", name, resp)
		}
	}
	if n := cp.calls.Load(); n != 0 {
		t.Fatalf("Checkpoint ran %d times for rejected requests, want 0", n)
	}

	var stdout, stderr bytes.Buffer
	code := checkpointSubcommand(context.Background(), []string{"-control-socket=tcp://" + addr, "-checkpoint-dir=ckpt"}, &stdout, &stderr)
	if code != 0 || cp.calls.Load() != 1 {
		t.Fatalf("checkpointSubcommand = %d (stderr %q), Checkpoint calls = %d, want 0 and 1", code, stderr.String(), cp.calls.Load())
	}

	ep.Cleanup()
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Fatalf("token file after Cleanup: %v, want not exist", err)
	}
}

func TestControlUnixSocketTokenFollowsHostOS(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "c.sock")
	cp := &fakeCheckpointer{}
	ep, _ := startFakeControl(t, sockPath, cp, 0)

	wantToken := runtime.GOOS == "windows"
	if got := ep.Token != ""; got != wantToken {
		t.Fatalf("Unix socket token present = %v, want %v on %s", got, wantToken, runtime.GOOS)
	}
	var stdout, stderr bytes.Buffer
	code := checkpointSubcommand(context.Background(), []string{"-control-socket=" + sockPath, "-checkpoint-dir=ckpt"}, &stdout, &stderr)
	if code != 0 || cp.calls.Load() != 1 {
		t.Fatalf("checkpointSubcommand = %d (stderr %q), Checkpoint calls = %d, want 0 and 1", code, stderr.String(), cp.calls.Load())
	}
}

func TestControlStopClosesIdleConnection(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "idle.sock")
	_, stop := startFakeControl(t, sockPath, &fakeCheckpointer{}, 0)

	idle := dialRaw(t, "unix", sockPath)
	// Wait briefly for Accept before initiating shutdown.
	time.Sleep(50 * time.Millisecond)

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("stop did not return while a client held an idle control connection")
	}
	_ = idle.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := idle.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatalf("idle connection Read = (%d, %v), want it closed", n, err)
	}
}

func TestControlRequestReadDeadlineFreesTheServer(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "slow.sock")
	cp := &fakeCheckpointer{}
	ep, _ := startFakeControl(t, sockPath, cp, 200*time.Millisecond)

	slow := dialRaw(t, "unix", sockPath)
	if _, err := slow.Write([]byte(`{"dir":`)); err != nil {
		t.Fatal(err)
	}

	resp := exchangeLegacyV1(t, dialRaw(t, "unix", sockPath), control.LegacyCheckpointRequest{Dir: "ckpt", Token: ep.Token})
	if !resp.OK || cp.calls.Load() != 1 {
		t.Fatalf("second client = %+v, Checkpoint calls = %d, want ok and 1", resp, cp.calls.Load())
	}
}

func TestControlStopKeepsInFlightResponse(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "busy.sock")
	cp := &fakeCheckpointer{started: make(chan struct{}, 1), gate: make(chan struct{})}
	ep, stop := startFakeControl(t, sockPath, cp, 0)

	conn := dialRaw(t, "unix", sockPath)
	respCh := make(chan control.LegacyCheckpointResponse, 1)
	go func() {
		respCh <- exchangeLegacyV1(t, conn, control.LegacyCheckpointRequest{Dir: "ckpt", Token: ep.Token})
	}()
	select {
	case <-cp.started:
	case resp := <-respCh:
		t.Fatalf("the request ended before Checkpoint started: %+v", resp)
	case <-time.After(10 * time.Second):
		t.Fatal("Checkpoint did not start")
	}

	stopped := make(chan struct{})
	go func() {
		stop()
		close(stopped)
	}()
	select {
	case <-stopped:
		t.Fatal("stop returned before the in-flight checkpoint finished")
	case <-time.After(200 * time.Millisecond):
	}
	close(cp.gate)
	if resp := <-respCh; !resp.OK {
		t.Fatalf("in-flight response = %+v, want ok", resp)
	}
	<-stopped
}

func TestControlFailedBindKeepsTheTokenOfTheLiveListener(t *testing.T) {
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	first, err := control.Listen("tcp://"+addr, control.ListenOptions{})
	if err != nil {
		t.Fatalf("first control.Listen: %v", err)
	}
	defer first.Cleanup()
	defer first.Listener.Close()

	if second, err := control.Listen("tcp://"+addr, control.ListenOptions{}); err == nil {
		second.Cleanup()
		_ = second.Listener.Close()
		t.Fatal("a second listener bound the address of a live listener")
	}

	got, err := control.ReadToken("tcp", addr, "")
	if err != nil {
		t.Fatalf("control.ReadToken: %v", err)
	}
	if got != first.Token {
		t.Fatalf("token file holds %q after a failed second bind, want the token %q of the live listener", got, first.Token)
	}
}

func TestRunBindControlSocketAcceptsGPUConfig(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "gpu.sock")
	absentRenderer := filepath.Join(t.TempDir(), "absent-renderer")
	rc, code, done, parseStderr := parse(t, "-gpu=venus", "-gpu-renderer="+absentRenderer, "-S", sockPath, "-net=none", "-lockdown=false", "-cache-dir="+t.TempDir(), "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended with code %d: %s", code, parseStderr)
	}

	var stderr bytes.Buffer
	ep, ok := bindControlSocket(&rc.cfg, rc.controlSocket, rc.controlTokenFile, "rungv run", &stderr)
	if !ok || ep == nil {
		t.Fatalf("bindControlSocket failed: %s", stderr.String())
	}
	t.Cleanup(ep.Cleanup)
	t.Cleanup(func() { _ = ep.Listener.Close() })

	if rc.cfg.ControlListener != ep.Listener || rc.cfg.CheckpointListener != ep.Listener {
		t.Fatalf("listeners = (%v, %v), want both set to control endpoint listener", rc.cfg.ControlListener, rc.cfg.CheckpointListener)
	}

	sb, err := gvx.New(context.Background(), rc.cfg)
	if sb != nil {
		_ = sb.Close()
		t.Fatal("gvx.New unexpectedly succeeded with absent renderer")
	}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if errors.Is(err, gvx.ErrInvalidConfig) {
			t.Fatalf("gvx.New(-gpu=venus -S) rejected config: %v", err)
		}
	} else {
		if !errors.Is(err, gvx.ErrInvalidConfig) || !strings.Contains(err.Error(), "darwin/arm64") {
			t.Fatalf("gvx.New(-gpu=venus -S) on %s/%s = %v, want darwin/arm64 ErrInvalidConfig", runtime.GOOS, runtime.GOARCH, err)
		}
	}
}
