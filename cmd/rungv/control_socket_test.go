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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
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

// startFakeControl binds a real control endpoint and serves it with cp.
func startFakeControl(t *testing.T, raw string, cp checkpointer) (*controlEndpoint, func()) {
	t.Helper()
	ep, err := listenCheckpointSocket(raw)
	if err != nil {
		t.Fatalf("listenCheckpointSocket(%q): %v", raw, err)
	}
	t.Cleanup(ep.Cleanup)
	absCkpt, err := filepath.Abs("ckpt")
	if err != nil {
		t.Fatal(err)
	}
	stop := serveCheckpointControl(context.Background(), cp, ep.Listener.Accept, ep.Listener, ep.Token, "ckpt", absCkpt)
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

func exchange(t *testing.T, conn net.Conn, req checkpointControlRequest) checkpointControlResponse {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("send request: %v", err)
	}
	var resp checkpointControlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("read response: %v", err)
	}
	return resp
}

func TestControlTCPRequiresTokenAndCLIClientSendsIt(t *testing.T) {
	isolateControlTokenDir(t)
	addr := freeLoopbackAddr(t)
	cp := &fakeCheckpointer{}
	ep, _ := startFakeControl(t, "tcp://"+addr, cp)

	if ep.Token == "" {
		t.Fatal("TCP control endpoint has no token")
	}
	tokenPath, err := controlTokenPath("tcp", addr)
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
		resp := exchange(t, dialRaw(t, "tcp", addr), checkpointControlRequest{Dir: "ckpt", Token: token})
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
	ep, _ := startFakeControl(t, sockPath, cp)

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
	_, stop := startFakeControl(t, sockPath, &fakeCheckpointer{})

	idle := dialRaw(t, "unix", sockPath)
	// Let the server accept the connection and block in its request read.
	time.Sleep(100 * time.Millisecond)

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
	old := controlRequestTimeout
	controlRequestTimeout = 200 * time.Millisecond
	t.Cleanup(func() { controlRequestTimeout = old })

	sockPath := filepath.Join(shortSocketDir(t), "slow.sock")
	cp := &fakeCheckpointer{}
	startFakeControl(t, sockPath, cp)

	slow := dialRaw(t, "unix", sockPath)
	if _, err := slow.Write([]byte(`{"dir":`)); err != nil {
		t.Fatal(err)
	}

	resp := exchange(t, dialRaw(t, "unix", sockPath), checkpointControlRequest{Dir: "ckpt"})
	if !resp.OK || cp.calls.Load() != 1 {
		t.Fatalf("second client = %+v, Checkpoint calls = %d, want ok and 1", resp, cp.calls.Load())
	}
}

func TestControlStopKeepsInFlightResponse(t *testing.T) {
	sockPath := filepath.Join(shortSocketDir(t), "busy.sock")
	cp := &fakeCheckpointer{started: make(chan struct{}, 1), gate: make(chan struct{})}
	_, stop := startFakeControl(t, sockPath, cp)

	conn := dialRaw(t, "unix", sockPath)
	respCh := make(chan checkpointControlResponse, 1)
	go func() { respCh <- exchange(t, conn, checkpointControlRequest{Dir: "ckpt"}) }()
	<-cp.started

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
	first, err := listenCheckpointSocket("tcp://" + addr)
	if err != nil {
		t.Fatalf("first listenCheckpointSocket: %v", err)
	}
	defer first.Cleanup()
	defer first.Listener.Close()

	if second, err := listenCheckpointSocket("tcp://" + addr); err == nil {
		second.Cleanup()
		_ = second.Listener.Close()
		t.Fatal("a second listener bound the address of a live listener")
	}

	got, err := readControlToken("tcp", addr)
	if err != nil {
		t.Fatalf("readControlToken: %v", err)
	}
	if got != first.Token {
		t.Fatalf("token file holds %q after a failed second bind, want the token %q of the live listener", got, first.Token)
	}
}
