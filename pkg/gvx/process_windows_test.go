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
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/pkg/sentry/platform/whpx"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "gvx-process-worker" {
		if err := ServeProcess(context.Background(), WorkerOptions{}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func processTestPlatforms(t *testing.T) []PlatformType {
	t.Helper()
	var platforms []PlatformType
	if runtime.GOARCH == "arm64" {
		platforms = append(platforms, PlatformSystrap)
	}
	p, err := whpx.New()
	if err == nil {
		if err := p.Close(); err != nil {
			t.Fatal(err)
		}
		platforms = append(platforms, PlatformWHPX)
	} else if !errors.Is(err, whpx.ErrUnsupported) {
		t.Fatal(err)
	}
	if len(platforms) == 0 {
		t.Skip("no confined execution platform is available")
	}
	return platforms
}

func TestWindowsNewRequiresProcessIsolation(t *testing.T) {
	sandbox, err := New(t.Context(), Config{NetworkMode: NetModeNone})
	if sandbox != nil || !errors.Is(err, ErrProcessIsolationRequired) {
		t.Fatalf("New: %v, %v", sandbox, err)
	}
}

func TestProcessForwardsGuestHTTP(t *testing.T) {
	for _, target := range processTestPlatforms(t) {
		t.Run(string(target), func(t *testing.T) { testProcessForwardsGuestHTTP(t, target) })
	}
}

func testProcessForwardsGuestHTTP(t *testing.T, target PlatformType) {
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "input.txt"), []byte("brokered HTTP\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	guest, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, 8080, "/workspace/input.txt", "/workspace/result.txt", "HTTP complete\n")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	sandbox, err := NewProcess(ctx, WorkerCommand{Executable: executable, Arguments: []string{"gvx-process-worker"}}, Config{Platform: target, NetworkMode: NetModeNAT, ELFBytes: guest, OCICacheDir: t.TempDir(), WorkspacePath: workspace, PortForwards: []PortForward{{HostPort: 0, GuestPort: 8080, Protocol: "tcp"}}, Stderr: &stderr})
	if err != nil {
		t.Fatalf("NewProcess: %v; stderr=%s", err, stderr.String())
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Error(err)
		}
	}()
	runDone := make(chan struct{})
	var runErr error
	go func() {
		code, err := sandbox.Run(ctx)
		if err == nil && code != 0 {
			err = fmt.Errorf("guest exit %d", code)
		}
		runErr = err
		close(runDone)
	}()
	defer func() { cancel(); _ = sandbox.Close(); <-runDone }()
	request, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1:"+strconv.Itoa(sandbox.BoundPort(0))+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		cancel()
		_ = sandbox.Close()
		<-runDone
		t.Fatalf("HTTP: %v; stderr=%s", err, stderr.String())
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || string(body) != "brokered HTTP\n" {
		t.Fatalf("HTTP body: %q, %v", body, err)
	}
	<-runDone
	if runErr != nil {
		t.Fatalf("guest Run: %v; stderr=%s", runErr, stderr.String())
	}
}

func TestProcessSandboxesHaveIndependentMemory(t *testing.T) {
	for _, target := range processTestPlatforms(t) {
		t.Run(string(target), func(t *testing.T) { testProcessSandboxesHaveIndependentMemory(t, target) })
	}
}

func testProcessSandboxesHaveIndependentMemory(t *testing.T, target PlatformType) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	var sandboxes []*ProcessSandbox
	var outputs []*bytes.Buffer
	for index := range 2 {
		text := fmt.Sprintf("worker %d\n", index)
		guest, err := testelf.BuildGuestELF64(runtime.GOARCH, index+3, text)
		if err != nil {
			t.Fatal(err)
		}
		output := new(bytes.Buffer)
		sandbox, err := NewProcess(ctx, WorkerCommand{Executable: executable, Arguments: []string{"gvx-process-worker"}}, Config{Platform: target, NetworkMode: NetModeNone, ELFBytes: guest, OCICacheDir: t.TempDir(), Stdout: output, Stderr: io.Discard})
		if err != nil {
			t.Fatal(err)
		}
		sandboxes = append(sandboxes, sandbox)
		outputs = append(outputs, output)
		t.Cleanup(func() {
			if err := sandbox.Close(); err != nil {
				t.Error(err)
			}
		})
	}
	for index, sandbox := range sandboxes {
		if code, err := sandbox.Run(ctx); err != nil || code != index+3 {
			t.Fatalf("worker Run: %d, %v", code, err)
		}
		if text := outputs[index].String(); text != fmt.Sprintf("worker %d\n", index) {
			t.Errorf("worker %d output: %q", index, text)
		}
	}
}

type readyOutput struct {
	ready  chan struct{}
	once   sync.Once
	buffer bytes.Buffer
}

func (w *readyOutput) Write(data []byte) (int, error) {
	n, err := w.buffer.Write(data)
	if bytes.Contains(w.buffer.Bytes(), []byte("ready\n")) {
		w.once.Do(func() { close(w.ready) })
	}
	return n, err
}

func TestProcessCancellationStopsBlockedGuest(t *testing.T) {
	for _, target := range processTestPlatforms(t) {
		t.Run(string(target), func(t *testing.T) { testProcessCancellationStopsBlockedGuest(t, target) })
	}
}

func testProcessCancellationStopsBlockedGuest(t *testing.T, target PlatformType) {
	guest, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	input, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer writer.Close()
	output := &readyOutput{ready: make(chan struct{})}
	setupCtx, setupCancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer setupCancel()
	sandbox, err := NewProcess(setupCtx, WorkerCommand{Executable: executable, Arguments: []string{"gvx-process-worker"}}, Config{Platform: target, NetworkMode: NetModeNone, ELFBytes: guest, Argv: []string{"/bin/app", "/dev/stdin", "/dev/stdin"}, OCICacheDir: t.TempDir(), Stdin: input, Stdout: output, Stderr: io.Discard})
	if err != nil {
		t.Fatal(err)
	}
	defer sandbox.Close()
	ctx, cancel := context.WithCancel(setupCtx)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := sandbox.Run(ctx); done <- err }()
	if _, err := writer.Write([]byte("ready\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-output.ready:
	case <-setupCtx.Done():
		t.Fatal("guest never echoed its input")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled Run: %v", err)
		}
	case <-setupCtx.Done():
		t.Fatal("worker did not stop")
	}
	if err := sandbox.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Stat(); err != nil {
		t.Fatalf("caller stdin closed: %v", err)
	}
}

func TestProcessRunsGuestWithoutLockingCaller(t *testing.T) {
	for _, target := range processTestPlatforms(t) {
		t.Run(string(target), func(t *testing.T) { testProcessRunsGuestWithoutLockingCaller(t, target) })
	}
}

func testProcessRunsGuestWithoutLockingCaller(t *testing.T, target PlatformType) {
	t.Chdir(t.TempDir())
	guest, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/result.txt", "isolated guest\n")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	workspace := "workspace"
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(secret, []byte("caller-only"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	sandbox, err := NewProcess(ctx, WorkerCommand{Executable: executable, Arguments: []string{"gvx-process-worker"}}, Config{Platform: target, NetworkMode: NetModeNone, ELFBytes: guest, OCICacheDir: t.TempDir(), WorkspacePath: workspace, Stdout: &stdout, Stderr: &stderr})
	if err != nil {
		t.Fatalf("NewProcess: %v; stderr=%s", err, stderr.String())
	}
	defer func() {
		if err := sandbox.Close(); err != nil {
			t.Error(err)
		}
	}()
	if status := sandbox.LockdownStatus(); !status.Applied || !status.AppContainer || !status.UnboundFileOpenBlocked || !status.NetworkOutboundBlocked {
		t.Fatalf("worker status: %+v", status)
	}
	if content, err := os.ReadFile(secret); err != nil || string(content) != "caller-only" {
		t.Fatalf("caller read: %q, %v", content, err)
	}
	code, err := sandbox.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("Run: %d, %v; stderr=%s", code, err, stderr.String())
	}
	content, err := os.ReadFile(filepath.Join(workspace, "result.txt"))
	if err != nil || string(content) != "isolated guest\n" {
		t.Fatalf("workspace result: %q, %v; stderr=%s", content, err, stderr.String())
	}
}

func TestProcessMountsAndLimits(t *testing.T) {
	for _, target := range processTestPlatforms(t) {
		t.Run(string(target), func(t *testing.T) {
			dir := t.TempDir()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			guest, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/data/result.txt", "mounted data")
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			sb, err := NewProcess(ctx, WorkerCommand{Executable: executable, Arguments: []string{"gvx-process-worker"}}, Config{
				Platform: target, NetworkMode: NetModeNone, ELFBytes: guest, OCICacheDir: t.TempDir(), Stderr: &stderr,
				Mounts: []Mount{{Kind: MountBind, HostPath: dir, GuestPath: "/data"}}, Resources: Resources{MemoryBytes: 64 << 20, CPUMillis: 500},
			})
			if err != nil {
				t.Fatalf("NewProcess: %v; stderr=%s", err, stderr.String())
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Error(err)
				}
			}()
			want := LimitReport{Memory: true, CPUCount: true, CPUTime: target == PlatformWHPX}
			if got := sb.Limits(); got != want {
				t.Fatalf("limits=%+v, want %+v", got, want)
			}
			if got := sb.PlatformName(); got != string(target) {
				t.Fatalf("platform=%s, want %s", got, target)
			}
			if code, err := sb.Run(ctx); err != nil || code != 0 {
				t.Fatalf("Run: %d, %v; stderr=%s", code, err, stderr.String())
			}
			if data, err := os.ReadFile(filepath.Join(dir, "result.txt")); err != nil || string(data) != "mounted data" {
				t.Fatalf("mount data=%q, error=%v", data, err)
			}
		})
	}
}

func TestProcessRefusesSystrapWithoutNativeSyscallSealing(t *testing.T) {
	if runtime.GOARCH == "arm64" {
		t.Skip("native syscall sealing is available")
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sb, err := NewProcess(t.Context(), WorkerCommand{Executable: executable}, Config{Platform: PlatformSystrap, NetworkMode: NetModeNone})
	if sb != nil || !errors.Is(err, ErrPlatformUnavailable) {
		t.Fatalf("NewProcess=%v, error=%v; want unavailable confined systrap", sb, err)
	}
}
