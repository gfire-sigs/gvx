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

package gvx

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/gpurender"
	"z.gfire.dev/gvx/internal/gpurender/gpurendertest"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu"
	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// Compile-time check that *gpurender.Client satisfies virtgpu.Renderer.
var _ virtgpu.Renderer = (*gpurender.Client)(nil)

const (
	gpuWorkerEnv         = "GVX_TEST_GPU_WORKER"
	gpuWorkerModeEnv     = "GVX_TEST_GPU_MODE"
	gpuWorkerRendererEnv = "GVX_TEST_GPU_RENDERER"
	gpuWorkerProbeEnv    = "GVX_TEST_GPU_PROBE"
	gpuWorkerCacheDirEnv = "GVX_TEST_GPU_CACHE_DIR"
)

func kinfoComm(kp *unix.KinfoProc) string {
	comm := kp.Proc.P_comm[:]
	if nul := bytes.IndexByte(comm, 0); nul >= 0 {
		comm = comm[:nul]
	}
	return string(comm)
}

func hasExactLine(text, want string) bool {
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimRight(line, "\r") == want {
			return true
		}
	}
	return false
}

func rendererChildren(t *testing.T) []int {
	t.Helper()
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		t.Fatalf("SysctlKinfoProcSlice(kern.proc.all): %v", err)
	}
	me := os.Getpid()
	var pids []int
	for i := range procs {
		kp := &procs[i]
		if int(kp.Eproc.Ppid) != me {
			continue
		}
		if kinfoComm(kp) == "gvx-gpu-renderer" {
			pids = append(pids, int(kp.Proc.P_pid))
		}
	}
	slices.Sort(pids)
	return pids
}

func gpuProbeLayerFromPath(t *testing.T, probePath string) []byte {
	t.Helper()
	data, err := os.ReadFile(probePath)
	if err != nil {
		t.Fatalf("read gpuprobe %s: %v", probePath, err)
	}
	tarBytes, err := testimage.Tar(testimage.File{
		Name: "bin/gpuprobe",
		Data: data,
		Mode: 0o755,
	})
	if err != nil {
		t.Fatalf("build gpuprobe layer: %v", err)
	}
	return tarBytes
}

func gpuProbeLayer(t *testing.T) []byte {
	t.Helper()
	return gpuProbeLayerFromPath(t, acceptprog.BuildGPUProbe(t, runtime.GOARCH))
}

func gpuTestConfigForMode(t *testing.T, mode GPUMode) Config {
	t.Helper()
	cfg := hostTestConfig(t)
	cfg.GPU = GPUConfig{
		Mode:         mode,
		RendererPath: gpurendertest.Path(t),
	}
	cfg.OCILayerTars = [][]byte{gpuProbeLayer(t)}
	return cfg
}

func gpuTestConfig(t *testing.T) Config {
	t.Helper()
	return gpuTestConfigForMode(t, GPUVenus)
}

type gpuRunResult struct {
	code int
	err  error
}

// startGPUProbeWaitLine starts a GPUVenus sandbox running gpuprobe with mode
// and waits until its stdout prints wantLine.
func startGPUProbeWaitLine(t *testing.T, mode, wantLine string) (*Sandbox, <-chan gpuRunResult) {
	t.Helper()
	cfg := gpuTestConfig(t)
	cfg.Argv = []string{"/bin/gpuprobe", mode}
	pr, pw := io.Pipe()
	var errBuf bytes.Buffer
	cfg.Stdout = pw
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVenus): %v", err)
	}
	t.Cleanup(func() { _ = sb.Close() })

	runCh := make(chan gpuRunResult, 1)
	go func() {
		code, rerr := sb.Run(context.Background())
		_ = pw.Close()
		runCh <- gpuRunResult{code: code, err: rerr}
	}()

	readyCh := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		var lines []string
		for sc.Scan() {
			line := sc.Text()
			lines = append(lines, line)
			if line == wantLine {
				readyCh <- nil
				_, _ = io.Copy(io.Discard, pr)
				return
			}
		}
		readyCh <- fmt.Errorf("gpuprobe %s exited before %s (lines=%q, scanErr=%v)", mode, wantLine, lines, sc.Err())
	}()

	select {
	case rerr := <-readyCh:
		if rerr != nil {
			res := <-runCh
			t.Fatalf("%v (run code=%d err=%v stderr=%q)", rerr, res.code, res.err, errBuf.String())
		}
	case <-time.After(15 * time.Second):
		_ = sb.Close()
		<-runCh
		t.Fatalf("timed out waiting for gpuprobe %s to print %s (stderr=%q)", mode, wantLine, errBuf.String())
	}
	return sb, runCh
}

func TestGPUOffAddsNothing(t *testing.T) {
	cfg := hostTestConfig(t)
	cfg.OCILayerTars = [][]byte{gpuProbeLayer(t)}
	cfg.Argv = []string{"/bin/gpuprobe", "absent"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUOff): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		_ = sb.Close()
		t.Fatalf("rendererChildren after New(GPUOff) = %v, want empty", got)
	}

	code, err := sb.Run(context.Background())
	if err != nil {
		_ = sb.Close()
		t.Fatalf("Run(GPUOff): %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	if code != 0 || !strings.Contains(outBuf.String(), "ABSENT OK") {
		_ = sb.Close()
		t.Fatalf("gpuprobe absent: code=%d stdout=%q stderr=%q, want code 0 and ABSENT OK", code, outBuf.String(), errBuf.String())
	}

	if err := sb.Close(); err != nil {
		t.Fatalf("Close(GPUOff): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close(GPUOff) = %v, want empty", got)
	}
}

func TestNewGPUFailsWithoutRenderer(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "absent")
	cfg := hostTestConfig(t)
	cfg.GPU = GPUConfig{
		Mode:         GPUVenus,
		RendererPath: absent,
	}
	sb, err := New(context.Background(), cfg)
	if sb != nil {
		_ = sb.Close()
		t.Fatalf("New(GPUVenus) returned non-nil sandbox")
	}
	if !errors.Is(err, ErrGPUUnavailable) {
		t.Fatalf("New(GPUVenus) error = %v, want ErrGPUUnavailable", err)
	}
	if !errors.Is(err, gpurender.ErrNotFound) {
		t.Fatalf("New(GPUVenus) error = %v, want gpurender.ErrNotFound", err)
	}
	if !strings.Contains(err.Error(), absent) {
		t.Fatalf("New(GPUVenus) error = %q, want absent path %q", err.Error(), absent)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after failed New = %v, want empty", got)
	}
}

func TestNewGPUFailsWhenRendererBreaksHandshake(t *testing.T) {
	script := filepath.Join(t.TempDir(), "broken-renderer")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 3\n"), 0o755); err != nil {
		t.Fatalf("write broken renderer script: %v", err)
	}
	cfg := hostTestConfig(t)
	cfg.GPU = GPUConfig{
		Mode:         GPUVenus,
		RendererPath: script,
	}
	sb, err := New(context.Background(), cfg)
	if sb != nil {
		_ = sb.Close()
		t.Fatalf("New(GPUVenus broken) returned non-nil sandbox")
	}
	if !errors.Is(err, ErrGPUUnavailable) {
		t.Fatalf("New(GPUVenus broken) error = %v, want ErrGPUUnavailable", err)
	}
	var se *gpurender.StartError
	if !errors.As(err, &se) {
		t.Fatalf("New(GPUVenus broken) error = %v, want *gpurender.StartError", err)
	}
	if se.ExitCode != 3 {
		t.Fatalf("StartError.ExitCode = %d, want 3 (err=%v)", se.ExitCode, err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after broken handshake = %v, want empty", got)
	}
}

func TestGPUCloseWithoutRun(t *testing.T) {
	cfg := gpuTestConfig(t)
	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVenus): %v", err)
	}
	if got := rendererChildren(t); len(got) != 1 {
		_ = sb.Close()
		t.Fatalf("rendererChildren after New = %v, want 1 child", got)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("first Close without Run: %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("second Close without Run: %v", err)
	}
}

func TestGPURunAfterCloseStartsNoKernel(t *testing.T) {
	cfg := gpuTestConfig(t)
	cfg.Argv = []string{"/bin/gpuprobe", "full"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVenus): %v", err)
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("Close before Run: %v", err)
	}
	_, runErr := sb.Run(context.Background())
	if !errors.Is(runErr, errRunConsumed) && !errors.Is(runErr, errSandboxClosing) {
		t.Fatalf("Run after Close error = %v, want errRunConsumed or errSandboxClosing", runErr)
	}
	if outBuf.Len() != 0 {
		t.Fatalf("Run after Close produced guest stdout %q, want empty", outBuf.String())
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Run-after-Close = %v, want empty", got)
	}
}

func TestGPUSandboxServesRenderNode(t *testing.T) {
	cfg := gpuTestConfig(t)
	cfg.Argv = []string{"/bin/gpuprobe", "full"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVenus): %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sb.Close()
		}
	}()

	if got := rendererChildren(t); len(got) != 1 {
		t.Fatalf("rendererChildren after New = %v, want 1 child", got)
	}

	code, err := sb.Run(context.Background())
	if err != nil {
		t.Fatalf("Run(GPUVenus): %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	stdout := outBuf.String()
	if code != 0 {
		t.Fatalf("gpuprobe full exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, errBuf.String())
	}
	wantLines := []string{
		"sysfs=/sys/devices/pci0000:00/0000:00:01.0/virtio0 vendor=0x1af4 device=0x1050",
		"version=virtio_gpu 0.1.0",
		"syncobj=0",
		"params=1,1,1,1,16384",
		"capset_wire_format=1",
		"alias=ok",
		"private=refused",
		"fence=ok",
		"PASS",
	}
	for _, want := range wantLines {
		if !hasExactLine(stdout, want) {
			t.Errorf("gpuprobe full stdout missing line %q\nstdout:\n%s", want, stdout)
		}
	}

	closed = true
	if err := sb.Close(); err != nil {
		t.Fatalf("Close(GPUVenus): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPUTwoSandboxesAreIndependent(t *testing.T) {
	requireGuestBackend(t)
	rendererPath := gpurendertest.Path(t)
	layer := gpuProbeLayer(t)

	newSB := func() (*Sandbox, *bytes.Buffer, *bytes.Buffer) {
		var outBuf, errBuf bytes.Buffer
		cfg := Config{
			Platform:            PlatformAuto,
			NetworkMode:         NetModeNone,
			OCICacheDir:         t.TempDir(),
			DisableHostLockdown: true,
			GPU: GPUConfig{
				Mode:         GPUVenus,
				RendererPath: rendererPath,
			},
			OCILayerTars: [][]byte{layer},
			Argv:         []string{"/bin/gpuprobe", "full"},
			Stdout:       &outBuf,
			Stderr:       &errBuf,
		}
		sb, err := New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New(GPUVenus): %v", err)
		}
		return sb, &outBuf, &errBuf
	}

	sbA, outA, errA := newSB()
	closedA := false
	defer func() {
		if !closedA {
			_ = sbA.Close()
		}
	}()
	pidsAfterA := rendererChildren(t)
	if len(pidsAfterA) != 1 {
		t.Fatalf("rendererChildren after New(A) = %v, want 1 child", pidsAfterA)
	}
	pidA := pidsAfterA[0]

	sbB, outB, errB := newSB()
	closedB := false
	defer func() {
		if !closedB {
			_ = sbB.Close()
		}
	}()
	pidsAfterB := rendererChildren(t)
	if len(pidsAfterB) != 2 {
		t.Fatalf("rendererChildren after New(B) = %v, want 2 children", pidsAfterB)
	}
	var pidB int
	for _, pid := range pidsAfterB {
		if pid != pidA {
			pidB = pid
		}
	}
	if pidB == 0 || pidB == pidA {
		t.Fatalf("expected distinct renderer PIDs, got %v (pidA=%d)", pidsAfterB, pidA)
	}

	codeA, err := sbA.Run(context.Background())
	if err != nil || codeA != 0 {
		t.Fatalf("Run(A): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeA, err, outA.String(), errA.String())
	}
	if !strings.Contains(outA.String(), "res_handle=1") || !hasExactLine(outA.String(), "PASS") {
		t.Fatalf("A output missing res_handle=1 or PASS:\n%s", outA.String())
	}

	closedA = true
	if err := sbA.Close(); err != nil {
		t.Fatalf("Close(A): %v", err)
	}
	pidsLeft := rendererChildren(t)
	if len(pidsLeft) != 1 || pidsLeft[0] != pidB {
		t.Fatalf("rendererChildren after Close(A) = %v, want [%d]", pidsLeft, pidB)
	}

	codeB, err := sbB.Run(context.Background())
	if err != nil || codeB != 0 {
		t.Fatalf("Run(B): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeB, err, outB.String(), errB.String())
	}
	if !strings.Contains(outB.String(), "res_handle=1") || !hasExactLine(outB.String(), "PASS") {
		t.Fatalf("B output missing res_handle=1 or PASS:\n%s", outB.String())
	}

	closedB = true
	if err := sbB.Close(); err != nil {
		t.Fatalf("Close(B): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close(B) = %v, want empty", got)
	}
}

func TestGPUCloseDuringRunStopsKernel(t *testing.T) {
	sb, runCh := startGPUProbeWaitLine(t, "hold", "HOLDING")

	closeStart := time.Now()
	closeErr := sb.Close()
	closeElapsed := time.Since(closeStart)
	if closeErr != nil {
		t.Fatalf("Close during Run: %v", closeErr)
	}
	if closeElapsed >= 35*time.Second {
		t.Fatalf("Close during Run took %v, want < 35s", closeElapsed)
	}

	res := <-runCh
	wantCode := 128 + int(linux.SIGKILL)
	if res.err != nil || res.code != wantCode {
		t.Fatalf("Run after Close = (code=%d, err=%v), want (code=%d, err=nil)", res.code, res.err, wantCode)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPUConcurrentCloseDuringRun(t *testing.T) {
	sb, runCh := startGPUProbeWaitLine(t, "hold", "HOLDING")

	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, 2)
	elapsed := make([]time.Duration, 2)
	for i := range 2 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			t0 := time.Now()
			errs[idx] = sb.Close()
			elapsed[idx] = time.Since(t0)
		}(i)
	}
	close(start)
	wg.Wait()

	for i := range 2 {
		if errs[i] != nil {
			t.Errorf("concurrent Close[%d] = %v, want nil", i, errs[i])
		}
		if elapsed[i] >= 35*time.Second {
			t.Errorf("concurrent Close[%d] took %v, want < 35s", i, elapsed[i])
		}
	}

	res := <-runCh
	wantCode := 128 + int(linux.SIGKILL)
	if res.err != nil || res.code != wantCode {
		t.Fatalf("Run after concurrent Close = (code=%d, err=%v), want (code=%d, err=nil)", res.code, res.err, wantCode)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after concurrent Close = %v, want empty", got)
	}
}

func TestGPUCloseAfterInitExitsWithChildHoldingBlob(t *testing.T) {
	sb, runCh := startGPUProbeWaitLine(t, "fork-hold", "CHILD_HOLDING")

	closeStart := time.Now()
	closeErr := sb.Close()
	closeElapsed := time.Since(closeStart)
	if closeErr != nil {
		t.Fatalf("Close after init exit with child holding blob: %v", closeErr)
	}
	if closeElapsed >= 35*time.Second {
		t.Fatalf("Close took %v, want < 35s", closeElapsed)
	}

	res := <-runCh
	if res.err != nil {
		t.Fatalf("Run returned error %v, want nil (code=%d)", res.err, res.code)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPURendererKilledBeforeRun(t *testing.T) {
	cfg := gpuTestConfig(t)
	cfg.Argv = []string{"/bin/gpuprobe", "full"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVenus): %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sb.Close()
		}
	}()

	pids := rendererChildren(t)
	if len(pids) != 1 {
		t.Fatalf("rendererChildren after New = %v, want 1 child", pids)
	}
	pid := pids[0]

	kq, err := unix.Kqueue()
	if err != nil {
		t.Fatalf("Kqueue: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(kq) })

	watch := []unix.Kevent_t{{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}}
	if _, err := unix.Kevent(kq, watch, nil, nil); err != nil {
		t.Fatalf("register NOTE_EXIT for pid %d: %v", pid, err)
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("kill renderer pid %d: %v", pid, err)
	}

	events := make([]unix.Kevent_t, 1)
	ts := unix.Timespec{Sec: 10}
	for {
		n, kerr := unix.Kevent(kq, nil, events, &ts)
		if errors.Is(kerr, unix.EINTR) {
			continue
		}
		if kerr != nil {
			t.Fatalf("wait NOTE_EXIT for pid %d: %v", pid, kerr)
		}
		if n != 1 {
			t.Fatalf("NOTE_EXIT for pid %d returned %d events, want 1", pid, n)
		}
		break
	}

	code, err := sb.Run(context.Background())
	if err != nil {
		t.Fatalf("Run after renderer SIGKILL: %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	stdout := outBuf.String()
	if code != 1 {
		t.Fatalf("gpuprobe full exit code after renderer SIGKILL = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, errBuf.String())
	}
	if !strings.Contains(stdout, "FAIL context:") || !strings.Contains(stdout, "EIO") {
		t.Fatalf("gpuprobe full stdout after renderer SIGKILL =\n%s\nwant FAIL context: with EIO", stdout)
	}

	closed = true
	if err := sb.Close(); err != nil {
		t.Fatalf("Close after renderer SIGKILL: %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

// TestGPULockdownWorker runs inside a re-executed child test process spawned
// by TestGPUServesRenderNodeUnderLockdown, because hostlockdown.Apply confines
// the entire process irreversibly.
func TestGPULockdownWorker(t *testing.T) {
	if os.Getenv(gpuWorkerEnv) == "" {
		return
	}
	rendererPath := os.Getenv(gpuWorkerRendererEnv)
	probePath := os.Getenv(gpuWorkerProbeEnv)
	cacheDir := os.Getenv(gpuWorkerCacheDirEnv)
	if rendererPath == "" || probePath == "" || cacheDir == "" {
		t.Fatalf("worker env incomplete: renderer=%q probe=%q cacheDir=%q", rendererPath, probePath, cacheDir)
	}
	mode := GPUVenus
	probeMode := "full"
	wantLines := []string{"alias=ok", "fence=ok", "gem_close=ok", "PASS"}
	if os.Getenv(gpuWorkerModeEnv) == string(GPUVirgl) {
		mode = GPUVirgl
		probeMode = "virgl"
		wantLines = []string{"create=ok bo=1", "transfer=ok", "wait=0", "VIRGL OK"}
	}

	var outBuf, errBuf bytes.Buffer
	cfg := Config{
		Platform:            PlatformHVF,
		NetworkMode:         NetModeNone,
		OCICacheDir:         cacheDir,
		DisableHostLockdown: false,
		GPU: GPUConfig{
			Mode:         mode,
			RendererPath: rendererPath,
		},
		OCILayerTars: [][]byte{gpuProbeLayerFromPath(t, probePath)},
		Argv:         []string{"/bin/gpuprobe", probeMode},
		Stdout:       &outBuf,
		Stderr:       &errBuf,
	}
	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("worker New(%s, lockdown): %v", mode, err)
	}
	st := sb.LockdownStatus()
	if !st.Applied || !st.SubprocessBlocked || !st.UnboundFileOpenBlocked || !st.NetworkOutboundBlocked {
		_ = sb.Close()
		t.Fatalf("worker LockdownStatus = %+v, want Applied, SubprocessBlocked, UnboundFileOpenBlocked, NetworkOutboundBlocked", st)
	}
	rpid := sb.gpu.client.PID()
	if rpid <= 0 {
		_ = sb.Close()
		t.Fatalf("worker renderer PID = %d, want > 0", rpid)
	}
	code, err := sb.Run(context.Background())
	if err != nil {
		_ = sb.Close()
		t.Fatalf("worker Run: %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	stdout := outBuf.String()
	if code != 0 {
		_ = sb.Close()
		t.Fatalf("worker gpuprobe exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, errBuf.String())
	}
	for _, want := range wantLines {
		if !hasExactLine(stdout, want) {
			_ = sb.Close()
			t.Fatalf("worker gpuprobe stdout missing line %q\nstdout:\n%s", want, stdout)
		}
	}
	if err := sb.Close(); err != nil {
		t.Fatalf("worker Close: %v", err)
	}
	fmt.Printf("RENDERER_PID %d\nWORKER_OK\n", rpid)
}

func runGPULockdownWorkerTest(t *testing.T, mode GPUMode) {
	t.Helper()
	requireGuestBackend(t)
	rendererPath := gpurendertest.Path(t)
	probePath := acceptprog.BuildGPUProbe(t, runtime.GOARCH)
	// The worker locks down its own process and cannot remove a t.TempDir at
	// exit, so the unconfined parent owns the cache directory.
	cacheDir := t.TempDir()

	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestGPULockdownWorker$", "-test.v")
	cmd.Env = append(os.Environ(),
		"GORACE=atexit_sleep_ms=0",
		gpuWorkerEnv+"=1",
		gpuWorkerModeEnv+"="+string(mode),
		gpuWorkerRendererEnv+"="+rendererPath,
		gpuWorkerProbeEnv+"="+probePath,
		gpuWorkerCacheDirEnv+"="+cacheDir,
	)
	out, err := cmd.CombinedOutput()
	outStr := string(out)
	if err != nil {
		t.Fatalf("lockdown worker failed: %v\noutput:\n%s", err, outStr)
	}
	if !hasExactLine(outStr, "WORKER_OK") {
		t.Fatalf("lockdown worker output missing WORKER_OK:\n%s", outStr)
	}

	var rpid int
	for _, line := range strings.Split(outStr, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "RENDERER_PID "); ok {
			n, perr := strconv.Atoi(strings.TrimSpace(rest))
			if perr != nil {
				t.Fatalf("parse RENDERER_PID %q: %v", line, perr)
			}
			rpid = n
			break
		}
	}
	if rpid <= 0 {
		t.Fatalf("lockdown worker output missing RENDERER_PID:\n%s", outStr)
	}
	if kp, kerr := unix.SysctlKinfoProc("kern.proc.pid", rpid); kerr == nil && kinfoComm(kp) == "gvx-gpu-renderer" {
		t.Fatalf("worker renderer pid %d is still running after worker exit", rpid)
	}
}

func TestGPUServesRenderNodeUnderLockdown(t *testing.T) {
	runGPULockdownWorkerTest(t, GPUVenus)
}

func TestGPUVirglUnderLockdown(t *testing.T) {
	runGPULockdownWorkerTest(t, GPUVirgl)
}

func TestGPUMemoryLimitReachesDevice(t *testing.T) {
	requireGuestBackend(t)
	rendererPath := gpurendertest.Path(t)
	layer := gpuProbeLayer(t)

	newFillSB := func(limit uint64, argv []string) (*Sandbox, *bytes.Buffer, *bytes.Buffer) {
		var outBuf, errBuf bytes.Buffer
		cfg := Config{
			Platform:            PlatformAuto,
			NetworkMode:         NetModeNone,
			OCICacheDir:         t.TempDir(),
			DisableHostLockdown: true,
			GPU: GPUConfig{
				Mode:         GPUVenus,
				RendererPath: rendererPath,
				MemoryLimit:  limit,
			},
			OCILayerTars: [][]byte{layer},
			Argv:         argv,
			Stdout:       &outBuf,
			Stderr:       &errBuf,
		}
		sb, err := New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New(GPUVenus, limit=%d): %v", limit, err)
		}
		return sb, &outBuf, &errBuf
	}

	sbSmall, outSmall, errSmall := newFillSB(64<<10, []string{"/bin/gpuprobe", "fill"})
	closedSmall := false
	defer func() {
		if !closedSmall {
			_ = sbSmall.Close()
		}
	}()

	sbDefault, outDefault, errDefault := newFillSB(0, []string{"/bin/gpuprobe", "fill", "8"})
	closedDefault := false
	defer func() {
		if !closedDefault {
			_ = sbDefault.Close()
		}
	}()

	codeSmall, err := sbSmall.Run(context.Background())
	if err != nil || codeSmall != 0 {
		t.Fatalf("Run(small limit): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeSmall, err, outSmall.String(), errSmall.String())
	}
	if !hasExactLine(outSmall.String(), "blobs=4 errno=ENOMEM") {
		t.Fatalf("small-limit gpuprobe fill stdout = %q, want line %q", outSmall.String(), "blobs=4 errno=ENOMEM")
	}

	codeDefault, err := sbDefault.Run(context.Background())
	if err != nil || codeDefault != 0 {
		t.Fatalf("Run(default limit): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeDefault, err, outDefault.String(), errDefault.String())
	}
	var gotDefaultBlobs int
	for _, line := range strings.Split(outDefault.String(), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "blobs="); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				n, perr := strconv.Atoi(fields[0])
				if perr != nil {
					t.Fatalf("parse default-limit blobs count from %q: %v", line, perr)
				}
				gotDefaultBlobs = n
				break
			}
		}
	}
	if gotDefaultBlobs <= 4 {
		t.Fatalf("default-limit gpuprobe fill created %d blobs (stdout=%q), want > 4", gotDefaultBlobs, outDefault.String())
	}

	closedSmall = true
	if err := sbSmall.Close(); err != nil {
		t.Fatalf("Close(small): %v", err)
	}
	closedDefault = true
	if err := sbDefault.Close(); err != nil {
		t.Fatalf("Close(default): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPUMemoryLimitForwardsToRenderer(t *testing.T) {
	script := filepath.Join(t.TempDir(), "echo-argv-renderer")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho \"argv:$*\" >&2\nexit 3\n"), 0o755); err != nil {
		t.Fatalf("write echo renderer script: %v", err)
	}
	ram, _ := hostMemory()
	defaultLimit := gpuMemoryLimit(GPUConfig{}, ram)

	for _, tc := range []struct {
		name       string
		configured uint64
		wantLimit  uint64
	}{
		{"explicit 1 MiB", 1 << 20, 1 << 20},
		{"default from host RAM", 0, defaultLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostTestConfig(t)
			cfg.GPU = GPUConfig{
				Mode:         GPUVenus,
				RendererPath: script,
				MemoryLimit:  tc.configured,
			}
			sb, err := New(context.Background(), cfg)
			if sb != nil {
				_ = sb.Close()
				t.Fatalf("New(GPUVenus) returned non-nil sandbox")
			}
			if !errors.Is(err, ErrGPUUnavailable) {
				t.Fatalf("New(GPUVenus) error = %v, want ErrGPUUnavailable", err)
			}
			var se *gpurender.StartError
			if !errors.As(err, &se) {
				t.Fatalf("New(GPUVenus) error = %v, want *gpurender.StartError", err)
			}
			if se.ExitCode != 3 {
				t.Fatalf("StartError.ExitCode = %d, want 3 (err=%v)", se.ExitCode, err)
			}
			wantFlag := gpuproto.ArgMemoryLimit + strconv.FormatUint(tc.wantLimit, 10)
			stderrText := strings.Join(se.Stderr, "\n")
			if !strings.Contains(stderrText, wantFlag) {
				t.Fatalf("renderer stderr = %q, want %q", stderrText, wantFlag)
			}
			if got := rendererChildren(t); len(got) != 0 {
				t.Fatalf("rendererChildren after failed New = %v, want empty", got)
			}
		})
	}
}

func TestGPUVirglSandboxServesRenderNode(t *testing.T) {
	cfg := gpuTestConfigForMode(t, GPUVirgl)
	cfg.Argv = []string{"/bin/gpuprobe", "virgl"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVirgl): %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sb.Close()
		}
	}()

	if got := rendererChildren(t); len(got) != 1 {
		t.Fatalf("rendererChildren after New = %v, want 1 child", got)
	}

	code, err := sb.Run(context.Background())
	if err != nil {
		t.Fatalf("Run(GPUVirgl): %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	stdout := outBuf.String()
	if code != 0 {
		t.Fatalf("gpuprobe virgl exit code = %d, want 0\nstdout:\n%s\nstderr:\n%s", code, stdout, errBuf.String())
	}
	wantLines := []string{
		"version=virtio_gpu 0.1.0",
		"params=1,1,0,0,0,1,6,1",
		"blob_alignment=EINVAL",
		"caps2_word0=2",
		"caps4=EINVAL",
		"create=ok bo=1",
		"context_init=EEXIST",
		"info=blob_mem:0 size:65536",
		"transfer=ok",
		"wait=0",
		"wait_bad=ENOENT",
		"blob=EINVAL",
		"transfer_stride=EINVAL",
		"VIRGL OK",
	}
	for _, want := range wantLines {
		if !hasExactLine(stdout, want) {
			t.Errorf("gpuprobe virgl stdout missing line %q\nstdout:\n%s", want, stdout)
		}
	}

	closed = true
	if err := sb.Close(); err != nil {
		t.Fatalf("Close(GPUVirgl): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPUVirglRendererKilledBeforeRun(t *testing.T) {
	cfg := gpuTestConfigForMode(t, GPUVirgl)
	cfg.Argv = []string{"/bin/gpuprobe", "virgl"}
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf

	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New(GPUVirgl): %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = sb.Close()
		}
	}()

	pids := rendererChildren(t)
	if len(pids) != 1 {
		t.Fatalf("rendererChildren after New = %v, want 1 child", pids)
	}
	pid := pids[0]

	kq, err := unix.Kqueue()
	if err != nil {
		t.Fatalf("Kqueue: %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(kq) })

	watch := []unix.Kevent_t{{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}}
	if _, err := unix.Kevent(kq, watch, nil, nil); err != nil {
		t.Fatalf("register NOTE_EXIT for pid %d: %v", pid, err)
	}
	if err := unix.Kill(pid, unix.SIGKILL); err != nil {
		t.Fatalf("kill renderer pid %d: %v", pid, err)
	}

	events := make([]unix.Kevent_t, 1)
	ts := unix.Timespec{Sec: 10}
	for {
		n, kerr := unix.Kevent(kq, nil, events, &ts)
		if errors.Is(kerr, unix.EINTR) {
			continue
		}
		if kerr != nil {
			t.Fatalf("wait NOTE_EXIT for pid %d: %v", pid, kerr)
		}
		if n != 1 {
			t.Fatalf("NOTE_EXIT for pid %d returned %d events, want 1", pid, n)
		}
		break
	}

	code, err := sb.Run(context.Background())
	if err != nil {
		t.Fatalf("Run after renderer SIGKILL: %v (stdout=%q stderr=%q)", err, outBuf.String(), errBuf.String())
	}
	stdout := outBuf.String()
	if code != 1 {
		t.Fatalf("gpuprobe virgl exit code after renderer SIGKILL = %d, want 1\nstdout:\n%s\nstderr:\n%s", code, stdout, errBuf.String())
	}
	if !strings.Contains(stdout, "FAIL create:") || !strings.Contains(stdout, "EIO") {
		t.Fatalf("gpuprobe virgl stdout after renderer SIGKILL =\n%s\nwant FAIL create: with EIO", stdout)
	}

	closed = true
	if err := sb.Close(); err != nil {
		t.Fatalf("Close after renderer SIGKILL: %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}

func TestGPUVirglMemoryLimitReachesDevice(t *testing.T) {
	requireGuestBackend(t)
	rendererPath := gpurendertest.Path(t)
	layer := gpuProbeLayer(t)

	newFillSB := func(limit uint64, argv []string) (*Sandbox, *bytes.Buffer, *bytes.Buffer) {
		var outBuf, errBuf bytes.Buffer
		cfg := Config{
			Platform:            PlatformAuto,
			NetworkMode:         NetModeNone,
			OCICacheDir:         t.TempDir(),
			DisableHostLockdown: true,
			GPU: GPUConfig{
				Mode:         GPUVirgl,
				RendererPath: rendererPath,
				MemoryLimit:  limit,
			},
			OCILayerTars: [][]byte{layer},
			Argv:         argv,
			Stdout:       &outBuf,
			Stderr:       &errBuf,
		}
		sb, err := New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New(GPUVirgl, limit=%d): %v", limit, err)
		}
		return sb, &outBuf, &errBuf
	}

	sbSmall, outSmall, errSmall := newFillSB(64<<10, []string{"/bin/gpuprobe", "virgl-fill"})
	closedSmall := false
	defer func() {
		if !closedSmall {
			_ = sbSmall.Close()
		}
	}()

	sbDefault, outDefault, errDefault := newFillSB(0, []string{"/bin/gpuprobe", "virgl-fill", "8"})
	closedDefault := false
	defer func() {
		if !closedDefault {
			_ = sbDefault.Close()
		}
	}()

	codeSmall, err := sbSmall.Run(context.Background())
	if err != nil || codeSmall != 0 {
		t.Fatalf("Run(small limit): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeSmall, err, outSmall.String(), errSmall.String())
	}
	if !hasExactLine(outSmall.String(), "blobs=4 errno=ENOMEM") {
		t.Fatalf("small-limit gpuprobe virgl-fill stdout = %q, want line %q", outSmall.String(), "blobs=4 errno=ENOMEM")
	}

	codeDefault, err := sbDefault.Run(context.Background())
	if err != nil || codeDefault != 0 {
		t.Fatalf("Run(default limit): code=%d err=%v\nstdout:\n%s\nstderr:\n%s", codeDefault, err, outDefault.String(), errDefault.String())
	}
	var gotDefaultBlobs int
	for _, line := range strings.Split(outDefault.String(), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "blobs="); ok {
			fields := strings.Fields(rest)
			if len(fields) > 0 {
				n, perr := strconv.Atoi(fields[0])
				if perr != nil {
					t.Fatalf("parse default-limit blobs count from %q: %v", line, perr)
				}
				gotDefaultBlobs = n
				break
			}
		}
	}
	if gotDefaultBlobs <= 4 {
		t.Fatalf("default-limit gpuprobe virgl-fill created %d blobs (stdout=%q), want > 4", gotDefaultBlobs, outDefault.String())
	}

	closedSmall = true
	if err := sbSmall.Close(); err != nil {
		t.Fatalf("Close(small): %v", err)
	}
	closedDefault = true
	if err := sbDefault.Close(); err != nil {
		t.Fatalf("Close(default): %v", err)
	}
	if got := rendererChildren(t); len(got) != 0 {
		t.Fatalf("rendererChildren after Close = %v, want empty", got)
	}
}
