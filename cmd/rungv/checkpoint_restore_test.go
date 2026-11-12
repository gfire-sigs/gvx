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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/pkg/gvx"
)

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "ckpt")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

type syncNotifyBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan struct{}
}

func newSyncNotifyBuffer() *syncNotifyBuffer {
	return &syncNotifyBuffer{ch: make(chan struct{}, 1)}
}

func (b *syncNotifyBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	b.mu.Unlock()
	select {
	case b.ch <- struct{}{}:
	default:
	}
	return n, err
}

func (b *syncNotifyBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *syncNotifyBuffer) waitForSubstring(t *testing.T, sub string, timeout time.Duration) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if strings.Contains(b.String(), sub) {
			return
		}
		select {
		case <-b.ch:
		case <-deadline.C:
			t.Fatalf("timed out waiting for %q in buffer %q", sub, b.String())
		}
	}
}

func TestParseRunArgsCheckpointFlags(t *testing.T) {
	rc, code, done, stderr := parse(t,
		"-checkpoint-dir=/tmp/ckpt-bundle",
		"-control-socket=/tmp/ckpt.sock",
		"-image=alpine:3.20",
	)
	if done || code != 0 {
		t.Fatalf("parseRunArgs failed: code=%d done=%v stderr=%q", code, done, stderr)
	}
	if rc.cfg.CheckpointDir != "/tmp/ckpt-bundle" {
		t.Errorf("CheckpointDir = %q, want /tmp/ckpt-bundle", rc.cfg.CheckpointDir)
	}
	if rc.controlSocket != "/tmp/ckpt.sock" {
		t.Errorf("controlSocket = %q, want /tmp/ckpt.sock", rc.controlSocket)
	}
}

func TestParseCheckpointArgs(t *testing.T) {
	var stderr bytes.Buffer
	ca, code, done := parseCheckpointArgs([]string{
		"-control-socket=/tmp/ctrl.sock",
		"-checkpoint-dir=/tmp/ckpt-out",
		"-leave-running",
	}, &stderr)
	if done || code != 0 {
		t.Fatalf("parseCheckpointArgs failed: code=%d done=%v stderr=%q", code, done, stderr.String())
	}
	if ca.controlSocket != "/tmp/ctrl.sock" || ca.checkpointDir != "/tmp/ckpt-out" || !ca.leaveRunning {
		t.Errorf("checkpointArgs = %+v", ca)
	}

	for _, tc := range []struct {
		name       string
		subcmd     string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"missing socket", "checkpoint", nil, 2, "specify -control-socket"},
		{"missing socket on snapshot alias", "snapshot", []string{"-checkpoint-dir=/tmp/x"}, 2, "specify -control-socket"},
		{"unexpected positional arg", "checkpoint", []string{"-control-socket=/tmp/s", "extra"}, 2, "unexpected positional"},
		{"help", "checkpoint", []string{"--help"}, 0, "Usage"},
		{"snapshot help", "snapshot", []string{"-h"}, 0, "Usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			gotCode := executeCLI(context.Background(), append([]string{tc.subcmd}, tc.args...), nil, &outBuf, &errBuf)
			if gotCode != tc.wantCode || !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("executeCLI(%s %v) = (code %d, stderr %q), want (code %d, stderr containing %q)",
					tc.subcmd, tc.args, gotCode, errBuf.String(), tc.wantCode, tc.wantStderr)
			}
		})
	}
}

func TestParseRestoreArgs(t *testing.T) {
	wsDir := t.TempDir()
	bindDir := t.TempDir()

	var stderr bytes.Buffer
	rc, code, done := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"-w=" + wsDir,
		"-ro",
		"-v=" + bindDir + ":/mnt/data:ro",
		"-p=127.0.0.1:18080:80",
		"-net=wg",
		"-wg-config=/tmp/wg.conf",
		"-control-socket=/tmp/next.sock",
	}, nil, &bytes.Buffer{}, &stderr)
	if done || code != 0 {
		t.Fatalf("parseRestoreArgs failed: code=%d done=%v stderr=%q", code, done, stderr.String())
	}
	if rc.dir != "/tmp/bundle" {
		t.Errorf("dir = %q, want /tmp/bundle", rc.dir)
	}
	if rc.cfg.WorkspacePath != wsDir || !rc.cfg.WorkspaceReadOnly {
		t.Errorf("WorkspacePath = %q WorkspaceReadOnly = %v, want %q and true", rc.cfg.WorkspacePath, rc.cfg.WorkspaceReadOnly, wsDir)
	}
	if len(rc.cfg.Mounts) != 1 || rc.cfg.Mounts[0].GuestPath != "/mnt/data" || !rc.cfg.Mounts[0].ReadOnly {
		t.Errorf("Mounts = %+v", rc.cfg.Mounts)
	}
	if len(rc.cfg.PortForwards) != 1 || rc.cfg.PortForwards[0].HostPort != 18080 || rc.cfg.PortForwards[0].GuestPort != 80 {
		t.Errorf("PortForwards = %+v", rc.cfg.PortForwards)
	}
	if rc.cfg.NetworkMode != gvx.NetModeWireGuard || rc.cfg.WireGuardConfigPath != "/tmp/wg.conf" {
		t.Errorf("NetworkMode = %q WireGuardConfigPath = %q", rc.cfg.NetworkMode, rc.cfg.WireGuardConfigPath)
	}
	if rc.cfg.CheckpointDir != "/tmp/bundle" || rc.controlSocket != "/tmp/next.sock" {
		t.Errorf("CheckpointDir = %q controlSocket = %q", rc.cfg.CheckpointDir, rc.controlSocket)
	}

	// Verify -workspace alias as well.
	rc2, code2, done2 := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"-workspace=" + wsDir,
	}, nil, &bytes.Buffer{}, &stderr)
	if done2 || code2 != 0 || rc2.cfg.WorkspacePath != wsDir {
		t.Fatalf("-workspace failed: code=%d done=%v WorkspacePath=%q", code2, done2, rc2.cfg.WorkspacePath)
	}

	for _, tc := range []struct {
		name       string
		subcmd     string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"missing dir", "restore", nil, 2, "specify -checkpoint-dir"},
		{"missing dir on resume alias", "resume", []string{"-net=none"}, 2, "specify -checkpoint-dir"},
		{"detach unsupported", "restore", []string{"-checkpoint-dir=/tmp/b", "-d"}, 2, "-d is not supported"},
		{"unexpected positional arg", "restore", []string{"-checkpoint-dir=/tmp/b", "extra"}, 2, "unexpected positional"},
		{"help", "restore", []string{"--help"}, 0, "Usage"},
		{"resume help", "resume", []string{"--help"}, 0, "Usage"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var outBuf, errBuf bytes.Buffer
			gotCode := executeCLI(context.Background(), append([]string{tc.subcmd}, tc.args...), nil, &outBuf, &errBuf)
			if gotCode != tc.wantCode || !strings.Contains(errBuf.String(), tc.wantStderr) {
				t.Fatalf("executeCLI(%s %v) = (code %d, stderr %q), want (code %d, stderr containing %q)",
					tc.subcmd, tc.args, gotCode, errBuf.String(), tc.wantCode, tc.wantStderr)
			}
		})
	}
}

func TestListenCheckpointSocketPermissionsAndValidation(t *testing.T) {
	sockDir := shortSocketDir(t)
	sockPath := filepath.Join(sockDir, "sub", "ctrl.sock")
	ep, err := listenCheckpointSocket(sockPath)
	if err != nil {
		t.Fatalf("listenCheckpointSocket(%q): %v", sockPath, err)
	}
	defer ep.Cleanup()
	defer ep.Listener.Close()

	if runtime.GOOS != "windows" {
		fi, statErr := os.Lstat(sockPath)
		if statErr != nil {
			t.Fatalf("Lstat(%q): %v", sockPath, statErr)
		}
		if perm := fi.Mode().Perm(); perm != 0o600 {
			t.Errorf("socket mode = %#o, want 0600", perm)
		}
	}

	// Refuses to overwrite a regular file.
	regFile := filepath.Join(sockDir, "regular.txt")
	if err := os.WriteFile(regFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listenCheckpointSocket(regFile); err == nil {
		t.Fatal("listenCheckpointSocket succeeded on regular file, want error")
	}

	// Rejects non-loopback TCP addresses.
	if _, err := listenCheckpointSocket("tcp://8.8.8.8:9999"); err == nil {
		t.Fatal("listenCheckpointSocket accepted non-loopback TCP address, want error")
	}
}

func requireCheckpointCLIPlatform(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		hvtest.Require(t)
		return "hvf"
	case "windows":
		if systraptest.Available(t) {
			return "systrap"
		}
		hvtest.Require(t)
		return "whpx"
	default:
		if !systraptest.Available(t) {
			t.Skip("systrap is unavailable on this host")
		}
		return "systrap"
	}
}

func TestCLICheckpointAndRestoreEndToEnd(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "cat.elf")
	if err := os.WriteFile(elfPath, catELF, 0o755); err != nil {
		t.Fatalf("write cat ELF: %v", err)
	}

	cacheDir := t.TempDir()
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "before.txt"), []byte("cli-before-ckpt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wsDir, "after.txt"), []byte("cli-after-ckpt\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ckptDir := filepath.Join(t.TempDir(), "bundle")
	sockDir := shortSocketDir(t)
	sockPath1 := filepath.Join(sockDir, "c1.sock")
	sockPath2 := filepath.Join(sockDir, "c2.sock")

	stdinR1, stdinW1 := net.Pipe()
	defer stdinR1.Close()
	defer stdinW1.Close()

	stdout1 := newSyncNotifyBuffer()
	stderr1 := newSyncNotifyBuffer()

	runDone := make(chan int, 1)
	go func() {
		code := executeCLI(
			context.Background(),
			[]string{
				"run",
				"-lockdown=false",
				"-platform=" + platform,
				"-net=none",
				"-cache-dir=" + cacheDir,
				"-workspace=" + wsDir,
				"-checkpoint-dir=" + ckptDir,
				"-control-socket=" + sockPath1,
				"-bin=" + elfPath,
				"--",
				"/workspace/before.txt",
				"/proc/self/fd/0",
				"/workspace/after.txt",
			},
			stdinR1,
			stdout1,
			stderr1,
		)
		runDone <- code
	}()

	// Wait until the guest has printed /workspace/before.txt and blocked on /proc/self/fd/0.
	stdout1.waitForSubstring(t, "cli-before-ckpt\n", 15*time.Second)

	// 1. A mismatched -checkpoint-dir is rejected over the control socket without stopping the sandbox.
	var ckptOut, ckptErr bytes.Buffer
	wrongDir := filepath.Join(t.TempDir(), "wrong-dir")
	code := executeCLI(context.Background(), []string{
		"checkpoint",
		"-control-socket=" + sockPath1,
		"-checkpoint-dir=" + wrongDir,
	}, nil, &ckptOut, &ckptErr)
	if code != 1 || !strings.Contains(ckptErr.String(), "does not match pre-opened -checkpoint-dir") {
		t.Fatalf("mismatched dir checkpoint = (code %d, stderr %q), want (1, mismatch error)", code, ckptErr.String())
	}

	// 2. Test -leave-running with the snapshot alias first.
	ckptOut.Reset()
	ckptErr.Reset()
	code = executeCLI(context.Background(), []string{
		"snapshot",
		"-control-socket=" + sockPath1,
		"-checkpoint-dir=" + ckptDir,
		"-leave-running",
	}, nil, &ckptOut, &ckptErr)
	if code != 0 {
		t.Fatalf("rungv snapshot -leave-running = (code %d, stderr %q), want 0", code, ckptErr.String())
	}
	select {
	case c := <-runDone:
		t.Fatalf("rungv run exited early after -leave-running with code %d (stderr=%q)", c, stderr1.String())
	default:
	}

	// 3. Trigger stop-on-checkpoint via `rungv checkpoint`.
	ckptOut.Reset()
	ckptErr.Reset()
	code = executeCLI(context.Background(), []string{
		"checkpoint",
		"-control-socket=" + sockPath1,
		"-checkpoint-dir=" + ckptDir,
	}, nil, &ckptOut, &ckptErr)
	if code != 0 {
		t.Fatalf("rungv checkpoint = (code %d, stderr %q), want 0", code, ckptErr.String())
	}

	runExit := <-runDone
	if runExit != 0 {
		t.Fatalf("rungv run exit code = %d, want 0 (stderr=%q)", runExit, stderr1.String())
	}

	// 4. Restore from ckptDir with `rungv restore` and re-checkpoint into ckptDir over sockPath2.
	stdinR2, stdinW2 := net.Pipe()
	defer stdinR2.Close()
	defer stdinW2.Close()

	stdout2 := newSyncNotifyBuffer()
	stderr2 := newSyncNotifyBuffer()
	restoreDone := make(chan int, 1)
	go func() {
		rCode := executeCLI(
			context.Background(),
			[]string{
				"restore",
				"-lockdown=false",
				"-platform=" + platform,
				"-cache-dir=" + cacheDir,
				"-w=" + wsDir,
				"-checkpoint-dir=" + ckptDir,
				"-control-socket=" + sockPath2,
			},
			stdinR2,
			stdout2,
			stderr2,
		)
		restoreDone <- rCode
	}()

	// Write a chunk to the restored guest's stdin to verify it is running, then re-checkpoint.
	if _, err := stdinW2.Write([]byte("mid-restore\n")); err != nil {
		t.Fatalf("write stdinW2: %v", err)
	}
	stdout2.waitForSubstring(t, "mid-restore\n", 15*time.Second)

	ckptOut.Reset()
	ckptErr.Reset()
	code = executeCLI(context.Background(), []string{
		"checkpoint",
		"-control-socket=" + sockPath2,
	}, nil, &ckptOut, &ckptErr)
	if code != 0 {
		t.Fatalf("second rungv checkpoint = (code %d, stderr %q), want 0", code, ckptErr.String())
	}
	if rExit := <-restoreDone; rExit != 0 {
		t.Fatalf("first rungv restore exit code = %d, want 0 (stderr=%q)", rExit, stderr2.String())
	}

	// 5. Resume from ckptDir using the `rungv resume` alias and let the guest finish.
	var stdout3, stderr3 bytes.Buffer
	resumeCode := executeCLI(
		context.Background(),
		[]string{
			"resume",
			"-lockdown=false",
			"-platform=" + platform,
			"-cache-dir=" + cacheDir,
			"-workspace=" + wsDir,
			"-checkpoint-dir=" + ckptDir,
		},
		strings.NewReader("final-stdin\n"),
		&stdout3,
		&stderr3,
	)
	if resumeCode != 0 {
		t.Fatalf("rungv resume exit code = %d, want 0 (stderr=%q)", resumeCode, stderr3.String())
	}
	wantOut3 := "final-stdin\ncli-after-ckpt\n"
	if stdout3.String() != wantOut3 {
		t.Fatalf("rungv resume stdout = %q, want %q", stdout3.String(), wantOut3)
	}
}
