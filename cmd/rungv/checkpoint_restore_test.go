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
	"z.gfire.dev/gvx/pkg/gvx/control"
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

func TestParseRunAndRestoreRootfsVolumeFlags(t *testing.T) {
	rc, code, done, stderr := parse(t, "-rootfs-volume=myroot", "alpine:3.20")
	if done || code != 0 || rc.cfg.RootVolume != "myroot" {
		t.Fatalf("parse(-rootfs-volume) = (code=%d done=%v rootVol=%q stderr=%q)", code, done, rc.cfg.RootVolume, stderr)
	}
	rcDouble, codeDouble, doneDouble, stderrDouble := parse(t, "--rootfs-volume", "/tmp/myroot.ext4", "alpine:3.20")
	if doneDouble || codeDouble != 0 || rcDouble.cfg.RootVolume != "/tmp/myroot.ext4" {
		t.Fatalf("parse(--rootfs-volume) = (code=%d done=%v rootVol=%q stderr=%q)", codeDouble, doneDouble, rcDouble.cfg.RootVolume, stderrDouble)
	}
	_, emptyCode, emptyDone, emptyStderr := parse(t, "--rootfs-volume=", "alpine:3.20")
	if !emptyDone || emptyCode != 2 || !strings.Contains(emptyStderr, "--rootfs-volume") {
		t.Fatalf("parse(--rootfs-volume=) = (code=%d done=%v stderr=%q), want exit 2", emptyCode, emptyDone, emptyStderr)
	}

	var restoreErr bytes.Buffer
	resCfg, resCode, resDone := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"--rootfs-volume=myroot",
	}, nil, &bytes.Buffer{}, &restoreErr)
	if resDone || resCode != 0 || resCfg.cfg.RootVolume != "myroot" {
		t.Fatalf("parseRestoreArgs(--rootfs-volume) = (code=%d done=%v rootVol=%q stderr=%q)", resCode, resDone, resCfg.cfg.RootVolume, restoreErr.String())
	}
	var restoreEmptyErr bytes.Buffer
	_, resEmptyCode, resEmptyDone := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"-rootfs-volume", "   ",
	}, nil, &bytes.Buffer{}, &restoreEmptyErr)
	if !resEmptyDone || resEmptyCode != 2 || !strings.Contains(restoreEmptyErr.String(), "--rootfs-volume") {
		t.Fatalf("parseRestoreArgs(empty -rootfs-volume) = (code=%d done=%v stderr=%q), want exit 2", resEmptyCode, resEmptyDone, restoreEmptyErr.String())
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
		"-workspace=" + wsDir,
		"-w=/srv",
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
	if rc.cfg.WorkDir != "/srv" {
		t.Errorf("WorkDir = %q, want /srv", rc.cfg.WorkDir)
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

	rc2, code2, done2 := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"--platform", "linux/arm64",
		"--backend", "systrap",
	}, nil, &bytes.Buffer{}, &stderr)
	if done2 || code2 != 0 || rc2.cfg.Architecture != "arm64" || rc2.cfg.Platform != gvx.PlatformSystrap || rc2.autoPlatform {
		t.Fatalf("restore --platform/--backend failed: code=%d done=%v arch=%q plat=%q auto=%v stderr=%q",
			code2, done2, rc2.cfg.Architecture, rc2.cfg.Platform, rc2.autoPlatform, stderr.String())
	}
	if rc2.cfg.NetworkMode != "" {
		t.Errorf("restore without network flags chooses %q, want to inherit bundle mode", rc2.cfg.NetworkMode)
	}

	rc3, code3, done3 := parseRestoreArgs([]string{
		"-checkpoint-dir=/tmp/bundle",
		"--net-tx-bps=0",
		"--net-rx-bps=500000",
	}, nil, &bytes.Buffer{}, &stderr)
	if done3 || code3 != 0 || rc3.cfg.NetworkMode != gvx.NetModeNAT ||
		rc3.cfg.NetworkBandwidth.TXBPS != 0 || rc3.cfg.NetworkBandwidth.RXBPS != 500_000 {
		t.Fatalf("restore bandwidth flags: code=%d, done=%t, mode=%q, bandwidth=%+v, stderr=%q",
			code3, done3, rc3.cfg.NetworkMode, rc3.cfg.NetworkBandwidth, stderr.String())
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
		{"non-NAT bandwidth", "restore", []string{"-checkpoint-dir=/tmp/b", "--net=wg", "--net-rx-bps=0"}, 2, "require -net=nat"},
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
	ep, err := control.Listen(sockPath, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen(%q): %v", sockPath, err)
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
	if _, err := control.Listen(regFile, control.ListenOptions{}); err == nil {
		t.Fatal("control.Listen succeeded on regular file, want error")
	}

	// Rejects non-loopback TCP addresses.
	if _, err := control.Listen("tcp://8.8.8.8:9999", control.ListenOptions{}); err == nil {
		t.Fatal("control.Listen accepted non-loopback TCP address, want error")
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
				"-workspace=" + wsDir,
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

func TestCheckpointAndRestoreCLIOverlayMounts(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)
	cacheDir := filepath.Join(t.TempDir(), "cache")
	ckptDir := filepath.Join(t.TempDir(), "ckpt-ovl-cli")
	sockPath := filepath.Join(shortSocketDir(t), "ovl.sock")

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	writeBaseELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/data/base.txt", "base-from-cli\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(base): %v", err)
	}
	writeUpperELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/ovl/upper.txt", "upper-from-cli\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(upper): %v", err)
	}
	catPath := filepath.Join(t.TempDir(), "cat.elf")
	writeBasePath := filepath.Join(t.TempDir(), "write-base.elf")
	writeUpperPath := filepath.Join(t.TempDir(), "write-upper.elf")
	for p, b := range map[string][]byte{catPath: catELF, writeBasePath: writeBaseELF, writeUpperPath: writeUpperELF} {
		if wErr := os.WriteFile(p, b, 0o755); wErr != nil {
			t.Fatal(wErr)
		}
	}

	// Seed base-cli volume, then seed branch-cli overlay upper via CLI!
	runCLIArgs(t, nil, "run", "-lockdown=false", "-platform="+platform, "-net=none", "-cache-dir="+cacheDir, "-v=base-cli:/data", "-bin="+writeBasePath).mustSucceed(t, "seed base-cli")
	runCLIArgs(t, nil, "run", "-lockdown=false", "-platform="+platform, "-net=none", "-cache-dir="+cacheDir, "--mount=type=overlay,src=base-cli,upper=branch-cli,dst=/ovl", "-bin="+writeUpperPath).mustSucceed(t, "seed branch-cli")

	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()
	stdout1 := newSyncNotifyBuffer()
	stderr1 := newSyncNotifyBuffer()
	runDone := make(chan int, 1)
	go func() {
		runDone <- executeCLI(
			context.Background(),
			[]string{
				"run",
				"-lockdown=false",
				"-platform=" + platform,
				"-net=none",
				"-cache-dir=" + cacheDir,
				"--mount=type=overlay,src=base-cli,upper=branch-cli,dst=/ovl",
				"--mount=type=overlay,src=base-cli,dst=/scratch,tmpfs-size=16m",
				"-checkpoint-dir=" + ckptDir,
				"-control-socket=" + sockPath,
				"-bin=" + catPath,
				"--",
				"/ovl/upper.txt",
				"/proc/self/fd/0",
				"/ovl/base.txt",
				"/scratch/base.txt",
			},
			stdinR,
			stdout1,
			stderr1,
		)
	}()

	stdout1.waitForSubstring(t, "upper-from-cli\n", 15*time.Second)

	var ckptOut, ckptErr bytes.Buffer
	if code := executeCLI(context.Background(), []string{"checkpoint", "-control-socket=" + sockPath, "-checkpoint-dir=" + ckptDir}, nil, &ckptOut, &ckptErr); code != 0 {
		t.Fatalf("rungv checkpoint = (%d, %q), want 0", code, ckptErr.String())
	}
	if exit := <-runDone; exit != 0 {
		t.Fatalf("rungv run exit = %d, stderr = %q", exit, stderr1.String())
	}

	var stdout2, stderr2 bytes.Buffer
	resCode := executeCLI(
		context.Background(),
		[]string{
			"restore",
			"-lockdown=false",
			"-platform=" + platform,
			"-net=none",
			"-cache-dir=" + cacheDir,
			"--mount=type=overlay,src=base-cli,upper=branch-cli,dst=/ovl",
			"--mount=type=overlay,src=base-cli,dst=/scratch,tmpfs-size=16m",
			"-checkpoint-dir=" + ckptDir,
		},
		strings.NewReader("cli-resumed\n"),
		&stdout2,
		&stderr2,
	)
	if resCode != 0 {
		t.Fatalf("rungv restore = (%d, %q), want 0", resCode, stderr2.String())
	}
	if want := "cli-resumed\nbase-from-cli\nbase-from-cli\n"; stdout2.String() != want {
		t.Fatalf("rungv restore stdout = %q, want %q", stdout2.String(), want)
	}
}
