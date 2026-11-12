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

//go:build darwin || windows || linux

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

const (
	restoreLockdownHelperEnv = "GVX_E2E_RESTORE_LOCKDOWN_HELPER"
	restoreLockdownDirEnv    = "GVX_E2E_RESTORE_LOCKDOWN_DIR"
	restoreLockdownWS        = "GVX_E2E_RESTORE_LOCKDOWN_WS"
	restoreLockdownCacheEnv  = "GVX_E2E_RESTORE_LOCKDOWN_CACHE"
	restoreLockdownPlatEnv   = "GVX_E2E_RESTORE_LOCKDOWN_PLAT"
	restoreLockdownProbeFile = "GVX_E2E_RESTORE_LOCKDOWN_OUTSIDE_FILE"
	restoreLockdownProbeDir  = "GVX_E2E_RESTORE_LOCKDOWN_OUTSIDE_DIR"
)

// checkpointNotifyBuffer collects guest output and wakes readers when new
// bytes arrive.
type checkpointNotifyBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
	ch  chan struct{}
}

func newCheckpointNotifyBuffer() *checkpointNotifyBuffer {
	return &checkpointNotifyBuffer{ch: make(chan struct{}, 1)}
}

func (b *checkpointNotifyBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	n, err := b.buf.Write(p)
	b.mu.Unlock()
	select {
	case b.ch <- struct{}{}:
	default:
	}
	return n, err
}

func (b *checkpointNotifyBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func (b *checkpointNotifyBuffer) waitForSubstring(t *testing.T, want string, timeout time.Duration, stderr ...*checkpointNotifyBuffer) {
	t.Helper()
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	for {
		if strings.Contains(b.String(), want) {
			return
		}
		select {
		case <-b.ch:
		case <-deadline.C:
			var errText string
			if len(stderr) > 0 && stderr[0] != nil {
				errText = stderr[0].String()
			}
			t.Fatalf("timed out after %v waiting for %q in output %q (stderr=%q)", timeout, want, b.String(), errText)
		}
	}
}

func shortCheckpointSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "gvxckpt")
	if err != nil {
		t.Fatalf("create short socket directory: %v", err)
	}
	t.Cleanup(func() {
		_ = os.RemoveAll(dir)
	})
	return dir
}

func freeLoopbackControlSocketAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate loopback TCP port: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func canBindUnixControlSocket(dir string) bool {
	if runtime.GOOS == "android" {
		return false
	}
	probe := filepath.Join(dir, "probe.sock")
	ln, err := net.Listen("unix", probe)
	if err != nil {
		return false
	}
	_ = ln.Close()
	_ = os.Remove(probe)
	return true
}

func verifyCheckpointBundleFiles(t *testing.T, dir string) {
	t.Helper()
	for _, name := range []string{"manifest.json", "state.img", "pages.meta", "pages.img"} {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat checkpoint file %s: %v", p, err)
		}
		if name != "pages.img" && fi.Size() == 0 {
			t.Fatalf("checkpoint file %s is empty", p)
		}
	}
}

// TestE2ECheckpointRestoreMemoryState verifies that Sandbox.Checkpoint and
// gvx.Restore preserve guest heap allocations and anonymous private mmap pages.
func TestE2ECheckpointRestoreMemoryState(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			ckptDir := filepath.Join(t.TempDir(), "bundle")

			stdinR1, stdinW1 := io.Pipe()
			defer stdinW1.Close()

			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				BinaryPath:          probePath,
				Argv:                []string{"-mode=memory"},
				Stdin:               stdinR1,
				Stdout:              stdout1,
				Stderr:              stderr1,
				CheckpointDir:       ckptDir,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "create memory checkpoint sandbox", err)
			defer func() { _ = sb.Close() }()

			runErrCh := make(chan error, 1)
			runCodeCh := make(chan int, 1)
			go func() {
				code, rErr := sb.Run(ctx)
				runCodeCh <- code
				runErrCh <- rErr
			}()

			stdout1.waitForSubstring(t, "READY:memory\n", 30*time.Second)

			if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: false}); err != nil {
				t.Fatalf("Checkpoint(memory) failed: %v (stderr=%q)", err, stderr1.String())
			}
			if rErr := <-runErrCh; rErr != nil {
				t.Fatalf("pre-checkpoint Run returned error: %v (stderr=%q)", rErr, stderr1.String())
			}
			if code := <-runCodeCh; code != 0 {
				t.Fatalf("pre-checkpoint exit code = %d, want 0 (stderr=%q)", code, stderr1.String())
			}
			if err := sb.Close(); err != nil {
				t.Fatalf("Close pre-checkpoint sandbox: %v", err)
			}
			verifyCheckpointBundleFiles(t, ckptDir)

			var stdout2, stderr2 bytes.Buffer
			restoredSB, err := gvx.Restore(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				Stdin:               strings.NewReader("RESUME\n"),
				Stdout:              &stdout2,
				Stderr:              &stderr2,
				DisableHostLockdown: true,
			}, gvx.RestoreOptions{Dir: ckptDir})
			if err != nil {
				t.Fatalf("Restore(memory) failed: %v", err)
			}
			defer func() { _ = restoredSB.Close() }()

			code, err := restoredSB.Run(ctx)
			if err != nil || code != 0 {
				t.Fatalf("restored Run(memory) = (code %d, err %v), stdout=%q stderr=%q",
					code, err, stdout2.String(), stderr2.String())
			}
			if !strings.Contains(stdout2.String(), "VERIFIED:memory\n") {
				t.Fatalf("restored stdout = %q, want VERIFIED:memory", stdout2.String())
			}
		})
	}
}

// TestE2ECheckpointRestoreHostfsState verifies that Sandbox.Checkpoint and
// gvx.Restore preserve hostfs open file seek offsets, MAP_SHARED file mappings,
// and unlinked open temporary files on /workspace.
func TestE2ECheckpointRestoreHostfsState(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			wsDir := t.TempDir()
			ckptDir := filepath.Join(t.TempDir(), "bundle")

			stdinR1, stdinW1 := io.Pipe()
			defer stdinW1.Close()

			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				WorkspacePath:       wsDir,
				BinaryPath:          probePath,
				Argv:                []string{"-mode=hostfs", "-workspace=/workspace"},
				Stdin:               stdinR1,
				Stdout:              stdout1,
				Stderr:              stderr1,
				CheckpointDir:       ckptDir,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "create hostfs checkpoint sandbox", err)
			defer func() { _ = sb.Close() }()

			runErrCh := make(chan error, 1)
			runCodeCh := make(chan int, 1)
			go func() {
				code, rErr := sb.Run(ctx)
				runCodeCh <- code
				runErrCh <- rErr
			}()

			stdout1.waitForSubstring(t, "READY:hostfs\n", 30*time.Second)

			if _, err := os.Stat(filepath.Join(wsDir, "unlinked.tmp")); !os.IsNotExist(err) {
				t.Fatalf("stat unlinked.tmp before checkpoint = %v, want not exist", err)
			}

			if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: false}); err != nil {
				t.Fatalf("Checkpoint(hostfs) failed: %v (stderr=%q)", err, stderr1.String())
			}
			if rErr := <-runErrCh; rErr != nil {
				t.Fatalf("pre-checkpoint Run returned error: %v (stderr=%q)", rErr, stderr1.String())
			}
			if code := <-runCodeCh; code != 0 {
				t.Fatalf("pre-checkpoint exit code = %d, want 0 (stderr=%q)", code, stderr1.String())
			}
			if err := sb.Close(); err != nil {
				t.Fatalf("Close pre-checkpoint sandbox: %v", err)
			}
			verifyCheckpointBundleFiles(t, ckptDir)

			var stdout2, stderr2 bytes.Buffer
			restoredSB, err := gvx.Restore(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				WorkspacePath:       wsDir,
				Stdin:               strings.NewReader("RESUME\n"),
				Stdout:              &stdout2,
				Stderr:              &stderr2,
				DisableHostLockdown: true,
			}, gvx.RestoreOptions{Dir: ckptDir})
			if err != nil {
				t.Fatalf("Restore(hostfs) failed: %v", err)
			}
			defer func() { _ = restoredSB.Close() }()

			code, err := restoredSB.Run(ctx)
			if err != nil || code != 0 {
				t.Fatalf("restored Run(hostfs) = (code %d, err %v), stdout=%q stderr=%q",
					code, err, stdout2.String(), stderr2.String())
			}
			if !strings.Contains(stdout2.String(), "VERIFIED:hostfs\n") {
				t.Fatalf("restored stdout = %q, want VERIFIED:hostfs", stdout2.String())
			}
			if err := restoredSB.Close(); err != nil {
				t.Fatalf("Close restored sandbox: %v", err)
			}

			verifyHostfsWorkspaceArtifacts(t, wsDir)
		})
	}
}

func verifyHostfsWorkspaceArtifacts(t *testing.T, wsDir string) {
	t.Helper()
	offsetBytes, err := os.ReadFile(filepath.Join(wsDir, "offset.bin"))
	if err != nil {
		t.Fatalf("read offset.bin on host: %v", err)
	}
	const wantOffsetBanner = "POST-RESTORE-AT-1401"
	const bannerStart = 1337 + 64
	if len(offsetBytes) != 8192 {
		t.Fatalf("offset.bin size = %d, want 8192", len(offsetBytes))
	}
	gotOffsetBanner := string(offsetBytes[bannerStart : bannerStart+len(wantOffsetBanner)])
	if gotOffsetBanner != wantOffsetBanner {
		t.Fatalf("offset.bin at %d = %q, want %q", bannerStart, gotOffsetBanner, wantOffsetBanner)
	}

	sharedBytes, err := os.ReadFile(filepath.Join(wsDir, "shared.bin"))
	if err != nil {
		t.Fatalf("read shared.bin on host: %v", err)
	}
	const wantPreMap = "HOSTFS-MAP-BEFORE-CKPT"
	const wantPostMap = "HOSTFS-MAP-AFTER-RESTORE"
	if string(sharedBytes[:len(wantPreMap)]) != wantPreMap {
		t.Fatalf("shared.bin prefix = %q, want %q", string(sharedBytes[:len(wantPreMap)]), wantPreMap)
	}
	if string(sharedBytes[4096:4096+len(wantPostMap)]) != wantPostMap {
		t.Fatalf("shared.bin at 4096 = %q, want %q", string(sharedBytes[4096:4096+len(wantPostMap)]), wantPostMap)
	}

	if _, err := os.Stat(filepath.Join(wsDir, "unlinked.tmp")); !os.IsNotExist(err) {
		t.Fatalf("stat unlinked.tmp on host after restore = %v, want not exist", err)
	}
}

// TestE2ECheckpointRestoreExt4liteState verifies that Sandbox.Checkpoint and
// gvx.Restore preserve ext4lite open files, unlinked open files, linkable
// O_TMPFILE inodes, and exclusive O_TMPFILE|O_EXCL inodes across sandboxes.
func TestE2ECheckpointRestoreExt4liteState(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			volImg := filepath.Join(t.TempDir(), "data.ext4")
			ckptDir := filepath.Join(t.TempDir(), "bundle")

			volMounts := []gvx.Mount{{
				Kind:      gvx.MountVolume,
				ImagePath: volImg,
				GuestPath: "/mnt/vol",
			}}

			stdinR1, stdinW1 := io.Pipe()
			defer stdinW1.Close()

			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				BinaryPath:          probePath,
				Argv:                []string{"-mode=ext4lite", "-vol=/mnt/vol"},
				Mounts:              volMounts,
				Stdin:               stdinR1,
				Stdout:              stdout1,
				Stderr:              stderr1,
				CheckpointDir:       ckptDir,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "create ext4lite checkpoint sandbox", err)
			defer func() { _ = sb.Close() }()

			runErrCh := make(chan error, 1)
			runCodeCh := make(chan int, 1)
			go func() {
				code, rErr := sb.Run(ctx)
				runCodeCh <- code
				runErrCh <- rErr
			}()

			stdout1.waitForSubstring(t, "READY:ext4lite\n", 30*time.Second)

			if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: false}); err != nil {
				t.Fatalf("Checkpoint(ext4lite) failed: %v (stderr=%q)", err, stderr1.String())
			}
			if rErr := <-runErrCh; rErr != nil {
				t.Fatalf("pre-checkpoint Run returned error: %v (stderr=%q)", rErr, stderr1.String())
			}
			if code := <-runCodeCh; code != 0 {
				t.Fatalf("pre-checkpoint exit code = %d, want 0 (stderr=%q)", code, stderr1.String())
			}
			if err := sb.Close(); err != nil {
				t.Fatalf("Close pre-checkpoint sandbox: %v", err)
			}
			verifyCheckpointBundleFiles(t, ckptDir)

			var stdout2, stderr2 bytes.Buffer
			restoredSB, err := gvx.Restore(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				Mounts:              volMounts,
				Stdin:               strings.NewReader("RESUME\n"),
				Stdout:              &stdout2,
				Stderr:              &stderr2,
				DisableHostLockdown: true,
			}, gvx.RestoreOptions{Dir: ckptDir})
			if err != nil {
				t.Fatalf("Restore(ext4lite) failed: %v", err)
			}
			defer func() { _ = restoredSB.Close() }()

			code, err := restoredSB.Run(ctx)
			if err != nil || code != 0 {
				t.Fatalf("restored Run(ext4lite) = (code %d, err %v), stdout=%q stderr=%q",
					code, err, stdout2.String(), stderr2.String())
			}
			if !strings.Contains(stdout2.String(), "VERIFIED:ext4lite\n") {
				t.Fatalf("restored stdout = %q, want VERIFIED:ext4lite", stdout2.String())
			}
			if err := restoredSB.Close(); err != nil {
				t.Fatalf("Close restored ext4lite sandbox: %v", err)
			}
			requireCleanImage(t, volImg, "after-restore")

			// Mount the ext4lite volume read-only in a third sandbox to verify persisted disk state.
			var stdout3, stderr3 bytes.Buffer
			verifySB, err := gvx.New(ctx, gvx.Config{
				Platform:    b.plat,
				NetworkMode: gvx.NetModeNone,
				OCICacheDir: cacheDir,
				BinaryPath:  probePath,
				Argv:        []string{"-mode=ext4lite-verify", "-vol=/mnt/vol"},
				Mounts: []gvx.Mount{{
					Kind:      gvx.MountVolume,
					ImagePath: volImg,
					GuestPath: "/mnt/vol",
					ReadOnly:  true,
				}},
				Stdout:              &stdout3,
				Stderr:              &stderr3,
				DisableHostLockdown: true,
			})
			if err != nil {
				t.Fatalf("create ext4lite verification sandbox: %v", err)
			}
			defer func() { _ = verifySB.Close() }()

			vCode, vErr := verifySB.Run(ctx)
			if vErr != nil || vCode != 0 || !strings.Contains(stdout3.String(), "VERIFIED:ext4lite-verify\n") {
				t.Fatalf("ext4lite-verify = (code %d, err %v), stdout=%q stderr=%q",
					vCode, vErr, stdout3.String(), stderr3.String())
			}
		})
	}
}

func exchangeForwardedTCP(t *testing.T, hostPort int, sendLine, wantReply string) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", hostPort)
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		t.Fatalf("dial forwarded port %s: %v", addr, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := io.WriteString(conn, sendLine); err != nil {
		t.Fatalf("write to forwarded port %s: %v", addr, err)
	}
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read from forwarded port %s: %v", addr, err)
	}
	if reply != wantReply {
		t.Fatalf("forwarded port %s reply = %q, want %q", addr, reply, wantReply)
	}
}

// TestE2ECheckpointRestoreNetnsIPSetPortForwarding verifies that checkpoint
// and restore preserve child network namespaces, per-namespace ipset state, and
// -p TCP port forwarding connectivity after gvx.Restore rebinds the listener.
func TestE2ECheckpointRestoreNetnsIPSetPortForwarding(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			ckptDir := filepath.Join(t.TempDir(), "bundle")

			stdinR1, stdinW1 := io.Pipe()
			defer stdinW1.Close()

			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			sb, err := gvx.New(ctx, gvx.Config{
				Platform:    b.plat,
				NetworkMode: gvx.NetModeNAT,
				NetRaw:      true,
				OCICacheDir: cacheDir,
				BinaryPath:  probePath,
				Argv:        []string{"-mode=net"},
				PortForwards: []gvx.PortForward{{
					BindAddress: "127.0.0.1",
					HostPort:    0,
					GuestPort:   8080,
					Protocol:    "tcp",
				}},
				Stdin:               stdinR1,
				Stdout:              stdout1,
				Stderr:              stderr1,
				CheckpointDir:       ckptDir,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "create net checkpoint sandbox", err)
			defer func() { _ = sb.Close() }()

			runErrCh := make(chan error, 1)
			runCodeCh := make(chan int, 1)
			go func() {
				code, rErr := sb.Run(ctx)
				runCodeCh <- code
				runErrCh <- rErr
			}()

			stdout1.waitForSubstring(t, "READY:net\n", 30*time.Second, stderr1)

			prePort := sb.BoundPort(0)
			if prePort == 0 {
				t.Fatalf("pre-checkpoint BoundPort(0) = 0, want non-zero port")
			}
			exchangeForwardedTCP(t, prePort, "ping-before-ckpt\n", "pong-before-ckpt\n")
			stdout1.waitForSubstring(t, "PRE_CONN_DONE:net\n", 15*time.Second, stderr1)

			if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: false}); err != nil {
				t.Fatalf("Checkpoint(net) failed: %v (stderr=%q)", err, stderr1.String())
			}
			if rErr := <-runErrCh; rErr != nil {
				t.Fatalf("pre-checkpoint Run returned error: %v (stderr=%q)", rErr, stderr1.String())
			}
			if code := <-runCodeCh; code != 0 {
				t.Fatalf("pre-checkpoint exit code = %d, want 0 (stderr=%q)", code, stderr1.String())
			}
			if err := sb.Close(); err != nil {
				t.Fatalf("Close pre-checkpoint net sandbox: %v", err)
			}
			verifyCheckpointBundleFiles(t, ckptDir)

			stdinR2, stdinW2 := io.Pipe()
			defer stdinW2.Close()

			stdout2 := newCheckpointNotifyBuffer()
			stderr2 := newCheckpointNotifyBuffer()

			restoredSB, err := gvx.Restore(ctx, gvx.Config{
				Platform:    b.plat,
				NetworkMode: gvx.NetModeNAT,
				NetRaw:      true,
				OCICacheDir: cacheDir,
				PortForwards: []gvx.PortForward{{
					BindAddress: "127.0.0.1",
					HostPort:    0,
					GuestPort:   8080,
					Protocol:    "tcp",
				}},
				Stdin:               stdinR2,
				Stdout:              stdout2,
				Stderr:              stderr2,
				DisableHostLockdown: true,
			}, gvx.RestoreOptions{Dir: ckptDir})
			if err != nil {
				t.Fatalf("Restore(net) failed: %v", err)
			}
			defer func() { _ = restoredSB.Close() }()

			postRunErrCh := make(chan error, 1)
			postRunCodeCh := make(chan int, 1)
			go func() {
				code, rErr := restoredSB.Run(ctx)
				postRunCodeCh <- code
				postRunErrCh <- rErr
			}()

			if _, err := io.WriteString(stdinW2, "RESUME\n"); err != nil {
				t.Fatalf("write RESUME to restored net sandbox: %v", err)
			}
			_ = stdinW2.Close()

			stdout2.waitForSubstring(t, "READY_POST_CONN:net\n", 30*time.Second, stderr2)

			postPort := restoredSB.BoundPort(0)
			if postPort == 0 {
				t.Fatalf("post-restore BoundPort(0) = 0, want non-zero port")
			}
			exchangeForwardedTCP(t, postPort, "ping-after-restore\n", "pong-after-restore\n")

			stdout2.waitForSubstring(t, "VERIFIED:net\n", 15*time.Second, stderr2)
			if rErr := <-postRunErrCh; rErr != nil {
				t.Fatalf("restored Run(net) error: %v (stderr=%q)", rErr, stderr2.String())
			}
			if code := <-postRunCodeCh; code != 0 {
				t.Fatalf("restored Run(net) exit code = %d, want 0 (stderr=%q)", code, stderr2.String())
			}
		})
	}
}

type restoreLockdownReport struct {
	RestoredSecurityPosture gvx.SecurityPosture `json:"restored_security_posture"`
	OutsideReadBlocked      bool                `json:"outside_read_blocked"`
	OutsideWriteBlocked     bool                `json:"outside_write_blocked"`
	SubprocessBlockedByOS   bool                `json:"subprocess_blocked_by_os"`
	ExitCode                int                 `json:"exit_code"`
	GuestStdout             string              `json:"guest_stdout"`
	GuestStderr             string              `json:"guest_stderr"`
	Error                   string              `json:"error,omitempty"`
}

func runRestoreLockdownHelperSubprocess(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ckptDir := os.Getenv(restoreLockdownDirEnv)
	wsDir := os.Getenv(restoreLockdownWS)
	cacheDir := os.Getenv(restoreLockdownCacheEnv)
	plat := gvx.PlatformType(os.Getenv(restoreLockdownPlatEnv))
	outsideFile := os.Getenv(restoreLockdownProbeFile)
	outsideDir := os.Getenv(restoreLockdownProbeDir)
	selfExe, exeErr := os.Executable()

	var stdoutBuf, stderrBuf bytes.Buffer
	restoredSB, err := gvx.Restore(ctx, gvx.Config{
		Platform:            plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         cacheDir,
		WorkspacePath:       wsDir,
		Stdin:               strings.NewReader("RESUME\n"),
		Stdout:              &stdoutBuf,
		Stderr:              &stderrBuf,
		DisableHostLockdown: false,
	}, gvx.RestoreOptions{Dir: ckptDir})

	var rep restoreLockdownReport
	if err != nil {
		rep.Error = err.Error()
		emitLockdownReportAndExit(rep)
		return
	}
	defer func() { _ = restoredSB.Close() }()

	rep.RestoredSecurityPosture = restoredSB.SecurityPosture()

	if _, rErr := os.ReadFile(outsideFile); rErr != nil {
		rep.OutsideReadBlocked = true
	}
	if wErr := os.WriteFile(filepath.Join(outsideDir, "escape.txt"), []byte("nope"), 0o600); wErr != nil {
		rep.OutsideWriteBlocked = true
	}
	if exeErr == nil {
		if cErr := exec.Command(selfExe, "-test.list=^$").Run(); cErr != nil {
			rep.SubprocessBlockedByOS = true
		}
	}

	code, runErr := restoredSB.Run(ctx)
	rep.ExitCode = code
	rep.GuestStdout = stdoutBuf.String()
	rep.GuestStderr = stderrBuf.String()
	if runErr != nil {
		rep.Error = runErr.Error()
	}
	_ = restoredSB.Close()
	emitLockdownReportAndExit(rep)
}

func emitLockdownReportAndExit(rep restoreLockdownReport) {
	enc, _ := json.Marshal(rep)
	fmt.Printf("LOCKDOWN_REPORT_JSON:%s\n", string(enc))
}

// TestE2ECheckpointRestoreHostLockdownInvariants verifies that gvx.Restore with
// default host lockdown enforces SubprocessBlocked and UnboundFileOpenBlocked
// before loading checkpoint state and running the restored guest.
func TestE2ECheckpointRestoreHostLockdownInvariants(t *testing.T) {
	if os.Getenv(restoreLockdownHelperEnv) == "1" {
		runRestoreLockdownHelperSubprocess(t)
		return
	}

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cacheDir := t.TempDir()
			wsDir := t.TempDir()
			ckptDir := filepath.Join(t.TempDir(), "bundle")
			outsideDir := t.TempDir()
			outsideFile := filepath.Join(outsideDir, "secret.txt")
			if err := os.WriteFile(outsideFile, []byte("host-secret"), 0o600); err != nil {
				t.Fatal(err)
			}

			stdinR1, stdinW1 := io.Pipe()
			defer stdinW1.Close()

			stdout1 := newCheckpointNotifyBuffer()
			stderr1 := newCheckpointNotifyBuffer()

			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				WorkspacePath:       wsDir,
				BinaryPath:          probePath,
				Argv:                []string{"-mode=hostfs", "-workspace=/workspace"},
				Stdin:               stdinR1,
				Stdout:              stdout1,
				Stderr:              stderr1,
				CheckpointDir:       ckptDir,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "create lockdown checkpoint sandbox", err)
			defer func() { _ = sb.Close() }()

			runErrCh := make(chan error, 1)
			go func() {
				_, rErr := sb.Run(ctx)
				runErrCh <- rErr
			}()

			stdout1.waitForSubstring(t, "READY:hostfs\n", 30*time.Second)

			if err := sb.Checkpoint(ctx, gvx.CheckpointOptions{LeaveRunning: false}); err != nil {
				t.Fatalf("Checkpoint(lockdown) failed: %v", err)
			}
			if rErr := <-runErrCh; rErr != nil {
				t.Fatalf("pre-checkpoint Run failed: %v", rErr)
			}
			if err := sb.Close(); err != nil {
				t.Fatalf("Close pre-checkpoint sandbox: %v", err)
			}

			selfExe, err := os.Executable()
			if err != nil {
				t.Fatalf("os.Executable: %v", err)
			}
			cmd := exec.CommandContext(ctx, selfExe, "-test.run=^TestE2ECheckpointRestoreHostLockdownInvariants$")
			cmd.Env = append(os.Environ(),
				restoreLockdownHelperEnv+"=1",
				restoreLockdownDirEnv+"="+ckptDir,
				restoreLockdownWS+"="+wsDir,
				restoreLockdownCacheEnv+"="+cacheDir,
				restoreLockdownPlatEnv+"="+string(b.plat),
				restoreLockdownProbeFile+"="+outsideFile,
				restoreLockdownProbeDir+"="+outsideDir,
			)
			outBytes, cmdErr := cmd.CombinedOutput()
			outStr := string(outBytes)

			var repJSON string
			for _, line := range strings.Split(outStr, "\n") {
				if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "LOCKDOWN_REPORT_JSON:"); ok {
					repJSON = rest
					break
				}
			}
			if repJSON == "" {
				t.Fatalf("restore lockdown helper did not emit report (err=%v):\n%s", cmdErr, outStr)
			}

			var rep restoreLockdownReport
			if err := json.Unmarshal([]byte(repJSON), &rep); err != nil {
				t.Fatalf("unmarshal restore lockdown report %q: %v", repJSON, err)
			}
			if rep.Error != "" {
				t.Fatalf("restore lockdown helper failed: %s (stderr=%q)", rep.Error, rep.GuestStderr)
			}
			if !rep.RestoredSecurityPosture.Lockdown.Applied {
				t.Errorf("RestoredSecurityPosture.Lockdown.Applied = false, want true")
			}
			if !rep.RestoredSecurityPosture.Lockdown.SubprocessBlocked {
				t.Errorf("RestoredSecurityPosture.Lockdown.SubprocessBlocked = false, want true")
			}
			if !rep.SubprocessBlockedByOS {
				t.Errorf("SubprocessBlockedByOS = false, want child process creation denied after gvx.Restore")
			}
			if runtime.GOOS == "darwin" || runtime.GOOS == "linux" {
				if !rep.RestoredSecurityPosture.Lockdown.UnboundFileOpenBlocked {
					t.Errorf("RestoredSecurityPosture.Lockdown.UnboundFileOpenBlocked = false on %s, want true", runtime.GOOS)
				}
			}
			if rep.RestoredSecurityPosture.Lockdown.UnboundFileOpenBlocked {
				if !rep.OutsideReadBlocked || !rep.OutsideWriteBlocked {
					t.Errorf("outside host file access after Restore = (readBlocked=%v, writeBlocked=%v), want both true",
						rep.OutsideReadBlocked, rep.OutsideWriteBlocked)
				}
			}
			if rep.ExitCode != 0 || !strings.Contains(rep.GuestStdout, "VERIFIED:hostfs\n") {
				t.Fatalf("restored guest = (code %d, stdout %q, stderr %q), want (0, VERIFIED:hostfs)",
					rep.ExitCode, rep.GuestStdout, rep.GuestStderr)
			}
			verifyHostfsWorkspaceArtifacts(t, wsDir)
		})
	}
}

// TestE2ECheckpointRestoreRungvCLIRoundTrip verifies end-to-end execution of
// rungv run, rungv checkpoint, and rungv restore under default host lockdown
// over both Unix and loopback TCP control sockets.
func TestE2ECheckpointRestoreRungvCLIRoundTrip(t *testing.T) {
	rungvBin := toolPath(t, rungvPkg)
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			probePath := acceptprog.BuildCheckpointProbe(t, hostArch())

			for _, mode := range []string{"tcp", "unix"} {
				t.Run(mode, func(t *testing.T) {
					var controlAddr string
					switch mode {
					case "tcp":
						controlAddr = freeLoopbackControlSocketAddr(t)
					case "unix":
						sockDir := shortCheckpointSocketDir(t)
						if !canBindUnixControlSocket(sockDir) {
							t.Skipf("unix socket bind not permitted in %s on %s", sockDir, runtime.GOOS)
						}
						controlAddr = filepath.Join(sockDir, "ctrl.sock")
					}

					ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
					defer cancel()

					cacheDir := t.TempDir()
					wsDir := t.TempDir()
					ckptDir := filepath.Join(t.TempDir(), "bundle")

					stdinR1, stdinW1 := io.Pipe()
					defer stdinW1.Close()

					stdout1 := newCheckpointNotifyBuffer()
					stderr1 := newCheckpointNotifyBuffer()

					runCmd := exec.CommandContext(ctx, rungvBin,
						"run",
						"-platform="+string(b.plat),
						"-net=none",
						"-cache-dir="+cacheDir,
						"-workspace="+wsDir,
						"-checkpoint-dir="+ckptDir,
						"-control-socket="+controlAddr,
						"-bin="+probePath,
						"--",
						"-mode=hostfs",
						"-workspace=/workspace",
					)
					runCmd.Stdin = stdinR1
					runCmd.Stdout = stdout1
					runCmd.Stderr = stderr1

					if err := runCmd.Start(); err != nil {
						t.Fatalf("start rungv run: %v", err)
					}

					runWaitCh := make(chan error, 1)
					go func() {
						runWaitCh <- runCmd.Wait()
					}()
					defer func() {
						_ = stdinW1.Close()
						if runCmd.Process != nil {
							_ = runCmd.Process.Kill()
						}
					}()

					// Wait until the guest signals readiness or rungv exits on an unsupported ET_EXEC backend.
					readyTimer := time.NewTimer(30 * time.Second)
					defer readyTimer.Stop()
					for !strings.Contains(stdout1.String(), "READY:hostfs\n") {
						select {
						case wErr := <-runWaitCh:
							skipWhenFixedAddressRefused(t, "rungv run", fmt.Errorf("%w: %s", wErr, stderr1.String()))
							t.Fatalf("rungv run exited before READY: %v (stdout=%q stderr=%q)", wErr, stdout1.String(), stderr1.String())
						case <-stdout1.ch:
						case <-stderr1.ch:
							if strings.Contains(stderr1.String(), "rungv run:") {
								_ = stdinW1.Close()
							}
						case <-readyTimer.C:
							t.Fatalf("timed out waiting for READY:hostfs from rungv run (stdout=%q stderr=%q)", stdout1.String(), stderr1.String())
						}
					}

					ckptOut, ckptStderr, ckptCode := runTool(t, rungvBin,
						"checkpoint",
						"-control-socket="+controlAddr,
						"-checkpoint-dir="+ckptDir,
					)
					if ckptCode != 0 {
						t.Fatalf("rungv checkpoint = (code %d, stdout %q, stderr %q), want 0", ckptCode, ckptOut, ckptStderr)
					}
					_ = stdinW1.Close()

					if wErr := <-runWaitCh; wErr != nil {
						t.Fatalf("rungv run exit after checkpoint: %v (stderr=%q)", wErr, stderr1.String())
					}
					verifyCheckpointBundleFiles(t, ckptDir)

					var restoreStdout, restoreStderr bytes.Buffer
					restoreCmd := exec.CommandContext(ctx, rungvBin,
						"restore",
						"-platform="+string(b.plat),
						"-net=none",
						"-cache-dir="+cacheDir,
						"-workspace="+wsDir,
						"-checkpoint-dir="+ckptDir,
					)
					restoreCmd.Stdin = strings.NewReader("RESUME\n")
					restoreCmd.Stdout = &restoreStdout
					restoreCmd.Stderr = &restoreStderr

					if err := restoreCmd.Run(); err != nil {
						t.Fatalf("rungv restore failed: %v (stdout=%q stderr=%q)", err, restoreStdout.String(), restoreStderr.String())
					}
					if !strings.Contains(restoreStdout.String(), "VERIFIED:hostfs\n") {
						t.Fatalf("rungv restore stdout = %q, want VERIFIED:hostfs (stderr=%q)", restoreStdout.String(), restoreStderr.String())
					}
					verifyHostfsWorkspaceArtifacts(t, wsDir)
				})
			}
		})
	}
}
