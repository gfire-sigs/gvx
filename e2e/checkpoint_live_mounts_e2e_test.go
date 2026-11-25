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
	"archive/tar"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestE2ECheckpointRestoreServeUnderHostLockdown(t *testing.T) {
	requireAutoPlatform(t)
	rungvx := toolPath(t, rungvxPkg)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	writeELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/proj/from_restored.txt", "restored-under-lockdown\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/writeproj", Data: writeELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("ckpt-live-ready\n"), Mode: 0o644},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2eliveckpt", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	cacheDir := t.TempDir()
	ckptDir := t.TempDir()
	serveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveDir, "hello.txt"), []byte("hello-under-lockdown\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sock1 := controlSocketSpecForE2E(t, "live1.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	plat := string(resolvedAutoPlatform())
	runArgs := []string{
		"run",
		"-platform=" + plat,
		"-net=none",
		"-cache-dir=" + cacheDir,
		"-registry-url=" + regURL,
		"-checkpoint-dir=" + ckptDir,
		"-S", sock1,
	}
	if runtime.GOOS == "windows" && plat == "systrap" {
		runArgs = append(runArgs, "-allow-unconfined-systrap")
	}
	runArgs = append(runArgs, "e2eliveckpt:latest")

	sb1Out := newCheckpointNotifyBuffer()
	sb1Err := newCheckpointNotifyBuffer()
	sb1Cmd := exec.CommandContext(ctx, rungvx, runArgs...)
	sb1In, err := sb1Cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe(sb1): %v", err)
	}
	sb1Cmd.Stdout = sb1Out
	sb1Cmd.Stderr = sb1Err
	if err := sb1Cmd.Start(); err != nil {
		t.Fatalf("start rungvx run: %v", err)
	}
	sb1Done := make(chan struct{})
	go func() {
		_ = sb1Cmd.Wait()
		close(sb1Done)
	}()
	t.Cleanup(func() {
		_ = sb1In.Close()
		cancel()
		select {
		case <-sb1Done:
		case <-time.After(10 * time.Second):
			_ = sb1Cmd.Process.Kill()
			<-sb1Done
		}
	})

	sb1Out.waitForSubstring(t, "ckpt-live-ready\n", 30*time.Second, sb1Err)
	if out, errS, code := runTool(t, rungvx, "ping", "-S", sock1, "--wait", "10s"); code != 0 {
		t.Fatalf("ping sb1 = (%d, %q, %q)", code, out, errS)
	}

	// Start rungvx mount serve for /mnt/proj under default lockdown.
	serveOut := newCheckpointNotifyBuffer()
	serveErr := newCheckpointNotifyBuffer()
	serveCmd := exec.CommandContext(ctx, rungvx, "mount", "serve", "-S", sock1, serveDir+":/mnt/proj")
	serveCmd.Stdout = serveOut
	serveCmd.Stderr = serveErr
	if err := serveCmd.Start(); err != nil {
		t.Fatalf("start rungvx mount serve: %v", err)
	}
	var serveWaitErr error
	serveDone := make(chan struct{})
	go func() {
		serveWaitErr = serveCmd.Wait()
		close(serveDone)
	}()
	t.Cleanup(func() {
		select {
		case <-serveDone:
		default:
			_ = serveCmd.Process.Kill()
			<-serveDone
		}
	})
	serveOut.waitForSubstring(t, "Serving ", 15*time.Second, serveErr)

	// Checkpoint and stop; serving client must detach cleanly and exit 0.
	if out, errS, code := runTool(t, rungvx, "checkpoint", "-S", sock1, "-checkpoint-dir", ckptDir); code != 0 {
		t.Fatalf("checkpoint = (%d, %q, %q)", code, out, errS)
	}
	select {
	case <-serveDone:
		if serveWaitErr != nil {
			t.Fatalf("mount serve exited with error after stopping checkpoint: %v (stdout=%q stderr=%q)", serveWaitErr, serveOut.String(), serveErr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("mount serve did not exit after stopping checkpoint (stdout=%q stderr=%q)", serveOut.String(), serveErr.String())
	}
	if !strings.Contains(serveOut.String(), "Detached /mnt/proj") {
		t.Fatalf("mount serve stdout = %q, want Detached /mnt/proj", serveOut.String())
	}
	select {
	case <-sb1Done:
	case <-time.After(15 * time.Second):
		t.Fatal("sb1 did not exit after stopping checkpoint")
	}

	// Restore WITH --serve under DEFAULT HOST LOCKDOWN (no -lockdown=false!).
	sock2 := controlSocketSpecForE2E(t, "live2.sock")
	restoreArgs := []string{
		"restore",
		"-platform=" + plat,
		"-net=none",
		"-cache-dir=" + cacheDir,
		"-checkpoint-dir=" + ckptDir,
		"--serve", serveDir + ":/mnt/proj",
		"-S", sock2,
	}
	if runtime.GOOS == "windows" && plat == "systrap" {
		restoreArgs = append(restoreArgs, "-allow-unconfined-systrap")
	}
	sb2Out := newCheckpointNotifyBuffer()
	sb2Err := newCheckpointNotifyBuffer()
	sb2Cmd := exec.CommandContext(ctx, rungvx, restoreArgs...)
	sb2In, err := sb2Cmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe(sb2): %v", err)
	}
	sb2Cmd.Stdout = sb2Out
	sb2Cmd.Stderr = sb2Err
	if err := sb2Cmd.Start(); err != nil {
		t.Fatalf("start rungvx restore: %v", err)
	}
	sb2Done := make(chan error, 1)
	go func() { sb2Done <- sb2Cmd.Wait() }()
	t.Cleanup(func() {
		_ = sb2In.Close()
		cancel()
		select {
		case <-sb2Done:
		case <-time.After(10 * time.Second):
			_ = sb2Cmd.Process.Kill()
		}
	})

	if out, errS, code := runTool(t, rungvx, "ping", "-S", sock2, "--wait", "15s"); code != 0 {
		t.Fatalf("ping sb2 = (%d, %q, %q) sb2Err=%q", code, out, errS, sb2Err.String())
	}
	statusOut, statusErr, statusCode := runTool(t, rungvx, "status", "-S", sock2, "-f", "json")
	if statusCode != 0 {
		t.Fatalf("status sb2 = (%d, %q, %q)", statusCode, statusOut, statusErr)
	}
	var inspect control.InspectResponse
	if err := json.Unmarshal([]byte(statusOut), &inspect); err != nil {
		t.Fatalf("decode status json: %v", err)
	}
	if !inspect.LockdownApplied {
		t.Fatalf("expected LockdownApplied=true on restored sandbox, got false (inspect=%+v)", inspect)
	}

	// Read and write /mnt/proj inside restored locked-down sandbox.
	if out, errS, code := runTool(t, rungvx, "exec", "-S", sock2, "--", "/bin/cat", "/mnt/proj/hello.txt"); code != 0 || out != "hello-under-lockdown\n" {
		t.Fatalf("exec cat /mnt/proj/hello.txt = (%d, %q, %q)", code, out, errS)
	}
	if out, errS, code := runTool(t, rungvx, "exec", "-S", sock2, "--", "/bin/writeproj"); code != 0 {
		t.Fatalf("exec writeproj = (%d, %q, %q)", code, out, errS)
	}
	gotHost, err := os.ReadFile(filepath.Join(serveDir, "from_restored.txt"))
	if err != nil || string(gotHost) != "restored-under-lockdown\n" {
		t.Fatalf("host from_restored.txt = (%q, %v), want restored-under-lockdown", gotHost, err)
	}
}
