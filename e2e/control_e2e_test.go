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
	"bytes"
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

func TestE2EControlProtocolUnderLockdown(t *testing.T) {
	requireAutoPlatform(t)
	rungv := toolPath(t, rungvPkg)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "e2e-hello\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64(hello): %v", err)
	}
	exit42ELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 42, "")
	if err != nil {
		t.Fatalf("BuildGuestELF64(42): %v", err)
	}
	writeProxyELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/proxy/guest.txt", "e2e-rpcfs-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64: %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/exit42", Data: exit42ELF, Mode: 0o755},
		testimage.File{Name: "bin/writeproxy", Data: writeProxyELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("e2e-ready\n"), Mode: 0o644},
		testimage.File{Name: "tmp/", Type: tar.TypeDir, Mode: 0o1777},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/tmp/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/proxy/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/bind/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2ectrl", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	cacheDir := t.TempDir()
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "ro.txt"), []byte("ro-data\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("/tmp", "gvx-e2e-c-")
	if err != nil {
		sockDir = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	}
	sockPath := filepath.Join(sockDir, "ctrl.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungv,
		"run",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=nat",
		"-cache-dir="+cacheDir,
		"-registry-url="+regURL,
		"-workspace="+wsDir,
		"-ro",
		"--name=e2e-locked",
		"-S", sockPath,
		"e2ectrl:latest",
	)
	sbStdin, err := sbCmd.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	sbCmd.Stdout = sbStdout
	sbCmd.Stderr = sbStderr
	if err := sbCmd.Start(); err != nil {
		t.Fatalf("start rungv sandbox: %v", err)
	}
	sbDone := make(chan error, 1)
	go func() { sbDone <- sbCmd.Wait() }()
	t.Cleanup(func() {
		_ = sbStdin.Close()
		cancel()
		select {
		case <-sbDone:
		case <-time.After(10 * time.Second):
			_ = sbCmd.Process.Kill()
		}
	})

	sbStdout.waitForSubstring(t, "e2e-ready\n", 30*time.Second, sbStderr)

	// 1. ping & status verify host lockdown is active.
	if out, errS, code := runTool(t, rungv, "ping", "-S", sockPath, "--wait", "10s"); code != 0 {
		t.Fatalf("ping = (%d, %q, %q)", code, out, errS)
	}
	statusOut, statusErr, statusCode := runTool(t, rungv, "status", "-S", sockPath, "-f", "json")
	if statusCode != 0 {
		t.Fatalf("status = (%d, %q, %q)", statusCode, statusOut, statusErr)
	}
	var inspect control.InspectResponse
	if err := json.Unmarshal([]byte(statusOut), &inspect); err != nil {
		t.Fatalf("decode status json: %v (raw=%q)", err, statusOut)
	}
	if !inspect.LockdownApplied {
		t.Fatalf("expected LockdownApplied=true under default run, got false (inspect=%+v)", inspect)
	}

	// 2. pause & unpause
	if _, errS, code := runTool(t, rungv, "pause", "-S", sockPath); code != 0 {
		t.Fatalf("pause = (%d, %q)", code, errS)
	}
	if _, errS, code := runTool(t, rungv, "unpause", "-S", sockPath); code != 0 {
		t.Fatalf("unpause = (%d, %q)", code, errS)
	}

	// 3. Docker-style exec (closed stdin, -i piped stdin, exit code 42)
	if out, errS, code := runTool(t, rungv, "exec", "-S", sockPath, "--", "/bin/hello"); code != 0 || out != "e2e-hello\n" {
		t.Fatalf("exec hello = (%d, %q, %q)", code, out, errS)
	}
	{
		cmd := exec.CommandContext(ctx, rungv, "exec", "-S", sockPath, "-i", "--", "/bin/cat", "/proc/self/fd/0")
		cmd.Stdin = strings.NewReader("locked-stdin\n")
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != "locked-stdin\n" {
			t.Fatalf("exec -i = (%q, %v)", out, err)
		}
	}
	if _, errS, code := runTool(t, rungv, "exec", "-S", sockPath, "--", "/bin/exit42"); code != 42 {
		t.Fatalf("exec exit42 = (%d, %q), want 42", code, errS)
	}

	// 4. cp host -> guest -> host (unlocked client performs host disk I/O)
	srcFile := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(srcFile, []byte("e2e-cp-locked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errS, code := runTool(t, rungv, "cp", "-S", sockPath, "-z", srcFile, ":/tmp/src.txt"); code != 0 {
		t.Fatalf("cp host->guest = (%d, %q)", code, errS)
	}
	dstFile := filepath.Join(t.TempDir(), "dst.txt")
	if _, errS, code := runTool(t, rungv, "cp", "-S", sockPath, "-z", ":/tmp/src.txt", dstFile); code != 0 {
		t.Fatalf("cp guest->host = (%d, %q)", code, errS)
	}
	gotCP, err := os.ReadFile(dstFile)
	if err != nil || string(gotCP) != "e2e-cp-locked\n" {
		t.Fatalf("cp roundtrip = (%q, %v)", gotCP, err)
	}

	// 5. update live limits under lockdown
	if _, errS, code := runTool(t, rungv, "update", "-S", sockPath, "-m", "256m", "--cpus", "0.5", "--pids-limit", "64", "--isolate-lan=true"); code != 0 {
		t.Fatalf("update = (%d, %q)", code, errS)
	}

	// 6. Lockdown denials return exit code 126.
	if _, errS, code := runTool(t, rungv, "port", "add", "-S", sockPath, "127.0.0.1:0:80"); code != 126 {
		t.Fatalf("port add without --dynamic-ports = (%d, %q), want exit 126", code, errS)
	}
	if _, errS, code := runTool(t, rungv, "mount", "remount", "-S", sockPath, "--rw", "/workspace"); code != 126 {
		t.Fatalf("mount remount host-RO workspace rw = (%d, %q), want exit 126", code, errS)
	}
	if _, errS, code := runTool(t, rungv, "mount", "add", "-S", sockPath, "--type", "bind", "--src", t.TempDir(), "--dst", "/mnt/bind"); code != 126 {
		t.Fatalf("mount add bind under lockdown = (%d, %q), want exit 126", code, errS)
	}

	// 7. mount add tmpfs + mount serve (rpcfs) work under full lockdown!
	if _, errS, code := runTool(t, rungv, "mount", "add", "-S", sockPath, "--type", "tmpfs", "--dst", "/mnt/tmp", "--size", "8m"); code != 0 {
		t.Fatalf("mount add tmpfs = (%d, %q)", code, errS)
	}

	serveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveDir, "host.txt"), []byte("locked-rpcfs-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	serveOut := newCheckpointNotifyBuffer()
	serveErr := newCheckpointNotifyBuffer()
	serveCmd := exec.CommandContext(serveCtx, rungv, "mount", "serve", "-S", sockPath, serveDir+":/mnt/proxy")
	serveCmd.Stdout = serveOut
	serveCmd.Stderr = serveErr
	if err := serveCmd.Start(); err != nil {
		t.Fatalf("start mount serve: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveCmd.Wait() }()
	serveOut.waitForSubstring(t, "Serving ", 15*time.Second, serveErr)

	if out, errS, code := runTool(t, rungv, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/proxy/host.txt"); code != 0 || out != "locked-rpcfs-read\n" {
		t.Fatalf("exec read rpcfs under lockdown = (%d, %q, %q)", code, out, errS)
	}
	if _, errS, code := runTool(t, rungv, "exec", "-S", sockPath, "--", "/bin/writeproxy"); code != 0 {
		t.Fatalf("exec write rpcfs under lockdown = (%d, %q)", code, errS)
	}
	written, err := os.ReadFile(filepath.Join(serveDir, "guest.txt"))
	if err != nil || string(written) != "e2e-rpcfs-ok\n" {
		t.Fatalf("guest rpcfs write = (%q, %v)", written, err)
	}
	serveCancel()
	<-serveDone

	// Wait for the server to finish auto-unmounting /mnt/proxy after client disconnect.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if out, _, code := runTool(t, rungv, "mount", "ls", "-S", sockPath, "-q"); code == 0 && !strings.Contains(out, "/mnt/proxy") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// 8. Streaming checkpoint (-o without -checkpoint-dir) + restore under lockdown.
	bundleDir := filepath.Join(t.TempDir(), "ckpt-stream")
	if _, errS, code := runTool(t, rungv, "checkpoint", "-S", sockPath, "-z", "-o", bundleDir); code != 0 {
		t.Fatalf("checkpoint -o = (%d, %q)", code, errS)
	}
	if err := <-sbDone; err != nil {
		t.Fatalf("sandbox exit after checkpoint -o: %v (stderr=%q)", err, sbStderr.String())
	}

	resCmd := exec.CommandContext(ctx, rungv,
		"restore",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=nat",
		"-cache-dir="+cacheDir,
		"-registry-url="+regURL,
		"--name=e2e-locked",
		"-workspace="+wsDir,
		"-ro",
		"--tmpfs=/mnt/tmp:size=8m",
		"-checkpoint-dir="+bundleDir,
	)
	resCmd.Stdin = strings.NewReader("resumed-under-lockdown\n")
	var resOut, resErr bytes.Buffer
	resCmd.Stdout = &resOut
	resCmd.Stderr = &resErr
	if err := resCmd.Run(); err != nil {
		t.Fatalf("restore from streamed checkpoint: %v (stderr=%q)", err, resErr.String())
	}
	if resOut.String() != "resumed-under-lockdown\n" {
		t.Fatalf("restored stdout = %q, want resumed-under-lockdown", resOut.String())
	}
}
