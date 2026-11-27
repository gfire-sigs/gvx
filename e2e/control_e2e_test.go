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
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func controlSocketSpecForE2E(t *testing.T, name string) string {
	t.Helper()
	sockDir := shortCheckpointSocketDir(t)
	if !canBindUnixControlSocket(sockDir) {
		return "tcp://" + freeLoopbackControlSocketAddr(t)
	}
	return filepath.Join(sockDir, name)
}

func freeLoopbackPortForE2E(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("allocate free loopback port: %v", err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

func httpGetWithRetry(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		data, readErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if readErr == nil && resp.StatusCode == http.StatusOK {
			return string(data)
		}
		lastErr = readErr
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("GET %s failed within %v: %v", url, timeout, lastErr)
	return ""
}

func TestE2EControlProtocolUnderLockdown(t *testing.T) {
	requireAutoPlatform(t)
	rungvx := toolPath(t, rungvxPkg)

	const guestHTTPPort uint16 = 18088
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
	httpELF, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, guestHTTPPort, "/etc/ready.txt", "", "")
	if err != nil {
		t.Fatalf("BuildGuestHTTPServerELF64: %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/exit42", Data: exit42ELF, Mode: 0o755},
		testimage.File{Name: "bin/writeproxy", Data: writeProxyELF, Mode: 0o755},
		testimage.File{Name: "bin/httpserver", Data: httpELF, Mode: 0o755},
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
	sockPath := controlSocketSpecForE2E(t, "ctrl.sock")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungvx,
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
		t.Fatalf("start rungvx sandbox: %v", err)
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
	if out, errS, code := runTool(t, rungvx, "ping", "-S", sockPath, "--wait", "10s"); code != 0 {
		t.Fatalf("ping = (%d, %q, %q)", code, out, errS)
	}
	statusOut, statusErr, statusCode := runTool(t, rungvx, "status", "-S", sockPath, "-f", "json")
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
	if _, errS, code := runTool(t, rungvx, "pause", "-S", sockPath); code != 0 {
		t.Fatalf("pause = (%d, %q)", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "unpause", "-S", sockPath); code != 0 {
		t.Fatalf("unpause = (%d, %q)", code, errS)
	}

	// 3. Docker-style exec (closed stdin, -i piped stdin, exit code 42)
	if out, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/hello"); code != 0 || out != "e2e-hello\n" {
		t.Fatalf("exec hello = (%d, %q, %q)", code, out, errS)
	}
	{
		cmd := exec.CommandContext(ctx, rungvx, "exec", "-S", sockPath, "-i", "--", "/bin/cat", "/proc/self/fd/0")
		cmd.Stdin = strings.NewReader("locked-stdin\n")
		out, err := cmd.CombinedOutput()
		if err != nil || string(out) != "locked-stdin\n" {
			t.Fatalf("exec -i = (%q, %v)", out, err)
		}
	}
	if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/exit42"); code != 42 {
		t.Fatalf("exec exit42 = (%d, %q), want 42", code, errS)
	}

	// 4. cp host -> guest -> host (unlocked client performs host disk I/O)
	srcFile := filepath.Join(t.TempDir(), "src.txt")
	if err := os.WriteFile(srcFile, []byte("e2e-cp-locked\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, errS, code := runTool(t, rungvx, "cp", "-S", sockPath, "-z", srcFile, ":/tmp/src.txt"); code != 0 {
		t.Fatalf("cp host->guest = (%d, %q)", code, errS)
	}
	dstFile := filepath.Join(t.TempDir(), "dst.txt")
	if _, errS, code := runTool(t, rungvx, "cp", "-S", sockPath, "-z", ":/tmp/src.txt", dstFile); code != 0 {
		t.Fatalf("cp guest->host = (%d, %q)", code, errS)
	}
	gotCP, err := os.ReadFile(dstFile)
	if err != nil || string(gotCP) != "e2e-cp-locked\n" {
		t.Fatalf("cp roundtrip = (%q, %v)", gotCP, err)
	}

	// 5. update live limits under lockdown
	if _, errS, code := runTool(t, rungvx, "update", "-S", sockPath, "-m", "256m", "--cpus", "0.5", "--pids-limit", "64", "--isolate-lan=true"); code != 0 {
		t.Fatalf("update = (%d, %q)", code, errS)
	}

	// 6. Lockdown denials return exit code 126.
	if _, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "127.0.0.1:0:80"); code != 126 {
		t.Fatalf("port add without --dynamic-ports = (%d, %q), want exit 126", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "mount", "remount", "-S", sockPath, "--rw", "/workspace"); code != 126 {
		t.Fatalf("mount remount host-RO workspace rw = (%d, %q), want exit 126", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "mount", "add", "-S", sockPath, "--type", "bind", "--src", t.TempDir(), "--dst", "/mnt/bind"); code != 126 {
		t.Fatalf("mount add bind under lockdown = (%d, %q), want exit 126", code, errS)
	}

	// 6b. port-forward tunnels TCP into the locked-down sandbox WITHOUT --dynamic-ports!
	{
		if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "-d", "--", "/bin/httpserver"); code != 0 {
			t.Fatalf("exec -d httpserver = (%d, %q)", code, errS)
		}
		localPort := freeLoopbackPortForE2E(t)
		pfCtx, pfCancel := context.WithCancel(ctx)
		pfOut := newCheckpointNotifyBuffer()
		pfErr := newCheckpointNotifyBuffer()
		pfCmd := exec.CommandContext(pfCtx, rungvx, "port-forward", "-S", sockPath,
			"127.0.0.1:"+strconv.Itoa(int(localPort))+":"+strconv.Itoa(int(guestHTTPPort)))
		pfCmd.Stdout = pfOut
		pfCmd.Stderr = pfErr
		if err := pfCmd.Start(); err != nil {
			pfCancel()
			t.Fatalf("start port-forward: %v", err)
		}
		pfDone := make(chan error, 1)
		go func() { pfDone <- pfCmd.Wait() }()
		t.Cleanup(func() {
			pfCancel()
			select {
			case <-pfDone:
			case <-time.After(5 * time.Second):
				_ = pfCmd.Process.Kill()
			}
		})
		pfOut.waitForSubstring(t, "Forwarding ", 15*time.Second, pfErr)

		gotBody := httpGetWithRetry(t, "http://127.0.0.1:"+strconv.Itoa(int(localPort))+"/", 15*time.Second)
		if gotBody != "e2e-ready\n" {
			t.Fatalf("port-forward HTTP body = %q, want e2e-ready", gotBody)
		}
		pfCancel()
		select {
		case <-pfDone:
		case <-time.After(5 * time.Second):
			t.Fatal("port-forward did not exit promptly on cancel")
		}
	}

	// 7. mount add tmpfs + mount serve (rpcfs) work under full lockdown!
	if _, errS, code := runTool(t, rungvx, "mount", "add", "-S", sockPath, "--type", "tmpfs", "--dst", "/mnt/tmp", "--size", "8m"); code != 0 {
		t.Fatalf("mount add tmpfs = (%d, %q)", code, errS)
	}

	serveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveDir, "host.txt"), []byte("locked-rpcfs-read\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	largePayload := bytes.Repeat([]byte("0123456789abcdef"), 32<<10) // 512 KiB (multi-chunk)
	if err := os.WriteFile(filepath.Join(serveDir, "large.bin"), largePayload, 0o600); err != nil {
		t.Fatal(err)
	}
	serveCtx, serveCancel := context.WithCancel(ctx)
	serveOut := newCheckpointNotifyBuffer()
	serveErr := newCheckpointNotifyBuffer()
	serveCmd := exec.CommandContext(serveCtx, rungvx, "mount", "serve", "-S", sockPath, serveDir+":/mnt/proxy")
	serveCmd.Stdout = serveOut
	serveCmd.Stderr = serveErr
	if err := serveCmd.Start(); err != nil {
		serveCancel()
		t.Fatalf("start mount serve: %v", err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- serveCmd.Wait() }()
	t.Cleanup(func() {
		serveCancel()
		select {
		case <-serveDone:
		case <-time.After(5 * time.Second):
			_ = serveCmd.Process.Kill()
		}
	})
	serveOut.waitForSubstring(t, "Serving ", 15*time.Second, serveErr)

	if out, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/proxy/host.txt"); code != 0 || out != "locked-rpcfs-read\n" {
		t.Fatalf("exec read rpcfs under lockdown = (%d, %q, %q)", code, out, errS)
	}
	if out, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/proxy/large.bin"); code != 0 || len(out) != len(largePayload) || out != string(largePayload) {
		t.Fatalf("exec read 512KiB rpcfs under lockdown = (%d, len=%d want=%d, err=%q)", code, len(out), len(largePayload), errS)
	}
	if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/writeproxy"); code != 0 {
		t.Fatalf("exec write rpcfs under lockdown = (%d, %q)", code, errS)
	}
	written, err := os.ReadFile(filepath.Join(serveDir, "guest.txt"))
	if err != nil || string(written) != "e2e-rpcfs-ok\n" {
		t.Fatalf("guest rpcfs write = (%q, %v)", written, err)
	}

	// Single-file mount serve under lockdown.
	singleHostFile := filepath.Join(t.TempDir(), "single.txt")
	if err := os.WriteFile(singleHostFile, []byte("single-file-rpcfs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	singleCtx, singleCancel := context.WithCancel(ctx)
	singleOut := newCheckpointNotifyBuffer()
	singleErr := newCheckpointNotifyBuffer()
	singleCmd := exec.CommandContext(singleCtx, rungvx, "mount", "serve", "-S", sockPath, singleHostFile+":/mnt/single.txt")
	singleCmd.Stdout = singleOut
	singleCmd.Stderr = singleErr
	if err := singleCmd.Start(); err != nil {
		singleCancel()
		t.Fatalf("start single-file mount serve: %v", err)
	}
	singleDone := make(chan error, 1)
	go func() { singleDone <- singleCmd.Wait() }()
	t.Cleanup(func() {
		singleCancel()
		select {
		case <-singleDone:
		case <-time.After(5 * time.Second):
			_ = singleCmd.Process.Kill()
		}
	})
	singleOut.waitForSubstring(t, "Serving ", 15*time.Second, singleErr)
	if out, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/single.txt"); code != 0 || out != "single-file-rpcfs\n" {
		t.Fatalf("exec read single-file rpcfs = (%d, %q, %q)", code, out, errS)
	}
	singleCancel()
	select {
	case <-singleDone:
	case <-time.After(5 * time.Second):
		t.Fatal("single-file mount serve did not exit promptly on cancel")
	}

	serveCancel()
	select {
	case <-serveDone:
	case <-time.After(5 * time.Second):
		t.Fatal("mount serve did not exit promptly on cancel")
	}

	// Wait for the server to finish auto-unmounting /mnt/proxy after client disconnect.
	unmounted := false
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if out, _, code := runTool(t, rungvx, "mount", "ls", "-S", sockPath, "-q"); code == 0 && !strings.Contains(out, "/mnt/proxy") {
			unmounted = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !unmounted {
		t.Fatal("/mnt/proxy was not unmounted within 5s after mount serve exited")
	}

	// 8. Streaming checkpoint (-o without -checkpoint-dir) + restore under lockdown.
	bundleDir := filepath.Join(t.TempDir(), "ckpt-stream")
	if _, errS, code := runTool(t, rungvx, "checkpoint", "-S", sockPath, "-z", "-o", bundleDir); code != 0 {
		t.Fatalf("checkpoint -o = (%d, %q)", code, errS)
	}
	if err := <-sbDone; err != nil {
		t.Fatalf("sandbox exit after checkpoint -o: %v (stderr=%q)", err, sbStderr.String())
	}

	resCmd := exec.CommandContext(ctx, rungvx,
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

func TestE2EDynamicPortsUnderLockdown(t *testing.T) {
	requireAutoPlatform(t)
	rungvx := toolPath(t, rungvxPkg)

	const guestPort uint16 = 18089
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	httpELF, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, guestPort, "/etc/ready.txt", "", "")
	if err != nil {
		t.Fatalf("BuildGuestHTTPServerELF64: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/httpserver", Data: httpELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("dyn-port-ok\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2edynport", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	sockPath := controlSocketSpecForE2E(t, "dyn.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungvx,
		"run",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=nat",
		"--dynamic-ports",
		"-cache-dir="+t.TempDir(),
		"-registry-url="+regURL,
		"--name=e2e-dynport",
		"-S", sockPath,
		"e2edynport:latest",
	)
	sbStdin, err := sbCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	sbCmd.Stdout = sbStdout
	sbCmd.Stderr = sbStderr
	if err := sbCmd.Start(); err != nil {
		t.Fatalf("start rungvx: %v", err)
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

	sbStdout.waitForSubstring(t, "dyn-port-ok\n", 30*time.Second, sbStderr)

	if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "-d", "--", "/bin/httpserver"); code != 0 {
		t.Fatalf("exec -d httpserver = (%d, %q)", code, errS)
	}
	addSpec := "127.0.0.1:0:" + strconv.Itoa(int(guestPort))
	addOut, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "-f", "json", addSpec)
	if code != 0 {
		t.Fatalf("port add = (%d, %q)", code, errS)
	}
	var addedPort control.PortRuleInfo
	if err := json.Unmarshal([]byte(addOut), &addedPort); err != nil || addedPort.HostPort == 0 {
		t.Fatalf("port add json = (%q, %v), want bound host port", addOut, err)
	}
	hostPort := addedPort.HostPort
	rmSpec := "127.0.0.1:" + strconv.Itoa(int(hostPort)) + ":" + strconv.Itoa(int(guestPort))
	// Non-loopback bind must still be refused under host lockdown even with --dynamic-ports.
	if _, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "0.0.0.0:0:80"); code != 126 {
		t.Fatalf("port add non-loopback = (%d, %q), want 126", code, errS)
	}
	gotBody := httpGetWithRetry(t, "http://127.0.0.1:"+strconv.Itoa(int(hostPort))+"/", 15*time.Second)
	if gotBody != "dyn-port-ok\n" {
		t.Fatalf("dynamic port HTTP body = %q, want dyn-port-ok", gotBody)
	}
	if _, errS, code := runTool(t, rungvx, "port", "rm", "-S", sockPath, rmSpec); code != 0 {
		t.Fatalf("port rm = (%d, %q)", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "stop", "-S", sockPath, "-t", "0"); code != 0 {
		t.Fatalf("stop -t 0 = (%d, %q)", code, errS)
	}
	_ = <-sbDone
}

func TestE2EDynamicPortAddrsUnderLockdown(t *testing.T) {
	requireAutoPlatform(t)
	rungvx := toolPath(t, rungvxPkg)

	const guestPort uint16 = 18090
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	httpELF, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, guestPort, "/etc/ready.txt", "", "")
	if err != nil {
		t.Fatalf("BuildGuestHTTPServerELF64: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/httpserver", Data: httpELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("dyn-addr-ok\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2edynaddr", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	sockPath := controlSocketSpecForE2E(t, "dynaddr.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungvx,
		"run",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=nat",
		"--dynamic-ports-addr", "0.0.0.0",
		"-cache-dir="+t.TempDir(),
		"-registry-url="+regURL,
		"--name=e2e-dynaddr",
		"-S", sockPath,
		"e2edynaddr:latest",
	)
	sbStdin, err := sbCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	sbCmd.Stdout = sbStdout
	sbCmd.Stderr = sbStderr
	if err := sbCmd.Start(); err != nil {
		t.Fatalf("start rungvx: %v", err)
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

	sbStdout.waitForSubstring(t, "dyn-addr-ok\n", 30*time.Second, sbStderr)

	pingOut, errS, code := runTool(t, rungvx, "ping", "-S", sockPath, "-f", "json")
	if code != 0 || !strings.Contains(pingOut, "port.dynamic_any") {
		t.Fatalf("ping = (%d, %q, %q), want port.dynamic_any", code, pingOut, errS)
	}
	statusOut, errS, code := runTool(t, rungvx, "status", "-S", sockPath, "-f", "json")
	if code != 0 {
		t.Fatalf("status = (%d, %q, %q)", code, statusOut, errS)
	}
	var statusResp struct {
		DynamicBindAddrs []string `json:"dynamic_bind_addrs"`
	}
	if err := json.Unmarshal([]byte(statusOut), &statusResp); err != nil || len(statusResp.DynamicBindAddrs) != 1 || statusResp.DynamicBindAddrs[0] != "0.0.0.0" {
		t.Fatalf("status dynamic_bind_addrs = (%v, %v), want [0.0.0.0]\nraw=%s", statusResp.DynamicBindAddrs, err, statusOut)
	}

	if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "-d", "--", "/bin/httpserver"); code != 0 {
		t.Fatalf("exec -d httpserver = (%d, %q)", code, errS)
	}

	addSpec := "0.0.0.0:0:" + strconv.Itoa(int(guestPort))
	addOut, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "-f", "json", addSpec)
	if code != 0 {
		t.Fatalf("port add 0.0.0.0 = (%d, %q)", code, errS)
	}
	var addedPort control.PortRuleInfo
	if err := json.Unmarshal([]byte(addOut), &addedPort); err != nil || addedPort.HostPort == 0 {
		t.Fatalf("port add 0.0.0.0 json = (%q, %v), want bound host port", addOut, err)
	}
	hostPort := addedPort.HostPort
	rmSpec := "0.0.0.0:" + strconv.Itoa(int(hostPort)) + ":" + strconv.Itoa(int(guestPort))
	gotBody := httpGetWithRetry(t, "http://127.0.0.1:"+strconv.Itoa(int(hostPort))+"/", 15*time.Second)
	if gotBody != "dyn-addr-ok\n" {
		t.Fatalf("dynamic 0.0.0.0 port HTTP body = %q, want dyn-addr-ok", gotBody)
	}

	// Unlisted IP addresses (including 127.0.0.1 without --dynamic-ports) and
	// Unix sockets must still fail with LOCKDOWN_DENIED (exit 126).
	if _, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "127.0.0.1:0:80"); code != 126 {
		t.Fatalf("port add unlisted loopback = (%d, %q), want 126", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "192.0.2.1:0:80"); code != 126 {
		t.Fatalf("port add unlisted IP = (%d, %q), want 126", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "port", "add", "-S", sockPath, "unix:"+filepath.Join(t.TempDir(), "deny.sock")+":80"); code != 126 {
		t.Fatalf("port add unix socket = (%d, %q), want 126", code, errS)
	}

	if _, errS, code := runTool(t, rungvx, "port", "rm", "-S", sockPath, rmSpec); code != 0 {
		t.Fatalf("port rm = (%d, %q)", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "stop", "-S", sockPath, "-t", "0"); code != 0 {
		t.Fatalf("stop -t 0 = (%d, %q)", code, errS)
	}
	_ = <-sbDone
}

func TestE2ELiveBindAttachUnderLockdown(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("live hostfs bind attach via SCM_RIGHTS is POSIX-only under lockdown")
	}
	requireAutoPlatform(t)
	rungvx := toolPath(t, rungvxPkg)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	writeOKELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/live/from-guest.txt", "guest-wrote-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(ok): %v", err)
	}
	writeROELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/one.txt", "denied\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64(ro): %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/writeok", Data: writeOKELF, Mode: 0o755},
		testimage.File{Name: "bin/writero", Data: writeROELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("bind-attach-ready\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2ebindattach", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	hostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(hostDir, "hello.txt"), []byte("live-hostfs-dir\n"), 0o644); err != nil {
		t.Fatalf("WriteFile hello: %v", err)
	}
	singleDir := t.TempDir()
	singleFile := filepath.Join(singleDir, "single.txt")
	if err := os.WriteFile(singleFile, []byte("live-hostfs-file\n"), 0o644); err != nil {
		t.Fatalf("WriteFile single: %v", err)
	}

	sockPath := controlSocketSpecForE2E(t, "bind.sock")
	if strings.HasPrefix(sockPath, "tcp://") {
		t.Skip("SCM_RIGHTS bind attach requires a Unix domain control socket")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungvx,
		"run",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=none",
		"--allow-bind-attach",
		"-cache-dir="+t.TempDir(),
		"-registry-url="+regURL,
		"--name=e2e-bindattach",
		"-S", sockPath,
		"e2ebindattach:latest",
	)
	sbStdin, err := sbCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	sbCmd.Stdout = sbStdout
	sbCmd.Stderr = sbStderr
	if err := sbCmd.Start(); err != nil {
		t.Fatalf("start rungvx: %v", err)
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

	sbStdout.waitForSubstring(t, "bind-attach-ready\n", 30*time.Second, sbStderr)

	pingOut, errS, code := runTool(t, rungvx, "ping", "-S", sockPath, "-f", "json")
	if code != 0 || !strings.Contains(pingOut, "mount.bind_attach") {
		t.Fatalf("ping = (%d, %q, %q), want mount.bind_attach", code, pingOut, errS)
	}

	// 1. Attach host directory as hostfs under full host lockdown.
	if outS, errS, code := runTool(t, rungvx, "mount", "add", "-S", sockPath, "--type=bind", "--src", hostDir, "--dst", "/mnt/live"); code != 0 {
		t.Fatalf("mount add bind dir = (%d, %q, %q)", code, outS, errS)
	}
	gotDir, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/live/hello.txt")
	if code != 0 || gotDir != "live-hostfs-dir\n" {
		t.Fatalf("exec cat /mnt/live/hello.txt = (%d, %q, %q)", code, gotDir, errS)
	}
	// Host edit reaches the live hostfs mount immediately.
	if err := os.WriteFile(filepath.Join(hostDir, "hello.txt"), []byte("updated-from-host\n"), 0o644); err != nil {
		t.Fatalf("WriteFile update: %v", err)
	}
	gotUpdated, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/live/hello.txt")
	if code != 0 || gotUpdated != "updated-from-host\n" {
		t.Fatalf("exec cat updated = (%d, %q, %q)", code, gotUpdated, errS)
	}
	// Guest-to-host write-back into the live attached directory.
	if _, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/writeok"); code != 0 {
		t.Fatalf("exec writeok = (%d, %q)", code, errS)
	}
	writtenHost, err := os.ReadFile(filepath.Join(hostDir, "from-guest.txt"))
	if err != nil || string(writtenHost) != "guest-wrote-ok\n" {
		t.Fatalf("host ReadFile(from-guest.txt) = (%q, %v), want guest-wrote-ok", writtenHost, err)
	}

	// 2. Attach single host file read-only under full host lockdown.
	if outS, errS, code := runTool(t, rungvx, "mount", "add", "-S", sockPath, "--type=bind", "--ro", "--src", singleFile, "--dst", "/mnt/one.txt"); code != 0 {
		t.Fatalf("mount add bind file = (%d, %q, %q)", code, outS, errS)
	}
	gotFile, errS, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/one.txt")
	if code != 0 || gotFile != "live-hostfs-file\n" {
		t.Fatalf("exec cat /mnt/one.txt = (%d, %q, %q)", code, gotFile, errS)
	}
	// Read-only enforcement: guest write fails and remount --rw returns LOCKDOWN_DENIED (126).
	if _, _, code := runTool(t, rungvx, "exec", "-S", sockPath, "--", "/bin/writero"); code == 0 {
		t.Fatal("exec writero on read-only attached file succeeded, want non-zero exit")
	}
	if _, errS, code := runTool(t, rungvx, "mount", "remount", "-S", sockPath, "--rw", "/mnt/one.txt"); code != 126 {
		t.Fatalf("mount remount --rw on --ro attached file = (%d, %q), want 126", code, errS)
	}

	// 3. Unmount the directory normally and lazy-detach the single file.
	if _, errS, code := runTool(t, rungvx, "mount", "rm", "-S", sockPath, "/mnt/live"); code != 0 {
		t.Fatalf("mount rm /mnt/live = (%d, %q)", code, errS)
	}
	if _, errS, code := runTool(t, rungvx, "mount", "rm", "-S", sockPath, "--detach", "/mnt/one.txt"); code != 0 {
		t.Fatalf("mount rm --detach /mnt/one.txt = (%d, %q)", code, errS)
	}

	if _, errS, code := runTool(t, rungvx, "stop", "-S", sockPath, "-t", "0"); code != 0 {
		t.Fatalf("stop -t 0 = (%d, %q)", code, errS)
	}
	_ = <-sbDone
}
