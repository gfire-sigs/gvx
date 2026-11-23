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

package e2e

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

func buildE2EGuestUnixClientELF(t *testing.T) []byte {
	t.Helper()
	srcDir := t.TempDir()
	src := `package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
)

func main() {
	sockPath, msg := os.Args[1], os.Args[2]
	fi, err := os.Lstat(sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "lstat: %v\n", err)
		os.Exit(3)
	}
	st := fi.Sys().(*syscall.Stat_t)
	fmt.Printf("STAT mode=%04o uid=%d gid=%d\n", fi.Mode().Perm(), st.Uid, st.Gid)
	c, err := net.Dial("unix", sockPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial: %v\n", err)
		os.Exit(4)
	}
	defer c.Close()
	if _, err := io.WriteString(c, msg); err != nil {
		os.Exit(5)
	}
	if uc, ok := c.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		os.Exit(6)
	}
	fmt.Printf("REPLY %s\n", string(reply))
}
`
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module e2euclient\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatalf("write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "uclient")
	cmd := exec.Command("go", "build", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build guest unix client: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read uclient: %v", err)
	}
	return data
}

func TestE2EReverseUnixForwardUnderLockdown(t *testing.T) {
	requireAutoPlatform(t)
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling guest unix client probe")
	}
	sockDir := shortCheckpointSocketDir(t)
	if !canBindUnixControlSocket(sockDir) {
		t.Skipf("host cannot bind Unix domain sockets in %q", sockDir)
	}
	rungv := toolPath(t, rungvPkg)

	// Start a host Unix echo server (simulating ssh-agent).
	hostSock := filepath.Join(sockDir, "agent.sock")
	ln, err := net.Listen("unix", hostSock)
	if err != nil {
		t.Fatalf("listen host unix %q: %v", hostSock, err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				req, err := io.ReadAll(conn)
				if err != nil {
					return
				}
				_, _ = io.WriteString(conn, "locked-agent:"+string(req))
			}(c)
		}
	}()

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	uclientELF := buildE2EGuestUnixClientELF(t)
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/uclient", Data: uclientELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("uf-e2e-ready\n"), Mode: 0o644},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "e2euf", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	ctrlSock := controlSocketSpecForE2E(t, "uf.sock")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	sbStdout := newCheckpointNotifyBuffer()
	sbStderr := newCheckpointNotifyBuffer()
	sbCmd := exec.CommandContext(ctx, rungv,
		"run",
		"-platform="+string(resolvedAutoPlatform()),
		"-net=none",
		"--unix-forward", "/run/host-services/ssh-auth.sock="+hostSock+",uid=1000,gid=1000,mode=0600",
		"-cache-dir="+t.TempDir(),
		"-registry-url="+regURL,
		"--name=e2e-uf",
		"-S", ctrlSock,
		"e2euf:latest",
	)
	sbStdin, err := sbCmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	sbCmd.Stdout = sbStdout
	sbCmd.Stderr = sbStderr
	if err := sbCmd.Start(); err != nil {
		t.Fatalf("start rungv: %v", err)
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

	sbStdout.waitForSubstring(t, "uf-e2e-ready\n", 30*time.Second, sbStderr)

	// Confirm host lockdown is active.
	statusOut, errS, code := runTool(t, rungv, "status", "-S", ctrlSock, "-f", "json")
	if code != 0 {
		t.Fatalf("status = (%d, %q, %q)", code, statusOut, errS)
	}
	var st struct {
		LockdownApplied bool `json:"lockdown_applied"`
	}
	if err := json.Unmarshal([]byte(statusOut), &st); err != nil || !st.LockdownApplied {
		t.Fatalf("lockdown_applied = %v (err=%v), want true", st.LockdownApplied, err)
	}

	// 1. Test boot-time --unix-forward under full host lockdown.
	outS, errS, code := runTool(t, rungv, "exec", "-S", ctrlSock, "--", "/bin/uclient", "/run/host-services/ssh-auth.sock", "hello-boot")
	if code != 0 || !strings.Contains(outS, "STAT mode=0600 uid=1000 gid=1000") || !strings.Contains(outS, "REPLY locked-agent:hello-boot") {
		t.Fatalf("boot unix-forward exec = (%d, %q, %q)", code, outS, errS)
	}

	// 2. Test runtime `rungv unix-forward` under full host lockdown.
	ufCtx, ufCancel := context.WithCancel(ctx)
	ufStdout := newCheckpointNotifyBuffer()
	ufStderr := newCheckpointNotifyBuffer()
	ufCmd := exec.CommandContext(ufCtx, rungv, "unix-forward", "-S", ctrlSock, "/tmp/live-agent.sock="+hostSock+",mode=0660")
	ufCmd.Stdout = ufStdout
	ufCmd.Stderr = ufStderr
	if err := ufCmd.Start(); err != nil {
		t.Fatalf("start rungv unix-forward: %v", err)
	}
	ufDone := make(chan error, 1)
	go func() { ufDone <- ufCmd.Wait() }()
	defer func() {
		ufCancel()
		select {
		case <-ufDone:
		case <-time.After(5 * time.Second):
			_ = ufCmd.Process.Kill()
		}
	}()

	ufStdout.waitForSubstring(t, "forwarding guest /tmp/live-agent.sock", 15*time.Second, ufStderr)

	outS, errS, code = runTool(t, rungv, "exec", "-S", ctrlSock, "--", "/bin/uclient", "/tmp/live-agent.sock", "hello-live")
	if code != 0 || !strings.Contains(outS, "STAT mode=0660") || !strings.Contains(outS, "REPLY locked-agent:hello-live") {
		t.Fatalf("runtime unix-forward exec = (%d, %q, %q)", code, outS, errS)
	}

	ufCancel()
	<-ufDone

	if _, errS, code := runTool(t, rungv, "stop", "-S", ctrlSock, "-t", "0"); code != 0 {
		t.Fatalf("stop -t 0 = (%d, %q)", code, errS)
	}
	_ = <-sbDone
}
