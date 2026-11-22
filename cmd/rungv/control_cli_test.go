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
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestParseControlRunFlags(t *testing.T) {
	rc, code, done, stderr := parse(t,
		"--name", "web1",
		"--control",
		"--control-policy", "readonly",
		"--control-disable", "exec,net.dial",
		"--dynamic-ports",
		"--allow-volume-attach",
		"--pids-limit", "64",
		"alpine:3.20",
	)
	if done || code != 0 {
		t.Fatalf("parseRunArgs failed: code=%d done=%v stderr=%q", code, done, stderr)
	}
	if !strings.HasSuffix(rc.controlSocket, "web1.sock") {
		t.Errorf("controlSocket = %q, want suffix web1.sock", rc.controlSocket)
	}
	if rc.cfg.ControlPolicy != control.PolicyReadOnly {
		t.Errorf("ControlPolicy = %q, want readonly", rc.cfg.ControlPolicy)
	}
	if len(rc.cfg.ControlDisable) != 2 || rc.cfg.ControlDisable[0] != "exec" || rc.cfg.ControlDisable[1] != "net.dial" {
		t.Errorf("ControlDisable = %v", rc.cfg.ControlDisable)
	}
	if !rc.cfg.DynamicPorts || !rc.cfg.AllowVolumeAttach || rc.cfg.Resources.PidsLimit != 64 {
		t.Errorf("flags mismatch: dyn=%v vol=%v pids=%d", rc.cfg.DynamicPorts, rc.cfg.AllowVolumeAttach, rc.cfg.Resources.PidsLimit)
	}

	// --control without --name must return exit code 2.
	_, badCode, badDone, badErr := parse(t, "--control", "alpine:3.20")
	if !badDone || badCode != 2 || !strings.Contains(badErr, "--control requires --name") {
		t.Fatalf("--control without --name = (code=%d done=%v stderr=%q)", badCode, badDone, badErr)
	}
}

func TestParseCPEndpointAndWindowsDriveSafety(t *testing.T) {
	for _, tc := range []struct {
		raw      string
		isGuest  bool
		isPipe   bool
		sandbox  string
		wantPath string
	}{
		{raw: "-", isPipe: true, wantPath: "-"},
		{raw: ":/etc/hosts", isGuest: true, wantPath: "/etc/hosts"},
		{raw: "web1:/var/log/app.log", isGuest: true, sandbox: "web1", wantPath: "/var/log/app.log"},
		{raw: `C:\Users\dev\file.txt`, isGuest: false, wantPath: `C:\Users\dev\file.txt`},
		{raw: `D:/work/app`, isGuest: false, wantPath: `D:/work/app`},
		{raw: "./local/file.txt", isGuest: false, wantPath: "./local/file.txt"},
	} {
		got := parseCPEndpoint(tc.raw)
		if got.isGuest != tc.isGuest || got.isPipe != tc.isPipe || got.sandboxName != tc.sandbox || got.path != tc.wantPath {
			t.Errorf("parseCPEndpoint(%q) = %+v, want guest=%v pipe=%v sb=%q path=%q",
				tc.raw, got, tc.isGuest, tc.isPipe, tc.sandbox, tc.wantPath)
		}
	}
}

func TestParseDetachKeysAndCopyWithDetach(t *testing.T) {
	seq, err := parseDetachKeys("ctrl-p,ctrl-q")
	if err != nil {
		t.Fatalf("parseDetachKeys: %v", err)
	}
	if !bytes.Equal(seq, []byte{0x10, 0x11}) {
		t.Fatalf("seq = %x, want 1011", seq)
	}
	var out bytes.Buffer
	detached := copyWithDetach(&out, bytes.NewReader([]byte{'a', 0x10, 'b', 0x10, 0x11, 'c'}), seq)
	if !detached {
		t.Fatal("copyWithDetach returned false, want true")
	}
	if !bytes.Equal(out.Bytes(), []byte{'a', 0x10, 'b'}) {
		t.Fatalf("forwarded bytes = %x, want 611062", out.Bytes())
	}
}

func TestParseTunnelAndServeMountSpecs(t *testing.T) {
	ts, err := parseTunnelSpec("8080:80", "127.0.0.1", "")
	if err != nil || ts.listenAddr != "127.0.0.1:8080" || ts.guestPort != 80 {
		t.Fatalf("parseTunnelSpec(8080:80) = (%+v, %v)", ts, err)
	}
	ts2, err := parseTunnelSpec("0.0.0.0:9090:172.17.0.2:8080", "127.0.0.1", "")
	if err != nil || ts2.listenAddr != "0.0.0.0:9090" || ts2.guestIP != "172.17.0.2" || ts2.guestPort != 8080 {
		t.Fatalf("parseTunnelSpec(4-part) = (%+v, %v)", ts2, err)
	}
	hostDir, guestTarget, err := parseServeMountSpec(`C:\src\proj:/mnt/proj`)
	if err != nil || hostDir != `C:\src\proj` || guestTarget != "/mnt/proj" {
		t.Fatalf("parseServeMountSpec(win) = (%q, %q, %v)", hostDir, guestTarget, err)
	}
}

func TestExtractTarToHostDirRejectsPathTraversal(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	_ = tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: 3})
	_, _ = tw.Write([]byte("bad"))
	_ = tw.Close()

	if err := extractTarToHostDir(&buf, t.TempDir(), hostExtractOptions{}); err == nil {
		t.Fatal("extractTarToHostDir accepted ../escape.txt, want error")
	}
}

func TestCLIControlSubcommandsEndToEnd(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "cli-exec-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64: %v", err)
	}
	exit7ELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 7, "")
	if err != nil {
		t.Fatalf("BuildGuestELF64(7): %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/exit7", Data: exit7ELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("cli-ready\n"), Mode: 0o644},
		testimage.File{Name: "tmp/", Type: tar.TypeDir, Mode: 0o1777},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/dyn/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/srv/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "clictrl", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	cacheDir := t.TempDir()
	sockPath := filepath.Join(shortSocketDir(t), "cli.sock")
	stdinR, stdinW := net.Pipe()
	defer stdinR.Close()
	defer stdinW.Close()
	stdout := newSyncNotifyBuffer()
	stderr := newSyncNotifyBuffer()

	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	runDone := make(chan int, 1)
	go func() {
		runDone <- executeCLI(runCtx, []string{
			"run",
			"-lockdown=false",
			"-platform=" + platform,
			"-net=none",
			"-cache-dir=" + cacheDir,
			"-registry-url=" + regURL,
			"--name=cli-box",
			"-S", sockPath,
			"clictrl:latest",
		}, stdinR, stdout, stderr)
	}()
	stdout.waitForSubstring(t, "cli-ready\n", 15*time.Second)

	runCmd := func(stdin io.Reader, args ...string) (int, string, string) {
		var outB, errB bytes.Buffer
		c := executeCLI(context.Background(), args, stdin, &outB, &errB)
		return c, outB.String(), errB.String()
	}

	// ping & status & top & stats
	if code, out, errS := runCmd(nil, "ping", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"cli-box"`) {
		t.Fatalf("ping = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "status", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"running"`) {
		t.Fatalf("status = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "top", "-S", sockPath, "-f", "json"); code != 0 || !strings.Contains(out, `"pid":1`) {
		t.Fatalf("top = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(nil, "stats", "-S", sockPath, "--no-stream", "-f", "json"); code != 0 || !strings.Contains(out, `"pids"`) {
		t.Fatalf("stats = (%d, %q, %q)", code, out, errS)
	}

	// pause & unpause
	if code, _, errS := runCmd(nil, "pause", "-S", sockPath); code != 0 {
		t.Fatalf("pause = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "unpause", "-S", sockPath); code != 0 {
		t.Fatalf("unpause = (%d, %q)", code, errS)
	}

	// exec (stdout, closed stdin, -i piped stdin, exit code)
	if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/hello"); code != 0 || out != "cli-exec-ok\n" {
		t.Fatalf("exec hello = (%d, %q, %q)", code, out, errS)
	}
	if code, out, errS := runCmd(strings.NewReader("from-host\n"), "exec", "-S", sockPath, "-i", "--", "/bin/cat", "/proc/self/fd/0"); code != 0 || out != "from-host\n" {
		t.Fatalf("exec -i = (%d, %q, %q)", code, out, errS)
	}
	if code, _, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/exit7"); code != 7 {
		t.Fatalf("exec exit7 = (%d, %q), want 7", code, errS)
	}

	// cp host -> guest -> host
	srcFile := filepath.Join(t.TempDir(), "in.txt")
	if err := os.WriteFile(srcFile, []byte("hello-cp-roundtrip\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-z", srcFile, ":/tmp/in.txt"); code != 0 {
		t.Fatalf("cp host->guest = (%d, %q)", code, errS)
	}
	dstFile := filepath.Join(t.TempDir(), "out.txt")
	if code, _, errS := runCmd(nil, "cp", "-S", sockPath, "-z", ":/tmp/in.txt", dstFile); code != 0 {
		t.Fatalf("cp guest->host = (%d, %q)", code, errS)
	}
	gotCP, err := os.ReadFile(dstFile)
	if err != nil || string(gotCP) != "hello-cp-roundtrip\n" {
		t.Fatalf("cp roundtrip content = (%q, %v)", gotCP, err)
	}

	// update live limits
	if code, out, errS := runCmd(nil, "update", "-S", sockPath, "-m", "300m", "--cpus", "0.5", "--pids-limit", "40", "-f", "json"); code != 0 {
		t.Fatalf("update = (%d, %q, %q)", code, out, errS)
	} else {
		var snap control.ResourceSnapshot
		if err := json.Unmarshal([]byte(out), &snap); err != nil || snap.PidsLimit != 40 || snap.CPUQuotaUSec != 50000 {
			t.Fatalf("update snap = (%+v, %v)", snap, err)
		}
	}

	// mount add tmpfs -> remount ro -> rm
	if code, _, errS := runCmd(nil, "mount", "add", "-S", sockPath, "--type", "tmpfs", "--dst", "/mnt/dyn", "--size", "8m"); code != 0 {
		t.Fatalf("mount add = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "mount", "remount", "-S", sockPath, "--ro", "/mnt/dyn"); code != 0 {
		t.Fatalf("mount remount = (%d, %q)", code, errS)
	}
	if code, _, errS := runCmd(nil, "mount", "rm", "-S", sockPath, "/mnt/dyn"); code != 0 {
		t.Fatalf("mount rm = (%d, %q)", code, errS)
	}

	// mount serve host dir -> read inside guest via exec
	serveHostDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveHostDir, "msg.txt"), []byte("served-by-cli\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveOut := newSyncNotifyBuffer()
	serveErr := newSyncNotifyBuffer()
	serveDone := make(chan int, 1)
	go func() {
		serveDone <- executeCLI(serveCtx, []string{"mount", "serve", "-S", sockPath, serveHostDir + ":/mnt/srv"}, nil, serveOut, serveErr)
	}()
	serveOut.waitForSubstring(t, "Serving ", 10*time.Second)

	if code, out, errS := runCmd(nil, "exec", "-S", sockPath, "--", "/bin/cat", "/mnt/srv/msg.txt"); code != 0 || out != "served-by-cli\n" {
		t.Fatalf("exec read served mount = (%d, %q, %q)", code, out, errS)
	}
	serveCancel()
	<-serveDone

	// Wait for the server to finish auto-unmounting /mnt/srv after client disconnect.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if code, out, _ := runCmd(nil, "mount", "ls", "-S", sockPath, "-q"); code == 0 && !strings.Contains(out, "/mnt/srv") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	// checkpoint -o streaming bundle (no -checkpoint-dir on run!) -> stop sandbox -> restore
	ckptOutDir := filepath.Join(t.TempDir(), "streamed-bundle")
	if code, _, errS := runCmd(nil, "checkpoint", "-S", sockPath, "-z", "-o", ckptOutDir); code != 0 {
		t.Fatalf("checkpoint -o = (%d, %q)", code, errS)
	}
	if exitCode := <-runDone; exitCode != 0 {
		t.Fatalf("run exited with %d (stderr=%q)", exitCode, stderr.String())
	}

	var resOut, resErr bytes.Buffer
	resCode := executeCLI(context.Background(), []string{
		"restore",
		"-lockdown=false",
		"-platform=" + platform,
		"-net=none",
		"-cache-dir=" + cacheDir,
		"-registry-url=" + regURL,
		"-checkpoint-dir=" + ckptOutDir,
	}, strings.NewReader("resumed-from-stream\n"), &resOut, &resErr)
	if resCode != 0 || resOut.String() != "resumed-from-stream\n" {
		t.Fatalf("restore from streamed checkpoint = (code=%d out=%q err=%q)", resCode, resOut.String(), resErr.String())
	}
}
