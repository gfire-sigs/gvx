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
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

const fdHoldGuestSource = `package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func main() {
	fmt.Println("READY")
	scanner := bufio.NewScanner(os.Stdin)
	var f *os.File
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		switch {
		case strings.HasPrefix(line, "open "):
			p := strings.TrimSpace(strings.TrimPrefix(line, "open "))
			var err error
			f, err = os.OpenFile(p, os.O_RDWR, 0)
			if err != nil {
				fmt.Printf("ERR:%v\n", err)
				continue
			}
			buf := make([]byte, 6)
			n, err := f.Read(buf)
			if err != nil {
				fmt.Printf("ERR:%v\n", err)
				continue
			}
			fmt.Printf("OPENED:%s\n", string(buf[:n]))
		case line == "read":
			if f == nil {
				fmt.Println("ERR:not-open")
				continue
			}
			buf := make([]byte, 4)
			n, err := f.Read(buf)
			if err != nil {
				fmt.Printf("ERR:%v\n", err)
				continue
			}
			fmt.Printf("READ:%s\n", string(buf[:n]))
		case strings.HasPrefix(line, "write "):
			if f == nil {
				fmt.Println("ERR:not-open")
				continue
			}
			payload := strings.TrimPrefix(line, "write ")
			if _, err := f.Write([]byte(payload)); err != nil {
				fmt.Printf("ERR:%v\n", err)
				continue
			}
			fmt.Println("WRITTEN")
		case line == "quit":
			if f != nil {
				_ = f.Close()
			}
			return
		}
	}
}
`

func buildFDHoldGuestELF(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module fdhold\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(fdHoldGuestSource), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "fdhold")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build fdhold guest ELF: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func startTestRPCFSServer(t *testing.T, ctx context.Context, client *control.Client, hostPath, guestTarget string, readOnly, singleFile bool) (detachedCh <-chan bool, cancelFn func(), doneCh <-chan struct{}) {
	t.Helper()
	var (
		root     *os.Root
		leafName string
		err      error
	)
	if singleFile {
		resolved, rErr := filepath.EvalSymlinks(hostPath)
		if rErr != nil {
			t.Fatalf("EvalSymlinks(%q): %v", hostPath, rErr)
		}
		leafName = filepath.Base(resolved)
		root, err = os.OpenRoot(filepath.Dir(resolved))
	} else {
		root, err = os.OpenRoot(hostPath)
	}
	if err != nil {
		t.Fatalf("OpenRoot(%q): %v", hostPath, err)
	}

	serveCtx, serveCancel := context.WithCancel(ctx)
	st, err := client.OpenStream(serveCtx, control.MethodMountServe, control.MountServeRequest{
		Target:     guestTarget,
		ReadOnly:   readOnly,
		Label:      hostPath,
		SingleFile: singleFile,
	})
	if err != nil {
		serveCancel()
		_ = root.Close()
		t.Fatalf("OpenStream(mount.serve %s): %v", guestTarget, err)
	}
	var resp control.MountServeResponse
	if err := st.WaitResponse(serveCtx, &resp); err != nil {
		st.Close()
		serveCancel()
		_ = root.Close()
		t.Fatalf("WaitResponse(mount.serve %s): %v", guestTarget, err)
	}

	detCh := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer root.Close()
		defer st.Close()
		gotDetached := false
		for {
			ev, err := st.RecvEvent(serveCtx)
			if err != nil {
				detCh <- gotDetached
				return
			}
			if ev.Type == "rpcfs.detached" {
				gotDetached = true
				detCh <- true
				return
			}
			if ev.Type != "rpcfs.req" {
				continue
			}
			var req control.RPCFSRequest
			if json.Unmarshal(ev.Data, &req) != nil {
				continue
			}
			if singleFile && (req.Path == "." || req.Path == "" || req.Path == "/") {
				req.Path = leafName
			}
			rpcResp := handleTestRPCFS(root, req)
			_ = st.SendEvent(serveCtx, "rpcfs.resp", rpcResp)
		}
	}()
	return detCh, func() {
		serveCancel()
		st.Cancel(nil)
	}, done
}

func startRestoredControlSandbox(t *testing.T, cfg Config, dir string) *runningControlSandbox {
	t.Helper()
	sockPath := shortControlSocketPath(t, "r.sock")
	ep, err := control.Listen(sockPath, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen(%q): %v", sockPath, err)
	}
	t.Cleanup(ep.Cleanup)

	stdinR, stdinW := net.Pipe()
	stdout := newNotifyBuffer()

	if cfg.Platform == "" {
		cfg.Platform = PlatformAuto
		cfg.AllowUnconfinedSystrap = runtime.GOOS == "windows"
	}
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = NetModeNone
	}
	cfg.DisableHostLockdown = true
	cfg.ControlListener = ep.Listener
	cfg.ControlToken = ep.Token
	cfg.Stdin = stdinR
	cfg.Stdout = stdout
	cfg.Stderr = io.Discard

	ctx, cancel := context.WithCancel(context.Background())
	sb, err := Restore(ctx, cfg, RestoreOptions{Dir: dir})
	if err != nil {
		cancel()
		_ = ep.Listener.Close()
		_ = stdinR.Close()
		_ = stdinW.Close()
		t.Fatalf("gvx.Restore: %v", err)
	}

	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	ctrlDone := make(chan struct{})
	go func() {
		defer close(ctrlDone)
		_ = sb.ServeControl(ctrlCtx)
	}()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_, _ = sb.Run(ctx)
	}()

	client, err := control.Dial(ctx, control.DialOptions{
		Endpoint: sockPath,
		Token:    ep.Token,
	})
	if err != nil {
		_ = stdinW.Close()
		_ = stdinR.Close()
		cancel()
		ctrlCancel()
		_ = sb.Close()
		<-ctrlDone
		<-runDone
		t.Fatalf("control.Dial: %v", err)
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = stdinW.Close()
		cancel()
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = sb.ShutdownControl(drainCtx)
		drainCancel()
		ctrlCancel()
		<-ctrlDone
		<-runDone
		_ = sb.Close()
		_ = stdinR.Close()
	})
	return &runningControlSandbox{
		sb:      sb,
		ep:      ep,
		client:  client,
		stdout:  stdout,
		stdinW:  stdinW,
		runDone: runDone,
		cancel:  cancel,
	}
}

func TestCheckpointRestoreWithLiveRPCFSAndDynamicMounts(t *testing.T) {
	requireCheckpointGuestBackend(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	fdHoldELF := buildFDHoldGuestELF(t)
	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/fdhold", Data: fdHoldELF, Mode: 0o755},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}

	cacheDir := t.TempDir()
	ckptDir := t.TempDir()
	serveDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(serveDir, "data.txt"), []byte("0123456789abcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	singleDir := t.TempDir()
	singleFile := filepath.Join(singleDir, "single.txt")
	if err := os.WriteFile(singleFile, []byte("single-file-content\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rs := startControlTestSandbox(t, Config{
		OCILayerTars:  [][]byte{layer},
		OCICacheDir:   cacheDir,
		CheckpointDir: ckptDir,
		Argv:          []string{"/bin/fdhold"},
	})
	rs.stdout.waitForSubstring(t, "READY\n", 15*time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Add dynamic tmpfs mount.
	var tmpInfo control.MountInfo
	if err := rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
		Type:   "tmpfs",
		Target: "/mnt/dyn-tmp",
	}, &tmpInfo); err != nil {
		t.Fatalf("mount.add tmpfs: %v", err)
	}

	// Serve a directory and a read-only single file over rpcfs.
	detDirCh, cancelDir, doneDir := startTestRPCFSServer(t, ctx, rs.client, serveDir, "/mnt/proj", false, false)
	defer func() {
		cancelDir()
		<-doneDir
	}()
	detSingleCh, cancelSingle, doneSingle := startTestRPCFSServer(t, ctx, rs.client, singleFile, "/mnt/single.txt", true, true)
	defer func() {
		cancelSingle()
		<-doneSingle
	}()

	// Have guest open /mnt/proj/data.txt and advance its FD offset to 6.
	if _, err := io.WriteString(rs.stdinW, "open /mnt/proj/data.txt\n"); err != nil {
		t.Fatalf("write open cmd: %v", err)
	}
	rs.stdout.waitForSubstring(t, "OPENED:012345\n", 10*time.Second)

	// 1. Checkpoint with LeaveRunning=true while rpcfs and dynamic tmpfs are active.
	if err := rs.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: true}); err != nil {
		t.Fatalf("Checkpoint(LeaveRunning=true): %v", err)
	}

	// Verify manifest.json records runtime mounts with labels and flags.
	manifest, err := readAndParseManifest(ckptDir)
	if err != nil {
		t.Fatalf("readAndParseManifest: %v", err)
	}
	byTarget := make(map[string]ManifestMount, len(manifest.Mounts))
	for _, mm := range manifest.Mounts {
		byTarget[mm.GuestPath] = mm
	}
	projMM, ok := byTarget["/mnt/proj"]
	if !ok || projMM.Type != MountRPCFS || !projMM.Dynamic || projMM.ReadOnly || projMM.SingleFile || projMM.Label != serveDir {
		t.Fatalf("manifest /mnt/proj = (%+v, ok=%v), want rpcfs dynamic rw label=%q", projMM, ok, serveDir)
	}
	singleMM, ok := byTarget["/mnt/single.txt"]
	if !ok || singleMM.Type != MountRPCFS || !singleMM.Dynamic || !singleMM.ReadOnly || !singleMM.SingleFile || singleMM.Label != singleFile {
		t.Fatalf("manifest /mnt/single.txt = (%+v, ok=%v), want rpcfs dynamic ro single_file label=%q", singleMM, ok, singleFile)
	}
	tmpMM, ok := byTarget["/mnt/dyn-tmp"]
	if !ok || tmpMM.Type != MountTmpfs || !tmpMM.Dynamic {
		t.Fatalf("manifest /mnt/dyn-tmp = (%+v, ok=%v), want dynamic tmpfs", tmpMM, ok)
	}

	// Original running guest must still read seamlessly from the open FD after LeaveRunning checkpoint.
	if _, err := io.WriteString(rs.stdinW, "read\n"); err != nil {
		t.Fatalf("write read cmd: %v", err)
	}
	rs.stdout.waitForSubstring(t, "READ:6789\n", 10*time.Second)

	// 2. Restore Case A: Restore WITH --serve (Config.ServeMounts) and WITHOUT dynamic tmpfs flag.
	restoreDirA := t.TempDir()
	if err := os.WriteFile(filepath.Join(restoreDirA, "data.txt"), []byte("012345ABCDabcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	rsA := startRestoredControlSandbox(t, Config{
		OCICacheDir: cacheDir,
		ServeMounts: []ServeMount{
			{HostPath: restoreDirA, GuestPath: "/mnt/proj"},
			{HostPath: singleFile, GuestPath: "/mnt/single.txt", ReadOnly: true},
		},
	}, ckptDir)

	if _, err := io.WriteString(rsA.stdinW, "read\n"); err != nil {
		t.Fatalf("write read to restored A: %v", err)
	}
	rsA.stdout.waitForSubstring(t, "READ:ABCD\n", 10*time.Second)
	if _, err := io.WriteString(rsA.stdinW, "write XY\n"); err != nil {
		t.Fatalf("write payload to restored A: %v", err)
	}
	rsA.stdout.waitForSubstring(t, "WRITTEN\n", 10*time.Second)
	diskA, err := os.ReadFile(filepath.Join(restoreDirA, "data.txt"))
	if err != nil || string(diskA) != "012345ABCDXYcdef" {
		t.Fatalf("restored A host data.txt = (%q, %v), want 012345ABCDXYcdef", diskA, err)
	}

	// Verify restored single-file rpcfs mount reads cleanly via exec.
	catSt, err := rsA.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
		Argv: []string{"/bin/cat", "/mnt/single.txt"},
	})
	if err != nil {
		t.Fatalf("exec cat single.txt: %v", err)
	}
	if err := catSt.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("exec cat single.txt wait: %v", err)
	}
	gotSingle, readErr := io.ReadAll(catSt.ChannelReader(ctx, control.ChannelStdout))
	catSt.Close()
	if readErr != nil || string(gotSingle) != "single-file-content\n" {
		t.Fatalf("restored single.txt = (%q, %v), want single-file-content", gotSingle, readErr)
	}

	// Verify mount.list on restored A shows /mnt/proj, /mnt/single.txt, and omitted dynamic /mnt/dyn-tmp.
	var ml control.MountListResponse
	if err := rsA.client.Call(ctx, control.MethodMountList, nil, &ml); err != nil {
		t.Fatalf("mount.list on restored A: %v", err)
	}
	seenTargets := make(map[string]bool, len(ml.Mounts))
	for _, m := range ml.Mounts {
		seenTargets[m.Target] = true
	}
	for _, want := range []string{"/mnt/proj", "/mnt/single.txt", "/mnt/dyn-tmp"} {
		if !seenTargets[want] {
			t.Fatalf("mount.list missing %q: %+v", want, ml.Mounts)
		}
	}

	// 3. Restore Case B: Restore WITHOUT --serve -> EIO -> reconnect via mount.serve -> same open FD works!
	restoreDirB := t.TempDir()
	if err := os.WriteFile(filepath.Join(restoreDirB, "data.txt"), []byte("012345WXYZabcdef"), 0o644); err != nil {
		t.Fatal(err)
	}
	rsB := startRestoredControlSandbox(t, Config{
		OCICacheDir: cacheDir,
	}, ckptDir)

	if _, err := io.WriteString(rsB.stdinW, "read\n"); err != nil {
		t.Fatalf("write detached read to restored B: %v", err)
	}
	rsB.stdout.waitForSubstring(t, "ERR:", 10*time.Second)

	// Reconnect /mnt/proj at runtime via mount.serve.
	_, cancelB, doneB := startTestRPCFSServer(t, ctx, rsB.client, restoreDirB, "/mnt/proj", false, false)
	defer func() {
		cancelB()
		<-doneB
	}()

	if _, err := io.WriteString(rsB.stdinW, "read\n"); err != nil {
		t.Fatalf("write reconnected read to restored B: %v", err)
	}
	rsB.stdout.waitForSubstring(t, "READ:WXYZ\n", 10*time.Second)

	// 4. Negative manifest validation checks on Restore.
	for _, tc := range []struct {
		name   string
		serves []ServeMount
	}{
		{
			name:   "unknown-target",
			serves: []ServeMount{{HostPath: restoreDirA, GuestPath: "/mnt/unknown"}},
		},
		{
			name:   "ro-widened-to-rw",
			serves: []ServeMount{{HostPath: singleFile, GuestPath: "/mnt/single.txt", ReadOnly: false}},
		},
		{
			name:   "single-file-mismatch",
			serves: []ServeMount{{HostPath: restoreDirA, GuestPath: "/mnt/single.txt", ReadOnly: true}},
		},
	} {
		t.Run("reject-"+tc.name, func(t *testing.T) {
			sb, rErr := Restore(ctx, Config{
				Platform:               PlatformAuto,
				AllowUnconfinedSystrap: runtime.GOOS == "windows",
				NetworkMode:            NetModeNone,
				OCICacheDir:            cacheDir,
				DisableHostLockdown:    true,
				ServeMounts:            tc.serves,
			}, RestoreOptions{Dir: ckptDir})
			if sb != nil {
				_ = sb.Close()
			}
			if !errors.Is(rErr, ErrCheckpointManifest) {
				t.Fatalf("Restore(%s) err = %v, want ErrCheckpointManifest", tc.name, rErr)
			}
		})
	}

	// 5. Stopping checkpoint (LeaveRunning=false) must notify serving clients with rpcfs.detached.
	if err := rs.sb.Checkpoint(ctx, CheckpointOptions{LeaveRunning: false}); err != nil {
		t.Fatalf("Checkpoint(LeaveRunning=false): %v", err)
	}
	for name, ch := range map[string]<-chan bool{"dir": detDirCh, "single": detSingleCh} {
		select {
		case detached := <-ch:
			if !detached {
				t.Fatalf("serving client %s exited without rpcfs.detached event", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("serving client %s did not receive rpcfs.detached within 5s", name)
		}
	}
}

func TestParseServeMount(t *testing.T) {
	sm, err := ParseServeMount("/tmp/host:/mnt/proj")
	if err != nil || sm.HostPath != "/tmp/host" || sm.GuestPath != "/mnt/proj" || sm.ReadOnly {
		t.Fatalf("ParseServeMount rw = (%+v, %v)", sm, err)
	}
	sm, err = ParseServeMount("/tmp/host:/mnt/proj:ro")
	if err != nil || !sm.ReadOnly {
		t.Fatalf("ParseServeMount ro = (%+v, %v)", sm, err)
	}
	sm, err = ParseServeMount(`C:\work\proj:/mnt/proj:ro`)
	if err != nil || sm.HostPath != `C:\work\proj` || sm.GuestPath != "/mnt/proj" || !sm.ReadOnly {
		t.Fatalf("ParseServeMount windows = (%+v, %v)", sm, err)
	}
	for _, bad := range []string{"", "/only-one", "/a:/b:bad", ":/b", "/a:"} {
		if _, err := ParseServeMount(bad); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("ParseServeMount(%q) err = %v, want ErrInvalidConfig", bad, err)
		}
	}
	_ = fmt.Sprint(sm)
}
