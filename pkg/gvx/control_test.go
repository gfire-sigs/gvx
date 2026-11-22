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
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

func shortControlSocketPath(t *testing.T, filename string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gvx-t-")
	if err != nil {
		dir = t.TempDir()
	} else {
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
	}
	return filepath.Join(dir, filename)
}

type runningControlSandbox struct {
	sb      *Sandbox
	ep      *control.Endpoint
	client  *control.Client
	stdout  *notifyBuffer
	stdinW  io.WriteCloser
	runDone chan struct{}
	cancel  context.CancelFunc
}

func startControlTestSandbox(t *testing.T, cfg Config) *runningControlSandbox {
	t.Helper()
	requireCheckpointGuestBackend(t)

	sockPath := shortControlSocketPath(t, "c.sock")
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
	if cfg.OCICacheDir == "" {
		cfg.OCICacheDir = t.TempDir()
	}
	cfg.DisableHostLockdown = true
	cfg.ControlListener = ep.Listener
	cfg.ControlToken = ep.Token
	cfg.Stdin = stdinR
	cfg.Stdout = stdout
	cfg.Stderr = io.Discard

	ctx, cancel := context.WithCancel(context.Background())
	sb, err := New(ctx, cfg)
	if err != nil {
		cancel()
		_ = ep.Listener.Close()
		_ = stdinR.Close()
		_ = stdinW.Close()
		t.Fatalf("gvx.New: %v", err)
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
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Errorf("Sandbox.Run did not exit within 10s during test cleanup")
		}
		_ = stdinR.Close()
		_ = sb.Close()
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

func buildControlTestImage(t *testing.T) (cacheDir, registryURL, imageRef string) {
	t.Helper()
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "exec-hello\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64(hello): %v", err)
	}
	exit42ELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 42, "exit42-out\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64(42): %v", err)
	}
	writeProxyELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/mnt/proxy/from_guest.txt", "written-via-rpcfs\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64: %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/exit42", Data: exit42ELF, Mode: 0o755},
		testimage.File{Name: "bin/writeproxy", Data: writeProxyELF, Mode: 0o755},
		testimage.File{Name: "etc/seed.txt", Data: []byte("ready-marker\n"), Mode: 0o644},
		testimage.File{Name: "etc/passwd", Data: []byte("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n"), Mode: 0o644},
		testimage.File{Name: "etc/group", Data: []byte("root:x:0:\nnogroup:x:65534:\n"), Mode: 0o644},
		testimage.File{Name: "tmp/", Type: tar.TypeDir, Mode: 0o1777},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/proxy/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/tmp/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	srvURL := testimage.NewRegistry(t, "ctrltest", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/seed.txt", "/proc/self/fd/0"},
	})
	return t.TempDir(), srvURL, "ctrltest:latest"
}

func TestControlOpsPauseExecFSAndMounts(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	wsDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(wsDir, "ro.txt"), []byte("host-ro\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rs := startControlTestSandbox(t, Config{
		Name:              "ctrl-main",
		OCIImage:          imgRef,
		OCICacheDir:       cacheDir,
		RegistryBaseURL:   regURL,
		WorkspacePath:     wsDir,
		WorkspaceReadOnly: true,
		Resources:         Resources{MemoryBytes: 256 << 20},
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()

	// 1. system.ping, sandbox.inspect, sandbox.stats, proc.list, kernel.log, debug.log_level
	var ping control.PingResponse
	if err := rs.client.Call(ctx, control.MethodPing, nil, &ping); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if ping.State != "running" || ping.SandboxID != "ctrl-main" {
		t.Fatalf("ping = %+v", ping)
	}

	var inspect control.InspectResponse
	if err := rs.client.Call(ctx, control.MethodInspect, nil, &inspect); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if inspect.State != "running" || inspect.PIDCount < 1 {
		t.Fatalf("inspect = %+v", inspect)
	}

	var stats control.StatsSample
	if err := rs.client.Call(ctx, control.MethodStats, control.StatsRequest{}, &stats); err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.PIDs < 1 || stats.Memory.LimitBytes != 256<<20 {
		t.Fatalf("stats = %+v", stats)
	}

	var procs control.ProcListResponse
	if err := rs.client.Call(ctx, control.MethodProcList, nil, &procs); err != nil {
		t.Fatalf("proc.list: %v", err)
	}
	if len(procs.Processes) == 0 || procs.Processes[0].PID != 1 {
		t.Fatalf("proc.list = %+v", procs.Processes)
	}

	var klog control.KernelLogResponse
	if err := rs.client.Call(ctx, control.MethodKernelLog, control.KernelLogRequest{Tail: 10}, &klog); err != nil {
		t.Fatalf("kernel.log: %v", err)
	}
	if err := rs.client.Call(ctx, control.MethodDebugLogLevel, control.DebugLogLevelRequest{Level: "warning"}, nil); err != nil {
		t.Fatalf("debug.log_level: %v", err)
	}

	// 2. pause & unpause + double-pause error + exec rejected while paused
	if err := rs.client.Call(ctx, control.MethodPause, control.PauseRequest{}, nil); err != nil {
		t.Fatalf("pause: %v", err)
	}
	if err := rs.client.Call(ctx, control.MethodPause, control.PauseRequest{}, nil); !control.IsCode(err, control.CodeAlreadyPaused) {
		t.Fatalf("second pause err = %v, want ALREADY_PAUSED", err)
	}
	if err := rs.client.Call(ctx, control.MethodExecStart, control.ExecStartRequest{Argv: []string{"/bin/hello"}}, nil); !control.IsCode(err, control.CodeAlreadyPaused) {
		t.Fatalf("exec while paused err = %v, want ALREADY_PAUSED", err)
	}
	if err := rs.client.Call(ctx, control.MethodUnpause, nil, nil); err != nil {
		t.Fatalf("unpause: %v", err)
	}

	// 3. Docker-style exec: closed stdin default vs interactive -i + exit code 42
	// 3a: /bin/cat /proc/self/fd/0 with Stdin=false exits immediately (EOF on /dev/null).
	{
		st, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
			Stdin: false,
		})
		if err != nil {
			t.Fatalf("exec open: %v", err)
		}
		var started control.ExecStartResponse
		if err := st.WaitResponse(ctx, &started); err != nil {
			t.Fatalf("exec wait: %v", err)
		}
		out, readErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		ev, err := st.RecvEvent(ctx)
		st.Close()
		if readErr != nil || err != nil || ev.Type != "exec.exit" || len(out) != 0 {
			t.Fatalf("closed-stdin exec: out=%q readErr=%v ev=%+v err=%v", out, readErr, ev, err)
		}
	}
	// 3b: /bin/cat /proc/self/fd/0 with Stdin=true echoes piped bytes.
	{
		st, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
			Stdin: true,
		})
		if err != nil {
			t.Fatalf("exec -i open: %v", err)
		}
		if err := st.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec -i wait: %v", err)
		}
		w := st.ChannelWriter(ctx, control.ChannelStdin, false)
		if _, err := io.WriteString(w, "piped-stdin-payload\n"); err != nil {
			t.Fatalf("exec -i write stdin: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("exec -i close stdin: %v", err)
		}
		out, readErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		st.Close()
		if readErr != nil || string(out) != "piped-stdin-payload\n" {
			t.Fatalf("exec -i stdout = (%q, %v), want piped-stdin-payload", out, readErr)
		}
	}
	// 3c: /bin/exit42 propagates exit code 42.
	{
		st, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv: []string{"/bin/exit42"},
		})
		if err != nil {
			t.Fatalf("exec42 open: %v", err)
		}
		if err := st.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec42 wait: %v", err)
		}
		out, readErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		ev, err := st.RecvEvent(ctx)
		st.Close()
		var exitEv control.ExecExitEvent
		unmarshalErr := json.Unmarshal(ev.Data, &exitEv)
		if readErr != nil || err != nil || unmarshalErr != nil || exitEv.ExitCode != 42 || string(out) != "exit42-out\n" {
			t.Fatalf("exec42 = (out=%q, readErr=%v, exit=%+v, unmarshalErr=%v, err=%v)", out, readErr, exitEv, unmarshalErr, err)
		}
	}

	// 4. fs.import -> fs.stat -> fs.export (regular & upper_only)
	{
		var tarBuf bytes.Buffer
		tw := tar.NewWriter(&tarBuf)
		payload := []byte("copied-from-host\n")
		_ = tw.WriteHeader(&tar.Header{Name: "copied.txt", Mode: 0o644, Size: int64(len(payload))})
		_, _ = tw.Write(payload)
		_ = tw.Close()

		impSt, err := rs.client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{
			DestPath: "/tmp",
			Compress: true,
		})
		if err != nil {
			t.Fatalf("fs.import open: %v", err)
		}
		w := impSt.ChannelWriter(ctx, control.ChannelGeneric, true)
		_, _ = w.Write(tarBuf.Bytes())
		_ = w.Close()
		var impResp control.FSImportResponse
		if err := impSt.WaitResponse(ctx, &impResp); err != nil {
			t.Fatalf("fs.import resp: %v", err)
		}
		impSt.Close()
		if impResp.FilesWritten != 1 {
			t.Fatalf("FilesWritten = %d, want 1", impResp.FilesWritten)
		}

		var stResp control.FSStatResponse
		if err := rs.client.Call(ctx, control.MethodFSStat, control.FSStatRequest{Path: "/tmp/copied.txt"}, &stResp); err != nil {
			t.Fatalf("fs.stat: %v", err)
		}
		if !stResp.Exists || stResp.Type != "file" || stResp.Size != int64(len(payload)) {
			t.Fatalf("fs.stat = %+v", stResp)
		}

		expSt, err := rs.client.OpenStream(ctx, control.MethodFSExport, control.FSExportRequest{
			Path:     "/tmp/copied.txt",
			Compress: true,
		})
		if err != nil {
			t.Fatalf("fs.export open: %v", err)
		}
		if err := expSt.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("fs.export resp: %v", err)
		}
		exportedBytes, err := io.ReadAll(expSt.ChannelReader(ctx, control.ChannelGeneric))
		expSt.Close()
		if err != nil {
			t.Fatalf("fs.export read: %v", err)
		}
		tr := tar.NewReader(bytes.NewReader(exportedBytes))
		hdr, err := tr.Next()
		if err != nil || hdr.Name != "copied.txt" {
			t.Fatalf("exported tar header = (%+v, %v)", hdr, err)
		}
		got, readErr := io.ReadAll(tr)
		if readErr != nil || string(got) != string(payload) {
			t.Fatalf("exported content = (%q, %v), want %q", got, readErr, payload)
		}

		// fs.import must reject symlink traversal escaping DestPath.
		{
			var escTar bytes.Buffer
			twEsc := tar.NewWriter(&escTar)
			_ = twEsc.WriteHeader(&tar.Header{Name: "sub", Typeflag: tar.TypeSymlink, Linkname: "/etc"})
			_ = twEsc.WriteHeader(&tar.Header{Name: "sub/escaped.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3})
			_, _ = twEsc.Write([]byte("bad"))
			_ = twEsc.Close()

			escSt, err := rs.client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{DestPath: "/tmp"})
			if err != nil {
				t.Fatalf("fs.import escape open: %v", err)
			}
			wEsc := escSt.ChannelWriter(ctx, control.ChannelGeneric, false)
			_, _ = wEsc.Write(escTar.Bytes())
			_ = wEsc.Close()
			if err := escSt.WaitResponse(ctx, nil); err == nil {
				t.Fatal("fs.import accepted symlink traversal outside DestPath, want error")
			}
			escSt.Close()

			var checkEsc control.FSStatResponse
			if err := rs.client.Call(ctx, control.MethodFSStat, control.FSStatRequest{Path: "/etc/escaped.txt"}, &checkEsc); err != nil {
				t.Fatalf("fs.stat escaped check: %v", err)
			}
			if checkEsc.Exists {
				t.Fatal("/etc/escaped.txt was created via fs.import symlink escape")
			}
		}

		// Upper-only export should include tmp/copied.txt and exclude lower-layer etc/seed.txt.
		upSt, err := rs.client.OpenStream(ctx, control.MethodFSExport, control.FSExportRequest{
			Path:      "/",
			UpperOnly: true,
		})
		if err != nil {
			t.Fatalf("fs.export upper_only open: %v", err)
		}
		if err := upSt.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("fs.export upper_only resp: %v", err)
		}
		upBytes, upErr := io.ReadAll(upSt.ChannelReader(ctx, control.ChannelGeneric))
		upSt.Close()
		if upErr != nil {
			t.Fatalf("fs.export upper_only read: %v", upErr)
		}
		upTR := tar.NewReader(bytes.NewReader(upBytes))
		var seenCopied, seenLower bool
		for {
			h, err := upTR.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatalf("upper tar read: %v", err)
			}
			if strings.HasSuffix(h.Name, "copied.txt") {
				seenCopied = true
			}
			if strings.HasSuffix(h.Name, "seed.txt") {
				seenLower = true
			}
		}
		if !seenCopied || seenLower {
			t.Fatalf("upper_only tar: seenCopied=%v seenLower=%v, want true/false", seenCopied, seenLower)
		}
	}

	// 5. Runtime mounts: add tmpfs, remount rw->ro->rw, refuse RO->RW on host-RO workspace, subpath, and symlink, unmount tmpfs
	{
		var added control.MountInfo
		if err := rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{
			Type:           "tmpfs",
			Target:         "/mnt/tmp",
			TmpfsSizeBytes: 8 << 20,
		}, &added); err != nil {
			t.Fatalf("mount.add tmpfs: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
			Target:   "/mnt/tmp",
			ReadOnly: true,
		}, nil); err != nil {
			t.Fatalf("mount.remount ro: %v", err)
		}
		// Originally writable mount must allow remounting back from ro to rw.
		if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
			Target:   "/mnt/tmp",
			ReadOnly: false,
		}, nil); err != nil {
			t.Fatalf("mount.remount rw round-trip: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
			Target:   "/workspace",
			ReadOnly: false,
		}, nil); !control.IsCode(err, control.CodeLockdownDenied) {
			t.Fatalf("remount host-RO workspace rw err = %v, want LOCKDOWN_DENIED", err)
		}
		// Subpath inside a host-RO mount must NOT bypass the RO->RW guard.
		if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
			Target:   "/workspace/ro.txt",
			ReadOnly: false,
		}, nil); err == nil {
			t.Fatal("remount subpath /workspace/ro.txt rw succeeded, want rejection")
		}
		// Symlink pointing to /workspace must NOT bypass the RO->RW guard.
		{
			var symTar bytes.Buffer
			twSym := tar.NewWriter(&symTar)
			_ = twSym.WriteHeader(&tar.Header{Name: "wslink", Typeflag: tar.TypeSymlink, Linkname: "/workspace"})
			_ = twSym.Close()
			symSt, err := rs.client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{DestPath: "/tmp"})
			if err != nil {
				t.Fatalf("import wslink open: %v", err)
			}
			wSym := symSt.ChannelWriter(ctx, control.ChannelGeneric, false)
			_, _ = wSym.Write(symTar.Bytes())
			_ = wSym.Close()
			if err := symSt.WaitResponse(ctx, nil); err != nil {
				t.Fatalf("import wslink resp: %v", err)
			}
			symSt.Close()
			if err := rs.client.Call(ctx, control.MethodMountRemount, control.MountRemountRequest{
				Target:   "/tmp/wslink",
				ReadOnly: false,
			}, nil); err == nil {
				t.Fatal("remount symlink /tmp/wslink rw succeeded, want rejection")
			}
		}
		if err := rs.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{
			Target: "/mnt/tmp",
		}, nil); err != nil {
			t.Fatalf("mount.remove: %v", err)
		}
	}

	// 6. mount.serve (rpcfs): serve host dir to /mnt/proxy, read & write from guest, checkpoint BUSY guard
	{
		serveDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(serveDir, "host.txt"), []byte("hello-from-rpcfs-host\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(serveDir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()

		serveCtx, serveCancel := context.WithCancel(ctx)
		serveSt, err := rs.client.OpenStream(serveCtx, control.MethodMountServe, control.MountServeRequest{
			Target: "/mnt/proxy",
			Label:  serveDir,
		})
		if err != nil {
			t.Fatalf("mount.serve open: %v", err)
		}
		if err := serveSt.WaitResponse(serveCtx, nil); err != nil {
			t.Fatalf("mount.serve wait: %v", err)
		}

		// Minimal in-test rpcfs server loop handling stat/read/create/write.
		loopDone := make(chan struct{})
		go func() {
			defer close(loopDone)
			for {
				ev, err := serveSt.RecvEvent(serveCtx)
				if err != nil {
					return
				}
				if ev.Type != "rpcfs.req" {
					continue
				}
				var r control.RPCFSRequest
				if json.Unmarshal(ev.Data, &r) != nil {
					continue
				}
				resp := handleTestRPCFS(root, r)
				_ = serveSt.SendEvent(serveCtx, "rpcfs.resp", resp)
			}
		}()

		// Read /mnt/proxy/host.txt inside the guest using exec /bin/cat.
		catSt, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv: []string{"/bin/cat", "/mnt/proxy/host.txt"},
		})
		if err != nil {
			t.Fatalf("exec cat proxy: %v", err)
		}
		if err := catSt.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec cat proxy wait: %v", err)
		}
		gotProxy, readErr := io.ReadAll(catSt.ChannelReader(ctx, control.ChannelStdout))
		catSt.Close()
		if readErr != nil || string(gotProxy) != "hello-from-rpcfs-host\n" {
			t.Fatalf("guest read from rpcfs = (%q, %v), want hello-from-rpcfs-host", gotProxy, readErr)
		}

		// Write /mnt/proxy/from_guest.txt from inside the guest.
		wrSt, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv: []string{"/bin/writeproxy"},
		})
		if err != nil {
			t.Fatalf("exec writeproxy: %v", err)
		}
		if err := wrSt.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec writeproxy wait: %v", err)
		}
		if _, err := wrSt.RecvEvent(ctx); err != nil {
			t.Fatalf("exec writeproxy exit event: %v", err)
		}
		wrSt.Close()

		hostWritten, err := os.ReadFile(filepath.Join(serveDir, "from_guest.txt"))
		if err != nil || string(hostWritten) != "written-via-rpcfs\n" {
			t.Fatalf("host file written by guest via rpcfs = (%q, %v)", hostWritten, err)
		}

		// Checkpoint while rpcfs is active must return BUSY.
		if err := rs.client.Call(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{LeaveRunning: true}, nil); !control.IsCode(err, control.CodeBusy) {
			t.Fatalf("checkpoint with active rpcfs err = %v, want BUSY", err)
		}

		serveCancel()
		serveSt.Cancel(nil)
		<-loopDone

		// Poll mount.list until /mnt/proxy is unmounted; fail if deadline expires.
		unmounted := false
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			var ml control.MountListResponse
			if err := rs.client.Call(ctx, control.MethodMountList, nil, &ml); err == nil {
				found := false
				for _, m := range ml.Mounts {
					if m.Target == "/mnt/proxy" {
						found = true
						break
					}
				}
				if !found {
					unmounted = true
					break
				}
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !unmounted {
			t.Fatal("/mnt/proxy was not unmounted within 5s after mount.serve stream closed")
		}
	}
}

func handleTestRPCFS(root *os.Root, req control.RPCFSRequest) control.RPCFSResponse {
	resp := control.RPCFSResponse{ID: req.ID}
	rel := strings.TrimPrefix(req.Path, "/")
	if rel == "" {
		rel = "."
	}
	switch req.Op {
	case "stat":
		fi, err := root.Lstat(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		mode := uint32(0o100000 | fi.Mode().Perm())
		if fi.IsDir() {
			mode = uint32(0o040000 | fi.Mode().Perm())
		}
		resp.Entry = &control.RPCFSEntry{Name: fi.Name(), Ino: 10, Mode: mode, Size: fi.Size(), Nlink: 1}
	case "read":
		f, err := root.Open(rel)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		buf := make([]byte, req.Length)
		n, err := f.ReadAt(buf, req.Offset)
		_ = f.Close()
		if err != nil && !errors.Is(err, io.EOF) {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		resp.Data = buf[:n]
	case "create":
		f, err := root.OpenFile(rel, os.O_CREATE|os.O_RDWR, 0o644)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		_ = f.Close()
		resp.Entry = &control.RPCFSEntry{Name: filepath.Base(rel), Ino: 20, Mode: 0o100644, Nlink: 1}
	case "write":
		f, err := root.OpenFile(rel, os.O_WRONLY, 0)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		n, err := f.WriteAt(req.Data, req.Offset)
		_ = f.Close()
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		resp.Written = int64(n)
	case "truncate":
		f, err := root.OpenFile(rel, os.O_WRONLY, 0)
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
			return resp
		}
		err = f.Truncate(req.Size)
		_ = f.Close()
		if err != nil {
			resp.Errno = control.HostErrorToLinuxErrno(err)
		}
	default:
		resp.Errno = control.LinuxEOPNOTSUPP
	}
	return resp
}

func TestControlResourceUpdateAndMultiSandboxIsolation(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	sbA := startControlTestSandbox(t, Config{
		Name:            "iso-a",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNAT,
		Resources:       Resources{MemoryBytes: 256 << 20, CPUMillis: 1000, PidsLimit: 100},
	})
	sbB := startControlTestSandbox(t, Config{
		Name:            "iso-b",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNAT,
		Resources:       Resources{MemoryBytes: 512 << 20, CPUMillis: 1000, PidsLimit: 200},
	})
	sbA.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	sbB.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()

	newMem := int64(384 << 20)
	newCPU := int64(500)
	newPids := int64(50)
	isoTrue := true
	var snapA control.ResourceSnapshot
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		MemoryBytes: &newMem,
		CPUMillis:   &newCPU,
		PidsLimit:   &newPids,
		IsolateLAN:  &isoTrue,
		Tuning:      map[string]string{"net.nat.dial_timeout": "5s"},
	}, &snapA); err != nil {
		t.Fatalf("update sbA: %v", err)
	}
	if snapA.MemoryBytes != newMem || snapA.CPUQuotaUSec != 50000 || snapA.PidsLimit != 50 || !snapA.IsolateLAN {
		t.Fatalf("snapA = %+v", snapA)
	}

	// Verify immutable tunable is rejected.
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		Tuning: map[string]string{"kernel.log_buf_len": "128KiB"},
	}, nil); !control.IsCode(err, control.CodeInvalidArgument) {
		t.Fatalf("immutable tunable err = %v, want INVALID_ARGUMENT", err)
	}

	// Verify memory limit below current usage returns LIMIT_EXCEEDED without ForceMemory.
	{
		// Allocate >7 MiB in guest tmpfs so Memory.TotalBytes exceeds the 6 MiB minimum.
		var fillTar bytes.Buffer
		twFill := tar.NewWriter(&fillTar)
		fillData := bytes.Repeat([]byte("M"), 7<<20)
		if err := twFill.WriteHeader(&tar.Header{Name: "memfill.bin", Mode: 0o644, Size: int64(len(fillData))}); err != nil {
			t.Fatal(err)
		}
		if _, err := twFill.Write(fillData); err != nil {
			t.Fatal(err)
		}
		if err := twFill.Close(); err != nil {
			t.Fatal(err)
		}
		fillSt, err := sbA.client.OpenStream(ctx, control.MethodFSImport, control.FSImportRequest{DestPath: "/tmp", Compress: true})
		if err != nil {
			t.Fatalf("fs.import memfill open: %v", err)
		}
		wFill := fillSt.ChannelWriter(ctx, control.ChannelGeneric, true)
		if _, err := wFill.Write(fillTar.Bytes()); err != nil {
			t.Fatalf("fs.import memfill write: %v", err)
		}
		if err := wFill.Close(); err != nil {
			t.Fatalf("fs.import memfill close: %v", err)
		}
		if err := fillSt.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("fs.import memfill resp: %v", err)
		}
		fillSt.Close()

		var curStats control.StatsSample
		if err := sbA.client.Call(ctx, control.MethodStats, control.StatsRequest{}, &curStats); err != nil {
			t.Fatalf("stats sbA: %v", err)
		}
		if curStats.Memory.TotalBytes <= 6<<20 {
			t.Fatalf("expected sbA TotalBytes > 6 MiB after 7 MiB tmpfs write, got %d", curStats.Memory.TotalBytes)
		}
		tooLow := int64(6 << 20)
		if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
			MemoryBytes: &tooLow,
		}, nil); !control.IsCode(err, control.CodeLimitExceeded) {
			t.Fatalf("memory below usage err = %v, want LIMIT_EXCEEDED", err)
		}
	}

	// Verify CPUQuotaUSec <= 0 (-1 and 0) clears the quota cleanly.
	clearNeg := int64(-1)
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		CPUQuotaUSec: &clearNeg,
	}, &snapA); err != nil || snapA.CPUQuotaUSec != 0 {
		t.Fatalf("update CPUQuotaUSec=-1 = (%+v, %v), want 0", snapA, err)
	}
	clearZero := int64(0)
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		CPUQuotaUSec: &clearZero,
	}, &snapA); err != nil || snapA.CPUQuotaUSec != 0 {
		t.Fatalf("update CPUQuotaUSec=0 = (%+v, %v), want 0", snapA, err)
	}

	// Verify Sandbox B is completely isolated from Sandbox A's updates.
	var inspectB control.InspectResponse
	if err := sbB.client.Call(ctx, control.MethodInspect, nil, &inspectB); err != nil {
		t.Fatalf("inspect sbB: %v", err)
	}
	if inspectB.Resources.MemoryBytes != 512<<20 || inspectB.Resources.CPUQuotaUSec != 100000 || inspectB.Resources.PidsLimit != 200 || inspectB.Resources.IsolateLAN {
		t.Fatalf("sbB limits leaked from sbA: %+v", inspectB.Resources)
	}
}

func TestControlCheckpointStreamAndRestoreRoundTrip(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	// Start WITHOUT CheckpointDir: streaming checkpoint works with zero pre-opened dir.
	rs := startControlTestSandbox(t, Config{
		Name:            "stream-ckpt",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()

	st, err := rs.client.OpenStream(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{
		LeaveRunning: false,
		Compress:     true,
	})
	if err != nil {
		t.Fatalf("checkpoint_stream open: %v", err)
	}
	var resp control.CheckpointStreamResponse
	if err := st.WaitResponse(ctx, &resp); err != nil {
		t.Fatalf("checkpoint_stream wait: %v", err)
	}
	bundleTar, err := io.ReadAll(st.ChannelReader(ctx, control.ChannelGeneric))
	st.Close()
	if err != nil {
		t.Fatalf("checkpoint_stream read: %v", err)
	}

	// Extract streamed bundle into a host directory and restore a fresh sandbox from it.
	bundleDir := t.TempDir()
	tr := tar.NewReader(bytes.NewReader(bundleTar))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("extract streamed tar: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %q: %v", hdr.Name, err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, filepath.Base(hdr.Name)), data, 0o600); err != nil {
			t.Fatalf("write bundle file %q: %v", hdr.Name, err)
		}
	}

	// Close the first sandbox completely before calling Restore so single-partition
	// hypervisors (such as Windows WHPX) release their partition first.
	_ = rs.client.Close()
	select {
	case <-rs.runDone:
	case <-time.After(15 * time.Second):
		t.Fatal("sandbox did not exit after checkpoint_stream with LeaveRunning=false")
	}
	if err := rs.sb.Close(); err != nil {
		t.Fatalf("close original sandbox before restore: %v", err)
	}

	var restoredOut bytes.Buffer
	restoredCfg := newCheckpointTestConfig(t, cacheDir)
	restoredCfg.OCIImage = imgRef
	restoredCfg.RegistryBaseURL = regURL
	restoredCfg.Stdin = strings.NewReader("after-stream-restore\n")
	restoredCfg.Stdout = &restoredOut
	restoredCfg.Stderr = io.Discard

	restoredSB, err := Restore(ctx, restoredCfg, RestoreOptions{Dir: bundleDir})
	if err != nil {
		t.Fatalf("gvx.Restore from streamed checkpoint: %v", err)
	}
	defer restoredSB.Close()

	code, err := restoredSB.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("restored sandbox Run = (code=%d, err=%v)", code, err)
	}
	if restoredOut.String() != "after-stream-restore\n" {
		t.Fatalf("restored stdout = %q, want after-stream-restore", restoredOut.String())
	}
}

func TestControlPolicyEnforcementAndPausedCancel(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	rs := startControlTestSandbox(t, Config{
		Name:            "policy-ro",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
		ControlPolicy:   control.PolicyReadOnly,
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()

	if err := rs.client.Call(ctx, control.MethodInspect, nil, nil); err != nil {
		t.Fatalf("inspect under readonly policy: %v", err)
	}
	if err := rs.client.Call(ctx, control.MethodKernelLog, control.KernelLogRequest{Tail: 5}, nil); err != nil {
		t.Fatalf("kernel.log read under readonly policy: %v", err)
	}
	if err := rs.client.Call(ctx, control.MethodKernelLog, control.KernelLogRequest{Clear: true}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("kernel.log clear under readonly policy = %v, want FORBIDDEN_BY_POLICY", err)
	}
	if err := rs.client.Call(ctx, control.MethodExecStart, control.ExecStartRequest{Argv: []string{"/bin/hello"}}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("exec under readonly policy = %v, want FORBIDDEN_BY_POLICY", err)
	}
	if err := rs.client.Call(ctx, control.MethodPause, control.PauseRequest{}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("pause under readonly policy = %v, want FORBIDDEN_BY_POLICY", err)
	}

	// Verify Pause directly followed by context cancellation never deadlocks Run().
	if err := rs.sb.Pause(ctx, true); err != nil {
		t.Fatalf("sb.Pause: %v", err)
	}
	rs.cancel()
	select {
	case <-rs.runDone:
	case <-time.After(10 * time.Second):
		t.Fatal("Sandbox.Run deadlocked when context was canceled while paused")
	}
}

func TestControlCheckpointStreamForceStopsActiveExec(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	rs := startControlTestSandbox(t, Config{
		Name:            "force-exec",
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()

	// Start a blocking exec session reading stdin.
	execSt, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
		Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
		Stdin: true,
	})
	if err != nil {
		t.Fatalf("exec open: %v", err)
	}
	defer execSt.Close()
	if err := execSt.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("exec wait: %v", err)
	}

	// Without Force, checkpoint_stream must fail with EXEC_ACTIVE.
	if err := rs.client.Call(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{
		LeaveRunning: true,
	}, nil); !control.IsCode(err, control.CodeExecActive) {
		t.Fatalf("checkpoint with active exec without Force = %v, want EXEC_ACTIVE", err)
	}

	// With Force=true, checkpoint_stream kills and drains the exec session cleanly.
	ckptSt, err := rs.client.OpenStream(ctx, control.MethodCheckpointStream, control.CheckpointStreamRequest{
		LeaveRunning: true,
		Force:        true,
	})
	if err != nil {
		t.Fatalf("checkpoint_stream Force open: %v", err)
	}
	if err := ckptSt.WaitResponse(ctx, nil); err != nil {
		t.Fatalf("checkpoint_stream Force resp: %v", err)
	}
	bundleTar, err := io.ReadAll(ckptSt.ChannelReader(ctx, control.ChannelGeneric))
	ckptSt.Close()
	if err != nil || len(bundleTar) == 0 {
		t.Fatalf("checkpoint_stream Force read = (%d bytes, %v)", len(bundleTar), err)
	}
}

func TestControlEarlyRPCBeforeRunDoesNotDeadlock(t *testing.T) {
	requireCheckpointGuestBackend(t)
	cacheDir, regURL, imgRef := buildControlTestImage(t)

	sockPath := shortControlSocketPath(t, "early.sock")
	ep, err := control.Listen(sockPath, control.ListenOptions{})
	if err != nil {
		t.Fatalf("control.Listen: %v", err)
	}
	t.Cleanup(ep.Cleanup)

	stdinR, stdinW := net.Pipe()
	stdout := newNotifyBuffer()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := Config{
		Name:                   "early-rpc",
		Platform:               PlatformAuto,
		AllowUnconfinedSystrap: runtime.GOOS == "windows",
		NetworkMode:            NetModeNone,
		OCIImage:               imgRef,
		OCICacheDir:            cacheDir,
		RegistryBaseURL:        regURL,
		DisableHostLockdown:    true,
		ControlListener:        ep.Listener,
		ControlToken:           ep.Token,
		Stdin:                  stdinR,
		Stdout:                 stdout,
		Stderr:                 io.Discard,
	}
	sb, err := New(ctx, cfg)
	if err != nil {
		_ = stdinR.Close()
		_ = stdinW.Close()
		_ = ep.Listener.Close()
		t.Fatalf("gvx.New: %v", err)
	}

	// Start ServeControl BEFORE calling sb.Run so early RPCs arrive while
	// kernelReady is still open.
	ctrlCtx, ctrlCancel := context.WithCancel(ctx)
	ctrlDone := make(chan struct{})
	go func() {
		defer close(ctrlDone)
		_ = sb.ServeControl(ctrlCtx)
	}()

	client, err := control.Dial(ctx, control.DialOptions{Endpoint: sockPath, Token: ep.Token})
	if err != nil {
		ctrlCancel()
		_ = sb.Close()
		<-ctrlDone
		t.Fatalf("control.Dial: %v", err)
	}

	runDone := make(chan struct{})
	t.Cleanup(func() {
		_ = client.Close()
		_ = stdinW.Close()
		cancel()
		drainCtx, drainCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = sb.ShutdownControl(drainCtx)
		drainCancel()
		ctrlCancel()
		<-ctrlDone
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Errorf("Sandbox.Run did not exit during cleanup")
		}
		_ = stdinR.Close()
		_ = sb.Close()
	})

	// Launch Pause and Exec RPCs BEFORE sb.Run starts; neither may deadlock
	// executeActiveKernel (AB-BA opMu vs kernelReady).
	pauseErrCh := make(chan error, 1)
	go func() {
		pauseErrCh <- client.Call(ctx, control.MethodPause, control.PauseRequest{}, nil)
	}()
	execErrCh := make(chan error, 1)
	go func() {
		st, err := client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{Argv: []string{"/bin/hello"}})
		if err != nil {
			execErrCh <- err
			return
		}
		defer st.Close()
		err = st.WaitResponse(ctx, nil)
		if err != nil {
			execErrCh <- err
			return
		}
		_, rErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		execErrCh <- rErr
	}()

	// Give early RPCs time to block on kernelReady before starting Run.
	time.Sleep(50 * time.Millisecond)

	go func() {
		defer close(runDone)
		_, _ = sb.Run(ctx)
	}()

	select {
	case err := <-pauseErrCh:
		if err != nil {
			t.Fatalf("early Pause RPC failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("early Pause RPC deadlocked with executeActiveKernel")
	}
	if err := client.Call(ctx, control.MethodUnpause, nil, nil); err != nil {
		t.Fatalf("Unpause after early Pause: %v", err)
	}
	select {
	case err := <-execErrCh:
		// Either exec ran before Pause (nil) or hit ALREADY_PAUSED after Pause;
		// either proves zero deadlock.
		if err != nil && !control.IsCode(err, control.CodeAlreadyPaused) {
			t.Fatalf("early Exec RPC unexpected error: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("early Exec RPC deadlocked with executeActiveKernel")
	}
}
