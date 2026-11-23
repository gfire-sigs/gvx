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
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

func shortControlSocketPath(t *testing.T, filename string) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gvx-t-")
	if err != nil {
		dir, err = os.MkdirTemp("", "gvxc-")
	}
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
	if rs.client.HasFeature(control.FeatureNetQoS) {
		t.Fatal("non-NAT sandbox advertises NAT bandwidth shaping")
	}
	if err := rs.client.Call(ctx, control.MethodResourceUpdate, json.RawMessage(`{"net_rx_bps":0}`), nil); !control.IsCode(err, control.CodeUnsupported) {
		t.Fatalf("raw bandwidth update in non-NAT mode = %v, want UNSUPPORTED", err)
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
		ControlDisable:  []string{control.CapResourceNetwork},
	})
	sbA.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	sbB.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	ctx := context.Background()
	if !sbA.client.HasFeature(control.FeatureNetQoS) || !sbB.client.HasFeature(control.FeatureNetQoS) {
		t.Fatal("HELLO must advertise network QoS support even when policy disables updates")
	}

	newMem := int64(384 << 20)
	newCPU := int64(500)
	newPids := int64(50)
	isoTrue := true
	newTX, newRX := uint64(800_000), uint64(400_000)
	var snapA control.ResourceSnapshot
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		MemoryBytes: &newMem,
		CPUMillis:   &newCPU,
		PidsLimit:   &newPids,
		IsolateLAN:  &isoTrue,
		NetTXBPS:    &newTX,
		NetRXBPS:    &newRX,
		Tuning:      map[string]string{"net.nat.dial_timeout": "5s"},
	}, &snapA); err != nil {
		t.Fatalf("update sbA: %v", err)
	}
	if snapA.MemoryBytes != newMem || snapA.CPUQuotaUSec != 50000 || snapA.PidsLimit != 50 || !snapA.IsolateLAN {
		t.Fatalf("snapA = %+v", snapA)
	}
	if snapA.NetTXBPS != newTX || snapA.NetRXBPS != newRX {
		t.Fatalf("updated bandwidth = TX %d RX %d, want TX %d RX %d", snapA.NetTXBPS, snapA.NetRXBPS, newTX, newRX)
	}

	clearTX := uint64(0)
	if err := sbA.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		NetTXBPS: &clearTX,
	}, &snapA); err != nil || snapA.NetTXBPS != 0 || snapA.NetRXBPS != newRX {
		t.Fatalf("clear TX bandwidth: TX %d RX %d, err %v, want TX 0 RX %d", snapA.NetTXBPS, snapA.NetRXBPS, err, newRX)
	}

	for _, raw := range []json.RawMessage{
		json.RawMessage(`{"memory_bytes":536870912,"net_rx_bps":-1}`),
		json.RawMessage(`{"memory_bytes":536870912,"net_rx_bps":1000000000001}`),
	} {
		if err := sbA.client.Call(ctx, control.MethodResourceUpdate, raw, nil); !control.IsCode(err, control.CodeInvalidArgument) {
			t.Errorf("update with invalid bandwidth %s returned %v, want INVALID_ARGUMENT", raw, err)
		}
	}
	var inspectA control.InspectResponse
	if err := sbA.client.Call(ctx, control.MethodInspect, nil, &inspectA); err != nil {
		t.Fatalf("inspect sbA after invalid updates: %v", err)
	}
	if res := inspectA.Resources; res.MemoryBytes != newMem || res.NetTXBPS != 0 || res.NetRXBPS != newRX {
		t.Fatalf("inspect sbA after invalid updates: memory %d, TX %d RX %d; want memory %d, TX 0 RX %d", res.MemoryBytes, res.NetTXBPS, res.NetRXBPS, newMem, newRX)
	}

	if err := sbB.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{
		MemoryBytes: &newMem,
		NetRXBPS:    &newRX,
	}, nil); !control.IsCode(err, control.CodeForbiddenByPolicy) {
		t.Fatalf("update when resource.network is disabled returned %v, want FORBIDDEN_BY_POLICY", err)
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
	if inspectB.Resources.NetTXBPS != 0 || inspectB.Resources.NetRXBPS != 0 {
		t.Fatalf("sbB bandwidth changed: TX %d RX %d, want both unlimited", inspectB.Resources.NetTXBPS, inspectB.Resources.NetRXBPS)
	}
}

func TestControlNATCustomInterceptorRetainsLANIsolationUpdates(t *testing.T) {
	cacheDir, regURL, imgRef := buildControlTestImage(t)
	rs := startControlTestSandbox(t, Config{
		OCIImage:        imgRef,
		OCICacheDir:     cacheDir,
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNAT,
		StreamInterceptor: func(context.Context, string, net.Conn, net.Conn) error {
			return errors.New("unexpected TCP relay")
		},
	})
	rs.stdout.waitForSubstring(t, "ready-marker\n", 15*time.Second)
	if rs.client.HasFeature(control.FeatureNetQoS) {
		t.Fatal("NAT with a custom interceptor advertises bandwidth shaping")
	}
	ctx := t.Context()
	if err := rs.client.Call(ctx, control.MethodResourceUpdate, json.RawMessage(`{"net_tx_bps":0}`), nil); !control.IsCode(err, control.CodeUnsupported) {
		t.Fatalf("bandwidth update with custom interceptor = %v, want UNSUPPORTED", err)
	}

	isolate := true
	var snapshot control.ResourceSnapshot
	if err := rs.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{IsolateLAN: &isolate}, &snapshot); err != nil || !snapshot.IsolateLAN {
		t.Fatalf("LAN isolation update with custom interceptor: isolate_lan=%t, err=%v", snapshot.IsolateLAN, err)
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

func TestMatchesEventFilters(t *testing.T) {
	evLifecycle := control.SandboxEvent{Type: "lifecycle", Action: "pause", Attributes: map[string]string{"quiesce_net": "true"}}
	evMount := control.SandboxEvent{Type: "mount", Action: "add", Attributes: map[string]string{"type": "tmpfs", "target": "/mnt/a"}}
	evExec := control.SandboxEvent{Type: "exec", Action: "start"}

	cases := []struct {
		name    string
		ev      control.SandboxEvent
		filters []string
		want    bool
	}{
		{"empty filters match all", evExec, nil, true},
		{"whitespace-only filter matches all", evExec, []string{"  "}, true},
		{"multiple same-key types OR match first", evLifecycle, []string{"type=lifecycle", "type=mount"}, true},
		{"multiple same-key types OR match second", evMount, []string{"type=lifecycle", "type=mount"}, true},
		{"multiple same-key types OR reject other", evExec, []string{"type=lifecycle", "type=mount"}, false},
		{"distinct keys AND match", evMount, []string{"type=mount", "action=add", "target=/mnt/a"}, true},
		{"distinct keys AND reject mismatch", evMount, []string{"type=mount", "action=remove"}, false},
		{"bare token with whitespace matches type", evLifecycle, []string{" lifecycle ", "mount"}, true},
		{"missing attribute fails", evLifecycle, []string{"target=/mnt/a"}, false},
		{"malformed empty key rejected", evLifecycle, []string{"=foo"}, false},
	}
	for _, tc := range cases {
		if got := matchesEventFilters(tc.ev, tc.filters); got != tc.want {
			t.Errorf("%s: matchesEventFilters(%+v, %v) = %v, want %v", tc.name, tc.ev, tc.filters, got, tc.want)
		}
	}
}

// TestControlExecTTYPermissionsPidsEventsDmesgAndPortRollback verifies the
// advanced control paths in one shared sandbox to minimize CI resource usage:
//   - exec TTY allocation (TERM=xterm, ONLCR echo), exec.resize, and exec.signal
//   - exec non-root users (nobody, 1000:1000) and --privileged=false cap drop
//   - real live pids.max enforcement (guest SYS_clone EAGAIN and exec LIMIT_EXCEEDED)
//   - proc.signal targeting a specific guest PID while PID 1 stays alive
//   - sandbox.events multi-type OR filtering and kernel.log follow + clear
//   - multi-spec port.add partial-failure rollback, replace=true, and --all-dynamic
func TestControlExecTTYPermissionsPidsEventsDmesgAndPortRollback(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	helloELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "exec-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64: %v", err)
	}
	forkELF, err := testelf.BuildGuestForkELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestForkELF64: %v", err)
	}

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/hello", Data: helloELF, Mode: 0o755},
		testimage.File{Name: "bin/fork", Data: forkELF, Mode: 0o755},
		testimage.File{Name: "etc/seed.txt", Data: []byte("adv-ready\n"), Mode: 0o644},
		testimage.File{Name: "etc/rootonly.txt", Data: []byte("secret-root\n"), Mode: 0o600},
		testimage.File{Name: "etc/passwd", Data: []byte("root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n"), Mode: 0o644},
		testimage.File{Name: "etc/group", Data: []byte("root:x:0:\nnogroup:x:65534:\n"), Mode: 0o644},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
		testimage.File{Name: "mnt/evtmp/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "advctrl", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/seed.txt", "/proc/self/fd/0"},
	})

	tv, err := (tuning.Values{}).Set("net.forward.max_dynamic_ports", "1")
	if err != nil {
		t.Fatalf("tuning.Set: %v", err)
	}
	rs := startControlTestSandbox(t, Config{
		Name:            "ctrl-adv",
		OCIImage:        "advctrl:latest",
		RegistryBaseURL: regURL,
		NetworkMode:     NetModeNAT,
		DynamicPorts:    true,
		Tuning:          tv,
		Resources:       Resources{PidsLimit: 16},
	})
	rs.stdout.waitForSubstring(t, "adv-ready\n", 15*time.Second)
	ctx := context.Background()

	runExec := func(req control.ExecStartRequest) (string, control.ExecExitEvent) {
		t.Helper()
		st, err := rs.client.OpenStream(ctx, control.MethodExecStart, req)
		if err != nil {
			t.Fatalf("exec %v open: %v", req.Argv, err)
		}
		defer st.Close()
		if err := st.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec %v wait: %v", req.Argv, err)
		}
		out, rErr := io.ReadAll(st.ChannelReader(ctx, control.ChannelStdout))
		ev, eErr := st.RecvEvent(ctx)
		if rErr != nil || eErr != nil || ev.Type != "exec.exit" {
			t.Fatalf("exec %v result: out=%q rErr=%v ev=%+v eErr=%v", req.Argv, out, rErr, ev, eErr)
		}
		var exitEv control.ExecExitEvent
		if err := json.Unmarshal(ev.Data, &exitEv); err != nil {
			t.Fatalf("exec %v decode exit: %v", req.Argv, err)
		}
		return string(out), exitEv
	}

	// 1. Exec TTY: TERM=xterm in environ, ONLCR echo, exec.resize, and exec.signal SIGINT (exit 130).
	{
		envOut, exitEv := runExec(control.ExecStartRequest{
			Argv: []string{"/bin/cat", "/proc/self/environ"},
			TTY:  true,
		})
		if exitEv.ExitCode != 0 || !strings.Contains(envOut, "TERM=xterm") {
			t.Fatalf("TTY exec environ = (code=%d, out=%q), want TERM=xterm", exitEv.ExitCode, envOut)
		}

		ttySt, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
			Stdin: true,
			TTY:   true,
			Rows:  24,
			Cols:  80,
		})
		if err != nil {
			t.Fatalf("exec TTY open: %v", err)
		}
		if err := ttySt.WaitResponse(ctx, nil); err != nil {
			ttySt.Close()
			t.Fatalf("exec TTY wait: %v", err)
		}
		if err := ttySt.SendEvent(ctx, "exec.resize", control.ExecResizeEvent{Rows: 40, Cols: 120}); err != nil {
			ttySt.Close()
			t.Fatalf("exec.resize: %v", err)
		}
		inW := ttySt.ChannelWriter(ctx, control.ChannelStdin, false)
		if _, err := io.WriteString(inW, "tty-hi\r"); err != nil {
			ttySt.Close()
			t.Fatalf("exec TTY write stdin: %v", err)
		}
		outR := ttySt.ChannelReader(ctx, control.ChannelStdout)
		buf := make([]byte, 256)
		var ttyOut strings.Builder
		readCtx, readCancel := context.WithTimeout(ctx, 5*time.Second)
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			for !strings.Contains(ttyOut.String(), "tty-hi\r\n") {
				n, err := outR.Read(buf)
				if n > 0 {
					ttyOut.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
		select {
		case <-readDone:
		case <-readCtx.Done():
			ttySt.Close()
			<-readDone
			t.Fatalf("timed out waiting for TTY echo, got %q", ttyOut.String())
		}
		readCancel()
		if !strings.Contains(ttyOut.String(), "tty-hi\r\n") {
			ttySt.Close()
			t.Fatalf("TTY stdout = %q, want ONLCR echo containing tty-hi\\r\\n", ttyOut.String())
		}

		if err := ttySt.SendEvent(ctx, "exec.signal", control.ExecSignalEvent{Signal: "SIGINT"}); err != nil {
			ttySt.Close()
			t.Fatalf("exec.signal SIGINT: %v", err)
		}
		ev, err := ttySt.RecvEvent(ctx)
		ttySt.Close()
		if err != nil || ev.Type != "exec.exit" {
			t.Fatalf("TTY exec exit after SIGINT = (%+v, %v), want exec.exit", ev, err)
		}
		var sigExit control.ExecExitEvent
		if err := json.Unmarshal(ev.Data, &sigExit); err != nil || sigExit.Signal != 2 || sigExit.ExitCode != 130 {
			t.Fatalf("TTY exec SIGINT exit = (%+v, %v), want Signal=2 ExitCode=130", sigExit, err)
		}
	}

	// 2. Exec non-root users (-u nobody, -u 1000:1000) and --privileged=false cap drop.
	{
		if out, exitEv := runExec(control.ExecStartRequest{Argv: []string{"/bin/cat", "/etc/rootonly.txt"}}); exitEv.ExitCode != 0 || out != "secret-root\n" {
			t.Fatalf("root cat /etc/rootonly.txt = (%q, %+v), want secret-root", out, exitEv)
		}
		privStatus, _ := runExec(control.ExecStartRequest{Argv: []string{"/bin/cat", "/proc/self/status"}})
		if strings.Contains(privStatus, "CapEff:\t0000000000000000") {
			t.Fatalf("default privileged root had empty CapEff:\n%s", privStatus)
		}

		dropPriv := false
		unprivStatus, exitEv := runExec(control.ExecStartRequest{
			Argv:       []string{"/bin/cat", "/proc/self/status"},
			Privileged: &dropPriv,
		})
		if exitEv.ExitCode != 0 ||
			!strings.Contains(unprivStatus, "CapEff:\t0000000000000000") ||
			!strings.Contains(unprivStatus, "CapPrm:\t0000000000000000") ||
			!strings.Contains(unprivStatus, "CapBnd:\t0000000000000000") {
			t.Fatalf("privileged=false status = (code=%d), want zero CapEff/CapPrm/CapBnd:\n%s", exitEv.ExitCode, unprivStatus)
		}

		if _, exitEv := runExec(control.ExecStartRequest{
			Argv: []string{"/bin/cat", "/etc/rootonly.txt"},
			User: "nobody",
		}); exitEv.ExitCode == 0 {
			t.Fatal("user=nobody read 0600 rootonly.txt, want EACCES non-zero exit")
		}
		nobodyStatus, exitEv := runExec(control.ExecStartRequest{
			Argv: []string{"/bin/cat", "/proc/self/status"},
			User: "nobody",
		})
		if exitEv.ExitCode != 0 || !strings.Contains(nobodyStatus, "Uid:\t65534\t") {
			t.Fatalf("user=nobody status = (code=%d), want Uid 65534:\n%s", exitEv.ExitCode, nobodyStatus)
		}

		numStatus, exitEv := runExec(control.ExecStartRequest{
			Argv: []string{"/bin/cat", "/proc/self/status"},
			User: "1000:1000",
		})
		if exitEv.ExitCode != 0 || !strings.Contains(numStatus, "Uid:\t1000\t") || !strings.Contains(numStatus, "Gid:\t1000\t") {
			t.Fatalf("user=1000:1000 status = (code=%d), want Uid/Gid 1000:\n%s", exitEv.ExitCode, numStatus)
		}
	}

	// 3. Real live pids.max enforcement (guest SYS_clone returns EAGAIN=11; exec returns LIMIT_EXCEEDED)
	// plus proc.signal targeting a specific exec PID while PID 1 remains alive.
	{
		if _, exitEv := runExec(control.ExecStartRequest{Argv: []string{"/bin/fork"}}); exitEv.ExitCode != 0 {
			t.Fatalf("initial /bin/fork with PidsLimit=16 exited %+v, want 0", exitEv)
		}

		cap2 := int64(2)
		if err := rs.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{PidsLimit: &cap2}, nil); err != nil {
			t.Fatalf("update PidsLimit=2: %v", err)
		}
		// PID 1 + /bin/fork occupy both slots; SYS_clone for the 3rd task must fail with EAGAIN (11).
		if _, exitEv := runExec(control.ExecStartRequest{Argv: []string{"/bin/fork"}}); exitEv.ExitCode != 11 {
			t.Fatalf("/bin/fork with PidsLimit=2 exited %+v, want exit code 11 (EAGAIN)", exitEv)
		}

		// Hold slot 2/2 with a blocking exec; a concurrent 2nd exec must fail with LIMIT_EXCEEDED.
		holdSt, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
			Stdin: true,
		})
		if err != nil {
			t.Fatalf("blocking exec open: %v", err)
		}
		var holdResp control.ExecStartResponse
		if err := holdSt.WaitResponse(ctx, &holdResp); err != nil {
			holdSt.Close()
			t.Fatalf("blocking exec wait: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodExecStart, control.ExecStartRequest{Argv: []string{"/bin/hello"}}, nil); !control.IsCode(err, control.CodeLimitExceeded) {
			holdSt.Close()
			t.Fatalf("exec at PidsLimit=2 err = %v, want LIMIT_EXCEEDED", err)
		}

		// proc.signal targeting holdResp.PID kills only the exec session; PID 1 stays alive.
		if err := rs.client.Call(ctx, control.MethodProcSignal, control.ProcSignalRequest{
			PID:    holdResp.PID,
			Signal: "SIGTERM",
		}, nil); err != nil {
			holdSt.Close()
			t.Fatalf("proc.signal PID %d: %v", holdResp.PID, err)
		}
		ev, err := holdSt.RecvEvent(ctx)
		holdSt.Close()
		var holdExit control.ExecExitEvent
		if err != nil || ev.Type != "exec.exit" || json.Unmarshal(ev.Data, &holdExit) != nil || holdExit.ExitCode != 143 {
			t.Fatalf("killed exec exit = (%+v, %+v, %v), want ExitCode=143 (SIGTERM)", ev, holdExit, err)
		}

		// Raising PidsLimit back to 16 immediately allows /bin/fork to succeed again.
		cap16 := int64(16)
		if err := rs.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{PidsLimit: &cap16}, nil); err != nil {
			t.Fatalf("update PidsLimit=16: %v", err)
		}
		if _, exitEv := runExec(control.ExecStartRequest{Argv: []string{"/bin/fork"}}); exitEv.ExitCode != 0 {
			t.Fatalf("/bin/fork after raising PidsLimit=16 exited %+v, want 0", exitEv)
		}
	}

	// 4. sandbox.events multi-type OR filtering + kernel.log follow & clear.
	func() {
		evCtx, evCancel := context.WithCancel(ctx)
		defer evCancel()
		evSt, err := rs.client.OpenStream(evCtx, control.MethodEvents, control.EventsRequest{
			Filters: []string{"type=lifecycle", "type=mount", "type=resource"},
		})
		if err != nil {
			t.Fatalf("events open: %v", err)
		}
		defer evSt.Close()
		if err := evSt.WaitResponse(evCtx, nil); err != nil {
			t.Fatalf("events wait: %v", err)
		}
		received := make(chan control.SandboxEvent, 16)
		evLoopDone := make(chan struct{})
		go func() {
			defer close(evLoopDone)
			for {
				ev, err := evSt.RecvEvent(evCtx)
				if err != nil {
					return
				}
				if ev.Type != "event" {
					continue
				}
				var se control.SandboxEvent
				if json.Unmarshal(ev.Data, &se) == nil {
					received <- se
				}
			}
		}()
		defer func() {
			evCancel()
			evSt.Close()
			<-evLoopDone
		}()

		// Trigger one filtered-out exec event, then 5 matching events.
		_, _ = runExec(control.ExecStartRequest{Argv: []string{"/bin/hello"}})
		if err := rs.client.Call(ctx, control.MethodPause, control.PauseRequest{}, nil); err != nil {
			t.Fatalf("pause for events: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodUnpause, nil, nil); err != nil {
			t.Fatalf("unpause for events: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodMountAdd, control.MountAddRequest{Type: "tmpfs", Target: "/mnt/evtmp"}, nil); err != nil {
			t.Fatalf("mount.add for events: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodMountRemove, control.MountRemoveRequest{Target: "/mnt/evtmp"}, nil); err != nil {
			t.Fatalf("mount.remove for events: %v", err)
		}
		cap32 := int64(32)
		if err := rs.client.Call(ctx, control.MethodResourceUpdate, control.ResourceUpdateRequest{PidsLimit: &cap32}, nil); err != nil {
			t.Fatalf("resource.update for events: %v", err)
		}

		wantSeq := []string{"lifecycle:pause", "lifecycle:unpause", "mount:add", "mount:remove", "resource:update"}
		for i, want := range wantSeq {
			select {
			case se := <-received:
				got := se.Type + ":" + se.Action
				if got != want {
					t.Fatalf("event[%d] = %q, want %q", i, got, want)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("timed out waiting for event[%d] %q", i, want)
			}
		}

		// kernel.log follow starts cleanly and cancels cleanly; clear empties the ring.
		fCtx, fCancel := context.WithCancel(ctx)
		fSt, err := rs.client.OpenStream(fCtx, control.MethodKernelLog, control.KernelLogRequest{Follow: true, Tail: 5})
		if err != nil {
			fCancel()
			t.Fatalf("kernel.log follow open: %v", err)
		}
		var initLog control.KernelLogResponse
		if err := fSt.WaitResponse(fCtx, &initLog); err != nil {
			fCancel()
			fSt.Close()
			t.Fatalf("kernel.log follow wait: %v", err)
		}
		fCancel()
		fSt.Close()

		var cleared control.KernelLogResponse
		if err := rs.client.Call(ctx, control.MethodKernelLog, control.KernelLogRequest{Clear: true}, &cleared); err != nil {
			t.Fatalf("kernel.log clear: %v", err)
		}
		var afterClear control.KernelLogResponse
		if err := rs.client.Call(ctx, control.MethodKernelLog, control.KernelLogRequest{}, &afterClear); err != nil {
			t.Fatalf("kernel.log after clear: %v", err)
		}
		if len(afterClear.Records) != 0 {
			t.Fatalf("kernel.log after clear returned %d records, want 0", len(afterClear.Records))
		}
	}()

	// 5. Multi-spec port.add partial-failure rollback, replace=true, and --all-dynamic.
	{
		// max_dynamic_ports=1: adding 2 specs must fail on the 2nd and roll back the 1st.
		if err := rs.client.Call(ctx, control.MethodPortAdd, control.PortAddRequest{
			Specs: []string{"127.0.0.1:0:8080", "127.0.0.1:0:8081"},
		}, nil); !control.IsCode(err, control.CodeLimitExceeded) {
			t.Fatalf("2-spec port.add with max=1 err = %v, want LIMIT_EXCEEDED", err)
		}
		var pl control.PortListResponse
		if err := rs.client.Call(ctx, control.MethodPortList, nil, &pl); err != nil {
			t.Fatalf("port.list after rollback: %v", err)
		}
		if len(pl.Ports) != 0 {
			t.Fatalf("port.list after failed batch = %+v, want empty (rolled back)", pl.Ports)
		}

		// Add 1 dynamic rule, replace it in place, then remove with AllDynamic.
		var addResp control.PortAddResponse
		if err := rs.client.Call(ctx, control.MethodPortAdd, control.PortAddRequest{
			Specs: []string{"127.0.0.1:0:8080"},
		}, &addResp); err != nil || len(addResp.Ports) != 1 {
			t.Fatalf("port.add single = (%+v, %v), want 1 port", addResp, err)
		}
		hp := addResp.Ports[0].HostPort

		var repResp control.PortAddResponse
		if err := rs.client.Call(ctx, control.MethodPortAdd, control.PortAddRequest{
			Specs:   []string{"127.0.0.1:" + strconv.Itoa(int(hp)) + ":9090"},
			Replace: true,
		}, &repResp); err != nil || len(repResp.Ports) != 1 || repResp.Ports[0].GuestPort != 9090 {
			t.Fatalf("port.add replace = (%+v, %v), want GuestPort=9090", repResp, err)
		}

		var rmResp control.PortRemoveResponse
		if err := rs.client.Call(ctx, control.MethodPortRemove, control.PortRemoveRequest{AllDynamic: true}, &rmResp); err != nil || len(rmResp.Removed) != 1 {
			t.Fatalf("port.remove all_dynamic = (%+v, %v), want 1 removed", rmResp, err)
		}
		if err := rs.client.Call(ctx, control.MethodPortList, nil, &pl); err != nil || len(pl.Ports) != 0 {
			t.Fatalf("port.list after all_dynamic = (%+v, %v), want empty", pl, err)
		}
	}

	// 6. proc.signal with All=true terminates both an active exec session and PID 1.
	{
		allExec, err := rs.client.OpenStream(ctx, control.MethodExecStart, control.ExecStartRequest{
			Argv:  []string{"/bin/cat", "/proc/self/fd/0"},
			Stdin: true,
		})
		if err != nil {
			t.Fatalf("exec for kill --all open: %v", err)
		}
		defer allExec.Close()
		if err := allExec.WaitResponse(ctx, nil); err != nil {
			t.Fatalf("exec for kill --all wait: %v", err)
		}
		if err := rs.client.Call(ctx, control.MethodProcSignal, control.ProcSignalRequest{
			All:    true,
			Signal: "SIGKILL",
		}, nil); err != nil {
			t.Fatalf("proc.signal all SIGKILL: %v", err)
		}
		select {
		case <-rs.runDone:
		case <-time.After(10 * time.Second):
			t.Fatal("sandbox did not exit after proc.signal(all=true, SIGKILL)")
		}
	}
}
