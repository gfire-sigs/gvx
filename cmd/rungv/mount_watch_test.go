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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestServeRPCFSReaddirPaginationRespectsFrameBudget(t *testing.T) {
	dir := t.TempDir()
	const totalFiles = 250
	for i := range totalFiles {
		name := fmt.Sprintf("file-%04d-padding-name.txt", i)
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	const maxEventBytes = 4096
	cfg := rpcfsServeConfig{
		root:          root,
		maxReadBytes:  4096,
		maxEventBytes: maxEventBytes,
	}

	var (
		got    []string
		offset int64
		pages  int
	)
	for {
		pages++
		if pages > 100 {
			t.Fatalf("pagination did not terminate after %d pages", pages)
		}
		resp := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{
			ID:     uint64(pages),
			Op:     "readdir",
			Path:   ".",
			Offset: offset,
		})
		if resp.Errno != 0 {
			t.Fatalf("page %d errno = %d (%s)", pages, resp.Errno, resp.Error)
		}
		raw, err := json.Marshal(control.EventEnvelope{Type: "rpcfs.resp", Data: mustMarshalJSON(t, resp)})
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > maxEventBytes+256 {
			t.Fatalf("page %d marshaled frame = %d bytes, exceeds budget %d", pages, len(raw), maxEventBytes+256)
		}
		for _, e := range resp.Entries {
			got = append(got, e.Name)
		}
		if !resp.HasMore {
			break
		}
		if resp.NextOffset <= offset {
			t.Fatalf("non-advancing NextOffset = %d (prev %d)", resp.NextOffset, offset)
		}
		offset = resp.NextOffset
	}
	if pages < 2 {
		t.Fatalf("expected multi-page readdir, got %d page", pages)
	}
	if len(got) != totalFiles {
		t.Fatalf("collected %d entries, want %d", len(got), totalFiles)
	}
	for i := range totalFiles {
		want := fmt.Sprintf("file-%04d-padding-name.txt", i)
		if got[i] != want {
			t.Fatalf("entry[%d] = %q, want %q", i, got[i], want)
		}
	}
}

func mustMarshalJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestServeRPCFSSingleFileConfinement(t *testing.T) {
	dir := t.TempDir()
	targetPath := filepath.Join(dir, "app.yml")
	siblingPath := filepath.Join(dir, "secret.yml")
	if err := os.WriteFile(targetPath, []byte("port: 8080\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(siblingPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	root, singleFile, leafName, err := openRPCFSServeRoot(targetPath)
	if err != nil {
		t.Fatalf("openRPCFSServeRoot: %v", err)
	}
	defer root.Close()
	if !singleFile || leafName != "app.yml" {
		t.Fatalf("openRPCFSServeRoot = (singleFile=%v, leaf=%q), want (true, app.yml)", singleFile, leafName)
	}

	cfg := rpcfsServeConfig{
		root:          root,
		singleFile:    singleFile,
		leafName:      leafName,
		maxReadBytes:  64 << 10,
		maxEventBytes: 64 << 10,
	}

	// Sibling file in the parent directory must never be readable or statable.
	for _, op := range []string{"stat", "read", "write", "unlink"} {
		resp := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{
			ID:     1,
			Op:     op,
			Path:   "secret.yml",
			Length: 64,
			Data:   []byte("nope"),
		})
		if resp.Errno != control.LinuxENOTDIR {
			t.Fatalf("single-file %s on sibling = errno %d, want ENOTDIR (%d)", op, resp.Errno, control.LinuxENOTDIR)
		}
	}

	// Root "." maps to app.yml for stat, read, write, and truncate.
	st := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{ID: 2, Op: "stat", Path: "."})
	if st.Errno != 0 || st.Entry == nil || st.Entry.Ino != 1 || st.Entry.Mode&control.LinuxSIFMT != control.LinuxSIFREG {
		t.Fatalf("single-file stat = %+v, want regular file Ino=1", st)
	}
	rd := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{ID: 3, Op: "read", Path: ".", Offset: 0, Length: 64})
	if rd.Errno != 0 || string(rd.Data) != "port: 8080\n" || !rd.EOF {
		t.Fatalf("single-file read = (%q, errno=%d, eof=%v)", rd.Data, rd.Errno, rd.EOF)
	}
	wr := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{ID: 4, Op: "write", Path: ".", Offset: 0, Data: []byte("port: 9090\n")})
	if wr.Errno != 0 || wr.Written != 11 {
		t.Fatalf("single-file write = %+v", wr)
	}
	if data, err := os.ReadFile(targetPath); err != nil || string(data) != "port: 9090\n" {
		t.Fatalf("host app.yml = (%q, %v), want port: 9090", data, err)
	}
	// Directory/unlink operations on root must fail with ENOTDIR / EBUSY.
	if r := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{ID: 5, Op: "readdir", Path: "."}); r.Errno != control.LinuxENOTDIR {
		t.Fatalf("single-file readdir = %d, want ENOTDIR", r.Errno)
	}
	if r := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{ID: 6, Op: "unlink", Path: "."}); r.Errno != control.LinuxEBUSY {
		t.Fatalf("single-file unlink = %d, want EBUSY", r.Errno)
	}
}

func TestRPCFSHostWatcherDetectsHostChangesAndSuppressesGuestEchoes(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "one.txt")
	if err := os.WriteFile(filePath, []byte("hello\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	var (
		mu     sync.Mutex
		events []control.RPCFSNotifyEvent
		notify = make(chan control.RPCFSNotifyEvent, 32)
	)
	w := newRPCFSHostWatcher(root, false, "", 15*time.Millisecond, 16, func(ev control.RPCFSNotifyEvent) {
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
		select {
		case notify <- ev:
		default:
		}
	})
	defer w.Close()

	if errno := w.Add("one.txt"); errno != 0 {
		t.Fatalf("Add(one.txt) = %d", errno)
	}
	if errno := w.Add("."); errno != 0 {
		t.Fatalf("Add(.) = %d", errno)
	}

	waitEvent := func(desc string, match func(control.RPCFSNotifyEvent) bool) {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case ev := <-notify:
				if match(ev) {
					return
				}
			case <-deadline:
				mu.Lock()
				snapshot := append([]control.RPCFSNotifyEvent(nil), events...)
				mu.Unlock()
				t.Fatalf("timed out waiting for %s; saw %+v", desc, snapshot)
			}
		}
	}

	// 1. Host edit triggers IN_MODIFY on both watched file and watched parent directory.
	if err := os.WriteFile(filePath, []byte("edited-on-host\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitEvent("file IN_MODIFY", func(ev control.RPCFSNotifyEvent) bool {
		return ev.Path == "one.txt" && ev.Name == "" && ev.Mask&control.LinuxInModify != 0
	})

	// 2. Host create and delete in watched directory emit IN_CREATE and IN_DELETE.
	createdPath := filepath.Join(dir, "added.txt")
	if err := os.WriteFile(createdPath, []byte("new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	waitEvent("dir IN_CREATE added.txt", func(ev control.RPCFSNotifyEvent) bool {
		return ev.Path == "." && ev.Name == "added.txt" && ev.Mask&control.LinuxInCreate != 0
	})
	if err := os.Remove(createdPath); err != nil {
		t.Fatal(err)
	}
	waitEvent("dir IN_DELETE added.txt", func(ev control.RPCFSNotifyEvent) bool {
		return ev.Path == "." && ev.Name == "added.txt" && ev.Mask&control.LinuxInDelete != 0
	})

	// 3. Host rename within watched directory emits paired IN_MOVED_FROM / IN_MOVED_TO on Unix.
	if runtime.GOOS != "windows" {
		src := filepath.Join(dir, "move-a.txt")
		dst := filepath.Join(dir, "move-b.txt")
		if err := os.WriteFile(src, []byte("move-data"), 0o600); err != nil {
			t.Fatal(err)
		}
		waitEvent("dir IN_CREATE move-a.txt", func(ev control.RPCFSNotifyEvent) bool {
			return ev.Path == "." && ev.Name == "move-a.txt" && ev.Mask&control.LinuxInCreate != 0
		})
		if err := os.Rename(src, dst); err != nil {
			t.Fatal(err)
		}
		var fromCookie uint32
		waitEvent("dir IN_MOVED_FROM move-a.txt", func(ev control.RPCFSNotifyEvent) bool {
			if ev.Path == "." && ev.Name == "move-a.txt" && ev.Mask&control.LinuxInMovedFrom != 0 && ev.Cookie != 0 {
				fromCookie = ev.Cookie
				return true
			}
			return false
		})
		waitEvent("dir IN_MOVED_TO move-b.txt", func(ev control.RPCFSNotifyEvent) bool {
			return ev.Path == "." && ev.Name == "move-b.txt" && ev.Mask&control.LinuxInMovedTo != 0 && ev.Cookie == fromCookie
		})
	}

	// 4. Guest mutation wrapped in BeginMutation/EndMutation produces no host echo.
	for len(notify) > 0 {
		<-notify
	}
	cfg := rpcfsServeConfig{root: root, maxReadBytes: 4096, maxEventBytes: 4096, watcher: w}
	wr := serveRPCFSRequestWithConfig(cfg, control.RPCFSRequest{
		ID:     10,
		Op:     "write",
		Path:   "one.txt",
		Offset: 0,
		Data:   []byte("guest-wrote-this-longer-payload\n"),
	})
	if wr.Errno != 0 {
		t.Fatalf("guest write errno = %d", wr.Errno)
	}
	select {
	case ev := <-notify:
		if ev.Path == "one.txt" || (ev.Path == "." && ev.Name == "one.txt") {
			t.Fatalf("unexpected echo notification after guest write: %+v", ev)
		}
	case <-time.After(80 * time.Millisecond):
	}

	// 5. Watch cap enforces ENOSPC.
	capped := newRPCFSHostWatcher(root, false, "", time.Hour, 1, nil)
	defer capped.Close()
	if errno := capped.Add("."); errno != 0 {
		t.Fatalf("capped Add(.) = %d", errno)
	}
	if errno := capped.Add("one.txt"); errno != control.LinuxENOSPC {
		t.Fatalf("capped Add(one.txt) = %d, want ENOSPC (%d)", errno, control.LinuxENOSPC)
	}
}

func TestSendRPCFSResponseOversizedFallsBackToEIOAndKeepsStreamAlive(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const smallMaxFrame = 4096
	received := make(chan control.RPCFSResponse, 4)
	srv := control.NewServer(ln, control.ServerConfig{
		SandboxID:     "test-oversized",
		Token:         "tok",
		Capabilities:  []string{control.CapMountServe},
		MaxFrameBytes: smallMaxFrame,
		Handler: &testOversizedHandler{
			onStream: func(ctx context.Context, st *control.Stream) error {
				if err := st.SendResponse(control.MountServeResponse{Target: "/mnt"}); err != nil {
					return err
				}
				for range 2 {
					ev, err := st.RecvEvent(ctx)
					if err != nil {
						return err
					}
					var resp control.RPCFSResponse
					if err := json.Unmarshal(ev.Data, &resp); err != nil {
						return err
					}
					received <- resp
				}
				return nil
			},
		},
	})
	srvCtx, srvCancel := context.WithCancel(context.Background())
	defer srvCancel()
	go func() { _ = srv.Serve(srvCtx) }()
	defer srv.Close()

	cli, err := control.Dial(context.Background(), control.DialOptions{
		Endpoint: "tcp://" + ln.Addr().String(),
		Token:    "tok",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer cli.Close()

	st, err := cli.OpenStream(context.Background(), control.MethodMountServe, control.MountServeRequest{Target: "/mnt"})
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	defer st.Close()
	if err := st.WaitResponse(context.Background(), nil); err != nil {
		t.Fatalf("WaitResponse: %v", err)
	}

	// Send an oversized response first; sendRPCFSResponse must degrade it to EIO without closing the stream.
	huge := control.RPCFSResponse{ID: 1, Data: []byte(strings.Repeat("A", smallMaxFrame*2))}
	if err := sendRPCFSResponse(context.Background(), st, huge); err != nil {
		t.Fatalf("sendRPCFSResponse(huge): %v", err)
	}
	// A follow-up normal response on the same stream must still succeed.
	okResp := control.RPCFSResponse{ID: 2, Data: []byte("still-alive")}
	if err := sendRPCFSResponse(context.Background(), st, okResp); err != nil {
		t.Fatalf("sendRPCFSResponse(ok): %v", err)
	}

	first := <-received
	if first.ID != 1 || first.Errno != control.LinuxEIO {
		t.Fatalf("first response = %+v, want ID=1 Errno=EIO", first)
	}
	second := <-received
	if second.ID != 2 || second.Errno != 0 || string(second.Data) != "still-alive" {
		t.Fatalf("second response = %+v, want ID=2 still-alive", second)
	}
}

type testOversizedHandler struct {
	onStream func(ctx context.Context, st *control.Stream) error
}

func (h *testOversizedHandler) HandleStream(ctx context.Context, st *control.Stream, _ control.RequestEnvelope, _ []int) error {
	return h.onStream(ctx, st)
}

func (h *testOversizedHandler) HandleLegacyCheckpoint(context.Context, control.LegacyCheckpointRequest) error {
	return nil
}

const rpcfsProbeGuestSource = `package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "usage: probe <sendfile|readdir|watch> <path>")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "sendfile":
		in, err := os.Open(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer in.Close()
		pr, pw, err := os.Pipe()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		h := sha256.New()
		var total int64
		done := make(chan error, 1)
		go func() {
			buf := make([]byte, 128<<10)
			for {
				n, rerr := pr.Read(buf)
				if n > 0 {
					h.Write(buf[:n])
					total += int64(n)
				}
				if rerr != nil {
					done <- nil
					return
				}
			}
		}()
		for {
			n, serr := syscall.Sendfile(int(pw.Fd()), int(in.Fd()), nil, 1<<20)
			if serr != nil {
				fmt.Fprintln(os.Stderr, serr)
				os.Exit(1)
			}
			if n == 0 {
				break
			}
		}
		_ = pw.Close()
		<-done
		_ = pr.Close()
		fmt.Printf("BYTES=%d SHA256=%s\n", total, hex.EncodeToString(h.Sum(nil)))

	case "readdir":
		des, err := os.ReadDir(os.Args[2])
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		first, last := "", ""
		if len(des) > 0 {
			first = des[0].Name()
			last = des[len(des)-1].Name()
		}
		fmt.Printf("COUNT=%d FIRST=%s LAST=%s\n", len(des), first, last)

	case "watch":
		fd, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		defer syscall.Close(fd)
		const mask = syscall.IN_MODIFY | syscall.IN_ATTRIB | syscall.IN_CREATE | syscall.IN_DELETE | syscall.IN_MOVED_FROM | syscall.IN_MOVED_TO | syscall.IN_DELETE_SELF
		if _, err := syscall.InotifyAddWatch(fd, os.Args[2], mask); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Println("WATCH_READY")
		buf := make([]byte, 4096)
		n, err := syscall.Read(fd, buf)
		if err != nil || n < 16 {
			fmt.Fprintf(os.Stderr, "inotify read=(%d, %v)\n", n, err)
			os.Exit(1)
		}
		evMask := binary.LittleEndian.Uint32(buf[4:8])
		nameLen := binary.LittleEndian.Uint32(buf[12:16])
		name := ""
		if nameLen > 0 && int(16+nameLen) <= n {
			name = strings.TrimRight(string(buf[16:16+nameLen]), "\x00")
		}
		fmt.Printf("EVENT mask=0x%x name=%s\n", evMask, name)

	default:
		fmt.Fprintln(os.Stderr, "unknown subcommand")
		os.Exit(2)
	}
}
`

func buildRPCFSProbeLinuxELF(t *testing.T) []byte {
	t.Helper()
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module rpcfsprobe\n\ngo 1.24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(rpcfsProbeGuestSource), 0o600); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(srcDir, "probe")
	cmd := exec.Command("go", "build", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build rpcfs linux probe: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestMountServeEndToEndSendfileReaddirInotifyAndSingleFile(t *testing.T) {
	platform := requireCheckpointCLIPlatform(t)

	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64: %v", err)
	}
	probeELF := buildRPCFSProbeLinuxELF(t)

	layer, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "bin/probe", Data: probeELF, Mode: 0o755},
		testimage.File{Name: "etc/ready.txt", Data: []byte("rpcfs-e2e-ready\n"), Mode: 0o644},
		testimage.File{Name: "mnt/", Type: tar.TypeDir, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	regURL := testimage.NewRegistry(t, "rpcfse2e", "latest", testimage.Image{
		Arch:       runtime.GOARCH,
		Layers:     [][]byte{layer},
		Entrypoint: []string{"/bin/cat"},
		Cmd:        []string{"/etc/ready.txt", "/proc/self/fd/0"},
	})

	cacheDir := t.TempDir()
	sockPath := filepath.Join(shortSocketDir(t), "rpcfs.sock")
	stdinR, stdinW := net.Pipe()
	t.Cleanup(func() {
		_ = stdinW.Close()
		_ = stdinR.Close()
	})
	stdout := newSyncNotifyBuffer()
	stderr := newSyncNotifyBuffer()

	runCtx, runCancel := context.WithCancel(context.Background())
	runDone := make(chan int, 1)
	go func() {
		runDone <- executeCLI(runCtx, []string{
			"run",
			"-lockdown=false",
			"-platform=" + platform,
			"-net=none",
			"-cache-dir=" + cacheDir,
			"-registry-url=" + regURL,
			"-S", sockPath,
			"rpcfse2e:latest",
		}, stdinR, stdout, stderr)
	}()
	t.Cleanup(func() {
		_ = stdinW.Close()
		runCancel()
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Errorf("sandbox goroutine did not exit within 10s")
		}
	})
	stdout.waitForSubstring(t, "rpcfs-e2e-ready\n", 15*time.Second)

	// Prepare host directory: 2,000 small files, a 2 MiB binary file, and a watched file.
	hostDir := t.TempDir()
	manyDir := filepath.Join(hostDir, "many")
	if err := os.MkdirAll(manyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	const manyCount = 2000
	for i := range manyCount {
		p := filepath.Join(manyDir, fmt.Sprintf("f%04d.txt", i))
		if err := os.WriteFile(p, []byte("ok\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	blob := bytes.Repeat([]byte("abcdefghijklmnopqrstuvwxyz012345"), 64<<10) // 2 MiB
	blobSum := sha256.Sum256(blob)
	if err := os.WriteFile(filepath.Join(hostDir, "mid.bin"), blob, 0o600); err != nil {
		t.Fatal(err)
	}
	onePath := filepath.Join(hostDir, "one.txt")
	if err := os.WriteFile(onePath, []byte("initial\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Start directory mount serve with default 256 KiB max_frame_bytes.
	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveOut := newSyncNotifyBuffer()
	serveErr := newSyncNotifyBuffer()
	serveDone := make(chan int, 1)
	go func() {
		serveDone <- executeCLI(serveCtx, []string{"mount", "serve", "-S", sockPath, hostDir + ":/mnt/proj"}, nil, serveOut, serveErr)
	}()
	var serveJoined atomic.Bool
	t.Cleanup(func() {
		serveCancel()
		if !serveJoined.Load() {
			<-serveDone
		}
	})
	serveOut.waitForSubstring(t, "Serving ", 10*time.Second)

	runExec := func(args ...string) (int, string, string) {
		var outB, errB bytes.Buffer
		full := append([]string{"exec", "-S", sockPath, "--"}, args...)
		code := executeCLI(context.Background(), full, nil, &outB, &errB)
		return code, outB.String(), errB.String()
	}

	// 1. 2,000-entry readdir succeeds with default 256 KiB max_frame_bytes and keeps mount alive.
	if code, out, errS := runExec("/bin/probe", "readdir", "/mnt/proj/many"); code != 0 || !strings.Contains(out, "COUNT=2000 FIRST=f0000.txt LAST=f1999.txt") {
		t.Fatalf("readdir 2000 entries = (%d, %q, %q, serveErr=%q)", code, out, errS, serveErr.String())
	}

	// 2. sendfile(2) of 2 MiB file completes cleanly with exact bytes and SHA-256 (no EOF stall).
	wantSF := fmt.Sprintf("BYTES=%d SHA256=%s", len(blob), hex.EncodeToString(blobSum[:]))
	if code, out, errS := runExec("/bin/probe", "sendfile", "/mnt/proj/mid.bin"); code != 0 || !strings.Contains(out, wantSF) {
		t.Fatalf("sendfile 2MiB = (%d, %q, %q), want %q", code, out, errS, wantSF)
	}

	// 3. Host edit reaches guest inotify watcher on /mnt/proj/one.txt.
	{
		watchOut := newSyncNotifyBuffer()
		watchErr := newSyncNotifyBuffer()
		watchDone := make(chan int, 1)
		go func() {
			watchDone <- executeCLI(context.Background(), []string{"exec", "-S", sockPath, "--", "/bin/probe", "watch", "/mnt/proj/one.txt"}, nil, watchOut, watchErr)
		}()
		watchOut.waitForSubstring(t, "WATCH_READY\n", 10*time.Second)
		if err := os.WriteFile(onePath, []byte("edited-on-host\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-watchDone:
			if code != 0 || !strings.Contains(watchOut.String(), "EVENT mask=0x2 ") {
				t.Fatalf("file inotify watch = (%d, %q, %q), want IN_MODIFY (0x2)", code, watchOut.String(), watchErr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for file inotify event (out=%q err=%q)", watchOut.String(), watchErr.String())
		}
	}

	// 4. Single-file mount serve supports sendfile read and host-change inotify.
	singleHost := filepath.Join(t.TempDir(), "config.yml")
	singleContent := []byte("mode: production\n")
	singleSum := sha256.Sum256(singleContent)
	if err := os.WriteFile(singleHost, singleContent, 0o600); err != nil {
		t.Fatal(err)
	}
	singleCtx, singleCancel := context.WithCancel(context.Background())
	singleOut := newSyncNotifyBuffer()
	singleErr := newSyncNotifyBuffer()
	singleDone := make(chan int, 1)
	go func() {
		singleDone <- executeCLI(singleCtx, []string{"mount", "serve", "-S", sockPath, singleHost + ":/mnt/config.yml"}, nil, singleOut, singleErr)
	}()
	var singleJoined atomic.Bool
	t.Cleanup(func() {
		singleCancel()
		if !singleJoined.Load() {
			<-singleDone
		}
	})
	singleOut.waitForSubstring(t, "Serving ", 10*time.Second)

	wantSingle := fmt.Sprintf("BYTES=%d SHA256=%s", len(singleContent), hex.EncodeToString(singleSum[:]))
	if code, out, errS := runExec("/bin/probe", "sendfile", "/mnt/config.yml"); code != 0 || !strings.Contains(out, wantSingle) {
		t.Fatalf("single-file sendfile = (%d, %q, %q), want %q", code, out, errS, wantSingle)
	}

	{
		watchOut := newSyncNotifyBuffer()
		watchErr := newSyncNotifyBuffer()
		watchDone := make(chan int, 1)
		go func() {
			watchDone <- executeCLI(context.Background(), []string{"exec", "-S", sockPath, "--", "/bin/probe", "watch", "/mnt/config.yml"}, nil, watchOut, watchErr)
		}()
		watchOut.waitForSubstring(t, "WATCH_READY\n", 10*time.Second)
		if err := os.WriteFile(singleHost, []byte("mode: updated\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		select {
		case code := <-watchDone:
			if code != 0 || !strings.Contains(watchOut.String(), "EVENT mask=0x2 ") {
				t.Fatalf("single-file inotify watch = (%d, %q, %q), want IN_MODIFY (0x2)", code, watchOut.String(), watchErr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("timed out waiting for single-file inotify event (out=%q err=%q)", watchOut.String(), watchErr.String())
		}
	}

	singleCancel()
	<-singleDone
	singleJoined.Store(true)
	serveCancel()
	<-serveDone
	serveJoined.Store(true)
}
