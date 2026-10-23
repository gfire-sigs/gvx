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

//go:build darwin || windows

package gvx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

// hostTestConfig returns a Config for in-process tests. The default host
// lockdown would confine the whole test binary, so these tests disable it.
// The e2e suite covers the lockdown in child processes.
func hostTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Platform:            PlatformAuto,
		NetworkMode:         NetModeNone,
		OCICacheDir:         t.TempDir(),
		DisableHostLockdown: true,
	}
}

func runConfig(t *testing.T, cfg Config) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	cfg.Stdout = &outBuf
	cfg.Stderr = &errBuf
	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	}()
	code, err = sb.Run(context.Background())
	if err != nil {
		t.Fatalf("Run() failed: %v (stderr=%q)", err, errBuf.String())
	}
	return code, outBuf.String(), errBuf.String()
}

func TestSandboxRunStaticAndDynamicELF64(t *testing.T) {
	staticELF, err := testelf.BuildGuestELF64At(runtime.GOARCH, staticBase(), 0, "hello-static-elf64\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	cfg := hostTestConfig(t)
	cfg.ELFBytes = staticELF
	code, stdout, stderr := runConfig(t, cfg)
	if code != 0 || stdout != "hello-static-elf64\n" {
		t.Fatalf("static ELF = (%d, %q, stderr=%q), want (0, %q)", code, stdout, stderr, "hello-static-elf64\n")
	}

	dynamicELF, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 42, "hello-dynamic-pie\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}
	cfg = hostTestConfig(t)
	cfg.ELFBytes = dynamicELF
	code, stdout, stderr = runConfig(t, cfg)
	if code != 42 || stdout != "hello-dynamic-pie\n" {
		t.Fatalf("dynamic ELF = (%d, %q, stderr=%q), want (42, %q)", code, stdout, stderr, "hello-dynamic-pie\n")
	}
}

func TestSandboxReportsPlatformName(t *testing.T) {
	hvtest.Require(t)
	want := "hvf"
	if runtime.GOOS == "windows" {
		want = "whpx"
	}
	for _, plat := range []PlatformType{PlatformAuto, PlatformType(want)} {
		cfg := hostTestConfig(t)
		cfg.Platform = plat
		sb, err := New(context.Background(), cfg)
		if err != nil {
			t.Fatalf("New(%s) failed: %v", plat, err)
		}
		if got := sb.PlatformName(); got != want {
			t.Errorf("PlatformName() with -platform=%s = %q, want %q", plat, got, want)
		}
		if st := sb.LockdownStatus(); st.Applied {
			t.Errorf("LockdownStatus().Applied = true with DisableHostLockdown")
		}
		if err := sb.Close(); err != nil {
			t.Errorf("Close() failed: %v", err)
		}
	}
}

func TestSandboxRejectsELFOfOtherArchitecture(t *testing.T) {
	foreignELF, err := testelf.BuildGuestELF64(otherArch(), 0, "x")
	if err != nil {
		t.Fatalf("BuildGuestELF64(%s) failed: %v", otherArch(), err)
	}
	cfg := hostTestConfig(t)
	cfg.ELFBytes = foreignELF
	if _, err := New(context.Background(), cfg); err == nil || !strings.Contains(err.Error(), "architecture mismatch") {
		t.Fatalf("New(foreign ELF) error = %v, want architecture mismatch", err)
	}
}

func TestSandboxRunTwiceFails(t *testing.T) {
	elfData, err := testelf.BuildGuestELF64At(runtime.GOARCH, staticBase(), 0, "once\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	cfg := hostTestConfig(t)
	cfg.ELFBytes = elfData
	cfg.Stdout = io.Discard
	sb, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = sb.Close()
	}()
	if code, err := sb.Run(context.Background()); err != nil || code != 0 {
		t.Fatalf("first Run() = (%d, %v), want (0, nil)", code, err)
	}
	if _, err := sb.Run(context.Background()); err == nil {
		t.Fatalf("second Run() succeeded, want error")
	}
}

func TestSandboxRegistryImageAppliesRuntimeConfig(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64 failed: %v", err)
	}
	foreignCat, err := testelf.BuildGuestCatELF64(otherArch())
	if err != nil {
		t.Fatalf("BuildGuestCatELF64(%s) failed: %v", otherArch(), err)
	}
	layerFor := func(cat []byte, marker string) []byte {
		layer, err := testimage.Tar(
			testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755},
			testimage.File{Name: "data/note.txt", Data: []byte(marker + "\n")},
		)
		if err != nil {
			t.Fatalf("testimage.Tar failed: %v", err)
		}
		return layer
	}
	baseURL := testimage.NewRegistry(t, "gvx/cfgtest", "v1",
		testimage.Image{
			Arch:       runtime.GOARCH,
			Layers:     [][]byte{layerFor(catELF, "host-arch-image")},
			Entrypoint: []string{"/bin/cat"},
			Cmd:        []string{"note.txt"},
			WorkingDir: "/data",
		},
		testimage.Image{
			Arch:       otherArch(),
			Layers:     [][]byte{layerFor(foreignCat, "foreign-arch-image")},
			Entrypoint: []string{"/bin/cat"},
			Cmd:        []string{"note.txt"},
			WorkingDir: "/data",
		},
	)

	cfg := hostTestConfig(t)
	cfg.OCIImage = "gvx/cfgtest:v1"
	cfg.RegistryBaseURL = baseURL
	code, stdout, stderr := runConfig(t, cfg)
	if code != 0 || stdout != "host-arch-image\n" {
		t.Fatalf("registry image = (%d, %q, stderr=%q), want (0, %q): Entrypoint, Cmd, WorkingDir, and architecture selection", code, stdout, stderr, "host-arch-image\n")
	}
}

func TestSandboxOverlayWhiteoutsOpaqueAndOrdering(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64 failed: %v", err)
	}
	lowerTar, err := testimage.Tar(
		testimage.File{Name: "bin/cat", Data: catELF, Mode: 0o755},
		testimage.File{Name: "app/README.md", Data: []byte("UPPER-README\n")},
		testimage.File{Name: "app/readme.md", Data: []byte("lower-readme\n")},
		testimage.File{Name: "app/CON", Data: []byte("reserved-con\n")},
		testimage.File{Name: "app/AUX", Data: []byte("reserved-aux\n")},
		testimage.File{Name: "app/obsolete.txt", Data: []byte("remove-me\n")},
		testimage.File{Name: "app/override.txt", Data: []byte("from-lower\n")},
		testimage.File{Name: "app/gone", Type: '5'},
		testimage.File{Name: "app/gone/child.txt", Data: []byte("hidden-with-dir\n")},
		testimage.File{Name: "app/opaque", Type: '5'},
		testimage.File{Name: "app/opaque/old.txt", Data: []byte("hidden-by-opaque\n")},
	)
	if err != nil {
		t.Fatalf("testimage.Tar(lower) failed: %v", err)
	}
	upperTar, err := testimage.Tar(
		testimage.File{Name: "app/.wh.obsolete.txt"},
		testimage.File{Name: "app/.wh.gone"},
		testimage.File{Name: "app/override.txt", Data: []byte("from-upper\n")},
		testimage.File{Name: "app/opaque/.wh..wh..opq"},
		testimage.File{Name: "app/opaque/fresh.txt", Data: []byte("visible-above-opaque\n")},
	)
	if err != nil {
		t.Fatalf("testimage.Tar(upper) failed: %v", err)
	}

	visible := []struct{ path, want string }{
		{"/app/README.md", "UPPER-README\n"},
		{"/app/readme.md", "lower-readme\n"},
		{"/app/CON", "reserved-con\n"},
		{"/app/AUX", "reserved-aux\n"},
		{"/app/override.txt", "from-upper\n"},
		{"/app/opaque/fresh.txt", "visible-above-opaque\n"},
	}
	hidden := []string{"/app/obsolete.txt", "/app/gone/child.txt", "/app/opaque/old.txt"}

	// Each probe reads one visible file first, so a non-zero exit with the
	// visible content on stdout proves that only the hidden path failed.
	for _, h := range hidden {
		t.Run("hidden"+strings.ReplaceAll(h, "/", "_"), func(t *testing.T) {
			cfg := hostTestConfig(t)
			cfg.OCILayerTars = [][]byte{lowerTar, upperTar}
			cfg.Argv = []string{"/bin/cat", "/app/README.md", h}
			code, stdout, stderr := runConfig(t, cfg)
			if code == 0 {
				t.Fatalf("cat %s succeeded, want failure (stdout=%q stderr=%q)", h, stdout, stderr)
			}
			if stdout != "UPPER-README\n" {
				t.Fatalf("stdout = %q, want only the visible file content", stdout)
			}
		})
	}

	cfg := hostTestConfig(t)
	cfg.OCILayerTars = [][]byte{lowerTar, upperTar}
	argv := []string{"/bin/cat"}
	var want strings.Builder
	for _, v := range visible {
		argv = append(argv, v.path)
		want.WriteString(v.want)
	}
	cfg.Argv = argv
	code, stdout, stderr := runConfig(t, cfg)
	if code != 0 || stdout != want.String() {
		t.Fatalf("visible files = (%d, %q, stderr=%q), want (0, %q)", code, stdout, stderr, want.String())
	}
}

func TestSandboxWorkspaceAndPortForward(t *testing.T) {
	workspaceAndPortForward(t, PlatformAuto, staticBase())
}

func TestSandboxWorkspaceAndPortForwardUnderSystrap(t *testing.T) {
	systraptest.Require(t)
	workspaceAndPortForward(t, PlatformSystrap, systrapBase())
}

// workspaceAndPortForward runs a guest HTTP server on platform, links the
// server at base, and reads its page through a published host port.
func workspaceAndPortForward(t *testing.T, platform PlatformType, base uint64) {
	t.Helper()
	httpServerELF, err := testelf.BuildGuestHTTPServerELF64At(
		runtime.GOARCH,
		base,
		8080,
		"/usr/share/nginx/html/index.html",
		"/workspace/result.txt",
		"workspace-ok\n",
	)
	if err != nil {
		t.Fatalf("BuildGuestHTTPServerELF64 failed: %v", err)
	}
	layer, err := testimage.Tar(
		testimage.File{Name: "usr/share/nginx/html/index.html", Data: []byte("nginx-from-erofs-layer\n")},
		testimage.File{Name: "usr/sbin/nginx", Data: httpServerELF, Mode: 0o755},
	)
	if err != nil {
		t.Fatalf("testimage.Tar failed: %v", err)
	}

	workspaceDir := t.TempDir()
	cfg := hostTestConfig(t)
	cfg.Platform = platform
	cfg.NetworkMode = NetModeNAT
	cfg.OCILayerTars = [][]byte{layer}
	cfg.WorkspacePath = workspaceDir
	cfg.PortForwards = []PortForward{{HostPort: 0, GuestPort: 8080, Protocol: "tcp", BindAddress: "127.0.0.1"}}
	cfg.Argv = []string{"/usr/sbin/nginx", "-p", "8080"}
	cfg.Stdout = io.Discard
	cfg.Stderr = io.Discard

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sb, err := New(ctx, cfg)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = sb.Close()
	}()

	hostPort := sb.BoundPort(0)
	if hostPort <= 0 {
		t.Fatalf("BoundPort(0) = %d, want > 0", hostPort)
	}

	type runRes struct {
		code int
		err  error
	}
	runCh := make(chan runRes, 1)
	go func() {
		c, rErr := sb.Run(ctx)
		runCh <- runRes{code: c, err: rErr}
	}()

	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(hostPort) + "/")
	if err != nil {
		t.Fatalf("GET forwarded port failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if cErr := resp.Body.Close(); cErr != nil {
		t.Errorf("close response body: %v", cErr)
	}
	if err != nil {
		t.Fatalf("read forwarded response: %v", err)
	}
	if strings.TrimSpace(string(body)) != "nginx-from-erofs-layer" {
		t.Fatalf("HTTP response body = %q, want %q", string(body), "nginx-from-erofs-layer\n")
	}

	res := <-runCh
	if res.err != nil || res.code != 0 {
		t.Fatalf("sb.Run(nginx) = (%d, %v), want (0, nil)", res.code, res.err)
	}

	hostBytes, err := os.ReadFile(filepath.Join(workspaceDir, "result.txt"))
	if err != nil || strings.TrimSpace(string(hostBytes)) != "workspace-ok" {
		t.Fatalf("workspace result.txt = (%q, %v)", string(hostBytes), err)
	}
}

// staticBase returns the link address of a static test ELF that the backend of
// PlatformAuto can load. A hardware backend accepts the classic 0x400000. A host
// without a hypervisor falls back to the systrap platform.
func staticBase() uint64 {
	if hvtest.Available() {
		return 0x400000
	}
	return systrapBase()
}

// systrapBase returns a link address that every systrap engine of the host
// allows. The macOS engine places guest addresses above the host reservations,
// which end at 0x7000000000 on Apple silicon, so it needs an address at 16TB.
// The Windows engine holds 16TB and up in its high window, and the classic
// addresses in its low window. The test of the low window is
// TestSandboxStartsStaticExecutablesAtLowAddresses. The upstream Linux
// platform accepts the classic 0x400000.
func systrapBase() uint64 {
	if runtime.GOOS == "linux" {
		return 0x400000
	}
	return 0x1000_0000_0000
}

func TestSandboxRunsStaticAndDynamicELF64UnderSystrap(t *testing.T) {
	systraptest.Require(t)
	staticELF, err := testelf.BuildGuestELF64At(runtime.GOARCH, systrapBase(), 0, "systrap-static\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64At failed: %v", err)
	}
	dynamicELF, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 9, "systrap-dynamic\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}
	for _, tc := range []struct {
		name     string
		elf      []byte
		wantCode int
		wantOut  string
	}{
		{"static", staticELF, 0, "systrap-static\n"},
		{"dynamic", dynamicELF, 9, "systrap-dynamic\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := hostTestConfig(t)
			cfg.Platform = PlatformSystrap
			cfg.ELFBytes = tc.elf
			var outBuf bytes.Buffer
			cfg.Stdout = &outBuf
			sb, err := New(context.Background(), cfg)
			if err != nil {
				t.Fatalf("New(systrap) failed: %v", err)
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close() failed: %v", err)
				}
			}()
			if got := sb.PlatformName(); got != "systrap" {
				t.Errorf("PlatformName() = %q, want systrap", got)
			}
			code, err := sb.Run(context.Background())
			if err != nil || code != tc.wantCode || outBuf.String() != tc.wantOut {
				t.Fatalf("Run() = (%d, %v) stdout %q, want (%d, nil) %q", code, err, outBuf.String(), tc.wantCode, tc.wantOut)
			}
		})
	}
}

// TestSandboxStartsStaticExecutablesAtLowAddresses starts static executables
// that link at the addresses that real linkers use: 0x10000 for Go on arm64 and
// 0x400000 for most others. The Windows engine holds them in its low window.
// The macOS engine cannot hold them, because every arm64 task has a 4GB
// PAGEZERO. It must refuse and name the cause and the engine that works.
func TestSandboxStartsStaticExecutablesAtLowAddresses(t *testing.T) {
	systraptest.Require(t)
	for _, base := range []uint64{0x10000, 0x400000} {
		t.Run("base-0x"+strconv.FormatUint(base, 16), func(t *testing.T) {
			elf, err := testelf.BuildGuestELF64At(runtime.GOARCH, base, 0, "low-window-ok\n")
			if err != nil {
				t.Fatalf("BuildGuestELF64At failed: %v", err)
			}
			cfg := hostTestConfig(t)
			cfg.Platform = PlatformSystrap
			cfg.ELFBytes = elf
			var outBuf bytes.Buffer
			cfg.Stdout = &outBuf
			sb, err := New(context.Background(), cfg)
			if err != nil {
				t.Fatalf("New(systrap) failed: %v", err)
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close() failed: %v", err)
				}
			}()
			code, err := sb.Run(context.Background())
			if runtime.GOOS == "windows" {
				if err != nil || code != 0 || outBuf.String() != "low-window-ok\n" {
					t.Fatalf("Run() = (%d, %v) stdout %q, want (0, nil) %q", code, err, outBuf.String(), "low-window-ok\n")
				}
				return
			}
			if err == nil {
				t.Fatalf("Run() = (%d, nil), want an error: this engine cannot hold an executable at %#x", code, base)
			}
			if msg := err.Error(); !strings.Contains(msg, "position-independent") || !strings.Contains(msg, "-platform=hvf") {
				t.Errorf("error %q does not name the cause and the engine that works", msg)
			}
		})
	}
}
