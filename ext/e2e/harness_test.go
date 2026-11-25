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
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
)

const rungvPkg = "../cmd/rungvx"

var (
	cacheMu  sync.Mutex
	cacheDir string

	toolsMu  sync.Mutex
	toolsDir string

	builtToolsMu sync.Mutex
	builtTools   = map[string]string{}
)

func TestMain(m *testing.M) {
	code := m.Run()
	if cacheDir != "" {
		_ = os.RemoveAll(cacheDir)
	}
	if toolsDir != "" {
		_ = os.RemoveAll(toolsDir)
	}
	os.Exit(code)
}

func sharedCacheDir(t *testing.T) string {
	t.Helper()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cacheDir == "" {
		dir, err := os.MkdirTemp("", "gvx-ext-e2e-cache-*")
		if err != nil {
			t.Fatalf("create shared layer cache: %v", err)
		}
		cacheDir = dir
	}
	return cacheDir
}

func hostArch() string { return runtime.GOARCH }

func autoPlatform() gvx.PlatformType {
	switch runtime.GOOS {
	case "darwin":
		return gvx.PlatformHVF
	case "windows":
		return gvx.PlatformWHPX
	default:
		return gvx.PlatformSystrap
	}
}

type gateBackend struct {
	name string
	plat gvx.PlatformType
}

func gateBackends() []gateBackend {
	backends := []gateBackend{{string(autoPlatform()), autoPlatform()}}
	if autoPlatform() != gvx.PlatformSystrap {
		backends = append(backends, gateBackend{"systrap", gvx.PlatformSystrap})
	}
	return backends
}

func requireBackend(t *testing.T, b gateBackend) {
	t.Helper()
	switch b.plat {
	case gvx.PlatformSystrap:
		exttest.RequireSystrap(t)
	case gvx.PlatformHVF, gvx.PlatformWHPX:
		exttest.RequireHardwareHypervisor(t)
	}
}

func requireAutoPlatform(t *testing.T) {
	t.Helper()
	requireBackend(t, gateBackend{string(autoPlatform()), autoPlatform()})
}

func requireRegistry(t *testing.T) {
	t.Helper()
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		t.Skip("skipping registry test (GVX_E2E_OFFLINE=1)")
	}
	conn, err := net.DialTimeout("tcp", "registry-1.docker.io:443", 3*time.Second)
	if err != nil {
		if os.Getenv("GVX_E2E_REQUIRE_NETWORK") == "1" {
			t.Fatalf("registry unreachable with GVX_E2E_REQUIRE_NETWORK=1: %v", err)
		}
		t.Skipf("registry unreachable: %v", err)
	}
	_ = conn.Close()
}

func toolPath(t *testing.T, pkg string) string {
	t.Helper()
	builtToolsMu.Lock()
	if p, ok := builtTools[pkg]; ok {
		builtToolsMu.Unlock()
		return p
	}
	builtToolsMu.Unlock()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for building rungvx with -tags ext_gpu")
	}

	toolsMu.Lock()
	if toolsDir == "" {
		dir, err := os.MkdirTemp("", "gvx-ext-e2e-tools-*")
		if err != nil {
			toolsMu.Unlock()
			t.Fatalf("create toolsDir: %v", err)
		}
		toolsDir = dir
	}
	dir := toolsDir
	toolsMu.Unlock()

	exe := "rungvx"
	if runtime.GOOS == "windows" {
		exe = "rungvx.exe"
	}
	out := filepath.Join(dir, exe)
	cmd := exec.Command("go", "build", "-tags", "ext_gpu", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s (-tags ext_gpu): %v\n%s", pkg, err, combined)
	}
	if runtime.GOOS == "darwin" {
		ent := filepath.Join("..", "..", "entitlements.plist")
		sign := exec.Command("codesign", "--sign", "-", "--entitlements", ent, "--force", out)
		if combined, err := sign.CombinedOutput(); err != nil {
			t.Fatalf("codesign %s: %v\n%s", out, err, combined)
		}
	}

	builtToolsMu.Lock()
	builtTools[pkg] = out
	builtToolsMu.Unlock()
	return out
}

type guestSpec struct {
	plat          gvx.PlatformType
	image         string
	argv          []string
	envv          []string
	workspace     string
	net           gvx.NetworkMode
	forwards      []gvx.PortForward
	stdin         io.Reader
	tty           bool
	timeout       time.Duration
	cmd           []string
	entrypoint    []string
	entrypointSet bool
	user          string
	hostname      string
	resources     gvx.Resources
	mounts        []gvx.Mount
	readOnlyRoot  bool
	publishAll    bool
	netRaw        bool
	hostCACerts   bool
	packetWrite   bool
	allowSUID     bool
	cacheDir      string
}

func (g guestSpec) config(cache string, stdout, stderr io.Writer) gvx.Config {
	netMode := g.net
	if netMode == "" {
		netMode = gvx.NetModeNone
	}
	return gvx.Config{
		Platform:               g.plat,
		NetworkMode:            netMode,
		PortForwards:           g.forwards,
		OCIImage:               g.image,
		OCICacheDir:            cache,
		WorkspacePath:          g.workspace,
		Argv:                   g.argv,
		Cmd:                    g.cmd,
		Entrypoint:             g.entrypoint,
		EntrypointSet:          g.entrypointSet,
		Envv:                   g.envv,
		User:                   g.user,
		Hostname:               g.hostname,
		Resources:              g.resources,
		Mounts:                 g.mounts,
		ReadOnlyRoot:           g.readOnlyRoot,
		PublishAll:             g.publishAll,
		HostCACerts:            g.hostCACerts,
		NetRaw:                 g.netRaw,
		AllowPacketSocketWrite: g.packetWrite,
		AllowSUID:              g.allowSUID,
		Stdin:                  g.stdin,
		Stdout:                 stdout,
		Stderr:                 stderr,
		TTY:                    g.tty,
		DisableHostLockdown:    true,
	}
}

func runGuest(t *testing.T, g guestSpec) (code int, stdout, stderr string) {
	t.Helper()
	timeout := g.timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	cache := g.cacheDir
	if cache == "" {
		cache = sharedCacheDir(t)
	}
	sb, err := gvx.New(ctx, g.config(cache, &outBuf, &errBuf))
	if err != nil {
		t.Fatalf("gvx.New(%s, %s) failed: %v", g.plat, g.image, err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close(%s, %s) failed: %v", g.plat, g.image, err)
		}
	}()
	code, err = sb.Run(ctx)
	if err != nil {
		t.Fatalf("sb.Run(%s, %v) = (%d, %v)\nstdout=%s\nstderr=%s", g.image, g.argv, code, err, outBuf.String(), errBuf.String())
	}
	return code, outBuf.String(), errBuf.String()
}

func mustRunGuest(t *testing.T, g guestSpec) string {
	t.Helper()
	code, stdout, stderr := runGuest(t, g)
	if code != 0 {
		t.Fatalf("guest %s %v exit code = %d, want 0\nstdout=%s\nstderr=%s", g.image, g.argv, code, stdout, stderr)
	}
	return stdout
}

func requireContains(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("%s lacks %q; full text:\n%s", what, want, text)
		}
	}
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o755)
}

type outputLog struct {
	mu   sync.Mutex
	buf  bytes.Buffer
	wake chan struct{}
}

func newOutputLog() *outputLog {
	return &outputLog{wake: make(chan struct{})}
}

func (o *outputLog) Write(p []byte) (int, error) {
	o.mu.Lock()
	n, err := o.buf.Write(p)
	close(o.wake)
	o.wake = make(chan struct{})
	o.mu.Unlock()
	return n, err
}

func (o *outputLog) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buf.String()
}

func (o *outputLog) waitFor(t *testing.T, from int, substr string, timeout time.Duration, done <-chan struct{}) int {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		o.mu.Lock()
		data := o.buf.Bytes()
		if from <= len(data) {
			if idx := bytes.Index(data[from:], []byte(substr)); idx >= 0 {
				end := from + idx + len(substr)
				o.mu.Unlock()
				return end
			}
		}
		wake := o.wake
		o.mu.Unlock()
		select {
		case <-wake:
		case <-done:
			if end, ok := o.find(from, substr); ok {
				return end
			}
			t.Fatalf("guest ended before output %q appeared; transcript:\n%s", substr, o.String())
		case <-timer.C:
			t.Fatalf("timeout after %s waiting for output %q; transcript:\n%s", timeout, substr, o.String())
		}
	}
}

func (o *outputLog) find(from int, substr string) (int, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	data := o.buf.Bytes()
	if from > len(data) {
		return 0, false
	}
	idx := bytes.Index(data[from:], []byte(substr))
	if idx < 0 {
		return 0, false
	}
	return from + idx + len(substr), true
}
