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
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/lockdownprobe"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

const (
	lockdownProbePkg = "z.gfire.dev/gvx/internal/lockdownprobe/cmd/lockdownprobe"
	rungvPkg         = "z.gfire.dev/gvx/cmd/rungv"
)

// autoPlatform returns the backend that -platform=auto selects: the hardware
// hypervisor on Windows and macOS, and the upstream systrap platform on Linux.
func autoPlatform() gvx.PlatformType {
	switch runtime.GOOS {
	case "windows":
		return gvx.PlatformWHPX
	case "linux":
		return gvx.PlatformSystrap
	}
	return gvx.PlatformHVF
}

// foreignHypervisorPlatform returns the hardware backend of the other host OS.
func foreignHypervisorPlatform() gvx.PlatformType {
	if runtime.GOOS == "windows" {
		return gvx.PlatformHVF
	}
	return gvx.PlatformWHPX
}

// otherArch returns the Linux architecture that differs from the host.
func otherArch() string {
	if runtime.GOARCH == "arm64" {
		return "amd64"
	}
	return "arm64"
}

var (
	toolsMu  sync.Mutex
	toolsDir string
	tools    = map[string]string{}
)

// TestMain removes the binaries that toolPath builds and the layer cache that
// sharedCacheDir creates.
func TestMain(m *testing.M) {
	code := m.Run()
	for _, dir := range []string{toolsDir, cacheDir} {
		if dir == "" {
			continue
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "e2e: remove %s: %v\n", dir, err)
			code = 1
		}
	}
	os.Exit(code)
}

// toolPath builds the main package pkg once per test run and returns the
// binary path. Darwin binaries get the ad-hoc hypervisor entitlement.
func toolPath(t *testing.T, pkg string) string {
	t.Helper()
	toolsMu.Lock()
	defer toolsMu.Unlock()
	if p, ok := tools[pkg]; ok {
		return p
	}
	if toolsDir == "" {
		dir, err := os.MkdirTemp("", "gvx-e2e-tools-*")
		if err != nil {
			t.Fatalf("create tool dir: %v", err)
		}
		toolsDir = dir
	}
	name := filepath.Base(pkg)
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	out := filepath.Join(toolsDir, name)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	buildArgs := []string{"build", "-o", out}
	if childBuildTags != "" {
		buildArgs = append(buildArgs, "-tags", childBuildTags)
	}
	buildArgs = append(buildArgs, pkg)
	if combined, err := exec.CommandContext(ctx, "go", buildArgs...).CombinedOutput(); err != nil {
		t.Fatalf("go build %s failed: %v\n%s", pkg, err, combined)
	}
	if runtime.GOOS == "darwin" {
		sign := exec.CommandContext(ctx, "codesign", "--force", "--sign", "-", "--entitlements", filepath.Join("..", "entitlements.plist"), out)
		if combined, err := sign.CombinedOutput(); err != nil {
			t.Fatalf("codesign %s failed: %v\n%s", out, err, combined)
		}
	}
	tools[pkg] = out
	return out
}

// runTool runs bin and returns stdout, stderr, and the exit code.
func runTool(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("run %s %v: %v", bin, args, err)
	}
	return outBuf.String(), errBuf.String(), code
}

// requireRegistry skips the calling test when Docker Hub is unreachable.
// GVX_E2E_REQUIRE_NETWORK=1 turns the skip into a failure for CI runs.
// GVX_E2E_OFFLINE=1 skips without a probe, so the per-push CI jobs spend no
// time on registry pulls. The weekly image workflow leaves it unset.
func requireRegistry(t *testing.T) {
	t.Helper()
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		t.Skip("registry tests are off (GVX_E2E_OFFLINE=1)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, oci.DefaultRegistryBaseURL+"/v2/", nil)
	if err != nil {
		t.Fatalf("build registry probe request: %v", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		if os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "" {
			t.Fatalf("registry %s unreachable: %v", oci.DefaultRegistryBaseURL, err)
		}
		t.Skipf("registry %s unreachable: %v", oci.DefaultRegistryBaseURL, err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close registry probe response: %v", err)
	}
}

func mustTar(t *testing.T, files ...testimage.File) []byte {
	t.Helper()
	layer, err := testimage.Tar(files...)
	if err != nil {
		t.Fatalf("testimage.Tar failed: %v", err)
	}
	return layer
}

// runELF boots one sandbox with the lockdown disabled, so the test process
// stays usable, and returns the guest result and the reported backend.
func runELF(t *testing.T, plat gvx.PlatformType, elfData []byte) (code int, stdout, backend string) {
	t.Helper()
	ctx := context.Background()
	var outBuf bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		ELFBytes:            elfData,
		Stdout:              &outBuf,
		DisableHostLockdown: true,
	})
	if err != nil {
		t.Fatalf("gvx.New(%s) failed: %v", plat, err)
	}
	defer func() {
		if err := sb.Close(); err != nil {
			t.Errorf("Close(%s) failed: %v", plat, err)
		}
	}()
	code, err = sb.Run(ctx)
	if err != nil {
		t.Fatalf("sb.Run(%s) failed: %v", plat, err)
	}
	return code, outBuf.String(), sb.PlatformName()
}

func TestE2EStaticAndDynamicELF64AcrossBackends(t *testing.T) {
	staticELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "e2e-static-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	dynamicELF, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 7, "e2e-dynamic-ok\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}

	// -platform=auto must resolve to the hardware backend of the host OS.
	wantBackend := string(autoPlatform())
	for _, plat := range []gvx.PlatformType{gvx.PlatformAuto, autoPlatform()} {
		t.Run(string(plat)+"_static", func(t *testing.T) {
			code, stdout, backend := runELF(t, plat, staticELF)
			if code != 0 || stdout != "e2e-static-ok\n" || backend != wantBackend {
				t.Fatalf("static on %s = (code %d, stdout %q, backend %q), want (0, %q, %q)", plat, code, stdout, backend, "e2e-static-ok\n", wantBackend)
			}
		})
		t.Run(string(plat)+"_dynamic", func(t *testing.T) {
			code, stdout, backend := runELF(t, plat, dynamicELF)
			if code != 7 || stdout != "e2e-dynamic-ok\n" || backend != wantBackend {
				t.Fatalf("dynamic on %s = (code %d, stdout %q, backend %q), want (7, %q, %q)", plat, code, stdout, backend, "e2e-dynamic-ok\n", wantBackend)
			}
		})
	}
}

func TestE2EOtherOSHypervisorFailsExplicitly(t *testing.T) {
	elfData, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "x\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	plat := foreignHypervisorPlatform()
	sb, err := gvx.New(context.Background(), gvx.Config{
		Platform:            plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		ELFBytes:            elfData,
		DisableHostLockdown: true,
	})
	if err == nil {
		_ = sb.Close()
		t.Fatalf("gvx.New(%s) succeeded on %s, want an error", plat, runtime.GOOS)
	}
}

// TestE2ESystrapPrerequisiteError checks the explicit -platform=systrap error
// in builds without a runnable engine. The 16KB-page darwin/arm64 build
// covers the running engine in the systrap tests below.
func TestE2ESystrapPrerequisiteError(t *testing.T) {
	systraptest.RequireUnavailable(t)
	_, err := gvx.New(context.Background(), gvx.Config{
		Platform:            gvx.PlatformSystrap,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		DisableHostLockdown: true,
	})
	if err == nil {
		t.Fatalf("gvx.New(systrap) succeeded although the engine is unavailable")
	}
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		if !strings.Contains(err.Error(), "pagesize_16k") {
			t.Fatalf("gvx.New(systrap) error = %v, want the page-size requirement", err)
		}
		return
	}
	if !errors.Is(err, gvx.ErrPlatformUnavailable) {
		t.Fatalf("gvx.New(systrap) error = %v, want ErrPlatformUnavailable", err)
	}
}

func TestE2ERungvReportsBackendAndRunsUnderDefaultLockdown(t *testing.T) {
	rungv := toolPath(t, rungvPkg)
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/guest.txt", "written-under-lockdown\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	workspace := t.TempDir()

	// No -lockdown flag: the CLI default applies the host lockdown.
	stdout, stderr, code := runTool(t, rungv, "run",
		"-platform=auto", "-net=none",
		"-cache-dir="+t.TempDir(), "-workspace="+workspace,
		elfPath)
	if code != 0 {
		t.Fatalf("rungv run exit code = %d, want 0\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	if want := "rungv: platform=" + string(autoPlatform()); !strings.Contains(stderr, want) {
		t.Fatalf("rungv run stderr = %q, want it to report %q", stderr, want)
	}
	if strings.Contains(stderr, "lockdown disabled") {
		t.Fatalf("rungv run reports a disabled lockdown without -lockdown=false: %q", stderr)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "guest.txt"))
	if err != nil || string(got) != "written-under-lockdown\n" {
		t.Fatalf("workspace guest.txt = (%q, %v), want %q", got, err, "written-under-lockdown\n")
	}

	// -lockdown=false is an explicit and loud opt-out.
	_, stderr, code = runTool(t, rungv, "run",
		"-lockdown=false", "-platform="+string(autoPlatform()), "-net=none",
		"-cache-dir="+t.TempDir(), "-workspace="+workspace,
		elfPath)
	if code != 0 {
		t.Fatalf("rungv run -lockdown=false exit code = %d, stderr=%s", code, stderr)
	}
	if !strings.Contains(stderr, "lockdown disabled") {
		t.Fatalf("rungv run -lockdown=false stderr = %q, want a lockdown warning", stderr)
	}
	if strings.Contains(stderr, "platform=") {
		t.Fatalf("rungv run with explicit backend printed a backend line: %q", stderr)
	}
}

func TestE2ERungvConfigurationErrors(t *testing.T) {
	rungv := toolPath(t, rungvPkg)
	guestELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "x\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	base := []string{"run", "-lockdown=false", "-cache-dir=" + t.TempDir()}

	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"port forward with none", []string{"-net=none", "-p", "8080:80"}, 2, "port forwards"},
		{"port forward with wireguard", []string{"-net=wg", "-wg-conf=missing.conf", "-p", "8080:80"}, 2, "port forwards"},
		{"wireguard without config", []string{"-net=wg"}, 2, "WireGuardConfig"},
		{"unknown architecture", []string{"-net=none", "-arch=riscv64"}, 2, "riscv64"},
		{"foreign architecture on hardware backend", []string{"-net=none", "-arch=" + otherArch()}, 2, "systrap"},
		{"unknown network mode", []string{"-net=vxlan"}, 2, "vxlan"},
		{"other-OS hypervisor", []string{"-net=none", "-platform=" + string(foreignHypervisorPlatform())}, 1, string(foreignHypervisorPlatform())},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(append([]string{}, base...), tc.args...)
			args = append(args, elfPath)
			stdout, stderr, code := runTool(t, rungv, args...)
			if code != tc.wantCode || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("rungv %v = (code %d, stderr %q), want (code %d, stderr containing %q); stdout=%q", tc.args, code, stderr, tc.wantCode, tc.wantStderr, stdout)
			}
		})
	}
}

// overlayRegistry serves a two-layer image for the host architecture and a
// one-layer image for the other architecture. The upper layer carries a
// whiteout, a directory whiteout, an opaque directory, and an override.
func overlayRegistry(t *testing.T) (baseURL string) {
	t.Helper()
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64 failed: %v", err)
	}
	foreignCat, err := testelf.BuildGuestCatELF64(otherArch())
	if err != nil {
		t.Fatalf("BuildGuestCatELF64(%s) failed: %v", otherArch(), err)
	}
	lower := mustTar(t,
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
	upper := mustTar(t,
		testimage.File{Name: "app/.wh.obsolete.txt"},
		testimage.File{Name: "app/.wh.gone"},
		testimage.File{Name: "app/override.txt", Data: []byte("from-upper\n")},
		testimage.File{Name: "app/opaque/.wh..wh..opq"},
		testimage.File{Name: "app/opaque/fresh.txt", Data: []byte("visible-above-opaque\n")},
	)
	foreign := mustTar(t, testimage.File{Name: "bin/cat", Data: foreignCat, Mode: 0o755})
	return testimage.NewRegistry(t, "gvx/e2e", "1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{lower, upper}},
		testimage.Image{Arch: otherArch(), Layers: [][]byte{foreign}},
	)
}

func TestE2ERungvPullAndRunOverlayWhiteoutsAndCaseSensitivity(t *testing.T) {
	rungv := toolPath(t, rungvPkg)
	baseURL := overlayRegistry(t)
	cacheDir := t.TempDir()

	// layers reports the number of layers that the store holds for the image
	// of the test registry and an architecture, as `rungv inspect` shows it.
	layers := func(arch string) int {
		t.Helper()
		name := strings.TrimPrefix(baseURL, "http://") + "/gvx/e2e:1"
		stdout, stderr, code := runTool(t, rungv, "inspect", "-arch="+arch, "-cache-dir="+cacheDir, name)
		if code != 0 {
			t.Fatalf("rungv inspect %s = (code %d, stdout %q, stderr %q), want the pulled image", name, code, stdout, stderr)
		}
		var out []struct {
			RootFS struct{ Layers []string }
		}
		if err := json.Unmarshal([]byte(stdout), &out); err != nil || len(out) != 1 {
			t.Fatalf("rungv inspect output = %q (%v), want one image", stdout, err)
		}
		return len(out[0].RootFS.Layers)
	}

	stdout, stderr, code := runTool(t, rungv, "pull", "-cache-dir="+cacheDir, "-registry-url="+baseURL, "gvx/e2e:1")
	if code != 0 || !strings.Contains(stdout, "Digest: sha256:") {
		t.Fatalf("rungv pull = (code %d, stdout %q, stderr %q), want success with the digest", code, stdout, stderr)
	}
	if got := layers(runtime.GOARCH); got != 2 {
		t.Fatalf("the pulled image has %d layers, want 2", got)
	}
	// -arch selects the other architecture's manifest: one layer.
	stdout, stderr, code = runTool(t, rungv, "pull", "-arch="+otherArch(), "-cache-dir="+cacheDir, "-registry-url="+baseURL, "gvx/e2e:1")
	if code != 0 {
		t.Fatalf("rungv pull -arch=%s = (code %d, stdout %q, stderr %q), want success", otherArch(), code, stdout, stderr)
	}
	if got := layers(otherArch()); got != 1 {
		t.Fatalf("the image for %s has %d layers, want 1", otherArch(), got)
	}

	runCat := func(paths ...string) (stdout, stderr string, code int) {
		args := []string{"run", "-platform=auto", "-net=none", "-cache-dir=" + cacheDir, "-registry-url=" + baseURL, "-image=gvx/e2e:1", "--", "/bin/cat"}
		return runTool(t, rungv, append(args, paths...)...)
	}

	// Visible files cover case sensitivity, Windows-reserved names, and the
	// upper layer replacing and extending the lower layer.
	visible := []string{"/app/README.md", "/app/readme.md", "/app/CON", "/app/AUX", "/app/override.txt", "/app/opaque/fresh.txt"}
	stdout, stderr, code = runCat(visible...)
	want := "UPPER-README\nlower-readme\nreserved-con\nreserved-aux\nfrom-upper\nvisible-above-opaque\n"
	if code != 0 || stdout != want {
		t.Fatalf("visible files = (code %d, stdout %q, stderr %q), want (0, %q)", code, stdout, stderr, want)
	}

	// Each hidden path follows a readable file in the same guest process, so
	// the failure belongs to the hidden path and not to the guest setup.
	for _, hidden := range []string{"/app/obsolete.txt", "/app/gone/child.txt", "/app/opaque/old.txt"} {
		stdout, stderr, code = runCat("/app/README.md", hidden)
		if code == 0 || stdout != "UPPER-README\n" {
			t.Fatalf("cat README.md %s = (code %d, stdout %q, stderr %q), want failure after the visible file", hidden, code, stdout, stderr)
		}
	}

	// The other architecture needs systrap, so the hardware backend refuses it.
	_, stderr, code = runTool(t, rungv, "run", "-platform=auto", "-net=none", "-arch="+otherArch(),
		"-cache-dir="+cacheDir, "-registry-url="+baseURL, "-image=gvx/e2e:1", "--", "/bin/cat", "/dev/null")
	if code != 2 || !strings.Contains(stderr, "systrap") {
		t.Fatalf("rungv run -arch=%s = (code %d, stderr %q), want usage error naming systrap", otherArch(), code, stderr)
	}
}

func TestE2EHostLockdownEnforcedByDefault(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/guest.txt", "guest-ran\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}

	probeRun := func(t *testing.T, extra ...string) (lockdownprobe.Report, string, string) {
		t.Helper()
		workspace := t.TempDir()
		outside := t.TempDir()
		secret := filepath.Join(outside, "secret.txt")
		if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write secret: %v", err)
		}
		args := append(extra,
			"-bin="+elfPath, "-workspace="+workspace, "-cache-dir="+t.TempDir(),
			"-outside-file="+secret, "-outside-dir="+outside)
		stdout, stderr, code := runTool(t, probe, args...)
		if code != 0 {
			t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
		}
		var rep lockdownprobe.Report
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("decode probe report %q: %v", stdout, err)
		}
		return rep, workspace, outside
	}

	t.Run("default_is_locked", func(t *testing.T) {
		rep, workspace, outside := probeRun(t)
		if rep.Platform != string(autoPlatform()) {
			t.Errorf("Platform = %q, want %q", rep.Platform, autoPlatform())
		}
		if !rep.Lockdown.Applied || !rep.LockedAPI {
			t.Errorf("Lockdown.Applied=%v IsLockedDown=%v, want both true by default", rep.Lockdown.Applied, rep.LockedAPI)
		}
		// The Linux seccomp filter cannot read paths, so a workspace keeps
		// opens relative to a directory descriptor, and the status says so.
		wantUnbound := runtime.GOOS != "linux"
		if !rep.Lockdown.SubprocessBlocked || rep.Lockdown.UnboundFileOpenBlocked != wantUnbound {
			t.Errorf("Lockdown status = %+v, want SubprocessBlocked and UnboundFileOpenBlocked=%v", rep.Lockdown, wantUnbound)
		}
		if rep.ReadOutsideErr == "" {
			t.Errorf("host read of a file outside the workspace succeeded after lockdown: %q", rep.OutsideReadBytes)
		}
		if rep.WriteOutsideErr == "" {
			t.Errorf("host write outside the workspace succeeded after lockdown")
		}
		if _, err := os.Stat(filepath.Join(outside, "escape.txt")); !os.IsNotExist(err) {
			t.Errorf("escape.txt exists outside the workspace: stat error = %v", err)
		}
		if rep.SpawnErr == "" {
			t.Errorf("host process spawn succeeded after lockdown")
		}
		if rep.GuestRunErr != "" || rep.GuestExitCode != 0 {
			t.Errorf("guest run = (code %d, err %q), want (0, none) under lockdown", rep.GuestExitCode, rep.GuestRunErr)
		}
		got, err := os.ReadFile(filepath.Join(workspace, "guest.txt"))
		if err != nil || string(got) != "guest-ran\n" {
			t.Errorf("workspace guest.txt = (%q, %v), want the guest write through the pinned os.Root", got, err)
		}
	})

	// The control proves that the three escape probes can succeed, so the
	// default run above fails them because of the lockdown.
	t.Run("opt_out_control", func(t *testing.T) {
		rep, workspace, outside := probeRun(t, "-lockdown=false")
		if rep.Lockdown.Applied || rep.LockedAPI {
			t.Errorf("Lockdown.Applied=%v IsLockedDown=%v with -lockdown=false, want both false", rep.Lockdown.Applied, rep.LockedAPI)
		}
		if rep.ReadOutsideErr != "" || rep.OutsideReadBytes != "secret" {
			t.Errorf("control read = (%q, err %q), want the secret", rep.OutsideReadBytes, rep.ReadOutsideErr)
		}
		if rep.WriteOutsideErr != "" {
			t.Errorf("control write failed: %s", rep.WriteOutsideErr)
		} else if _, err := os.Stat(filepath.Join(outside, "escape.txt")); err != nil {
			t.Errorf("control write left no escape.txt: %v", err)
		}
		if rep.SpawnErr != "" {
			t.Errorf("control spawn failed: %s", rep.SpawnErr)
		}
		if rep.GuestRunErr != "" || rep.GuestExitCode != 0 {
			t.Errorf("control guest run = (code %d, err %q)", rep.GuestExitCode, rep.GuestRunErr)
		}
		if got, err := os.ReadFile(filepath.Join(workspace, "guest.txt")); err != nil || string(got) != "guest-ran\n" {
			t.Errorf("control workspace guest.txt = (%q, %v)", got, err)
		}
	})
}

// startTool starts bin without waiting. The caller calls the returned wait
// function to collect stdout, stderr, and the exit code.
func startTool(t *testing.T, bin string, args ...string) (wait func() (stdout, stderr string, code int)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, bin, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s %v: %v", bin, args, err)
	}
	return func() (string, string, int) {
		err := cmd.Wait()
		var exitErr *exec.ExitError
		switch {
		case err == nil:
			return outBuf.String(), errBuf.String(), 0
		case errors.As(err, &exitErr):
			return outBuf.String(), errBuf.String(), exitErr.ExitCode()
		default:
			t.Fatalf("wait %s %v: %v", bin, args, err)
			return "", "", -1
		}
	}
}

// TestE2EHostLockdownNetworkModes checks that the lockdown profile follows
// the network mode. A listener on the host loopback stands in for any host
// service: NAT may dial it, and none and wg must not.
func TestE2EHostLockdownNetworkModes(t *testing.T) {
	probe := toolPath(t, lockdownProbePkg)
	guestELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on loopback: %v", err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	baseArgs := func(t *testing.T, mode string) []string {
		t.Helper()
		outside := t.TempDir()
		secret := filepath.Join(outside, "secret.txt")
		if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
			t.Fatalf("write secret: %v", err)
		}
		return []string{
			"-net=" + mode, "-bin=" + elfPath, "-workspace=" + t.TempDir(), "-cache-dir=" + t.TempDir(),
			"-outside-file=" + secret, "-outside-dir=" + outside, "-dial-target=" + listener.Addr().String(),
		}
	}
	decode := func(t *testing.T, stdout, stderr string, code int) lockdownprobe.Report {
		t.Helper()
		if code != 0 {
			t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
		}
		var rep lockdownprobe.Report
		if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
			t.Fatalf("decode probe report %q: %v", stdout, err)
		}
		if rep.GuestRunErr != "" || rep.GuestExitCode != 0 || rep.GuestStdout != "ok\n" {
			t.Fatalf("guest run = (code %d, stdout %q, err %q), want (0, %q, none)", rep.GuestExitCode, rep.GuestStdout, rep.GuestRunErr, "ok\n")
		}
		return rep
	}

	t.Run("none_blocks_outbound", func(t *testing.T) {
		stdout, stderr, code := runTool(t, probe, baseArgs(t, "none")...)
		rep := decode(t, stdout, stderr, code)
		if !rep.DialAttempted || rep.DialErr == "" {
			t.Fatalf("dial of the host listener under -net=none = (attempted %v, err %q), want a refusal", rep.DialAttempted, rep.DialErr)
		}
	})

	t.Run("nat_allows_outbound", func(t *testing.T) {
		stdout, stderr, code := runTool(t, probe, baseArgs(t, "nat")...)
		rep := decode(t, stdout, stderr, code)
		if !rep.Lockdown.Applied || rep.ReadOutsideErr == "" || rep.SpawnErr == "" {
			t.Fatalf("NAT run is not locked down: status %+v, read err %q, spawn err %q", rep.Lockdown, rep.ReadOutsideErr, rep.SpawnErr)
		}
		if !rep.DialAttempted || rep.DialErr != "" {
			t.Fatalf("dial of the host listener under -net=nat = (attempted %v, err %q), want success", rep.DialAttempted, rep.DialErr)
		}
	})

	// The WireGuard run keeps one UDP socket alive across the lockdown. The
	// probe sends a datagram through the tunnel and waits for the reply. The
	// test peer decrypts the datagram and returns the reply.
	t.Run("wg_keeps_only_the_prebound_udp_socket", func(t *testing.T) {
		curve := ecdh.X25519()
		guestPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate guest WireGuard key: %v", err)
		}
		peerPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate peer WireGuard key: %v", err)
		}
		var peerPrivBytes, guestPubBytes [32]byte
		copy(peerPrivBytes[:], peerPriv.Bytes())
		copy(guestPubBytes[:], guestPriv.PublicKey().Bytes())
		guestIP := netip.MustParseAddr("10.0.2.15")
		peer := startWireGuardPeer(t, peerPrivBytes, guestPubBytes, guestIP)

		args := append(baseArgs(t, "wg"),
			"-wg-private="+hex.EncodeToString(guestPriv.Bytes()),
			"-wg-peer-public="+hex.EncodeToString(peerPriv.PublicKey().Bytes()),
			"-wg-endpoint="+peer.endpoint)
		wait := startTool(t, probe, args...)

		const peerWait = 30 * time.Second
		src, dst, payload := peer.readUDPv4(t, peerWait)
		remote := netip.MustParseAddrPort(lockdownprobe.WireGuardRemote)
		if src.Addr() != guestIP || dst != remote || string(payload) != lockdownprobe.WireGuardPayload {
			t.Fatalf("peer received %s -> %s %q, want %s -> %s %q", src, dst, payload, guestIP, remote, lockdownprobe.WireGuardPayload)
		}
		peer.sendPacket(t, buildUDPv4Packet(remote, src, []byte(lockdownprobe.WireGuardReply)), peerWait)

		stdout, stderr, code := wait()
		rep := decode(t, stdout, stderr, code)
		if !rep.Lockdown.Applied {
			t.Fatalf("WireGuard run is not locked down: status %+v", rep.Lockdown)
		}
		if rep.WireGuardErr != "" {
			t.Fatalf("UDP exchange through the tunnel after lockdown failed: %s", rep.WireGuardErr)
		}
		if !rep.DialAttempted || rep.DialErr == "" {
			t.Fatalf("TCP dial of the host listener under -net=wg = (attempted %v, err %q), want a refusal", rep.DialAttempted, rep.DialErr)
		}
	})
}

func TestE2EWorkspaceGuestWriteAndReadOnlyMount(t *testing.T) {
	ctx := context.Background()
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/out.txt", "from-guest\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	run := func(t *testing.T, readOnly bool) (workspace string, code int) {
		t.Helper()
		workspace = t.TempDir()
		sb, err := gvx.New(ctx, gvx.Config{
			Platform:            gvx.PlatformAuto,
			NetworkMode:         gvx.NetModeNone,
			OCICacheDir:         t.TempDir(),
			ELFBytes:            guestELF,
			WorkspacePath:       workspace,
			WorkspaceReadOnly:   readOnly,
			Stdout:              io.Discard,
			Stderr:              io.Discard,
			DisableHostLockdown: true,
		})
		if err != nil {
			t.Fatalf("gvx.New failed: %v", err)
		}
		defer func() {
			_ = sb.Close()
		}()
		code, err = sb.Run(ctx)
		if err != nil {
			t.Fatalf("sb.Run failed: %v", err)
		}
		return workspace, code
	}

	workspace, code := run(t, false)
	got, err := os.ReadFile(filepath.Join(workspace, "out.txt"))
	if code != 0 || err != nil || string(got) != "from-guest\n" {
		t.Fatalf("read-write workspace = (code %d, file %q, err %v), want (0, %q)", code, got, err, "from-guest\n")
	}

	workspace, code = run(t, true)
	if code != 1 {
		t.Fatalf("read-only workspace guest exit code = %d, want 1 (openat must fail)", code)
	}
	if _, err := os.Stat(filepath.Join(workspace, "out.txt")); !os.IsNotExist(err) {
		t.Fatalf("read-only workspace received out.txt: stat error = %v", err)
	}
}

func TestE2EWorkspaceHostfsPOSIXAndAntiTOCTOU(t *testing.T) {
	requireRegistry(t)
	ctx := context.Background()
	workspaceDir := t.TempDir()

	var stdout, stderr bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            gvx.PlatformAuto,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		OCIImage:            "alpine:3.20",
		WorkspacePath:       workspaceDir,
		DisableHostLockdown: true,
		Argv: []string{
			"/bin/sh", "-c",
			"mkdir /workspace/src && echo v1 > /workspace/src/main.go && mv /workspace/src/main.go /workspace/src/app.go && chmod 0755 /workspace/src/app.go && ln -s app.go /workspace/src/link.go && cat /workspace/src/app.go",
		},
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("gvx.New failed: %v", err)
	}
	defer func() {
		_ = sb.Close()
	}()

	code, err := sb.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("sb.Run = (%d, %v) stderr=%q", code, err, stderr.String())
	}
	if strings.TrimSpace(stdout.String()) != "v1" {
		t.Fatalf("stdout = %q, want %q", stdout.String(), "v1\n")
	}

	ws := sb.Workspace()
	// Verify POSIX rename while file handle is open.
	openFile, err := ws.OpenFile("src/app.go", os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("ws.OpenFile(src/app.go) failed: %v", err)
	}
	if err := ws.Rename("src/app.go", "src/renamed_while_open.go"); err != nil {
		_ = openFile.Close()
		t.Fatalf("ws.Rename on open file failed: %v", err)
	}
	if err := openFile.Close(); err != nil {
		t.Fatalf("close renamed file: %v", err)
	}

	// Verify .gvx_meta symlink and permissions.
	target, err := ws.Readlink("src/link.go")
	if err != nil || target != "app.go" {
		t.Fatalf("ws.Readlink(src/link.go) = (%q, %v), want (\"app.go\", nil)", target, err)
	}
	attr, _, err := ws.Stat("src/renamed_while_open.go")
	if err != nil || (attr.Mode&0o777) != 0o755 {
		t.Fatalf("ws.Stat(src/renamed_while_open.go) mode = %o, err = %v, want 0755", attr.Mode&0o777, err)
	}

	// Verify anti-TOCTOU path traversal and escaping symlinks are rejected.
	if _, err := ws.ReadFile("../../etc/passwd"); err == nil {
		t.Fatalf("ws.ReadFile(../../etc/passwd) succeeded, want ErrPathTraversal")
	}
	if err := ws.Symlink("../../outside", "src/escape_link"); err == nil {
		t.Fatalf("ws.Symlink(../../outside) succeeded, want ErrPathTraversal")
	}
}

func TestE2ENetstackDualTrackNATAndWireGuard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start a host HTTP server on 127.0.0.1 to test guest -> 10.0.2.2 gateway routing.
	hostSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("host-gateway-200-ok"))
	}))
	defer hostSrv.Close()
	hostAddr := hostSrv.Listener.Addr().(*net.TCPAddr)

	httpServerELF, err := testelf.BuildGuestHTTPServerELF64(
		runtime.GOARCH,
		8080,
		"/usr/share/nginx/html/index.html",
		"",
		"",
	)
	if err != nil {
		t.Fatalf("BuildGuestHTTPServerELF64 failed: %v", err)
	}

	nginxLayer := mustTar(t,
		testimage.File{Name: "usr/sbin/nginx", Data: httpServerELF, Mode: 0o755},
		testimage.File{Name: "usr/share/nginx/html/index.html", Data: []byte("<html><body>Welcome to nginx on gvx!</body></html>\n")},
	)

	var stdout, stderr bytes.Buffer
	sbNAT, err := gvx.New(ctx, gvx.Config{
		Platform:            gvx.PlatformAuto,
		NetworkMode:         gvx.NetModeNAT,
		OCICacheDir:         t.TempDir(),
		OCILayerTars:        [][]byte{nginxLayer},
		DisableHostLockdown: true,
		PortForwards: []gvx.PortForward{
			{HostPort: 0, GuestPort: 8080, Protocol: "tcp", BindAddress: "127.0.0.1"},
		},
		Argv:   []string{"/usr/sbin/nginx", "-p", "8080"},
		Stdout: &stdout,
		Stderr: &stderr,
	})
	if err != nil {
		t.Fatalf("gvx.New(NAT) failed: %v", err)
	}
	defer func() {
		_ = sbNAT.Close()
	}()

	type runRes struct {
		code int
		err  error
	}
	natRunCh := make(chan runRes, 1)
	go func() {
		c, rErr := sbNAT.Run(ctx)
		natRunCh <- runRes{code: c, err: rErr}
	}()

	// 1. Test inbound -p port forwarding from host to guest HTTP server inside Sentry kernel.
	boundPort := sbNAT.BoundPort(0)
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(boundPort) + "/")
	if err != nil {
		t.Fatalf("GET inbound forwarded port failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if !strings.Contains(string(body), "Welcome to nginx on gvx!") {
		t.Fatalf("inbound port forward body = %q", string(body))
	}
	if natRes := <-natRunCh; natRes.err != nil || natRes.code != 0 {
		t.Fatalf("sbNAT.Run = (%d, %v)", natRes.code, natRes.err)
	}

	// 2. and 3. need the python and alpine images from the public registry.
	// Part 2 is the positive control for part 3: the same gateway URL works
	// without -isolate-lan and fails with it.
	t.Run("outbound_gateway_and_isolate_lan", func(t *testing.T) {
		requireRegistry(t)
		stdout.Reset()
		stderr.Reset()
		gatewayURL := "http://10.0.2.2:" + strconv.Itoa(hostAddr.Port) + "/"
		sbFetch, err := gvx.New(ctx, gvx.Config{
			Platform:            gvx.PlatformAuto,
			NetworkMode:         gvx.NetModeNAT,
			OCICacheDir:         t.TempDir(),
			OCIImage:            "python:3.12-alpine",
			DisableHostLockdown: true,
			Argv:                []string{"python3", "-S", "-c", "import urllib.request; print(urllib.request.urlopen('" + gatewayURL + "').read().decode('utf-8'), end='')"},
			Stdout:              &stdout,
			Stderr:              &stderr,
		})
		if err != nil {
			t.Fatalf("gvx.New(Fetch) failed: %v", err)
		}
		defer func() {
			_ = sbFetch.Close()
		}()

		if code, err := sbFetch.Run(ctx); err != nil || code != 0 {
			t.Fatalf("sbFetch.Run = (%d, %v) stderr=%q", code, err, stderr.String())
		}
		if stdout.String() != "host-gateway-200-ok" {
			t.Fatalf("outbound gateway fetch = %q, want %q", stdout.String(), "host-gateway-200-ok")
		}

		sbIso, err := gvx.New(ctx, gvx.Config{
			Platform:            gvx.PlatformAuto,
			NetworkMode:         gvx.NetModeNAT,
			IsolateLAN:          true,
			OCICacheDir:         t.TempDir(),
			OCIImage:            "alpine:3.20",
			DisableHostLockdown: true,
			Argv:                []string{"wget", "-qO-", "-T", "2", gatewayURL},
			Stdout:              io.Discard,
			Stderr:              io.Discard,
		})
		if err != nil {
			t.Fatalf("gvx.New(IsolateLAN) failed: %v", err)
		}
		defer func() {
			_ = sbIso.Close()
		}()
		if code, _ := sbIso.Run(ctx); code == 0 {
			t.Fatalf("sbIso.Run succeeded with IsolateLAN=true, want non-zero failure")
		}
	})

	// 4. Test Track B (-net=wg): the guest Netstack exchanges UDP datagrams with
	// a real wireguard-go peer through the in-memory device and the one
	// pre-bound UDP socket. The peer never knew the guest address, so the
	// guest starts the handshake.
	curve := ecdh.X25519()
	guestPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate guest WireGuard key: %v", err)
	}
	peerPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate peer WireGuard key: %v", err)
	}
	var guestPrivBytes, guestPubBytes, peerPrivBytes, peerPubBytes [32]byte
	copy(guestPrivBytes[:], guestPriv.Bytes())
	copy(guestPubBytes[:], guestPriv.PublicKey().Bytes())
	copy(peerPrivBytes[:], peerPriv.Bytes())
	copy(peerPubBytes[:], peerPriv.PublicKey().Bytes())

	guestIP := netip.MustParseAddr("10.0.2.15")
	wgPeer := startWireGuardPeer(t, peerPrivBytes, guestPubBytes, guestIP)

	sbWG, err := gvx.New(ctx, gvx.Config{
		Platform:            gvx.PlatformAuto,
		NetworkMode:         gvx.NetModeWireGuard,
		OCICacheDir:         t.TempDir(),
		DisableHostLockdown: true,
		WireGuardConfig: &netbackend.WireGuardConfig{
			PrivateKey:    guestPrivBytes,
			PeerPublicKey: peerPubBytes,
			PeerEndpoint:  wgPeer.endpoint,
			GuestIPv4:     netip.PrefixFrom(guestIP, 24),
			MTU:           netbackend.DefaultWireGuardMTU,
		},
		Argv: []string{"true"},
	})
	if err != nil {
		t.Fatalf("gvx.New(WireGuard) failed: %v", err)
	}
	defer func() {
		_ = sbWG.Close()
	}()

	remote := netip.MustParseAddrPort("198.51.100.1:9999")
	udpConn, err := gonet.DialUDP(sbWG.Stack(), nil, &tcpip.FullAddress{
		NIC:  netbackend.Eth0NICID,
		Addr: tcpip.AddrFrom4(remote.Addr().As4()),
		Port: remote.Port(),
	}, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("gonet.DialUDP over WireGuard stack failed: %v", err)
	}
	defer func() {
		_ = udpConn.Close()
	}()
	if _, err := udpConn.Write([]byte("wg-e2e-payload")); err != nil {
		t.Fatalf("udpConn.Write over WireGuard failed: %v", err)
	}

	// The peer decrypts the datagram with its own wireguard-go device.
	const wgWait = 15 * time.Second
	src, dst, payload := wgPeer.readUDPv4(t, wgWait)
	if src.Addr() != guestIP || dst != remote || string(payload) != "wg-e2e-payload" {
		t.Fatalf("peer received %s -> %s %q, want %s -> %s %q", src, dst, payload, guestIP, remote, "wg-e2e-payload")
	}

	// The reply travels the other way and reaches the guest socket.
	wgPeer.sendPacket(t, buildUDPv4Packet(remote, src, []byte("wg-e2e-reply")), wgWait)
	if err := udpConn.SetReadDeadline(time.Now().Add(wgWait)); err != nil {
		t.Fatalf("udpConn.SetReadDeadline failed: %v", err)
	}
	reply := make([]byte, 64)
	n, err := udpConn.Read(reply)
	if err != nil || string(reply[:n]) != "wg-e2e-reply" {
		t.Fatalf("guest read = (%q, %v), want %q", reply[:n], err, "wg-e2e-reply")
	}
}

func TestE2ERealLinuxBusyboxPythonNodeAcrossBackends(t *testing.T) {
	platforms := []gvx.PlatformType{autoPlatform()}

	workcases := []struct {
		name       string
		image      string
		argv       []string
		wantSubstr string
	}{
		{
			name:       "busybox_musl",
			image:      "busybox:1.36.1-musl",
			argv:       []string{"sh", "-c", "uname -s && echo busybox-ok | tr a-z A-Z"},
			wantSubstr: "Linux\nBUSYBOX-OK",
		},
		{
			name:  "python3_alpine",
			image: "python:3.12-alpine",
			argv: []string{
				"python3", "-S", "-c",
				`import sys, math, hashlib, json; print(json.dumps({"py": sys.version.split()[0], "pi": round(math.pi, 4), "sha256": hashlib.sha256(b"gvx").hexdigest()[:8]}))`,
			},
			wantSubstr: `"sha256": "6ca05ce9"`,
		},
		{
			name:  "nodejs_alpine",
			image: "node:22-alpine",
			argv: []string{
				"node", "-e",
				`const crypto = require("crypto"); console.log(JSON.stringify({node: process.version, arch: process.arch, sha256: crypto.createHash("sha256").update("gvx").digest("hex").slice(0, 8)}))`,
			},
			wantSubstr: `"sha256":"6ca05ce9"`,
		},
	}

	for _, plat := range platforms {
		for _, tc := range workcases {
			t.Run(string(plat)+"_"+tc.name, func(t *testing.T) {
				requireRegistry(t)
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				var stdout, stderr bytes.Buffer
				sb, err := gvx.New(ctx, gvx.Config{
					Platform:            plat,
					NetworkMode:         gvx.NetModeNone,
					OCIImage:            tc.image,
					WorkspacePath:       t.TempDir(),
					Argv:                tc.argv,
					Stdout:              &stdout,
					Stderr:              &stderr,
					DisableHostLockdown: true,
				})
				if err != nil {
					t.Fatalf("gvx.New(%s, %s) failed: %v", plat, tc.image, err)
				}
				defer func() {
					_ = sb.Close()
				}()

				code, err := sb.Run(ctx)
				if err != nil || code != 0 {
					t.Fatalf("sb.Run(%s, %s) = (%d, %v)\nstdout=%s\nstderr=%s", plat, tc.image, code, err, stdout.String(), stderr.String())
				}
				if !strings.Contains(stdout.String(), tc.wantSubstr) {
					t.Fatalf("stdout = %q, want substring %q", stdout.String(), tc.wantSubstr)
				}
			})
		}
	}
}

// systrapStaticBase is a link address that the macOS systrap engine allows.
// Its guest addresses start above the host reservations, which end at 0x7000000000
// on Apple silicon, so the address sits at 16TB.
const systrapStaticBase = 0x1000_0000_0000

func TestE2ESystrapStaticAndDynamicELF64(t *testing.T) {
	systraptest.Require(t)
	staticELF, err := testelf.BuildGuestELF64At(runtime.GOARCH, systrapStaticBase, 0, "systrap-static-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64At failed: %v", err)
	}
	dynamicELF, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 7, "systrap-dynamic-ok\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}
	for _, tc := range []struct {
		name     string
		elf      []byte
		wantCode int
		wantOut  string
	}{
		{"static", staticELF, 0, "systrap-static-ok\n"},
		{"dynamic", dynamicELF, 7, "systrap-dynamic-ok\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, backend := runELF(t, gvx.PlatformSystrap, tc.elf)
			if code != tc.wantCode || stdout != tc.wantOut || backend != "systrap" {
				t.Fatalf("%s on systrap = (code %d, stdout %q, backend %q), want (%d, %q, systrap)", tc.name, code, stdout, backend, tc.wantCode, tc.wantOut)
			}
		})
	}
}

func TestE2ESystrapWorkspaceWrite(t *testing.T) {
	systraptest.Require(t)
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/out.txt", "systrap-wrote\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	workspace := t.TempDir()
	sb, err := gvx.New(context.Background(), gvx.Config{
		Platform:            gvx.PlatformSystrap,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         t.TempDir(),
		ELFBytes:            guestELF,
		WorkspacePath:       workspace,
		Stdout:              io.Discard,
		Stderr:              io.Discard,
		DisableHostLockdown: true,
	})
	if err != nil {
		t.Fatalf("gvx.New(systrap) failed: %v", err)
	}
	defer func() {
		_ = sb.Close()
	}()
	code, err := sb.Run(context.Background())
	got, readErr := os.ReadFile(filepath.Join(workspace, "out.txt"))
	if err != nil || code != 0 || readErr != nil || string(got) != "systrap-wrote\n" {
		t.Fatalf("workspace write on systrap = (code %d, err %v, file %q, read err %v), want (0, nil, %q)", code, err, got, readErr, "systrap-wrote\n")
	}
}

func TestE2ESystrapHostLockdownDefault(t *testing.T) {
	systraptest.Require(t)
	probe := toolPath(t, lockdownProbePkg)
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/guest.txt", "systrap-locked\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	workspace := t.TempDir()
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	stdout, stderr, code := runTool(t, probe, "-platform=systrap", "-bin="+elfPath, "-workspace="+workspace,
		"-cache-dir="+t.TempDir(), "-outside-file="+secret, "-outside-dir="+outside)
	if code != 0 {
		t.Fatalf("lockdownprobe exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	var rep lockdownprobe.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		t.Fatalf("decode probe report %q: %v", stdout, err)
	}
	if rep.Platform != "systrap" || !rep.Lockdown.Applied || !rep.LockedAPI {
		t.Errorf("platform %q, lockdown %+v, IsLockedDown %v, want systrap and a default lockdown", rep.Platform, rep.Lockdown, rep.LockedAPI)
	}
	if rep.ReadOutsideErr == "" || rep.WriteOutsideErr == "" || rep.SpawnErr == "" {
		t.Errorf("escape probes after lockdown: read %q write %q spawn %q, want three refusals", rep.ReadOutsideErr, rep.WriteOutsideErr, rep.SpawnErr)
	}
	if rep.GuestRunErr != "" || rep.GuestExitCode != 0 {
		t.Errorf("guest run under systrap and lockdown = (code %d, err %q), want (0, none)", rep.GuestExitCode, rep.GuestRunErr)
	}
	got, err := os.ReadFile(filepath.Join(workspace, "guest.txt"))
	if err != nil || string(got) != "systrap-locked\n" {
		t.Errorf("workspace guest.txt = (%q, %v), want the guest write under systrap and lockdown", got, err)
	}
}

func TestE2ERungvSystrapDefaultLockdown(t *testing.T) {
	systraptest.Require(t)
	rungv := toolPath(t, rungvPkg)
	guestELF, err := testelf.BuildGuestWriteFileELF64(runtime.GOARCH, "/workspace/cli.txt", "cli-systrap\n")
	if err != nil {
		t.Fatalf("BuildGuestWriteFileELF64 failed: %v", err)
	}
	elfPath := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	workspace := t.TempDir()
	stdout, stderr, code := runTool(t, rungv, "run", "-platform=systrap", "-net=none",
		"-cache-dir="+t.TempDir(), "-workspace="+workspace, elfPath)
	if code != 0 {
		t.Fatalf("rungv run -platform=systrap exit code = %d\nstdout=%s\nstderr=%s", code, stdout, stderr)
	}
	if got, err := os.ReadFile(filepath.Join(workspace, "cli.txt")); err != nil || string(got) != "cli-systrap\n" {
		t.Fatalf("workspace cli.txt = (%q, %v), want the guest write", got, err)
	}

	stdout, stderr, code = runTool(t, rungv, "stub")
	if code != 0 || !strings.HasPrefix(stdout, "systrap stub ok\n") {
		t.Fatalf("rungv stub = (code %d, stdout %q, stderr %q), want a handshake report", code, stdout, stderr)
	}
}

// runImageShell runs argv in image under systrap with the lockdown off and
// returns stdout. Real images need the public registry.
func runImageShell(t *testing.T, image string, argv ...string) string {
	t.Helper()
	requireRegistry(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var stdout, stderr bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            gvx.PlatformSystrap,
		NetworkMode:         gvx.NetModeNone,
		OCIImage:            image,
		WorkspacePath:       t.TempDir(),
		Argv:                argv,
		Stdout:              &stdout,
		Stderr:              &stderr,
		DisableHostLockdown: true,
	})
	if err != nil {
		t.Fatalf("gvx.New(systrap, %s) failed: %v", image, err)
	}
	defer func() {
		_ = sb.Close()
	}()
	code, err := sb.Run(ctx)
	if err != nil || code != 0 {
		t.Fatalf("sb.Run(systrap, %s %v) = (%d, %v)\nstdout=%s\nstderr=%s", image, argv, code, err, stdout.String(), stderr.String())
	}
	return stdout.String()
}

func TestE2ESystrapBusyboxPipeline(t *testing.T) {
	systraptest.Require(t)
	requireRegistry(t)
	for i := range 50 {
		got := runImageShell(t, "busybox:1.36.1-musl", "sh", "-c", "echo a | cat; echo hi")
		if got != "a\nhi\n" {
			t.Fatalf("iteration %d: pipeline stdout = %q, want %q", i, got, "a\nhi\n")
		}
	}
}

func TestE2ESystrapPythonAlpine(t *testing.T) {
	systraptest.Require(t)
	got := runImageShell(t, "python:3.12-alpine", "python3", "-S", "-c",
		`import hashlib, json; print(json.dumps({"sha256": hashlib.sha256(b"gvx").hexdigest()[:8]}))`)
	if !strings.Contains(got, `"sha256": "6ca05ce9"`) {
		t.Fatalf("python stdout = %q, want the sha256 prefix", got)
	}
}
