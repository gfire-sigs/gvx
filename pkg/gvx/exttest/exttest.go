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

// Package exttest exports narrow test-only helpers for extension modules (such
// as z.gfire.dev/gvx/ext) to run real guest probes without importing root
// internal packages. Production packages are forbidden from importing exttest
// by tools/upstream/boundaries.go.
package exttest

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/gvx"
)

// GuestFile describes one file packed into a synthetic OCI layer tar for tests.
type GuestFile struct {
	Name string
	Data []byte
	Mode int64
}

// RequireHardwareHypervisor skips t when no hardware hypervisor is available
// and GVX_ALLOW_NO_HYPERVISOR=1 is set; otherwise fails t if unavailable.
func RequireHardwareHypervisor(t testing.TB) {
	t.Helper()
	hvtest.Require(t)
}

// HardwareHypervisorAvailable reports whether the host hardware hypervisor starts.
func HardwareHypervisorAvailable() bool {
	return hvtest.Available()
}

// RequireSystrap skips t when the systrap engine is unavailable on this host.
func RequireSystrap(t testing.TB) {
	t.Helper()
	systraptest.Require(t)
}

// RequireGuestBackend skips t when neither the host hardware hypervisor nor
// systrap can execute guests in this environment.
func RequireGuestBackend(t testing.TB) {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		hvtest.Require(t)
	case "windows":
		if !hvtest.Available() {
			systraptest.Require(t)
		}
	default:
		systraptest.Require(t)
	}
}

// BuildLayerTar creates an uncompressed tar layer suitable for gvx.Config.OCILayerTars.
func BuildLayerTar(t testing.TB, files ...GuestFile) []byte {
	t.Helper()
	in := make([]testimage.File, len(files))
	for i, f := range files {
		mode := f.Mode
		if mode == 0 {
			mode = 0o644
		}
		in[i] = testimage.File{
			Name: f.Name,
			Data: f.Data,
			Mode: mode,
		}
	}
	data, err := testimage.Tar(in...)
	if err != nil {
		t.Fatalf("exttest.BuildLayerTar: %v", err)
	}
	return data
}

// BuildGuestGoELF compiles a self-contained single-file Go main program as a
// pure-Go Linux ELF64 executable for the host architecture.
func BuildGuestGoELF(t testing.TB, mainSource string) []byte {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain unavailable for compiling guest probe ELF")
	}
	srcDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(srcDir, "go.mod"), []byte("module guestprobe\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatalf("exttest.BuildGuestGoELF write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcDir, "main.go"), []byte(mainSource), 0o644); err != nil {
		t.Fatalf("exttest.BuildGuestGoELF write main.go: %v", err)
	}
	outPath := filepath.Join(srcDir, "probe")
	cmd := exec.Command("go", "build", "-ldflags=-linkmode=internal", "-o", outPath, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("exttest.BuildGuestGoELF build failed: %v\n%s", err, out)
	}
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("exttest.BuildGuestGoELF read ELF: %v", err)
	}
	return data
}

// RunResult holds the captured output and exit status of RunSandbox.
type RunResult struct {
	ExitCode int
	Stdout   string
	Stderr   string
}

// RunSandbox boots a sandbox with cfg (defaulting Platform, NetworkMode,
// OCICacheDir, and DisableHostLockdown for in-process tests), runs it to
// completion, closes it, and returns the result.
func RunSandbox(t testing.TB, ctx context.Context, cfg gvx.Config) (RunResult, error) {
	t.Helper()
	if cfg.Platform == "" {
		cfg.Platform = gvx.PlatformAuto
		cfg.AllowUnconfinedSystrap = runtime.GOOS == "windows"
	}
	if cfg.NetworkMode == "" {
		cfg.NetworkMode = gvx.NetModeNone
	}
	if cfg.OCICacheDir == "" {
		cfg.OCICacheDir = t.TempDir()
	}
	cfg.DisableHostLockdown = true

	var stdout, stderr bytes.Buffer
	if cfg.Stdout == nil {
		cfg.Stdout = &stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = &stderr
	}

	sb, err := gvx.New(ctx, cfg)
	if err != nil {
		return RunResult{ExitCode: 1, Stdout: stdout.String(), Stderr: stderr.String()}, err
	}
	code, runErr := sb.Run(ctx)
	closeErr := sb.Close()
	if runErr == nil {
		runErr = closeErr
	}
	return RunResult{ExitCode: code, Stdout: stdout.String(), Stderr: stderr.String()}, runErr
}
