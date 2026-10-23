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

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/internal/testimage"
)

func otherArch() string {
	if runtime.GOARCH == "arm64" {
		return "amd64"
	}
	return "arm64"
}

func hypervisorName() string {
	if runtime.GOOS == "windows" {
		return "whpx"
	}
	return "hvf"
}

// runCLI runs executeCLI in-process. Every run call passes -lockdown=false,
// because the default lockdown would confine the test binary.
func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code = executeCLI(context.Background(), args, nil, &outBuf, &errBuf)
	return code, outBuf.String(), errBuf.String()
}

func writeELF(t *testing.T, elfData []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "guest.elf")
	if err := os.WriteFile(p, elfData, 0o755); err != nil {
		t.Fatalf("write guest ELF: %v", err)
	}
	return p
}

func TestRunELFReportsAutoBackend(t *testing.T) {
	hvtest.Require(t)
	elfData, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "elf-cli-ok\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	elfPath := writeELF(t, elfData)

	code, stdout, stderr := runCLI(t, "run", "-lockdown=false", "-platform=auto", "-net=none", "-cache-dir="+t.TempDir(), elfPath)
	if code != 0 || stdout != "elf-cli-ok\n" {
		t.Fatalf("rungv run <elf> = (code %d, stdout %q, stderr %q), want (0, %q)", code, stdout, stderr, "elf-cli-ok\n")
	}
	if !strings.Contains(stderr, "rungv: platform="+hypervisorName()) {
		t.Fatalf("stderr = %q, want the resolved auto backend %q", stderr, hypervisorName())
	}
	if !strings.Contains(stderr, "lockdown disabled") {
		t.Fatalf("stderr = %q, want the opt-out warning", stderr)
	}

	// An explicit backend prints no selection line.
	code, _, stderr = runCLI(t, "run", "-lockdown=false", "-platform="+hypervisorName(), "-net=none", "-cache-dir="+t.TempDir(), elfPath)
	if code != 0 || strings.Contains(stderr, "platform=") {
		t.Fatalf("explicit backend run = (code %d, stderr %q), want success without a selection line", code, stderr)
	}
}

func TestRunConfigurationErrorsExitWithUsageCode(t *testing.T) {
	elfData, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "x\n")
	if err != nil {
		t.Fatalf("BuildGuestELF64 failed: %v", err)
	}
	elfPath := writeELF(t, elfData)
	cache := "-cache-dir=" + t.TempDir()

	for _, tc := range []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{"port forward with none", []string{"-net=none", "-p", "8080:80"}, 2, "port forwards"},
		{"port forward with wireguard", []string{"-net=wg", "-wg-conf=x.conf", "-p", "8080:80"}, 2, "port forwards"},
		{"wireguard without config", []string{"-net=wg"}, 2, "WireGuardConfig"},
		{"unknown architecture", []string{"-arch=mips"}, 2, "mips"},
		{"foreign architecture", []string{"-arch=" + otherArch()}, 2, "systrap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"run", "-lockdown=false", cache}, tc.args...)
			code, _, stderr := runCLI(t, append(args, elfPath)...)
			if code != tc.wantCode || !strings.Contains(stderr, tc.wantStderr) {
				t.Fatalf("rungv %v = (code %d, stderr %q), want (code %d, stderr containing %q)", tc.args, code, stderr, tc.wantCode, tc.wantStderr)
			}
		})
	}
}

func TestPullAndRunRegistryImage(t *testing.T) {
	catELF, err := testelf.BuildGuestCatELF64(runtime.GOARCH)
	if err != nil {
		t.Fatalf("BuildGuestCatELF64 failed: %v", err)
	}
	foreignCat, err := testelf.BuildGuestCatELF64(otherArch())
	if err != nil {
		t.Fatalf("BuildGuestCatELF64(%s) failed: %v", otherArch(), err)
	}
	layer := func(cat []byte, marker string) []byte {
		data, err := testimage.Tar(
			testimage.File{Name: "bin/cat", Data: cat, Mode: 0o755},
			testimage.File{Name: "etc/marker", Data: []byte(marker + "\n")},
		)
		if err != nil {
			t.Fatalf("testimage.Tar failed: %v", err)
		}
		return data
	}
	baseURL := testimage.NewRegistry(t, "gvx/cli", "1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{layer(catELF, "host-arch")}},
		testimage.Image{Arch: otherArch(), Layers: [][]byte{layer(foreignCat, "foreign-arch")}},
	)
	cacheDir := t.TempDir()

	code, stdout, stderr := runCLI(t, "pull", "-cache-dir="+cacheDir, "-registry-url="+baseURL, "gvx/cli:1")
	if code != 0 || !strings.Contains(stdout, "Digest: sha256:") || !strings.Contains(stdout, "Status: Downloaded newer image for") {
		t.Fatalf("rungv pull = (code %d, stdout %q, stderr %q)", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, "pull", "-arch="+otherArch(), "-cache-dir="+cacheDir, "-registry-url="+baseURL, "gvx/cli:1")
	if code != 0 {
		t.Fatalf("rungv pull -arch=%s = (code %d, stdout %q, stderr %q)", otherArch(), code, stdout, stderr)
	}
	code, _, stderr = runCLI(t, "pull", "-arch=s390x", "-cache-dir="+t.TempDir(), "-registry-url="+baseURL, "gvx/cli:1")
	if code != 1 {
		t.Fatalf("rungv pull -arch=s390x = (code %d, stderr %q), want 1", code, stderr)
	}

	code, stdout, stderr = runCLI(t, "run", "-lockdown=false", "-net=none",
		"-cache-dir="+cacheDir, "-registry-url="+baseURL, "-image=gvx/cli:1", "--", "/bin/cat", "/etc/marker")
	if code != 0 || stdout != "host-arch\n" {
		t.Fatalf("rungv run -image = (code %d, stdout %q, stderr %q), want (0, %q)", code, stdout, stderr, "host-arch\n")
	}
}

// TestRunPlatformSystrap runs a guest under -platform=systrap where the engine
// starts, and checks the typed engine error elsewhere.
func TestRunPlatformSystrap(t *testing.T) {
	elfData, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 5, "systrap-cli\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}
	elfPath := writeELF(t, elfData)
	code, stdout, stderr := runCLI(t, "run", "-lockdown=false", "-platform=systrap", "-net=none", "-cache-dir="+t.TempDir(), elfPath)

	if !systraptest.Available(t) {
		want := "unavailable"
		if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
			want = "pagesize_16k"
		}
		if code != 1 || stdout != "" || !strings.Contains(stderr, want) {
			t.Fatalf("rungv run -platform=systrap = (code %d, stdout %q, stderr %q), want (1, empty, error containing %q)", code, stdout, stderr, want)
		}
		return
	}
	if code != 5 || stdout != "systrap-cli\n" {
		t.Fatalf("rungv run -platform=systrap = (code %d, stdout %q, stderr %q), want (5, %q)", code, stdout, stderr, "systrap-cli\n")
	}
	if strings.Contains(stderr, "platform=") {
		t.Fatalf("explicit backend printed a selection line: %q", stderr)
	}
}
