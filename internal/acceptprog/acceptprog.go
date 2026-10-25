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

// Package acceptprog provides the guest programs that decide whether an
// execution backend runs executables that link at a fixed address (type
// ET_EXEC). Each program is a real executable, not a synthetic image: a static
// Go program, a static C program, and the herdr release binary.
package acceptprog

import (
	"crypto/sha256"
	"debug/elf"
	_ "embed"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// CStaticSource is the source of the static C program. Build it in a guest
// with gcc -O2 -static -no-pie.
//
//go:embed cstatic/main.c
var CStaticSource []byte

const (
	// GoStaticWant is the output of the static Go program on every backend.
	GoStaticWant = "sum 4004000\ngc ok\nframes main.frameNames main.main\npreempt ok\nrecover boom\n"

	// CStaticWant is the output of the static C program on every backend.
	CStaticWant = "one=1\ntwo=2\nthree=3\napple fig kiwi pear \nop0=11\nop1=20\n" +
		"identity next==&n2:1 lock_ptr==&lock:1 op0==add_one:1\ntotal 120000\nlongjmp ok\n"

	// HerdrWorkspaceListWant is the answer of a fresh herdr server to the
	// request that lists workspaces.
	HerdrWorkspaceListWant = `{"id":"cli:workspace:list","result":{"type":"workspace_list","workspaces":[]}}` + "\n"

	goStaticPackage    = "z.gfire.dev/gvx/internal/acceptprog/gostatic"
	volTreePackage     = "z.gfire.dev/gvx/internal/acceptprog/voltree"
	compatProbePackage = "z.gfire.dev/gvx/internal/acceptprog/compatprobe"
	herdrReleaseURL    = "https://github.com/herdrdev/herdr/releases/download/v0.9.5/"
)

// herdrAssets maps a Linux architecture to the herdr v0.9.5 release file and
// the SHA-256 digest that GitHub publishes for it. The arm64 file is an
// ET_EXEC image that links at 0x400000. The amd64 file is position-independent.
var herdrAssets = map[string]struct{ name, sha256 string }{
	"arm64": {"herdr-linux-aarch64", "17d7536f2da50859523680ef279dffcac8e4a235f4e46fe8da6c2ec44141897c"},
	"amd64": {"herdr-linux-x86_64", "14d9e8bc8b4a9e0118d77c32266f76d461f09b40342eb23752960bd89f59929d"},
}

// BuildGoStatic compiles the static Go program for the Linux architecture
// goarch and returns the path of the executable. It fails the test when the
// toolchain does not produce an ET_EXEC image, because the acceptance
// criterion needs one.
func BuildGoStatic(tb testing.TB, goarch string) string {
	tb.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	out := filepath.Join(tb.TempDir(), "gostatic")
	cmd := exec.Command(goTool, "build", "-o", out, "-ldflags=-linkmode=internal", goStaticPackage)
	cmd.Dir = moduleRoot(tb)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("build the static Go program for linux/%s: %v\n%s", goarch, err, msg)
	}
	f, err := elf.Open(out)
	if err != nil {
		tb.Fatalf("open the static Go program: %v", err)
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC {
		tb.Fatalf("the static Go program has type %v, want ET_EXEC", f.Type)
	}
	return out
}

// FetchHerdr returns the path of the herdr release binary for goarch. It
// downloads the file into a cache directory below the temporary directory of
// the host, and it verifies the SHA-256 digest. It skips the test when
// GVX_E2E_OFFLINE is 1. It also skips when the download fails and
// GVX_E2E_REQUIRE_NETWORK is empty.
func FetchHerdr(tb testing.TB, goarch string) string {
	tb.Helper()
	asset, ok := herdrAssets[goarch]
	if !ok {
		tb.Fatalf("no herdr release for linux/%s", goarch)
	}
	dir := filepath.Join(os.TempDir(), "gvx-acceptprog-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("create the herdr cache directory: %v", err)
	}
	path := filepath.Join(dir, asset.sha256+"-"+asset.name)
	if fileDigest(path) == asset.sha256 {
		return path
	}
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		tb.Skip("herdr download is off (GVX_E2E_OFFLINE=1)")
	}
	if err := download(herdrReleaseURL+asset.name, path); err != nil {
		if os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "" {
			tb.Fatalf("download herdr: %v", err)
		}
		tb.Skipf("download herdr: %v", err)
	}
	if got := fileDigest(path); got != asset.sha256 {
		_ = os.Remove(path)
		tb.Fatalf("herdr digest = %s, want %s", got, asset.sha256)
	}
	return path
}

// moduleRoot returns the directory of the go.mod file of this module.
func moduleRoot(tb testing.TB) string {
	tb.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		tb.Fatal("locate the source of package acceptprog")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// fileDigest returns the SHA-256 digest of a file in hexadecimal, or an empty
// string when the file cannot be read.
func fileDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// download writes the body of url to path through a temporary file. An
// interrupted download then never leaves a partial file under the final name.
func download(url, path string) error {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o755); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// BuildVolumeTree compiles the guest program voltree for the Linux
// architecture goarch and returns the path of the executable. The program
// writes a tree into a volume and verifies it in a later sandbox.
func BuildVolumeTree(tb testing.TB, goarch string) string {
	tb.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	out := filepath.Join(tb.TempDir(), "voltree")
	cmd := exec.Command(goTool, "build", "-o", out, "-ldflags=-linkmode=internal", volTreePackage)
	cmd.Dir = moduleRoot(tb)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("build the volume guest for linux/%s: %v\n%s", goarch, err, msg)
	}
	return out
}

// BuildCompatProbe compiles the guest compatibility, fingerprint, and
// benchmark program compatprobe for the Linux architecture goarch and returns
// the path of the static ET_EXEC executable.
func BuildCompatProbe(tb testing.TB, goarch string) string {
	tb.Helper()
	return BuildCompatProbeAt(tb, goarch, 0)
}

// BuildCompatProbeAt compiles compatprobe linked at textAddr when textAddr is
// non-zero, or at the default toolchain address when textAddr is zero.
func BuildCompatProbeAt(tb testing.TB, goarch string, textAddr uint64) string {
	tb.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		goTool = filepath.Join(runtime.GOROOT(), "bin", "go")
	}
	out := filepath.Join(tb.TempDir(), "compatprobe")
	ldflags := "-ldflags=-linkmode=internal"
	if textAddr != 0 {
		ldflags = fmt.Sprintf("-ldflags=-linkmode=internal -T %#x", textAddr)
	}
	cmd := exec.Command(goTool, "build", "-o", out, ldflags, compatProbePackage)
	cmd.Dir = moduleRoot(tb)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+goarch, "CGO_ENABLED=0")
	if msg, err := cmd.CombinedOutput(); err != nil {
		tb.Fatalf("build compatprobe for linux/%s: %v\n%s", goarch, err, msg)
	}
	f, err := elf.Open(out)
	if err != nil {
		tb.Fatalf("open compatprobe: %v", err)
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC {
		tb.Fatalf("compatprobe has type %v, want ET_EXEC", f.Type)
	}
	return out
}
