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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/pkg/gvx"
)

// Acceptance gate for executables that link at a fixed address (type
// ET_EXEC). Four real programs must print the same output on every backend.
// They are a static Go program, a static C program, the herdr schema command,
// and the herdr server with one request. The macOS systrap engine cannot hold
// such an image, because every arm64 task there has a 4GB PAGEZERO. Its
// subtests skip while the error names that cause. The extra backend
// systrap-zone turns on the prototype zone mode of that engine, and it runs
// the four programs.

// fixedAddressBackends lists each backend once. On Linux the hardware entry
// and the systrap entry are the same platform.
func fixedAddressBackends() []gateBackend {
	var out []gateBackend
	seen := map[gvx.PlatformType]bool{}
	for _, b := range gateBackends() {
		if !seen[b.plat] {
			seen[b.plat] = true
			out = append(out, b)
		}
	}
	return out
}

// requireFixedAddressBackend skips the subtest when the backend cannot start
// for a documented reason.
func requireFixedAddressBackend(t *testing.T, b gateBackend) {
	t.Helper()
	if b.plat == gvx.PlatformHVF || b.plat == gvx.PlatformWHPX {
		if childBuildTags != "" {
			t.Skip("the hardware backends keep 4KB guest pages; this build has larger pages")
		}
		hvtest.Require(t)
		return
	}
	requireBackend(t, b)
}

// skipWhenFixedAddressRefused skips the test when err is the refusal of an
// engine that cannot hold an ET_EXEC image, and fails it on any other error.
func skipWhenFixedAddressRefused(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if msg := err.Error(); strings.Contains(msg, "not position-independent") || strings.Contains(msg, "cannot hold the zone") {
		t.Skipf("this engine cannot hold an executable that links at a fixed address: %v", err)
	}
	t.Fatalf("%s: %v", what, err)
}

// runHostProgram runs the executable at path as the only guest process. It
// returns the exit code and the output, and the error of New or Run.
func runHostProgram(t *testing.T, plat gvx.PlatformType, path string, argv, envv []string) (code int, stdout, stderr string, err error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         sharedCacheDir(t),
		BinaryPath:          path,
		Argv:                argv,
		Envv:                envv,
		Stdout:              &outBuf,
		Stderr:              &errBuf,
		DisableHostLockdown: true,
	})
	if err != nil {
		return 0, "", "", err
	}
	defer func() {
		if cerr := sb.Close(); cerr != nil {
			t.Errorf("Close(%s) failed: %v", plat, cerr)
		}
	}()
	code, err = sb.Run(ctx)
	return code, outBuf.String(), errBuf.String(), err
}

// expectProgramOutput runs the program and requires exit code 0 and the exact
// output.
func expectProgramOutput(t *testing.T, b gateBackend, path string, argv, envv []string, want string) {
	t.Helper()
	code, stdout, stderr, err := runHostProgram(t, b.plat, path, argv, envv)
	skipWhenFixedAddressRefused(t, "run the program", err)
	if code != 0 || stdout != want {
		t.Fatalf("program = (%d) stdout %q stderr %q, want (0) %q", code, stdout, stderr, want)
	}
}

func TestE2EGateETExecGoStatic(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			path := acceptprog.BuildGoStatic(t, hostArch())
			expectProgramOutput(t, b, path, nil, nil, acceptprog.GoStaticWant)
		})
	}
}

var (
	cStaticOnce sync.Once
	cStaticPath string
	cStaticErr  string
)

// buildCStatic compiles the static C program once per test run inside an
// Alpine guest. Prefer the hypervisor backend when the host has one, because
// this step only builds the fixture. The test loop below then runs the binary
// on each backend that the file tests.
func buildCStatic(t *testing.T) string {
	t.Helper()
	requireRegistry(t)
	cStaticOnce.Do(func() {
		dir := filepath.Join(sharedCacheDir(t), "etexec-cstatic")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			cStaticErr = "create the build directory: " + err.Error()
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "main.c"), acceptprog.CStaticSource, 0o644); err != nil {
			cStaticErr = "write the source: " + err.Error()
			return
		}
		plat := gvx.PlatformSystrap
		if hvtest.Available() {
			plat = autoPlatform()
		}
		script := "apk add --no-cache build-base >/dev/null && gcc -O2 -static -no-pie -o /workspace/cstatic /workspace/main.c"
		code, stdout, stderr, err := runGuestQuiet(guestSpec{
			plat:      plat,
			image:     "alpine:3.20",
			argv:      []string{"/bin/sh", "-c", script},
			workspace: dir,
			net:       gvx.NetModeNAT,
			timeout:   20 * time.Minute,
		}, sharedCacheDir(t))
		if err != nil || code != 0 {
			cStaticErr = fmt.Sprintf("compile in the guest: exit %d, error %v, stdout %q, stderr %q", code, err, stdout, stderr)
			return
		}
		cStaticPath = filepath.Join(dir, "cstatic")
	})
	if cStaticErr != "" {
		t.Fatalf("build the static C program: %s", cStaticErr)
	}
	return cStaticPath
}

// runGuestQuiet runs a guest to completion and returns the error of New or
// Run. It calls no test method, so a step inside sync.Once can use it.
func runGuestQuiet(g guestSpec, cache string) (code int, stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), g.timeout)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	sb, err := gvx.New(ctx, g.config(cache, &outBuf, &errBuf))
	if err != nil {
		return 0, "", "", err
	}
	defer func() { _ = sb.Close() }()
	code, err = sb.Run(ctx)
	return code, outBuf.String(), errBuf.String(), err
}

func TestE2EGateETExecCStatic(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			path := buildCStatic(t)
			expectProgramOutput(t, b, path, nil, nil, acceptprog.CStaticWant)
		})
	}
}

// herdrEnv gives herdr a home directory. Without one, herdr panics at start.
var herdrEnv = []string{"HOME=/tmp"}

func TestE2EGateETExecHerdrSchema(t *testing.T) {
	var reference string
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			path := acceptprog.FetchHerdr(t, hostArch())
			code, stdout, stderr, err := runHostProgram(t, b.plat, path, []string{"api", "schema", "--json"}, herdrEnv)
			skipWhenFixedAddressRefused(t, "run herdr", err)
			if code != 0 || !json.Valid([]byte(stdout)) || !strings.Contains(stdout, `"protocol"`) {
				t.Fatalf("herdr api schema = (%d) %d bytes of output, stderr %q, want exit 0 and the JSON schema", code, len(stdout), stderr)
			}
			if reference == "" {
				reference = stdout
			} else if stdout != reference {
				t.Errorf("herdr api schema on %s differs from the first backend that ran", b.name)
			}
		})
	}
}

// herdrServerScript starts the herdr server, waits until it answers a request,
// prints the answer, and stops the server.
const herdrServerScript = `export HOME=/tmp/h && mkdir -p $HOME &&
cp /workspace/herdr /usr/local/bin/herdr && chmod 755 /usr/local/bin/herdr &&
(herdr server >/tmp/server.log 2>&1 &) &&
i=0 &&
until herdr workspace list >/tmp/list.txt 2>/dev/null; do
  i=$((i+1))
  if [ $i -ge 120 ]; then echo "the server gave no answer"; cat /tmp/server.log; exit 1; fi
  sleep 0.5
done &&
cat /tmp/list.txt &&
herdr server stop >/dev/null 2>&1; exit 0`

func TestE2EGateETExecHerdrServer(t *testing.T) {
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			requireRegistry(t)
			herdr := acceptprog.FetchHerdr(t, hostArch())
			// The shell starts herdr through exec, so an engine that refuses the
			// image tells only the shell. Ask the engine first.
			_, _, _, probeErr := runHostProgram(t, b.plat, herdr, []string{"--version"}, herdrEnv)
			skipWhenFixedAddressRefused(t, "run herdr --version", probeErr)
			dir := t.TempDir()
			data, err := os.ReadFile(herdr)
			if err != nil {
				t.Fatalf("read herdr: %v", err)
			}
			if err := os.WriteFile(filepath.Join(dir, "herdr"), data, 0o755); err != nil {
				t.Fatalf("copy herdr into the workspace: %v", err)
			}
			code, stdout, stderr, err := runGuestQuiet(guestSpec{
				plat:      b.plat,
				image:     "alpine:3.20",
				argv:      []string{"/bin/sh", "-c", herdrServerScript},
				workspace: dir,
				timeout:   10 * time.Minute,
			}, sharedCacheDir(t))
			skipWhenFixedAddressRefused(t, "run the herdr server", err)
			if code != 0 || stdout != acceptprog.HerdrWorkspaceListWant {
				t.Fatalf("herdr server = (%d) stdout %q stderr %q, want (0) %q", code, stdout, stderr, acceptprog.HerdrWorkspaceListWant)
			}
		})
	}
}
