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

//go:build linux

package e2e

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/internal/testelf"
)

// staticRungv builds a rungv binary without cgo. A guest has no dynamic
// loader for the host libc, so only a static binary runs in it.
func staticRungv(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "rungv-static")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, rungvPkg)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+runtime.GOARCH)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s failed: %v\n%s", rungvPkg, err, combined)
	}
	return out
}

// TestE2ENestedRungvInRungv runs rungv with systrap inside a guest of rungv
// with systrap. The inner Sentry needs ptrace, seccomp, shared memory, the
// futex calls, and the signal frame of the architecture from the guest
// kernel. docs/cli.md section 11 lists the limits.
func TestE2ENestedRungvInRungv(t *testing.T) {
	systraptest.Require(t)
	if runtime.GOARCH != "arm64" {
		// The inner guest starts and then makes no progress on amd64.
		t.Skip("nested systrap runs only on arm64; docs/cli.md section 11 lists the amd64 limit")
	}
	inner := staticRungv(t)
	elfData, err := testelf.BuildDynamicGuestELF64(runtime.GOARCH, 0, "nested-ok\n")
	if err != nil {
		t.Fatalf("BuildDynamicGuestELF64 failed: %v", err)
	}
	smoke := filepath.Join(t.TempDir(), "smoke")
	if err := os.WriteFile(smoke, elfData, 0o755); err != nil {
		t.Fatalf("write the guest binary: %v", err)
	}

	outer := toolPath(t, rungvPkg)
	stdout, stderr, code := runTool(t, outer,
		"run", "-platform=systrap", "-v", smoke+":/smoke:ro", "-bin", inner,
		"--", "run", "-platform=systrap", "-bin", "/smoke")
	if code != 0 || !strings.Contains(stdout, "nested-ok") {
		t.Fatalf("nested run = (%d, %q), want (0, output with nested-ok)\nstderr=%s", code, stdout, stderr)
	}
}
