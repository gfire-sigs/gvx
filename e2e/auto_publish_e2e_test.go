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
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
)

// TestE2EAutoPublishUnderHostLockdown verifies that rungvx --auto-publish
// discovers a guest TCP listener and exposes it on host 127.0.0.1 with host
// lockdown active, without any static -p flag.
func TestE2EAutoPublishUnderHostLockdown(t *testing.T) {
	rungvx := toolPath(t, rungvxPkg)

	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)

			probeLn, err := net.Listen("tcp4", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("reserve free loopback port: %v", err)
			}
			port := uint16(probeLn.Addr().(*net.TCPAddr).Port)
			_ = probeLn.Close()

			workspace := t.TempDir()
			const wantBody = "hello-auto-publish\n"
			if err := os.WriteFile(filepath.Join(workspace, "index.html"), []byte(wantBody), 0o644); err != nil {
				t.Fatalf("write index.html: %v", err)
			}

			guestELF, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, port, "/workspace/index.html", "", "")
			if err != nil {
				t.Fatalf("BuildGuestHTTPServerELF64: %v", err)
			}
			elfPath := filepath.Join(t.TempDir(), "httpserver.elf")
			if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
				t.Fatalf("write guest ELF: %v", err)
			}

			wait := startTool(t, rungvx,
				"run",
				"-backend="+b.name,
				"--auto-publish",
				"--tune", "net.forward.dynamic_poll_interval=50ms",
				"-bin="+elfPath,
				"-workspace="+workspace,
				"-cache-dir="+t.TempDir(),
			)

			targetURL := "http://127.0.0.1:" + strconv.Itoa(int(port)) + "/"
			client := &http.Client{Timeout: 2 * time.Second}
			deadline := time.Now().Add(20 * time.Second)
			var gotBody string
			var lastErr error
			for time.Now().Before(deadline) {
				resp, err := client.Get(targetURL)
				if err != nil {
					lastErr = err
					time.Sleep(50 * time.Millisecond)
					continue
				}
				data, readErr := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				if readErr == nil && resp.StatusCode == http.StatusOK {
					gotBody = string(data)
					lastErr = nil
					break
				}
				lastErr = readErr
				time.Sleep(50 * time.Millisecond)
			}

			stdout, stderr, code := wait()
			if lastErr != nil {
				t.Fatalf("GET %s failed: %v\ncode=%d stdout=%q stderr=%q", targetURL, lastErr, code, stdout, stderr)
			}
			if gotBody != wantBody {
				t.Fatalf("GET %s body = %q, want %q\nstderr=%q", targetURL, gotBody, wantBody, stderr)
			}
			if code != 0 {
				t.Fatalf("rungvx exit code = %d, want 0\nstdout=%q\nstderr=%q", code, stdout, stderr)
			}
			wantNotice := "auto-published 127.0.0.1:" + strconv.Itoa(int(port))
			if !strings.Contains(stderr, wantNotice) {
				t.Fatalf("stderr = %q, want %q", stderr, wantNotice)
			}
		})
	}
}
