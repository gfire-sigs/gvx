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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testelf"
)

func isHostPortBindConflict(stderr string) bool {
	lower := strings.ToLower(stderr)
	return strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "only one usage of each socket address")
}

// TestE2EAutoPublishUnderHostLockdown verifies that rungvx --auto-publish
// discovers a guest TCP listener and exposes it on host 127.0.0.1 with host
// lockdown active, without any static -p flag.
func TestE2EAutoPublishUnderHostLockdown(t *testing.T) {
	rungvx := toolPath(t, rungvxPkg)

	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)

			workspace := t.TempDir()
			const wantBody = "hello-auto-publish\n"
			if err := os.WriteFile(filepath.Join(workspace, "index.html"), []byte(wantBody), 0o644); err != nil {
				t.Fatalf("write index.html: %v", err)
			}

			const maxAttempts = 3
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				probeLn, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatalf("reserve free loopback port: %v", err)
				}
				port := uint16(probeLn.Addr().(*net.TCPAddr).Port)
				_ = probeLn.Close()

				guestELF, err := testelf.BuildGuestHTTPServerELF64(runtime.GOARCH, port, "/workspace/index.html", "", "")
				if err != nil {
					t.Fatalf("BuildGuestHTTPServerELF64: %v", err)
				}
				elfPath := filepath.Join(t.TempDir(), "httpserver.elf")
				if err := os.WriteFile(elfPath, guestELF, 0o755); err != nil {
					t.Fatalf("write guest ELF: %v", err)
				}

				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				stdoutBuf := newCheckpointNotifyBuffer()
				stderrBuf := newCheckpointNotifyBuffer()
				cmd := exec.CommandContext(ctx, rungvx,
					"run",
					"-backend="+b.name,
					"--auto-publish",
					"--tune", "net.forward.dynamic_poll_interval=50ms",
					"-bin="+elfPath,
					"-workspace="+workspace,
					"-cache-dir="+t.TempDir(),
				)
				cmd.Stdout = stdoutBuf
				cmd.Stderr = stderrBuf
				if err := cmd.Start(); err != nil {
					cancel()
					t.Fatalf("start rungvx: %v", err)
				}
				waitCh := make(chan error, 1)
				go func() { waitCh <- cmd.Wait() }()

				waitCmd := func() (string, string, int) {
					err := <-waitCh
					cancel()
					var exitErr *exec.ExitError
					switch {
					case err == nil:
						return stdoutBuf.String(), stderrBuf.String(), 0
					case errors.As(err, &exitErr):
						return stdoutBuf.String(), stderrBuf.String(), exitErr.ExitCode()
					default:
						t.Fatalf("wait rungvx: %v", err)
						return "", "", -1
					}
				}

				targetURL := "http://127.0.0.1:" + strconv.Itoa(int(port)) + "/"
				client := &http.Client{Timeout: 10 * time.Second}
				deadline := time.Now().Add(20 * time.Second)
				var gotBody string
				var gotOK bool
				var firstErr, lastErr error
				var exitedEarly bool
				var waitErr error
				for time.Now().Before(deadline) {
					select {
					case waitErr = <-waitCh:
						exitedEarly = true
					default:
					}
					if exitedEarly {
						break
					}
					resp, err := client.Get(targetURL)
					if err != nil {
						if firstErr == nil {
							firstErr = err
						}
						lastErr = err
						time.Sleep(50 * time.Millisecond)
						continue
					}
					data, readErr := io.ReadAll(resp.Body)
					_ = resp.Body.Close()
					if readErr == nil && resp.StatusCode == http.StatusOK {
						gotBody = string(data)
						gotOK = true
						lastErr = nil
						break
					}
					if readErr == nil {
						readErr = fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
					}
					if firstErr == nil {
						firstErr = readErr
					}
					lastErr = readErr
					time.Sleep(50 * time.Millisecond)
				}

				var stdout, stderr string
				var code int
				if exitedEarly {
					cancel()
					stdout, stderr = stdoutBuf.String(), stderrBuf.String()
					var exitErr *exec.ExitError
					switch {
					case waitErr == nil:
						code = 0
					case errors.As(waitErr, &exitErr):
						code = exitErr.ExitCode()
					default:
						code = -1
					}
				} else {
					if !gotOK {
						cancel()
					}
					stdout, stderr, code = waitCmd()
				}

				if !gotOK && attempt < maxAttempts && isHostPortBindConflict(stderr) {
					t.Logf("attempt %d hit host port %d bind conflict; retrying", attempt, port)
					continue
				}
				if !gotOK {
					t.Fatalf("GET %s failed: last=%v first=%v exitedEarly=%v\ncode=%d stdout=%q stderr=%q",
						targetURL, lastErr, firstErr, exitedEarly, code, stdout, stderr)
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
				return
			}
		})
	}
}
