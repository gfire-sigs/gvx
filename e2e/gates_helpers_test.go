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
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/systraptest"
	"z.gfire.dev/gvx/pkg/gvx"
)

var (
	cacheMu  sync.Mutex
	cacheDir string
)

// sharedCacheDir returns one EROFS layer cache for the whole test run, so
// that every gate pulls and compiles each real image once. TestMain removes
// it with the tool directory.
func sharedCacheDir(t *testing.T) string {
	t.Helper()
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cacheDir == "" {
		dir, err := os.MkdirTemp("", "gvx-e2e-cache-*")
		if err != nil {
			t.Fatalf("create shared layer cache: %v", err)
		}
		cacheDir = dir
	}
	return cacheDir
}

// gateBackend names one execution backend that a gate runs on.
type gateBackend struct {
	name string
	plat gvx.PlatformType
}

// gateBackends lists the hardware backend of the host and systrap. Systrap
// subtests skip only when the engine reports a missing prerequisite.
func gateBackends() []gateBackend {
	return []gateBackend{
		{string(autoPlatform()), autoPlatform()},
		{"systrap", gvx.PlatformSystrap},
	}
}

// requireBackend skips the calling subtest when the backend cannot start for
// a documented reason.
func requireBackend(t *testing.T, b gateBackend) {
	t.Helper()
	if b.plat == gvx.PlatformSystrap {
		systraptest.Require(t)
	}
}

// outputLog is a concurrency-safe transcript of guest output. Waiters wake on
// every write, so tests never poll with sleeps.
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

// waitFor blocks until the transcript holds substr at or after offset from.
// It returns the offset just past the match. It fails the test when the
// timeout expires or done closes first.
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
			// One last look: the final write may precede the close.
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

// guestResult is the outcome of one Sandbox.Run.
type guestResult struct {
	code int
	err  error
}

// guestSpec describes one guest run of the gates.
type guestSpec struct {
	plat      gvx.PlatformType
	image     string
	argv      []string
	envv      []string
	workspace string
	net       gvx.NetworkMode
	forwards  []gvx.PortForward
	stdin     io.Reader
	tty       bool
	timeout   time.Duration

	// The Docker run settings. A zero value leaves the default.
	cmd           []string
	entrypoint    []string
	entrypointSet bool
	user          string
	hostname      string
	resources     gvx.Resources
	mounts        []gvx.Mount
	readOnlyRoot  bool
	publishAll    bool
}

func (g guestSpec) config(cache string, stdout, stderr io.Writer) gvx.Config {
	netMode := g.net
	if netMode == "" {
		netMode = gvx.NetModeNone
	}
	return gvx.Config{
		Platform:            g.plat,
		NetworkMode:         netMode,
		PortForwards:        g.forwards,
		OCIImage:            g.image,
		OCICacheDir:         cache,
		WorkspacePath:       g.workspace,
		Argv:                g.argv,
		Cmd:                 g.cmd,
		Entrypoint:          g.entrypoint,
		EntrypointSet:       g.entrypointSet,
		Envv:                g.envv,
		User:                g.user,
		Hostname:            g.hostname,
		Resources:           g.resources,
		Mounts:              g.mounts,
		ReadOnlyRoot:        g.readOnlyRoot,
		PublishAll:          g.publishAll,
		Stdin:               g.stdin,
		Stdout:              stdout,
		Stderr:              stderr,
		TTY:                 g.tty,
		DisableHostLockdown: true,
	}
}

// runGuest runs g to completion and returns the exit code with the separate
// stdout and stderr text. The lockdown stays off so the test process keeps
// working; the CLI-level gates cover the default lockdown.
func runGuest(t *testing.T, g guestSpec) (code int, stdout, stderr string) {
	t.Helper()
	timeout := g.timeout
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	sb, err := gvx.New(ctx, g.config(sharedCacheDir(t), &outBuf, &errBuf))
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

// mustRunGuest runs g and fails the test unless the guest exits with 0.
func mustRunGuest(t *testing.T, g guestSpec) string {
	t.Helper()
	code, stdout, stderr := runGuest(t, g)
	if code != 0 {
		t.Fatalf("guest %s %v exit code = %d, want 0\nstdout=%s\nstderr=%s", g.image, g.argv, code, stdout, stderr)
	}
	return stdout
}

// requireContains fails the test when text lacks any of the wanted parts.
func requireContains(t *testing.T, what, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("%s lacks %q; full text:\n%s", what, want, text)
		}
	}
}

// hostArch returns the Linux architecture name of the host.
func hostArch() string { return runtime.GOARCH }
