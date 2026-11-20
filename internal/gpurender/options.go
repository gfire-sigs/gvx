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

package gpurender

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/devices/virtgpu/gpuproto"
)

// EnvRenderer names the environment variable that selects the renderer
// executable.
const EnvRenderer = "GVX_GPU_RENDERER"

// Default timeout limits for renderer startup, requests, submissions, and
// shutdown.
const (
	// DefaultStartTimeout bounds the process start, HELLO, and every
	// GET_CAPSET. A new renderer binary with an empty Metal shader cache takes
	// about 5 s on an M1 Ultra; later starts take about 2 s.
	DefaultStartTimeout = 20 * time.Second
	// DefaultRequestTimeout bounds the reply to every request except SUBMIT,
	// and the write of every frame except SUBMIT.
	DefaultRequestTimeout = 10 * time.Second
	// DefaultSubmitTimeout bounds the write of a SUBMIT frame and its reply.
	DefaultSubmitTimeout = 30 * time.Second
	// KillGrace is how long Close waits for the renderer to exit after end of
	// file on its socket before it sends SIGKILL.
	KillGrace = 500 * time.Millisecond
)

// Options configures Start.
type Options struct {
	// Path is the absolute path of the renderer executable. Use Locate to find it.
	Path string
	// Log receives each sanitized stderr line of the renderer and each client
	// diagnostic line. The Client calls it from its goroutines and it must not
	// block. Nil discards the lines.
	Log func(line string)
	// StartTimeout, RequestTimeout, and SubmitTimeout replace the defaults
	// when they are above zero. Tests set them; pkg/gvx leaves them zero.
	StartTimeout   time.Duration
	RequestTimeout time.Duration
	SubmitTimeout  time.Duration
	// StallFences starts the renderer with gpuproto.ArgStallFences and
	// gpuproto.EnvTestMode=1, so fences never retire. Tests only.
	StallFences bool
	// MemoryLimit is the blob memory limit of the sandbox in bytes. Start passes
	// it as gpuproto.ArgMemoryLimit, and the renderer watchdog exits above
	// MemoryLimit + gpuproto.WatchdogHeadroomBytes. Zero starts no watchdog.
	MemoryLimit uint64
	// TestWatchdogBytes sets the watchdog threshold directly. Start then sets
	// gpuproto.EnvTestMode=1. Tests only.
	TestWatchdogBytes uint64
	// TestOps sets gpuproto.EnvTestMode=1 in the renderer environment without
	// adding a command-line flag, enabling test-only ops such as TEST_CONFINE.
	// Tests only.
	TestOps bool
}

func (o Options) withDefaults() Options {
	if o.StartTimeout <= 0 {
		o.StartTimeout = DefaultStartTimeout
	}
	if o.RequestTimeout <= 0 {
		o.RequestTimeout = DefaultRequestTimeout
	}
	if o.SubmitTimeout <= 0 {
		o.SubmitTimeout = DefaultSubmitTimeout
	}
	return o
}

// StartError reports a renderer that did not complete the handshake.
type StartError struct {
	Path string
	// ExitCode is the exit code of the renderer, or -1 when it did not exit
	// by itself (killed after a timeout, or never started).
	ExitCode int
	// Stderr holds the last stderr lines of the renderer (at most 8).
	Stderr []string
	Err    error
}

// Error names the path, the exit code with its gpuproto meaning, the cause,
// and the last stderr line.
func (e *StartError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "gpurender: start %s", e.Path)
	if e.Err != nil {
		fmt.Fprintf(&b, ": %v", e.Err)
	}
	var details []string
	if e.ExitCode >= 0 {
		details = append(details, "renderer "+exitCodeWords(e.ExitCode))
	}
	if len(e.Stderr) > 0 {
		last := e.Stderr[len(e.Stderr)-1]
		details = append(details, fmt.Sprintf("last stderr line: %q", last))
	}
	if len(details) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(details, "; "))
	}
	return b.String()
}

// Unwrap returns the underlying start failure error.
func (e *StartError) Unwrap() error {
	return e.Err
}

func exitCodeWords(code int) string {
	switch code {
	case gpuproto.ExitOK:
		return "exited"
	case gpuproto.ExitUsage:
		return "usage error"
	case gpuproto.ExitInit:
		return "initialization failed"
	case gpuproto.ExitConfine:
		return "confinement failed"
	case gpuproto.ExitProtocol:
		return "protocol error"
	case gpuproto.ExitSelftest:
		return "self-test failed"
	case gpuproto.ExitMemoryLimit:
		return "memory limit"
	default:
		return fmt.Sprintf("exit code %d", code)
	}
}

// ExitError reports a renderer process that exited by itself after the
// handshake. Code is its exit code, with the meanings of gpuproto.Exit*.
type ExitError struct {
	Code int
}

// Error formats the exit code using its gpuproto meaning.
func (e *ExitError) Error() string {
	return fmt.Sprintf("gpurender: renderer exited (%s)", exitCodeWords(e.Code))
}

// ErrRendererHung signals that a reply, frame read, or frame write missed its
// deadline. Client wraps it together with gpuproto.ErrRendererLost.
var ErrRendererHung = errors.New("gpurender: renderer did not answer in time")

// ErrUnsupported signals that the host OS is not darwin. Start returns it on
// every non-darwin OS, and it wraps errors.ErrUnsupported.
var ErrUnsupported = fmt.Errorf("gpurender: the GPU renderer runs only on darwin: %w", errors.ErrUnsupported)

// ErrNotFound reports that no renderer executable exists at a searched path.
var ErrNotFound = errors.New("gpurender: renderer executable not found")

var errClosed = errors.New("gpurender: client closed")
