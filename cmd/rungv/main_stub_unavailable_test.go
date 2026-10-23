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

//go:build !linux && !windows && !(darwin && arm64 && pagesize_16k)

package main

import (
	"runtime"
	"strings"
	"testing"
)

// TestStubReportsUnavailableEngine covers every host without a runnable
// systrap engine: the default 4KB build on darwin/arm64 and darwin/amd64.
// Linux runs the upstream platform, and Windows runs the engine of gvx. The
// command prints no stub data and exits with the engine error.
func TestStubReportsUnavailableEngine(t *testing.T) {
	code, stdout, stderr := runStub(t)
	if code != 1 || stdout != "" {
		t.Fatalf("rungv stub = (code %d, stdout %q, stderr %q), want (1, empty stdout)", code, stdout, stderr)
	}
	want := "unavailable"
	if runtime.GOOS == "darwin" && runtime.GOARCH == "arm64" {
		want = "pagesize_16k"
	}
	if !strings.Contains(stderr, "rungv stub: ") || !strings.Contains(stderr, want) {
		t.Fatalf("rungv stub stderr = %q, want the engine error containing %q", stderr, want)
	}
}
