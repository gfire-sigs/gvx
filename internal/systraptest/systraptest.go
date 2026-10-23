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

// Package systraptest tells tests whether the systrap engine can start in the
// current build. The engine runs on darwin/arm64 when the Sentry builds with
// -tags pagesize_16k. Every other build reports a typed error. The package
// imports no gvx package, so tests inside pkg/gvx can use it.
package systraptest

import (
	"runtime"
	"testing"
)

// Available reports whether the systrap engine starts in this build. It
// returns false only for the typed errors that mean a missing prerequisite: an
// unavailable engine and a page-size mismatch. Any other probe error fails the
// test, because the engine should have started.
func Available(t testing.TB) bool {
	t.Helper()
	missing, err := probe()
	if err == nil {
		return true
	}
	if missing {
		return false
	}
	t.Fatalf("systrap probe failed with an error that is not a missing prerequisite: %v", err)
	return false
}

// Require skips the test with an explicit reason when Available is false.
func Require(t testing.TB) {
	t.Helper()
	if !Available(t) {
		_, err := probe()
		t.Skipf("systrap engine unavailable in this build: %v", err)
	}
}

// RequireUnavailable skips the test when the engine starts. It guards checks
// of the error path, which only builds without an engine exercise.
func RequireUnavailable(t testing.TB) {
	t.Helper()
	if Available(t) {
		t.Skip("systrap engine is available in this build, so the unavailable path does not apply")
	}
}

// RequireHostLockdown skips targets that support trusted systrap execution only.
func RequireHostLockdown(t testing.TB) {
	t.Helper()
	Require(t)
	if runtime.GOOS == "windows" && runtime.GOARCH != "arm64" {
		t.Skip("confined Windows systrap requires ARM64 native syscall sealing")
	}
}
