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

package exttest

import (
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// Pinned conformance and browser tool revisions re-exported for ext/e2e tests.
const (
	ElectronVersion = acceptprog.ElectronVersion
	WebGLCTSCommit  = acceptprog.WebGLCTSCommit
	WebGLCTSSHA256  = acceptprog.WebGLCTSSHA256
)

// FetchPlaywrightCore returns a verified local playwright-core tree for tests.
func FetchPlaywrightCore(tb testing.TB) string {
	tb.Helper()
	return acceptprog.FetchPlaywrightCore(tb)
}

// FetchElectron returns a verified local Electron tree for arch.
func FetchElectron(tb testing.TB, arch string) string {
	tb.Helper()
	return acceptprog.FetchElectron(tb, arch)
}

// FetchGPUGuestDebs returns a verified host directory containing the pinned
// Mesa guest .deb packages for arch.
func FetchGPUGuestDebs(tb testing.TB, arch string) string {
	tb.Helper()
	return acceptprog.FetchGPUGuestDebs(tb, arch)
}

// FetchWebGLCTS returns a verified local Khronos WebGL CTS tree for tests.
func FetchWebGLCTS(tb testing.TB) string {
	tb.Helper()
	return acceptprog.FetchWebGLCTS(tb)
}
