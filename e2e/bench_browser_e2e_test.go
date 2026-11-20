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
	"os"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// browserBenchEnv turns the browser benchmark on when it is "1". The
// benchmark also needs GVX_E2E_BROWSER=1.
const browserBenchEnv = "GVX_E2E_BROWSER_BENCH"

// browserBenchWebGL lists the webgl-load.html variants of the benchmark: a
// page paced by requestAnimationFrame with many small triangles, the same
// page without pacing, and a page whose fragment shader dominates.
const browserBenchWebGL = "n=20000&size=0.05&iters=16;sync=1&n=20000&size=0.05&iters=16;sync=1&n=200&size=1.0&iters=64"

// TestE2EBrowserBench records the Phase 0 baseline of docs/moonshots.md: the
// launch time of the browser, the time of a new tab, and the share of
// SwiftShader in the CPU time of a WebGL page and of an automation script.
// It logs one line for each result and asserts only that the script ran.
func TestE2EBrowserBench(t *testing.T) {
	if os.Getenv(browserBenchEnv) != "1" {
		t.Skipf("set %s=1 and %s=1 to run the browser benchmark", browserGateEnv, browserBenchEnv)
	}
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			pwcore := acceptprog.FetchPlaywrightCore(t)
			spec := browserSpec(b, browserWorkspace(t), "node", "/workspace/browser-bench.js")
			spec.mounts = []gvx.Mount{readOnlyBind(pwcore, playwrightCoreGuestPath)}
			spec.envv = []string{"GVX_BENCH_WEBGL=" + browserBenchWebGL}
			spec.timeout = 30 * time.Minute
			out := mustRunGuest(t, spec)
			for _, line := range strings.Split(out, "\n") {
				if strings.HasPrefix(line, "GVX-BENCH ") {
					t.Logf("BROWSERBENCH backend=%s %s", b.name, strings.TrimPrefix(line, "GVX-BENCH "))
				}
			}
			requireContains(t, "benchmark output", out, "GVX-BENCH done\n")
		})
	}
}
