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
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
)

// TestE2ECPUMaxEnforcement checks the enforcement of cgroup v2 cpu.max on every
// backend (GVXIP-005, test A14). The guest program makes cgroups, runs busy-loop
// children in them, and compares usage_usec of cpu.stat with the wall time.
// With 50000 100000 a loop uses 0.5 +- 0.1 CPU over 5 seconds and nr_throttled
// grows. With max, a loop uses about one CPU. A child obeys the limit of its
// parent. The tasks of one cgroup share the quota across CPUs.
func TestE2ECPUMaxEnforcement(t *testing.T) {
	bin := acceptprog.BuildCPUMaxProbe(t, runtime.GOARCH)
	want := []string{
		"cpu-max-limits-busy-loop-to-half-cpu", "cpu-max-max-gives-full-cpu",
		"cpu-max-of-parent-limits-child", "cpu-max-quota-is-shared-by-all-tasks",
		"cpu-max-raised-to-max-resumes-task",
	}
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			code, out := runParityProbe(t, b, bin, false, "checks")
			t.Logf("cpumaxprobe output:\n%s", out)
			if code != 0 || !strings.Contains(out, "DONE") {
				t.Fatalf("cpumaxprobe checks exited with %d\n%s", code, out)
			}
			for _, name := range want {
				if !strings.Contains(out, "PASS "+name+"\n") {
					t.Errorf("check %s did not pass\n%s", name, out)
				}
			}
			if strings.Contains(out, "FAIL ") {
				t.Errorf("failed checks:\n%s", out)
			}
		})
	}
}
