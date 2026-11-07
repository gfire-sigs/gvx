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
	"runtime"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2ECPUMaxEnforcement checks the enforcement of cgroup v2 cpu.max on every
// backend (GVXIP-005, test A14). The guest program makes cgroups, runs busy-loop
// children in them, and compares usage_usec of cpu.stat with the wall time.
// With 50000 100000 a loop uses 0.5 +- 0.1 CPU over 5 seconds and nr_throttled
// grows. With max, one thread uses one CPU, and below its quota of 1.3 CPUs it never throttles. A tenth of a CPU gives both the billed time and the progress of the loop a tenth. A child obeys the limit of its
// parent. The tasks of one cgroup share the quota across CPUs. A held-back task runs again at once when a write lifts the limit, when it moves to another cgroup, and when the cpu controller leaves its cgroup.
func TestE2ECPUMaxEnforcement(t *testing.T) {
	bin := acceptprog.BuildCPUMaxProbe(t, runtime.GOARCH)
	want := []string{
		"cpu-max-limits-busy-loop-to-half-cpu", "cpu-max-max-gives-one-cpu-to-one-thread",
		"cpu-max-of-parent-limits-child", "cpu-max-quota-is-shared-by-all-tasks",
		"cpu-max-above-demand-never-throttles-one-thread",
		"cpu-max-small-quota-bills-and-delivers-the-same-time",
		"cpu-max-raised-to-max-resumes-task", "cpu-max-moving-task-to-free-cgroup-resumes-it",
		"cpu-max-disabling-controller-resumes-task",
		"cpu-max-limits-loop-without-system-calls",
		"cpu-stat-usage-of-parent-includes-children",
		"cpu-stat-usage-of-parent-keeps-removed-children",
		"memory-stat-exists-at-root",
	}
	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			// Resuming a throttled task costs more on hvf, so a loop at a tenth of
			// a CPU keeps a smaller share of its speed there.
			minShare := "0.07"
			if b.plat == gvx.PlatformHVF {
				minShare = "0.02"
			}
			// GVX_E2E_CPUMAX_CHECKS names the checks that a stress run selects.
			selected := want
			args := []string{"checks", minShare}
			if only := os.Getenv("GVX_E2E_CPUMAX_CHECKS"); only != "" {
				selected = strings.Split(only, ",")
				args = append(args, selected...)
			}
			code, out := runParityProbe(t, b, bin, false, args...)
			t.Logf("cpumaxprobe output:\n%s", out)
			if code != 0 || !strings.Contains(out, "DONE") {
				t.Fatalf("cpumaxprobe checks exited with %d\n%s", code, out)
			}
			for _, name := range selected {
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
