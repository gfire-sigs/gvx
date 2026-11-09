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

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBenchReportGeneratesHistoryLatestAndMarkdown(t *testing.T) {
	inDir := t.TempDir()
	outDir := t.TempDir()

	winLog := strings.Join([]string{
		"=== RUN   TestE2EMicroBench/systrap",
		"    microbench_e2e_test.go:146: MBRESULT backend=systrap name=host_new median_ns=4200000 runs=5",
		"    microbench_e2e_test.go:146: MBRESULT backend=systrap name=host_run_exit median_ns=950000 runs=5",
		"    microbench_e2e_test.go:146: MBRESULT backend=systrap name=host_close median_ns=120000 runs=5",
		"    microbench_e2e_test.go:220: MBSUMMARY backend=systrap name=getpid median_ns_per_op=490 median_cpu_pct=105.20 runs=3 of 3",
		"    microbench_e2e_test.go:220: MBSUMMARY backend=systrap name=fork_exec_true median_ns_per_op=3800000 median_cpu_pct=98.40 runs=3 of 3",
		"    microbench_e2e_test.go:220: MBSUMMARY backend=systrap name=shm_sparse_idle median_ns_per_op=2000100000 median_cpu_pct=0.25 runs=3 of 3",
		"    microbench_e2e_test.go:223: MBDONE backend=systrap failures=0",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(inDir, "bench-windows-amd64.log"), []byte(winLog), 0o644); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"-input-dir", inDir,
		"-outdir", outDir,
		"-commit", "abcdef1234567890",
		"-branch", "main",
		"-timestamp", "2026-11-09T15:00:00Z",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run failed: %v (stderr=%s)", err, stderr.String())
	}

	hist, err := loadHistory(filepath.Join(outDir, "history.ndjson"))
	if err != nil {
		t.Fatalf("loadHistory: %v", err)
	}
	if len(hist) != 1 {
		t.Fatalf("got %d history records, want 1", len(hist))
	}
	rec := hist[0]
	if rec.OS != "windows" || rec.Arch != "amd64" || rec.Backend != "systrap" {
		t.Errorf("record target = %s/%s:%s, want windows/amd64:systrap", rec.OS, rec.Arch, rec.Backend)
	}
	if got := rec.Metrics["shm_sparse_idle"].MedianCPUPct; got != 0.25 {
		t.Errorf("shm_sparse_idle MedianCPUPct = %v, want 0.25", got)
	}

	mdBytes, err := os.ReadFile(filepath.Join(outDir, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	md := string(mdBytes)
	for _, want := range []string{"`windows/amd64`", "`systrap`", "`abcdef12`", "0.2% CPU", "3.80 ms (98%)"} {
		if !strings.Contains(md, want) {
			t.Errorf("README.md does not contain %q:\n%s", want, md)
		}
	}
}
