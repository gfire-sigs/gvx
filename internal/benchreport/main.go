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

// Command benchreport parses TestE2EMicroBench logs and updates the benchmark
// history and Markdown trend report on the bench-results branch.
package main

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// MetricSummary stores the median latency and host CPU percentage of one
// micro-benchmark.
type MetricSummary struct {
	MedianNsPerOp float64 `json:"median_ns_per_op"`
	MedianCPUPct  float64 `json:"median_cpu_pct,omitempty"`
	Runs          int     `json:"runs,omitempty"`
}

// RunRecord stores one benchmark run for one platform target and backend.
type RunRecord struct {
	Timestamp string                   `json:"timestamp"`
	Commit    string                   `json:"commit"`
	Branch    string                   `json:"branch,omitempty"`
	OS        string                   `json:"os"`
	Arch      string                   `json:"arch"`
	Backend   string                   `json:"backend"`
	Failures  int                      `json:"failures"`
	Metrics   map[string]MetricSummary `json:"metrics"`
}

func (r RunRecord) targetKey() string {
	return r.OS + "/" + r.Arch + ":" + r.Backend
}

var orderedMetrics = []string{
	"host_new",
	"host_run_exit",
	"host_close",
	"getpid",
	"open_close",
	"pipe_pingpong",
	"futex_pingpong",
	"fork_wait",
	"fork_exec_true",
	"shm_sparse_idle",
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "benchreport: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("benchreport", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		inputDir  = fs.String("input-dir", "", "directory of <os>-<arch>.log benchmark files")
		inputFile = fs.String("input", "", "single benchmark log file")
		outDir    = fs.String("outdir", ".", "output directory for history.ndjson, latest.json, and README.md")
		commit    = fs.String("commit", "unknown", "git commit SHA")
		branch    = fs.String("branch", "main", "git branch name")
		timestamp = fs.String("timestamp", time.Now().UTC().Format(time.RFC3339), "run timestamp in RFC3339")
		goos      = fs.String("os", "", "default GOOS when -input is used")
		goarch    = fs.String("arch", "", "default GOARCH when -input is used")
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *inputDir == "" && *inputFile == "" {
		return fmt.Errorf("specify -input-dir or -input")
	}

	var newRecords []RunRecord
	if *inputDir != "" {
		entries, err := os.ReadDir(*inputDir)
		if err != nil {
			return fmt.Errorf("read input dir: %w", err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".log") {
				continue
			}
			p := filepath.Join(*inputDir, e.Name())
			fOS, fArch := inferOSArch(e.Name(), *goos, *goarch)
			recs, err := parseLogFile(p, *timestamp, *commit, *branch, fOS, fArch)
			if err != nil {
				return err
			}
			newRecords = append(newRecords, recs...)
		}
	}
	if *inputFile != "" {
		fOS, fArch := inferOSArch(filepath.Base(*inputFile), *goos, *goarch)
		recs, err := parseLogFile(*inputFile, *timestamp, *commit, *branch, fOS, fArch)
		if err != nil {
			return err
		}
		newRecords = append(newRecords, recs...)
	}
	if len(newRecords) == 0 {
		return fmt.Errorf("no benchmark results found in input")
	}

	if err := os.MkdirAll(*outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir outdir: %w", err)
	}
	historyPath := filepath.Join(*outDir, "history.ndjson")
	history, err := loadHistory(historyPath)
	if err != nil {
		return err
	}
	history = append(history, newRecords...)
	if err := writeHistory(historyPath, history); err != nil {
		return err
	}

	latest := computeLatest(history)
	latestBytes, err := json.MarshalIndent(latest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*outDir, "latest.json"), append(latestBytes, '\n'), 0o644); err != nil {
		return err
	}

	readme := renderMarkdown(history, latest)
	if err := os.WriteFile(filepath.Join(*outDir, "README.md"), []byte(readme), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "recorded %d benchmark run(s) (%d total in history)\n", len(newRecords), len(history))
	return nil
}

func inferOSArch(filename, defaultOS, defaultArch string) (string, string) {
	base := strings.TrimSuffix(filename, filepath.Ext(filename))
	base = strings.TrimPrefix(base, "bench-")
	for _, knownOS := range []string{"linux", "darwin", "windows"} {
		for _, knownArch := range []string{"amd64", "arm64"} {
			if strings.Contains(base, knownOS+"-"+knownArch) || strings.Contains(base, knownOS+"_"+knownArch) {
				return knownOS, knownArch
			}
		}
	}
	if defaultOS == "" {
		defaultOS = "unknown"
	}
	if defaultArch == "" {
		defaultArch = "unknown"
	}
	return defaultOS, defaultArch
}

func parseLogFile(path, timestamp, commit, branch, goos, goarch string) ([]RunRecord, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseLogReader(f, timestamp, commit, branch, goos, goarch)
}

func parseLogReader(r io.Reader, timestamp, commit, branch, goos, goarch string) ([]RunRecord, error) {
	byBackend := map[string]*RunRecord{}
	getRec := func(backend string) *RunRecord {
		rec := byBackend[backend]
		if rec == nil {
			rec = &RunRecord{
				Timestamp: timestamp,
				Commit:    commit,
				Branch:    branch,
				OS:        goos,
				Arch:      goarch,
				Backend:   backend,
				Metrics:   make(map[string]MetricSummary),
			}
			byBackend[backend] = rec
		}
		return rec
	}

	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.Index(line, "MBRESULT "); idx >= 0 {
			kv := parseFields(line[idx+len("MBRESULT "):])
			backend, name := kv["backend"], kv["name"]
			if backend == "" || name == "" {
				continue
			}
			// Host cold-start lines carry median_ns directly on MBRESULT.
			if medStr, ok := kv["median_ns"]; ok {
				med, err := strconv.ParseFloat(medStr, 64)
				if err == nil {
					runs, _ := strconv.Atoi(kv["runs"])
					getRec(backend).Metrics[name] = MetricSummary{
						MedianNsPerOp: med,
						Runs:          runs,
					}
				}
			}
			continue
		}
		if idx := strings.Index(line, "MBSUMMARY "); idx >= 0 {
			kv := parseFields(line[idx+len("MBSUMMARY "):])
			backend, name := kv["backend"], kv["name"]
			if backend == "" || name == "" {
				continue
			}
			med, err := strconv.ParseFloat(kv["median_ns_per_op"], 64)
			if err != nil {
				continue
			}
			cpuPct, _ := strconv.ParseFloat(kv["median_cpu_pct"], 64)
			runs, _ := strconv.Atoi(kv["runs"])
			getRec(backend).Metrics[name] = MetricSummary{
				MedianNsPerOp: med,
				MedianCPUPct:  cpuPct,
				Runs:          runs,
			}
			continue
		}
		if idx := strings.Index(line, "MBDONE "); idx >= 0 {
			kv := parseFields(line[idx+len("MBDONE "):])
			if backend := kv["backend"]; backend != "" {
				if fails, err := strconv.Atoi(kv["failures"]); err == nil {
					getRec(backend).Failures = fails
				}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	out := make([]RunRecord, 0, len(byBackend))
	for _, rec := range byBackend {
		if len(rec.Metrics) > 0 {
			out = append(out, *rec)
		}
	}
	slices.SortFunc(out, func(a, b RunRecord) int {
		return cmp.Compare(a.targetKey(), b.targetKey())
	})
	return out, nil
}

func parseFields(s string) map[string]string {
	out := make(map[string]string)
	for tok := range strings.FieldsSeq(s) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			out[k] = v
		}
	}
	return out
}

func loadHistory(path string) ([]RunRecord, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []RunRecord
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec RunRecord
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		out = append(out, rec)
	}
	return out, sc.Err()
}

func writeHistory(path string, history []RunRecord) error {
	var buf bytes.Buffer
	for _, rec := range history {
		b, err := json.Marshal(rec)
		if err != nil {
			return err
		}
		buf.Write(b)
		buf.WriteByte('\n')
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func computeLatest(history []RunRecord) []RunRecord {
	byKey := make(map[string]RunRecord)
	for _, rec := range history {
		byKey[rec.targetKey()] = rec
	}
	out := make([]RunRecord, 0, len(byKey))
	for _, rec := range byKey {
		out = append(out, rec)
	}
	slices.SortFunc(out, func(a, b RunRecord) int {
		return cmp.Compare(a.targetKey(), b.targetKey())
	})
	return out
}

func formatDurationNs(ns float64) string {
	switch {
	case ns <= 0:
		return "-"
	case ns >= 1e6:
		return fmt.Sprintf("%.2f ms", ns/1e6)
	case ns >= 1e3:
		return fmt.Sprintf("%.1f us", ns/1e3)
	default:
		return fmt.Sprintf("%.0f ns", ns)
	}
}

func formatMetricCell(name string, m MetricSummary, ok bool) string {
	if !ok {
		return "-"
	}
	if name == "shm_sparse_idle" {
		return fmt.Sprintf("%.1f%% CPU", m.MedianCPUPct)
	}
	if m.MedianCPUPct > 0 {
		return fmt.Sprintf("%s (%.0f%%)", formatDurationNs(m.MedianNsPerOp), m.MedianCPUPct)
	}
	return formatDurationNs(m.MedianNsPerOp)
}

func shortCommit(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func renderMarkdown(history, latest []RunRecord) string {
	var b strings.Builder
	b.WriteString("# Cross-Platform Benchmark Results\n\n")
	b.WriteString("This branch records automated cross-platform `TestE2EMicroBench` latency and host CPU utilization results.\n\n")
	b.WriteString("## Latest Summary by Platform and Backend\n\n")
	b.WriteString("| Target | Backend | Commit | `host_new` | `getpid` | `open_close` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` |\n")
	b.WriteString("| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	for _, rec := range latest {
		cell := func(name string) string {
			m, ok := rec.Metrics[name]
			return formatMetricCell(name, m, ok)
		}
		fmt.Fprintf(&b, "| `%s/%s` | `%s` | `%s` | %s | %s | %s | %s | %s | %s | %s | %s |\n",
			rec.OS, rec.Arch, rec.Backend, shortCommit(rec.Commit),
			cell("host_new"), cell("getpid"), cell("open_close"),
			cell("pipe_pingpong"), cell("futex_pingpong"),
			cell("fork_wait"), cell("fork_exec_true"), cell("shm_sparse_idle"))
	}

	b.WriteString("\n## Historical Trend (Last 10 Runs per Target)\n\n")
	byTarget := make(map[string][]RunRecord)
	for _, rec := range history {
		k := rec.targetKey()
		byTarget[k] = append(byTarget[k], rec)
	}
	keys := make([]string, 0, len(byTarget))
	for k := range byTarget {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	for _, k := range keys {
		runs := byTarget[k]
		if len(runs) > 10 {
			runs = runs[len(runs)-10:]
		}
		sample := runs[len(runs)-1]
		fmt.Fprintf(&b, "### `%s/%s` (`%s`)\n\n", sample.OS, sample.Arch, sample.Backend)
		b.WriteString("| Timestamp (UTC) | Commit | `getpid` | `pipe_pingpong` | `futex_pingpong` | `fork_wait` | `fork_exec_true` | `shm_sparse_idle` | Failures |\n")
		b.WriteString("| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
		for i := len(runs) - 1; i >= 0; i-- {
			rec := runs[i]
			cell := func(name string) string {
				m, ok := rec.Metrics[name]
				return formatMetricCell(name, m, ok)
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | %s | %s | %s | %s | %s | %s | %d |\n",
				rec.Timestamp, shortCommit(rec.Commit),
				cell("getpid"), cell("pipe_pingpong"), cell("futex_pingpong"),
				cell("fork_wait"), cell("fork_exec_true"), cell("shm_sparse_idle"), rec.Failures)
		}
		b.WriteString("\n")
	}
	return b.String()
}
