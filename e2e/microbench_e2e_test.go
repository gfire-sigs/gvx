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
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/testelf"
	"z.gfire.dev/gvx/pkg/gvx"
)

// The micro-benchmarks run one guest program on every backend and print the
// same numbers for each, so the backends can be compared. They cost minutes, so
// they run only when GVX_E2E_BENCH=1. GVX_E2E_BENCH_REPEAT sets the number of
// runs for each backend, which is 3 by default.
//
// Every result line starts with MBRESULT, so a script can collect them:
//
//	GVX_E2E_BENCH=1 go test -run TestE2EMicroBench -v ./e2e/ | grep MBRESULT
//
// The guest numbers come from internal/acceptprog/microbench. The host numbers
// come from this file: they time gvx.New, Run, and Close of a guest that exits
// at once.

const microBenchEnv = "GVX_E2E_BENCH"

type benchLine struct {
	Name    string  `json:"name"`
	Iters   int     `json:"iters"`
	TotalNs int64   `json:"total_ns"`
	NsPerOp float64 `json:"ns_per_op"`
}

func benchRepeat(t *testing.T) int {
	t.Helper()
	if v := os.Getenv("GVX_E2E_BENCH_REPEAT"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			t.Fatalf("GVX_E2E_BENCH_REPEAT=%q is not a positive number", v)
		}
		return n
	}
	return 3
}

// benchOnly returns the benchmarks that GVX_E2E_BENCH_ONLY names, separated by
// commas, or nil for all of them.
func benchOnly() []string {
	if v := os.Getenv("GVX_E2E_BENCH_ONLY"); v != "" {
		return strings.Split(v, ",")
	}
	return nil
}

func median(v []float64) float64 {
	s := slices.Clone(v)
	slices.Sort(s)
	return s[len(s)/2]
}

func TestE2EMicroBench(t *testing.T) {
	if os.Getenv(microBenchEnv) != "1" {
		t.Skipf("set %s=1 to run the micro-benchmarks", microBenchEnv)
	}
	repeat := benchRepeat(t)
	bin := acceptprog.BuildMicroBench(t, runtime.GOARCH)
	exitELF, err := testelf.BuildGuestELF64(runtime.GOARCH, 0, "")
	if err != nil {
		t.Fatalf("BuildGuestELF64: %v", err)
	}

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireFixedAddressBackend(t, b)
			benchHostColdStart(t, b, exitELF, max(repeat, 5))
			benchGuest(t, b, bin, repeat)
		})
	}
}

// benchHostColdStart times the three steps of a sandbox that runs a guest which
// exits at once.
func benchHostColdStart(t *testing.T, b gateBackend, elfData []byte, reps int) {
	t.Helper()
	var newNs, runNs, closeNs []float64
	for range reps {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		t0 := time.Now()
		sb, err := gvx.New(ctx, gvx.Config{
			Platform:            b.plat,
			NetworkMode:         gvx.NetModeNone,
			OCICacheDir:         sharedCacheDir(t),
			ELFBytes:            elfData,
			DisableHostLockdown: true,
		})
		t1 := time.Now()
		if err != nil {
			cancel()
			skipWhenFixedAddressRefused(t, "New", err)
			return
		}
		code, err := sb.Run(ctx)
		t2 := time.Now()
		cerr := sb.Close()
		t3 := time.Now()
		cancel()
		if err != nil || code != 0 || cerr != nil {
			t.Fatalf("exit guest on %s: code %d, run error %v, close error %v", b.name, code, err, cerr)
		}
		newNs = append(newNs, float64(t1.Sub(t0)))
		runNs = append(runNs, float64(t2.Sub(t1)))
		closeNs = append(closeNs, float64(t3.Sub(t2)))
	}
	for _, r := range []struct {
		name string
		v    []float64
	}{{"host_new", newNs}, {"host_run_exit", runNs}, {"host_close", closeNs}} {
		t.Logf("MBRESULT backend=%s name=%s median_ns=%.0f runs=%d", b.name, r.name, median(r.v), len(r.v))
	}
}

// benchNames lists the benchmarks of the guest. Each runs in its own sandbox,
// so a crash in one of them costs only that number.
var benchNames = []string{"getpid", "open_close", "pipe_pingpong", "futex_pingpong", "fork_wait", "fork_exec_true"}

// benchGuest runs each benchmark of the microbench guest repeat times and
// prints each result and the median of each benchmark. A run that fails is
// printed as MBFAIL and does not stop the others.
func benchGuest(t *testing.T, b gateBackend, bin string, repeat int) {
	t.Helper()
	names := benchNames
	if only := benchOnly(); only != nil {
		names = only
	}
	failures := 0
	for _, name := range names {
		var samples []float64
		for rep := range repeat {
			ns, detail, err := runBenchOnce(b, bin, name)
			if err != nil {
				if strings.Contains(err.Error(), "not position-independent") || strings.Contains(err.Error(), "cannot hold the zone") {
					t.Skipf("this engine cannot hold the guest: %v", err)
				}
				failures++
				t.Logf("MBFAIL backend=%s name=%s rep=%d %v%s", b.name, name, rep, err, detail)
				continue
			}
			samples = append(samples, ns)
			t.Logf("MBRESULT backend=%s name=%s rep=%d ns_per_op=%.0f", b.name, name, rep, ns)
		}
		if len(samples) > 0 {
			t.Logf("MBSUMMARY backend=%s name=%s median_ns_per_op=%.0f runs=%d of %d", b.name, name, median(samples), len(samples), repeat)
		}
	}
	t.Logf("MBDONE backend=%s failures=%d", b.name, failures)
}

// runBenchOnce runs one benchmark of the guest in a new sandbox and returns its
// time for each operation. On failure, detail holds the head of the guest
// error output.
func runBenchOnce(b gateBackend, bin, name string) (nsPerOp float64, detail string, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	var outBuf, errBuf bytes.Buffer
	sb, err := gvx.New(ctx, gvx.Config{
		Platform:            b.plat,
		NetworkMode:         gvx.NetModeNone,
		OCICacheDir:         os.TempDir(),
		BinaryPath:          bin,
		Argv:                []string{name},
		Stdout:              &outBuf,
		Stderr:              &errBuf,
		DisableHostLockdown: true,
	})
	if err != nil {
		return 0, "", err
	}
	code, runErr := sb.Run(ctx)
	closeErr := sb.Close()
	fail := func(format string, args ...any) (float64, string, error) {
		head := errBuf.String()
		if len(head) > 600 {
			head = head[:600]
		}
		return 0, "\nstderr: " + strings.ReplaceAll(head, "\n", " | "), fmt.Errorf(format, args...)
	}
	if runErr != nil {
		return fail("run: %v", runErr)
	}
	if code != 0 {
		return fail("exit code %d", code)
	}
	if closeErr != nil {
		return fail("close: %v", closeErr)
	}
	for _, line := range strings.Split(outBuf.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MICROBENCH_ERR ") {
			return fail("%s", line)
		}
		if rest, ok := strings.CutPrefix(line, "MICROBENCH "); ok && !strings.HasPrefix(line, "MICROBENCH_") {
			var r benchLine
			if err := json.Unmarshal([]byte(rest), &r); err != nil {
				return fail("parse %q: %v", line, err)
			}
			return r.NsPerOp, "", nil
		}
	}
	return fail("no result in the output %q", outBuf.String())
}
