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
	"runtime"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
	"z.gfire.dev/gvx/internal/acceptprog/compatprobe/report"
	"z.gfire.dev/gvx/internal/hvtest"
	"z.gfire.dev/gvx/pkg/gvx"
)

// TestE2ESystrapCompatSuite runs the high-efficiency guest compatibility,
// Wine64 ABI, system fingerprint, and micro-benchmark suite across all active
// backends and verifies that every probe digest matches the Linux golden
// standard.
func TestE2ESystrapCompatSuite(t *testing.T) {
	bin := acceptprog.BuildCompatProbe(t, runtime.GOARCH)

	for _, b := range fixedAddressBackends() {
		t.Run(b.name, func(t *testing.T) {
			if (b.plat == gvx.PlatformHVF || b.plat == gvx.PlatformWHPX) && !hvtest.Available() {
				t.Skip("no hardware hypervisor on this host")
			}
			requireFixedAddressBackend(t, b)

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			workspace := t.TempDir()
			cacheDir := t.TempDir()
			var outBuf, errBuf bytes.Buffer
			sb, err := gvx.New(ctx, gvx.Config{
				Platform:            b.plat,
				NetworkMode:         gvx.NetModeNone,
				OCICacheDir:         cacheDir,
				BinaryPath:          bin,
				Argv:                []string{"/bin/compatprobe"},
				WorkspacePath:       workspace,
				Mounts:              []gvx.Mount{{Kind: gvx.MountVolume, VolumeName: "compatvol", GuestPath: "/mnt/vol"}},
				Stdout:              &outBuf,
				Stderr:              &errBuf,
				DisableHostLockdown: true,
			})
			skipWhenFixedAddressRefused(t, "New(compatprobe)", err)
			defer func() {
				if cerr := sb.Close(); cerr != nil {
					t.Errorf("Close(%s) failed: %v", b.name, cerr)
				}
			}()

			code, err := sb.Run(ctx)
			skipWhenFixedAddressRefused(t, "Run(compatprobe)", err)
			if code != 0 {
				t.Fatalf("compatprobe on %s exited with %d\nstdout:\n%s\nstderr:\n%s",
					b.name, code, outBuf.String(), errBuf.String())
			}

			rawJSON := strings.TrimSpace(outBuf.String())
			for _, line := range strings.Split(rawJSON, "\n") {
				if after, ok := strings.CutPrefix(strings.TrimSpace(line), "COMPATPROBE_JSON="); ok {
					rawJSON = after
					break
				}
			}
			var rep report.Report
			if err := json.Unmarshal([]byte(rawJSON), &rep); err != nil {
				t.Fatalf("unmarshal compatprobe report on %s: %v\nstdout:\n%s\nstderr:\n%s",
					b.name, err, outBuf.String(), errBuf.String())
			}

			verifyCompatReport(t, b.name, &rep)
		})
	}
}

func verifyCompatReport(t *testing.T, backend string, rep *report.Report) {
	t.Helper()
	if rep.SchemaVersion != 1 {
		t.Errorf("%s: SchemaVersion = %d, want 1", backend, rep.SchemaVersion)
	}
	fp := rep.Fingerprint
	if fp.Arch != runtime.GOARCH {
		t.Errorf("%s: Fingerprint.Arch = %q, want %q", backend, fp.Arch, runtime.GOARCH)
	}
	if fp.Sysname != "Linux" {
		t.Errorf("%s: Fingerprint.Sysname = %q, want Linux", backend, fp.Sysname)
	}
	if fp.PageSize != 4096 && fp.PageSize != 16384 {
		t.Errorf("%s: Fingerprint.PageSize = %d, want 4096 or 16384", backend, fp.PageSize)
	}
	if fp.Auxv.PageSize != uint64(fp.PageSize) {
		t.Errorf("%s: Auxv.PageSize = %d, want %d", backend, fp.Auxv.PageSize, fp.PageSize)
	}
	if fp.AddressSpace.RegionCount < 3 {
		t.Errorf("%s: AddressSpace.RegionCount = %d, want >= 3", backend, fp.AddressSpace.RegionCount)
	}

	switch runtime.GOARCH {
	case "amd64":
		if fp.CPU.Vendor == "" || fp.CPU.FSBase == "" || fp.CPU.FSBase == "0x0" {
			t.Errorf("%s: amd64 CPU fingerprint incomplete: %+v", backend, fp.CPU)
		}
	case "arm64":
		if fp.CPU.MIDREL1 == "" || fp.CPU.MIDREL1 == "0x00000000" ||
			fp.CPU.CTREL0 == "" || fp.CPU.CTREL0 == "0x00000000" ||
			fp.CPU.TPIDREL0 == "" || fp.CPU.TPIDREL0 == "0x0" {
			t.Errorf("%s: arm64 CPU fingerprint incomplete: %+v", backend, fp.CPU)
		}
	}

	t.Logf("[%s/%s/%s] System Fingerprint: kernel=%s %s machine=%s page=%d cpus=%d regions=%d exec=%s stack=%s vdso=%s cpu=%+v",
		runtime.GOOS, runtime.GOARCH, backend, fp.Sysname, fp.Release, fp.Machine,
		fp.PageSize, fp.NumCPU, fp.AddressSpace.RegionCount,
		fp.AddressSpace.ExecStart, fp.AddressSpace.StackStart, fp.AddressSpace.VDSOStart, fp.CPU)

	seenProbes := make(map[string]bool, len(rep.Probes))
	for _, p := range rep.Probes {
		seenProbes[p.Name] = true
		t.Logf("[%s/%s/%s] Probe %-28s [%-7s] passed=%v (%6.2f ms) digest=%s (%s)",
			runtime.GOOS, runtime.GOARCH, backend, p.Name, p.Category, p.Passed,
			float64(p.DurationNs)/1e6, p.Digest, p.Detail)
		if !p.Passed {
			t.Errorf("%s: probe %s failed: %s", backend, p.Name, p.Detail)
			continue
		}
		want, ok := report.GoldenDigests[p.Name]
		if !ok {
			t.Errorf("%s: unexpected probe %s", backend, p.Name)
			continue
		}
		if p.Digest != want {
			t.Errorf("%s: probe %s digest = %q, want golden %q", backend, p.Name, p.Digest, want)
		}
	}
	for name := range report.GoldenDigests {
		if !seenProbes[name] {
			t.Errorf("%s: missing golden probe %s", backend, name)
		}
	}
	if !rep.AllPassed {
		t.Errorf("%s: AllPassed = false", backend)
	}

	if len(rep.Benchmarks) != 7 {
		t.Errorf("%s: len(Benchmarks) = %d, want 7", backend, len(rep.Benchmarks))
	}
	var benchLines []string
	for _, bm := range rep.Benchmarks {
		if bm.Iterations <= 0 || bm.TotalNs <= 0 || bm.NsPerOp <= 0 || bm.OpsPerSec <= 0 {
			t.Errorf("%s: invalid benchmark result %+v", backend, bm)
		}
		benchLines = append(benchLines, bm.Name)
		t.Logf("[%s/%s/%s] Bench %-30s iters=%-6d %9.1f ns/op (%10.0f ops/s)",
			runtime.GOOS, runtime.GOARCH, backend, bm.Name, bm.Iterations, bm.NsPerOp, bm.OpsPerSec)
	}
	t.Logf("[%s/%s/%s] Total suite time: %.2f ms (benchmarks: %s)",
		runtime.GOOS, runtime.GOARCH, backend, float64(rep.TotalNs)/1e6, strings.Join(benchLines, ", "))
}
