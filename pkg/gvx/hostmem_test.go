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

package gvx

import (
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
)

func TestEffectiveMemoryLimit(t *testing.T) {
	const (
		hostRAM                 = 8 << 30
		hostMemoryGuardInterval = 100 * time.Millisecond
		memoryPollInterval      = 5 * time.Millisecond
	)
	for _, tc := range []struct {
		name         string
		configured   int64
		hostRAM      uint64
		wantLimit    uint64
		wantInterval time.Duration
	}{
		{name: "no limit uses the host RAM", configured: 0, hostRAM: hostRAM, wantLimit: hostRAM, wantInterval: hostMemoryGuardInterval},
		{name: "minimum limit wins", configured: MinMemoryLimit, hostRAM: hostRAM, wantLimit: MinMemoryLimit, wantInterval: memoryPollInterval},
		{name: "limit above the host RAM wins", configured: 2 * hostRAM, hostRAM: hostRAM, wantLimit: 2 * hostRAM, wantInterval: memoryPollInterval},
		{name: "unknown host RAM and no limit has no guard", configured: 0, hostRAM: 0, wantLimit: 0, wantInterval: 0},
		{name: "unknown host RAM keeps the limit", configured: 1 << 30, hostRAM: 0, wantLimit: 1 << 30, wantInterval: memoryPollInterval},
	} {
		t.Run(tc.name, func(t *testing.T) {
			limit, interval := effectiveMemoryLimit(tc.configured, tc.hostRAM, tuning.Values{})
			if limit != tc.wantLimit || interval != tc.wantInterval {
				t.Errorf("effectiveMemoryLimit(%d, %d) = (%d, %v), want (%d, %v)", tc.configured, tc.hostRAM, limit, interval, tc.wantLimit, tc.wantInterval)
			}
		})
	}
}

func TestMemoryGuardIntervalsComeFromTheTunables(t *testing.T) {
	tuned, err := tuning.Parse(map[string]string{
		"memory.guard.poll_interval":      "20ms",
		"memory.guard.host_poll_interval": "300ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, interval := effectiveMemoryLimit(MinMemoryLimit, 8<<30, tuned); interval != 20*time.Millisecond {
		t.Errorf("interval with a limit = %v, want 20ms", interval)
	}
	if _, interval := effectiveMemoryLimit(0, 8<<30, tuned); interval != 300*time.Millisecond {
		t.Errorf("interval without a limit = %v, want 300ms", interval)
	}
}

// TestCgroupEnforcerDefaultsMatchTheRegistry keeps the defaults of the memory.max
// enforcer in the Sentry equal to the defaults of the registry. The Sentry
// package cannot import the registry.
func TestCgroupEnforcerDefaultsMatchTheRegistry(t *testing.T) {
	var v tuning.Values
	got := cgroup2fs.DefaultMemoryEnforcerOptions()
	if want := v.Duration(tuning.MemoryCgroupPollInterval); got.PollInterval != want {
		t.Errorf("poll interval = %v, registry default %v", got.PollInterval, want)
	}
	if want := v.Duration(tuning.MemoryCgroupIdlePollInterval); got.IdlePollInterval != want {
		t.Errorf("idle poll interval = %v, registry default %v", got.IdlePollInterval, want)
	}
	if want := v.Int(tuning.MemoryCgroupScanRatio); got.ScanRatio != want {
		t.Errorf("scan ratio = %d, registry default %d", got.ScanRatio, want)
	}
}

func TestReportedMemoryFollowsTheLimitBelowTheHostRAM(t *testing.T) {
	const hostRAM = 8 << 30
	for _, tc := range []struct {
		name       string
		configured int64
		hostRAM    uint64
		want       uint64
	}{
		{name: "limit below the host RAM", configured: 2 << 30, hostRAM: hostRAM, want: 2 << 30},
		{name: "limit above the host RAM reports the host RAM", configured: 16 << 30, hostRAM: hostRAM, want: hostRAM},
		{name: "limit equal to the host RAM", configured: hostRAM, hostRAM: hostRAM, want: hostRAM},
		{name: "unknown host RAM keeps the limit", configured: 1 << 30, hostRAM: 0, want: 1 << 30},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := reportedMemory(tc.configured, tc.hostRAM); got != tc.want {
				t.Errorf("reportedMemory(%d, %d) = %d, want %d", tc.configured, tc.hostRAM, got, tc.want)
			}
		})
	}
}
