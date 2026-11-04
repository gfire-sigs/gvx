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

package cgroup2fs

import (
	"errors"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestValidateCPUMaxFollowsLinuxLimits(t *testing.T) {
	tests := []struct {
		name    string
		quota   int64
		period  int64
		wantErr bool
	}{
		{"docker --cpus=0.5", 50000, 100000, false},
		{"no limit", cpuMaxUnlimited, 100000, false},
		{"shortest period", 1000, 1000, false},
		{"longest period", 500000, 1000000, false},
		{"quota above the period", 400000, 100000, false},
		{"period below 1 ms", 50000, 999, true},
		{"period above 1 s", 50000, 1000001, true},
		{"quota below 1 ms", 999, 100000, true},
		{"quota above the Linux maximum", 1 << 44, 100000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCPUMax(tc.quota, tc.period)
			if tc.wantErr && !errors.Is(err, linuxerr.EINVAL) {
				t.Errorf("validateCPUMax(%d, %d) = %v, want EINVAL", tc.quota, tc.period, err)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateCPUMax(%d, %d) = %v, want nil", tc.quota, tc.period, err)
			}
		})
	}
}

func TestBandwidthLimitsConvertsMicroseconds(t *testing.T) {
	quota, period := bandwidthLimits(50000, 100000)
	if quota != 50*time.Millisecond || period != 100*time.Millisecond {
		t.Errorf("bandwidthLimits(50000, 100000) = (%v, %v), want (50ms, 100ms)", quota, period)
	}
	quota, period = bandwidthLimits(cpuMaxUnlimited, 200000)
	if quota >= 0 || period != 200*time.Millisecond {
		t.Errorf("bandwidthLimits(max, 200000) = (%v, %v), want a negative quota and 200ms", quota, period)
	}
}
