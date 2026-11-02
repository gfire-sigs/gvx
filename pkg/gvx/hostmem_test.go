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
)

func TestEffectiveMemoryLimit(t *testing.T) {
	const hostRAM = 8 << 30
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
			limit, interval := effectiveMemoryLimit(tc.configured, tc.hostRAM)
			if limit != tc.wantLimit || interval != tc.wantInterval {
				t.Errorf("effectiveMemoryLimit(%d, %d) = (%d, %v), want (%d, %v)", tc.configured, tc.hostRAM, limit, interval, tc.wantLimit, tc.wantInterval)
			}
		})
	}
}
