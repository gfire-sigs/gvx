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

package hostlockdown

import "testing"

func TestJobCPURate(t *testing.T) {
	for _, tc := range []struct {
		name  string
		quota int64
		cpus  int
		want  uint32
	}{
		{"one of four CPUs is a quarter", 1000, 4, 2500},
		{"half of one CPU", 500, 1, 5000},
		{"all CPUs", 4000, 4, 10000},
		{"above the capacity is capped", 9000, 4, 10000},
		{"below one hundredth of a percent is raised", 1, 64, 1},
		{"a host with no CPU count counts as one CPU", 500, 0, 5000},
	} {
		if got := jobCPURate(tc.quota, tc.cpus); got != tc.want {
			t.Errorf("%s: jobCPURate(%d, %d) = %d, want %d", tc.name, tc.quota, tc.cpus, got, tc.want)
		}
	}
}
