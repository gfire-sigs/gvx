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

import "testing"

func TestSupportsVolumeAttachPlatforms(t *testing.T) {
	cases := []struct {
		goos   string
		locked bool
		allow  bool
		want   bool
	}{
		{"darwin", true, false, true},
		{"linux", false, false, true},
		{"linux", true, false, false},
		{"linux", true, true, true},
		{"android", false, false, true},
		{"android", true, false, false},
		{"android", true, true, true},
		{"windows", false, true, false},
	}
	for _, tc := range cases {
		if got := supportsVolumeAttach(tc.goos, tc.locked, tc.allow); got != tc.want {
			t.Errorf("supportsVolumeAttach(%q, locked=%t, allow=%t) = %t, want %t", tc.goos, tc.locked, tc.allow, got, tc.want)
		}
	}
}
