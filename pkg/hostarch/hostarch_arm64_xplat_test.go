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

//go:build arm64

package hostarch

import "testing"

func TestHostPageShiftFor(t *testing.T) {
	tests := []struct {
		name      string
		goos      string
		size      int
		wantShift uint
		wantWarn  bool
	}{
		{name: "darwin_16k", goos: "darwin", size: 16384, wantShift: MinPageShift, wantWarn: false},
		{name: "linux_4k", goos: "linux", size: 4096, wantShift: 12, wantWarn: false},
		{name: "linux_64k", goos: "linux", size: 65536, wantShift: 16, wantWarn: false},
		{name: "linux_16k", goos: "linux", size: 16384, wantShift: MinPageShift, wantWarn: false},
		{name: "android_16k", goos: "android", size: 16384, wantShift: MinPageShift, wantWarn: false},
		{name: "windows_4k", goos: "windows", size: 4096, wantShift: 12, wantWarn: false},
		{name: "invalid_non_power_of_two", goos: "linux", size: 12288, wantShift: MinPageShift, wantWarn: true},
		{name: "invalid_zero", goos: "linux", size: 0, wantShift: MinPageShift, wantWarn: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			shift, warn := hostPageShiftFor(tc.goos, tc.size)
			if shift != tc.wantShift || warn != tc.wantWarn {
				t.Fatalf("hostPageShiftFor(%q, %d) = (%d, %v), want (%d, %v)", tc.goos, tc.size, shift, warn, tc.wantShift, tc.wantWarn)
			}
		})
	}
}
