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

package rungvx

import (
	"os"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx/control"
)

func TestOSModeToLinuxModeWindowsExecutable(t *testing.T) {
	tests := []struct {
		name string
		goos string
		mode os.FileMode
		want uint32
	}{
		{
			name: "windows writable regular file",
			goos: "windows",
			mode: 0o666,
			want: control.LinuxSIFREG | 0o755,
		},
		{
			name: "windows read-only regular file",
			goos: "windows",
			mode: 0o444,
			want: control.LinuxSIFREG | 0o555,
		},
		{
			name: "windows writable directory",
			goos: "windows",
			mode: os.ModeDir | 0o777,
			want: control.LinuxSIFDIR | 0o755,
		},
		{
			name: "windows read-only directory",
			goos: "windows",
			mode: os.ModeDir | 0o555,
			want: control.LinuxSIFDIR | 0o555,
		},
		{
			name: "unix non-executable regular file preserved",
			goos: "linux",
			mode: 0o644,
			want: control.LinuxSIFREG | 0o644,
		},
		{
			name: "unix executable regular file preserved",
			goos: "darwin",
			mode: 0o755,
			want: control.LinuxSIFREG | 0o755,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := osModeToLinuxModeForOS(tc.goos, tc.mode); got != tc.want {
				t.Fatalf("osModeToLinuxModeForOS(%q, %#o) = %#o, want %#o", tc.goos, tc.mode, got, tc.want)
			}
		})
	}
}
