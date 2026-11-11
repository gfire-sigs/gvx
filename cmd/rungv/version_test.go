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

package main

import (
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"
)

func TestFormatVersionPrintsArchitectureLevel(t *testing.T) {
	cases := []struct {
		name     string
		info     *debug.BuildInfo
		expected string
	}{
		{
			name: "linux amd64 v2",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "v0.12.10032026110200"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "linux"},
					{Key: "GOARCH", Value: "amd64"},
					{Key: "GOAMD64", Value: "v2"},
					{Key: "vcs.revision", Value: "abe4a6f0"},
					{Key: "vcs.time", Value: "2026-11-11T01:00:00Z"},
				},
			},
			expected: "rungv v0.12.10032026110200\ncommit abe4a6f0 (2026-11-11T01:00:00Z)\ngo go1.27.4 linux/amd64 GOAMD64=v2\n",
		},
		{
			name: "linux arm64 lse variant",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "v0.12.10032026110200"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "linux"},
					{Key: "GOARCH", Value: "arm64"},
					{Key: "GOARM64", Value: "v8.2"},
					{Key: "vcs.revision", Value: "abe4a6f0"},
					{Key: "vcs.modified", Value: "true"},
				},
			},
			expected: "rungv v0.12.10032026110200\ncommit abe4a6f0 modified\ngo go1.27.4 linux/arm64 GOARM64=v8.2\n",
		},
		{
			name: "darwin arm64 v8.4",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "(devel)"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOARCH", Value: "arm64"},
					{Key: "GOARM64", Value: "v8.4"},
				},
			},
			expected: "rungv (devel)\ngo go1.27.4 darwin/arm64 GOARM64=v8.4\n",
		},
		{
			name: "fallback without settings",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "(devel)"},
			},
			expected: "rungv (devel)\ngo go1.27.4 " + runtime.GOOS + "/" + runtime.GOARCH + "\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := formatVersion(tc.info)
			if got != tc.expected {
				t.Fatalf("formatVersion() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestReproBuildSelectsTargetBaselinesAndOverrides(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("repro-build.sh requires a POSIX shell")
	}
	script, err := filepath.Abs(filepath.Join("..", "..", "scripts", "repro-build.sh"))
	if err != nil {
		t.Fatalf("resolve repro-build.sh: %v", err)
	}
	if _, err := os.Stat(script); err != nil {
		t.Skipf("repro-build.sh unavailable in test environment: %v", err)
	}

	cases := []struct {
		name     string
		goos     string
		goarch   string
		extraEnv []string
		wantKey  string
		wantVal  string
		wantLine string
	}{
		{
			name:     "darwin arm64 default",
			goos:     "darwin",
			goarch:   "arm64",
			wantKey:  "GOARM64",
			wantVal:  "v8.4",
			wantLine: "darwin/arm64 GOARM64=v8.4\n",
		},
		{
			name:     "windows arm64 default",
			goos:     "windows",
			goarch:   "arm64",
			wantKey:  "GOARM64",
			wantVal:  "v8.1",
			wantLine: "windows/arm64 GOARM64=v8.1\n",
		},
		{
			name:     "windows amd64 default",
			goos:     "windows",
			goarch:   "amd64",
			wantKey:  "GOAMD64",
			wantVal:  "v2",
			wantLine: "windows/amd64 GOAMD64=v2\n",
		},
		{
			name:     "linux amd64 default",
			goos:     "linux",
			goarch:   "amd64",
			wantKey:  "GOAMD64",
			wantVal:  "v2",
			wantLine: "linux/amd64 GOAMD64=v2\n",
		},
		{
			name:     "linux arm64 default",
			goos:     "linux",
			goarch:   "arm64",
			wantKey:  "GOARM64",
			wantVal:  "v8.0",
			wantLine: "linux/arm64 GOARM64=v8.0\n",
		},
		{
			name:     "android arm64 default",
			goos:     "android",
			goarch:   "arm64",
			wantKey:  "GOARM64",
			wantVal:  "v8.0",
			wantLine: "android/arm64 GOARM64=v8.0\n",
		},
		{
			name:     "linux arm64 v8.2 override",
			goos:     "linux",
			goarch:   "arm64",
			extraEnv: []string{"GOARM64=v8.2"},
			wantKey:  "GOARM64",
			wantVal:  "v8.2",
			wantLine: "linux/arm64 GOARM64=v8.2\n",
		},
		{
			name:     "linux amd64 v3 override",
			goos:     "linux",
			goarch:   "amd64",
			extraEnv: []string{"GOAMD64=v3"},
			wantKey:  "GOAMD64",
			wantVal:  "v3",
			wantLine: "linux/amd64 GOAMD64=v3\n",
		},
	}

	tmpDir := t.TempDir()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out := filepath.Join(tmpDir, tc.goos+"-"+tc.goarch+"-"+tc.wantVal)
			if tc.goos == "windows" {
				out += ".exe"
			}
			cmd := exec.Command("/bin/sh", script, out, "./tools/upstream")
			env := append(os.Environ(),
				"GOOS="+tc.goos,
				"GOARCH="+tc.goarch,
				"GVX_BUILDVCS=false",
				"GOAMD64=",
				"GOARM64=",
			)
			cmd.Env = append(env, tc.extraEnv...)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("repro-build.sh failed: %v\n%s", err, output)
			}
			info, err := buildinfo.ReadFile(out)
			if err != nil {
				t.Fatalf("buildinfo.ReadFile(%s): %v", out, err)
			}
			var gotVal string
			for _, s := range info.Settings {
				if s.Key == tc.wantKey {
					gotVal = s.Value
					break
				}
			}
			if gotVal != tc.wantVal {
				t.Fatalf("%s = %q, want %q", tc.wantKey, gotVal, tc.wantVal)
			}
			rendered := formatVersion(info)
			if len(rendered) < len(tc.wantLine) || rendered[len(rendered)-len(tc.wantLine):] != tc.wantLine {
				t.Fatalf("formatVersion() = %q, want suffix %q", rendered, tc.wantLine)
			}
		})
	}
}
