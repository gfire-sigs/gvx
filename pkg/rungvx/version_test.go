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
	"bytes"
	"context"
	"debug/buildinfo"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
)

type stubCLIPlugin struct {
	name    string
	summary string
}

func (p stubCLIPlugin) Name() string                  { return p.name }
func (p stubCLIPlugin) BuildSummary() string          { return p.summary }
func (p stubCLIPlugin) RegisterFlags(*flag.FlagSet)   {}
func (p stubCLIPlugin) ApplyConfig(*gvx.Config) error { return nil }

func TestFormatVersionPrintsArchitectureLevelAndBuildOptions(t *testing.T) {
	cases := []struct {
		name     string
		info     *debug.BuildInfo
		opts     BuildInfoOptions
		expected string
	}{
		{
			name: "linux amd64 v2 pure go",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "v0.12.10032026110200"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "linux"},
					{Key: "GOARCH", Value: "amd64"},
					{Key: "GOAMD64", Value: "v2"},
					{Key: "CGO_ENABLED", Value: "0"},
					{Key: "vcs.revision", Value: "abe4a6f0"},
					{Key: "vcs.time", Value: "2026-11-11T01:00:00Z"},
				},
			},
			expected: "rungvx v0.12.10032026110200\ncommit abe4a6f0 (2026-11-11T01:00:00Z)\ngo go1.27.4 linux/amd64 GOAMD64=v2\nbuild options: cgo=0 tags=none extensions=none\n",
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
			expected: "rungvx v0.12.10032026110200\ncommit abe4a6f0 modified\ngo go1.27.4 linux/arm64 GOARM64=v8.2\nbuild options: cgo=0 tags=none extensions=none\n",
		},
		{
			name: "darwin arm64 v8.4 with ext_gpu verbose",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "v0.22.10002026111600"},
				Settings: []debug.BuildSetting{
					{Key: "GOOS", Value: "darwin"},
					{Key: "GOARCH", Value: "arm64"},
					{Key: "GOARM64", Value: "v8.4"},
					{Key: "CGO_ENABLED", Value: "0"},
					{Key: "-tags", Value: "ext_gpu"},
					{Key: "-compiler", Value: "gc"},
					{Key: "-buildmode", Value: "exe"},
					{Key: "-trimpath", Value: "true"},
					{Key: "vcs.revision", Value: "1234abcd"},
					{Key: "vcs.time", Value: "2026-11-24T12:00:00Z"},
				},
			},
			opts: BuildInfoOptions{
				Verbose: true,
				Plugins: []CLIPlugin{
					stubCLIPlugin{name: "gpu", summary: "modes=venus,virgl"},
				},
			},
			expected: strings.Join([]string{
				"rungvx v0.22.10002026111600",
				"commit 1234abcd (2026-11-24T12:00:00Z)",
				"go go1.27.4 darwin/arm64 GOARM64=v8.4",
				"build options: cgo=0 tags=ext_gpu extensions=gpu",
				"compiler: gc",
				"buildmode: exe",
				"trimpath: true",
				"spi: 1",
				"extension gpu: modes=venus,virgl",
				"",
			}, "\n"),
		},
		{
			name: "fallback without settings",
			info: &debug.BuildInfo{
				GoVersion: "go1.27.4",
				Main:      debug.Module{Version: "(devel)"},
			},
			expected: "rungvx (devel)\ngo go1.27.4 " + runtime.GOOS + "/" + runtime.GOARCH + "\nbuild options: cgo=0 tags=none extensions=none\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := FormatVersion(tc.info, tc.opts)
			if got != tc.expected {
				t.Fatalf("FormatVersion() = %q, want %q", got, tc.expected)
			}
		})
	}
}

func TestVersionCLIFlagVPrintsVerboseBuildOptions(t *testing.T) {
	plugins := []CLIPlugin{stubCLIPlugin{name: "gpu", summary: "modes=venus,virgl"}}
	for _, args := range [][]string{{"-V"}, {"version", "-V"}, {"--version", "-V"}} {
		var stdout, stderr bytes.Buffer
		code := executeCLIWithPlugins(context.Background(), args, nil, &stdout, &stderr, plugins)
		if code != 0 {
			t.Fatalf("executeCLIWithPlugins(%v) = %d, stderr=%q", args, code, stderr.String())
		}
		out := stdout.String()
		for _, want := range []string{"rungvx ", "build options: ", "extensions=gpu", "spi: 1", "extension gpu: modes=venus,virgl"} {
			if !strings.Contains(out, want) {
				t.Fatalf("output for %v = %q, missing %q", args, out, want)
			}
		}
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
			if !strings.Contains(rendered, tc.wantLine) {
				t.Fatalf("formatVersion() = %q, want line containing %q", rendered, tc.wantLine)
			}
			if !strings.Contains(rendered, "build options: cgo=0 tags=none extensions=none\n") {
				t.Fatalf("formatVersion() = %q, want pure-Go build options line", rendered)
			}
		})
	}
}
