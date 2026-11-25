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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExtRungvxBuildTagsAndVersionOutput(t *testing.T) {
	tmp := t.TempDir()
	extSuffix := ""
	if runtime.GOOS == "windows" {
		extSuffix = ".exe"
	}

	cases := []struct {
		name      string
		tags      string
		wantLines []string
	}{
		{
			name: "default no tags",
			tags: "",
			wantLines: []string{
				"rungvx ",
				"build options: cgo=0 tags=none extensions=none",
				"spi: 1",
			},
		},
		{
			name: "ext_gpu tag",
			tags: "ext_gpu",
			wantLines: []string{
				"rungvx ",
				"build options: cgo=0 tags=ext_gpu extensions=gpu",
				"spi: 1",
				"extension gpu: modes=venus,virgl",
			},
		},
		{
			name: "ext_all tag",
			tags: "ext_all",
			wantLines: []string{
				"rungvx ",
				"build options: cgo=0 tags=ext_all extensions=gpu",
				"spi: 1",
				"extension gpu: modes=venus,virgl",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bin := filepath.Join(tmp, strings.ReplaceAll(tc.name, " ", "_")+extSuffix)
			args := []string{"build", "-o", bin}
			if tc.tags != "" {
				args = append(args, "-tags", tc.tags)
			}
			args = append(args, ".")
			buildCmd := exec.Command("go", args...)
			buildCmd.Env = append(buildCmd.Environ(), "CGO_ENABLED=0")
			if out, err := buildCmd.CombinedOutput(); err != nil {
				t.Fatalf("go %v failed: %v\n%s", args, err, out)
			}
			runCmd := exec.Command(bin, "-V")
			out, err := runCmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s -V failed: %v\n%s", bin, err, out)
			}
			text := string(out)
			for _, want := range tc.wantLines {
				if !strings.Contains(text, want) {
					t.Fatalf("output =\n%s\nmissing %q", text, want)
				}
			}
		})
	}
}
