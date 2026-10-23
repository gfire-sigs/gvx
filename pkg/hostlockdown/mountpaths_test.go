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

//go:build darwin || windows

package hostlockdown

import (
	"path/filepath"
	"testing"
)

func TestWithinMatchesWholePathElementsOnly(t *testing.T) {
	base := t.TempDir()
	mount := filepath.Join(base, "data")
	for _, tt := range []struct {
		name string
		path string
		want bool
	}{
		{"the mount itself", mount, true},
		{"a child", filepath.Join(mount, "child"), true},
		{"a deep child", filepath.Join(mount, "a", "b"), true},
		{"a sibling that shares the name prefix", mount + "-other", false},
		{"the parent", base, false},
		{"an unrelated path", filepath.Join(base, "elsewhere", "data"), false},
	} {
		if got := within(mount, tt.path); got != tt.want {
			t.Errorf("%s: within(%q, %q) = %v, want %v", tt.name, mount, tt.path, got, tt.want)
		}
	}
}

func TestOutsideAllRequiresEveryMountToMiss(t *testing.T) {
	base := t.TempDir()
	mounts := []string{filepath.Join(base, "a"), filepath.Join(base, "a", "b"), filepath.Join(base, "c")}
	if outsideAll(filepath.Join(base, "a", "b", "file"), mounts) {
		t.Error("a path below a nested mount counts as outside")
	}
	if outsideAll(filepath.Join(base, "c"), mounts) {
		t.Error("a mount path counts as outside")
	}
	if !outsideAll(base, mounts) || !outsideAll(filepath.Join(base, "d"), mounts) {
		t.Error("a path that no mount covers does not count as outside")
	}
	if !outsideAll(base, nil) {
		t.Error("every path is outside an empty mount list")
	}
}
