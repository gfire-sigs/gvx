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

//go:build windows

package hostlockdown

import (
	"path/filepath"
	"testing"
)

func TestUnlistedProbeTargetsSkipPathsInsideAnyMount(t *testing.T) {
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("SystemRoot", filepath.Join(home, "windows"))
	mounts := []string{home, filepath.Join(home, "data")}
	for _, target := range unlistedProbeTargets(mounts) {
		if !outsideAll(target, mounts) {
			t.Errorf("probe target %q lies inside a mount", target)
		}
	}
	if got := unlistedProbeTargets(mounts); len(got) != 1 || got[0] != filepath.Dir(home) {
		t.Errorf("unlistedProbeTargets(%q) = %q, want only the parent of the outer mount", mounts, got)
	}
}
