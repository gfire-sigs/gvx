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

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateMountsRefusesEmptyPathAndFilesystemRoot(t *testing.T) {
	volumeRoot := filepath.VolumeName(os.TempDir()) + string(filepath.Separator)
	for _, tt := range []struct {
		name   string
		mounts []HostMount
	}{
		{"empty path", []HostMount{{Path: ""}}},
		{"filesystem root", []HostMount{{Path: volumeRoot}}},
		{"read-only filesystem root", []HostMount{{Path: volumeRoot, ReadOnly: true}}},
		{"root after a valid mount", []HostMount{{Path: t.TempDir()}, {Path: volumeRoot}}},
		{"root spelled with dot segments", []HostMount{{Path: filepath.Join(volumeRoot, "a", "..")}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateMounts(tt.mounts); err == nil {
				t.Fatalf("validateMounts(%+v) accepted the mounts", tt.mounts)
			}
		})
	}
}

func TestValidateMountsAcceptsDuplicateAndNestedMounts(t *testing.T) {
	dir := t.TempDir()
	mounts := []HostMount{{Path: dir}, {Path: dir, ReadOnly: true}, {Path: filepath.Join(dir, "sub")}, {Path: filepath.Join(dir, "sub")}}
	if err := validateMounts(mounts); err != nil {
		t.Fatalf("validateMounts(%+v) = %v, want success", mounts, err)
	}
}
