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

package sys

import (
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/kernfs"
)

func TestVirtGPUSysfsRefusesTakenEntries(t *testing.T) {
	g := &VirtGPUSysfs{DevMajor: 226, DevMinor: 128}
	for _, tc := range []struct {
		name  string
		taken int // index of the map that holds the taken entry
		entry string
	}{
		{"root complex", 1, "pci0000:00"},
		{"bus pci slot", 3, "0000:00:01.0"},
		{"bus virtio", 2, "virtio"},
		{"class drm", 0, "drm"},
		{"device number", 4, "226:128"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			maps := make([]map[string]kernfs.Inode, 5)
			for i := range maps {
				maps[i] = map[string]kernfs.Inode{}
			}
			maps[tc.taken][tc.entry] = nil
			if err := virtGPUCollision(g, maps[0], maps[1], maps[2], maps[3], maps[4]); err == nil {
				t.Errorf("virtGPUCollision with %s taken = nil, want an error", tc.entry)
			}
		})
	}
	if err := virtGPUCollision(g, map[string]kernfs.Inode{"net": nil}, map[string]kernfs.Inode{"system": nil}, nil, nil, nil); err != nil {
		t.Errorf("virtGPUCollision with unrelated entries = %v, want nil", err)
	}
}
