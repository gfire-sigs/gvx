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
	"strings"
)

// within reports whether path is root or lies below root. Both paths must be
// absolute and clean. Case rules follow filepath.Rel on the host OS.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// outsideAll reports whether path lies outside every directory in roots.
func outsideAll(path string, roots []string) bool {
	for _, root := range roots {
		if within(root, path) {
			return false
		}
	}
	return true
}
