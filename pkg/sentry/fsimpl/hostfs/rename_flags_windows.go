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

package hostfs

import "fmt"

// exchange reports that NTFS has no call that swaps two names atomically.
// WorkspaceCaps.NativeRenameSwap is false on Windows, so Workspace swaps the
// names with three renames through a "~gvx~swap" file and never calls this
// method.
func (h *hostRoot) exchange(oldRel, newRel string) error {
	return fmt.Errorf("hostfs: exchange %q and %q: %w", oldRel, newRel, errHostUnsupported)
}
