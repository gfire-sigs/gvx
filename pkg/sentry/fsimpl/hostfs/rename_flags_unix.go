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

//go:build !windows

package hostfs

import "z.gfire.dev/gvx/internal/xsys/unix"

// exchange swaps the entries oldRel and newRel with one host call. Both parent
// directories resolve through descriptors, so the call stays inside the pinned
// workspace. renameSwap holds the call of the platform.
func (h *hostRoot) exchange(oldRel, newRel string) error {
	return h.withTwoParents("exchange", "and", oldRel, newRel, unix.EBUSY, renameSwap)
}
