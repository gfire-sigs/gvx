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

package hostfs

import "errors"

// maxMetaEntries is the most entries that Workspace.meta holds. The table
// lives in memory and in one JSON file, so a guest that creates records
// without end would exhaust host memory.
const maxMetaEntries = 262144

// errMetaFull reports that a mutation would add a record to a full table.
// translateHostError maps it to ENOSPC.
var errMetaFull = errors.New("hostfs: the .gvx_meta table is full")

// metaLimit returns the entry limit for a workspace. A zero override selects
// the default.
func metaLimit(override int) int {
	if override > 0 {
		return override
	}
	return maxMetaEntries
}

// checkMetaRoomLocked fails with errMetaFull when the table has no room for a
// record at rel. A record that exists already needs no room. Every mutation
// that can add a record calls it before the first host change, so a refused
// mutation leaves no host file without a record. Callers hold w.mu.
func (w *Workspace) checkMetaRoomLocked(rel string) error {
	if _, ok := w.meta[rel]; ok || len(w.meta) < w.maxMeta {
		return nil
	}
	return errMetaFull
}
