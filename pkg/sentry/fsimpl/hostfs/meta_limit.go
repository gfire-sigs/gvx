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

// maxMetaBytes is the memory that the records of one Workspace may use. The
// table lives in memory and in the .gvx_meta journal, so a guest that creates
// records without end would exhaust host memory. The cap counts the estimated
// size of each record (see recSize), so a table of small records holds more
// entries than a table of records with large attributes. About 1,100,000 plain
// records fit, twice the files and directories of a Chromium source tree.
const maxMetaBytes = 512 << 20

// errMetaFull reports that a mutation would add a record to a full table.
// translateHostError maps it to ENOSPC.
var errMetaFull = errors.New("hostfs: the .gvx_meta table is full")

// metaLimit returns the memory cap in bytes for a workspace. A zero override
// selects the default.
func metaLimit(override int64) int64 {
	if override > 0 {
		return override
	}
	return maxMetaBytes
}
