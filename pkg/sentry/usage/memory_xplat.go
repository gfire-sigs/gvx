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

package usage

// NewMemoryLocked returns an accounting that no file backs. A process that runs
// more than one Sentry kernel gives each kernel its own accounting through
// pgalloc.MemoryFileOpts.Accounting, so the counters of one kernel never include
// the memory of another. The real-time counters of the result live in the heap
// and no other process reads them.
func NewMemoryLocked() *MemoryLocked {
	return &MemoryLocked{
		RTMemoryStats:     &RTMemoryStats{},
		MemCgIDToMemStats: make(map[uint32]*memoryStats),
	}
}
