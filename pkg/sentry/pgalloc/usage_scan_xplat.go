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

package pgalloc

import (
	"runtime"

	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// canSkipUsageScan reports whether UpdateUsage may skip its scan because the
// usage of the memory file equals the committed bytes that it already knows.
// The usage is the block count of the file. Linux updates the count when a
// page commits. macOS updates it late, by up to 15 seconds in a measurement,
// so the scan for memory cgroups always runs on hosts other than Linux. The
// files memory.current and memory.stat must not show a cgroup as empty while
// its tasks hold memory.
func canSkipUsageScan(memCgIDs map[uint32]struct{}) bool {
	return memCgIDs == nil || runtime.GOOS == "linux"
}

// Accounting returns the memory usage accounting that f charges. It is
// MemoryFileOpts.Accounting, or usage.MemoryAccounting when the option is nil.
// A reader of the usage of one sandbox, such as /proc/meminfo or memory.current,
// must read the accounting of the memory file of that sandbox. The global
// usage.MemoryAccounting sums the memory of every kernel of the process.
func (f *MemoryFile) Accounting() *usage.MemoryLocked {
	if f.opts.Accounting != nil {
		return f.opts.Accounting
	}
	return usage.MemoryAccounting
}
