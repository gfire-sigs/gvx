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

import (
	"sync/atomic"
	"time"
)

// The cap of watched objects plays the role of fs.inotify.max_user_watches on
// Linux: inotify_add_watch fails with ENOSPC above it. The cap protects the
// resources that a host watch holds.
//
//   - On Linux and macOS each watched directory keeps one pinned descriptor.
//     macOS adds one kqueue registration for each watched object and for the
//     files below it, up to kqueueMaxRegistrations. A cap above the descriptor
//     limit of the process makes every later open fail with EMFILE, so the cap
//     follows RLIMIT_NOFILE (watchLimitFromNofile).
//   - On Windows each watched object holds one directory handle and one buffer
//     (see windowsMaxWatchedDentries).
//
// The scan cost of the poll backend is a third limit. A scan of one watched
// directory takes tens of microseconds, so a pass over 65,536 objects takes
// seconds and would keep one core busy all the time. pollDelay stretches the
// time between two passes instead.

const (
	// maxWatchedDentries is the largest cap on any host.
	maxWatchedDentries = 65536

	// minWatchedDentries is the smallest cap. A host with a lower descriptor
	// limit still gets room for a normal project tree.
	minWatchedDentries = 2048

	// watchFDReserve is the number of descriptors that the sandbox keeps for
	// its other uses: the pinned handle cache, volume files, listeners, and
	// the sockets of the network backends.
	watchFDReserve = 1024

	// pollDutyFactor sets the share of time that a polling backend may spend
	// in scans: a pass of duration d waits for pollDutyFactor times d before the
	// next one, so the scans take at most a quarter of one core.
	pollDutyFactor = 3
)

// watchLimitFromNofile returns the cap for a process that may hold soft
// descriptors, of which reserved stay free for other uses. The result lies
// between minWatchedDentries and maxWatchedDentries.
func watchLimitFromNofile(soft uint64, reserved int) int {
	usable := soft - min(soft, uint64(reserved))
	return int(max(min(usable, maxWatchedDentries), minWatchedDentries))
}

// pollDelay returns the time to wait after a pass of a polling backend that
// took pass. The delay never falls below the interval of the backend.
func pollDelay(interval, pass time.Duration) time.Duration {
	return max(interval, pollDutyFactor*pass)
}

// processWatches is the budget of watched objects that every workspace of the
// process shares. The descriptors of the process are one resource. The cap of
// one workspace follows the descriptor limit of the whole process, so the caps
// of two workspaces together would pass that limit, and every later open of
// every sandbox would fail with EMFILE. A watch that the budget refuses fails
// with ENOSPC, as one that the cap of the workspace refuses.
var processWatches processBudget

// processBudget counts the watched objects of all workspaces.
type processBudget struct {
	// limit is the size of the budget. OpenWorkspace sets it from the host. A
	// zero value stands for the largest cap.
	limit atomic.Int64
	// held is the number of watched objects of all workspaces.
	held atomic.Int64
}

// acquire takes one slot of the budget. It reports false when none is free.
func (b *processBudget) acquire() bool {
	limit := b.limit.Load()
	if limit == 0 {
		limit = maxWatchedDentries
	}
	for {
		held := b.held.Load()
		if held >= limit {
			return false
		}
		if b.held.CompareAndSwap(held, held+1) {
			return true
		}
	}
}

// release gives n slots back.
func (b *processBudget) release(n int) {
	b.held.Add(-int64(n))
}
