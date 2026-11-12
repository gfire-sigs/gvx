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

package gvx

import (
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// hostMemory returns the physical RAM of the host. It reads the value one time,
// before the host lockdown, and returns the cached value after that.
var hostMemory = sync.OnceValues(hostMemoryBytes)

// applyHostMemoryDefaults sets the process-wide memory values of the Sentry
// from the RAM of the host, as runsc does. A tmpfs mount without a size option
// then gets half of that RAM, size=N% resolves against it, and MemTotal in
// /proc/meminfo and sysinfo(2) reports that RAM. A memory limit of the sandbox
// changes only the reported total, which belongs to the kernel (see
// reportedMemory); the tmpfs sizes still follow the host RAM. New calls it
// before the host lockdown. When the host does not report its RAM, the Sentry
// keeps its built-in values.
var applyHostMemoryDefaults = sync.OnceFunc(func() {
	total, err := hostMemory()
	if err != nil || total == 0 {
		log.Warningf("gvx: read the host RAM: %v; tmpfs mounts get no default size", err)
		return
	}
	tmpfs.SetTotalHostMem(total)
	usage.MinimumTotalMemoryBytes = total
	usage.MaximumTotalMemoryBytes = total
})

// reportedMemory returns the total memory that the guest sees in
// /proc/meminfo and sysinfo(2). A limit below the host RAM wins, so tools in
// the guest, such as the kubelet, size the node from the limit. A limit above
// the host RAM reports the host RAM.
func reportedMemory(configured int64, hostRAM uint64) uint64 {
	if configured > 0 && (hostRAM == 0 || uint64(configured) < hostRAM) {
		return uint64(configured)
	}
	return hostRAM
}

// effectiveMemoryLimit returns the memory limit that the guard enforces and
// its poll interval. A limit that the caller sets wins, and the tunable
// memory.guard.poll_interval sets the interval. Without a limit, the guard
// stops a guest that passes the RAM of the host. That limit needs less
// precision, so the tunable memory.guard.host_poll_interval sets the interval.
// Zero means no guard.
func effectiveMemoryLimit(configured int64, hostRAM uint64, t tuning.Values) (uint64, time.Duration) {
	if configured > 0 {
		return uint64(configured), t.Duration(tuning.MemoryGuardPollInterval)
	}
	if hostRAM > 0 {
		return hostRAM, t.Duration(tuning.MemoryGuardHostPollInterval)
	}
	return 0, 0
}

// restoreFileLimit returns the largest backing file size in bytes that a
// restore accepts for the kernel memory file, or zero for no limit. The
// guard of a running sandbox keeps committed memory below the effective
// memory limit, and the file can hold uncommitted address space beyond it, so
// the bound is twice the limit plus one 1 GiB chunk.
func restoreFileLimit(configured int64, hostRAM uint64, t tuning.Values) uint64 {
	limit, _ := effectiveMemoryLimit(configured, hostRAM, t)
	if limit == 0 {
		return 0
	}
	const chunk = 1 << 30
	return 2*limit + chunk
}
