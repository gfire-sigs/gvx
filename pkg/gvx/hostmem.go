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

	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// hostMemoryGuardInterval is the poll interval of the memory guard when the
// limit is the RAM of the host. That limit needs less precision than a limit
// that the caller sets.
const hostMemoryGuardInterval = 100 * time.Millisecond

// hostMemory returns the physical RAM of the host. It reads the value one time,
// before the host lockdown, and returns the cached value after that.
var hostMemory = sync.OnceValues(hostMemoryBytes)

// applyHostMemoryDefaults sets the process-wide memory values of the Sentry
// from the RAM of the host, as runsc does. A tmpfs mount without a size option
// then gets half of that RAM, size=N% resolves, and MemTotal in /proc/meminfo
// and sysinfo(2) reports that RAM. New calls it before the host lockdown. When
// the host does not report its RAM, the Sentry keeps its built-in values.
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

// setReportedMemory sets the total memory that the Sentry reports and returns a
// function that restores the previous values. The values are process-wide, as
// those of applyHostMemoryDefaults. The caller restores them after the guest
// ends, so a later sandbox in the same process starts with the old values.
func setReportedMemory(total uint64) (restore func()) {
	oldMin, oldMax := usage.MinimumTotalMemoryBytes, usage.MaximumTotalMemoryBytes
	usage.MinimumTotalMemoryBytes = total
	usage.MaximumTotalMemoryBytes = total
	return func() {
		usage.MinimumTotalMemoryBytes = oldMin
		usage.MaximumTotalMemoryBytes = oldMax
	}
}

// effectiveMemoryLimit returns the memory limit that the guard enforces and
// its poll interval. A limit that the caller sets wins. Without one, the
// guard stops a guest that passes the RAM of the host. Zero means no guard.
func effectiveMemoryLimit(configured int64, hostRAM uint64) (uint64, time.Duration) {
	if configured > 0 {
		return uint64(configured), memoryPollInterval
	}
	if hostRAM > 0 {
		return hostRAM, hostMemoryGuardInterval
	}
	return 0, 0
}
