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

package kernel

import (
	"runtime"
	"weak"

	"z.gfire.dev/gvx/pkg/sync"
)

// shmRmidForced holds kernel.shm_rmid_forced of the IPC namespaces that set it.
// The map holds the namespaces weakly, so a namespace that the guest drops
// frees its entry. A struct field would need a change in ipc_namespace.go.
var shmRmidForced struct {
	mu     sync.Mutex
	values map[weak.Pointer[IPCNamespace]]int32
}

// ShmRmidForced returns kernel.shm_rmid_forced of the namespace: 0 or 1. The
// value is stored only. The shm registry does not read it.
func (i *IPCNamespace) ShmRmidForced() int32 {
	shmRmidForced.mu.Lock()
	defer shmRmidForced.mu.Unlock()
	return shmRmidForced.values[weak.Make(i)]
}

// SetShmRmidForced stores kernel.shm_rmid_forced of the namespace.
func (i *IPCNamespace) SetShmRmidForced(v int32) {
	key := weak.Make(i)
	shmRmidForced.mu.Lock()
	defer shmRmidForced.mu.Unlock()
	if _, ok := shmRmidForced.values[key]; !ok {
		if shmRmidForced.values == nil {
			shmRmidForced.values = make(map[weak.Pointer[IPCNamespace]]int32)
		}
		runtime.AddCleanup(i, func(key weak.Pointer[IPCNamespace]) {
			shmRmidForced.mu.Lock()
			defer shmRmidForced.mu.Unlock()
			delete(shmRmidForced.values, key)
		}, key)
	}
	shmRmidForced.values[key] = v
}
