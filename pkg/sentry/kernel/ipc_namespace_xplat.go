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

import "z.gfire.dev/gvx/internal/weakmap"

// shmRmidForcedFallback backs zero-valued IPCNamespace structs in tests that
// bypass NewIPCNamespace. Standard namespaces persist shm_rmid_forced directly
// in i.shms across checkpoint and restore.
var shmRmidForcedFallback weakmap.Map[IPCNamespace, int32]

// ShmRmidForced returns kernel.shm_rmid_forced of the namespace: 0 or 1. The
// value is stored only. The shm registry does not read it.
func (i *IPCNamespace) ShmRmidForced() int32 {
	if i == nil {
		return 0
	}
	if i.shms != nil {
		return i.shms.RmidForced()
	}
	v, _ := shmRmidForcedFallback.Load(i)
	return v
}

// SetShmRmidForced stores kernel.shm_rmid_forced of the namespace.
func (i *IPCNamespace) SetShmRmidForced(v int32) {
	if i == nil {
		return
	}
	if i.shms != nil {
		i.shms.SetRmidForced(v)
		return
	}
	shmRmidForcedFallback.Store(i, v)
}
