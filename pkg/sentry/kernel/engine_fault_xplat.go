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

// engineFaults holds the cause of the last engine fault of each kernel. The map
// holds the kernels weakly, so a kernel that a test drops frees its entry. A
// struct field would need a change in kernel.go.
var engineFaults struct {
	mu     sync.Mutex
	causes map[weak.Pointer[Kernel]]string
}

// recordEngineFault keeps the text of err as the cause of the last engine fault
// of the kernel. A task calls it when the platform fails to run the task, and
// the kernel then ends the task group with SIGKILL.
func (k *Kernel) recordEngineFault(err error) {
	key := weak.Make(k)
	engineFaults.mu.Lock()
	defer engineFaults.mu.Unlock()
	if engineFaults.causes == nil {
		engineFaults.causes = make(map[weak.Pointer[Kernel]]string)
	}
	if _, ok := engineFaults.causes[key]; !ok {
		runtime.AddCleanup(k, func(key weak.Pointer[Kernel]) {
			engineFaults.mu.Lock()
			defer engineFaults.mu.Unlock()
			delete(engineFaults.causes, key)
		}, key)
	}
	engineFaults.causes[key] = err.Error()
}

// TakeEngineFault returns the cause of the last engine fault of the kernel and
// clears it. It returns an empty string when no fault happened. A process that
// runs more than one kernel gets the fault of this kernel only.
func (k *Kernel) TakeEngineFault() string {
	engineFaults.mu.Lock()
	defer engineFaults.mu.Unlock()
	key := weak.Make(k)
	cause := engineFaults.causes[key]
	delete(engineFaults.causes, key)
	return cause
}
