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

// engineFaults holds the cause of the last engine fault of each kernel weakly,
// so a kernel dropped by a test frees its entry automatically.
var engineFaults weakmap.Map[Kernel, string]

// recordEngineFault keeps the text of err as the cause of the last engine fault
// of the kernel. A task calls it when the platform fails to run the task, and
// the kernel then ends the task group with SIGKILL.
func (k *Kernel) recordEngineFault(err error) {
	engineFaults.Store(k, err.Error())
}

// TakeEngineFault returns the cause of the last engine fault of the kernel and
// clears it. It returns an empty string when no fault happened. A process that
// runs more than one kernel gets the fault of this kernel only.
func (k *Kernel) TakeEngineFault() string {
	cause, _ := engineFaults.Delete(k)
	return cause
}
