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

// IdleTaskActivityChan reports whether no task is running and returns the
// channel that closes when the next task becomes runnable. A caller that reads
// idle == true before a final accounting scan can wait on ch after the scan
// without missing a task wakeup that occurred during the scan.
//
// +checklocksexclude:k.runningTasksMu
func (k *Kernel) IdleTaskActivityChan() (ch <-chan struct{}, idle bool) {
	k.runningTasksMu.Lock()
	defer k.runningTasksMu.Unlock()
	if k.runningTasks.Load() != 0 {
		return nil, false
	}
	return k.taskActivityCh, true
}
