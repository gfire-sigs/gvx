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

// IOTotals counts the read and write system calls of the tasks of a kernel
// since it started.
type IOTotals struct {
	ReadSyscalls  uint64
	WriteSyscalls uint64
	CharsRead     uint64
	CharsWritten  uint64
}

// exitedIO holds the counts of the tasks that exited, by kernel. A task keeps
// its counts only until it dies, so the kernel adds them here at that moment.
// The map holds the kernels weakly, so a kernel that a test drops frees its
// entry. The exit path adds under the TaskSet mutex, which IOTotals also holds,
// so a count never shows twice or not at all.
var exitedIO struct {
	mu     sync.Mutex
	totals map[weak.Pointer[Kernel]]*IOTotals
}

// accountExitedIO adds the counts of the dying task t to the kernel totals.
//
// +checklocks:t.tg.pidns.owner.mu
func (t *Task) accountExitedIO() {
	key := weak.Make(t.k)
	exitedIO.mu.Lock()
	defer exitedIO.mu.Unlock()
	total, ok := exitedIO.totals[key]
	if !ok {
		if exitedIO.totals == nil {
			exitedIO.totals = make(map[weak.Pointer[Kernel]]*IOTotals)
		}
		total = new(IOTotals)
		exitedIO.totals[key] = total
		runtime.AddCleanup(t.k, func(key weak.Pointer[Kernel]) {
			exitedIO.mu.Lock()
			defer exitedIO.mu.Unlock()
			delete(exitedIO.totals, key)
		}, key)
	}
	total.ReadSyscalls += t.ioUsage.ReadSyscalls.Load()
	total.WriteSyscalls += t.ioUsage.WriteSyscalls.Load()
	total.CharsRead += t.ioUsage.CharsRead.Load()
	total.CharsWritten += t.ioUsage.CharsWritten.Load()
}

// IOTotals returns the counts of the live tasks plus those of the tasks that
// exited. The syscall path pays nothing for it: each task counts for itself.
func (k *Kernel) IOTotals() IOTotals {
	ts := k.tasks
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	var sum IOTotals
	ts.forEachTaskLocked(func(t *Task) {
		sum.ReadSyscalls += t.ioUsage.ReadSyscalls.Load()
		sum.WriteSyscalls += t.ioUsage.WriteSyscalls.Load()
		sum.CharsRead += t.ioUsage.CharsRead.Load()
		sum.CharsWritten += t.ioUsage.CharsWritten.Load()
	})
	exitedIO.mu.Lock()
	defer exitedIO.mu.Unlock()
	if done, ok := exitedIO.totals[weak.Make(k)]; ok {
		sum.ReadSyscalls += done.ReadSyscalls
		sum.WriteSyscalls += done.WriteSyscalls
		sum.CharsRead += done.CharsRead
		sum.CharsWritten += done.CharsWritten
	}
	return sum
}
