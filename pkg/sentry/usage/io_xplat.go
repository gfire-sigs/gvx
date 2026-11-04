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

package usage

import "z.gfire.dev/gvx/pkg/atomicbitops"

// TotalIO counts the read and write system calls of every task of the process,
// including the tasks that exited. A task's IO value loses its counts when the
// task group is reaped, so /proc/diskstats reads this total instead.
// The counts include every file kind, not only files on a block device.
var TotalIO struct {
	ReadSyscalls  atomicbitops.Uint64
	WriteSyscalls atomicbitops.Uint64
	CharsRead     atomicbitops.Uint64
	CharsWritten  atomicbitops.Uint64
}

// accountTotalRead adds one read system call of bytes to TotalIO.
func accountTotalRead(bytes int64) {
	TotalIO.ReadSyscalls.Add(1)
	if bytes > 0 {
		TotalIO.CharsRead.Add(uint64(bytes))
	}
}

// accountTotalWrite adds one write system call of bytes to TotalIO.
func accountTotalWrite(bytes int64) {
	TotalIO.WriteSyscalls.Add(1)
	if bytes > 0 {
		TotalIO.CharsWritten.Add(uint64(bytes))
	}
}
