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

package proc

import (
	"bytes"
	"fmt"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/sentry/usage"
)

// The Sentry has no block layer, so /proc/diskstats describes one disk, vda,
// that stands for the root file system. Its counters come from usage.TotalIO,
// the read and write system calls of all tasks. The counts grow with every
// read and write, and they include sockets, pipes, and terminals.

const (
	diskstatsDevice = "vda"
	// diskstatsMajor is the block major that virtio disks use.
	diskstatsMajor = 254
	diskSectorSize = 512
)

// diskstatsData implements vfs.DynamicBytesSource for /proc/diskstats.
type diskstatsData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*diskstatsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate. The line has the 20
// fields of Linux 5.5 and later. The Sentry has no merged, discarded, or
// flushed requests and no latency, so those fields stay 0.
func (*diskstatsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "%4d %7d %s %d 0 %d 0 %d 0 %d 0 0 0 0 0 0 0 0 0 0\n",
		diskstatsMajor, 0, diskstatsDevice,
		usage.TotalIO.ReadSyscalls.Load(), usage.TotalIO.CharsRead.Load()/diskSectorSize,
		usage.TotalIO.WriteSyscalls.Load(), usage.TotalIO.CharsWritten.Load()/diskSectorSize)
	return nil
}
