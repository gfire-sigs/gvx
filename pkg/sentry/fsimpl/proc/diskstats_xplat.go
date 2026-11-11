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
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// /proc/diskstats and /proc/partitions list the disks of the sandbox. A disk is
// the host file that backs a file system: the image of an ext4lite volume, and
// the EROFS layers of the root file system. The counters come from the I/O that
// the Sentry does against that host file (package blockdev), so a socket, a
// pipe, a terminal, and a tmpfs file never change them.

// disks returns the disks of the kernel of the reader.
func disks(ctx context.Context) []*blockdev.Device {
	return blockdev.Of(kernel.KernelFromContext(ctx).VFS()).Devices()
}

// diskstatsData implements vfs.DynamicBytesSource for /proc/diskstats.
//
// +stateify savable
type diskstatsData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*diskstatsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate. Each line has the 20
// columns of Linux 5.5 and later: the device numbers, the name, and the 17
// counters of Snapshot.
func (*diskstatsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	writeDiskstats(buf, disks(ctx))
	return nil
}

// writeDiskstats writes the line of each disk in the format of /proc/diskstats.
func writeDiskstats(buf *bytes.Buffer, disks []*blockdev.Device) {
	for _, d := range disks {
		fmt.Fprintf(buf, "%4d %7d %s", d.Major, d.Minor, d.Name)
		for _, v := range d.Stats.Snapshot().Fields() {
			fmt.Fprintf(buf, " %d", v)
		}
		buf.WriteByte('\n')
	}
}

// partitionsData implements vfs.DynamicBytesSource for /proc/partitions.
//
// +stateify savable
type partitionsData struct {
	dynamicBytesFileSetAttr
}

var _ dynamicInode = (*partitionsData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate. The size is in blocks of
// 1 KiB, as on Linux.
func (*partitionsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	writePartitions(buf, disks(ctx))
	return nil
}

// writePartitions writes the header and the line of each disk in the format of
// /proc/partitions.
func writePartitions(buf *bytes.Buffer, disks []*blockdev.Device) {
	buf.WriteString("major minor  #blocks  name\n\n")
	for _, d := range disks {
		fmt.Fprintf(buf, "%4d  %7d %10d %s\n", d.Major, d.Minor, d.Sectors()/(1024/blockdev.SectorSize), d.Name)
	}
}
