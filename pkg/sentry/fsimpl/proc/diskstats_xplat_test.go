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
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/sentry/blockdev"
)

// testDisk adds a disk with a known size and one read and one write request.
func testDisk(t *testing.T, r *blockdev.Registry, sectors uint64) *blockdev.Device {
	t.Helper()
	var now int64
	stats := blockdev.NewStats(func() int64 { return now })
	req := stats.Begin()
	now += 3_000_000
	stats.End(blockdev.Read, req, 8192)
	req = stats.Begin()
	now += 5_000_000
	stats.End(blockdev.Write, req, 1<<20)
	d, err := r.Add(blockdev.Options{Stats: stats, Sectors: func() uint64 { return sectors }})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	return d
}

func TestDiskstatsHasOneLineOfTwentyColumnsForEachDisk(t *testing.T) {
	var r blockdev.Registry
	testDisk(t, &r, 2048)
	testDisk(t, &r, 4096)

	var buf bytes.Buffer
	writeDiskstats(&buf, r.Devices())

	want := "" +
		" 254       0 vda 1 0 16 3 1 0 2048 5 0 8 8 0 0 0 0 0 0\n" +
		" 254      16 vdb 1 0 16 3 1 0 2048 5 0 8 8 0 0 0 0 0 0\n"
	if got := buf.String(); got != want {
		t.Errorf("diskstats =\n%q\nwant\n%q", got, want)
	}
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if n := len(strings.Fields(line)); n != 20 {
			t.Errorf("line %q has %d columns, want 20", line, n)
		}
	}
}

func TestDiskstatsOfNoDiskIsEmpty(t *testing.T) {
	var buf bytes.Buffer
	writeDiskstats(&buf, nil)
	if buf.Len() != 0 {
		t.Errorf("diskstats without a disk = %q, want empty", buf.String())
	}
}

func TestPartitionsListSizeInKiB(t *testing.T) {
	var r blockdev.Registry
	testDisk(t, &r, 2048)
	testDisk(t, &r, 2<<21+1)

	var buf bytes.Buffer
	writePartitions(&buf, r.Devices())

	want := "major minor  #blocks  name\n\n" +
		" 254        0       1024 vda\n" +
		" 254       16    2097152 vdb\n"
	if got := buf.String(); got != want {
		t.Errorf("partitions =\n%q\nwant\n%q", got, want)
	}
}
