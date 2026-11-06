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

package ext4lite

import (
	"bytes"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// disks returns the disks that the mounted volume registered.
func (e *env) disks() []*blockdev.Device {
	return blockdev.Of(e.vfsObj).Devices()
}

func TestMountedVolumeIsOneDiskWithTheNumbersOfItsFiles(t *testing.T) {
	e := newEnv(t)
	e.writeFile("/f", []byte("data"))

	disks := e.disks()
	if len(disks) != 1 {
		t.Fatalf("a mounted volume registered %d disks, want 1", len(disks))
	}
	d := disks[0]
	if d.Name != "vda" || d.Major != 254 || d.Minor != 0 {
		t.Errorf("disk = %s %d:%d, want vda 254:0", d.Name, d.Major, d.Minor)
	}
	for _, p := range []string{"/", "/f"} {
		st := e.mustStat(p)
		if st.DevMajor != d.Major || st.DevMinor != d.Minor {
			t.Errorf("st_dev of %s = %d:%d, want the disk number %d:%d", p, st.DevMajor, st.DevMinor, d.Major, d.Minor)
		}
	}
	if got := e.fs.MountSource(); got != "/dev/vda" {
		t.Errorf("MountSource = %q, want /dev/vda", got)
	}
	// The size of a disk does not change while the volume is mounted, although
	// the free space of the host does.
	first := d.Sectors()
	e.writeFile("/g", bytes.Repeat([]byte{'g'}, 1<<20))
	if first == 0 || d.Sectors() != first {
		t.Errorf("Sectors = %d and then %d, want one positive number", first, d.Sectors())
	}

	e.unmount()
	if got := e.disks(); len(got) != 0 {
		t.Errorf("an unmounted volume leaves %d disks, want 0", len(got))
	}
}

func TestFileDataCountsAsSectorsWrittenAndFlushes(t *testing.T) {
	e := newEnv(t)
	stats := e.disks()[0].Stats
	before := stats.Snapshot()

	const size = 4 << 20
	fd := e.mustOpen("/big", linux.O_CREAT|linux.O_WRONLY)
	defer fd.DecRef(e.ctx)
	e.write(fd, bytes.Repeat([]byte{'x'}, size))
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("fsync: %v", err)
	}

	after := stats.Snapshot()
	if got, want := after.SectorsWritten-before.SectorsWritten, uint64(size/blockdev.SectorSize); got < want {
		t.Errorf("sectors written grew by %d, want at least %d", got, want)
	}
	if after.WritesCompleted <= before.WritesCompleted {
		t.Errorf("writes completed stayed at %d", after.WritesCompleted)
	}
	if after.FlushesCompleted <= before.FlushesCompleted {
		t.Errorf("flushes completed stayed at %d after fsync", after.FlushesCompleted)
	}
	if after.InFlight != 0 {
		t.Errorf("requests in flight after fsync = %d, want 0", after.InFlight)
	}
}

func TestReadingFileDataCountsAsSectorsRead(t *testing.T) {
	e := newEnv(t)
	const size = 1 << 20
	e.writeFile("/f", bytes.Repeat([]byte{'y'}, size))
	e = e.remount()
	stats := e.disks()[0].Stats
	before := stats.Snapshot()

	if got := e.readFile("/f"); len(got) != size {
		t.Fatalf("read %d bytes, want %d", len(got), size)
	}

	after := stats.Snapshot()
	if got, want := after.SectorsRead-before.SectorsRead, uint64(size/blockdev.SectorSize); got < want {
		t.Errorf("sectors read grew by %d, want at least %d", got, want)
	}
	if after.SectorsWritten != before.SectorsWritten {
		t.Errorf("a read changed the sectors written from %d to %d", before.SectorsWritten, after.SectorsWritten)
	}
}

func TestReadOnlyVolumeIsAReadOnlyDisk(t *testing.T) {
	first := newEnv(t)
	path := first.path
	first.unmount()
	e := openEnv(t, path, VolumeOptions{ReadOnly: true}, vfs.MountOptions{ReadOnly: true})
	if d := e.disks(); len(d) != 1 || !d[0].ReadOnly {
		t.Errorf("a read-only volume registered %+v, want one read-only disk", d)
	}
}

func TestCountedFileCountsHostCalls(t *testing.T) {
	stats := blockdev.NewStats(nil)
	hf := &countedFile{hostFile: newTestHostFile(t, false), stats: stats}
	t.Cleanup(func() { hf.Close() })

	if _, err := hf.WriteAt(make([]byte, 8192), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if _, err := hf.ReadAt(make([]byte, 4096), 4096); err != nil {
		t.Fatalf("ReadAt: %v", err)
	}
	if _, err := hf.ReadAt(nil, 0); err != nil {
		t.Fatalf("ReadAt of nothing: %v", err)
	}
	if err := hf.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	// A call that grows the file moves no data and releases nothing.
	if err := hf.Truncate(16384); err != nil {
		t.Fatalf("Truncate grow: %v", err)
	}
	if err := hf.EnsureSize(32768); err != nil {
		t.Fatalf("EnsureSize: %v", err)
	}
	before := stats.Snapshot()
	if before.DiscardsCompleted != 0 {
		t.Errorf("growing the file counted %d discards, want 0", before.DiscardsCompleted)
	}
	sizeBefore, err := hf.Size()
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if err := hf.Truncate(12288); err != nil {
		t.Fatalf("Truncate shrink: %v", err)
	}

	got := stats.Snapshot()
	if got.WritesCompleted != 1 || got.SectorsWritten != 16 {
		t.Errorf("writes = %d requests, %d sectors, want 1, 16", got.WritesCompleted, got.SectorsWritten)
	}
	if got.ReadsCompleted != 1 || got.SectorsRead != 8 {
		t.Errorf("reads = %d requests, %d sectors, want 1, 8 (an empty read counts nothing)", got.ReadsCompleted, got.SectorsRead)
	}
	if got.FlushesCompleted != 1 {
		t.Errorf("flushes = %d, want 1", got.FlushesCompleted)
	}
	if want := uint64((sizeBefore - 12288) / blockdev.SectorSize); got.DiscardsCompleted != 1 || got.SectorsDiscarded != want {
		t.Errorf("discards = %d requests, %d sectors, want 1, %d", got.DiscardsCompleted, got.SectorsDiscarded, want)
	}
}
