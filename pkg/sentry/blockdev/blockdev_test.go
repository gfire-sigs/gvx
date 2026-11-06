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

package blockdev

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// fakeClock is a clock that the test moves.
type fakeClock struct{ now int64 }

func (c *fakeClock) Clock() int64            { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now += int64(d) }
func newStats() (*Stats, *fakeClock) {
	c := &fakeClock{now: 1}
	return NewStats(c.Clock), c
}

func TestSectorsRoundUpAndRequestsCount(t *testing.T) {
	s, c := newStats()
	r := s.Begin()
	c.Advance(3 * time.Millisecond)
	s.End(Read, r, 4096)
	r = s.Begin()
	c.Advance(2 * time.Millisecond)
	s.End(Read, r, 513)
	r = s.Begin()
	c.Advance(5 * time.Millisecond)
	s.End(Write, r, 1<<20)

	got := s.Snapshot()
	want := Snapshot{
		ReadsCompleted: 2, SectorsRead: 8 + 2, ReadMillis: 5,
		WritesCompleted: 1, SectorsWritten: 2048, WriteMillis: 5,
		IOMillis: 10, WeightedMillis: 10,
	}
	if got != want {
		t.Errorf("Snapshot = %+v, want %+v", got, want)
	}
}

func TestOverlappingRequestsWeighTheirTime(t *testing.T) {
	s, c := newStats()
	a := s.Begin()
	c.Advance(10 * time.Millisecond)
	b := s.Begin()
	if got := s.Snapshot().InFlight; got != 2 {
		t.Errorf("InFlight with two requests = %d, want 2", got)
	}
	c.Advance(10 * time.Millisecond)
	s.End(Read, a, 512)
	c.Advance(10 * time.Millisecond)
	s.End(Write, b, 512)
	// Time with a request in flight: 30 ms. Weighted: 10*1 + 10*2 + 10*1.
	got := s.Snapshot()
	if got.IOMillis != 30 || got.WeightedMillis != 40 {
		t.Errorf("IOMillis, WeightedMillis = %d, %d, want 30, 40", got.IOMillis, got.WeightedMillis)
	}
	if got.ReadMillis != 20 || got.WriteMillis != 20 {
		t.Errorf("ReadMillis, WriteMillis = %d, %d, want 20, 20", got.ReadMillis, got.WriteMillis)
	}
	if got.InFlight != 0 {
		t.Errorf("InFlight after both ended = %d, want 0", got.InFlight)
	}
}

func TestIdleTimeIsNotIOTime(t *testing.T) {
	s, c := newStats()
	r := s.Begin()
	c.Advance(4 * time.Millisecond)
	s.End(Read, r, 512)
	c.Advance(time.Hour)
	if got := s.Snapshot().IOMillis; got != 4 {
		t.Errorf("IOMillis after an idle hour = %d, want 4", got)
	}
}

func TestInFlightRequestAddsIOTimeAtSnapshot(t *testing.T) {
	s, c := newStats()
	s.Begin()
	c.Advance(7 * time.Millisecond)
	got := s.Snapshot()
	if got.InFlight != 1 || got.IOMillis != 7 || got.WeightedMillis != 7 {
		t.Errorf("Snapshot of an open request = %+v, want InFlight 1, IOMillis 7, WeightedMillis 7", got)
	}
}

func TestDiscardAndFlushFields(t *testing.T) {
	s, c := newStats()
	r := s.Begin()
	c.Advance(time.Millisecond)
	s.End(Discard, r, 8192)
	r = s.Begin()
	c.Advance(9 * time.Millisecond)
	s.End(Flush, r, 4096) // A flush moves no sectors, whatever n is.
	got := s.Snapshot()
	if got.DiscardsCompleted != 1 || got.SectorsDiscarded != 16 || got.DiscardMillis != 1 {
		t.Errorf("discard fields = %d, %d, %d, want 1, 16, 1", got.DiscardsCompleted, got.SectorsDiscarded, got.DiscardMillis)
	}
	if got.FlushesCompleted != 1 || got.FlushMillis != 9 {
		t.Errorf("flush fields = %d, %d, want 1, 9", got.FlushesCompleted, got.FlushMillis)
	}
	if got.SectorsRead != 0 || got.SectorsWritten != 0 {
		t.Errorf("a discard and a flush changed the read and write sectors: %+v", got)
	}
}

func TestDefaultClockNeverGoesBack(t *testing.T) {
	s := NewStats(nil)
	r := s.Begin()
	s.End(Write, r, 512)
	got := s.Snapshot()
	if got.WritesCompleted != 1 || got.InFlight != 0 {
		t.Errorf("Snapshot with the default clock = %+v, want one completed write", got)
	}
	prev := monotonicClock()
	for range 1000 {
		now := monotonicClock()
		if now < prev {
			t.Fatalf("the clock went back from %d to %d", prev, now)
		}
		prev = now
	}
}

func TestDiskNames(t *testing.T) {
	for index, want := range map[int]string{0: "vda", 1: "vdb", 25: "vdz", 26: "vdaa", 27: "vdab", 51: "vdaz", 52: "vdba", 701: "vdzz", 702: "vdaaa"} {
		if got := diskName(index); got != want {
			t.Errorf("diskName(%d) = %q, want %q", index, got, want)
		}
	}
}

func TestRegistryAssignsLowestFreeIndex(t *testing.T) {
	var r Registry
	add := func() *Device {
		d, err := r.Add(Options{Stats: NewStats(nil), Sectors: func() uint64 { return 8 }})
		if err != nil {
			t.Fatalf("Add: %v", err)
		}
		return d
	}
	a, b, c := add(), add(), add()
	for i, d := range []*Device{a, b, c} {
		if d.Major != 254 || d.Minor != uint32(i*16) {
			t.Errorf("disk %s = %d:%d, want 254:%d", d.Name, d.Major, d.Minor, i*16)
		}
	}
	r.Remove(b)
	r.Remove(b) // A second Remove has no effect.
	if got := r.Find("vdb"); got != nil {
		t.Errorf("Find(vdb) after Remove = %v, want nil", got)
	}
	d := add()
	if d.Name != "vdb" || d.Minor != 16 {
		t.Errorf("the new disk = %s %d, want vdb 16", d.Name, d.Minor)
	}
	var names []string
	for _, d := range r.Devices() {
		names = append(names, d.Name)
	}
	if len(names) != 3 || names[0] != "vda" || names[1] != "vdb" || names[2] != "vdc" {
		t.Errorf("Devices = %v, want [vda vdb vdc]", names)
	}
	if got := r.Find("vdc"); got != c {
		t.Errorf("Find(vdc) = %v, want the third disk", got)
	}
}

func TestOfReturnsOneRegistryForEachVFS(t *testing.T) {
	v1, v2 := new(vfs.VirtualFilesystem), new(vfs.VirtualFilesystem)
	if Of(v1) != Of(v1) {
		t.Error("Of(v1) returned two registries")
	}
	if Of(v1) == Of(v2) {
		t.Error("Of returned one registry for two VFS objects")
	}
}

// BenchmarkRequestParallel measures one request on a disk that all CPUs share,
// as the reads of a root image do.
func BenchmarkRequestParallel(b *testing.B) {
	s := NewStats(nil)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			r := s.Begin()
			s.End(Read, r, 4096)
		}
	})
}

func TestAddCountsWithoutTimeOrFlight(t *testing.T) {
	s, c := newStats()
	s.Add(Read, 8192)
	c.Advance(time.Hour)
	got := s.Snapshot()
	want := Snapshot{ReadsCompleted: 1, SectorsRead: 16}
	if got != want {
		t.Errorf("Snapshot after Add = %+v, want %+v", got, want)
	}
}

func TestParallelRequestsLoseNoCount(t *testing.T) {
	const workers, perWorker = 16, 2000
	s := NewStats(nil)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range perWorker {
				r := s.Begin()
				s.End(Write, r, 4096)
				s.Add(Read, 512)
			}
		}()
	}
	wg.Wait()
	got := s.Snapshot()
	if got.WritesCompleted != workers*perWorker || got.SectorsWritten != workers*perWorker*8 {
		t.Errorf("writes = %d requests, %d sectors, want %d, %d", got.WritesCompleted, got.SectorsWritten, workers*perWorker, workers*perWorker*8)
	}
	if got.ReadsCompleted != workers*perWorker || got.SectorsRead != workers*perWorker {
		t.Errorf("reads = %d requests, %d sectors, want %d, %d", got.ReadsCompleted, got.SectorsRead, workers*perWorker, workers*perWorker)
	}
	if got.InFlight != 0 {
		t.Errorf("InFlight = %d, want 0", got.InFlight)
	}
}

func TestFirstTouchCountsEachPageOnce(t *testing.T) {
	ft := NewFirstTouch(10 * PageSize)
	for _, tc := range []struct {
		name   string
		off, n uint64
		want   uint64
	}{
		{"first page", 0, 100, PageSize},
		{"same page again", 50, 100, 0},
		{"range over a page boundary", PageSize - 1, 2, PageSize},
		{"pages 3 to 5", 3 * PageSize, 3 * PageSize, 3 * PageSize},
		{"overlap of old and new pages", 4 * PageSize, 3 * PageSize, PageSize},
		{"empty range", 7 * PageSize, 0, 0},
		{"up to the end of the image", 8 * PageSize, 100 * PageSize, 2 * PageSize},
		{"beyond the image", 20 * PageSize, 10, 0},
	} {
		if got := ft.Claim(tc.off, tc.n); got != tc.want {
			t.Errorf("%s: Claim(%d, %d) = %d, want %d", tc.name, tc.off, tc.n, got, tc.want)
		}
	}
}

func TestFirstTouchAcrossWordsAndImagesWithAPartialLastPage(t *testing.T) {
	ft := NewFirstTouch(200*PageSize + 17)
	if got, want := ft.Claim(0, 200*PageSize+17), uint64(201*PageSize); got != want {
		t.Errorf("Claim of the whole image = %d, want %d", got, want)
	}
	if got := ft.Claim(63*PageSize, 3*PageSize); got != 0 {
		t.Errorf("Claim over a word boundary after a full claim = %d, want 0", got)
	}
}

func TestFirstTouchParallelClaimsCountEachPageOnce(t *testing.T) {
	const pages = 4096
	ft := NewFirstTouch(pages * PageSize)
	var total atomic.Uint64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := uint64(0); p < pages; p += 3 {
				total.Add(ft.Claim(p*PageSize, 5*PageSize))
			}
		}()
	}
	wg.Wait()
	if got, want := total.Load(), uint64(pages*PageSize); got != want {
		t.Errorf("eight overlapping claimers counted %d bytes, want %d", got, want)
	}
}
