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

// Package blockdev counts the block I/O that the Sentry does against the host
// files that back its file systems, and it names the disks that carry those
// counters. The kernel files /proc/diskstats, /proc/partitions, and
// /sys/block/<disk>/stat report the counters with the field rules of Linux.
//
// The Sentry has no block layer. Each engine that reads or writes a backing
// host file calls Stats.Begin before the host call and Stats.End after it, so
// one host call is one request.
package blockdev

import (
	"context"
	"sync/atomic"
	"time"
)

// SectorSize is the size of the sector in all counters. Linux counts sectors
// of 512 bytes, whatever the block size of the device is.
const SectorSize = 512

// Op is the kind of a request.
type Op int

const (
	// Read is a request that reads data from the disk.
	Read Op = iota
	// Write is a request that writes data to the disk.
	Write
	// Discard is a request that releases a range of the disk.
	Discard
	// Flush is a request that makes the earlier writes durable.
	Flush
	numOps
)

// Clock returns a monotonic time in nanoseconds. Only the differences of two
// values have a meaning.
type Clock func() int64

var processStart = time.Now()

// monotonicClock reads the monotonic clock of the process. The time package
// uses the monotonic reading of processStart, so the clock does not jump when
// the wall clock changes.
func monotonicClock() int64 { return int64(time.Since(processStart)) }

// opCounters is the count of one kind of request.
//
// +stateify savable
type opCounters struct {
	completed atomic.Uint64 `state:".(uint64)"`
	sectors   atomic.Uint64 `state:".(uint64)"`
	// ticks is the total time of the requests, in nanoseconds, from Begin to
	// End. Requests that overlap each add their own time.
	ticks atomic.Uint64 `state:".(uint64)"`
}

func (c *opCounters) saveCompleted() uint64                     { return c.completed.Load() }
func (c *opCounters) loadCompleted(_ context.Context, v uint64) { c.completed.Store(v) }
func (c *opCounters) saveSectors() uint64                       { return c.sectors.Load() }
func (c *opCounters) loadSectors(_ context.Context, v uint64)   { c.sectors.Store(v) }
func (c *opCounters) saveTicks() uint64                         { return c.ticks.Load() }
func (c *opCounters) loadTicks(_ context.Context, v uint64)     { c.ticks.Store(v) }

// Stats holds the counters of one disk. The zero value does not work: use
// NewStats. All methods are safe for concurrent use. No method takes a lock:
// each counter is an atomic word, so the CPUs of a guest that read one disk at
// once do not wait for each other.
//
// +stateify savable
type Stats struct {
	clock Clock `state:"nosave"`

	// ops holds the counters of each kind of request.
	ops [numOps]opCounters
	// inFlight is the number of requests between Begin and End.
	inFlight atomic.Int64 `state:".(int64)"`
	// ioTicks is the time, in nanoseconds, in which at least one request was
	// in flight.
	ioTicks atomic.Uint64 `state:".(uint64)"`
	// weighted is the sum, over all time, of the requests in flight, in
	// nanoseconds.
	weighted atomic.Uint64 `state:".(uint64)"`
	// last is the time of the latest update of ioTicks and weighted, in
	// milliseconds of the clock. Only the
	// goroutine that moves it forward adds the interval, so no interval counts
	// twice.
	last atomic.Int64 `state:"nosave"`
}

func (s *Stats) saveInFlight() int64                      { return s.inFlight.Load() }
func (s *Stats) loadInFlight(_ context.Context, v int64)  { s.inFlight.Store(v) }
func (s *Stats) saveIoTicks() uint64                      { return s.ioTicks.Load() }
func (s *Stats) loadIoTicks(_ context.Context, v uint64)  { s.ioTicks.Store(v) }
func (s *Stats) saveWeighted() uint64                     { return s.weighted.Load() }
func (s *Stats) loadWeighted(_ context.Context, v uint64) { s.weighted.Store(v) }

func (s *Stats) beforeSave() {
	if s.clock != nil {
		s.update(s.clock())
	}
}

func (s *Stats) afterLoad(context.Context) {
	if s.clock == nil {
		s.clock = monotonicClock
	}
	s.last.Store(s.clock() / int64(nsPerMilli))
}

// NewStats returns counters that read time from clock. A nil clock selects the
// monotonic clock of the process.
func NewStats(clock Clock) *Stats {
	if clock == nil {
		clock = monotonicClock
	}
	return &Stats{clock: clock}
}

// SetClock binds clock as the time source of s and rebases its tick stamp. A
// nil clock selects the monotonic clock of the process.
func (s *Stats) SetClock(clock Clock) {
	if clock == nil {
		clock = monotonicClock
	}
	s.clock = clock
	s.last.Store(clock() / int64(nsPerMilli))
}

// Request is a request between Begin and End.
//
// +stateify savable
type Request struct {
	start int64
}

// update adds the time since the last update to ioTicks and weighted, as
// update_io_ticks of Linux does. The stamp has the resolution of a millisecond,
// the resolution of the counters, so most calls see a stamp that is current and
// return after one load. The goroutine that moves the stamp forward owns the
// interval before it. A request that starts or ends at the same time reads the
// number of requests in flight a moment early or late, as it does on Linux, so
// the two times are exact only when the requests do not race.
func (s *Stats) update(now int64) {
	tick := now / int64(nsPerMilli)
	for {
		stamp := s.last.Load()
		if tick <= stamp {
			return
		}
		if !s.last.CompareAndSwap(stamp, tick) {
			continue
		}
		if n := s.inFlight.Load(); n > 0 {
			dt := uint64(tick-stamp) * nsPerMilli
			s.ioTicks.Add(dt)
			s.weighted.Add(dt * uint64(n))
		}
		return
	}
}

// Begin starts a request. Call End with the result when the host call returns.
func (s *Stats) Begin() Request {
	now := s.clock()
	s.update(now)
	s.inFlight.Add(1)
	return Request{start: now}
}

// End completes the request r of the kind op. The request moved n bytes. The
// sector count rounds up, because the host moves whole sectors. A Flush moves
// no sectors, whatever n is. A request that failed still completes: Linux
// counts the requests that end with an error too, and n is then what the host
// call transferred.
func (s *Stats) End(op Op, r Request, n int64) {
	now := s.clock()
	s.update(now)
	s.inFlight.Add(-1)
	c := &s.ops[op]
	c.completed.Add(1)
	if op != Flush && n > 0 {
		c.sectors.Add(uint64((n + SectorSize - 1) / SectorSize))
	}
	if dt := now - r.start; dt > 0 {
		c.ticks.Add(uint64(dt))
	}
}

// Add counts one completed request of the kind op that moved n bytes and took
// no measurable time, such as a range that a memory mapping takes from a page
// cache. It touches no clock and keeps no request in flight.
func (s *Stats) Add(op Op, n int64) {
	c := &s.ops[op]
	c.completed.Add(1)
	if op != Flush && n > 0 {
		c.sectors.Add(uint64((n + SectorSize - 1) / SectorSize))
	}
}

// Snapshot holds the counters of a disk at one time, in the units of
// /proc/diskstats. The comments give the field number of the Linux document
// Documentation/admin-guide/iostats.rst.
//
// +stateify savable
type Snapshot struct {
	// ReadsCompleted, ReadsMerged, SectorsRead, and ReadMillis are the fields 1
	// to 4.
	ReadsCompleted, ReadsMerged, SectorsRead, ReadMillis uint64
	// WritesCompleted, WritesMerged, SectorsWritten, and WriteMillis are the
	// fields 5 to 8.
	WritesCompleted, WritesMerged, SectorsWritten, WriteMillis uint64
	// InFlight is the field 9.
	InFlight uint64
	// IOMillis is the field 10: the time in which the disk had a request.
	IOMillis uint64
	// WeightedMillis is the field 11: the time of each request, added up.
	WeightedMillis uint64
	// DiscardsCompleted, DiscardsMerged, SectorsDiscarded, and DiscardMillis
	// are the fields 12 to 15.
	DiscardsCompleted, DiscardsMerged, SectorsDiscarded, DiscardMillis uint64
	// FlushesCompleted and FlushMillis are the fields 16 and 17.
	FlushesCompleted, FlushMillis uint64
}

const nsPerMilli = uint64(time.Millisecond)

// Snapshot returns the counters. The Sentry has no request queue that merges
// adjacent requests, so the merged counts are always 0. The counters are read
// one after the other, so a snapshot taken during a request can show it in some
// counters and not in others, as /proc/diskstats does on Linux.
func (s *Stats) Snapshot() Snapshot {
	s.update(s.clock())
	r, w, d, f := &s.ops[Read], &s.ops[Write], &s.ops[Discard], &s.ops[Flush]
	return Snapshot{
		ReadsCompleted:    r.completed.Load(),
		SectorsRead:       r.sectors.Load(),
		ReadMillis:        r.ticks.Load() / nsPerMilli,
		WritesCompleted:   w.completed.Load(),
		SectorsWritten:    w.sectors.Load(),
		WriteMillis:       w.ticks.Load() / nsPerMilli,
		InFlight:          uint64(max(s.inFlight.Load(), 0)),
		IOMillis:          s.ioTicks.Load() / nsPerMilli,
		WeightedMillis:    s.weighted.Load() / nsPerMilli,
		DiscardsCompleted: d.completed.Load(),
		SectorsDiscarded:  d.sectors.Load(),
		DiscardMillis:     d.ticks.Load() / nsPerMilli,
		FlushesCompleted:  f.completed.Load(),
		FlushMillis:       f.ticks.Load() / nsPerMilli,
	}
}

// NumFields is the number of counters in a Snapshot, which is the number of
// statistics fields that Linux 5.5 and later print.
const NumFields = 17

// Fields returns the counters in the order of the Linux statistics files:
// the fields 1 to 17 of Documentation/admin-guide/iostats.rst.
func (s Snapshot) Fields() [NumFields]uint64 {
	return [NumFields]uint64{
		s.ReadsCompleted, s.ReadsMerged, s.SectorsRead, s.ReadMillis,
		s.WritesCompleted, s.WritesMerged, s.SectorsWritten, s.WriteMillis,
		s.InFlight, s.IOMillis, s.WeightedMillis,
		s.DiscardsCompleted, s.DiscardsMerged, s.SectorsDiscarded, s.DiscardMillis,
		s.FlushesCompleted, s.FlushMillis,
	}
}
