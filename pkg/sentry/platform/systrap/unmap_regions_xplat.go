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

//go:build linux

package systrap

import (
	"errors"
	"fmt"
	"slices"
	"sync"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/arch"
)

// sealedHoles lists the address ranges that the host kernel refuses to unmap.
// A host kernel can seal a mapping that its Sentry owns, such as the syscall
// patching table of a host Sentry. The Sentry process holds the mapping, and
// every stub process inherits it by fork. A stub that runs under such a kernel
// is the stub of a nested Sentry.
var sealedHoles struct {
	sync.Mutex
	ranges []mapsRegion
}

// unmapRange unmaps [addr, addr+length) in the stub process, except for the
// sealed ranges of the host kernel.
//
// This will panic on any failure other than a refusal with EPERM (which should
// never happen).
func (s *subprocess) unmapRange(addr, length uintptr) {
	sealedHoles.Lock()
	holes := slices.Clone(sealedHoles.ranges)
	sealedHoles.Unlock()
	for _, r := range subtractRanges(mapsRegion{start: addr, end: addr + length}, holes) {
		s.unmapSegment(r)
	}
}

// unmapSegment unmaps r with one call. When the host kernel refuses with EPERM,
// it splits r in two halves until it finds the host pages that the host kernel
// seals, and it records them in sealedHoles.
func (s *subprocess) unmapSegment(r mapsRegion) {
	unmapSegmentWith(
		r,
		hostPageSize,
		func(start, length uintptr) error {
			_, err := s.syscall(
				unix.SYS_MUNMAP,
				arch.SyscallArgument{Value: start},
				arch.SyscallArgument{Value: length})
			return err
		},
		func(hole mapsRegion) {
			log.Debugf("The host kernel keeps the sealed page %x in the stub process.", hole.start)
			sealedHoles.Lock()
			sealedHoles.ranges = addRange(sealedHoles.ranges, hole)
			sealedHoles.Unlock()
		},
	)
}

func unmapSegmentWith(r mapsRegion, unit uintptr, unmap func(start, length uintptr) error, recordHole func(mapsRegion)) {
	err := unmap(r.start, r.end-r.start)
	switch {
	case err == nil || err == errDeadSubprocess:
	case errors.Is(err, unix.EPERM) && r.end-r.start > unit:
		half := ((r.end - r.start) / 2) &^ (unit - 1)
		if half == 0 {
			half = unit
		}
		mid := r.start + half
		if mid >= r.end {
			recordHole(r)
			return
		}
		unmapSegmentWith(mapsRegion{start: r.start, end: mid}, unit, unmap, recordHole)
		unmapSegmentWith(mapsRegion{start: mid, end: r.end}, unit, unmap, recordHole)
	case errors.Is(err, unix.EPERM):
		recordHole(r)
	default:
		panic(fmt.Sprintf("munmap(%x, %x)) failed: %v", r.start, r.end-r.start, err))
	}
}

// isForkStubSealedSweep reports whether err is EPERM from forkStub's
// upper-range munmap sweep (stubROMapEnd..maximumUserAddress). The
// subsequent subprocess.unmap call isolates sealed pages page by page.
func isForkStubSealedSweep(args []arch.SyscallArgument, err error) bool {
	return errors.Is(err, unix.EPERM) &&
		len(args) >= 2 &&
		args[0].Value == stubROMapEnd &&
		args[1].Value == maximumUserAddress-stubROMapEnd
}

// subtractRanges returns the parts of r that no range of holes covers. holes
// is sorted and its ranges do not overlap.
func subtractRanges(r mapsRegion, holes []mapsRegion) []mapsRegion {
	var parts []mapsRegion
	for _, h := range holes {
		if h.end <= r.start || h.start >= r.end {
			continue
		}
		if h.start > r.start {
			parts = append(parts, mapsRegion{start: r.start, end: h.start})
		}
		r.start = max(r.start, h.end)
	}
	if r.start < r.end {
		parts = append(parts, r)
	}
	return parts
}

// addRange adds r to the sorted ranges, and joins the ranges that touch or
// overlap.
func addRange(ranges []mapsRegion, r mapsRegion) []mapsRegion {
	ranges = append(ranges, r)
	slices.SortFunc(ranges, func(a, b mapsRegion) int {
		switch {
		case a.start < b.start:
			return -1
		case a.start > b.start:
			return 1
		}
		return 0
	})
	joined := ranges[:1]
	for _, next := range ranges[1:] {
		last := &joined[len(joined)-1]
		if next.start <= last.end {
			last.end = max(last.end, next.end)
			continue
		}
		joined = append(joined, next)
	}
	return joined
}
