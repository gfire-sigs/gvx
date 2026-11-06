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
	"z.gfire.dev/gvx/pkg/hostarch"
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
// it splits r in two halves until it finds the pages that the host kernel
// seals, and it records them in sealedHoles.
func (s *subprocess) unmapSegment(r mapsRegion) {
	_, err := s.syscall(
		unix.SYS_MUNMAP,
		arch.SyscallArgument{Value: r.start},
		arch.SyscallArgument{Value: r.end - r.start})
	switch {
	case err == nil || err == errDeadSubprocess:
	case errors.Is(err, unix.EPERM) && r.end-r.start > hostarch.PageSize:
		mid := r.start + (r.end-r.start)/2
		mid -= mid % hostarch.PageSize
		s.unmapSegment(mapsRegion{start: r.start, end: mid})
		s.unmapSegment(mapsRegion{start: mid, end: r.end})
	case errors.Is(err, unix.EPERM):
		log.Debugf("The host kernel keeps the sealed page %x in the stub process.", r.start)
		sealedHoles.Lock()
		sealedHoles.ranges = addRange(sealedHoles.ranges, r)
		sealedHoles.Unlock()
	default:
		panic(fmt.Sprintf("munmap(%x, %x)) failed: %v", r.start, r.end-r.start, err))
	}
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
