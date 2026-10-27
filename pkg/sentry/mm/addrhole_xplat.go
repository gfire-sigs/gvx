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

package mm

import (
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// addressHole returns the gap inside the guest address range that no mapping
// may use. A platform that has no gap returns an empty range.
func (mm *MemoryManager) addressHole() hostarch.AddrRange {
	if hp, ok := mm.p.(platform.AddressHolePlatform); ok {
		return hp.UserAddressHole()
	}
	return hostarch.AddrRange{}
}

// overlapsHole reports whether ar overlaps the address hole of the platform.
func (mm *MemoryManager) overlapsHole(ar hostarch.AddrRange) bool {
	hole := mm.addressHole()
	return hole.Length() != 0 && ar.Overlaps(hole)
}

// isHostBlockPlatform reports whether the platform maps guest memory in 16KB
// host blocks.
func (mm *MemoryManager) isHostBlockPlatform() bool {
	if mm.layout.MinAddr >= 0x4_0000_0000 {
		return true
	}
	return mm.addressHole().End >= 0x4000_0000_0000
}

// findAvoidingHoleLocked searches bounds like findLowestAvailableLocked, or
// like findHighestAvailableLocked when highest is true, but never returns a
// range inside the address hole. The part of bounds on the preferred side of
// the hole comes first.
//
// +checklocksread:mm.mappingMu
func (mm *MemoryManager) findAvoidingHoleLocked(length, alignment uint64, bounds hostarch.AddrRange, highest bool) (hostarch.Addr, error) {
	const hostBlockAlign = 0x4000
	hole := mm.addressHole()
	if mm.isHostBlockPlatform() && alignment < hostBlockAlign {
		alignment = hostBlockAlign
	}
	find := mm.findLowestAlignedLocked
	if highest {
		find = mm.findHighestAlignedLocked
	}
	if hole.Length() == 0 || !bounds.Overlaps(hole) {
		return find(length, alignment, bounds)
	}
	var below, above hostarch.AddrRange
	if bounds.Start < hole.Start {
		below = hostarch.AddrRange{Start: bounds.Start, End: hole.Start}
	}
	if bounds.End > hole.End {
		above = hostarch.AddrRange{Start: hole.End, End: bounds.End}
	}
	first, second := below, above
	if highest {
		first, second = above, below
	}
	for _, part := range []hostarch.AddrRange{first, second} {
		if uint64(part.Length()) < length {
			continue
		}
		if addr, err := find(length, alignment, part); err == nil {
			return addr, nil
		}
	}
	return 0, linuxerr.ENOMEM
}

// +checklocksread:mm.mappingMu
func (mm *MemoryManager) findLowestAlignedLocked(length, alignment uint64, bounds hostarch.AddrRange) (hostarch.Addr, error) {
	for gap := mm.vmas.LowerBoundGap(bounds.Start); gap.Ok() && gap.Start() < bounds.End; gap = gap.NextLargeEnoughGap(hostarch.Addr(length)) {
		gr := gap.availableRange().Intersect(bounds)
		if offset := uint64(gr.Start) % alignment; offset != 0 {
			if uint64(gr.Length()) < alignment-offset {
				continue
			}
			gr.Start += hostarch.Addr(alignment - offset)
		}
		if uint64(gr.Length()) >= length {
			return gr.Start, nil
		}
	}
	return mm.findLowestAvailableLocked(length, alignment, bounds)
}

// +checklocksread:mm.mappingMu
func (mm *MemoryManager) findHighestAlignedLocked(length, alignment uint64, bounds hostarch.AddrRange) (hostarch.Addr, error) {
	for gap := mm.vmas.UpperBoundGap(bounds.End); gap.Ok() && gap.End() > bounds.Start; gap = gap.PrevLargeEnoughGap(hostarch.Addr(length)) {
		gr := gap.availableRange().Intersect(bounds)
		if rem := uint64(gr.End) % alignment; rem != 0 {
			if uint64(gr.End) <= rem || gr.End-hostarch.Addr(rem) <= gr.Start {
				continue
			}
			gr.End -= hostarch.Addr(rem)
		}
		if uint64(gr.Length()) >= length {
			start := gr.End - hostarch.Addr(length)
			if offset := uint64(start) % alignment; offset != 0 {
				if gr.Start <= start-hostarch.Addr(offset) {
					return start - hostarch.Addr(offset), nil
				}
				continue
			}
			return start, nil
		}
	}
	return mm.findHighestAvailableLocked(length, alignment, bounds)
}
