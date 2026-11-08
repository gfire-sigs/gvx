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
	"slices"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// addressHoles returns the gaps inside the guest address range that no mapping
// may use, in ascending order. A platform that has no gap returns none.
func (mm *MemoryManager) addressHoles() []hostarch.AddrRange {
	if hp, ok := mm.p.(platform.AddressHolePlatform); ok {
		return hp.UserAddressHoles()
	}
	return nil
}

// overlapsHole reports whether ar overlaps one of the holes.
func overlapsHole(ar hostarch.AddrRange, holes []hostarch.AddrRange) bool {
	return slices.ContainsFunc(holes, ar.Overlaps)
}

// isHostBlockPlatform reports whether the platform maps guest memory in 16KB
// host blocks. holes are the address holes of the platform.
func (mm *MemoryManager) isHostBlockPlatform(holes []hostarch.AddrRange) bool {
	if hbp, ok := mm.p.(platform.HostBlockPlatform); ok && hbp.HostBlockSize() != 0 {
		return true
	}
	if mm.layout.MinAddr >= 0x4_0000_0000 {
		return true
	}
	return len(holes) != 0 && holes[len(holes)-1].End >= 0x4000_0000_0000
}

// maxHoles is the number of holes that a search handles without an allocation.
// The Windows systrap layout has 31 holes.
const maxHoles = 32

// appendRangesAvoiding appends the parts of bounds that no hole covers to dst,
// in ascending order. holes must be in ascending order and must not overlap.
func appendRangesAvoiding(dst []hostarch.AddrRange, bounds hostarch.AddrRange, holes []hostarch.AddrRange) []hostarch.AddrRange {
	next := bounds.Start
	for _, hole := range holes {
		if hole.End <= next {
			continue
		}
		if hole.Start >= bounds.End {
			break
		}
		if hole.Start > next {
			dst = append(dst, hostarch.AddrRange{Start: next, End: hole.Start})
		}
		next = hole.End
	}
	if next < bounds.End {
		dst = append(dst, hostarch.AddrRange{Start: next, End: bounds.End})
	}
	return dst
}

// findAvoidingHoleLocked searches bounds like findLowestAvailableLocked, or
// like findHighestAvailableLocked when highest is true, but never returns a
// range inside one of the holes. The part of bounds on the preferred side comes
// first: the lowest part, or the highest part when highest is true.
//
// +checklocksread:mm.mappingMu
func (mm *MemoryManager) findAvoidingHoleLocked(length, alignment uint64, bounds hostarch.AddrRange, holes []hostarch.AddrRange, highest bool) (hostarch.Addr, error) {
	const hostBlockAlign = 0x4000
	if mm.isHostBlockPlatform(holes) && alignment < hostBlockAlign {
		alignment = hostBlockAlign
	}
	find := mm.findLowestAlignedLocked
	if highest {
		find = mm.findHighestAlignedLocked
	}
	if !slices.ContainsFunc(holes, bounds.Overlaps) {
		return find(length, alignment, bounds)
	}
	var buf [maxHoles + 1]hostarch.AddrRange
	parts := appendRangesAvoiding(buf[:0], bounds, holes)
	if highest {
		slices.Reverse(parts)
	}
	for _, part := range parts {
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

// releaseHostBlocksLocked tells an address space with spare pages that a new
// virtual memory area covers ar (platform.HostBlockOwner). A spare page in the
// host block of ar must not hide the new pages from the memory manager.
//
// +checklocks:mm.mappingMu
// +checklocksexclude:mm.activeMu
func (mm *MemoryManager) releaseHostBlocksLocked(ar hostarch.AddrRange) {
	if hbp, ok := mm.p.(platform.HostBlockPlatform); !ok || hbp.HostBlockSize() == 0 {
		return
	}
	mm.activeMu.Lock()
	defer mm.activeMu.Unlock()
	mm.releaseHostBlocksActiveLocked(ar)
}

// releaseHostBlocksActiveLocked is releaseHostBlocksLocked for a caller that
// holds activeMu. mprotect calls it when an area without access gains access.
//
// +checklocks:mm.activeMu
func (mm *MemoryManager) releaseHostBlocksActiveLocked(ar hostarch.AddrRange) {
	if owner, ok := mm.as.(platform.HostBlockOwner); ok {
		owner.ReleaseHostBlocks(ar)
	}
}

// alignStackToHostBlock moves the end of the stack down to a host block, and
// grows the size of the stack to a whole number of host blocks. The top of the
// stack is then in a block that holds no other mapping, so the platform maps
// the pages that the stack uses without a composite page. It returns the
// arguments unchanged on a platform that does not report a host block size.
func (mm *MemoryManager) alignStackToHostBlock(end hostarch.Addr, size uint64) (hostarch.Addr, uint64) {
	hbp, ok := mm.p.(platform.HostBlockPlatform)
	if !ok || hbp.HostBlockSize() == 0 {
		return end, size
	}
	mask := hbp.HostBlockSize() - 1
	return end &^ hostarch.Addr(mask), (size + mask) &^ mask
}
