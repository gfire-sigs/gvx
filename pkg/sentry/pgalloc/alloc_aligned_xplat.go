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

package pgalloc

import (
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// findUnfreeAllocGap selects a free gap and target range in unfree for alloc,
// aligning small allocations to host pages when possible.
func findUnfreeAllocGap(unfree *unfreeSet, alloc *allocState, out *memmap.FileRange) unfreeGapIterator {
	*out = memmap.FileRange{}
	var ufgap unfreeGapIterator
	if alloc.opts.Dir == BottomUp {
		ufgap = unfree.FirstLargeEnoughGap(alloc.length)
	} else {
		ufgap = unfree.LastLargeEnoughGap(alloc.length)
	}
	if ufgap.Ok() && !alloc.huge {
		if alignedFR, ok := alignSmallAllocRange(ufgap.Range(), alloc.length, alloc.opts.Dir); ok {
			*out = alignedFR
			return ufgap
		}
		need := alloc.length + uint64(unix.Getpagesize()) - uint64(hostarch.PageSize)
		if alloc.opts.Dir == BottomUp {
			ufgap = unfree.FirstLargeEnoughGap(need)
		} else {
			ufgap = unfree.LastLargeEnoughGap(need)
		}
		if ufgap.Ok() {
			*out, _ = alignSmallAllocRange(ufgap.Range(), alloc.length, alloc.opts.Dir)
		}
	}
	if !ufgap.Ok() {
		return ufgap
	}
	if out.Length() == 0 {
		if alloc.opts.Dir == BottomUp {
			*out = memmap.FileRange{
				Start: ufgap.Start(),
				End:   ufgap.Start() + alloc.length,
			}
		} else {
			*out = memmap.FileRange{
				Start: ufgap.End() - alloc.length,
				End:   ufgap.End(),
			}
		}
	}
	return ufgap
}

// AllocateAligned is Allocate for a range that starts at a multiple of align.
// Allocate aligns a range to guest pages only, so a misaligned result is
// released, and a larger range gives up its head and its tail. align must be a
// power of two that is a multiple of hostarch.PageSize.
func (f *MemoryFile) AllocateAligned(length, align uint64, opts AllocOpts) (memmap.FileRange, error) {
	if align < hostarch.PageSize || align&(align-1) != 0 {
		return memmap.FileRange{}, fmt.Errorf("alignment %#x is not a power of two of at least one page", align)
	}
	fr, err := f.Allocate(length, opts)
	if err != nil || fr.Start%align == 0 {
		return fr, err
	}
	f.DecRef(fr)
	wide, err := f.Allocate(length+align-hostarch.PageSize, opts)
	if err != nil {
		return memmap.FileRange{}, err
	}
	start := (wide.Start + align - 1) &^ (align - 1)
	fr = memmap.FileRange{Start: start, End: start + length}
	if wide.Start < fr.Start {
		f.DecRef(memmap.FileRange{Start: wide.Start, End: fr.Start})
	}
	if fr.End < wide.End {
		f.DecRef(memmap.FileRange{Start: fr.End, End: wide.End})
	}
	return fr, nil
}
