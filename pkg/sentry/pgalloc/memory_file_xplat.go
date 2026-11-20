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

//go:build !windows

package pgalloc

import (
	"errors"
	"fmt"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

type windowsBacking struct{}

func (f *MemoryFile) truncateBackingFile(size int64) error {
	return f.file.Truncate(size)
}

func (f *MemoryFile) extendBackingChunksLocked(oldFileSize, newFileSize uint64, newChunks []chunkInfo) error {
	if err := f.file.Truncate(int64(newFileSize)); err != nil {
		return err
	}
	if len(newChunks) == 0 {
		return nil
	}
	size := uintptr(uint64(len(newChunks)) * chunkSize)
	m, _, errno := unix.Syscall6(
		unix.SYS_MMAP,
		0,
		size,
		unix.PROT_READ|unix.PROT_WRITE,
		unix.MAP_SHARED,
		f.file.Fd(),
		uintptr(oldFileSize))
	if errno != 0 {
		return errno
	}
	for i := range newChunks {
		newChunks[i].mapping = m
		m += chunkSize
	}
	return nil
}

func (f *MemoryFile) unmapBackingChunks(chunks []chunkInfo) error {
	var errs []error
	for i := range chunks {
		chunk := &chunks[i]
		if chunk.mapping == 0 {
			continue
		}
		_, _, errno := unix.Syscall(unix.SYS_MUNMAP, chunk.mapping, chunkSize, 0)
		if errno != 0 {
			log.Warningf("Failed to unmap mapping %#x for MemoryFile chunk %d: %v", chunk.mapping, i, errno)
			errs = append(errs, fmt.Errorf("chunk %d (%#x): %w", i, chunk.mapping, errno))
		}
		chunk.mapping = 0
	}
	return errors.Join(errs...)
}

func (f *MemoryFile) commitFile(fr memmap.FileRange) error {
	// "The default operation (i.e., mode is zero) of fallocate() allocates the
	// disk space within the range specified by offset and len." - fallocate(2)
	return unix.Fallocate(
		int(f.file.Fd()),
		0, // mode
		int64(fr.Start),
		int64(fr.Length()))
}

func (*MemoryFile) commitRange(memmap.FileRange) error {
	return nil
}

func (f *MemoryFile) decommitReleasedRange(fr memmap.FileRange) {
	f.decommitRange(fr)
}

func (f *MemoryFile) decommitOnDestroyLocked(fr memmap.FileRange) {
	f.decommitRange(fr)
}

func (f *MemoryFile) totalUsage() (uint64, error) {
	// Stat the underlying file to discover the underlying usage. stat(2)
	// always reports the allocated block count in units of 512 bytes. This
	// includes pages in the page cache and swapped pages.
	var stat unix.Stat_t
	if err := unix.Fstat(int(f.file.Fd()), &stat); err != nil {
		return 0, err
	}
	return uint64(stat.Blocks * 512), nil
}

// expandReleaseRangeLocked extends fr to cover the start and end host pages
// when their remaining 4KB sub-pages are already free in f.unfreeSmall. It
// reserves the added sub-pages in f.unfreeSmall so no allocation takes them
// while f.mu is unlocked during the decommit.
//
// Preconditions: f.mu must be locked.
func (f *MemoryFile) expandReleaseRangeLocked(fr memmap.FileRange) memmap.FileRange {
	hostPage := uint64(unix.Getpagesize())
	if hostPage <= uint64(hostarch.PageSize) || fr.Length() == 0 {
		return fr
	}
	mask := hostPage - 1
	hpStart := fr.Start &^ mask
	hpEnd := (fr.End + mask) &^ mask

	if fr.Start > hpStart {
		canCompleteFirst := fr.End >= hpStart+hostPage
		if !canCompleteFirst {
			gapAfter := f.unfreeSmall.FindGap(fr.End)
			canCompleteFirst = gapAfter.Ok() && gapAfter.End() >= hpStart+hostPage
		}
		if canCompleteFirst {
			if gapBefore := f.unfreeSmall.FindGap(fr.Start - 1); gapBefore.Ok() && gapBefore.Start() <= hpStart {
				prefix := memmap.FileRange{Start: hpStart, End: fr.Start}
				f.unfreeSmall.Insert(gapBefore, prefix, unfreeInfo{refs: 0})
				fr.Start = hpStart
			}
		}
	}

	if fr.End < hpEnd && fr.Start <= hpEnd-hostPage {
		if gapAfter := f.unfreeSmall.FindGap(fr.End); gapAfter.Ok() && gapAfter.End() >= hpEnd {
			suffix := memmap.FileRange{Start: fr.End, End: hpEnd}
			f.unfreeSmall.Insert(gapAfter, suffix, unfreeInfo{refs: 0})
			fr.End = hpEnd
		}
	}
	return fr
}

// decommitRange punches holes for whole host pages in fr with f.decommitFile
// and zeroes any unaligned sub-host-page head or tail in memory.
func (f *MemoryFile) decommitRange(fr memmap.FileRange) {
	hostPage := uint64(unix.Getpagesize())
	if hostPage <= uint64(hostarch.PageSize) {
		if err := f.decommitFile(fr); err != nil {
			log.Warningf("Failed to decommit %v: %v", fr, err)
			f.manuallyZero(fr)
		}
		return
	}
	mask := hostPage - 1
	alignedStart := min(fr.End, (fr.Start+mask)&^mask)
	alignedEnd := max(alignedStart, fr.End&^mask)

	if head := (memmap.FileRange{Start: fr.Start, End: alignedStart}); head.Length() > 0 {
		f.manuallyZero(head)
	}
	if middle := (memmap.FileRange{Start: alignedStart, End: alignedEnd}); middle.Length() > 0 {
		if err := f.decommitFile(middle); err != nil {
			log.Warningf("Failed to decommit %v: %v", middle, err)
			f.manuallyZero(middle)
		}
	}
	if tail := (memmap.FileRange{Start: alignedEnd, End: fr.End}); tail.Length() > 0 {
		f.manuallyZero(tail)
	}
}

// alignSmallAllocRange chooses a range of length bytes inside gap, aligned to
// the host page size when possible.
func alignSmallAllocRange(gap memmap.FileRange, length uint64, dir Direction) (memmap.FileRange, bool) {
	if gap.Length() < length {
		return memmap.FileRange{}, false
	}
	hostPage := uint64(unix.Getpagesize())
	if hostPage > uint64(hostarch.PageSize) {
		mask := hostPage - 1
		if dir == BottomUp {
			start := (gap.Start + mask) &^ mask
			if start >= gap.Start && start+length > start && start+length <= gap.End {
				return memmap.FileRange{Start: start, End: start + length}, true
			}
			if length >= hostPage {
				return memmap.FileRange{}, false
			}
		} else {
			start := (gap.End - length) &^ mask
			if start >= gap.Start {
				return memmap.FileRange{Start: start, End: start + length}, true
			}
			if length >= hostPage {
				return memmap.FileRange{}, false
			}
		}
	}
	if dir == BottomUp {
		return memmap.FileRange{Start: gap.Start, End: gap.Start + length}, true
	}
	return memmap.FileRange{Start: gap.End - length, End: gap.End}, true
}
