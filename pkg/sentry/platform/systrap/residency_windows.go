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

//go:build windows

package systrap

import (
	"slices"
	"sort"
	"sync"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

// Guest code executes inside stub processes, so pages that a stub faults in do
// not enter the working set of the Sentry process. This index tracks each
// shared view between a stub process and a memory file so scans and unmaps see
// those resident pages.
//
// Lock order: addressSpace.mu comes before residencyIndex.mu (leaf) and before
// MemoryFile.mu. scanResidency runs outside MemoryFile.mu, retains each target
// addressSpace with residencyWG under residencyIndex.mu, and then locks
// addressSpace.mu.

const residencyBucketShift = 20

// residencySource matches pgalloc.MemoryFile residency methods without
// importing pkg/sentry/pgalloc.
type residencySource interface {
	ObserveResidency(fn func(fr memmap.FileRange, resident []byte)) (stop func())
	UncommittedRanges(fr memmap.FileRange) ([]memmap.FileRange, uint64)
	MarkCommittedPages(fr memmap.FileRange, resident []byte, lastCommitSeq uint64)
}

type memView struct {
	as      *addressSpace
	src     residencySource
	file    uintptr
	va      uint64
	fileOff uint64
	size    uint64
}

type residencyWatch struct {
	mu     sync.Mutex
	stops  map[uintptr]func()
	closed bool
}

type residencyIndex struct {
	mu      sync.Mutex
	buckets map[bucketKey][]*memView
}

func allResidentBitsSet(b []byte) bool {
	for _, v := range b {
		if v&1 == 0 {
			return false
		}
	}
	return true
}

func anyResidentBitSet(b []byte) bool {
	for _, v := range b {
		if v&1 != 0 {
			return true
		}
	}
	return false
}

func (p *Platform) watchResidency(f memmap.File, file uintptr) {
	if file == 0 {
		return
	}
	src, ok := f.(residencySource)
	if !ok {
		return
	}
	w := &p.residencyWatch
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	if _, ok := w.stops[file]; ok {
		return
	}
	stop := src.ObserveResidency(func(fr memmap.FileRange, resident []byte) {
		p.residency.scanResidency(file, fr, resident)
	})
	if w.stops == nil {
		w.stops = make(map[uintptr]func())
	}
	w.stops[file] = stop
}

func (p *Platform) stopResidencyWatches() {
	w := &p.residencyWatch
	w.mu.Lock()
	w.closed = true
	stops := w.stops
	w.stops = nil
	w.mu.Unlock()
	for _, stop := range stops {
		stop()
	}
}

func (x *residencyIndex) addView(v *memView) {
	if v.size == 0 {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.buckets == nil {
		x.buckets = make(map[bucketKey][]*memView)
	}
	for n := v.fileOff >> residencyBucketShift; n <= (v.fileOff+v.size-1)>>residencyBucketShift; n++ {
		bk := bucketKey{v.file, n}
		x.buckets[bk] = append(x.buckets[bk], v)
	}
}

func (x *residencyIndex) removeView(v *memView) {
	if v.size == 0 {
		return
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	for n := v.fileOff >> residencyBucketShift; n <= (v.fileOff+v.size-1)>>residencyBucketShift; n++ {
		bk := bucketKey{v.file, n}
		list := x.buckets[bk]
		if len(list) == 0 {
			continue
		}
		list = slices.DeleteFunc(list, func(o *memView) bool { return o == v })
		if len(list) == 0 {
			delete(x.buckets, bk)
		} else {
			x.buckets[bk] = list
		}
	}
}

func (x *residencyIndex) scanResidency(file uintptr, fr memmap.FileRange, resident []byte) {
	pageCount := int(fr.Length() >> hostarch.PageShift)
	if file == 0 || pageCount == 0 || len(resident) < pageCount || allResidentBitsSet(resident[:pageCount]) {
		return
	}
	var targets []*addressSpace
	x.mu.Lock()
	if len(x.buckets) > 0 {
		for n := fr.Start >> residencyBucketShift; n <= (fr.End-1)>>residencyBucketShift; n++ {
			for _, v := range x.buckets[bucketKey{file, n}] {
				if v.size == 0 || v.fileOff >= fr.End || v.fileOff+v.size <= fr.Start {
					continue
				}
				if !slices.Contains(targets, v.as) {
					targets = append(targets, v.as)
				}
			}
		}
		for _, as := range targets {
			as.residencyWG.Add(1)
		}
	}
	x.mu.Unlock()

	complete := false
	buf := resident[:pageCount]
	for _, as := range targets {
		if !complete {
			as.scanResidency(file, fr, buf)
			complete = allResidentBitsSet(buf)
		}
		as.residencyWG.Done()
	}
}

func (as *addressSpace) scanResidency(file uintptr, fr memmap.FileRange, resident []byte) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released || as.sp.dead.Load() {
		return
	}
	for _, v := range as.memViews {
		if v.file != file || v.fileOff >= fr.End || v.fileOff+v.size <= fr.Start {
			continue
		}
		lo := max(v.fileOff, fr.Start)
		hi := min(v.fileOff+v.size, fr.End)
		if hi <= lo {
			continue
		}
		va := uintptr(v.va + (lo - v.fileOff))
		startPg := int((lo - fr.Start) >> hostarch.PageShift)
		endPg := int((hi - fr.Start) >> hostarch.PageShift)
		_ = unix.QueryProcessWorkingSetValid(as.sp.proc, va, resident[startPg:endPg])
		if allResidentBitsSet(resident) {
			return
		}
	}
}

func (as *addressSpace) flushViewRange(src residencySource, baseVA uint64, fr memmap.FileRange) {
	if as.sp.dead.Load() || !fr.WellFormed() || fr.Length() == 0 {
		return
	}
	ranges, seq := src.UncommittedRanges(fr)
	if len(ranges) == 0 {
		return
	}
	var vec []byte
	for _, r := range ranges {
		pages := int(r.Length() >> hostarch.PageShift)
		if pages == 0 {
			continue
		}
		if cap(vec) < pages {
			vec = make([]byte, pages)
		} else {
			vec = vec[:pages]
			clear(vec)
		}
		va := uintptr(baseVA + (r.Start - fr.Start))
		if errno := unix.QueryProcessWorkingSetRange(as.sp.proc, va, vec); errno != 0 {
			continue
		}
		if anyResidentBitSet(vec) {
			src.MarkCommittedPages(r, vec, seq)
		}
	}
}

// +checklocks:as.mu
func (as *addressSpace) flushRangeResidencyLocked(start, end uint64) {
	if as.sp.dead.Load() || len(as.memViews) == 0 || end <= start {
		return
	}
	i := sort.Search(len(as.memViews), func(i int) bool { return as.memViews[i].va+as.memViews[i].size > start })
	for j := i; j < len(as.memViews) && as.memViews[j].va < end; j++ {
		v := as.memViews[j]
		vaLo := max(v.va, start)
		vaHi := min(v.va+v.size, end)
		if vaHi <= vaLo {
			continue
		}
		fr := memmap.FileRange{
			Start: v.fileOff + (vaLo - v.va),
			End:   v.fileOff + (vaHi - v.va),
		}
		as.flushViewRange(v.src, vaLo, fr)
	}
}

// +checklocks:as.mu
func (as *addressSpace) removeMemViewsLocked(start, end uint64) {
	if len(as.memViews) == 0 || end <= start {
		return
	}
	i := sort.Search(len(as.memViews), func(i int) bool { return as.memViews[i].va+as.memViews[i].size > start })
	j := i
	var pieces []*memView
	for ; j < len(as.memViews) && as.memViews[j].va < end; j++ {
		v := as.memViews[j]
		as.p.residency.removeView(v)
		if v.va < start {
			pieces = append(pieces, &memView{
				as:      as,
				src:     v.src,
				file:    v.file,
				va:      v.va,
				fileOff: v.fileOff,
				size:    start - v.va,
			})
		}
		if v.va+v.size > end {
			pieces = append(pieces, &memView{
				as:      as,
				src:     v.src,
				file:    v.file,
				va:      end,
				fileOff: v.fileOff + (end - v.va),
				size:    v.va + v.size - end,
			})
		}
	}
	if i == j {
		return
	}
	as.memViews = slices.Replace(as.memViews, i, j, pieces...)
	for _, piece := range pieces {
		as.p.residency.addView(piece)
	}
}

// +checklocks:as.mu
func (as *addressSpace) memViewsMappedLocked(guest, length uint64, src residencySource, file uintptr, fileOff uint64) {
	as.removeMemViewsLocked(guest, guest+length)
	if src == nil || file == 0 || length == 0 {
		return
	}
	v := &memView{
		as:      as,
		src:     src,
		file:    file,
		va:      guest,
		fileOff: fileOff,
		size:    length,
	}
	i := sort.Search(len(as.memViews), func(i int) bool { return as.memViews[i].va > guest })
	as.memViews = slices.Insert(as.memViews, i, v)
	as.p.residency.addView(v)
}

// +checklocks:as.mu
func (as *addressSpace) detachMemViewsLocked() []*memView {
	views := as.memViews
	for _, v := range views {
		as.p.residency.removeView(v)
	}
	as.memViews = nil
	return views
}

func (as *addressSpace) flushViewsResidency(views []*memView) {
	if as.sp.dead.Load() {
		return
	}
	for _, v := range views {
		fr := memmap.FileRange{Start: v.fileOff, End: v.fileOff + v.size}
		as.flushViewRange(v.src, v.va, fr)
	}
}
