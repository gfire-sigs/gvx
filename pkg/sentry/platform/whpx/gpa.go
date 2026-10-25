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

package whpx

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// errGPAExhausted reports that a zone of the guest physical window is full.
var errGPAExhausted = errors.New("whpx: guest physical address window is exhausted")

// gpaAllocator hands out 4KB pages of the table zone of the guest physical
// window. The kernel region and the page-table slabs use it. It never takes
// a page back, because those pages live as long as the partition.
type gpaAllocator struct {
	mu   sync.Mutex
	end  uint64
	next uint64

	// free holds the pages that an aligned run skipped.
	free []uint64
}

func newGPAAllocator(base, end uint64) *gpaAllocator {
	return &gpaAllocator{end: end, next: base}
}

// allocPage returns one free page. Skipped pages come first, then the window
// grows.
func (a *gpaAllocator) allocPage() (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if n := len(a.free); n > 0 {
		gpa := a.free[n-1]
		a.free = a.free[:n-1]
		return gpa, nil
	}
	if a.next+pageSize > a.end {
		return 0, errGPAExhausted
	}
	gpa := a.next
	a.next += pageSize
	return gpa, nil
}

// allocRunAligned returns pages contiguous pages from the top of the window.
// The first page is a multiple of align pages. The pages that alignment skips
// go to the free list.
func (a *gpaAllocator) allocRunAligned(pages, align int) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	alignBytes := uint64(align) * pageSize
	start := (a.next + alignBytes - 1) &^ (alignBytes - 1)
	size := uint64(pages) * pageSize
	if start+size > a.end {
		return 0, errGPAExhausted
	}
	for gpa := a.next; gpa < start; gpa += pageSize {
		a.free = append(a.free, gpa)
	}
	a.next = start + size
	return start, nil
}

// allocRun returns pages contiguous pages from the top of the window.
func (a *gpaAllocator) allocRun(pages int) (uint64, error) {
	return a.allocRunAligned(pages, 1)
}

// partitionFlags returns the mapping flags of the partition. Execute stays
// on because the guest page tables enforce execute permission.
func partitionFlags(writable bool) uint32 {
	f := mapFlagRead | mapFlagExecute
	if writable {
		f |= mapFlagWrite
	}
	return f
}

// gpaRun is a contiguous range of guest physical memory.
type gpaRun = hvcommon.GPARun

// appendRun adds a range to runs. It joins the range to the last run when
// the two touch.
func appendRun(runs []gpaRun, gpa, size uint64) []gpaRun {
	return hvcommon.AppendGPARun(runs, gpa, size)
}

// span is a range inside an arena. Both fields are byte offsets from the
// start of the host window of the arena.
type span struct {
	lo, hi uint32
}

// arenaKey names one arena. The index is the host address divided by
// arenaSize.
type arenaKey struct {
	index    uintptr
	writable bool
}

// arena is the registration state of one host window and one access level.
// Its guest physical window starts at gpa. The span list holds the parts of
// the host window that the partition maps, sorted and disjoint. Each span is
// one backend mapGPA call, so close can unmap it with the same arguments.
type arena struct {
	gpa   uint64
	spans []span
}

// find returns the end of the span that contains off.
func (a *arena) find(off uint32) (hi uint32, ok bool) {
	i := sort.Search(len(a.spans), func(i int) bool { return a.spans[i].hi > off })
	if i < len(a.spans) && a.spans[i].lo <= off {
		return a.spans[i].hi, true
	}
	return 0, false
}

// nextStart returns the start of the first span after off. It returns
// arenaSize when no span follows.
func (a *arena) nextStart(off uint32) uint32 {
	i := sort.Search(len(a.spans), func(i int) bool { return a.spans[i].lo > off })
	if i < len(a.spans) {
		return a.spans[i].lo
	}
	return arenaSize
}

func (a *arena) insert(s span) {
	i := sort.Search(len(a.spans), func(i int) bool { return a.spans[i].lo > s.lo })
	a.spans = slices.Insert(a.spans, i, s)
}

// hostView converts addresses inside one host slice to pointers. It lets the
// code compute with uintptr and still hand a valid pointer to the backend.
type hostView struct {
	base  unsafe.Pointer
	start uintptr
}

func (v hostView) at(addr uintptr) unsafe.Pointer {
	return unsafe.Add(v.base, addr-v.start)
}

// memoryMap registers host memory in the partition and assigns guest
// physical addresses to it.
//
// The partition maps a host range once and keeps it until close. The kvm
// platform of upstream gVisor does the same with its memory regions. Address
// spaces only change their own page tables.
//
// The host memory must stay mapped at its address until close. The hypervisor
// binds the guest physical range to the pages that back the host range when
// the call runs. The memory file of the Sentry never moves its chunks. The
// erofs image mapping lives as long as the run.
//
// The host address space splits into arenas of arenaSize bytes. Each arena
// has one guest physical window of the same size. A host address keeps its
// offset inside that window. A range inside one arena stays contiguous in
// guest physical memory, however many calls registered it.
//
// An arena has two access levels. The writable level maps host memory with
// write permission. The read-only level maps it without write permission. A
// request without write access can name a host view that lacks write
// permission. A write request never uses the read-only level. When a host
// range that registered read-only needs write access, the writable level
// registers a second guest physical range for the same host pages. The
// hypervisor backs both ranges with the same memory. The map never replaces
// or removes a mapping, so no virtual processor loses a page that it may
// still use.
type memoryMap struct {
	mu     sync.Mutex
	be     backend
	next   uint64
	end    uint64
	arenas map[arenaKey]*arena
	closed bool
}

// newMemoryMap creates a map that takes its guest physical windows from
// [base, end). base must be a multiple of arenaSize.
func newMemoryMap(be backend, base, end uint64) *memoryMap {
	return &memoryMap{be: be, next: base, end: end, arenas: make(map[arenaKey]*arena)}
}

// resolve returns the guest physical ranges of data in order and appends them
// to runs. It registers the parts of data that the partition does not map
// yet. write tells whether the host view accepts writes and the caller needs
// write access. data must start on a page boundary and span whole pages.
func (m *memoryMap) resolve(data []byte, write bool, runs []gpaRun) ([]gpaRun, error) {
	if len(data) == 0 || len(data)&pageMask != 0 {
		return runs, fmt.Errorf("whpx: host slice of %d bytes is not a whole number of pages", len(data))
	}
	view := hostView{base: unsafe.Pointer(&data[0]), start: uintptr(unsafe.Pointer(&data[0]))}
	if view.start&pageMask != 0 {
		return runs, fmt.Errorf("whpx: host address %#x is not page aligned", view.start)
	}
	cur, end := view.start, view.start+uintptr(len(data))

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return runs, errClosed
	}
	for cur < end {
		windowEnd := (cur | arenaMask) + 1
		if windowEnd == 0 || windowEnd > end {
			windowEnd = end
		}
		var err error
		if runs, err = m.resolveWindow(view, cur, windowEnd, write, runs); err != nil {
			return runs, err
		}
		cur = windowEnd
	}
	return runs, nil
}

// resolveWindow resolves [cur, end), which lies inside one arena window.
func (m *memoryMap) resolveWindow(view hostView, cur, end uintptr, write bool, runs []gpaRun) ([]gpaRun, error) {
	index := cur >> arenaShift
	rw := m.arenas[arenaKey{index: index, writable: true}]
	var ro *arena
	if !write {
		ro = m.arenas[arenaKey{index: index}]
	}
	for cur < end {
		off := uint32(cur & arenaMask)
		if rw != nil {
			if hi, ok := rw.find(off); ok {
				n := min(uintptr(hi-off), end-cur)
				runs = appendRun(runs, rw.gpa+uint64(off), uint64(n))
				cur += n
				continue
			}
		}
		if ro != nil {
			if hi, ok := ro.find(off); ok {
				n := min(uintptr(hi-off), end-cur)
				runs = appendRun(runs, ro.gpa+uint64(off), uint64(n))
				cur += n
				continue
			}
		}

		// The gap ends where the next registered span of either level begins.
		windowStart := cur - uintptr(off)
		gapEnd := end
		if rw != nil {
			gapEnd = min(gapEnd, windowStart+uintptr(rw.nextStart(off)))
		}
		if ro != nil {
			gapEnd = min(gapEnd, windowStart+uintptr(ro.nextStart(off)))
		}
		a, err := m.register(arenaKey{index: index, writable: write}, view.at(cur), off, gapEnd-cur, write)
		if err != nil {
			return runs, err
		}
		if write {
			rw = a
		} else {
			ro = a
		}
		runs = appendRun(runs, a.gpa+uint64(off), uint64(gapEnd-cur))
		cur = gapEnd
	}
	return runs, nil
}

// register maps size bytes of host memory at host, which sits at offset off
// of its arena. It creates the arena when none exists. A failed call changes
// nothing.
func (m *memoryMap) register(key arenaKey, host unsafe.Pointer, off uint32, size uintptr, write bool) (*arena, error) {
	a := m.arenas[key]
	fresh := a == nil
	if fresh {
		if m.next+arenaSize > m.end {
			return nil, errGPAExhausted
		}
		a = &arena{gpa: m.next}
	}
	gpa := a.gpa + uint64(off)
	if err := m.be.mapGPA(host, gpa, uint64(size), partitionFlags(write)); err != nil {
		return nil, fmt.Errorf("whpx: map guest memory at %#x, %d bytes: %w", gpa, size, err)
	}
	if fresh {
		m.next += arenaSize
		m.arenas[key] = a
	}
	a.insert(span{lo: off, hi: off + uint32(size)})
	return a, nil
}

// close unmaps every registered range and makes later calls of resolve fail.
// The caller stops every virtual processor first.
func (m *memoryMap) close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var errs []error
	for _, a := range m.arenas {
		for _, s := range a.spans {
			gpa := a.gpa + uint64(s.lo)
			if err := m.be.unmapGPA(gpa, uint64(s.hi-s.lo)); err != nil {
				errs = append(errs, fmt.Errorf("whpx: unmap guest memory at %#x: %w", gpa, err))
			}
		}
	}
	clear(m.arenas)
	return errors.Join(errs...)
}
