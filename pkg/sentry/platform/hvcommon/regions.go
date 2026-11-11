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

package hvcommon

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const largePageAlign = 2 << 20

// Stage2Backend is the hypervisor boundary for Stage-2 GPA or IPA mappings and
// optional private copies of read-only host pages.
type Stage2Backend interface {
	// MapHost maps size bytes of host memory at gpa. Both host and size are
	// multiples of RegionMapConfig.Granule.
	MapHost(host uintptr, gpa uint64, size uintptr, writable bool) error
	// UnmapGPA removes the Stage-2 mapping at gpa.
	UnmapGPA(gpa uint64, size uintptr) error
	// RefusedMemory reports whether err means that the hypervisor refuses
	// direct mapping of this host memory, allowing a private copy for reads.
	RefusedMemory(err error) bool
	// AllocCopy returns zeroed host memory for a private read-only copy.
	AllocCopy(size uintptr) ([]byte, error)
	// FreeCopy releases memory from AllocCopy.
	FreeCopy(mem []byte) error
}

// ChunkedFile is a memmap.File whose full host range remains mapped for the
// life of the file. pgalloc.MemoryFile implements this contract.
type ChunkedFile interface {
	memmap.File
	TotalSize() uint64
}

// HostBlock describes one contiguous host virtual memory range. Slice holds
// the backing bytes when private-copy fallback may read them.
type HostBlock struct {
	Addr  uintptr
	Len   uintptr
	Slice []byte
}

// HostBlocksFromSeq converts non-empty blocks in bs into HostBlock values.
func HostBlocksFromSeq(bs safemem.BlockSeq) []HostBlock {
	if bs.IsEmpty() {
		return nil
	}
	out := make([]HostBlock, 0, bs.NumBlocks())
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		slice := bs.Head().ToSlice()
		if len(slice) == 0 {
			continue
		}
		out = append(out, HostBlock{
			Addr:  uintptr(unsafe.Pointer(unsafe.SliceData(slice))),
			Len:   uintptr(len(slice)),
			Slice: slice,
		})
	}
	return out
}

// RegionMapConfig configures a RegionMap for one hypervisor partition or VM.
type RegionMapConfig struct {
	Granule          uintptr
	Base             uint64
	Limit            uint64
	SeparateReadOnly bool
	LogPrefix        string
	ErrClosed        error
	ErrExhausted     error
	ErrRejected      error
}

// Region is one Stage-2 mapping of the host range [host, host+size) at gpa.
type Region struct {
	owner    *ownerRegions
	host     uintptr
	size     uintptr
	gpa      uint64
	writable bool
	copied   []byte
	filled   []bool
	refs     int
}

// Host returns the start of the mapped host virtual range.
func (r *Region) Host() uintptr { return r.host }

// Size returns the byte length of the Stage-2 region.
func (r *Region) Size() uintptr { return r.size }

// GPA returns the guest physical address of the Stage-2 region.
func (r *Region) GPA() uint64 { return r.gpa }

// Copied returns the private read-only copy slice, or nil for direct mappings.
func (r *Region) Copied() []byte { return r.copied }

func (r *Region) end() uintptr     { return r.host + r.size }
func (r *Region) persistent() bool { return r.owner != nil && r.owner.persistent }

func (r *Region) fill(block []byte) {
	if len(block) == 0 {
		return
	}
	first := uintptr(unsafe.Pointer(unsafe.SliceData(block)))
	lo, hi := max(first, r.host), min(first+uintptr(len(block)), r.end())
	for p := lo; p < hi; p += PageSize4K {
		i := (p - r.host) / PageSize4K
		if r.filled[i] {
			continue
		}
		copy(r.copied[p-r.host:p-r.host+PageSize4K], block[p-first:])
		r.filled[i] = true
	}
}

type regionList []*Region

func (l regionList) find(addr uintptr) *Region {
	i := sort.Search(len(l), func(i int) bool { return l[i].end() > addr })
	if i < len(l) && l[i].host <= addr {
		return l[i]
	}
	return nil
}

func (l regionList) covers(start, end uintptr) bool {
	i := sort.Search(len(l), func(i int) bool { return l[i].end() > start })
	cur := start
	for ; cur < end; i++ {
		if i >= len(l) || l[i].host > cur {
			return false
		}
		cur = l[i].end()
	}
	return true
}

func (l regionList) gaps(start, end uintptr) [][2]uintptr {
	var out [][2]uintptr
	i := sort.Search(len(l), func(i int) bool { return l[i].end() > start })
	cur := start
	for ; i < len(l) && l[i].host < end; i++ {
		r := l[i]
		if r.host > cur {
			out = append(out, [2]uintptr{cur, r.host})
		}
		cur = max(cur, r.end())
	}
	if cur < end {
		out = append(out, [2]uintptr{cur, end})
	}
	return out
}

func (l *regionList) insert(r *Region) {
	s := *l
	i := sort.Search(len(s), func(i int) bool { return s[i].host >= r.host })
	*l = slices.Insert(s, i, r)
}

func (l *regionList) remove(r *Region) {
	s := *l
	if i := slices.Index(s, r); i >= 0 {
		*l = slices.Delete(s, i, i+1)
	}
}

type ownerRegions struct {
	key        memmap.File
	rw         regionList
	ro         regionList
	persistent bool
	chunkTotal uint64
	stored     bool
}

func (o *ownerRegions) empty() bool {
	return len(o.rw) == 0 && len(o.ro) == 0
}

type gvaExtent struct {
	start  uint64
	end    uint64
	region *Region
}

// RegionUser tracks the Stage-2 regions referenced by one AddressSpace.
// Callers synchronize access to a RegionUser under the AddressSpace lock.
type RegionUser struct {
	set       map[*Region]struct{}
	last      *Region
	extents   []gvaExtent
	extCounts map[*Region]int
}

func (u *RegionUser) use(r *Region) {
	if u.last == r {
		return
	}
	u.last = r
	if _, ok := u.set[r]; ok {
		return
	}
	if u.set == nil {
		u.set = make(map[*Region]struct{})
	}
	u.set[r] = struct{}{}
	r.refs++
}

func (u *RegionUser) incExt(r *Region) bool {
	if u.extCounts == nil {
		u.extCounts = make(map[*Region]int)
	}
	c := u.extCounts[r]
	u.extCounts[r] = c + 1
	return c == 0
}

func (u *RegionUser) decExt(r *Region, dropped *[]*Region) {
	c := u.extCounts[r] - 1
	if c == 0 {
		delete(u.extCounts, r)
		*dropped = append(*dropped, r)
		return
	}
	u.extCounts[r] = c
}

// ClearRange removes any non-persistent GVA extents overlapping [start, end)
// and returns regions whose extent count in u dropped to zero.
func (u *RegionUser) ClearRange(start, end uint64) []*Region {
	if start >= end || len(u.extents) == 0 {
		return nil
	}
	lo := sort.Search(len(u.extents), func(i int) bool { return u.extents[i].end > start })
	if lo == len(u.extents) || u.extents[lo].start >= end {
		return nil
	}
	if e := u.extents[lo]; e.start < start && end < e.end {
		u.extents[lo].end = start
		u.extents = slices.Insert(u.extents, lo+1, gvaExtent{start: end, end: e.end, region: e.region})
		u.incExt(e.region)
		return nil
	}
	if u.extents[lo].start < start {
		u.extents[lo].end = start
		lo++
	}
	var dropped []*Region
	hi := lo
	for hi < len(u.extents) && u.extents[hi].end <= end {
		u.decExt(u.extents[hi].region, &dropped)
		hi++
	}
	if hi < len(u.extents) && u.extents[hi].start < end {
		u.extents[hi].start = end
	}
	if lo < hi {
		u.extents = slices.Delete(u.extents, lo, hi)
	}
	return dropped
}

// RecordRuns updates the GVA extent table for [addr, addr+size(runs)) and
// returns newly acquired and newly dropped non-persistent regions.
func (u *RegionUser) RecordRuns(addr uint64, runs []GPARun) (acquired, dropped []*Region) {
	var total uint64
	hasTracked := false
	for _, r := range runs {
		total += r.Size
		if r.region != nil {
			hasTracked = true
		}
	}
	if total == 0 {
		return nil, nil
	}
	dropped = u.ClearRange(addr, addr+total)
	if !hasTracked {
		return nil, dropped
	}
	va := addr
	for _, run := range runs {
		nextVA := va + run.Size
		r := run.region
		if r != nil {
			i := sort.Search(len(u.extents), func(i int) bool { return u.extents[i].start >= va })
			leftMatch := i > 0 && u.extents[i-1].end == va && u.extents[i-1].region == r
			rightMatch := i < len(u.extents) && u.extents[i].start == nextVA && u.extents[i].region == r
			switch {
			case leftMatch && rightMatch:
				u.extents[i-1].end = u.extents[i].end
				u.extents = slices.Delete(u.extents, i, i+1)
				u.extCounts[r]--
			case leftMatch:
				u.extents[i-1].end = nextVA
			case rightMatch:
				u.extents[i].start = va
			default:
				u.extents = slices.Insert(u.extents, i, gvaExtent{start: va, end: nextVA, region: r})
				if u.incExt(r) {
					acquired = append(acquired, r)
				}
			}
		}
		va = nextVA
	}
	return acquired, dropped
}

// GPAFreeSpan describes one free guest physical interval [Start, End).
type GPAFreeSpan struct {
	Start uint64
	End   uint64
}

// RegionMap assigns guest physical addresses to memmap.File host ranges and
// reference-counts Stage-2 mappings across AddressSpaces.
type RegionMap struct {
	granule          uintptr
	limit            uint64
	separateReadOnly bool
	logPrefix        string
	errClosed        error
	errExhausted     error
	errRejected      error

	mu      sync.Mutex
	be      Stage2Backend
	closed  bool
	owners  map[memmap.File]*ownerRegions
	unowned []*ownerRegions
	free    []GPAFreeSpan
	next    uint64
	count   int
}

// NewRegionMap creates a RegionMap backed by be and configured by cfg.
func NewRegionMap(be Stage2Backend, cfg RegionMapConfig) *RegionMap {
	prefix := cfg.LogPrefix
	if prefix == "" {
		prefix = "hvcommon"
	}
	errClosed := cfg.ErrClosed
	if errClosed == nil {
		errClosed = errors.New(prefix + ": platform closed")
	}
	errExhausted := cfg.ErrExhausted
	if errExhausted == nil {
		errExhausted = errors.New(prefix + ": guest physical address space exhausted")
	}
	return &RegionMap{
		be:               be,
		granule:          cfg.Granule,
		limit:            cfg.Limit,
		separateReadOnly: cfg.SeparateReadOnly,
		logPrefix:        prefix,
		errClosed:        errClosed,
		errExhausted:     errExhausted,
		errRejected:      cfg.ErrRejected,
		owners:           make(map[memmap.File]*ownerRegions),
		next:             cfg.Base,
	}
}

// SetBackend swaps the Stage-2 backend for testing.
func (m *RegionMap) SetBackend(be Stage2Backend) {
	m.mu.Lock()
	m.be = be
	m.mu.Unlock()
}

func (m *RegionMap) ownerLocked(f memmap.File) *ownerRegions {
	if f == nil || !reflect.TypeOf(f).Comparable() {
		o := &ownerRegions{key: f}
		m.unowned = append(m.unowned, o)
		return o
	}
	_, chunked := f.(ChunkedFile)
	o, ok := m.owners[f]
	if !ok {
		o = &ownerRegions{key: f, persistent: chunked, stored: true}
		m.owners[f] = o
	}
	return o
}

// Resolve maps the blocks of bs into Stage-2 and binds every used region to u
// for the lifetime of u until Release.
func (m *RegionMap) Resolve(u *RegionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]GPARun, error) {
	return m.ResolveBlocks(u, f, HostBlocksFromSeq(bs), write)
}

// ResolveBlocks resolves explicit HostBlock values and binds used regions to u
// until Release.
func (m *RegionMap) ResolveBlocks(u *RegionUser, f memmap.File, blocks []HostBlock, write bool) ([]GPARun, error) {
	return m.resolveBlocks(u, f, blocks, write, false)
}

// ResolvePinned resolves bs for range-tracked mappings. Persistent ChunkedFile
// regions attach to u immediately; non-persistent regions return pinned in
// runs until FinishPin transfers or drops the pins.
func (m *RegionMap) ResolvePinned(u *RegionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]GPARun, error) {
	return m.ResolvePinnedBlocks(u, f, HostBlocksFromSeq(bs), write)
}

// ResolvePinnedBlocks resolves explicit HostBlock values with temporary pins on
// non-persistent regions.
func (m *RegionMap) ResolvePinnedBlocks(u *RegionUser, f memmap.File, blocks []HostBlock, write bool) ([]GPARun, error) {
	return m.resolveBlocks(u, f, blocks, write, true)
}

func (m *RegionMap) resolveBlocks(u *RegionUser, f memmap.File, blocks []HostBlock, write bool, pinEphemeral bool) ([]GPARun, error) {
	for _, b := range blocks {
		if b.Len == 0 {
			continue
		}
		if b.Addr&PageMask4K != 0 || b.Len&PageMask4K != 0 {
			return nil, fmt.Errorf("%s: host block %#x+%#x is not 4KB aligned", m.logPrefix, b.Addr, b.Len)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, m.errClosed
	}
	o := m.ownerLocked(f)
	if m.separateReadOnly && o.persistent {
		write = true
	}
	runs := make([]GPARun, 0, len(blocks))
	for _, b := range blocks {
		if b.Len == 0 {
			continue
		}
		if err := m.coverLocked(o, f, b, write); err != nil {
			return nil, err
		}
		for off := uintptr(0); off < b.Len; {
			cur := b.Addr + off
			r := m.findLocked(o, cur, write)
			if r == nil {
				return nil, fmt.Errorf("%s: host address %#x has no Stage-2 region", m.logPrefix, cur)
			}
			if write && r.copied != nil {
				return nil, fmt.Errorf("%w: the memory is a private copy of read-only memory", m.errRejected)
			}
			take := min(b.Len-off, r.end()-cur)
			if r.copied != nil && len(b.Slice) >= int(off+take) {
				r.fill(b.Slice[off : off+take])
			}
			gpa := r.gpa + uint64(cur-r.host)
			if pinEphemeral && !r.persistent() {
				runs = appendRegionRun(runs, gpa, uint64(take), r)
			} else {
				if u != nil {
					u.use(r)
				}
				runs = AppendGPARun(runs, gpa, uint64(take))
			}
			off += take
		}
	}
	if pinEphemeral {
		for i := range runs {
			if runs[i].region != nil {
				runs[i].region.refs++
			}
		}
	}
	return runs, nil
}

// FinishPin applies acquired and dropped extent reference transitions and
// releases the temporary pins placed on runs by ResolvePinned.
func (m *RegionMap) FinishPin(runs []GPARun, acquired, dropped []*Region) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for _, r := range acquired {
		r.refs++
	}
	for _, r := range dropped {
		m.decRefLocked(r)
	}
	for _, run := range runs {
		if run.region != nil {
			m.decRefLocked(run.region)
		}
	}
}

// ReleaseRegions decrements references for regions dropped by ClearRange.
func (m *RegionMap) ReleaseRegions(dropped []*Region) {
	if len(dropped) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}
	for _, r := range dropped {
		m.decRefLocked(r)
	}
}

func (m *RegionMap) findLocked(o *ownerRegions, addr uintptr, write bool) *Region {
	if r := o.rw.find(addr); r != nil {
		return r
	}
	if !m.separateReadOnly || write {
		return nil
	}
	return o.ro.find(addr)
}

func (m *RegionMap) coverLocked(o *ownerRegions, f memmap.File, b HostBlock, write bool) error {
	start, end := m.roundOut(b.Addr, b.Addr+b.Len)
	if !m.separateReadOnly || write {
		if o.rw.covers(start, end) {
			return nil
		}
		if cf, ok := f.(ChunkedFile); ok && o.persistent {
			m.registerChunksLocked(o, cf)
			if o.rw.covers(start, end) {
				return nil
			}
		}
		mapWrite := write
		if !m.separateReadOnly {
			mapWrite = true
		}
		for _, gap := range o.rw.gaps(start, end) {
			if err := m.addLocked(o, &o.rw, b.Slice, gap[0], gap[1], write, mapWrite); err != nil {
				return err
			}
		}
		return nil
	}

	for _, rwGap := range o.rw.gaps(start, end) {
		for _, gap := range o.ro.gaps(rwGap[0], rwGap[1]) {
			if err := m.addLocked(o, &o.ro, b.Slice, gap[0], gap[1], false, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *RegionMap) roundOut(start, end uintptr) (uintptr, uintptr) {
	mask := m.granule - 1
	return start &^ mask, (end + mask) &^ mask
}

func (m *RegionMap) registerChunksLocked(o *ownerRegions, cf ChunkedFile) {
	total := cf.TotalSize()
	if total == 0 || total == o.chunkTotal {
		return
	}
	if o.chunkTotal == 0 {
		m.evictIdleLocked()
	}
	o.chunkTotal = total
	bs, err := cf.MapInternal(memmap.FileRange{Start: 0, End: total}, hostarch.ReadWrite)
	if err != nil {
		return
	}
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		chunk := bs.Head().ToSlice()
		if len(chunk) == 0 {
			continue
		}
		base := uintptr(unsafe.Pointer(unsafe.SliceData(chunk)))
		start, end := m.roundOut(base, base+uintptr(len(chunk)))
		for _, gap := range o.rw.gaps(start, end) {
			if err := m.addLocked(o, &o.rw, chunk, gap[0], gap[1], true, true); err != nil {
				log.Warningf("%s: map the memory file range %#x-%#x: %v", m.logPrefix, gap[0], gap[1], err)
				break
			}
		}
	}
}

func (m *RegionMap) addLocked(o *ownerRegions, list *regionList, slice []byte, start, end uintptr, reqWrite, mapWrite bool) error {
	if end <= start {
		return fmt.Errorf("%s: invalid host range %#x-%#x", m.logPrefix, start, end)
	}
	size := end - start
	align := uint64(m.granule)
	if size >= largePageAlign && start&(largePageAlign-1) == 0 {
		align = largePageAlign
	}
	gpa, err := m.allocGPALocked(uint64(size), align)
	if err != nil {
		return err
	}
	r := &Region{owner: o, host: start, size: size, gpa: gpa, writable: mapWrite}
	if err := m.be.MapHost(start, gpa, size, mapWrite); err != nil {
		if reqWrite || !m.be.RefusedMemory(err) {
			m.freeGPALocked(gpa, uint64(size))
			if m.errRejected != nil {
				return fmt.Errorf("%w: %w", m.errRejected, err)
			}
			return fmt.Errorf("%s: map host range %#x-%#x at %#x: %w", m.logPrefix, start, end, gpa, err)
		}
		if err := m.copyLocked(r, slice); err != nil {
			m.freeGPALocked(gpa, uint64(size))
			return err
		}
	}
	list.insert(r)
	m.count++
	return nil
}

func (m *RegionMap) copyLocked(r *Region, block []byte) error {
	mem, err := m.be.AllocCopy(r.size)
	if err != nil {
		return fmt.Errorf("%s: allocate a private copy of read-only memory: %w", m.logPrefix, err)
	}
	r.copied = mem
	r.filled = make([]bool, r.size/PageSize4K)
	r.fill(block)
	if err := m.be.MapHost(uintptr(unsafe.Pointer(unsafe.SliceData(mem))), r.gpa, r.size, true); err != nil {
		r.copied, r.filled = nil, nil
		return errors.Join(err, m.be.FreeCopy(mem))
	}
	return nil
}

// AllocGPAForTest allocates a granule-aligned GPA span under m.mu for unit tests.
func (m *RegionMap) AllocGPAForTest(size uint64) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allocGPALocked(size, uint64(m.granule))
}

// FreeGPAForTest releases a GPA span under m.mu for unit tests.
func (m *RegionMap) FreeGPAForTest(start, size uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.freeGPALocked(start, size)
}

// AllocatorStateForTest returns a copy of the free list and bump cursor.
func (m *RegionMap) AllocatorStateForTest() ([]GPAFreeSpan, uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.free), m.next
}

func (m *RegionMap) tryAllocLocked(size, align uint64) (uint64, bool) {
	for i, s := range m.free {
		aligned := (s.Start + align - 1) &^ (align - 1)
		if aligned < s.Start || aligned+size < aligned || aligned+size > s.End {
			continue
		}
		left := aligned > s.Start
		right := aligned+size < s.End
		switch {
		case !left && !right:
			m.free = slices.Delete(m.free, i, i+1)
		case left && !right:
			m.free[i].End = aligned
		case !left && right:
			m.free[i].Start = aligned + size
		default:
			m.free[i].End = aligned
			m.free = slices.Insert(m.free, i+1, GPAFreeSpan{Start: aligned + size, End: s.End})
		}
		return aligned, true
	}
	aligned := (m.next + align - 1) &^ (align - 1)
	if aligned < m.next || aligned+size < aligned || aligned+size > m.limit {
		return 0, false
	}
	if aligned > m.next {
		m.free = append(m.free, GPAFreeSpan{Start: m.next, End: aligned})
	}
	m.next = aligned + size
	return aligned, true
}

func (m *RegionMap) allocGPALocked(size, align uint64) (uint64, error) {
	for {
		if gpa, ok := m.tryAllocLocked(size, align); ok {
			return gpa, nil
		}
		if align > uint64(m.granule) {
			if gpa, ok := m.tryAllocLocked(size, uint64(m.granule)); ok {
				return gpa, nil
			}
		}
		if !m.evictIdleLocked() {
			return 0, m.errExhausted
		}
	}
}

func (m *RegionMap) freeGPALocked(start, size uint64) {
	end := start + size
	i := sort.Search(len(m.free), func(i int) bool { return m.free[i].Start >= start })
	m.free = slices.Insert(m.free, i, GPAFreeSpan{Start: start, End: end})
	if i+1 < len(m.free) && m.free[i].End == m.free[i+1].Start {
		m.free[i].End = m.free[i+1].End
		m.free = slices.Delete(m.free, i+1, i+2)
	}
	if i > 0 && m.free[i-1].End == m.free[i].Start {
		m.free[i-1].End = m.free[i].End
		m.free = slices.Delete(m.free, i, i+1)
		i--
	}
	if m.free[i].End == m.next {
		m.next = m.free[i].Start
		m.free = slices.Delete(m.free, i, i+1)
	}
}

func (m *RegionMap) decRefLocked(r *Region) {
	r.refs--
	if r.refs == 0 && !r.persistent() && !m.closed {
		m.dropLocked(r)
	}
}

func (m *RegionMap) dropLocked(r *Region) {
	o := r.owner
	if r.writable || !m.separateReadOnly {
		o.rw.remove(r)
	} else {
		o.ro.remove(r)
	}
	o.chunkTotal = 0
	m.count--
	if o.empty() {
		if o.stored {
			delete(m.owners, o.key)
			o.stored = false
		} else if i := slices.Index(m.unowned, o); i >= 0 {
			m.unowned = slices.Delete(m.unowned, i, i+1)
		}
	}
	if err := m.be.UnmapGPA(r.gpa, r.size); err != nil {
		log.Warningf("%s: unmap guest physical range %#x: %v", m.logPrefix, r.gpa, err)
		return
	}
	m.freeGPALocked(r.gpa, uint64(r.size))
	if r.copied != nil {
		if err := m.be.FreeCopy(r.copied); err != nil {
			log.Warningf("%s: free a private copy: %v", m.logPrefix, err)
		}
		r.copied = nil
	}
}

func (m *RegionMap) evictIdleLocked() bool {
	before := m.count
	for _, o := range slices.Collect(maps.Values(m.owners)) {
		for _, r := range slices.Clone(o.rw) {
			if r.refs == 0 {
				m.dropLocked(r)
			}
		}
		for _, r := range slices.Clone(o.ro) {
			if r.refs == 0 {
				m.dropLocked(r)
			}
		}
	}
	return m.count < before
}

// Release drops every Stage-2 reference held by u after no vCPU runs u's
// page tables. Non-persistent regions with zero remaining references unmap
// immediately.
func (m *RegionMap) Release(u *RegionUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for r := range u.set {
		m.decRefLocked(r)
	}
	for r := range u.extCounts {
		m.decRefLocked(r)
	}
	clear(u.set)
	clear(u.extCounts)
	u.extents = nil
	u.last = nil
}

// MarkClosed rejects future Resolve calls when VM destruction tears down
// Stage-2 mappings in one hypervisor call.
func (m *RegionMap) MarkClosed() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
}

// FreeAfterDestroy releases private read-only copies after VM destruction.
func (m *RegionMap) FreeAfterDestroy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	freeList := func(list regionList) {
		for _, r := range list {
			if r.copied != nil {
				if err := m.be.FreeCopy(r.copied); err != nil {
					log.Warningf("%s: free a private copy: %v", m.logPrefix, err)
				}
				r.copied = nil
			}
		}
	}
	for _, o := range m.owners {
		freeList(o.rw)
		freeList(o.ro)
	}
	for _, o := range m.unowned {
		freeList(o.rw)
		freeList(o.ro)
	}
	clear(m.owners)
	m.unowned = nil
	m.free = nil
	m.count = 0
}

// Close marks m closed and unmaps every Stage-2 region before partition
// deletion.
func (m *RegionMap) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil
	}
	m.closed = true
	var errs error
	unmapList := func(list regionList) {
		for _, r := range list {
			if err := m.be.UnmapGPA(r.gpa, r.size); err != nil {
				errs = errors.Join(errs, err)
			}
			if r.copied != nil {
				errs = errors.Join(errs, m.be.FreeCopy(r.copied))
				r.copied = nil
			}
		}
	}
	for _, o := range m.owners {
		unmapList(o.rw)
		unmapList(o.ro)
	}
	for _, o := range m.unowned {
		unmapList(o.rw)
		unmapList(o.ro)
	}
	clear(m.owners)
	m.unowned = nil
	m.free = nil
	m.count = 0
	return errs
}

// RegionCount returns the number of active Stage-2 regions.
func (m *RegionMap) RegionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}

// CopyCount returns the number of regions backed by a private read-only copy.
func (m *RegionMap) CopyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	countList := func(list regionList) {
		for _, r := range list {
			if r.copied != nil {
				n++
			}
		}
	}
	for _, o := range m.owners {
		countList(o.rw)
		countList(o.ro)
	}
	for _, o := range m.unowned {
		countList(o.rw)
		countList(o.ro)
	}
	return n
}

// RegionsOfForTest returns a snapshot of the Stage-2 regions owned by f.
func (m *RegionMap) RegionsOfForTest(f memmap.File) []*Region {
	m.mu.Lock()
	defer m.mu.Unlock()
	o := m.owners[f]
	if o == nil {
		return nil
	}
	out := make([]*Region, 0, len(o.rw)+len(o.ro))
	out = append(out, o.rw...)
	out = append(out, o.ro...)
	return out
}
