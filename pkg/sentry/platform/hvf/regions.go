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

package hvf

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
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

var (
	errPlatformClosed = errors.New("hvf: platform closed")
	// errHostBlockRejected reports that Hypervisor.framework refused a host
	// memory region. It wraps the framework error.
	errHostBlockRejected = errors.New("hvf: hv_vm_map rejected the host memory")
	errIPAExhausted      = errors.New("hvf: guest physical address space exhausted")
)

// stage2Backend is the call boundary to the hypervisor and to the host memory
// that backs private copies. Tests replace it to count Stage-2 calls.
type stage2Backend interface {
	// mapHost maps size bytes of host memory at ipa with read, write and
	// execute permission. Host address and size are multiples of the host page.
	mapHost(host uintptr, ipa uint64, size uintptr) error
	// unmapIPA removes the mapping that mapHost created at ipa.
	unmapIPA(ipa uint64, size uintptr) error
	// refusedMemory reports whether err means that the hypervisor refuses
	// this host memory for any request, so a private copy can replace it.
	refusedMemory(err error) bool
	// allocCopy returns zeroed host memory for a private copy.
	allocCopy(size uintptr) ([]byte, error)
	// freeCopy returns memory from allocCopy.
	freeCopy(mem []byte) error
}

// chunkedFile is a memmap.File whose whole range stays mapped in host memory
// for the life of the file. pgalloc.MemoryFile is the only implementation. The
// registry maps every chunk of such a file once and keeps the mapping.
type chunkedFile interface {
	memmap.File
	// TotalSize returns the size of the host mapped range from offset 0.
	TotalSize() uint64
}

// segment is a run of contiguous guest physical memory.
type segment = hvcommon.GPARun

// region is one Stage-2 mapping. It maps the host range [host, host+size) at
// ipa. When copied is non-nil, the mapping holds a private copy of that range
// instead, because the hypervisor refused the host memory.
type region struct {
	owner  *ownerRegions
	host   uintptr
	size   uintptr
	ipa    uint64
	copied []byte
	// filled marks the 4KB pages of copied that hold source bytes.
	filled []bool
	// refs counts the address spaces that may hold a Stage-1 mapping of the
	// region. The count changes under regionMap.mu.
	refs int
}

func (r *region) end() uintptr { return r.host + r.size }

// fill copies the pages of block that lie in r into the private copy. block is
// a slice of the host mapping that starts and ends at a 4KB boundary. The
// copy holds no other byte of the host pages around the block: a host page
// can be larger than the 4KB pages that the guest maps from one file range.
func (r *region) fill(block []byte) {
	first := uintptr(unsafe.Pointer(unsafe.SliceData(block)))
	lo, hi := max(first, r.host), min(first+uintptr(len(block)), r.end())
	for p := lo; p < hi; p += pageSize4K {
		i := (p - r.host) / pageSize4K
		if r.filled[i] {
			continue
		}
		copy(r.copied[p-r.host:p-r.host+pageSize4K], block[p-first:])
		r.filled[i] = true
	}
}

// ownerRegions holds the regions of one memmap.File, ordered by host address.
// Host address ranges belong to one file: the file can unmap and reuse the
// range, so a lookup by host address alone could return a stale mapping.
type ownerRegions struct {
	key     memmap.File
	regions []*region
	// persistent regions stay after the last address space leaves. They hold
	// no memory of their own, and the file outlives its address spaces.
	persistent bool
	// chunkTotal is the TotalSize at the last chunk registration.
	chunkTotal uint64
	// stored is true while the registry map holds the entry.
	stored bool
}

// find returns the region that contains addr, or nil.
func (o *ownerRegions) find(addr uintptr) *region {
	i := sort.Search(len(o.regions), func(i int) bool { return o.regions[i].end() > addr })
	if i < len(o.regions) && o.regions[i].host <= addr {
		return o.regions[i]
	}
	return nil
}

// covers reports whether regions cover every byte of [start, end).
func (o *ownerRegions) covers(start, end uintptr) bool {
	i := sort.Search(len(o.regions), func(i int) bool { return o.regions[i].end() > start })
	cur := start
	for ; cur < end; i++ {
		if i >= len(o.regions) || o.regions[i].host > cur {
			return false
		}
		cur = o.regions[i].end()
	}
	return true
}

// gaps returns the parts of [start, end) that no region covers.
func (o *ownerRegions) gaps(start, end uintptr) [][2]uintptr {
	var out [][2]uintptr
	i := sort.Search(len(o.regions), func(i int) bool { return o.regions[i].end() > start })
	cur := start
	for ; i < len(o.regions) && o.regions[i].host < end; i++ {
		r := o.regions[i]
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

func (o *ownerRegions) insert(r *region) {
	i := sort.Search(len(o.regions), func(i int) bool { return o.regions[i].host >= r.host })
	o.regions = slices.Insert(o.regions, i, r)
}

func (o *ownerRegions) remove(r *region) {
	if i := slices.Index(o.regions, r); i >= 0 {
		o.regions = slices.Delete(o.regions, i, i+1)
	}
}

// regionUser is the set of regions that one address space uses. The address
// space calls resolve and release under its own lock.
type regionUser struct {
	set  map[*region]struct{}
	last *region
}

// use records r. The caller holds regionMap.mu.
func (u *regionUser) use(r *region) {
	if u.last == r {
		return
	}
	u.last = r
	if _, ok := u.set[r]; ok {
		return
	}
	if u.set == nil {
		u.set = make(map[*region]struct{})
	}
	u.set[r] = struct{}{}
	r.refs++
}

type ipaSpan struct{ start, end uint64 }

// regionMap assigns guest physical addresses to host memory and keeps the
// Stage-2 mappings. MapFile and Unmap of an address space change only Stage-1
// tables. A region stays mapped until the VM ends. Regions of a file that is
// not a chunkedFile go away with their last address space, and any idle region
// goes away when the guest physical range runs out.
type regionMap struct {
	be      stage2Backend
	granule uintptr
	limit   uint64

	mu     sync.Mutex
	closed bool
	owners map[memmap.File]*ownerRegions
	// free holds released ranges, sorted and merged. Addresses from next up
	// were never assigned.
	free  []ipaSpan
	next  uint64
	count int
}

func newRegionMap(be stage2Backend, granule uintptr, base, limit uint64) *regionMap {
	return &regionMap{be: be, granule: granule, limit: limit, next: base, owners: make(map[memmap.File]*ownerRegions)}
}

// ownerLocked returns the registry entry of f. A file whose dynamic type
// cannot be a map key gets a private entry that no later call finds.
func (m *regionMap) ownerLocked(f memmap.File) *ownerRegions {
	_, chunked := f.(chunkedFile)
	if !reflect.TypeOf(f).Comparable() {
		return &ownerRegions{key: f}
	}
	o, ok := m.owners[f]
	if !ok {
		o = &ownerRegions{key: f, persistent: chunked, stored: true}
		m.owners[f] = o
	}
	return o
}

// resolve returns the guest physical runs that map the blocks of bs and
// records every region that they use in u. A read-only request for memory
// that the hypervisor refuses gets a private copy. The copy never changes
// because its source is immutable. A writable request fails instead.
func (m *regionMap) resolve(u *regionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]segment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errPlatformClosed
	}
	o := m.ownerLocked(f)
	segs := make([]segment, 0, bs.NumBlocks())
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		slice := bs.Head().ToSlice()
		if len(slice) == 0 {
			continue
		}
		base := uintptr(unsafe.Pointer(unsafe.SliceData(slice)))
		n := uintptr(len(slice))
		if base&pageMask4K != 0 || n&pageMask4K != 0 {
			return nil, fmt.Errorf("hvf: host block %#x+%#x is not 4KB aligned", base, n)
		}
		if err := m.coverLocked(o, f, slice, write); err != nil {
			return nil, err
		}
		for off := uintptr(0); off < n; {
			r := o.find(base + off)
			if r == nil {
				return nil, fmt.Errorf("hvf: host address %#x has no Stage-2 region", base+off)
			}
			if write && r.copied != nil {
				return nil, fmt.Errorf("%w: the memory is a private copy of read-only memory", errHostBlockRejected)
			}
			take := min(n-off, r.end()-(base+off))
			if r.copied != nil {
				r.fill(slice[off : off+take])
			}
			u.use(r)
			ipa := r.ipa + uint64(base+off-r.host)
			segs = hvcommon.AppendGPARun(segs, ipa, uint64(take))
			off += take
		}
	}
	return segs, nil
}

// coverLocked makes regions cover the host pages of block.
func (m *regionMap) coverLocked(o *ownerRegions, f memmap.File, block []byte, write bool) error {
	base := uintptr(unsafe.Pointer(unsafe.SliceData(block)))
	start, end := m.roundOut(base, base+uintptr(len(block)))
	if o.covers(start, end) {
		return nil
	}
	if cf, ok := f.(chunkedFile); ok {
		m.registerChunksLocked(o, cf)
		if o.covers(start, end) {
			return nil
		}
	}
	for _, gap := range o.gaps(start, end) {
		if err := m.addLocked(o, block, gap[0], gap[1], write); err != nil {
			return err
		}
	}
	return nil
}

func (m *regionMap) roundOut(start, end uintptr) (uintptr, uintptr) {
	mask := m.granule - 1
	return start &^ mask, (end + mask) &^ mask
}

// registerChunksLocked maps every chunk of the file that has no region. It
// ignores failures: the caller then maps the host range it needs. A memory
// file that registers for the first time drops the idle regions of earlier
// memory files. The hypervisor keeps the memory of a region alive after the
// file unmapped it, so an idle region of a destroyed file would hold that
// memory until the VM ends.
func (m *regionMap) registerChunksLocked(o *ownerRegions, cf chunkedFile) {
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
		for _, gap := range o.gaps(start, end) {
			if err := m.addLocked(o, chunk, gap[0], gap[1], true); err != nil {
				log.Warningf("hvf: map the memory file range %#x-%#x: %v", gap[0], gap[1], err)
				break
			}
		}
	}
}

// addLocked maps the host range [start, end) into Stage-2 and records the
// region. block is a slice of the same host mapping. It is the source of a
// private copy, and start and end can lie beyond it by less than one host page
// on each side.
func (m *regionMap) addLocked(o *ownerRegions, block []byte, start, end uintptr, write bool) error {
	size := end - start
	ipa, err := m.allocIPALocked(uint64(size))
	if err != nil {
		return err
	}
	r := &region{owner: o, host: start, size: size, ipa: ipa}
	if err := m.be.mapHost(start, ipa, size); err != nil {
		if write || !m.be.refusedMemory(err) {
			m.freeIPALocked(ipa, uint64(size))
			return fmt.Errorf("%w: %w", errHostBlockRejected, err)
		}
		if err := m.copyLocked(r, block); err != nil {
			m.freeIPALocked(ipa, uint64(size))
			return err
		}
	}
	o.insert(r)
	m.count++
	return nil
}

// copyLocked fills r with a private copy of the pages of block and maps it.
// The rest of the host pages stays zero until a later resolve asks for it.
func (m *regionMap) copyLocked(r *region, block []byte) error {
	mem, err := m.be.allocCopy(r.size)
	if err != nil {
		return fmt.Errorf("hvf: allocate a private copy of read-only memory: %w", err)
	}
	r.copied = mem
	r.filled = make([]bool, r.size/pageSize4K)
	r.fill(block)
	if err := m.be.mapHost(uintptr(unsafe.Pointer(unsafe.SliceData(mem))), r.ipa, r.size); err != nil {
		r.copied, r.filled = nil, nil
		return errors.Join(err, m.be.freeCopy(mem))
	}
	return nil
}

// allocIPALocked assigns a guest physical range. When none is left, it drops
// the idle regions and tries again.
func (m *regionMap) allocIPALocked(size uint64) (uint64, error) {
	for {
		for i, s := range m.free {
			if s.end-s.start >= size {
				ipa := s.start
				if s.end-s.start == size {
					m.free = slices.Delete(m.free, i, i+1)
				} else {
					m.free[i].start += size
				}
				return ipa, nil
			}
		}
		if m.next+size <= m.limit {
			ipa := m.next
			m.next += size
			return ipa, nil
		}
		if !m.evictIdleLocked() {
			return 0, errIPAExhausted
		}
	}
}

// freeIPALocked returns a range and merges it with its neighbours.
func (m *regionMap) freeIPALocked(start, size uint64) {
	end := start + size
	i := sort.Search(len(m.free), func(i int) bool { return m.free[i].start >= start })
	m.free = slices.Insert(m.free, i, ipaSpan{start, end})
	if i+1 < len(m.free) && m.free[i].end == m.free[i+1].start {
		m.free[i].end = m.free[i+1].end
		m.free = slices.Delete(m.free, i+1, i+2)
	}
	if i > 0 && m.free[i-1].end == m.free[i].start {
		m.free[i-1].end = m.free[i].end
		m.free = slices.Delete(m.free, i, i+1)
		i--
	}
	if m.free[i].end == m.next {
		m.next = m.free[i].start
		m.free = slices.Delete(m.free, i, i+1)
	}
}

// dropLocked unmaps an unused region and frees its resources. When the
// hypervisor fails to unmap, the region keeps its address and memory because
// the mapping state is unknown.
func (m *regionMap) dropLocked(r *region) {
	o := r.owner
	o.remove(r)
	o.chunkTotal = 0
	m.count--
	if len(o.regions) == 0 && o.stored {
		delete(m.owners, o.key)
		o.stored = false
	}
	if err := m.be.unmapIPA(r.ipa, r.size); err != nil {
		log.Warningf("hvf: unmap guest physical range %#x: %v", r.ipa, err)
		return
	}
	m.freeIPALocked(r.ipa, uint64(r.size))
	if r.copied != nil {
		if err := m.be.freeCopy(r.copied); err != nil {
			log.Warningf("hvf: free a private copy: %v", err)
		}
		r.copied = nil
	}
}

// evictIdleLocked drops every region that no address space uses. It reports
// whether it freed any range.
func (m *regionMap) evictIdleLocked() bool {
	before := m.count
	for _, o := range slices.Collect(maps.Values(m.owners)) {
		for _, r := range slices.Clone(o.regions) {
			if r.refs == 0 {
				m.dropLocked(r)
			}
		}
	}
	return m.count < before
}

// release drops the references of an address space that has no Stage-1
// mapping any more. The caller stops every vCPU of the address space first.
// A region of a file that is not persistent goes away with its last user.
func (m *regionMap) release(u *regionUser) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for r := range u.set {
		r.refs--
		if r.refs == 0 && !r.owner.persistent && !m.closed {
			m.dropLocked(r)
		}
	}
	clear(u.set)
	u.last = nil
}

// markClosed makes later resolve calls fail. The hypervisor mappings vanish
// with the VM, so the registry never unmaps them.
func (m *regionMap) markClosed() {
	m.mu.Lock()
	m.closed = true
	m.mu.Unlock()
}

// freeAfterDestroy frees the private copies after the VM no longer maps them.
func (m *regionMap) freeAfterDestroy() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, o := range m.owners {
		for _, r := range o.regions {
			if r.copied != nil {
				if err := m.be.freeCopy(r.copied); err != nil {
					log.Warningf("hvf: free a private copy: %v", err)
				}
				r.copied = nil
			}
		}
	}
	clear(m.owners)
	m.free = nil
	m.count = 0
}

// regionCount returns the number of mapped regions for tests.
func (m *regionMap) regionCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.count
}
