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
	"fmt"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// AddressSpace implements platform.AddressSpace with its own guest page
// tables.
//
// MapFile asks Platform.mem for the guest physical ranges of the host blocks.
// The partition keeps those ranges mapped. MapFile then writes one run of
// leaf entries for each contiguous range. Unmap only clears entries. The
// kernel region comes from the shared upper half. Unmap and any change of an
// existing entry stop every processor that may hold the old translation
// before the call returns. The Sentry reuses a page only after its entry is
// gone, so the guest cannot reach a reused page. The Sentry reads and writes
// guest memory through its own host mappings, not through this type.
type AddressSpace struct {
	platform.NoAddressSpaceIO

	p     *Platform
	id    uint64
	alloc *ptAllocator
	pt    *pagetables.PageTables

	// mu guards the page tables and released.
	mu       sync.Mutex
	released bool

	// gen counts invalidations. A virtual processor flushes its TLB when its
	// copy differs.
	gen atomic.Uint64

	// dead is true after Release. A Switch on a released address space fails.
	dead atomic.Bool

	// execGen counts mappings with execute permission. The arm64 stub
	// invalidates the instruction cache when it changes.
	execGen atomic.Uint64

	// activeMu guards active, the processors that run this address space.
	activeMu sync.Mutex
	active   map[*vcpu]struct{}
}

func newAddressSpace(p *Platform) (*AddressSpace, error) {
	as := &AddressSpace{
		p:      p,
		id:     p.nextASID.Add(1),
		alloc:  newPTAllocator(p.pool),
		active: make(map[*vcpu]struct{}),
	}
	if err := as.alloc.Reserve(2); err != nil {
		as.alloc.Drain()
		return nil, fmt.Errorf("whpx: reserve page tables: %w", err)
	}
	as.pt = pagetables.NewWithUpper(as.alloc, p.kernelPageTables(), uintptr(p.kernel.layout.base))
	return as, nil
}

// addActive records that v may execute this address space.
func (as *AddressSpace) addActive(v *vcpu) {
	as.activeMu.Lock()
	as.active[v] = struct{}{}
	as.activeMu.Unlock()
}

func (as *AddressSpace) removeActive(v *vcpu) {
	as.activeMu.Lock()
	delete(as.active, v)
	as.activeMu.Unlock()
}

// invalidate makes every processor of the address space discard its cached
// translations before it runs guest code again. Then it recycles the
// page-table pages that the last change freed. The caller holds mu.
func (as *AddressSpace) invalidate() {
	as.gen.Add(1)
	as.activeMu.Lock()
	vps := make([]*vcpu, 0, len(as.active))
	for v := range as.active {
		vps = append(vps, v)
	}
	as.activeMu.Unlock()
	for _, v := range vps {
		v.kickAndWait()
	}
	as.alloc.Recycle()
}

// checkRange verifies that [addr, addr+length) is a page-aligned range in the
// user part of the address space.
func (as *AddressSpace) checkRange(addr hostarch.Addr, length uint64) error {
	end := uint64(addr) + length
	if uint64(addr)&pageMask != 0 || length == 0 || length&pageMask != 0 || end < uint64(addr) || end > as.p.maxUser() {
		return platform.SegmentationFault{Addr: addr}
	}
	return nil
}

// chunkedFile is a memmap.File whose whole range stays mapped in host memory
// with write access for the life of the file. pgalloc.MemoryFile is the only
// implementation. The hvf backend recognizes it the same way.
type chunkedFile interface {
	memmap.File
	// TotalSize returns the size of the host mapped range from offset 0.
	TotalSize() uint64
}

func isChunkedFile(f memmap.File) bool {
	_, ok := f.(chunkedFile)
	return ok
}

// MapFile implements platform.AddressSpace.MapFile.
func (as *AddressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, _ bool) error {
	if fr.Start&pageMask != 0 || fr.End&pageMask != 0 || !at.Any() {
		return platform.SegmentationFault{Addr: addr}
	}
	if err := as.checkRange(addr, fr.Length()); err != nil {
		return err
	}
	// A memory file keeps every chunk mapped with write access, whatever the
	// guest may do with a page. The partition registers that memory once and
	// writable, and the page-table entries of install enforce a read-only
	// mapping. Any other file registers writable only when the request writes.
	hostWrite := at.Write || isChunkedFile(f)
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true, Write: hostWrite})
	if err != nil {
		return err
	}
	if bs.NumBytes() != fr.Length() {
		return fmt.Errorf("whpx: MapInternal returned %d bytes for a range of %d bytes", bs.NumBytes(), fr.Length())
	}
	var buf [4]gpaRun
	runs := buf[:0]
	for !bs.IsEmpty() {
		runs, err = as.p.mem.resolve(bs.Head().ToSlice(), hostWrite, runs)
		if err != nil {
			return err
		}
		bs = bs.Tail()
	}
	return as.install(addr, runs, at)
}

// mapHost maps a page-aligned host slice at addr. Tests use it to map memory
// without a memmap.File.
func (as *AddressSpace) mapHost(addr hostarch.Addr, data []byte, at hostarch.AccessType) error {
	if err := as.checkRange(addr, uint64(len(data))); err != nil {
		return err
	}
	runs, err := as.p.mem.resolve(data, at.Write, nil)
	if err != nil {
		return err
	}
	return as.install(addr, runs, at)
}

// install writes the page-table entries of runs, which cover consecutive
// pages from addr. A change of an existing entry stops the processors before
// install returns.
func (as *AddressSpace) install(addr hostarch.Addr, runs []gpaRun, at hostarch.AccessType) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return platform.SegmentationFault{Addr: addr}
	}
	if err := as.alloc.Reserve(ptReserveForRuns(runs)); err != nil {
		return fmt.Errorf("whpx: reserve page tables: %w", err)
	}
	opts := userPageOpts(at)
	replaced := false
	va := uint64(addr)
	for _, r := range runs {
		if as.pt.Map(hostarch.Addr(va), uintptr(r.Size), opts, uintptr(r.GPA)) {
			replaced = true
		}
		va += r.Size
	}
	if at.Execute {
		as.execGen.Add(1)
	}
	if replaced || as.alloc.Quarantined() > 0 {
		as.invalidate()
	}
	return nil
}

// Unmap implements platform.AddressSpace.Unmap.
func (as *AddressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return
	}
	start := uint64(addr) &^ pageMask
	end := (uint64(addr) + length + pageMask) &^ pageMask
	if end < start || end > as.p.maxUser() {
		end = as.p.maxUser()
	}
	if end <= start {
		return
	}
	// A range that starts or ends inside a large entry splits the entry. The
	// split needs page-table pages. A failure here leaves entries that the
	// guest can still use, so it stops the program.
	if err := as.alloc.Reserve(ptSplitReserve); err != nil {
		log.Warningf("whpx: %v", err)
		panic(fmt.Sprintf("whpx: cannot reserve page tables to unmap guest memory: %v", err))
	}
	removed := as.pt.Unmap(hostarch.Addr(start), uintptr(end-start))
	if removed || as.alloc.Quarantined() > 0 {
		as.invalidate()
	}
}

// Release implements platform.AddressSpace.Release.
func (as *AddressSpace) Release() {
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return
	}
	as.released = true
	as.dead.Store(true)
	as.pt.Unmap(0, uintptr(as.p.maxUser()))
	as.invalidate()
	as.forgetIdleRoots()
	as.alloc.Drain()
}

// forgetIdleRoots invalidates the state of every idle processor that still
// names as. The hardware root register of such a processor points to the
// top-level table that drain recycles, and the next entry must not rely on
// it. Platform.mu orders the scan with acquire, so no holder uses an idle
// processor during the scan. The function skips a busy processor. Its holder
// owns the state and writes the root register on the host when it switches
// to another address space, because the identifier of as never returns.
// The caller holds as.mu. No path takes as.mu while it holds Platform.mu.
func (as *AddressSpace) forgetIdleRoots() {
	p := as.p
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, v := range p.vps {
		if !v.busy && v.st.asID == as.id {
			v.st.invalidate()
		}
	}
}

// PreFork implements platform.AddressSpace.PreFork.
func (*AddressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*AddressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS.
func (*AddressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return nil
}
