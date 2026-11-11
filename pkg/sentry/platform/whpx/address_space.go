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
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// hostBlockFile allows unit tests to supply explicit 64-bit host virtual
// addresses without constructing invalid Go pointers.
type hostBlockFile interface {
	hostBlocks(fr memmap.FileRange, at hostarch.AccessType) ([]hvcommon.HostBlock, error)
}

// AddressSpace implements platform.AddressSpace with its own guest page
// tables and reference-counted Stage-2 region tracking.
//
// MapFile resolves Stage-2 GPA runs owned by each memmap.File through
// Platform.mem and installs 4KB or 2MiB Stage-1 leaf entries. Persistent
// ChunkedFile regions stay mapped across Unmap and Release until evicted or
// closed. Non-persistent file regions release their Stage-2 mappings through
// WHvUnmapGpaRange once all referencing guest page-table entries clear and all
// active virtual processors flush their TLBs.
type AddressSpace struct {
	platform.NoAddressSpaceIO

	p     *Platform
	id    uint64
	alloc *ptAllocator
	pt    *pagetables.PageTables

	// mu guards pt, regions, and released. Callers acquire mu before
	// Platform.mem.inner.mu so extent updates in regions and reference updates
	// in RegionMap execute atomically.
	mu       sync.Mutex
	regions  hvcommon.RegionUser
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

func isChunkedFile(f memmap.File) bool {
	_, ok := f.(hvcommon.ChunkedFile)
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
	hostWrite := at.Write || isChunkedFile(f)
	hostAT := hostarch.AccessType{Read: true, Write: hostWrite}

	var (
		blocks    []hvcommon.HostBlock
		useBlocks bool
	)
	if hf, ok := f.(hostBlockFile); ok {
		var err error
		blocks, err = hf.hostBlocks(fr, hostAT)
		if err != nil {
			return err
		}
		var total uint64
		for _, b := range blocks {
			total += uint64(b.Len)
		}
		if total != fr.Length() {
			return fmt.Errorf("whpx: hostBlocks returned %d bytes for a range of %d bytes", total, fr.Length())
		}
		useBlocks = true
	}

	if !useBlocks {
		mapped, err := f.MapInternal(fr, hostAT)
		if err != nil {
			return err
		}
		if mapped.NumBytes() != fr.Length() {
			return fmt.Errorf("whpx: MapInternal returned %d bytes for a range of %d bytes", mapped.NumBytes(), fr.Length())
		}
		blocks = hvcommon.HostBlocksFromSeq(mapped)
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return platform.SegmentationFault{Addr: addr}
	}
	runs, err := as.p.mem.resolvePinnedBlocks(&as.regions, f, blocks, hostWrite)
	if err != nil {
		return err
	}
	if err := as.installLocked(addr, runs, at); err != nil {
		as.p.mem.finishPin(runs, nil, nil)
		return err
	}
	acquired, dropped := as.regions.RecordRuns(uint64(addr), runs)
	as.p.mem.finishPin(runs, acquired, dropped)
	return nil
}

// mapHost maps a page-aligned host slice at addr. Tests use it to map memory
// without a memmap.File.
func (as *AddressSpace) mapHost(addr hostarch.Addr, data []byte, at hostarch.AccessType) error {
	if err := as.checkRange(addr, uint64(len(data))); err != nil {
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return platform.SegmentationFault{Addr: addr}
	}
	runs, err := as.p.mem.resolveRaw(&as.regions, data, at.Write)
	if err != nil {
		return err
	}
	return as.installLocked(addr, runs, at)
}

// installLocked writes the page-table entries of runs under as.mu. Any
// overwritten entry flushes active processors before installLocked returns.
func (as *AddressSpace) installLocked(addr hostarch.Addr, runs []gpaRun, at hostarch.AccessType) error {
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
	if err := as.alloc.Reserve(ptSplitReserve); err != nil {
		log.Warningf("whpx: %v", err)
		panic(fmt.Sprintf("whpx: cannot reserve page tables to unmap guest memory: %v", err))
	}
	removed := as.pt.Unmap(hostarch.Addr(start), uintptr(end-start))
	if removed || as.alloc.Quarantined() > 0 {
		as.invalidate()
	}
	dropped := as.regions.ClearRange(start, end)
	as.p.mem.releaseRegions(dropped)
}

// Release implements platform.AddressSpace.Release.
func (as *AddressSpace) Release() {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return
	}
	as.released = true
	as.dead.Store(true)
	as.pt.Unmap(0, uintptr(as.p.maxUser()))
	as.invalidate()
	as.forgetIdleRoots()
	as.alloc.Drain()
	as.p.mem.release(&as.regions)
	as.mu.Unlock()
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
