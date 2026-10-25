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
	"fmt"
	"unsafe"

	"z.gfire.dev/gvx/pkg/ring0/pagetables"
)

const (
	// PageSize4K is the 4KB guest page size used by Stage-1 tables.
	PageSize4K = 4096
	// PageMask4K masks the byte offset inside a 4KB guest page.
	PageMask4K = PageSize4K - 1
	// MinUserAddr is the lowest address mapped for guest user processes.
	MinUserAddr = 0x10000
	// MaxUserAddrX64 bounds the lower canonical half of 4-level x86-64 paging.
	MaxUserAddrX64 = 1 << 47
	// MaxUserAddrA64 bounds the 48-bit TTBR0_EL1 user region on ARM64.
	MaxUserAddrA64 = 1 << 48

	// SplitReserve is the maximum number of page-table pages that one Map or
	// Unmap call allocates when splitting block descriptors at both range ends.
	SplitReserve = 4

	// KernelTablePages is the number of page-table pages that a shared kernel
	// page-table tree reserves before building its mappings.
	KernelTablePages = 16
)

// PagePool supplies 4KB pages mapped in Stage-2 for Stage-1 page tables.
type PagePool interface {
	// AllocPage returns a zeroed 4KB page and its guest physical address.
	AllocPage() (page []byte, gpa uint64, err error)
	// FreePage returns a 4KB page to the pool.
	FreePage(page []byte, gpa uint64)
}

// PTAllocator implements pagetables.Allocator over a PagePool.
//
// Because pagetables.Allocator cannot report an allocation error during a walk,
// callers call Reserve before every operation that can allocate. Freed table
// pages wait in Quarantine until Recycle runs after every active vCPU flushes
// its TLB.
type PTAllocator struct {
	pool       PagePool
	Ready      []*pagetables.PTEs
	owned      map[*pagetables.PTEs]uint64
	byGPA      map[uint64]*pagetables.PTEs
	Quarantine []*pagetables.PTEs
}

// NewPTAllocator creates a Stage-1 page-table allocator backed by pool.
func NewPTAllocator(pool PagePool) *PTAllocator {
	return &PTAllocator{
		pool:  pool,
		owned: make(map[*pagetables.PTEs]uint64),
		byGPA: make(map[uint64]*pagetables.PTEs),
	}
}

func (a *PTAllocator) take() (*pagetables.PTEs, error) {
	page, gpa, err := a.pool.AllocPage()
	if err != nil {
		return nil, err
	}
	ptes := (*pagetables.PTEs)(unsafe.Pointer(unsafe.SliceData(page)))
	a.owned[ptes] = gpa
	a.byGPA[gpa] = ptes
	return ptes, nil
}

// Reserve ensures that at least n pages are ready in a.Ready for NewPTEs.
func (a *PTAllocator) Reserve(n int) error {
	for len(a.Ready) < n {
		ptes, err := a.take()
		if err != nil {
			return err
		}
		a.Ready = append(a.Ready, ptes)
	}
	return nil
}

// NewPTEs implements pagetables.Allocator.NewPTEs.
func (a *PTAllocator) NewPTEs() *pagetables.PTEs {
	if len(a.Ready) == 0 {
		if err := a.Reserve(1); err != nil {
			panic(fmt.Sprintf("hvcommon: allocate page-table page: %v", err))
		}
	}
	n := len(a.Ready)
	ptes := a.Ready[n-1]
	a.Ready = a.Ready[:n-1]
	return ptes
}

// PhysicalFor implements pagetables.Allocator.PhysicalFor.
func (a *PTAllocator) PhysicalFor(ptes *pagetables.PTEs) uintptr {
	gpa, ok := a.owned[ptes]
	if !ok {
		panic(fmt.Sprintf("hvcommon: page-table page %p does not belong to allocator", ptes))
	}
	return uintptr(gpa)
}

// LookupPTEs implements pagetables.Allocator.LookupPTEs.
func (a *PTAllocator) LookupPTEs(physical uintptr) *pagetables.PTEs {
	ptes, ok := a.byGPA[uint64(physical)]
	if !ok {
		panic(fmt.Sprintf("hvcommon: guest physical address %#x is not a page-table page", physical))
	}
	return ptes
}

// FreePTEs implements pagetables.Allocator.FreePTEs.
func (a *PTAllocator) FreePTEs(ptes *pagetables.PTEs) {
	a.Quarantine = append(a.Quarantine, ptes)
}

// Recycle implements pagetables.Allocator.Recycle.
func (a *PTAllocator) Recycle() {
	for _, ptes := range a.Quarantine {
		clear(ptes[:])
		a.Ready = append(a.Ready, ptes)
	}
	a.Quarantine = a.Quarantine[:0]
}

// Quarantined returns the number of freed pages waiting for Recycle.
func (a *PTAllocator) Quarantined() int { return len(a.Quarantine) }

// Drain returns every page owned by a back to the underlying PagePool.
func (a *PTAllocator) Drain() {
	for ptes, gpa := range a.owned {
		a.pool.FreePage(unsafe.Slice((*byte)(unsafe.Pointer(ptes)), PageSize4K), gpa)
	}
	clear(a.owned)
	clear(a.byGPA)
	a.Ready, a.Quarantine = nil, nil
}

// ReserveForMap returns an upper bound on the number of page-table pages that
// mapping n consecutive 4KB pages can allocate across three lower levels.
func ReserveForMap(n uint64) int {
	const entries = 512
	return int(n/entries+2) + int(n/(entries*entries)+2) + int(n/(entries*entries*entries)+2) + 1
}

// GPARun is a contiguous range of guest physical memory.
type GPARun struct {
	GPA  uint64
	Size uint64
}

// AppendGPARun appends a range to runs, coalescing it with the previous run
// when the two are contiguous.
func AppendGPARun(runs []GPARun, gpa, size uint64) []GPARun {
	if n := len(runs); n > 0 && runs[n-1].GPA+runs[n-1].Size == gpa {
		runs[n-1].Size += size
		return runs
	}
	return append(runs, GPARun{GPA: gpa, Size: size})
}

// ReserveForRuns returns an upper bound on the number of page-table pages that
// mapping all runs can allocate.
func ReserveForRuns(runs []GPARun) int {
	n := 0
	for _, r := range runs {
		n += SplitReserve + ReserveForMap(r.Size/PageSize4K)
	}
	return n
}

var _ pagetables.Allocator = (*PTAllocator)(nil)
