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
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

const (
	// ptSlabPages is the number of page-table pages that one slab maps. A
	// slab is 64 KiB, the allocation granularity of Windows.
	ptSlabPages = 16
	ptSlabSize  = ptSlabPages * pageSize
	ptSlabShift = 16
)

// ptSlab is a run of page-table pages with consecutive guest physical
// addresses.
type ptSlab struct {
	mem []byte
	gpa uint64
}

type ptFreePage struct {
	page []byte
	gpa  uint64
}

// ptPool owns the pages that back guest page tables.
type ptPool struct {
	be  backend
	gpa *gpaAllocator

	mu    sync.Mutex
	slabs []*ptSlab
	free  []ptFreePage
}

func newPTPool(be backend, gpa *gpaAllocator) *ptPool {
	return &ptPool{be: be, gpa: gpa}
}

// grow maps one more slab and adds its pages to the free list.
func (p *ptPool) grow() error {
	mem, err := p.be.allocHost(ptSlabSize)
	if err != nil {
		return fmt.Errorf("whpx: allocate page-table slab: %w", err)
	}
	if uintptr(unsafe.Pointer(&mem[0]))&(ptSlabSize-1) != 0 {
		return errors.Join(fmt.Errorf("whpx: page-table slab is not 64 KiB aligned"), p.be.freeHost(mem))
	}
	gpa, err := p.gpa.allocRunAligned(ptSlabPages, ptSlabPages)
	if err != nil {
		return errors.Join(err, p.be.freeHost(mem))
	}
	if err := p.be.mapGPA(unsafe.Pointer(&mem[0]), gpa, ptSlabSize, partitionFlags(true)&^mapFlagExecute); err != nil {
		return errors.Join(fmt.Errorf("whpx: map page-table slab at %#x: %w", gpa, err), p.be.freeHost(mem))
	}
	p.slabs = append(p.slabs, &ptSlab{mem: mem, gpa: gpa})
	for i := ptSlabPages - 1; i >= 0; i-- {
		off := i * pageSize
		p.free = append(p.free, ptFreePage{
			page: mem[off : off+pageSize : off+pageSize],
			gpa:  gpa + uint64(off),
		})
	}
	return nil
}

// AllocPage implements hvcommon.PagePool.
func (p *ptPool) AllocPage() ([]byte, uint64, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.free) == 0 {
		if err := p.grow(); err != nil {
			return nil, 0, err
		}
	}
	n := len(p.free)
	fp := p.free[n-1]
	p.free = p.free[:n-1]
	return fp.page, fp.gpa, nil
}

// FreePage implements hvcommon.PagePool.
func (p *ptPool) FreePage(page []byte, gpa uint64) {
	clear(page)
	p.mu.Lock()
	p.free = append(p.free, ptFreePage{page: page, gpa: gpa})
	p.mu.Unlock()
}

// release unmaps and frees every slab. The caller guarantees that no virtual
// processor runs.
func (p *ptPool) release() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	var errs []error
	for _, s := range p.slabs {
		if err := p.be.unmapGPA(s.gpa, ptSlabSize); err != nil {
			errs = append(errs, fmt.Errorf("whpx: unmap page-table slab %#x: %w", s.gpa, err))
			continue
		}
		if err := p.be.freeHost(s.mem); err != nil {
			errs = append(errs, err)
		}
	}
	p.slabs = nil
	p.free = nil
	return errors.Join(errs...)
}

type ptAllocator = hvcommon.PTAllocator

func newPTAllocator(pool *ptPool) *ptAllocator {
	return hvcommon.NewPTAllocator(pool)
}

const ptSplitReserve = hvcommon.SplitReserve

func ptReserveForRuns(runs []gpaRun) int {
	return hvcommon.ReserveForRuns(runs)
}

func userPageOpts(at hostarch.AccessType) pagetables.MapOpts {
	return pagetables.MapOpts{AccessType: at, User: true}
}
