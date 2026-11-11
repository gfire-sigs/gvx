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

	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
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

type whpxStage2Backend struct {
	be backend
}

func (w whpxStage2Backend) MapHost(host uintptr, gpa uint64, size uintptr, writable bool) error {
	return w.be.mapGPA(host, gpa, uint64(size), partitionFlags(writable))
}

func (w whpxStage2Backend) UnmapGPA(gpa uint64, size uintptr) error {
	return w.be.unmapGPA(gpa, uint64(size))
}

func (whpxStage2Backend) RefusedMemory(error) bool          { return false }
func (whpxStage2Backend) AllocCopy(uintptr) ([]byte, error) { return nil, errGPAExhausted }
func (whpxStage2Backend) FreeCopy([]byte) error             { return nil }

// rawHostFile owns test mappings installed through AddressSpace.mapHost.
type rawHostFile struct {
	memmap.File
}

func (*rawHostFile) TotalSize() uint64 { return 0 }

// memoryMap owns Stage-2 GPA mappings for a WHPX partition via hvcommon.RegionMap.
type memoryMap struct {
	inner   *hvcommon.RegionMap
	rawFile *rawHostFile
}

func newMemoryMap(be backend, base, end uint64) *memoryMap {
	return &memoryMap{
		inner: hvcommon.NewRegionMap(whpxStage2Backend{be: be}, hvcommon.RegionMapConfig{
			Granule:          pageSize,
			Base:             base,
			Limit:            end,
			SeparateReadOnly: true,
			LogPrefix:        "whpx",
			ErrClosed:        errClosed,
			ErrExhausted:     errGPAExhausted,
		}),
		rawFile: &rawHostFile{},
	}
}

func (m *memoryMap) resolveRaw(u *hvcommon.RegionUser, data []byte, write bool) ([]gpaRun, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("whpx: empty host memory slice")
	}
	block := hvcommon.HostBlock{
		Addr:  uintptr(unsafe.Pointer(unsafe.SliceData(data))),
		Len:   uintptr(len(data)),
		Slice: data,
	}
	return m.inner.ResolveBlocks(u, m.rawFile, []hvcommon.HostBlock{block}, write)
}

func (m *memoryMap) resolvePinned(u *hvcommon.RegionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]gpaRun, error) {
	return m.inner.ResolvePinned(u, f, bs, write)
}

func (m *memoryMap) resolvePinnedBlocks(u *hvcommon.RegionUser, f memmap.File, blocks []hvcommon.HostBlock, write bool) ([]gpaRun, error) {
	return m.inner.ResolvePinnedBlocks(u, f, blocks, write)
}

func (m *memoryMap) finishPin(runs []gpaRun, acquired, dropped []*hvcommon.Region) {
	m.inner.FinishPin(runs, acquired, dropped)
}

func (m *memoryMap) releaseRegions(dropped []*hvcommon.Region) {
	m.inner.ReleaseRegions(dropped)
}

func (m *memoryMap) release(u *hvcommon.RegionUser) {
	m.inner.Release(u)
}

func (m *memoryMap) close() error {
	return m.inner.Close()
}
