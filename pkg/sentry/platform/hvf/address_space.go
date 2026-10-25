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
	"sync"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

var errNoAddressSpace = errors.New("hvf: the memory manager has no hvf address space")

// AddressSpace implements platform.AddressSpace. Stage-1 maps 4KB pages with
// exact permissions over whole contiguous host ranges. Stage-2 regions stay
// mapped after Unmap, so MapFile and Unmap change only Stage-1 tables.
//
// The guest reaches only the memory that a Stage-1 descriptor names. Unmap and
// each replacement of a mapping stop every vCPU that can hold the old
// translation before they return. The Sentry reuses the memory after that.
type AddressSpace struct {
	platform.NoAddressSpaceIO

	vm *vmState
	pt *stage1Tables

	mu sync.Mutex
	// regions are the Stage-2 regions that this address space may map. Release
	// drops them after no vCPU can run the page tables.
	regions  regionUser
	released bool
}

func newAddressSpace(vm *vmState) (*AddressSpace, error) {
	if err := vm.retain(); err != nil {
		return nil, err
	}
	pt, err := newStage1Tables(vm, vm.kernelTables())
	if err != nil {
		vm.release()
		return nil, err
	}
	return &AddressSpace{vm: vm, pt: pt}, nil
}

// settle stops every vCPU that can hold a stale translation of this address
// space. Then it recycles the table pages that the last change freed, because
// no vCPU can walk them any more.
func (as *AddressSpace) settle() {
	as.vm.quiesce(as.pt)
	as.pt.recycle()
}

// MapFile implements platform.AddressSpace.MapFile. It replaces existing
// mappings in the range.
func (as *AddressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, _ bool) error {
	length := fr.Length()
	end := uint64(addr) + length
	if uint64(addr)&pageMask4K != 0 || fr.Start&pageMask4K != 0 || fr.End&pageMask4K != 0 || length == 0 || !at.Any() ||
		end < uint64(addr) || end > maxUserAddress {
		return platform.SegmentationFault{Addr: addr}
	}
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true, Write: at.Write})
	if err != nil {
		return err
	}
	if bs.NumBytes() != length {
		return platform.SegmentationFault{Addr: addr}
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return platform.SegmentationFault{Addr: addr}
	}
	segs, err := as.vm.resolveMemory(&as.regions, f, bs, at.Write)
	if err != nil {
		return err
	}
	invalidated := false
	// A replaced mapping can leave a stale translation in a running vCPU. The
	// caller can reuse the old memory when MapFile returns, so MapFile waits
	// for those vCPUs even when it fails after a partial change.
	defer func() {
		if invalidated {
			as.settle()
		}
	}()
	va := uint64(addr)
	for _, s := range segs {
		inv, err := as.pt.mapRange(va, s.GPA, s.Size, at)
		invalidated = invalidated || inv
		if err != nil {
			return err
		}
		va += s.Size
	}
	return nil
}

// Unmap implements platform.AddressSpace.Unmap. It returns after no vCPU can
// translate an address in the range.
func (as *AddressSpace) Unmap(addr hostarch.Addr, length uint64) {
	as.mu.Lock()
	defer as.mu.Unlock()
	start := uint64(addr) &^ pageMask4K
	end := (uint64(addr) + length + pageMask4K) &^ pageMask4K
	if end < start || end > maxUserAddress {
		end = maxUserAddress
	}
	if start >= end {
		return
	}
	if as.pt.unmapRange(start, end-start) {
		as.settle()
	}
}

// Release implements platform.AddressSpace.Release. It frees the page tables
// and drops every Stage-2 region reference.
func (as *AddressSpace) Release() {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return
	}
	as.released = true
	as.mu.Unlock()

	as.vm.retire(as.pt)
	as.vm.releaseMemory(&as.regions)
	as.vm.release()
}

// PreFork implements platform.AddressSpace.PreFork.
func (*AddressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*AddressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS.
func (*AddressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error {
	return nil
}
