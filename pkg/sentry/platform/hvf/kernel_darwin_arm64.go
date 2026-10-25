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
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
)

// The EL1-only mappings (the exception vector page and one CommPage per vCPU)
// live in one process-wide Stage-1 tree installed through TTBR1_EL1. The tree
// is complete before the first vCPU exists and no code changes or frees it
// until the VM ends.
//
// WHY TTBR1: an exception from EL0 runs the vector stub before the stub can
// flush the TLB. If the stub translated its own addresses through the user
// tree (TTBR0_EL1), a released address space could leave stale cached walk
// entries that point at table pages the allocator has since reused. The
// hardware would then fault or, worse, translate through another address
// space's table. The kernel tree is the same for every vCPU and never
// changes, so cached entries for it are always valid. User tables can be
// freed and reused without any leak or any ordering constraint.
const (
	// kernelBaseVA is the first address of the TTBR1 range used by the stub.
	kernelBaseVA uint64 = 0xffff_ff00_0000_0000
	// kernelVectorVA is the VBAR_EL1 value.
	kernelVectorVA = kernelBaseVA
	// kernelCommBaseVA is the address of the CommPage of vCPU 0.
	kernelCommBaseVA = kernelBaseVA + 0x10000
	// kernelCommStride leaves one unmapped guard page after every CommPage.
	kernelCommStride = 2 * pageSize4K
	// kernelCommPages is the CommPage count: one page per possible vCPU.
	kernelCommPages = 64
)

// kernelComm is the CommPage of one vCPU slot.
type kernelComm struct {
	page []byte
	view *CommPage
	ipa  uint64
	va   uint64
}

// kernelMap is the immutable TTBR1 mapping set.
type kernelMap struct {
	pt    *pagetables.PageTables
	alloc *tableAlloc
	comm  []kernelComm
}

// kernelPageKind selects the permissions of a TTBR1 page.
type kernelPageKind int

const (
	// kernelCode is EL1 read-only and executable, and EL0 has no access.
	kernelCode kernelPageKind = iota
	// kernelData is EL1 read-write and never executable.
	kernelData
)

// ttbr1 returns the TTBR1_EL1 value.
func (k *kernelMap) ttbr1() uint64 {
	return k.pt.TTBR1_EL1(false, 0)
}

// initKernel builds the TTBR1 tree with one CommPage per vCPU slot. It runs
// before the VM state is visible to other goroutines.
func (v *vmState) initKernel(slots int) error {
	initPageTables()
	alloc := newTableAlloc(v)
	if err := alloc.Reserve(kernelTablePages); err != nil {
		alloc.Drain()
		return err
	}
	k := &v.kernel
	k.alloc = alloc
	k.pt = pagetables.New(alloc)
	k.comm = make([]kernelComm, slots)

	vecPage, vecIPA, err := v.AllocPage()
	if err != nil {
		return err
	}
	copy(vecPage, buildVectorPage())
	k.mapPage(kernelVectorVA, vecIPA, kernelCode)
	for i := range k.comm {
		page, ipa, err := v.AllocPage()
		if err != nil {
			return err
		}
		va := kernelCommBaseVA + uint64(i)*kernelCommStride
		k.mapPage(va, ipa, kernelData)
		k.comm[i] = kernelComm{
			page: page,
			view: (*CommPage)(unsafe.Pointer(unsafe.SliceData(page))),
			ipa:  ipa,
			va:   va,
		}
	}
	k.pt.MarkReadOnlyShared()
	return nil
}

// mapPage maps one global EL1-only page. The nG bit stays clear, so the entry
// applies to every address space.
func (k *kernelMap) mapPage(va, ipa uint64, kind kernelPageKind) {
	at := hostarch.ReadWrite
	if kind == kernelCode {
		at = hostarch.AccessType{Read: true, Execute: true}
	}
	k.pt.Map(hostarch.Addr(va), pageSize4K, pagetables.MapOpts{AccessType: at, Global: true}, uintptr(ipa))
}
