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
	"unsafe"

	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/sentry/platform/hvcommon"
)

// kernelRegion is the guest memory that every address space shares: the stub
// code, the amd64 descriptor tables and one CommPage per virtual processor.
//
// Its page tables are the shared upper half of every address space. The
// pages are supervisor-only, so applications cannot read or change them.
type kernelRegion struct {
	layout kernelLayout

	x64 *x64Stubs
	a64 *a64Stubs

	// codeMem holds the code page and the GDT/IDT page.
	codeMem []byte
	codeGPA uint64
	sysGPA  uint64

	// commMem holds the CommPage of each virtual processor slot.
	commMem []byte
	commGPA uint64
	slots   int

	alloc *ptAllocator
	pt    *pagetables.PageTables
}

// kernelPageCount is the number of page-table pages that mapping the kernel
// region can allocate at most.
const kernelPageCount = hvcommon.KernelTablePages

// buildKernelRegion creates the shared kernel mappings for slots virtual
// processors.
func buildKernelRegion(be backend, gpa *gpaAllocator, pool *ptPool, arm64 bool, slots int) (kr *kernelRegion, err error) {
	kr = &kernelRegion{layout: newKernelLayout(arm64), slots: slots}
	defer func() {
		if err != nil {
			err = errors.Join(err, kr.release(be, gpa))
			kr = nil
		}
	}()

	if arm64 {
		kr.a64, err = buildA64Stubs()
	} else {
		kr.x64, err = buildX64Stubs(kr.layout.base)
	}
	if err != nil {
		return kr, err
	}

	kr.codeMem, err = be.allocHost(ptSlabSize)
	if err != nil {
		return kr, fmt.Errorf("whpx: allocate stub memory: %w", err)
	}
	commBytes := (uintptr(slots)*pageSize + ptSlabSize - 1) &^ (ptSlabSize - 1)
	kr.commMem, err = be.allocHost(commBytes)
	if err != nil {
		return kr, fmt.Errorf("whpx: allocate CommPage memory: %w", err)
	}

	codePage := kr.codeMem[:pageSize]
	sysPage := kr.codeMem[pageSize : 2*pageSize]
	if arm64 {
		copy(codePage, kr.a64.Code)
	} else {
		copy(codePage, kr.x64.Code)
		copy(sysPage, kr.x64.Sys)
	}
	for i := range slots {
		page := overlayCommPage(kr.commMem[i*pageSize : (i+1)*pageSize])
		commVA := kr.layout.comm(i)
		// The amd64 stub switches to this kernel stack, and the amd64
		// exception path pushes onto it. The arm64 stub uses SP_EL1, which
		// the Sentry sets to the CommPage address.
		if !arm64 {
			page.Regs[4] = commVA + commStackTop
			x64InitTSS(page, commVA)
		}
	}

	if kr.codeGPA, err = gpa.allocPage(); err != nil {
		return kr, err
	}
	if err = be.mapGPA(unsafe.Pointer(&codePage[0]), kr.codeGPA, pageSize, mapFlagRead|mapFlagExecute); err != nil {
		return kr, fmt.Errorf("whpx: map stub code page: %w", err)
	}
	if !arm64 {
		if kr.sysGPA, err = gpa.allocPage(); err != nil {
			return kr, err
		}
		if err = be.mapGPA(unsafe.Pointer(&sysPage[0]), kr.sysGPA, pageSize, mapFlagRead); err != nil {
			return kr, fmt.Errorf("whpx: map descriptor table page: %w", err)
		}
	}
	if kr.commGPA, err = gpa.allocRun(slots); err != nil {
		return kr, err
	}
	if err = be.mapGPA(unsafe.Pointer(&kr.commMem[0]), kr.commGPA, uint64(slots)*pageSize, mapFlagRead|mapFlagWrite); err != nil {
		return kr, fmt.Errorf("whpx: map CommPages: %w", err)
	}

	kr.alloc = newPTAllocator(pool)
	if err = kr.alloc.Reserve(kernelPageCount); err != nil {
		return kr, err
	}
	kr.pt = pagetables.New(kr.alloc)
	kernel := func(at hostarch.AccessType) pagetables.MapOpts {
		return pagetables.MapOpts{AccessType: at, Global: true}
	}
	kr.pt.Map(hostarch.Addr(kr.layout.code()), pageSize, kernel(hostarch.AccessType{Read: true, Execute: true}), uintptr(kr.codeGPA))
	if !arm64 {
		kr.pt.Map(hostarch.Addr(kr.layout.sys()), pageSize, kernel(hostarch.Read), uintptr(kr.sysGPA))
	}
	kr.pt.Map(hostarch.Addr(kr.layout.comm(0)), uintptr(slots)*pageSize, kernel(hostarch.ReadWrite), uintptr(kr.commGPA))
	kr.pt.MarkReadOnlyShared()
	return kr, nil
}

// commPage returns the host view of the CommPage of a slot.
func (kr *kernelRegion) commPage(slot int) *CommPage {
	return overlayCommPage(kr.commMem[slot*pageSize : (slot+1)*pageSize])
}

// release unmaps and frees the kernel memory. Callers stop every virtual
// processor first.
func (kr *kernelRegion) release(be backend, gpa *gpaAllocator) error {
	var errs []error
	unmap := func(at uint64, size uint64) {
		if at == 0 {
			return
		}
		if err := be.unmapGPA(at, size); err != nil {
			errs = append(errs, fmt.Errorf("whpx: unmap kernel page %#x: %w", at, err))
		}
	}
	unmap(kr.codeGPA, pageSize)
	unmap(kr.sysGPA, pageSize)
	if kr.slots > 0 {
		unmap(kr.commGPA, uint64(kr.slots)*pageSize)
	}
	if kr.alloc != nil {
		kr.alloc.Drain()
	}
	for _, mem := range [][]byte{kr.codeMem, kr.commMem} {
		if mem != nil {
			if err := be.freeHost(mem); err != nil {
				errs = append(errs, err)
			}
		}
	}
	kr.codeMem, kr.commMem = nil, nil
	return errors.Join(errs...)
}
