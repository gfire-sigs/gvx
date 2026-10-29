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

//go:build darwin

package hvf

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"z.gfire.dev/gvx/pkg/ring0/pagetables"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

const (
	hostPageMask     = hostPageSize - 1
	slabPagesPerHost = hostPageSize / pageSize4K

	// Guest physical layout. Slab blocks hold page tables, the vector page and
	// CommPages. Host blocks alias Sentry memory. Both ranges must fit in the
	// IPA size of the VM, which is 36 bits by default on Apple silicon.
	slabBaseIPA uint64 = 0x1_0000_0000
	hostBaseIPA uint64 = 0x2_0000_0000
)

type slabPage struct {
	page []byte
	ipa  uint64
}

// slabBlock is one 16KB anonymous host mapping that Stage-2 maps at ipa.
type slabBlock struct {
	mem []byte
	ipa uint64
}

// vmState owns one Hypervisor.framework VM from hv_vm_create to hv_vm_destroy.
type vmState struct {
	maxIPA uint64 // Exclusive upper bound of the guest physical address space.

	mu     sync.Mutex
	closed bool

	// Slab allocator for 4KB table pages.
	slabs       []slabBlock
	slabCur     []byte
	slabCurIPA  uint64
	slabUsed    int
	nextSlabIPA uint64
	freePages   []slabPage
	pagesInUse  int

	// Stage-2 regions of Sentry memory and private copies.
	stage2  stage2Backend
	regions *regionMap

	kernel kernelMap // Process-wide TTBR1 tables and vector page.
	pool   workerPool

	// users counts address spaces that still use slab memory. The slab memory
	// stays mapped until the last user releases it, even after Close.
	users     int
	destroyed bool
}

var vmGlobal struct {
	sync.Mutex
	vm       *vmState
	refs     int
	deathErr error // Set when a previous hv_vm_destroy failed.
}

// acquireVM returns the shared VM, creating it on first use.
func acquireVM() (*vmState, error) {
	vmGlobal.Lock()
	defer vmGlobal.Unlock()
	if vmGlobal.deathErr != nil {
		return nil, fmt.Errorf("hvf: previous VM could not be destroyed: %w", vmGlobal.deathErr)
	}
	if vmGlobal.vm == nil {
		if err := createVMWithEntitlement(); err != nil {
			return nil, err
		}
		v, err := newVMState()
		if err != nil {
			return nil, errors.Join(err, hvVMDestroy())
		}
		vmGlobal.vm = v
	}
	vmGlobal.refs++
	return vmGlobal.vm, nil
}

// releaseVM drops one Platform reference and destroys the VM with the last.
func releaseVM(v *vmState) error {
	vmGlobal.Lock()
	defer vmGlobal.Unlock()
	vmGlobal.refs--
	if vmGlobal.refs > 0 {
		return nil
	}
	vmGlobal.vm = nil
	if err := v.shutdown(); err != nil {
		vmGlobal.deathErr = err
		return err
	}
	return nil
}

func newVMState() (*vmState, error) {
	bits, err := hvDefaultIPABits()
	if err != nil {
		return nil, err
	}
	maxVCPUs, err := hvVMMaxVCPUs()
	if err != nil {
		return nil, err
	}
	return newVMStateOn(hvBackend{}, bits, maxVCPUs)
}

// newVMStateOn builds the VM state over a backend. Tests pass a backend that
// counts calls instead of calling the hypervisor.
func newVMStateOn(be stage2Backend, bits uint, maxVCPUs int) (*vmState, error) {
	v := &vmState{
		maxIPA:      1 << bits,
		nextSlabIPA: slabBaseIPA,
		stage2:      be,
	}
	if hostBaseIPA >= v.maxIPA {
		return nil, fmt.Errorf("hvf: guest physical address space of %d bits is too small", bits)
	}
	v.regions = newRegionMap(be, hostPageSize, hostBaseIPA, v.maxIPA)
	slots := min(maxVCPUs, kernelCommPages)
	if slots < 1 {
		return nil, fmt.Errorf("hvf: the VM allows %d vCPUs", maxVCPUs)
	}
	if err := v.initKernel(slots); err != nil {
		v.releaseSlabs()
		return nil, err
	}
	v.pool.init(v, slots)
	return v, nil
}

// shutdown stops every vCPU thread and destroys the VM. hv_vm_destroy removes
// every Stage-2 mapping, so no per-region unmap is needed. Address spaces that
// outlive the Platform keep their slab memory until they release it.
func (v *vmState) shutdown() error {
	v.mu.Lock()
	v.closed = true
	v.mu.Unlock()
	v.regions.markClosed()

	err := v.pool.stop()
	if err != nil {
		return err
	}
	if err := hvVMDestroy(); err != nil {
		return err
	}
	v.regions.freeAfterDestroy()
	v.mu.Lock()
	v.destroyed = true
	if v.users == 0 {
		v.releaseSlabsLocked()
	}
	v.mu.Unlock()
	return nil
}

// kernelTables returns the read-only tree of the shared kernel mappings. Every
// user tree shares it.
func (v *vmState) kernelTables() *pagetables.PageTables {
	return v.kernel.pt
}

// retain registers an address space that uses slab memory.
func (v *vmState) retain() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return errPlatformClosed
	}
	v.users++
	return nil
}

// release unregisters an address space and frees the slab memory when the VM
// is already destroyed and no user remains.
func (v *vmState) release() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.users--
	if v.users == 0 && v.destroyed {
		v.releaseSlabsLocked()
	}
}

func (v *vmState) releaseSlabs() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.releaseSlabsLocked()
}

func (v *vmState) releaseSlabsLocked() {
	for _, s := range v.slabs {
		if err := unix.Munmap(s.mem); err != nil {
			panic(fmt.Sprintf("hvf: munmap slab: %v", err))
		}
	}
	v.slabs = nil
	v.slabCur = nil
	v.freePages = nil
}

// AllocPage implements pageAllocator.
func (v *vmState) AllocPage() ([]byte, uint64, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil, 0, errPlatformClosed
	}
	if n := len(v.freePages); n > 0 {
		p := v.freePages[n-1]
		v.freePages = v.freePages[:n-1]
		clear(p.page)
		v.pagesInUse++
		return p.page, p.ipa, nil
	}
	if v.slabCur == nil || v.slabUsed == slabPagesPerHost {
		if err := v.newSlabLocked(); err != nil {
			return nil, 0, err
		}
	}
	off := v.slabUsed * pageSize4K
	v.slabUsed++
	v.pagesInUse++
	return v.slabCur[off : off+pageSize4K : off+pageSize4K], v.slabCurIPA + uint64(off), nil
}

// newSlabLocked maps one more 16KB slab block into Stage-2.
func (v *vmState) newSlabLocked() error {
	if v.nextSlabIPA+hostPageSize > hostBaseIPA {
		return errors.New("hvf: slab guest physical range exhausted")
	}
	mem, err := unix.Mmap(-1, 0, hostPageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
	if err != nil {
		return fmt.Errorf("hvf: allocate slab block: %w", err)
	}
	ipa := v.nextSlabIPA
	if err := v.stage2.mapHost(uintptr(unsafe.Pointer(unsafe.SliceData(mem))), ipa, hostPageSize); err != nil {
		return errors.Join(err, unix.Munmap(mem))
	}
	v.nextSlabIPA += hostPageSize
	v.slabs = append(v.slabs, slabBlock{mem: mem, ipa: ipa})
	v.slabCur = mem
	v.slabCurIPA = ipa
	v.slabUsed = 0
	return nil
}

// FreePage implements pageAllocator.
func (v *vmState) FreePage(page []byte, ipa uint64) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.pagesInUse--
	if v.destroyed {
		return
	}
	v.freePages = append(v.freePages, slabPage{page: page, ipa: ipa})
}

// slabStats reports slab usage for leak tests.
type slabStats struct {
	blocks     int // 16KB slab blocks ever mapped.
	pagesInUse int // 4KB pages handed out and not freed.
}

func (v *vmState) slabStats() slabStats {
	v.mu.Lock()
	defer v.mu.Unlock()
	return slabStats{blocks: len(v.slabs), pagesInUse: v.pagesInUse}
}

// resolveMemory returns the guest physical runs of the host blocks of bs and
// records the regions in u. See regionMap.resolve.
func (v *vmState) resolveMemory(u *regionUser, f memmap.File, bs safemem.BlockSeq, write bool) ([]segment, error) {
	return v.regions.resolve(u, f, bs, write)
}

// releaseMemory drops the region references of an address space after no vCPU
// can run its page tables.
func (v *vmState) releaseMemory(u *regionUser) {
	v.regions.release(u)
}

// hvBackend is the stage2Backend of a real VM.
type hvBackend struct{}

func (hvBackend) mapHost(host uintptr, ipa uint64, size uintptr) error {
	return hvVMMap(host, ipa, size, hvMemoryRead|hvMemoryWrite|hvMemoryExec)
}

func (hvBackend) unmapIPA(ipa uint64, size uintptr) error {
	return hvVMUnmap(ipa, size)
}

// refusedMemory reports the code that Hypervisor.framework returns for every
// memory region whose backing file was opened read-only. hv_vm_map returns
// HV_ERROR for RWX, RX and R requests alike (probe on macOS 26: anonymous,
// shared and private mappings of a read-write descriptor map, and a MAP_SHARED
// PROT_READ mapping of an O_RDONLY descriptor does not). The EROFS layer
// images take this path: the Sentry maps each image through a read-only
// descriptor, and every guest file page (ELF text, libraries, read-only data)
// arrives here. A missing entitlement returns the same code.
func (hvBackend) refusedMemory(err error) bool {
	code, ok := hvCode(err)
	return ok && code == hvErrGeneral
}

func (hvBackend) allocCopy(size uintptr) ([]byte, error) {
	return unix.Mmap(-1, 0, int(size), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
}

func (hvBackend) freeCopy(mem []byte) error {
	return unix.Munmap(mem)
}
