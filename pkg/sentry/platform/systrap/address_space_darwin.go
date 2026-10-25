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

//go:build darwin && arm64

package systrap

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// islandReach is the largest distance between a patched instruction and the
// island that holds its slot. A B instruction reaches 128MiB, and the margin
// covers the island size and the slot's own branch back.
const islandReach = 120 << 20

// blockState says which mapping of a guest block the stub currently sees.
type blockState uint8

const (
	// blockData maps the original frame without execute permission.
	blockData blockState = iota
	// blockExec maps a patched private copy as read and execute.
	blockExec
)

// execBlock is one host page of a guest mapping that allows execution.
//
// WHY: the original frame can be shared between address spaces and mapped at
// different addresses, and the patch encodes addresses. So the stub never
// executes the original frame. A first fetch faults, the Sentry patches a
// private copy and the stub sees the copy instead. A block that also allows
// writes alternates between the writable original and the executable copy, so
// code that a guest writes is always patched before it runs.
type execBlock struct {
	base  uint64
	src   uint64
	at    hostarch.AccessType
	state blockState
	priv  uint64
	slots []slotRef
}

// slotRef identifies one allocated range inside a trampoline island.
type slotRef struct {
	isl  *island
	off  uint32
	size uint32
}

// slotUnit is the allocation granularity of an island in bytes, and
// islandUnits is the number of units in one island page.
const (
	slotUnit    = 8
	islandUnits = blockSize / slotUnit
)

// patchItem is one instruction that the patcher replaces. x18 is set for the
// instructions that name x18.
type patchItem struct {
	patchSite
	x18 *x18Plan
}

// slotMeta describes one slot of an island.
type slotMeta struct {
	site uint64
	kind siteKind
	// reg is the register operand of an MRS or MSR site. A jump slot stores 1
	// in it for blr.
	reg uint8
	// size is the byte size of the slot.
	size uint32
	// body counts the words of the guest instruction in an x18 slot.
	body uint8
	// scratch is the register that an x18 slot borrows.
	scratch uint8
}

// island is one host page of trampoline slots in the guest address space.
type island struct {
	base     uint64
	page     uint64
	usedBits [islandUnits / 64]uint64
	slots    map[uint32]slotMeta
}

// alloc claims a contiguous range of size bytes in the island and returns its
// byte offset. Callers hold as.mu.
func (isl *island) alloc(size uint32) (uint32, bool) {
	need := (size + slotUnit - 1) / slotUnit
	if need == 0 || need > islandUnits {
		return 0, false
	}
	var run, start uint32
	for u := uint32(0); u < islandUnits; u++ {
		if isl.usedBits[u/64]&(uint64(1)<<(u%64)) != 0 {
			run = 0
			continue
		}
		if run == 0 {
			start = u
		}
		run++
		if run == need {
			for k := start; k < start+need; k++ {
				isl.usedBits[k/64] |= uint64(1) << (k % 64)
			}
			return start * slotUnit, true
		}
	}
	return 0, false
}

// free releases a slot range that alloc claimed. Callers hold as.mu.
func (isl *island) free(off, size uint32) {
	delete(isl.slots, off)
	start := off / slotUnit
	need := (size + slotUnit - 1) / slotUnit
	for k := start; k < start+need && k < islandUnits; k++ {
		isl.usedBits[k/64] &^= uint64(1) << (k % 64)
	}
}

// addressSpace is one stub task and the guest mappings in it.
type addressSpace struct {
	platform.NoAddressSpaceIO

	p    *Platform
	proc *stubProc

	// patchMu serializes patching. Two threads that fault on the same block
	// then patch it once, and no sites get duplicate slots.
	patchMu sync.Mutex

	mu       sync.Mutex
	released bool
	blocks   map[uint64]*execBlock
	islands  map[uint64]*island
	// zoneMapped holds the stub address of every block that the guest maps in
	// the zone. It is empty outside the zone mode.
	zoneMapped map[uint64]struct{}
	// zoneImageDone records that the first block of the zone prepared the
	// image, and goText bounds the code of a Go image as guest addresses.
	zoneImageDone bool
	goText        [2]uint64
	// reserved holds island addresses that a pending mm.MMap call creates.
	reserved map[uint64]struct{}
	threads  map[*thread]struct{}
	freeIdx  []int
	nextIdx  int

	// dead mirrors proc.dead for lock-free reads.
	dead atomic.Bool

	// selfStoreLogged records that logSelfStore ran.
	selfStoreLogged atomic.Bool

	// patchedBlocks counts blocks that the Sentry patched.
	patchedBlocks atomic.Uint64
}

// PatchedBlocks returns how many code blocks this address space patched.
func (as *addressSpace) PatchedBlocks() uint64 { return as.patchedBlocks.Load() }

var (
	errAddressSpaceReleased = errors.New("the address space is released")
	errDeadStub             = errors.New("the stub task died")
)

// AlignmentError reports a mapping request that the 16KB host page cannot honor.
type AlignmentError struct {
	Op   string
	Addr uint64
	Len  uint64
}

// Error implements error.
func (e *AlignmentError) Error() string {
	return fmt.Sprintf("%s [%#x, %#x) is not aligned to the %dKB host page", e.Op, e.Addr, e.Addr+e.Len, blockSize/1024)
}

func newAddressSpace(p *Platform) (*addressSpace, error) {
	proc, err := p.host.forkProc()
	if err != nil {
		return nil, fmt.Errorf("create a stub task: %w", err)
	}
	as := &addressSpace{
		p:          p,
		proc:       proc,
		blocks:     make(map[uint64]*execBlock),
		islands:    make(map[uint64]*island),
		zoneMapped: make(map[uint64]struct{}),
		reserved:   make(map[uint64]struct{}),
		threads:    make(map[*thread]struct{}),
	}
	wake := as.wakeAll
	proc.onDead.Store(&wake)
	if proc.dead.Load() {
		as.wakeAll()
	}
	return as, nil
}

// wakeAll wakes every waiter of every thread so that it notices the death.
func (as *addressSpace) wakeAll() {
	as.dead.Store(true)
	as.mu.Lock()
	defer as.mu.Unlock()
	for th := range as.threads {
		ulockWakeAll(&th.sm.State)
	}
}

func blockRound(n uint64) uint64 { return n &^ (blockSize - 1) }

func checkAligned(op string, addr, length uint64) error {
	if length == 0 || addr%blockSize != 0 || length%blockSize != 0 {
		return &AlignmentError{Op: op, Addr: addr, Len: length}
	}
	return nil
}

// stubProt converts guest access to a Mach protection that never includes execute.
func stubProt(at hostarch.AccessType) int {
	prot := vmProtRead
	if at.Write {
		prot |= vmProtWrite
	}
	return prot
}

// mapPages maps size bytes at the Sentry address src into the stub at addr.
// It lowers the maximum protection first, so the guest cannot raise it with a
// raw Mach trap even if the sandbox profile were to allow one.
func (as *addressSpace) mapPages(addr, size, src uint64, prot int) error {
	if err := vmRemap(as.proc.task, addr, size, as.p.host.self, src); err != nil {
		return as.taskErr(err)
	}
	if err := vmProtect(as.proc.task, addr, size, true, prot); err != nil {
		_ = vmDeallocate(as.proc.task, addr, size)
		return as.taskErr(err)
	}
	if err := vmProtect(as.proc.task, addr, size, false, prot); err != nil {
		_ = vmDeallocate(as.proc.task, addr, size)
		return as.taskErr(err)
	}
	return nil
}

// taskErr maps Mach errors of a dead task to errDeadStub.
func (as *addressSpace) taskErr(err error) error {
	if isDeadTaskError(err) || as.proc.dead.Load() {
		return fmt.Errorf("%w: %v", errDeadStub, err)
	}
	return err
}

// MapFile implements platform.AddressSpace.MapFile.
//
// Every mapping covers whole host pages. The memory file frames must also
// start on a host page boundary, because Mach maps pages and not bytes. A
// build with 16KB guest pages guarantees both. In zone mode a mapping inside
// the zone lands at the guest address plus the bias.
func (as *addressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	guest := uint64(addr)
	if err := checkAligned("map", guest, fr.Length()); err != nil {
		return err
	}
	if as.p.zone && guest < zoneLimit && (guest < zoneMin || guest+fr.Length() > zoneLimit) {
		return fmt.Errorf("map [%#x, %#x) crosses the edge of the zone [%#x, %#x)", guest, guest+fr.Length(), uint64(zoneMin), uint64(zoneLimit))
	}
	if as.dead.Load() {
		return errDeadStub
	}
	bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true, Write: at.Write})
	if err != nil {
		return fmt.Errorf("map the memory file range %v for the stub: %w", fr, err)
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return errAddressSpaceReleased
	}
	va := as.p.stubAddr(guest)
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		b := bs.Head()
		src, n := uint64(uintptr(b.Addr())), uint64(b.Len())
		if src%blockSize != 0 || n%blockSize != 0 {
			return &AlignmentError{Op: "map memory file range", Addr: src, Len: n}
		}
		if err := as.mapRangeLocked(va, n, src, at); err != nil {
			return err
		}
		va += n
	}
	return nil
}

// mapRangeLocked installs [va, va+n) from the Sentry address src.
//
// An island lives in a sealed VMA that the memory manager populates like any
// other mapping. The island keeps its own private page, so the frame of the VMA
// stays unused and the range skips the block of every island, including an
// island that the memory manager still populates. The memory manager can hand
// over a range that spans an island when it maps a whole map unit of one
// pma. The sealed VMA protects the island, so no mapping can replace it.
func (as *addressSpace) mapRangeLocked(va, n, src uint64, at hostarch.AccessType) error {
	runStart := va
	for base := va; base < va+n; base += blockSize {
		if !as.isIslandBlockLocked(base) {
			continue
		}
		if err := as.mapRunLocked(runStart, base-runStart, src+(runStart-va), at); err != nil {
			return err
		}
		runStart = base + blockSize
	}
	return as.mapRunLocked(runStart, va+n-runStart, src+(runStart-va), at)
}

// isIslandBlockLocked reports whether the block at base holds an island or
// will hold one when the pending mapping of its VMA completes.
func (as *addressSpace) isIslandBlockLocked(base uint64) bool {
	if _, pending := as.reserved[base]; pending {
		return true
	}
	_, ok := as.islands[base]
	return ok
}

// mapRunLocked installs [va, va+n), a range without an island, from the Sentry
// address src.
func (as *addressSpace) mapRunLocked(va, n, src uint64, at hostarch.AccessType) error {
	if n == 0 {
		return nil
	}
	if err := as.mapPages(va, n, src, stubProt(at)); err != nil {
		return fmt.Errorf("map [%#x, %#x): %w", va, va+n, err)
	}
	for base := va; base < va+n; base += blockSize {
		as.dropBlockLocked(base)
		if inZoneStub(base) {
			as.zoneMapped[base] = struct{}{}
		}
		if at.Execute {
			as.blocks[base] = &execBlock{base: base, src: src + (base - va), at: at, state: blockData}
		}
	}
	return nil
}

// dropBlockLocked forgets the exec state of one block and frees its copy.
func (as *addressSpace) dropBlockLocked(base uint64) {
	if blk, ok := as.blocks[base]; ok {
		as.freeSlotRefsLocked(blk.slots)
		blk.slots = nil
		if blk.priv != 0 {
			as.p.pool.release(blk.priv)
		}
		delete(as.blocks, base)
	}
}

// freeSlotRefsLocked releases the island slots in refs. Callers hold as.mu.
func (as *addressSpace) freeSlotRefsLocked(refs []slotRef) {
	for _, r := range refs {
		if as.islands[r.isl.base] == r.isl {
			r.isl.free(r.off, r.size)
		}
	}
}

// Unmap implements platform.AddressSpace.Unmap. A range that is not host page
// aligned unmaps whole pages around it, which can only remove more than the
// request and never leaves access that the memory manager revoked.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	guestStart := blockRound(uint64(addr))
	guestEnd := (uint64(addr) + length + blockSize - 1) &^ (blockSize - 1)
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released || as.dead.Load() {
		return
	}
	for _, r := range as.p.stubRanges(guestStart, guestEnd) {
		as.unmapStubLocked(r[0], r[1])
	}
}

// stubRanges splits the guest range [start, end) into the ranges that the stub
// holds. In zone mode the part inside the zone moves by the bias, and the
// hole between the zone and the guest mappings above the biased zone is not
// part of any guest mapping. The biased zone lies in the hole, so a guest
// range that spans the hole must not unmap it as it is.
func (p *Platform) stubRanges(start, end uint64) [][2]uint64 {
	if !p.zone {
		return [][2]uint64{{start, end}}
	}
	var out [][2]uint64
	if start < zoneMin {
		out = append(out, [2]uint64{start, min(end, zoneMin)})
	}
	if lo, hi := max(start, zoneMin), min(end, zoneLimit); lo < hi {
		out = append(out, [2]uint64{lo + zoneBias, hi + zoneBias})
	}
	if above := uint64(zoneBias + zoneLimit); end > above {
		out = append(out, [2]uint64{max(start, above), end})
	}
	return out
}

// unmapStubLocked removes the stub range [start, end).
func (as *addressSpace) unmapStubLocked(start, end uint64) {
	if err := vmDeallocate(as.proc.task, start, end-start); err != nil && !as.proc.dead.Load() {
		// The kernel rejects only a malformed range here, which is a Sentry bug.
		panic(fmt.Sprintf("systrap: unmap [%#x, %#x): %v", start, end, err))
	}
	// The memory manager unmaps whole address spaces when a process exits, so
	// the range can hold far more pages than the address space has blocks.
	if (end-start)/blockSize > uint64(len(as.blocks)) {
		for base := range as.blocks {
			if base >= start && base < end {
				as.dropBlockLocked(base)
			}
		}
	} else {
		for base := start; base < end; base += blockSize {
			as.dropBlockLocked(base)
		}
	}
	for base := range as.zoneMapped {
		if base >= start && base < end {
			delete(as.zoneMapped, base)
		}
	}
	for base, isl := range as.islands {
		if base < end && start < base+blockSize {
			delete(as.islands, base)
			as.p.pool.release(isl.page)
		}
	}
}

// Release implements platform.AddressSpace.Release.
func (as *addressSpace) Release() {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return
	}
	as.released = true
	threads := make([]*thread, 0, len(as.threads))
	for th := range as.threads {
		threads = append(threads, th)
	}
	as.mu.Unlock()

	// Terminating the task stops every thread, so no stub thread touches the
	// pages that go back to the pool below.
	as.p.host.dropProc(as.proc)
	as.dead.Store(true)
	for _, th := range threads {
		ulockWakeAll(&th.sm.State)
		_ = portDeallocate(as.p.host.self, th.port)
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	for base := range as.blocks {
		as.dropBlockLocked(base)
	}
	for base, isl := range as.islands {
		as.p.pool.release(isl.page)
		delete(as.islands, base)
	}
	for th := range as.threads {
		as.p.pool.releaseSpan(th.block, threadSpan/blockSize)
		delete(as.threads, th)
	}
}

// PreFork implements platform.AddressSpace.PreFork.
func (*addressSpace) PreFork() {}

// PostFork implements platform.AddressSpace.PostFork.
func (*addressSpace) PostFork() {}

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. arm64 has no
// GS register.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error { return nil }

// ----- lazy patching ------------------------------------------------------

var errPatchRaced = errors.New("the block changed while it was patched")

// patchBlock patches the block that holds addr and maps the patched copy as
// read and execute. It runs on the task goroutine, which is allowed to call
// into the memory manager.
func (as *addressSpace) patchBlock(ctx context.Context, mm platform.MemoryManager, addr uint64) error {
	as.patchMu.Lock()
	defer as.patchMu.Unlock()
	base := blockRound(addr)
	if as.p.zone && inZoneStub(base) {
		as.prepareZoneImage(ctx, mm, base)
	}
	for attempt := 0; attempt < 4; attempt++ {
		err := as.patchBlockOnce(ctx, mm, base)
		if !errors.Is(err, errPatchRaced) {
			return err
		}
	}
	return errPatchRaced
}

func (as *addressSpace) patchBlockOnce(ctx context.Context, mm platform.MemoryManager, base uint64) error {
	as.mu.Lock()
	blk := as.blocks[base]
	if as.released || blk == nil {
		as.mu.Unlock()
		return errPatchRaced
	}
	if blk.state == blockExec {
		// Another thread patched the block while this one waited for patchMu.
		as.mu.Unlock()
		return nil
	}
	src := blk.src
	as.mu.Unlock()

	// The guest can write the original frame while this copy runs when the
	// block allows writes. The patched copy then holds a torn image, but the
	// guest has no promise about code that it modifies while it executes it.
	copyBuf := make([]byte, blockSize)
	copy(copyBuf, unsafe.Slice((*byte)(addrPtr(src)), blockSize))
	sites := scanARM64(copyBuf)
	items := make([]patchItem, 0, len(sites))
	claimed := make(map[int]struct{}, len(sites))
	for _, s := range sites {
		claimed[int(s.Offset)] = struct{}{}
		it := patchItem{patchSite: s}
		if s.Kind == siteMRS && s.Reg == x18Reg {
			// The slot of `mrs x18, tpidr_el0` writes the virtual x18.
			it.Kind, it.x18 = siteX18, planTPIDRRead()
		}
		if s.Kind == siteCTR && s.Reg == x18Reg {
			// The slot of `mrs x18, ctr_el0` writes the virtual x18.
			it.Kind, it.x18 = siteX18, planCTRRead()
		}
		items = append(items, it)
	}
	gbase := as.p.guestAddr(base)
	scope := as.p.scopeOf(ctx, mm, gbase)
	for _, x := range scanX18(copyBuf, base, func(off int) bool {
		_, taken := claimed[off]
		return taken || !scope.contains(gbase+uint64(off))
	}) {
		items = append(items, patchItem{
			patchSite: patchSite{Offset: x.Offset, Kind: x.Plan.kind, Orig: binary.LittleEndian.Uint32(copyBuf[x.Offset:])},
			x18:       x.Plan,
		})
	}
	touched := make(map[*island]struct{})
	var allocated []slotRef
	freeAllocated := func() {
		as.mu.Lock()
		as.freeSlotRefsLocked(allocated)
		as.mu.Unlock()
	}
	for _, s := range items {
		site := base + uint64(s.Offset)
		if (s.Kind == siteMRS || s.Kind == siteCTR) && s.Reg == 31 {
			// Reading TPIDR_EL0 or CTR_EL0 into XZR discards the value.
			putWord(copyBuf[s.Offset:], arm64NOP)
			continue
		}
		size := slotSizeFor(s.Kind)
		if s.x18 != nil {
			size = s.x18.slotSize()
		}
		isl, off, slotVA, err := as.allocSlot(ctx, mm, site, size)
		if err != nil {
			freeAllocated()
			return fmt.Errorf("allocate a trampoline slot for %#x: %w", site, err)
		}
		allocated = append(allocated, slotRef{isl: isl, off: off, size: uint32(size)})
		buf := pageBytes(isl.page)[off:]
		meta := slotMeta{site: site, kind: s.Kind, reg: s.Reg, size: uint32(size)}
		switch s.Kind {
		case siteMRS:
			err = encodeLoadSlot(buf, slotVA, site+4, s.Reg, tlsOffset)
		case siteCTR:
			err = encodeCTRSlot(buf, slotVA, site+4, s.Reg)
		case siteX18, siteX18Cond:
			meta.body, meta.scratch = uint8(len(s.x18.body)), s.x18.scratch
			err = encodeX18Slot(buf, slotVA, site, s.x18)
		case siteX18Jump:
			if s.x18.link {
				meta.reg = 1
			}
			err = encodeTrapSlot(buf, slotVA, site+4, as.p.host.hello.Spill)
		default:
			err = encodeTrapSlot(buf, slotVA, site+4, as.p.host.hello.Spill)
		}
		if err != nil {
			freeAllocated()
			return fmt.Errorf("encode the slot for %#x: %w", site, err)
		}
		br, err := encodeBranch(site, slotVA)
		if err != nil {
			freeAllocated()
			return err
		}
		putWord(copyBuf[s.Offset:], br)
		as.mu.Lock()
		isl.slots[off] = meta
		as.mu.Unlock()
		touched[isl] = struct{}{}
	}
	if as.p.zone {
		taken := claimed
		for _, it := range items {
			taken[int(it.Offset)] = struct{}{}
		}
		// The scan recognizes instructions by their bit pattern. A data word in
		// a block that also holds code, such as a string at the start of the
		// read-only data, can look like an adr or a br. When the section
		// headers describe the block, the scan skips the words outside the
		// executable sections. A page without usable headers stays whole,
		// because the biased addresses need the slots.
		skip := func(off int) bool {
			if _, t := taken[off]; t {
				return true
			}
			return scope.proven() && !scope.contains(gbase+uint64(off))
		}
		for _, z := range scanZone(copyBuf, base, skip) {
			if z.kind == siteAdrp && as.isGoCode(z.value) {
				// The Go runtime compares a function address with the code range
				// of its module data, and the zone mode biased that range. An
				// adr or adrp that yields a code address keeps the biased value.
				continue
			}
			site := base + uint64(z.offset)
			size := adrpSlotSize
			switch {
			case z.kind == siteIndirect && z.link:
				size = blrSlotSize
			case z.kind == siteIndirect:
				size = brSlotSize
			}
			isl, off, slotVA, err := as.allocSlot(ctx, mm, site, size)
			if err != nil {
				freeAllocated()
				return fmt.Errorf("allocate a zone slot for %#x: %w", site, err)
			}
			allocated = append(allocated, slotRef{isl: isl, off: off, size: uint32(size)})
			buf := pageBytes(isl.page)[off:]
			switch z.kind {
			case siteAdrp:
				err = encodeAdrpSlot(buf, slotVA, site, z.reg, z.value)
			default:
				_, err = encodeIndirectSlot(buf, slotVA, site, z.reg, z.link)
			}
			if err != nil {
				freeAllocated()
				return fmt.Errorf("encode the zone slot for %#x: %w", site, err)
			}
			br, err := encodeBranch(site, slotVA)
			if err != nil {
				freeAllocated()
				return err
			}
			putWord(copyBuf[z.offset:], br)
			as.mu.Lock()
			isl.slots[off] = slotMeta{site: site, kind: z.kind, reg: z.reg, size: uint32(size)}
			as.mu.Unlock()
			touched[isl] = struct{}{}
		}
	}
	for isl := range touched {
		flushCode(pageBytes(isl.page))
	}

	privAddr, err := as.p.pool.alloc()
	if err != nil {
		freeAllocated()
		return err
	}
	priv := pageBytes(privAddr)
	copy(priv, copyBuf)
	flushCode(priv)

	as.mu.Lock()
	defer as.mu.Unlock()
	if cur := as.blocks[base]; as.released || cur != blk || blk.state != blockData || blk.src != src {
		as.freeSlotRefsLocked(allocated)
		as.p.pool.release(privAddr)
		return errPatchRaced
	}
	if err := as.mapPages(base, blockSize, privAddr, vmProtRead|vmProtExecute); err != nil {
		as.freeSlotRefsLocked(allocated)
		as.p.pool.release(privAddr)
		return err
	}
	blk.priv = privAddr
	blk.state = blockExec
	blk.slots = allocated
	as.patchedBlocks.Add(1)
	return nil
}

// restoreData maps the original frame of a block again, so that a guest write
// to a writable and executable block succeeds. The next fetch patches again.
func (as *addressSpace) restoreData(base uint64) (bool, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[base]
	if as.released || blk == nil || blk.state != blockExec || !blk.at.Write {
		return false, nil
	}
	if err := as.mapPages(base, blockSize, blk.src, stubProt(blk.at)); err != nil {
		return false, err
	}
	as.freeSlotRefsLocked(blk.slots)
	blk.slots = nil
	as.p.pool.release(blk.priv)
	blk.priv = 0
	blk.state = blockData
	return true, nil
}

// blockStateOf reports whether base is an exec block and its state.
func (as *addressSpace) blockStateOf(base uint64) (blockState, hostarch.AccessType, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[base]
	if blk == nil {
		return 0, hostarch.NoAccess, false
	}
	return blk.state, blk.at, true
}

// isWritableExecutable reports whether base is an exec block that allows
// writes. A write fault in such a block from an instruction inside the block
// cannot succeed, because the engine gives the block either write or execute
// access, never both.
func (as *addressSpace) isWritableExecutable(base uint64) bool {
	_, at, ok := as.blockStateOf(base)
	return ok && at.Write && at.Execute
}

// logSelfStore tells the operator why a guest got SIGSEGV for a store to the
// block of its own instruction. It logs once for each address space.
func (as *addressSpace) logSelfStore(pc, far uint64) {
	if as.selfStoreLogged.Swap(true) {
		return
	}
	log.Warningf("systrap: the guest instruction at %#x stores to %#x in the same %dKB block. "+
		"This engine gives a block write or execute access, never both, so the guest gets SIGSEGV. "+
		"Run the executable with -platform=hvf.", pc, far, blockSize/1024)
}

func putWord(b []byte, w uint32) {
	b[0], b[1], b[2], b[3] = byte(w), byte(w>>8), byte(w>>16), byte(w>>24)
}

// ----- islands --------------------------------------------------------------

// allocSlot returns space for a slot within reach of site. It creates an
// island through the memory manager when no island has room.
func (as *addressSpace) allocSlot(ctx context.Context, mm platform.MemoryManager, site uint64, size int) (*island, uint32, uint64, error) {
	for attempt := 0; attempt < 3; attempt++ {
		as.mu.Lock()
		for _, isl := range as.islands {
			if absDiff(isl.base, site) < islandReach {
				if off, ok := isl.alloc(uint32(size)); ok {
					as.mu.Unlock()
					return isl, off, isl.base + uint64(off), nil
				}
			}
		}
		as.mu.Unlock()
		if err := as.newIsland(ctx, mm, site); err != nil {
			return nil, 0, 0, err
		}
	}
	return nil, 0, 0, errors.New("no trampoline island has room")
}

func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// newIsland reserves a sealed VMA within reach of near through the memory
// manager and maps a private page of slots there.
func (as *addressSpace) newIsland(ctx context.Context, mm platform.MemoryManager, near uint64) error {
	minAddr, maxAddr := as.p.userMin, as.p.userMax
	// A site in the zone gets an island in the zone, at a guest address that
	// maps to a stub address within reach. Every other site gets an island
	// above the biased zone.
	var shift uint64
	switch {
	case as.p.zone && inZoneStub(near):
		shift = zoneBias
		near -= shift
		minAddr, maxAddr = zoneMin, zoneLimit
	case as.p.zone:
		minAddr = max(minAddr, zoneBias+zoneLimit)
	}
	var lastErr error
	for try := 0; try < 128; try++ {
		off := (uint64(rand.Int64N(islandReach-(4<<20))) + 2<<20) &^ (blockSize - 1)
		var cand uint64
		if rand.IntN(2) == 0 {
			if near < off {
				continue
			}
			cand = near - off
		} else {
			cand = near + off
		}
		cand = blockRound(cand)
		if cand < minAddr || cand+blockSize > maxAddr {
			continue
		}
		stubCand := cand + shift
		as.mu.Lock()
		if _, busy := as.reserved[stubCand]; busy || as.islands[stubCand] != nil || as.released {
			as.mu.Unlock()
			continue
		}
		as.reserved[stubCand] = struct{}{}
		as.mu.Unlock()

		_, err := mm.MMap(ctx, memmap.MMapOpts{
			Length:    blockSize,
			Addr:      hostarch.Addr(cand),
			Fixed:     true,
			NoReplace: true,
			Private:   true,
			Name:      "[systrap]",
			Sealed:    true,
			Perms:     hostarch.AccessType{Read: true, Execute: true},
			MaxPerms:  hostarch.AccessType{Read: true, Execute: true},
		})
		if err != nil {
			as.mu.Lock()
			delete(as.reserved, stubCand)
			as.mu.Unlock()
			lastErr = err
			continue
		}
		if err := as.installIsland(stubCand); err != nil {
			return err
		}
		return nil
	}
	if lastErr == nil {
		lastErr = unix.ENOMEM
	}
	return fmt.Errorf("find an address within 128MiB for a trampoline island: %w", lastErr)
}

// installIsland maps a zeroed private page as read and execute at base.
func (as *addressSpace) installIsland(base uint64) error {
	page, err := as.p.pool.alloc()
	if err != nil {
		return err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.reserved, base)
	if as.released {
		as.p.pool.release(page)
		return errAddressSpaceReleased
	}
	if err := as.mapPages(base, blockSize, page, vmProtRead|vmProtExecute); err != nil {
		as.p.pool.release(page)
		return err
	}
	as.islands[base] = &island{base: base, page: page, slots: make(map[uint32]slotMeta)}
	return nil
}

// inIsland reports whether pc lies in an island.
func (as *addressSpace) inIsland(pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	_, ok := as.islands[blockRound(pc)]
	return ok
}

// maxSlotSize bounds the byte size of a slot, so that a lookup by an address
// inside a slot looks back a limited distance.
const maxSlotSize = memSlotSize

// The longest slot of the x18 classes must fit in maxSlotSize.
var _ = [maxSlotSize - (16 + 4*x18MaxBody + 16 + 4)]struct{}{}

// isTrap reports whether a slot kind parks the thread in the Sentry.
func (k siteKind) isTrap() bool {
	return k == siteSVC || k == siteMSR || k == siteX18Jump
}

// slotAt returns the trap slot that owns a tail address, or the slot that
// starts at or contains an address inside it.
func (as *addressSpace) slotAt(addr uint64, isTail bool) (slotMeta, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	isl := as.islands[blockRound(addr)]
	if isl == nil {
		return slotMeta{}, false
	}
	off := uint32(addr - isl.base)
	if isTail {
		if off < trapSlotTailOffset {
			return slotMeta{}, false
		}
		m, ok := isl.slots[off-trapSlotTailOffset]
		return m, ok && m.kind.isTrap()
	}
	m, _, ok := isl.slotContaining(off)
	return m, ok
}

// slotContaining returns the slot that holds the island offset off and the
// island offset of its first word.
func (isl *island) slotContaining(off uint32) (slotMeta, uint32, bool) {
	for back := uint32(0); back < maxSlotSize && back <= off; back += 4 {
		if m, ok := isl.slots[off-back]; ok {
			return m, off - back, back < m.size
		}
	}
	return slotMeta{}, 0, false
}

// slotWithin returns the slot that contains pc and the address of its first word.
func (as *addressSpace) slotWithin(pc uint64) (slotMeta, uint64, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	isl := as.islands[blockRound(pc)]
	if isl == nil {
		return slotMeta{}, 0, false
	}
	m, start, ok := isl.slotContaining(uint32(pc - isl.base))
	return m, isl.base + uint64(start), ok
}

// isSlotTail reports whether pc is the tail instruction of a trap slot.
func (as *addressSpace) isSlotTail(pc uint64) bool {
	_, ok := as.slotAt(pc, true)
	return ok
}

// codeWord returns the 32-bit instruction word of the original frame or island
// at stub address pc, or false when pc does not lie at an aligned offset of an
// executable block or trampoline island.
func (as *addressSpace) codeWord(pc uint64) (uint32, bool) {
	if pc&3 != 0 {
		return 0, false
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	base := blockRound(pc)
	if blk := as.blocks[base]; blk != nil && blk.src != 0 {
		page := unsafe.Slice((*byte)(addrPtr(blk.src)), blockSize)
		return binary.LittleEndian.Uint32(page[pc-base:]), true
	}
	if isl := as.islands[base]; isl != nil && isl.page != 0 {
		page := pageBytes(isl.page)
		return binary.LittleEndian.Uint32(page[pc-base:]), true
	}
	return 0, false
}
