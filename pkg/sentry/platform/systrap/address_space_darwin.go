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
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

const subBlocksPerBlock = blockSize / subBlockSize

// subPage describes one 4KB guest sub-block inside a 16KB host block.
type subPage struct {
	src uint64
	at  hostarch.AccessType
}

// hostBlock tracks the four 4KB guest sub-blocks of one 16KB host page.
type hostBlock struct {
	subs       [subBlocksPerBlock]subPage
	mappedMask uint8
	execMask   uint8
	writeMask  uint8
	directSrc  uint64
	comp       uint64
	mappedComp bool
}

func (hb *hostBlock) recompute() {
	var mapped, exec, write uint8
	for s := 0; s < subBlocksPerBlock; s++ {
		sub := hb.subs[s]
		if sub.src == 0 {
			continue
		}
		bit := uint8(1 << s)
		mapped |= bit
		if sub.at.Execute {
			exec |= bit
		}
		if sub.at.Write {
			write |= bit
		}
	}
	hb.mappedMask = mapped
	hb.execMask = exec
	hb.writeMask = write
	hb.directSrc = 0
	if mapped == 0xF && hb.subs[0].src%blockSize == 0 {
		baseSrc := hb.subs[0].src
		contig := true
		for s := 1; s < subBlocksPerBlock; s++ {
			if hb.subs[s].src != baseSrc+uint64(s)*subBlockSize {
				contig = false
				break
			}
		}
		if contig {
			hb.directSrc = baseSrc
		}
	}
}

func (hb *hostBlock) canMapDirect() bool {
	return hb.directSrc != 0 && (hb.writeMask == 0 || hb.writeMask == 0xF)
}

func (hb *hostBlock) syncComp() {
	if hb.comp == 0 {
		return
	}
	dst := pageBytes(hb.comp)
	for s := 0; s < subBlocksPerBlock; s++ {
		off := s * subBlockSize
		dstWords := unsafe.Slice((*uint64)(unsafe.Pointer(&dst[off])), subBlockSize/8)
		sub := hb.subs[s]
		if sub.src != 0 {
			srcWords := unsafe.Slice((*uint64)(addrPtr(sub.src)), subBlockSize/8)
			for i, w := range srcWords {
				if dstWords[i] != w {
					dstWords[i] = w
				}
			}
		} else {
			for i, w := range dstWords {
				if w != 0 {
					dstWords[i] = 0
				}
			}
		}
	}
}

// execBlock is one host page of a guest mapping that allows execution.
//
// WHY: the original frame can be shared between address spaces and mapped at
// different addresses, and the patch encodes addresses. So the stub never
// executes the original frame. A first fetch faults, the Sentry patches a
// private copy and the stub sees the copy instead. A block that also allows
// writes alternates between the writable original and the executable copy, so
// code that a guest writes is always patched before it runs.
type execBlock struct {
	base         uint64
	src          uint64
	at           hostarch.AccessType
	state        blockState
	priv         uint64
	slots        []slotRef
	retiredSlots []slotRef
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
	// brSlots caches the offset+1 of shared non-linking indirect branch slots
	// (BR Xn and RET Xn) indexed by register number 0..30.
	brSlots [31]uint32
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

	mu            sync.Mutex
	released      bool
	blocks        map[uint64]*execBlock
	hostBlocks    map[uint64]*hostBlock
	partialBlocks map[uint64]*hostBlock
	compBlocks    map[uint64]*hostBlock
	islands       map[uint64]*island
	// zoneMapped holds the stub address of every block that the guest maps in
	// the zone. It is empty outside the zone mode.
	zoneMapped map[uint64]struct{}
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

	// zoneState caches whether this address space holds mappings in the 4GB
	// zone (0: unknown, 1: no zone mappings, 2: has zone mappings).
	zoneState atomic.Uint32
}

var errDeadStub = errors.New("the stub task died")

func newAddressSpace(p *Platform) (*addressSpace, error) {
	proc, err := p.host.forkProc()
	if err != nil {
		return nil, fmt.Errorf("create a stub task: %w", err)
	}
	as := &addressSpace{
		p:             p,
		proc:          proc,
		blocks:        make(map[uint64]*execBlock),
		hostBlocks:    make(map[uint64]*hostBlock),
		partialBlocks: make(map[uint64]*hostBlock),
		compBlocks:    make(map[uint64]*hostBlock),
		islands:       make(map[uint64]*island),
		zoneMapped:    make(map[uint64]struct{}),
		reserved:      make(map[uint64]struct{}),
		threads:       make(map[*thread]struct{}),
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
	if _, _, err := vmRemap(as.proc.task, addr, size, as.p.host.self, src); err != nil {
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

func checkSubBlockAligned(op string, addr, length uint64) error {
	if length == 0 || addr%subBlockSize != 0 || length%subBlockSize != 0 {
		return &AlignmentError{Op: op, Addr: addr, Len: length}
	}
	return nil
}

// isReadOnlyFile reports whether f rejects writable internal mappings.
func isReadOnlyFile(f memmap.File, fr memmap.FileRange) bool {
	probe := memmap.FileRange{Start: fr.Start, End: fr.Start + subBlockSize}
	_, err := f.MapInternal(probe, hostarch.Write)
	return err != nil
}

// MapFile implements platform.AddressSpace.MapFile.
//
// Mappings may be aligned to 4KB virtual sub-blocks (subBlockSize) or 16KB
// host blocks (blockSize). When four contiguous 4KB sub-blocks share a
// 16KB-aligned MemoryFile frame and agree on write access, the stub maps the
// MemoryFile frame directly; otherwise the address space maintains a 16KB
// composite page for that host block.
func (as *addressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	guest := uint64(addr)
	if err := checkSubBlockAligned("map", guest, fr.Length()); err != nil {
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
	immutable := !at.Write && isReadOnlyFile(f, fr)
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		return errAddressSpaceReleased
	}
	va := as.p.stubAddr(guest)
	for ; !bs.IsEmpty(); bs = bs.Tail() {
		b := bs.Head()
		src, n := uint64(uintptr(b.Addr())), uint64(b.Len())
		if src%subBlockSize != 0 || n%subBlockSize != 0 {
			return &AlignmentError{Op: "map memory file range", Addr: src, Len: n}
		}
		if err := as.mapRangeImmutableLocked(va, n, src, at, immutable); err != nil {
			return err
		}
		va += n
	}
	return nil
}

// mapRangeLocked installs [va, va+n) from the Sentry address src.
func (as *addressSpace) mapRangeLocked(va, n, src uint64, at hostarch.AccessType) error {
	return as.mapRangeImmutableLocked(va, n, src, at, false)
}

func (as *addressSpace) mapRangeImmutableLocked(va, n, src uint64, at hostarch.AccessType, immutable bool) error {
	for n > 0 && (va%blockSize != 0 || n < blockSize) {
		step := min(n, blockRound(va)+blockSize-va)
		if err := as.mapSubBlocksInHostBlockLocked(va, step, src, at); err != nil {
			return err
		}
		va += step
		src += step
		n -= step
	}
	fullLen := n &^ (blockSize - 1)
	if fullLen > 0 {
		runSrc := src
		aligned := runSrc%blockSize == 0
		if !aligned && immutable {
			if cachedSrc, ok := as.p.alignedReadOnly(src, fullLen); ok {
				runSrc = cachedSrc
				aligned = true
			}
		}
		if aligned {
			if err := as.mapAlignedRunLocked(va, fullLen, runSrc, at); err != nil {
				return err
			}
		} else {
			for base := va; base < va+fullLen; base += blockSize {
				if err := as.mapSubBlocksInHostBlockLocked(base, blockSize, src+(base-va), at); err != nil {
					return err
				}
			}
		}
		va += fullLen
		src += fullLen
		n -= fullLen
	}
	if n > 0 {
		if err := as.mapSubBlocksInHostBlockLocked(va, n, src, at); err != nil {
			return err
		}
	}
	return nil
}

func (as *addressSpace) mapAlignedRunLocked(va, fullLen, src uint64, at hostarch.AccessType) error {
	runStart := va
	for base := va; base < va+fullLen; base += blockSize {
		if !as.isIslandBlockLocked(base) {
			continue
		}
		if err := as.mapRunLocked(runStart, base-runStart, src+(runStart-va), at); err != nil {
			return err
		}
		runStart = base + blockSize
	}
	return as.mapRunLocked(runStart, va+fullLen-runStart, src+(runStart-va), at)
}

func (as *addressSpace) mapSubBlocksInHostBlockLocked(va, length, subSrc uint64, at hostarch.AccessType) error {
	base := blockRound(va)
	if as.isIslandBlockLocked(base) {
		return nil
	}
	hb := as.hostBlocks[base]
	if hb == nil {
		hb = &hostBlock{}
		as.hostBlocks[base] = hb
	}
	for off := uint64(0); off < length; off += subBlockSize {
		subIdx := int((va + off - base) / subBlockSize)
		hb.subs[subIdx] = subPage{src: subSrc + off, at: at}
	}
	return as.refreshHostBlockLocked(base, hb)
}

func (as *addressSpace) refreshHostBlockLocked(base uint64, hb *hostBlock) error {
	hb.recompute()
	if hb.mappedMask == 0 {
		if err := vmDeallocate(as.proc.task, base, blockSize); err != nil && !as.proc.dead.Load() {
			return as.taskErr(err)
		}
		as.dropBlockLocked(base)
		if hb.comp != 0 {
			as.p.pool.release(hb.comp)
			hb.comp = 0
		}
		delete(as.hostBlocks, base)
		delete(as.partialBlocks, base)
		delete(as.compBlocks, base)
		delete(as.zoneMapped, base)
		return nil
	}
	if hb.mappedMask != 0xF || (hb.writeMask == 0xF && hb.execMask == 0 && hb.directSrc == 0) {
		as.partialBlocks[base] = hb
	} else {
		delete(as.partialBlocks, base)
	}
	if inZoneStub(base) {
		as.zoneMapped[base] = struct{}{}
		as.zoneState.Store(2)
	}
	var backingSrc uint64
	prot := vmProtRead
	needMap := true
	if hb.canMapDirect() {
		backingSrc = hb.directSrc
		if hb.writeMask == 0xF {
			prot |= vmProtWrite
		}
		if hb.comp != 0 {
			as.p.pool.release(hb.comp)
			hb.comp = 0
		}
		hb.mappedComp = false
		delete(as.compBlocks, base)
	} else {
		if hb.comp == 0 {
			comp, err := as.p.pool.alloc()
			if err != nil {
				return err
			}
			hb.comp = comp
			hb.mappedComp = false
		}
		hb.syncComp()
		as.compBlocks[base] = hb
		backingSrc = hb.comp
		if hb.mappedComp && (as.blocks[base] == nil || as.blocks[base].state == blockData) {
			needMap = false
		}
	}
	if needMap {
		if err := as.mapPages(base, blockSize, backingSrc, prot); err != nil {
			return fmt.Errorf("map [%#x, %#x): %w", base, base+blockSize, err)
		}
		hb.mappedComp = (backingSrc == hb.comp && hb.comp != 0)
	}
	if hb.execMask != 0 {
		execAt := hostarch.AccessType{Read: true, Write: hb.writeMask != 0, Execute: true}
		if blk := as.blocks[base]; blk != nil {
			blk.retiredSlots = append(blk.retiredSlots, blk.slots...)
			blk.slots = nil
			if blk.priv != 0 {
				as.p.pool.release(blk.priv)
				blk.priv = 0
			}
			blk.src = backingSrc
			blk.at = execAt
			blk.state = blockData
		} else {
			as.blocks[base] = &execBlock{base: base, src: backingSrc, at: execAt, state: blockData}
		}
	} else {
		as.dropBlockLocked(base)
	}
	return nil
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

// mapRunLocked installs [va, va+n), a 16KB-aligned range without an island,
// from the 16KB-aligned Sentry address src.
func (as *addressSpace) mapRunLocked(va, n, src uint64, at hostarch.AccessType) error {
	if n == 0 {
		return nil
	}
	if err := as.mapPages(va, n, src, stubProt(at)); err != nil {
		return fmt.Errorf("map [%#x, %#x): %w", va, va+n, err)
	}
	for base := va; base < va+n; base += blockSize {
		bSrc := src + (base - va)
		hb := as.hostBlocks[base]
		if hb == nil {
			hb = &hostBlock{}
			as.hostBlocks[base] = hb
		} else if hb.comp != 0 {
			as.p.pool.release(hb.comp)
			hb.comp = 0
		}
		hb.mappedComp = false
		for s := 0; s < subBlocksPerBlock; s++ {
			hb.subs[s] = subPage{src: bSrc + uint64(s)*subBlockSize, at: at}
		}
		hb.mappedMask = 0xF
		if at.Execute {
			hb.execMask = 0xF
		} else {
			hb.execMask = 0
		}
		if at.Write {
			hb.writeMask = 0xF
		} else {
			hb.writeMask = 0
		}
		hb.directSrc = bSrc
		delete(as.partialBlocks, base)
		delete(as.compBlocks, base)
		as.dropBlockLocked(base)
		if inZoneStub(base) {
			as.zoneMapped[base] = struct{}{}
			as.zoneState.Store(2)
		}
		if at.Execute {
			as.blocks[base] = &execBlock{base: base, src: bSrc, at: at, state: blockData}
		}
	}
	return nil
}

// dropBlockLocked forgets the exec state of one block and frees its copy.
func (as *addressSpace) dropBlockLocked(base uint64) {
	if blk, ok := as.blocks[base]; ok {
		as.freeSlotRefsLocked(blk.slots)
		as.freeSlotRefsLocked(blk.retiredSlots)
		blk.slots = nil
		blk.retiredSlots = nil
		if blk.priv != 0 {
			as.p.pool.release(blk.priv)
		}
		delete(as.blocks, base)
	}
}

func (as *addressSpace) dropHostBlockLocked(base uint64) {
	if hb, ok := as.hostBlocks[base]; ok {
		if hb.comp != 0 {
			as.p.pool.release(hb.comp)
			hb.comp = 0
		}
		delete(as.hostBlocks, base)
	}
	delete(as.partialBlocks, base)
	delete(as.compBlocks, base)
}

// freeSlotRefsLocked releases the island slots in refs. Callers hold as.mu.
func (as *addressSpace) freeSlotRefsLocked(refs []slotRef) {
	for _, r := range refs {
		if as.islands[r.isl.base] == r.isl {
			r.isl.free(r.off, r.size)
		}
	}
}

// Unmap implements platform.AddressSpace.Unmap.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	guestStart := uint64(addr) &^ (subBlockSize - 1)
	guestEnd := (uint64(addr) + length + subBlockSize - 1) &^ (subBlockSize - 1)
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
	for start < end && (start%blockSize != 0 || end-start < blockSize) {
		step := min(end-start, blockRound(start)+blockSize-start)
		as.unmapSubBlocksInHostBlockLocked(start, step)
		start += step
	}
	midEnd := end &^ (blockSize - 1)
	if start < midEnd {
		if err := vmDeallocate(as.proc.task, start, midEnd-start); err != nil && !as.proc.dead.Load() {
			panic(fmt.Sprintf("systrap: unmap [%#x, %#x): %v", start, midEnd, err))
		}
		if (midEnd-start)/blockSize > uint64(len(as.hostBlocks)+len(as.blocks)) {
			for base := range as.blocks {
				if base >= start && base < midEnd {
					as.dropBlockLocked(base)
				}
			}
			for base := range as.hostBlocks {
				if base >= start && base < midEnd {
					as.dropHostBlockLocked(base)
				}
			}
		} else {
			for base := start; base < midEnd; base += blockSize {
				as.dropBlockLocked(base)
				as.dropHostBlockLocked(base)
			}
		}
		for base := range as.zoneMapped {
			if base >= start && base < midEnd {
				delete(as.zoneMapped, base)
			}
		}
		for base, isl := range as.islands {
			if base < midEnd && start < base+blockSize {
				delete(as.islands, base)
				as.p.pool.release(isl.page)
			}
		}
		start = midEnd
	}
	if start < end {
		as.unmapSubBlocksInHostBlockLocked(start, end-start)
	}
}

func (as *addressSpace) unmapSubBlocksInHostBlockLocked(va, length uint64) {
	base := blockRound(va)
	hb := as.hostBlocks[base]
	if hb == nil {
		return
	}
	changed := false
	for off := uint64(0); off < length; off += subBlockSize {
		subIdx := int((va + off - base) / subBlockSize)
		if hb.subs[subIdx].src != 0 {
			hb.subs[subIdx] = subPage{}
			changed = true
		}
	}
	if changed {
		_ = as.refreshHostBlockLocked(base, hb)
	}
}

// beforeSwitch populates sibling 4KB sub-blocks of partially mapped 16KB host
// blocks and synchronizes composite pages with their underlying 4KB MemoryFile
// frames before resuming the guest thread.
func (as *addressSpace) beforeSwitch(ctx context.Context, mm platform.MemoryManager) {
	if mm == nil {
		return
	}
	if pop, ok := mm.(platform.SubBlockPopulator); ok {
		var toPop []hostarch.Addr
		var poppedBases []uint64
		as.mu.Lock()
		for base, hb := range as.partialBlocks {
			delete(as.partialBlocks, base)
			poppedBases = append(poppedBases, base)
			gbase := as.p.guestAddr(base)
			if hb.mappedMask == 0xF {
				toPop = append(toPop, hostarch.Addr(gbase))
			} else {
				for s := 0; s < subBlocksPerBlock; s++ {
					if hb.mappedMask&(1<<s) == 0 {
						toPop = append(toPop, hostarch.Addr(gbase+uint64(s)*subBlockSize))
					}
				}
			}
		}
		as.mu.Unlock()
		for _, addr := range toPop {
			pop.PopulateSubBlock(ctx, addr)
		}
		if len(poppedBases) > 0 {
			as.mu.Lock()
			for _, base := range poppedBases {
				delete(as.partialBlocks, base)
			}
			as.mu.Unlock()
		}
	}
	as.mu.Lock()
	for base, hb := range as.compBlocks {
		hb.syncComp()
		if blk := as.blocks[base]; blk != nil && blk.state == blockExec && blk.priv != 0 {
			priv := pageBytes(blk.priv)
			for s := 0; s < subBlocksPerBlock; s++ {
				if hb.execMask&(1<<s) == 0 && hb.subs[s].src != 0 {
					off := s * subBlockSize
					srcWords := unsafe.Slice((*uint64)(addrPtr(hb.subs[s].src)), subBlockSize/8)
					dstWords := unsafe.Slice((*uint64)(unsafe.Pointer(&priv[off])), subBlockSize/8)
					for i, w := range srcWords {
						if dstWords[i] != w {
							dstWords[i] = w
						}
					}
				}
			}
		}
	}
	as.mu.Unlock()
}

// isExecSubBlock reports whether the 4KB sub-block containing stubAddr has
// execute permission.
func (as *addressSpace) isExecSubBlock(stubAddr uint64) bool {
	base := blockRound(stubAddr)
	subIdx := (stubAddr - base) / subBlockSize
	as.mu.Lock()
	defer as.mu.Unlock()
	if hb := as.hostBlocks[base]; hb != nil {
		return hb.execMask&(1<<subIdx) != 0
	}
	blk := as.blocks[base]
	return blk != nil && blk.at.Execute
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
	for base := range as.hostBlocks {
		as.dropHostBlockLocked(base)
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

// UserModifiedGS implements platform.AddressSpace.UserModifiedGS. arm64 has no
// GS register.
func (*addressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error { return nil }

// ----- lazy patching ------------------------------------------------------

// populateBlock populates any unmapped 4KB sibling sub-blocks of the 16KB host
// block at base before patching or executing it.
func (as *addressSpace) populateBlock(ctx context.Context, mm platform.MemoryManager, base uint64) {
	if mm == nil {
		return
	}
	pop, ok := mm.(platform.SubBlockPopulator)
	if !ok {
		return
	}
	var toPop []hostarch.Addr
	as.mu.Lock()
	if hb := as.partialBlocks[base]; hb != nil {
		delete(as.partialBlocks, base)
		gbase := as.p.guestAddr(base)
		for s := 0; s < subBlocksPerBlock; s++ {
			if hb.mappedMask&(1<<s) == 0 {
				toPop = append(toPop, hostarch.Addr(gbase+uint64(s)*subBlockSize))
			}
		}
	}
	as.mu.Unlock()
	for _, addr := range toPop {
		pop.PopulateSubBlock(ctx, addr)
	}
	if len(toPop) > 0 {
		as.mu.Lock()
		delete(as.partialBlocks, base)
		as.mu.Unlock()
	}
}

// patchBlock patches the block that holds addr and maps the patched copy as
// read and execute. It runs on the task goroutine, which is allowed to call
// into the memory manager.
func (as *addressSpace) patchBlock(ctx context.Context, mm platform.MemoryManager, addr uint64) error {
	base := blockRound(addr)
	as.populateBlock(ctx, mm, base)
	as.patchMu.Lock()
	defer as.patchMu.Unlock()
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
	hb := as.hostBlocks[base]
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
	var subs [subBlocksPerBlock]subPage
	execMask := uint8(0xF)
	directRO := !blk.at.Write && src != 0
	if hb != nil {
		if hb.comp != 0 {
			hb.syncComp()
		}
		subs = hb.subs
		execMask = hb.execMask
		directRO = directRO && hb.canMapDirect() && hb.writeMask == 0 && hb.execMask == 0xF
	}
	retired := blk.retiredSlots
	blk.retiredSlots = nil
	as.mu.Unlock()

	directRO = directRO && !as.hasZone(mm)
	copyBuf := make([]byte, blockSize)
	if hb != nil && !hb.canMapDirect() {
		for s := 0; s < subBlocksPerBlock; s++ {
			if subs[s].src != 0 {
				off := s * subBlockSize
				copy(copyBuf[off:off+subBlockSize], unsafe.Slice((*byte)(addrPtr(subs[s].src)), subBlockSize))
			}
		}
	} else {
		copy(copyBuf, unsafe.Slice((*byte)(addrPtr(src)), blockSize))
	}

	var items []patchItem
	var claimed map[int]struct{}
	var gbase uint64
	var scope codeScope
	var effExecMask uint8
	_, cleanHit := false, false
	if directRO {
		_, cleanHit = as.p.cleanCode.Load(src)
	}
	if !cleanHit {
		gbase = as.p.guestAddr(base)
		scope = as.p.scopeOf(ctx, mm, gbase)
		effExecMask = execMask & scope.subBlockMask(gbase)

		claimed = make(map[int]struct{})
		for _, s := range scanARM64(copyBuf) {
			subIdx := s.Offset / subBlockSize
			if execMask&(1<<subIdx) == 0 {
				continue
			}
			claimed[int(s.Offset)] = struct{}{}
			it := patchItem{patchSite: s}
			if s.Kind == siteMRS && s.Reg == x18Reg {
				it.Kind, it.x18 = siteX18, planTPIDRRead()
			}
			if s.Kind == siteCTR && s.Reg == x18Reg {
				it.Kind, it.x18 = siteX18, planCTRRead()
			}
			items = append(items, it)
		}
		skippedX18 := false
		if !scope.none {
			for _, x := range scanX18(copyBuf, base, func(off int) bool {
				subIdx := off / subBlockSize
				if effExecMask&(1<<subIdx) == 0 {
					skippedX18 = true
					return true
				}
				if _, taken := claimed[off]; taken {
					return true
				}
				if !scope.contains(gbase + uint64(off)) {
					skippedX18 = true
					return true
				}
				if scope.stripped && isASCIIStringWindow(copyBuf, off) {
					skippedX18 = true
					return true
				}
				return false
			}) {
				items = append(items, patchItem{
					patchSite: patchSite{Offset: x.Offset, Kind: x.Plan.kind, Orig: binary.LittleEndian.Uint32(copyBuf[x.Offset:])},
					x18:       x.Plan,
				})
			}
		}
		if directRO && !scope.none && !skippedX18 && len(items) == 0 {
			as.p.cleanCode.Store(src, struct{}{})
		}
	}

	touched := make(map[*island]struct{})
	var allocated []slotRef
	var keptTrapSlots []slotRef
	takeRetired := func(site uint64, kind siteKind, reg uint8, size uint32) (*island, uint32, uint64, bool) {
		as.mu.Lock()
		defer as.mu.Unlock()
		for i, r := range retired {
			if as.islands[r.isl.base] != r.isl {
				continue
			}
			m, ok := r.isl.slots[r.off]
			if ok && m.site == site && m.kind == kind && m.reg == reg && r.size == size {
				retired = append(retired[:i], retired[i+1:]...)
				return r.isl, r.off, r.isl.base + uint64(r.off), true
			}
		}
		return nil, 0, 0, false
	}
	cleanupUnusedRetired := func() {
		as.mu.Lock()
		defer as.mu.Unlock()
		for _, r := range retired {
			if as.islands[r.isl.base] != r.isl {
				continue
			}
			if m, ok := r.isl.slots[r.off]; ok && m.kind.isTrap() {
				keptTrapSlots = append(keptTrapSlots, r)
				continue
			}
			r.isl.free(r.off, r.size)
		}
		retired = nil
	}
	freeAllocated := func() {
		as.mu.Lock()
		as.freeSlotRefsLocked(allocated)
		as.freeSlotRefsLocked(retired)
		as.freeSlotRefsLocked(keptTrapSlots)
		as.mu.Unlock()
	}

	for _, s := range items {
		site := base + uint64(s.Offset)
		if (s.Kind == siteMRS || s.Kind == siteCTR) && s.Reg == 31 {
			putWord(copyBuf[s.Offset:], arm64NOP)
			continue
		}
		size := slotSizeFor(s.Kind)
		if s.x18 != nil {
			size = s.x18.slotSize()
		}
		metaReg := s.Reg
		if s.Kind == siteX18Jump && s.x18.link {
			metaReg = 1
		}
		isl, off, slotVA, ok := takeRetired(site, s.Kind, metaReg, uint32(size))
		if !ok {
			var err error
			isl, off, slotVA, err = as.allocSlot(ctx, mm, site, size)
			if err != nil {
				freeAllocated()
				return fmt.Errorf("allocate a trampoline slot for %#x: %w", site, err)
			}
		}
		allocated = append(allocated, slotRef{isl: isl, off: off, size: uint32(size)})
		buf := pageBytes(isl.page)[off:]
		meta := slotMeta{site: site, kind: s.Kind, reg: metaReg, size: uint32(size)}
		var err error
		switch s.Kind {
		case siteMRS:
			err = encodeLoadSlot(buf, slotVA, site+4, s.Reg, tlsOffset)
		case siteCTR:
			err = encodeCTRSlot(buf, slotVA, site+4, s.Reg)
		case siteX18, siteX18Cond:
			meta.body, meta.scratch = uint8(len(s.x18.body)), s.x18.scratch
			err = encodeX18Slot(buf, slotVA, site, s.x18)
		case siteX18Jump:
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
	if as.hasZone(mm) {
		taken := claimed
		for _, it := range items {
			taken[int(it.Offset)] = struct{}{}
		}
		lits := literalWords(copyBuf)
		skip := func(off int) bool {
			subIdx := off / subBlockSize
			if effExecMask&(1<<subIdx) == 0 {
				return true
			}
			if _, t := taken[off]; t {
				return true
			}
			if _, data := lits[off]; data {
				return true
			}
			if scope.proven() && !scope.contains(gbase+uint64(off)) {
				return true
			}
			return isASCIIStringWindow(copyBuf, off)
		}
		for _, z := range scanZone(copyBuf, base, skip) {
			site := base + uint64(z.offset)
			if z.kind == siteIndirect && !z.link {
				slotVA, isl, newlyCreated, err := as.allocSharedBrSlot(ctx, mm, site, z.reg)
				if err != nil {
					freeAllocated()
					return fmt.Errorf("allocate a shared indirect slot for %#x: %w", site, err)
				}
				if newlyCreated {
					touched[isl] = struct{}{}
				}
				br, err := encodeBranch(site, slotVA)
				if err != nil {
					freeAllocated()
					return err
				}
				putWord(copyBuf[z.offset:], br)
				continue
			}
			size := adrpSlotSize
			switch {
			case z.kind == siteBL:
				size = blSlotSize
			case z.kind == siteIndirect && z.link:
				size = blrSlotSize
			case z.kind == siteIndirect:
				size = brSlotSize
			}
			isl, off, slotVA, ok := takeRetired(site, z.kind, z.reg, uint32(size))
			if !ok {
				var err error
				if z.kind == siteBL {
					isl, off, slotVA, err = as.allocSlotNearBoth(ctx, mm, site, z.value, size)
				} else {
					isl, off, slotVA, err = as.allocSlot(ctx, mm, site, size)
				}
				if err != nil {
					freeAllocated()
					return fmt.Errorf("allocate a zone slot for %#x: %w", site, err)
				}
			}
			allocated = append(allocated, slotRef{isl: isl, off: off, size: uint32(size)})
			buf := pageBytes(isl.page)[off:]
			var err error
			switch z.kind {
			case siteAdrp:
				err = encodeAdrpSlot(buf, slotVA, site, z.reg, z.value)
			case siteBL:
				guestRet := (site - zoneBias) + 4
				err = encodeBLSlot(buf, slotVA, guestRet, z.value)
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
	cleanupUnusedRetired()
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
		as.freeSlotRefsLocked(keptTrapSlots)
		as.p.pool.release(privAddr)
		return errPatchRaced
	}
	if err := as.mapPages(base, blockSize, privAddr, vmProtRead|vmProtExecute); err != nil {
		as.freeSlotRefsLocked(allocated)
		as.freeSlotRefsLocked(keptTrapSlots)
		as.p.pool.release(privAddr)
		return err
	}
	if hb := as.hostBlocks[base]; hb != nil {
		hb.mappedComp = false
	}
	blk.priv = privAddr
	blk.state = blockExec
	blk.slots = allocated
	blk.retiredSlots = append(blk.retiredSlots, keptTrapSlots...)
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
	if hb := as.hostBlocks[base]; hb != nil && (!hb.canMapDirect() || hb.writeMask != 0xF) {
		return false, nil
	}
	if err := as.mapPages(base, blockSize, blk.src, stubProt(blk.at)); err != nil {
		return false, err
	}
	blk.retiredSlots = append(blk.retiredSlots, blk.slots...)
	blk.slots = nil
	as.p.pool.release(blk.priv)
	blk.priv = 0
	blk.state = blockData
	return true, nil
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

// allocSlotNearBoth returns space for a slot within reach of both site and
// target.
func (as *addressSpace) allocSlotNearBoth(ctx context.Context, mm platform.MemoryManager, site, target uint64, size int) (*island, uint32, uint64, error) {
	mid := site/2 + target/2
	for attempt := 0; attempt < 3; attempt++ {
		as.mu.Lock()
		for _, isl := range as.islands {
			if absDiff(isl.base, site) < islandReach && absDiff(isl.base, target) < islandReach {
				if off, ok := isl.alloc(uint32(size)); ok {
					as.mu.Unlock()
					return isl, off, isl.base + uint64(off), nil
				}
			}
		}
		as.mu.Unlock()
		if err := as.newIslandNearBoth(ctx, mm, mid, site, target); err != nil {
			return nil, 0, 0, err
		}
	}
	return nil, 0, 0, errors.New("no trampoline island has room within reach of both site and target")
}

// allocSharedBrSlot returns the address of a shared non-linking indirect
// branch slot (BR Xn or RET Xn) for register rn within reach of site.
func (as *addressSpace) allocSharedBrSlot(ctx context.Context, mm platform.MemoryManager, site uint64, rn uint8) (uint64, *island, bool, error) {
	if rn >= 31 {
		return 0, nil, false, fmt.Errorf("invalid indirect branch register %d", rn)
	}
	for attempt := 0; attempt < 3; attempt++ {
		as.mu.Lock()
		for _, isl := range as.islands {
			if absDiff(isl.base, site) >= islandReach {
				continue
			}
			if cached := isl.brSlots[rn]; cached != 0 {
				off := cached - 1
				as.mu.Unlock()
				return isl.base + uint64(off), isl, false, nil
			}
			if off, ok := isl.alloc(brSlotSize); ok {
				slotVA := isl.base + uint64(off)
				buf := pageBytes(isl.page)[off:]
				if _, err := encodeIndirectSlot(buf, slotVA, site, rn, false); err != nil {
					isl.free(off, brSlotSize)
					as.mu.Unlock()
					return 0, nil, false, err
				}
				isl.slots[off] = slotMeta{site: site, kind: siteIndirect, reg: rn, size: brSlotSize}
				isl.brSlots[rn] = off + 1
				as.mu.Unlock()
				return slotVA, isl, true, nil
			}
		}
		as.mu.Unlock()
		if err := as.newIsland(ctx, mm, site); err != nil {
			return 0, nil, false, err
		}
	}
	return 0, nil, false, errors.New("no trampoline island has room")
}

// newIsland reserves a sealed VMA within reach of near through the memory
// manager and maps a private page of slots there.
func (as *addressSpace) newIsland(ctx context.Context, mm platform.MemoryManager, near uint64) error {
	minAddr, maxAddr := as.p.userMin, as.p.userMax
	var shift uint64
	switch {
	case as.p.zone && inZoneStub(near):
		shift = zoneBias
		near -= shift
		minAddr, maxAddr = zoneMin, zoneLimit
	case as.p.zone:
		minAddr = max(minAddr, zoneBias+zoneLimit)
	}
	return as.newIslandAt(ctx, mm, near, func(cand uint64) (uint64, bool) {
		if cand < minAddr || cand+blockSize > maxAddr {
			return 0, false
		}
		return cand + shift, true
	})
}

func (as *addressSpace) newIslandNearBoth(ctx context.Context, mm platform.MemoryManager, mid, site, target uint64) error {
	minAddr, maxAddr := as.p.userMin, as.p.userMax
	var shift uint64
	switch {
	case as.p.zone && inZoneStub(mid):
		shift = zoneBias
		mid -= shift
		minAddr, maxAddr = zoneMin, zoneLimit
	case as.p.zone:
		minAddr = max(minAddr, zoneBias+zoneLimit)
	}
	return as.newIslandAt(ctx, mm, mid, func(cand uint64) (uint64, bool) {
		if cand < minAddr || cand+blockSize > maxAddr {
			return 0, false
		}
		stubCand := cand + shift
		if absDiff(stubCand, site) >= islandReach || absDiff(stubCand, target) >= islandReach {
			return 0, false
		}
		return stubCand, true
	})
}

// installIsland maps a zeroed private page as read and execute at base.
func (as *addressSpace) installIsland(base uint64) error {
	page, err := as.p.pool.alloc()
	if err != nil {
		as.dropReservation(base)
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
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.codeWordLocked(pc)
}

func (as *addressSpace) codeWordLocked(pc uint64) (uint32, bool) {
	if pc&3 != 0 {
		return 0, false
	}
	base := blockRound(pc)
	subIdx := int((pc - base) / subBlockSize)
	if hb := as.hostBlocks[base]; hb != nil {
		sub := hb.subs[subIdx]
		if sub.src != 0 && sub.at.Execute {
			subOff := pc - (base + uint64(subIdx)*subBlockSize)
			page := unsafe.Slice((*byte)(addrPtr(sub.src)), subBlockSize)
			return binary.LittleEndian.Uint32(page[subOff:]), true
		}
	}
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

// hasZone reports whether zone translation is active for as. An address space
// whose MemoryManager reports no mappings in the low 4GB zone is a normal PIE
// process and skips zone scanning and fault translation.
func (as *addressSpace) hasZone(mm platform.MemoryManager) bool {
	if !as.p.zone {
		return false
	}
	switch as.zoneState.Load() {
	case 2:
		return true
	case 1:
		return false
	}
	if q, ok := mm.(interface{ HasMappingIn(hostarch.AddrRange) bool }); ok {
		if q.HasMappingIn(hostarch.AddrRange{Start: zoneMin, End: zoneLimit}) {
			as.zoneState.Store(2)
			return true
		}
		as.zoneState.CompareAndSwap(0, 1)
		return as.zoneState.Load() == 2
	}
	return as.zoneState.Load() == 2
}
