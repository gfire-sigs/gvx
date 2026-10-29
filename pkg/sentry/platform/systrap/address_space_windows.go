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

//go:build windows

package systrap

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"z.gfire.dev/gvx/internal/xsys/unix"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// execBlock is one page of a guest mapping that allows execution.
//
// WHY: the original frame can be shared between address spaces and mapped at
// different addresses, and the patch holds addresses and site tables. So the
// stub never executes the original frame. A first fetch faults, the Sentry
// patches a private copy, and the stub sees the copy instead. A block that
// also allows writes alternates between the writable original and the
// executable copy, so code that a guest writes is always patched before it
// runs.
type execBlock struct {
	base uint64
	// src is the Sentry address of the original frame.
	src     uint64
	srcSec  *sectionRef
	srcOff  uint64
	at      hostarch.AccessType
	state   blockState
	priv    privPage
	hasPriv bool
	// sites maps the page offset of a patched instruction to its description.
	sites map[uint16]siteInfo
	// slots holds the island slots that this executable copy occupies.
	slots []winSlotRef
}

// copyHold counts the pages of an address space that still map a copied section.
type copyHold struct {
	sec  *anonSection
	refs int
}

// addressSpace is one stub process and the guest mappings in it.
type addressSpace struct {
	platform.NoAddressSpaceIO

	p  *Platform
	sp *stubProc

	// patchMu serializes patching. Two threads that fault on the same block
	// then patch it once.
	patchMu sync.Mutex

	mu       sync.Mutex
	released bool
	win      *guestWindows
	blocks   map[uint64]*execBlock

	// internal holds the engine pages at the top of the window.
	internal *anonSection
	// copies maps each block address of a copied section to its reference count.
	copies map[uint64]*copyHold

	// islands holds the pages of trampoline slots, by base address. reserved
	// holds the island addresses that a pending mm.MMap call creates.
	islands  map[uint64]*island
	reserved map[uint64]struct{}

	// patchedBlocks counts blocks that the Sentry patched.
	patchedBlocks atomic.Uint64
}

// stubView performs the window map calls on one stub process.
type stubView struct{ proc windows.Handle }

func winProtect(p viewProt) uint32 {
	switch p {
	case viewRead:
		return windows.PAGE_READONLY
	case viewReadWrite:
		return windows.PAGE_READWRITE
	case viewReadExec:
		return windows.PAGE_EXECUTE_READ
	case viewReadWriteExec:
		return windows.PAGE_EXECUTE_READWRITE
	}
	return windows.PAGE_NOACCESS
}

func (v stubView) SplitPlaceholder(addr, size uint64) error {
	return splitPlaceholder(v.proc, uintptr(addr), uintptr(size))
}

func (v stubView) CoalescePlaceholders(addr, size uint64) error {
	return coalescePlaceholders(v.proc, uintptr(addr), uintptr(size))
}

func (v stubView) MapView(addr, size uint64, backing viewBacking, off uint64, prot viewProt) error {
	ref := backing.(*sectionRef)
	err := mapViewIntoPlaceholder(ref.h, v.proc, uintptr(addr), uintptr(size), off, winProtect(prot))
	if err == nil || (prot != viewReadExec && prot != viewReadWriteExec) {
		return err
	}
	// A view that asks for execute directly can fail on some builds. The
	// documented sequence maps the view as read-write-execute and lowers it.
	if err2 := mapViewIntoPlaceholder(ref.h, v.proc, uintptr(addr), uintptr(size), off, windows.PAGE_EXECUTE_READWRITE); err2 != nil {
		return fmt.Errorf("%w (second attempt: %v)", err, err2)
	}
	if prot == viewReadExec {
		return v.ProtectView(addr, size, prot)
	}
	return nil
}

func (v stubView) UnmapView(addr uint64) error {
	return unmapViewToPlaceholder(v.proc, uintptr(addr))
}

func (v stubView) ProtectView(addr, size uint64, prot viewProt) error {
	var old uint32
	if err := windows.VirtualProtectEx(v.proc, uintptr(addr), uintptr(size), winProtect(prot), &old); err != nil {
		return fmt.Errorf("VirtualProtectEx(%#x+%#x): %w", addr, size, err)
	}
	return nil
}

func newAddressSpace(p *Platform) (*addressSpace, error) {
	sp, err := p.newStubProc()
	if err != nil {
		return nil, fmt.Errorf("create a stub process: %w", err)
	}
	wins := []*windowMap{newWindowMap(stubView{sp.proc}, winBase, winLimit)}
	if p.lowWindow {
		wins = append(wins, newWindowMap(stubView{sp.proc}, lowBase, lowLimit))
	}
	as := &addressSpace{
		p:        p,
		sp:       sp,
		win:      newGuestWindows(wins...),
		blocks:   make(map[uint64]*execBlock),
		copies:   make(map[uint64]*copyHold),
		islands:  make(map[uint64]*island),
		reserved: make(map[uint64]struct{}),
	}
	sp.owner.Store(as)
	pagesStart := time.Now()
	defer func() { bringUpStats.pagesNs.Add(uint64(time.Since(pagesStart))) }()
	if err := as.setupInternal(); err != nil {
		sp.destroy()
		return nil, fmt.Errorf("map the engine pages of the stub: %w", err)
	}
	return as, nil
}

// setupInternal maps the engine pages: one page of code and the pages of the
// per-thread data slots. The arch file writes the code.
func (as *addressSpace) setupInternal() error {
	sec, err := newAnonSection(winEnginePagesSize)
	if err != nil {
		return err
	}
	as.internal = sec
	as.sp.internal = sec
	writeInternalCode(sec.local[:codeSize])
	if as.p.fast {
		copy(sec.local[winSpillOffset:], as.p.spill.code)
	}
	if err := as.win.Map(internalBase, codeSize, &sec.ref, 0, viewReadExec); err != nil {
		return err
	}
	if err := as.win.Map(internalBase+codeSize, winEnginePagesSize-codeSize, &sec.ref, codeSize, viewReadWrite); err != nil {
		return err
	}
	return flushInstructionCache(as.sp.proc, uintptr(internalBase), codeSize)
}

// viewProtFor converts guest access to the protection of an original frame.
// An original frame never allows execute.
func viewProtFor(at hostarch.AccessType) viewProt {
	switch {
	case at.Write:
		return viewReadWrite
	case at.Read || at.Execute:
		return viewRead
	}
	return viewNone
}

// MapFile implements platform.AddressSpace.MapFile.
func (as *addressSpace) MapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) (err error) {
	if traceEvents {
		defer func() {
			if err != nil {
				tracef("MapFile %#x %v %v: %v", uint64(addr), fr, at, err)
			}
		}()
	}
	guest := uint64(addr)
	if err := checkAligned("map", guest, fr.Length()); err != nil {
		return err
	}
	if fr.Start%blockSize != 0 {
		return &AlignmentError{Op: "map memory file range", Addr: fr.Start, Len: fr.Length()}
	}
	if guest < as.p.userMin || guest+fr.Length() > as.p.userMax {
		return fmt.Errorf("mapping [%#x, %#x) lies outside the guest range [%#x, %#x)", guest, guest+fr.Length(), as.p.userMin, as.p.userMax)
	}
	if as.sp.dead.Load() {
		return as.sp.deathError()
	}
	if skip, err := as.islandRange(guest, fr.Length()); skip || err != nil {
		// The memory manager populates the sealed mapping of a trampoline
		// island like any other mapping. The island keeps its own private page.
		return err
	}
	// A file with a host handle maps through a section of that file. Any other
	// file, such as a workspace file of hostfs, maps through a copy of its
	// bytes, which serves a mapping without write permission.
	var sec *sectionRef
	var copied *anonSection
	if fd := f.FD(); fd >= 0 {
		var err error
		if sec, err = as.p.sections.get(windows.Handle(fd), fr.End, at.Write); err != nil {
			sec = nil
			if at.Write {
				return fmt.Errorf("map a writable range of the memory file: %w", err)
			}
		}
	} else if at.Write {
		return fmt.Errorf("the file has no host handle and cannot map writable: %w", unix.ENODEV)
	}
	if sec == nil {
		var err error
		if copied, err = copyRange(f, fr); err != nil {
			return err
		}
		sec = &copied.ref
	}
	secOff := fr.Start
	if copied != nil {
		secOff = 0
	}
	var srcs []uint64
	if at.Execute {
		// The patcher reads the original frames through the Sentry mapping.
		bs, err := f.MapInternal(fr, hostarch.AccessType{Read: true})
		if err != nil {
			if copied != nil {
				copied.close()
			}
			return fmt.Errorf("map the memory file range %v for the patcher: %w", fr, err)
		}
		for ; !bs.IsEmpty(); bs = bs.Tail() {
			b := bs.Head()
			n := uint64(b.Len())
			if n%blockSize != 0 || uint64(uintptr(b.Addr()))%blockSize != 0 {
				if copied != nil {
					copied.close()
				}
				return &AlignmentError{Op: "map memory file range", Addr: uint64(uintptr(b.Addr())), Len: n}
			}
			for off := uint64(0); off < n; off += blockSize {
				srcs = append(srcs, uint64(uintptr(b.Addr()))+off)
			}
		}
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released {
		if copied != nil {
			copied.close()
		}
		return errAddressSpaceReleased
	}
	// keep marks the blocks that an earlier call mapped from the same frame at
	// the same file offset with the same access. The memory manager maps a whole
	// mapping at each fault, so most blocks of the range are already mapped. A
	// patched block holds a copy, a table of sites, and island slots. A new
	// mapping would drop them while a thread of the guest can still trap at a
	// site of the block.
	nblk := int(fr.Length() / blockSize)
	keep := make([]bool, nblk)
	if at.Execute && copied == nil {
		for i := range keep {
			old := as.blocks[guest+uint64(i)*blockSize]
			keep[i] = old != nil && old.src == srcs[i] && old.srcOff == secOff+uint64(i)*blockSize && old.at == at
		}
	}
	for i := 0; i < nblk; {
		if keep[i] {
			i++
			continue
		}
		j := i
		for j < nblk && !keep[j] {
			j++
		}
		start, length := guest+uint64(i)*blockSize, uint64(j-i)*blockSize
		if err := as.win.Map(start, length, sec, secOff+uint64(i)*blockSize, viewProtFor(at)); err != nil {
			if copied != nil {
				copied.close()
			}
			return as.mapErr(fmt.Errorf("map [%#x, %#x): %w", start, start+length, err))
		}
		i = j
	}
	var hold *copyHold
	if copied != nil {
		hold = &copyHold{sec: copied, refs: nblk}
	}
	for i := range nblk {
		if keep[i] {
			continue
		}
		base := guest + uint64(i)*blockSize
		as.dropBlockLocked(base)
		as.dropCopyLocked(base)
		if hold != nil {
			as.copies[base] = hold
		}
		if at.Execute {
			as.blocks[base] = &execBlock{base: base, src: srcs[i], srcSec: sec, srcOff: secOff + uint64(i)*blockSize, at: at, state: blockData}
		}
	}
	return nil
}

// mapErr reports a dead stub as such.
func (as *addressSpace) mapErr(err error) error {
	if as.sp.dead.Load() {
		return as.sp.deathError()
	}
	return err
}

// dropBlockLocked forgets the exec state of one block and frees its copy.
func (as *addressSpace) dropBlockLocked(base uint64) {
	if blk, ok := as.blocks[base]; ok {
		freeSlotRefsLocked(blk.slots)
		blk.slots = nil
		if blk.hasPriv {
			as.p.priv.release(blk.priv)
		}
		delete(as.blocks, base)
	}
}

// dropCopyLocked releases one block reference to a copied section and closes
// the section when no block maps it any more.
func (as *addressSpace) dropCopyLocked(base uint64) {
	if hold, ok := as.copies[base]; ok {
		delete(as.copies, base)
		hold.refs--
		if hold.refs == 0 {
			hold.sec.close()
		}
	}
}

// Unmap implements platform.AddressSpace.Unmap. A range that is not page
// aligned unmaps whole pages around it, which can only remove more than the
// request and never leaves access that the memory manager revoked.
func (as *addressSpace) Unmap(addr hostarch.Addr, length uint64) {
	start := blockRound(uint64(addr))
	end := (uint64(addr) + length + blockSize - 1) &^ (blockSize - 1)
	start = max(start, as.p.userMin)
	end = min(end, as.p.userMax)
	if end <= start {
		return
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if as.released || as.sp.dead.Load() {
		return
	}
	if err := as.win.Unmap(start, end-start); err != nil && !as.sp.dead.Load() {
		// Windows rejects only a malformed range or a broken window here. Both
		// are Sentry bugs, and a stale mapping would expose freed memory.
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
	if (end-start)/blockSize > uint64(len(as.copies)) {
		for base := range as.copies {
			if base >= start && base < end {
				as.dropCopyLocked(base)
			}
		}
	} else {
		for base := start; base < end; base += blockSize {
			as.dropCopyLocked(base)
		}
	}
	as.dropIslandsLocked(start, end)
}

// Release implements platform.AddressSpace.Release.
func (as *addressSpace) Release() {
	as.mu.Lock()
	if as.released {
		as.mu.Unlock()
		return
	}
	as.released = true
	as.mu.Unlock()

	// Terminating the process stops every thread, so no stub thread touches
	// the pages that go back to the pool below.
	as.sp.destroy()
	as.sp.closeFast()
	as.mu.Lock()
	defer as.mu.Unlock()
	for base := range as.blocks {
		as.dropBlockLocked(base)
	}
	if as.internal != nil {
		as.internal.close()
		as.internal = nil
	}
	for base := range as.copies {
		as.dropCopyLocked(base)
	}
	as.releaseIslandsLocked()
}

// ----- lazy patching ------------------------------------------------------

// patchBlock patches the block that holds addr and maps the patched copy as
// read and execute. It runs on the task goroutine, which is allowed to call
// into the memory manager.
func (as *addressSpace) patchBlock(ctx context.Context, mm platform.MemoryManager, addr uint64) error {
	as.patchMu.Lock()
	defer as.patchMu.Unlock()
	base := blockRound(addr)
	for attempt := 0; attempt < 4; attempt++ {
		err := as.patchBlockOnce(ctx, mm, base)
		if !errors.Is(err, errPatchRaced) {
			return err
		}
	}
	return errPatchRaced
}

// neighborBytes returns the Sentry copy of up to n bytes at the edge of the
// exec block next to base. before selects the block under base.
func (as *addressSpace) neighborBytes(base uint64, before bool, n int) []byte {
	as.mu.Lock()
	defer as.mu.Unlock()
	nb := base + blockSize
	if before {
		nb = base - blockSize
	}
	blk := as.blocks[nb]
	if blk == nil {
		return nil
	}
	page := blk.frame()
	if page == nil {
		return nil
	}
	var out []byte
	if before {
		out = page[blockSize-n:]
	} else {
		out = page[:n]
	}
	return append([]byte(nil), out...)
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
	readOnly := !blk.at.Write && src != 0
	as.mu.Unlock()

	// The guest can write the original frame while this copy runs when the
	// block allows writes. The patched copy then holds a torn image, but the
	// guest has no promise about code that it modifies while it executes it.
	orig := unsafe.Slice((*byte)(addrPtr(src)), blockSize)
	copyBuf := make([]byte, blockSize)
	copy(copyBuf, orig)
	var sites map[uint16]siteInfo
	var slots []winSlotRef
	// A page that an earlier scan found clean needs no scan again. The cache
	// holds the digest of the scanned bytes, and a hit needs the same digest.
	// The address alone is no key: the memory file reuses a frame for other
	// content, and the guest can write the frame through another mapping.
	var digest [sha256.Size]byte
	cleanHit := false
	if readOnly {
		digest = sha256.Sum256(copyBuf)
		if v, ok := as.p.cleanCode.Load(src); ok {
			cleanHit = v.([sha256.Size]byte) == digest
		}
	}
	if !cleanHit {
		var err error
		sites, slots, err = as.patchPage(ctx, mm, base, copyBuf)
		if err != nil {
			return err
		}
		if readOnly && len(sites) == 0 && len(slots) == 0 && cleanBoundarySafe(copyBuf) && bytes.Equal(copyBuf, orig) {
			as.p.cleanCode.Store(src, digest)
		}
	}

	pg, err := as.p.priv.alloc()
	if err != nil {
		as.mu.Lock()
		freeSlotRefsLocked(slots)
		as.mu.Unlock()
		return err
	}
	copy(pg.bytes(), copyBuf)
	if err := flushInstructionCache(windows.CurrentProcess(), uintptr(unsafe.Pointer(&pg.bytes()[0])), blockSize); err != nil {
		as.p.priv.release(pg)
		as.mu.Lock()
		freeSlotRefsLocked(slots)
		as.mu.Unlock()
		return err
	}

	as.mu.Lock()
	defer as.mu.Unlock()
	if cur := as.blocks[base]; as.released || cur != blk || blk.state != blockData || blk.src != src {
		freeSlotRefsLocked(slots)
		as.p.priv.release(pg)
		return errPatchRaced
	}
	if err := as.win.Map(base, blockSize, &pg.chunk.ref, pg.off, viewReadExec); err != nil {
		freeSlotRefsLocked(slots)
		as.p.priv.release(pg)
		return as.mapErr(err)
	}
	if err := flushInstructionCache(as.sp.proc, uintptr(base), blockSize); err != nil {
		freeSlotRefsLocked(slots)
		return err
	}
	blk.priv, blk.hasPriv = pg, true
	blk.state = blockExec
	blk.sites = sites
	blk.slots = slots
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
	if err := as.win.Map(base, blockSize, blk.srcSec, blk.srcOff, viewProtFor(blk.at)); err != nil {
		return false, as.mapErr(err)
	}
	freeSlotRefsLocked(blk.slots)
	blk.slots = nil
	as.p.priv.release(blk.priv)
	blk.priv, blk.hasPriv = privPage{}, false
	blk.state = blockData
	blk.sites = nil
	return true, nil
}

// siteAt returns the description of the patched instruction at guest address
// a, if the block of a is an executable copy that has one there.
func (as *addressSpace) siteAt(a uint64) (siteInfo, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[blockRound(a)]
	if blk == nil || blk.state != blockExec {
		return siteInfo{}, false
	}
	s, ok := blk.sites[uint16(a-blk.base)]
	return s, ok
}

// inInternal reports whether a lies in the engine pages.
func inInternal(a uint64) bool { return a >= internalBase && a < internalBase+internalSize }

// codeBytes returns up to n bytes of the original frames at guest address a,
// or nil when the block of a is not an exec block.
func (as *addressSpace) codeBytes(a uint64, n int) []byte {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[blockRound(a)]
	if blk == nil {
		return nil
	}
	page := blk.frame()
	if page == nil {
		return nil
	}
	off := int(a - blk.base)
	out := append([]byte(nil), page[off:min(off+n, blockSize)]...)
	if len(out) < n {
		if next := as.blocks[blk.base+blockSize]; next != nil {
			if np := next.frame(); np != nil {
				out = append(out, np[:n-len(out)]...)
			}
		}
	}
	return out
}

// frame returns the bytes of the block: the original frame, or the patched
// copy for a block that has no memory file frame.
func (blk *execBlock) frame() []byte {
	switch {
	case blk.src != 0:
		return unsafe.Slice((*byte)(addrPtr(blk.src)), blockSize)
	case blk.hasPriv:
		return blk.priv.bytes()
	}
	return nil
}

// cleanBoundarySafe reports whether the first and last 15 bytes of page have
// no opcode bytes that could join a neighbor page to form a patched site.
func cleanBoundarySafe(page []byte) bool {
	const edge = 15
	if len(page) < 2*edge {
		return false
	}
	for _, b := range page[:edge] {
		if b == 0x05 || b == 0x0F || b == 0xAE || b == 0x65 {
			return false
		}
	}
	for _, b := range page[len(page)-edge:] {
		if b == 0x05 || b == 0x0F || b == 0xAE || b == 0x65 {
			return false
		}
	}
	return true
}
