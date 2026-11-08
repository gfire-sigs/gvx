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

//go:build linux

package systrap

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// A host with 16 KB pages cannot map a 4 KB guest page: the address, the
// length, and the file offset of a host mapping must be multiples of the host
// page size. The sub-block layer in this file keeps the guest pages at 4 KB.
// It splits the guest address space into host blocks of 16 KB. Each block
// holds four guest pages that the Sentry maps one by one.
//
// A block maps in one of two ways:
//
//   - Direct. The four guest pages exist, their file ranges are contiguous,
//     the first range starts on a block boundary, and the pages agree on
//     write access. The stub maps the file range itself.
//   - Composite. Any other block maps a private 16 KB page of the platform
//     memory file. The Sentry copies each guest page into it and fills the
//     page of a missing guest page with zeros. The stub maps the composite
//     page without write access, so a guest store into it faults. The Sentry
//     runs the store for the guest (substore_xplat_arm64.go).
//
// Execute access is the union of the pages of a block: a block maps with
// execute access when one page has it. A data page that shares a block with
// code is executable, and a page without any access that shares a block with
// a mapped page reads as zeros. A 16 KB host page cannot do better.

const (
	// subBlockSize is the size of a host block.
	subBlockSize = 0x4000
	// subPagesPerBlock is the number of guest pages in a host block.
	subPagesPerBlock = subBlockSize / hostarch.PageSize
	// allSubPages is the mask of every guest page in a block.
	allSubPages = 1<<subPagesPerBlock - 1
)

// subBlocksForced makes the layer work on a host with 4 KB pages. Only tests
// set it, before they create a platform.
var subBlocksForced bool

// subBlocksEnabled reports whether address spaces use the sub-block layer.
func subBlocksEnabled() bool {
	return hostPageSize > hostarch.PageSize || subBlocksForced
}

// errSubBlockHostPage reports a host page that is larger than a host block.
var errSubBlockHostPage = errors.New("the host page size is larger than 16 KB")

// checkSubBlockHost returns an error when the host page does not divide a
// host block.
func checkSubBlockHost() error {
	if hostPageSize > subBlockSize {
		return fmt.Errorf("%w: %d bytes", errSubBlockHostPage, hostPageSize)
	}
	return nil
}

// subBlockBase returns the address of the block that holds addr.
func subBlockBase(addr uintptr) uintptr {
	return addr &^ (subBlockSize - 1)
}

// compPage is a composite page: a block-sized range of the platform memory
// file, and the mapping of the Sentry for it.
type compPage struct {
	fr  memmap.FileRange
	buf []byte
}

// blockHost is the stub side of the layer.
type blockHost interface {
	// mapRange maps length bytes of the file descriptor at addr in the stub,
	// from file offset off. It replaces what the stub maps there.
	mapRange(addr, length uintptr, prot int, populate bool, fd int, off uint64) error
	// unmapRange removes the mappings of the stub in [addr, addr+length).
	unmapRange(addr, length uintptr) error
	// allocComp returns a zeroed composite page.
	allocComp() (compPage, error)
	// freeComp frees a composite page that no stub mapping uses.
	freeComp(c compPage)
	// compFD returns the descriptor of the file that holds composite pages.
	compFD() int
}

// subPage is one guest page of a block.
type subPage struct {
	// f is the file that holds the page, or nil when the page is not mapped.
	f memmap.File
	// off is the offset of the page in f, and fd is the descriptor for it.
	off uint64
	fd  int32
	at  hostarch.AccessType
	// src is the mapping of the Sentry for the page. It is nil until a
	// composite page needs it.
	src []byte
}

// bytes returns the mapping of the Sentry for the page.
func (sp *subPage) bytes() ([]byte, error) {
	if sp.src != nil {
		return sp.src, nil
	}
	at := hostarch.Read
	if sp.at.Write {
		at = hostarch.Write
	}
	bs, err := sp.f.MapInternal(memmap.FileRange{Start: sp.off, End: sp.off + hostarch.PageSize}, at)
	if err != nil {
		return nil, fmt.Errorf("map the memory file page at %#x: %w", sp.off, err)
	}
	if bs.NumBlocks() != 1 || bs.Head().Len() != hostarch.PageSize {
		return nil, fmt.Errorf("the memory file page at %#x has %d mappings", sp.off, bs.NumBlocks())
	}
	sp.src = bs.Head().ToSlice()
	return sp.src, nil
}

// stubMap is what the stub maps for a block.
type stubMap struct {
	kind stubMapKind
	// off is the offset of the mapping in its file.
	off  uint64
	prot int
}

type stubMapKind uint8

const (
	stubMapNone stubMapKind = iota
	stubMapDirect
	stubMapComp
)

// hostBlock tracks the guest pages of one host block.
type hostBlock struct {
	subs [subPagesPerBlock]subPage

	// mapped, exec, and write have a bit for each guest page that is mapped,
	// that allows execution, and that allows writes.
	mapped, exec, write uint8

	cur     stubMap
	comp    compPage
	hasComp bool
}

// recompute updates the masks from the guest pages.
func (hb *hostBlock) recompute() {
	hb.mapped, hb.exec, hb.write = 0, 0, 0
	for i := range hb.subs {
		sp := &hb.subs[i]
		if sp.f == nil {
			continue
		}
		bit := uint8(1) << i
		hb.mapped |= bit
		if sp.at.Execute {
			hb.exec |= bit
		}
		if sp.at.Write {
			hb.write |= bit
		}
	}
}

// direct returns the file offset that the stub can map for the whole block,
// and false when the block needs a composite page.
func (hb *hostBlock) direct() (uint64, bool) {
	if hb.mapped != allSubPages || (hb.write != 0 && hb.write != allSubPages) {
		return 0, false
	}
	first := &hb.subs[0]
	if first.off%subBlockSize != 0 {
		return 0, false
	}
	for i := 1; i < subPagesPerBlock; i++ {
		sp := &hb.subs[i]
		if sp.f != first.f || sp.fd != first.fd || sp.off != first.off+uint64(i)*hostarch.PageSize {
			return 0, false
		}
	}
	return first.off, true
}

// blockProt returns the protection of the stub mapping. A composite page never
// has write access, so that a store faults.
func (hb *hostBlock) blockProt(direct bool) int {
	prot := unix.PROT_READ
	if direct && hb.write != 0 {
		prot |= unix.PROT_WRITE
	}
	if hb.exec != 0 {
		prot |= unix.PROT_EXEC
	}
	return prot
}

// syncComp copies the guest pages into the composite page. A page that is not
// mapped reads as zeros. It writes a word of the composite page only when the
// word differs, so that an unchanged page keeps its cache lines.
func (hb *hostBlock) syncComp() error {
	for i := range hb.subs {
		dst := hb.comp.buf[i*hostarch.PageSize : (i+1)*hostarch.PageSize]
		sp := &hb.subs[i]
		if sp.f == nil {
			clear(dst)
			continue
		}
		src, err := sp.bytes()
		if err != nil {
			return err
		}
		if !bytes.Equal(dst, src) {
			copy(dst, src)
		}
	}
	return nil
}

// subBlockLayer maps guest pages of 4 KB into the stub on a host with larger
// pages.
type subBlockLayer struct {
	host blockHost

	// pending counts the blocks in partial and comps. beforeSwitch returns
	// at once when it is zero.
	pending atomic.Int32

	mu sync.Mutex
	// blocks holds the blocks that have a guest page.
	blocks map[uintptr]*hostBlock
	// partial holds the blocks that miss a guest page and that the next
	// switch tries to populate.
	partial map[uintptr]struct{}
	// comps holds the blocks that map a composite page.
	comps map[uintptr]*hostBlock
}

func newSubBlockLayer(host blockHost) *subBlockLayer {
	return &subBlockLayer{
		host:    host,
		blocks:  make(map[uintptr]*hostBlock),
		partial: make(map[uintptr]struct{}),
		comps:   make(map[uintptr]*hostBlock),
	}
}

// updatePendingLocked publishes the number of blocks that beforeSwitch visits.
func (l *subBlockLayer) updatePendingLocked() {
	l.pending.Store(int32(len(l.partial) + len(l.comps)))
}

// mapFile maps [addr, addr+fr.Length()) of f.
func (l *subBlockLayer) mapFile(addr hostarch.Addr, f memmap.File, fr memmap.FileRange, at hostarch.AccessType, precommit bool) error {
	fd, err := f.DataFD(fr)
	if err != nil {
		return err
	}
	va := uintptr(addr)
	end := va + uintptr(fr.Length())
	off := fr.Start
	if va%hostarch.PageSize != 0 || end%hostarch.PageSize != 0 || off%hostarch.PageSize != 0 || va >= end {
		return fmt.Errorf("map [%#x, %#x) from offset %#x: the range is not aligned to guest pages", va, end, off)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.updatePendingLocked()
	src := subPage{f: f, fd: int32(fd), at: at}
	// The head and the tail share a block with other ranges. The blocks in
	// the middle belong to this range only.
	headEnd := min(end, (va+subBlockSize-1)&^(subBlockSize-1))
	midEnd := max(headEnd, end&^(subBlockSize-1))
	if err := l.setPagesLocked(va, headEnd, off, src); err != nil {
		return err
	}
	if headEnd < midEnd {
		midOff := off + uint64(headEnd-va)
		if err := l.mapBlocksLocked(headEnd, midEnd, midOff, src, precommit); err != nil {
			return err
		}
	}
	return l.setPagesLocked(midEnd, end, off+uint64(midEnd-va), src)
}

// setPagesLocked records the guest pages in [va, end) of one block, which
// come from src at file offset off, and maps the block again. The range may be
// empty.
func (l *subBlockLayer) setPagesLocked(va, end uintptr, off uint64, src subPage) error {
	if va >= end {
		return nil
	}
	base := subBlockBase(va)
	hb := l.blocks[base]
	if hb == nil {
		hb = &hostBlock{}
		l.blocks[base] = hb
	}
	for p := va; p < end; p += hostarch.PageSize {
		sp := src
		sp.off = off + uint64(p-va)
		hb.subs[(p-base)/hostarch.PageSize] = sp
	}
	return l.refreshLocked(base, hb)
}

// mapBlocksLocked maps the whole blocks in [start, end) from file offset off.
func (l *subBlockLayer) mapBlocksLocked(start, end uintptr, off uint64, src subPage, precommit bool) error {
	if off%subBlockSize != 0 {
		// The source is not aligned: every block needs a composite page.
		for base := start; base < end; base += subBlockSize {
			hb := l.blocks[base]
			if hb == nil {
				hb = &hostBlock{}
				l.blocks[base] = hb
			}
			for i := range hb.subs {
				sp := src
				sp.off = off + uint64(base-start) + uint64(i)*hostarch.PageSize
				hb.subs[i] = sp
			}
			if err := l.refreshLocked(base, hb); err != nil {
				return err
			}
		}
		return nil
	}
	// One mapping covers the whole range.
	run := &hostBlock{}
	for i := range run.subs {
		run.subs[i] = src
		run.subs[i].off = off + uint64(i)*hostarch.PageSize
	}
	run.recompute()
	prot := run.blockProt(true)
	if err := l.host.mapRange(start, end-start, prot, precommit, int(src.fd), off); err != nil {
		return fmt.Errorf("map [%#x, %#x): %w", start, end, err)
	}
	for base := start; base < end; base += subBlockSize {
		hb := l.blocks[base]
		if hb == nil {
			hb = &hostBlock{}
			l.blocks[base] = hb
		}
		blockOff := off + uint64(base-start)
		for i := range hb.subs {
			sp := src
			sp.off = blockOff + uint64(i)*hostarch.PageSize
			hb.subs[i] = sp
		}
		hb.recompute()
		hb.cur = stubMap{kind: stubMapDirect, off: blockOff, prot: prot}
		l.freeCompLocked(base, hb)
		delete(l.partial, base)
	}
	return nil
}

// refreshLocked updates the stub mapping of a block to its guest pages.
func (l *subBlockLayer) refreshLocked(base uintptr, hb *hostBlock) error {
	hb.recompute()
	if hb.mapped == 0 {
		return l.dropBlockLocked(base, hb)
	}
	if hb.mapped == allSubPages {
		delete(l.partial, base)
	} else {
		l.partial[base] = struct{}{}
	}
	if off, ok := hb.direct(); ok {
		want := stubMap{kind: stubMapDirect, off: off, prot: hb.blockProt(true)}
		if hb.cur != want {
			if err := l.host.mapRange(base, subBlockSize, want.prot, false, int(hb.subs[0].fd), off); err != nil {
				return fmt.Errorf("map [%#x, %#x): %w", base, base+subBlockSize, err)
			}
			hb.cur = want
		}
		l.freeCompLocked(base, hb)
		return nil
	}
	if !hb.hasComp {
		comp, err := l.host.allocComp()
		if err != nil {
			return fmt.Errorf("allocate a composite page for [%#x, %#x): %w", base, base+subBlockSize, err)
		}
		hb.comp, hb.hasComp = comp, true
	}
	if err := hb.syncComp(); err != nil {
		return fmt.Errorf("fill the composite page for [%#x, %#x): %w", base, base+subBlockSize, err)
	}
	l.comps[base] = hb
	want := stubMap{kind: stubMapComp, off: hb.comp.fr.Start, prot: hb.blockProt(false)}
	if hb.cur != want {
		if err := l.host.mapRange(base, subBlockSize, want.prot, false, l.host.compFD(), want.off); err != nil {
			return fmt.Errorf("map [%#x, %#x): %w", base, base+subBlockSize, err)
		}
		hb.cur = want
	}
	return nil
}

// freeCompLocked frees the composite page of a block that the stub no longer
// maps.
func (l *subBlockLayer) freeCompLocked(base uintptr, hb *hostBlock) {
	delete(l.comps, base)
	if hb.hasComp {
		l.host.freeComp(hb.comp)
		hb.comp, hb.hasComp = compPage{}, false
	}
}

// dropBlockLocked removes a block without guest pages.
func (l *subBlockLayer) dropBlockLocked(base uintptr, hb *hostBlock) error {
	var err error
	if hb.cur.kind != stubMapNone {
		err = l.host.unmapRange(base, subBlockSize)
	}
	hb.cur = stubMap{}
	l.freeCompLocked(base, hb)
	delete(l.partial, base)
	delete(l.blocks, base)
	return err
}

// unmap removes [addr, addr+length). A failure other than the death of the
// stub is a bug.
func (l *subBlockLayer) unmap(addr hostarch.Addr, length uint64) {
	va := uintptr(addr) &^ (hostarch.PageSize - 1)
	end := (uintptr(addr) + uintptr(length) + hostarch.PageSize - 1) &^ (hostarch.PageSize - 1)
	if va >= end {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.updatePendingLocked()
	headEnd := min(end, (va+subBlockSize-1)&^(subBlockSize-1))
	midEnd := max(headEnd, end&^(subBlockSize-1))
	l.clearPagesLocked(va, headEnd)
	if headEnd < midEnd {
		if err := l.host.unmapRange(headEnd, midEnd-headEnd); err != nil && !errors.Is(err, errDeadSubprocess) {
			panic(fmt.Sprintf("munmap(%#x, %#x) failed: %v", headEnd, midEnd-headEnd, err))
		}
		l.forgetBlocksLocked(headEnd, midEnd)
	}
	l.clearPagesLocked(midEnd, end)
}

// clearPagesLocked removes the guest pages in [va, end) of one block. The
// range may be empty.
func (l *subBlockLayer) clearPagesLocked(va, end uintptr) {
	if va >= end {
		return
	}
	base := subBlockBase(va)
	hb := l.blocks[base]
	if hb == nil {
		return
	}
	for p := va; p < end; p += hostarch.PageSize {
		hb.subs[(p-base)/hostarch.PageSize] = subPage{}
	}
	if err := l.refreshLocked(base, hb); err != nil && !errors.Is(err, errDeadSubprocess) {
		log.Warningf("systrap: update the block at %#x after an unmap: %v", base, err)
	}
}

// forgetBlocksLocked drops the records of the whole blocks in [start, end)
// after the stub unmapped them.
func (l *subBlockLayer) forgetBlocksLocked(start, end uintptr) {
	forget := func(base uintptr, hb *hostBlock) {
		hb.cur = stubMap{}
		l.freeCompLocked(base, hb)
		delete(l.partial, base)
		delete(l.blocks, base)
	}
	if n := (end - start) / subBlockSize; n > uintptr(len(l.blocks)) {
		for base, hb := range l.blocks {
			if base >= start && base < end {
				forget(base, hb)
			}
		}
		return
	}
	for base := start; base < end; base += subBlockSize {
		if hb := l.blocks[base]; hb != nil {
			forget(base, hb)
		}
	}
}

// reset forgets every block. The caller unmapped the stub already.
func (l *subBlockLayer) reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for base, hb := range l.blocks {
		hb.cur = stubMap{}
		l.freeCompLocked(base, hb)
	}
	clear(l.blocks)
	clear(l.partial)
	clear(l.comps)
	l.updatePendingLocked()
}

// beforeSwitch prepares the blocks before a thread of the address space runs.
// It populates the guest pages that a mapped block misses, so that the guest
// does not read zeros where memory exists. Then it copies the guest pages into
// the composite pages, because the Sentry or another address space can change
// a page that the stub reads through a copy.
func (l *subBlockLayer) beforeSwitch(ctx context.Context, mm platform.MemoryManager) {
	if l.pending.Load() == 0 {
		return
	}
	if pop, ok := mm.(platform.SubBlockPopulator); ok {
		l.populatePartial(ctx, pop)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for base, hb := range l.comps {
		if err := hb.syncComp(); err != nil {
			log.Warningf("systrap: refresh the composite page at %#x: %v", base, err)
		}
	}
}

// populatePartial asks the memory manager to map the guest pages that blocks
// miss. A block is checked once after each change of it.
func (l *subBlockLayer) populatePartial(ctx context.Context, pop platform.SubBlockPopulator) {
	var addrs []hostarch.Addr
	l.mu.Lock()
	for base := range l.partial {
		hb := l.blocks[base]
		for i := range hb.subs {
			if hb.subs[i].f == nil {
				addrs = append(addrs, hostarch.Addr(base+uintptr(i)*hostarch.PageSize))
			}
		}
	}
	clear(l.partial)
	l.updatePendingLocked()
	l.mu.Unlock()
	if len(addrs) == 0 {
		return
	}
	for _, addr := range addrs {
		pop.PopulateSubBlock(ctx, addr)
	}
	// A populate that maps only some pages queues the block again. The next
	// change of the block checks it, so that a block next to unmapped memory
	// does not cost a check for each switch.
	l.mu.Lock()
	for _, addr := range addrs {
		delete(l.partial, subBlockBase(uintptr(addr)))
	}
	l.updatePendingLocked()
	l.mu.Unlock()
}
