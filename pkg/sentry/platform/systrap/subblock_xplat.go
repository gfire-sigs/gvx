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
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/platform"
)

// A host with 16 KB pages cannot map a 4 KB guest page. The address, the
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
// code is executable. A page without any access that shares a block with a
// mapped page reads as zeros. A 16 KB host page cannot do better.
//
// A composite page holds copies. A write that does not pass through the layer
// must therefore refresh it. beforeSwitch refreshes the guest-writable pages
// of a composite page on each switch, because another address space can share
// them. It refreshes a read-only page in three cases. In the first case, the
// memory file reports a Sentry write into it
// (pgalloc.MemoryFile.ObserveHostWrites). In the second case, a guest store
// that any layer ran through a composite block changed it
// (pgalloc.MemoryFile.NoteHostWrite). In the third case, a writable direct
// block of the same address space maps it, and beforeSwitch then refreshes the
// page on each switch. A guest store through a writable direct mapping of
// another address space does not reach a read-only page of a composite page.
// The page stays stale until the next change of the block.

const (
	// subBlockSize is the size of a host block.
	subBlockSize = 0x4000
	// subPagesPerBlock is the number of guest pages in a host block.
	subPagesPerBlock = subBlockSize / hostarch.PageSize
	// allSubPages is the mask of every guest page in a block.
	allSubPages = 1<<subPagesPerBlock - 1
)

// subBlocksForced makes the layer work on a host with 4 KB pages. CI on such a
// host then runs the code of a 16 KB host. GVX_SYSTRAP_SUBBLOCKS=1 sets it for
// the whole process. AGENTS.md lists the variable for CI use only.
var subBlocksForced = os.Getenv("GVX_SYSTRAP_SUBBLOCKS") == "1"

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
	fr := memmap.FileRange{Start: sp.off, End: sp.off + hostarch.PageSize}
	var bs safemem.BlockSeq
	var err error
	// MapInternal would report a write on every composite refresh that maps a
	// guest-writable page, so bytes uses MapInternalUnreported; writeLocked
	// reports emulated guest stores with NoteHostWrite.
	if u, ok := sp.f.(interface {
		MapInternalUnreported(memmap.FileRange, hostarch.AccessType) (safemem.BlockSeq, error)
	}); ok {
		bs, err = u.MapInternalUnreported(fr, at)
	} else {
		bs, err = sp.f.MapInternal(fr, at)
	}
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
	// off is the offset of the mapping in its file, and fd is its descriptor.
	off  uint64
	fd   int
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

	// wseq holds, for each guest page, the sequence number of the last store
	// that the Sentry ran for the guest (substore_xplat.go).
	wseq [subPagesPerBlock]uint64

	// dirty counts the refreshes of the composite page that a Sentry write
	// into a page of the block still asks for. The observer of the memory
	// file sets it without the lock of the layer. Some writers report a
	// write before they copy the bytes, so a write asks for two refreshes:
	// the second comes after the copy (beforeSwitch).
	dirty atomic.Int32
	// alwaysSync makes beforeSwitch refresh the composite page on each switch.
	// rebuildSourcesLocked sets it.
	alwaysSync bool
	// compMapped reports that the stub mapped the composite page at least
	// once, and compExec that the last such mapping allowed execution
	// (mapCompLocked).
	compMapped, compExec bool
}

// dirtyRefreshes is the number of refreshes that a Sentry write asks for.
const dirtyRefreshes = 2

// srcRef is one page of a read-only composite page, by its offset in the
// memory file.
type srcRef struct {
	off uint64
	hb  *hostBlock
}

// needsPopulate reports whether a block that the stub does not map directly
// asks the memory manager for a populate call. A block that misses a guest
// page does. So does a block whose pages are all writable and not executable.
// The memory manager can coalesce the pages of private anonymous memory into
// one file range, and then the block maps directly.
func (hb *hostBlock) needsPopulate(direct bool) bool {
	return !direct && (hb.mapped != allSubPages || (hb.write == allSubPages && hb.exec == 0))
}

// canCoalesce reports whether the memory manager can coalesce the mapped pages
// of a block that misses guest pages: they all allow writes, and none allows
// execution.
func (hb *hostBlock) canCoalesce() bool {
	return hb.mapped != 0 && hb.write == hb.mapped && hb.exec == 0
}

// ownedBlock is a host block of a memory file whose spare pages the layer
// holds (platform.HostBlockOwner). The guest pages of the block come from fr,
// and bit i of spare is set for a spare page at fr.Start + i*PageSize.
type ownedBlock struct {
	f     memmap.File
	fr    memmap.FileRange
	spare uint8
}

// release drops the references of the layer on the spare pages.
func (ob ownedBlock) release() {
	for i := range subPagesPerBlock {
		if ob.spare&(1<<i) != 0 {
			start := ob.fr.Start + uint64(i)*hostarch.PageSize
			ob.f.DecRef(memmap.FileRange{Start: start, End: start + hostarch.PageSize})
		}
	}
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

// directLocked returns the file offset and the descriptor that the stub can
// map for the whole block. It returns false when the block needs a composite
// page. A block that misses guest pages maps directly when the layer holds
// those pages as spare pages, and the other pages allow the same access.
func (l *subBlockLayer) directLocked(base uintptr, hb *hostBlock) (uint64, int, bool) {
	if off, ok := hb.direct(); ok {
		return off, int(hb.subs[0].fd), true
	}
	ob, ok := l.owned[base]
	if !ok || hb.mapped == 0 || hb.exec != 0 || (hb.write != 0 && hb.write != hb.mapped) {
		return 0, 0, false
	}
	fd := -1
	for i := range hb.subs {
		sp := &hb.subs[i]
		if sp.f == nil {
			if ob.spare&(1<<i) == 0 {
				return 0, 0, false
			}
			continue
		}
		if sp.f != ob.f || sp.off != ob.fr.Start+uint64(i)*hostarch.PageSize {
			return 0, 0, false
		}
		if fd < 0 {
			fd = int(sp.fd)
		} else if int(sp.fd) != fd {
			return 0, 0, false
		}
	}
	return ob.fr.Start, fd, true
}

// disownLocked releases the spare pages of a block. The stub must not map
// them any more.
func (l *subBlockLayer) disownLocked(base uintptr) {
	if ob, ok := l.owned[base]; ok {
		delete(l.owned, base)
		ob.release()
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
// mapped reads as zeros. It writes a page of the composite page only when the
// page differs, so that an unchanged page keeps its cache lines. It reports
// whether a page changed.
func (hb *hostBlock) syncComp() (bool, error) {
	return hb.syncCompPages(allSubPages)
}

// syncCompPages is syncComp for the guest pages in mask.
func (hb *hostBlock) syncCompPages(mask uint8) (bool, error) {
	changed := false
	for i := range hb.subs {
		if mask&(1<<i) == 0 {
			continue
		}
		dst := hb.comp.buf[i*hostarch.PageSize : (i+1)*hostarch.PageSize]
		sp := &hb.subs[i]
		var src []byte
		if sp.f != nil {
			var err error
			if src, err = sp.bytes(); err != nil {
				return changed, err
			}
		}
		switch {
		case src == nil && !isZeroPage(dst):
			clear(dst)
		case src != nil && !bytes.Equal(dst, src):
			copy(dst, src)
		default:
			continue
		}
		changed = true
		flushICache(uintptr(unsafe.Pointer(&dst[0])), uintptr(len(dst)))
	}
	return changed, nil
}

// isZeroPage reports whether every byte of p is zero.
func isZeroPage(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// subBlockLayer maps guest pages of 4 KB into the stub on a host with larger
// pages.
type subBlockLayer struct {
	host blockHost

	// pending counts the blocks in partial and comps. beforeSwitch skips the
	// work on the blocks when it is zero.
	pending atomic.Int32

	// storeSeq counts the stores that the Sentry ran for the guest.
	storeSeq atomic.Uint64

	// popMu serializes beforeSwitch across threads so no thread maps a
	// deferred block with zero-filled sub-pages while another thread runs
	// populatePartial without mu.
	popMu sync.Mutex

	mu sync.Mutex
	// blocks holds the blocks that have a guest page.
	blocks map[uintptr]*hostBlock
	// partial holds the blocks that miss a guest page and that the next
	// switch tries to populate.
	partial map[uintptr]struct{}
	// populating is 1 while populatePartial runs without mu, so pending
	// stays positive until beforeSwitch finishes mapping deferred blocks.
	populating int
	// releaseGen counts release calls so populatePartial retries a block
	// when a new guest mapping arrives during PopulateSubBlock.
	releaseGen uint64
	// comps holds the blocks that map a composite page.
	comps map[uintptr]*hostBlock
	// deferred holds the blocks that miss a guest page and that the stub does
	// not map. beforeSwitch maps them after it populates them (refreshLocked).
	deferred map[uintptr]struct{}
	// owned holds the blocks whose spare pages the layer holds.
	owned map[uintptr]ownedBlock
	// refusedLogged records that logRefusedLocked logged a store.
	refusedLogged bool

	// observed holds, for each memory file that backs a composite page, the
	// function that stops the observer of the layer on it.
	observed map[memmap.File]func()
	// immutable caches whether a file without an observer refuses writable
	// internal mappings, as an EROFS image does. Its pages never change.
	immutable map[memmap.File]bool
	// sources holds, for each observed file, the pages of the composite pages
	// at the last rebuild, sorted by offset. It is nil before the first one.
	sources atomic.Pointer[map[memmap.File][]srcRef]
	// recent holds the blocks that refreshLocked filled since the last rebuild
	// of sources, so that a write into them marks them before the rebuild.
	recent atomic.Pointer[[]*hostBlock]
	// sourcesStale reports a change of the blocks since the last rebuild of
	// sources.
	sourcesStale bool
	// allDirty reports a Sentry write that arrived while sources was nil.
	allDirty atomic.Bool
	// changes counts the changes of the stub mappings. A thread that faulted
	// in a block that changed since it resumed runs the instruction again.
	changes atomic.Uint64
}

// newSubBlockLayer returns a layer whose stub side is host.
func newSubBlockLayer(host blockHost) *subBlockLayer {
	return &subBlockLayer{
		host:         host,
		blocks:       make(map[uintptr]*hostBlock),
		partial:      make(map[uintptr]struct{}),
		comps:        make(map[uintptr]*hostBlock),
		deferred:     make(map[uintptr]struct{}),
		owned:        make(map[uintptr]ownedBlock),
		observed:     make(map[memmap.File]func()),
		immutable:    make(map[memmap.File]bool),
		sourcesStale: true,
	}
}

// hostWriteObservable is a memory file that reports the writes of the
// Sentry, such as pgalloc.MemoryFile.
type hostWriteObservable interface {
	ObserveHostWrites(fn func(memmap.FileRange)) (stop func())
}

// noteHostWrite marks the read-only composite pages that hold a page of fr in
// f. The memory file calls it on the writing goroutine, so it takes no lock.
func (l *subBlockLayer) noteHostWrite(f memmap.File, fr memmap.FileRange) {
	p := l.sources.Load()
	if p == nil {
		l.allDirty.Store(true)
		return
	}
	refs := (*p)[f]
	i, _ := slices.BinarySearchFunc(refs, fr.Start, func(r srcRef, start uint64) int {
		return cmp.Compare(r.off+hostarch.PageSize, start+1)
	})
	for ; i < len(refs) && refs[i].off < fr.End; i++ {
		refs[i].hb.dirty.Store(dirtyRefreshes)
	}
	if r := l.recent.Load(); r != nil {
		for _, hb := range *r {
			for j := range hb.subs {
				sp := &hb.subs[j]
				if sp.f == f && sp.off < fr.End && fr.Start < sp.off+hostarch.PageSize {
					hb.dirty.Store(dirtyRefreshes)
					break
				}
			}
		}
	}
}

// observeLocked starts the observer of the layer on f, when f reports Sentry
// writes. It reports whether the pages of f need no refresh on each switch:
// f reports its writes, or f never changes.
func (l *subBlockLayer) observeLocked(f memmap.File) bool {
	if _, ok := l.observed[f]; ok {
		return true
	}
	if o, ok := f.(hostWriteObservable); ok {
		l.observed[f] = o.ObserveHostWrites(func(fr memmap.FileRange) { l.noteHostWrite(f, fr) })
		return true
	}
	ro, ok := l.immutable[f]
	if !ok {
		// A file of an image refuses a writable mapping of any range.
		_, err := f.MapInternal(memmap.FileRange{Start: 0, End: hostarch.PageSize}, hostarch.Write)
		ro = err != nil
		l.immutable[f] = ro
	}
	return ro
}

// stopObserversLocked stops every observer of the layer. rebuildSourcesLocked
// starts them again for the files of the next composite pages.
func (l *subBlockLayer) stopObserversLocked() {
	for f, stop := range l.observed {
		stop()
		delete(l.observed, f)
	}
	clear(l.immutable)
}

// markChangedLocked records a change of the blocks, so that beforeSwitch
// rebuilds sources.
func (l *subBlockLayer) markChangedLocked() {
	l.sourcesStale = true
}

// addRecentLocked adds a block that refreshLocked filled to recent.
func (l *subBlockLayer) addRecentLocked(hb *hostBlock) {
	var next []*hostBlock
	if cur := l.recent.Load(); cur != nil {
		next = append(next, *cur...)
	}
	next = append(next, hb)
	l.recent.Store(&next)
}

// filePage names one page of a file.
type filePage struct {
	f   memmap.File
	off uint64
}

// rebuildSourcesLocked recomputes sources and the alwaysSync flags.
func (l *subBlockLayer) rebuildSourcesLocked() {
	// The pages that a writable direct block maps. A guest store into them
	// does not reach a composite page that holds the same page.
	aliased := make(map[filePage]struct{})
	for _, hb := range l.blocks {
		if hb.cur.kind != stubMapDirect || hb.write == 0 {
			continue
		}
		for i := range hb.subs {
			aliased[filePage{hb.subs[i].f, hb.subs[i].off}] = struct{}{}
		}
	}
	srcs := make(map[memmap.File][]srcRef)
	for _, hb := range l.comps {
		hb.alwaysSync = false
		for i := range hb.subs {
			sp := &hb.subs[i]
			if sp.f == nil {
				continue
			}
			if !l.observeLocked(sp.f) {
				hb.alwaysSync = true
				continue
			}
			if _, ok := aliased[filePage{sp.f, sp.off}]; ok {
				hb.alwaysSync = true
			}
			if _, ok := l.observed[sp.f]; ok {
				srcs[sp.f] = append(srcs[sp.f], srcRef{off: sp.off, hb: hb})
			}
		}
	}
	for _, refs := range srcs {
		slices.SortFunc(refs, func(a, b srcRef) int { return cmp.Compare(a.off, b.off) })
	}
	l.sources.Store(&srcs)
	l.recent.Store(nil)
	l.sourcesStale = false
}

// updatePendingLocked publishes the number of blocks that beforeSwitch visits.
func (l *subBlockLayer) updatePendingLocked() {
	l.pending.Store(int32(len(l.partial) + len(l.comps) + len(l.deferred) + l.populating))
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
	return l.refreshLocked(base, hb, false)
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
			if err := l.refreshLocked(base, hb, false); err != nil {
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
	l.changes.Add(1)
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
		hb.cur = stubMap{kind: stubMapDirect, off: blockOff, fd: int(src.fd), prot: prot}
		l.freeCompLocked(base, hb)
		delete(l.partial, base)
		delete(l.deferred, base)
	}
	return nil
}

// refreshLocked updates the stub mapping of a block to its guest pages.
//
// A block that misses a guest page maps a composite page in which that page
// reads as zeros. The memory manager can still map the missing page, for
// example after a copy on write or a new mapping. Until beforeSwitch asks it
// to populate the page, the stub does not map such a block. An access of a
// running thread faults, and the fault populates the block. beforeSwitch then
// calls refreshLocked with mapPartial set.
func (l *subBlockLayer) refreshLocked(base uintptr, hb *hostBlock, mapPartial bool) error {
	l.markChangedLocked()
	l.changes.Add(1)
	hb.recompute()
	if hb.mapped == 0 {
		return l.dropBlockLocked(base, hb)
	}
	off, fd, isDirect := l.directLocked(base, hb)
	if !isDirect && hb.mapped != allSubPages && !mapPartial {
		if hb.cur.kind != stubMapNone {
			if err := l.host.unmapRange(base, subBlockSize); err != nil {
				return err
			}
			hb.cur = stubMap{}
		}
		// The memory manager maps the pages of a block that it coalesced
		// one range at a time, so the block keeps its spare pages here.
		delete(l.comps, base)
		l.partial[base] = struct{}{}
		l.deferred[base] = struct{}{}
		return nil
	}
	delete(l.deferred, base)
	if hb.needsPopulate(isDirect) && !mapPartial {
		l.partial[base] = struct{}{}
	} else {
		delete(l.partial, base)
	}
	if isDirect {
		want := stubMap{kind: stubMapDirect, off: off, fd: fd, prot: hb.blockProt(true)}
		if hb.cur != want {
			if err := l.host.mapRange(base, subBlockSize, want.prot, false, fd, off); err != nil {
				return fmt.Errorf("map [%#x, %#x): %w", base, base+subBlockSize, err)
			}
			hb.cur = want
		}
		if ob, ok := l.owned[base]; ok && ob.fr.Start != off {
			l.disownLocked(base)
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
	l.addRecentLocked(hb)
	changed, err := hb.syncComp()
	if err != nil {
		return fmt.Errorf("fill the composite page for [%#x, %#x): %w", base, base+subBlockSize, err)
	}
	l.comps[base] = hb
	if err := l.mapCompLocked(base, hb, changed); err != nil {
		return err
	}
	l.disownLocked(base)
	return nil
}

// mapCompLocked maps the composite page of a block into the stub. changed
// reports a change of the composite page since the stub mapped it.
//
// The I-cache of a host CPU can index lines by virtual address. The
// maintenance that the Sentry makes through its own mapping can therefore miss
// the lines of the stub mapping. The host kernel cleans the caches of a page
// that write(2) changed when it maps the page with execute access. A
// composite page goes through write(2) on the memory file if it can run. This
// happens when the page changed or gained execute access since the stub mapped
// it. The stub then maps it again.
func (l *subBlockLayer) mapCompLocked(base uintptr, hb *hostBlock, changed bool) error {
	clean := hb.exec != 0 && (changed || !hb.compExec || !hb.compMapped)
	if clean {
		if _, err := unix.Pwrite(l.host.compFD(), hb.comp.buf, int64(hb.comp.fr.Start)); err != nil {
			return fmt.Errorf("write the composite page for [%#x, %#x): %w", base, base+subBlockSize, err)
		}
	}
	want := stubMap{kind: stubMapComp, off: hb.comp.fr.Start, fd: l.host.compFD(), prot: hb.blockProt(false)}
	if hb.cur != want || clean {
		l.changes.Add(1)
		if err := l.host.mapRange(base, subBlockSize, want.prot, false, l.host.compFD(), want.off); err != nil {
			return fmt.Errorf("map [%#x, %#x): %w", base, base+subBlockSize, err)
		}
		hb.cur = want
	}
	hb.compMapped = true
	hb.compExec = hb.exec != 0
	return nil
}

// freeCompLocked frees the composite page of a block that the stub no longer
// maps.
func (l *subBlockLayer) freeCompLocked(base uintptr, hb *hostBlock) {
	l.markChangedLocked()
	delete(l.comps, base)
	if hb.hasComp {
		l.host.freeComp(hb.comp)
		hb.comp, hb.hasComp = compPage{}, false
		hb.compMapped, hb.compExec = false, false
	}
}

// dropBlockLocked removes a block without guest pages.
func (l *subBlockLayer) dropBlockLocked(base uintptr, hb *hostBlock) error {
	var err error
	if hb.cur.kind != stubMapNone {
		err = l.host.unmapRange(base, subBlockSize)
	}
	if err != nil {
		// The stub can still map the composite page or the spare pages.
		// The block keeps cur and stays in blocks, so that a later drop
		// unmaps it again and reset releases the pages.
		delete(l.comps, base)
		delete(l.partial, base)
		delete(l.deferred, base)
		return err
	}
	l.disownLocked(base)
	hb.cur = stubMap{}
	l.freeCompLocked(base, hb)
	delete(l.partial, base)
	delete(l.deferred, base)
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
		l.changes.Add(1)
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
	// An unmapped page is not a spare page, so a block with spare pages
	// stops its direct mapping here (directLocked).
	for p := va; p < end; p += hostarch.PageSize {
		hb.subs[(p-base)/hostarch.PageSize] = subPage{}
	}
	if err := l.refreshLocked(base, hb, false); err != nil && !errors.Is(err, errDeadSubprocess) {
		log.Warningf("systrap: update the block at %#x after an unmap: %v", base, err)
	}
}

// releaseOwnedLocked ends the use of the spare pages of a block, because a new
// guest mapping covers one of them. A spare page would hide the pages of the
// new mapping from the memory manager.
func (l *subBlockLayer) releaseOwnedLocked(base uintptr) {
	ob := l.owned[base]
	delete(l.owned, base)
	hb := l.blocks[base]
	if hb == nil {
		ob.release()
		return
	}
	err := l.refreshLocked(base, hb, false)
	if err != nil && !errors.Is(err, errDeadSubprocess) {
		log.Warningf("systrap: update the block at %#x after a new mapping: %v", base, err)
	}
	if err != nil && hb.cur.kind == stubMapDirect && hb.cur.off == ob.fr.Start {
		// The stub can still map the spare pages. reset releases them.
		l.owned[base] = ob
		return
	}
	ob.release()
}

// adopt implements platform.HostBlockOwner.AdoptHostBlock.
func (l *subBlockLayer) adopt(base uintptr, f memmap.File, fr memmap.FileRange, spare uint8) {
	l.mu.Lock()
	defer l.mu.Unlock()
	// The memory manager unmapped the block before the call, so the stub
	// does not map old spare pages.
	l.disownLocked(base)
	l.owned[base] = ownedBlock{f: f, fr: fr, spare: spare}
}

// release implements platform.HostBlockOwner.ReleaseHostBlocks.
func (l *subBlockLayer) release(ar hostarch.AddrRange) {
	l.mu.Lock()
	defer l.mu.Unlock()
	defer l.updatePendingLocked()
	l.releaseGen++
	// A block that misses a guest page reads that page as zeros or as a
	// spare page. A new mapping there creates no PMA that the layer sees.
	// Such a block stops its stub mapping until the next populate.
	affected := func(base uintptr) bool {
		if _, ok := l.owned[base]; ok {
			return true
		}
		hb := l.blocks[base]
		return hb != nil && hb.mapped != allSubPages
	}
	start := subBlockBase(uintptr(ar.Start))
	end := uintptr(ar.End)
	var bases []uintptr
	if n := (end - start + subBlockSize - 1) / subBlockSize; n > uintptr(len(l.blocks)+len(l.owned)) {
		// The runtime of Go reserves large ranges, so a range can hold many
		// more blocks than the layer tracks.
		for base := range l.blocks {
			if base >= start && base < end && affected(base) {
				bases = append(bases, base)
			}
		}
		for base := range l.owned {
			if base >= start && base < end && l.blocks[base] == nil {
				bases = append(bases, base)
			}
		}
	} else {
		for base := start; base < end; base += subBlockSize {
			if affected(base) {
				bases = append(bases, base)
			}
		}
	}
	for _, base := range bases {
		if _, ok := l.owned[base]; ok {
			l.releaseOwnedLocked(base)
			continue
		}
		if err := l.refreshLocked(base, l.blocks[base], false); err != nil && !errors.Is(err, errDeadSubprocess) {
			log.Warningf("systrap: update the block at %#x after a new mapping: %v", base, err)
		}
	}
}

// forgetBlocksLocked drops the records of the whole blocks in [start, end)
// after the stub unmapped them.
func (l *subBlockLayer) forgetBlocksLocked(start, end uintptr) {
	forget := func(base uintptr, hb *hostBlock) {
		hb.cur = stubMap{}
		l.disownLocked(base)
		l.freeCompLocked(base, hb)
		delete(l.partial, base)
		delete(l.deferred, base)
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
	l.markChangedLocked()
	l.stopObserversLocked()
	for base, hb := range l.blocks {
		hb.cur = stubMap{}
		l.freeCompLocked(base, hb)
	}
	for _, ob := range l.owned {
		ob.release()
	}
	clear(l.owned)
	clear(l.blocks)
	clear(l.partial)
	clear(l.comps)
	clear(l.deferred)
	l.populating = 0
	l.releaseGen++
	l.updatePendingLocked()
}

// beforeSwitch prepares the blocks before a thread of the address space runs.
// It populates the guest pages that a mapped block misses, so that the guest
// does not read zeros where memory exists. Then it copies the guest pages into
// the composite pages. The Sentry or another address space can change a page
// that the stub reads through a copy. It returns the number of stores that the
// Sentry ran so far. A store exclusive compares it with the number of the last
// store to the same page. This comparison finds a store of another thread
// since the thread resumed.
func (l *subBlockLayer) beforeSwitch(ctx context.Context, mm platform.MemoryManager) uint64 {
	if l.pending.Load() == 0 {
		return l.storeSeq.Load()
	}
	l.popMu.Lock()
	defer l.popMu.Unlock()
	if pop, ok := mm.(platform.SubBlockPopulator); ok {
		l.populatePartial(ctx, pop)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	// The populate calls mapped what the memory manager can map. A page that
	// is still missing has no mapping of the guest, and it reads as zeros.
	for base := range l.deferred {
		if _, again := l.partial[base]; again {
			// A new mapping in the block arrived after its populate call.
			// The next switch populates the block again.
			continue
		}
		if hb := l.blocks[base]; hb != nil {
			if err := l.refreshLocked(base, hb, true); err != nil && !errors.Is(err, errDeadSubprocess) {
				log.Warningf("systrap: map the block at %#x: %v", base, err)
			}
		}
		delete(l.deferred, base)
	}
	l.populating = 0
	l.updatePendingLocked()
	// refreshLocked filled each composite page that changed, and a Sentry
	// write after that marked it through recent. A Sentry write before the
	// first rebuild set allDirty, because no block could be marked.
	if l.sourcesStale {
		l.rebuildSourcesLocked()
	}
	all := l.allDirty.Swap(false)
	for base, hb := range l.comps {
		mask := hb.write
		if d := hb.dirty.Load(); d > 0 {
			hb.dirty.CompareAndSwap(d, d-1)
			mask = allSubPages
		}
		if all || hb.alwaysSync {
			mask = allSubPages
		}
		if mask == 0 {
			continue
		}
		changed, err := hb.syncCompPages(mask)
		if err != nil {
			log.Warningf("systrap: refresh the composite page at %#x: %v", base, err)
			continue
		}
		if changed && hb.exec != 0 {
			if err := l.mapCompLocked(base, hb, true); err != nil && !errors.Is(err, errDeadSubprocess) {
				log.Warningf("systrap: map the composite page at %#x: %v", base, err)
			}
		}
	}
	return l.storeSeq.Load()
}

// fixMissingPageFault rewrites a fault in a guest page that a mapped block
// misses. The host saw a mapped page: a store into it faults with SEGV_ACCERR,
// and an instruction fetch runs zeros and raises SIGILL. Linux reports
// SEGV_MAPERR for both, and the memory manager maps the page when the guest
// has a mapping there.
//
// seen is the value of changes when the thread resumed. It returns true when
// the thread must run the instruction again. A stub mapping changed since the
// thread resumed. The SIGILL can therefore come from zeros or from old
// contents that the thread fetched before the change.
func (l *subBlockLayer) fixMissingPageFault(si *linux.SignalInfo, at *hostarch.AccessType, ac *arch.Context64, seen uint64) bool {
	switch linux.Signal(si.Signo) {
	case linux.SIGSEGV:
		if si.Code == segvAccerr && l.missingPage(uintptr(si.Addr())) {
			si.Code = segvMaperr
		}
	case linux.SIGILL:
		pc := ac.IP()
		l.mu.Lock()
		defer l.mu.Unlock()
		hb, _, present := l.pageLocked(pc)
		switch {
		case hb != nil && !present:
			// The block was mapped when the thread ran zeros there. Another
			// thread can have unmapped it since then.
			*si = linux.SignalInfo{Signo: int32(linux.SIGSEGV), Code: segvMaperr}
			si.SetAddr(uint64(pc))
			*at = hostarch.Execute
		case l.changes.Load() != seen:
			// Another thread changed or dropped the block since the thread
			// resumed.
			return true
		}
	}
	return false
}

// missingPage reports whether addr lies in a guest page that a block misses.
// Such a page reads as zeros while the stub maps the block (refreshLocked). A
// fault there comes from such a mapping, even if the stub no longer maps the
// block.
func (l *subBlockLayer) missingPage(addr uintptr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	hb, _, ok := l.pageLocked(addr)
	return hb != nil && !ok
}

// populatePartial asks the memory manager to map the guest pages that blocks
// miss. The layer verifies a block once after each change of the block.
func (l *subBlockLayer) populatePartial(ctx context.Context, pop platform.SubBlockPopulator) {
	l.mu.Lock()
	if len(l.partial) == 0 {
		l.mu.Unlock()
		return
	}
	l.populating = 1
	l.updatePendingLocked()
	checked := make(map[uintptr]uint64, len(l.partial))
	for {
		gen := l.releaseGen
		var addrs []hostarch.Addr
		for base := range l.partial {
			if checkedGen, ok := checked[base]; ok && checkedGen == gen {
				delete(l.partial, base)
				continue
			}
			checked[base] = gen
			hb := l.blocks[base]
			if hb == nil {
				delete(l.partial, base)
				continue
			}
			if hb.mapped == allSubPages {
				addrs = append(addrs, hostarch.Addr(base))
				continue
			}
			first := -1
			for i := range hb.subs {
				if hb.subs[i].f == nil {
					addrs = append(addrs, hostarch.Addr(base+uintptr(i)*hostarch.PageSize))
				} else if first < 0 {
					first = i
				}
			}
			// After the missing pages, a call for a mapped page lets the memory
			// manager coalesce the block with spare pages.
			if hb.canCoalesce() {
				addrs = append(addrs, hostarch.Addr(base+uintptr(first)*hostarch.PageSize))
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
		// change of the block verifies it, so that a block next to unmapped memory
		// does not cost a verification for each switch.
		l.mu.Lock()
		if l.releaseGen == gen {
			for _, addr := range addrs {
				delete(l.partial, subBlockBase(uintptr(addr)))
			}
		}
	}
}
