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
	"fmt"
	"slices"
	"sort"
	"sync"

	"z.gfire.dev/gvx/pkg/hostarch"
)

// A frame of the memory file can have several views: one address space maps it
// twice, or two address spaces share it. A JIT compiler uses this to write code
// through a read-write view and run it through a read-execute view. The engine
// executes a patched private copy of each code page, so a write through
// another view leaves the copy stale.
//
// The index records every copy and every writable view of a frame, in all
// address spaces of the platform. While a copy exists, the engine lowers each
// writable view of its frame to read-only. A write then faults. The fault
// handler drops the copies of the frame, restores the write permission, and
// resumes the write. A write that does not pass through a stub view, such as a
// write(2) into a shared file, is not seen (section 9 of
// docs/systrap-windows.md).
//
// Lock order: an address space lock (addressSpace.mu) comes before the lock of
// the index. Code that holds the lock of the index never takes another lock.

// frameKey names one frame of a host file that a stub can map.
type frameKey struct {
	file uintptr
	off  uint64
}

// aliasBucketShift selects the size of the file range that one bucket covers:
// 1 MiB. A query then scans the entries of one bucket and not every entry of
// the platform.
const aliasBucketShift = 20

type bucketKey struct {
	file uintptr
	n    uint64
}

// copyEntry records a patched copy of a frame that an exec block holds. The
// entry is pending while the engine builds the copy, and installed once the
// stub maps it.
type copyEntry struct {
	as   *addressSpace
	base uint64
	key  frameKey
	// installed is true once the stub maps the copy.
	installed bool
	// poisoned is true when a write to the frame faulted after the entry
	// started. The copy can miss that write, so install refuses it.
	poisoned bool
}

// writeView records a range of a guest address space that maps frames of a file
// with write permission.
type writeView struct {
	as   *addressSpace
	va   uint64
	file uintptr
	off  uint64
	size uint64
}

// viewHit names the page of a writable view that maps a frame.
type viewHit struct {
	as *addressSpace
	va uint64
}

type aliasBucket struct {
	copies map[uint64][]*copyEntry
	views  []*writeView
}

// aliasIndex is the reverse index from frames to the copies and to the writable
// views that name them. The zero value is ready for use.
type aliasIndex struct {
	mu      sync.Mutex
	buckets map[bucketKey]*aliasBucket
}

func (x *aliasIndex) bucketLocked(k bucketKey) *aliasBucket {
	b := x.buckets[k]
	if b == nil {
		if x.buckets == nil {
			x.buckets = make(map[bucketKey]*aliasBucket)
		}
		b = &aliasBucket{copies: make(map[uint64][]*copyEntry)}
		x.buckets[k] = b
	}
	return b
}

func (x *aliasIndex) dropIfEmptyLocked(k bucketKey, b *aliasBucket) {
	if len(b.copies) == 0 && len(b.views) == 0 {
		delete(x.buckets, k)
	}
}

func frameBucket(key frameKey) bucketKey {
	return bucketKey{key.file, key.off >> aliasBucketShift}
}

// begin records e as a pending copy and returns the writable views of its frame
// except the view at e.base.
func (x *aliasIndex) begin(e *copyEntry) []viewHit {
	x.mu.Lock()
	defer x.mu.Unlock()
	bk := frameBucket(e.key)
	b := x.bucketLocked(bk)
	b.copies[e.key.off] = append(b.copies[e.key.off], e)
	var hits []viewHit
	for _, v := range b.views {
		if v.file != e.key.file || e.key.off < v.off || e.key.off-v.off >= v.size {
			continue
		}
		if va := v.va + (e.key.off - v.off); v.as != e.as || va != e.base {
			hits = append(hits, viewHit{v.as, va})
		}
	}
	return hits
}

// install turns a pending copy into an installed copy. It returns false for a
// copy that a write poisoned, and then removes the entry.
func (x *aliasIndex) install(e *copyEntry) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	if e.poisoned {
		x.removeLocked(e)
		return false
	}
	e.installed = true
	return true
}

// remove forgets a copy. It accepts an entry that is already gone.
func (x *aliasIndex) remove(e *copyEntry) {
	x.mu.Lock()
	defer x.mu.Unlock()
	x.removeLocked(e)
}

func (x *aliasIndex) removeLocked(e *copyEntry) {
	bk := frameBucket(e.key)
	b := x.buckets[bk]
	if b == nil {
		return
	}
	list := slices.DeleteFunc(b.copies[e.key.off], func(o *copyEntry) bool { return o == e })
	if len(list) == 0 {
		delete(b.copies, e.key.off)
	} else {
		b.copies[e.key.off] = list
	}
	x.dropIfEmptyLocked(bk, b)
}

// invalidate poisons the pending copies of a frame and returns its installed
// copies, which the owners must drop. An installed copy stays in the index until
// its owner drops it. A second writer then still sees a live copy and keeps its
// view lowered until the first drop finishes.
func (x *aliasIndex) invalidate(key frameKey) []*copyEntry {
	x.mu.Lock()
	defer x.mu.Unlock()
	b := x.buckets[frameBucket(key)]
	if b == nil {
		return nil
	}
	var installed []*copyEntry
	for _, e := range b.copies[key.off] {
		if e.installed {
			installed = append(installed, e)
		} else {
			e.poisoned = true
		}
	}
	return installed
}

// dropAll drops every installed copy of key and reports the first failure.
func (x *aliasIndex) dropAll(key frameKey) error {
	var first error
	for _, e := range x.invalidate(key) {
		if err := e.as.dropExecCopy(e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// otherCopy reports whether a live copy of key exists that is not the copy of
// the block at (as, va). A poisoned entry is not live, because it can never be
// installed.
func (x *aliasIndex) otherCopy(key frameKey, as *addressSpace, va uint64) bool {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.otherCopyLocked(key, as, va)
}

func (x *aliasIndex) otherCopyLocked(key frameKey, as *addressSpace, va uint64) bool {
	b := x.buckets[frameBucket(key)]
	if b == nil {
		return false
	}
	for _, e := range b.copies[key.off] {
		if !e.poisoned && (e.as != as || e.base != va) {
			return true
		}
	}
	return false
}

// copiesIn returns the live copies of the frames in [off, off+length) of file,
// in the order of their offsets.
func (x *aliasIndex) copiesIn(file uintptr, off, length uint64) []*copyEntry {
	x.mu.Lock()
	defer x.mu.Unlock()
	if len(x.buckets) == 0 {
		return nil
	}
	var out []*copyEntry
	for n := off >> aliasBucketShift; n <= (off+length-1)>>aliasBucketShift; n++ {
		b := x.buckets[bucketKey{file, n}]
		if b == nil {
			continue
		}
		for o, list := range b.copies {
			if o < off || o >= off+length {
				continue
			}
			for _, e := range list {
				if !e.poisoned {
					out = append(out, e)
				}
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key.off < out[j].key.off })
	return out
}

func (x *aliasIndex) addView(v *writeView) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for n := v.off >> aliasBucketShift; n <= (v.off+v.size-1)>>aliasBucketShift; n++ {
		b := x.bucketLocked(bucketKey{v.file, n})
		b.views = append(b.views, v)
	}
}

func (x *aliasIndex) removeView(v *writeView) {
	x.mu.Lock()
	defer x.mu.Unlock()
	for n := v.off >> aliasBucketShift; n <= (v.off+v.size-1)>>aliasBucketShift; n++ {
		bk := bucketKey{v.file, n}
		b := x.buckets[bk]
		if b == nil {
			continue
		}
		b.views = slices.DeleteFunc(b.views, func(o *writeView) bool { return o == v })
		x.dropIfEmptyLocked(bk, b)
	}
}

// ---- address space side ----------------------------------------------------

// frameID returns the key of the frame that the block copies. It returns false
// for a block that has no host file frame, because only a frame of a host file
// can have another view.
func (blk *execBlock) frameID() (frameKey, bool) {
	if blk.srcSec == nil || blk.srcSec.file == 0 {
		return frameKey{}, false
	}
	return frameKey{blk.srcSec.file, blk.srcOff}, true
}

// lowerAliasLocked makes the view page at va read-only when it is a writable
// view of the frame key. A failure leaves a writable view next to a copy, which
// can run stale code, so the caller must not install the copy. Callers hold
// as.mu.
func (as *addressSpace) lowerAliasLocked(va uint64, key frameKey) error {
	if as.released || as.sp.dead.Load() {
		return nil
	}
	vi, _, ok := as.win.Lookup(va)
	if !ok || vi.prot != viewReadWrite || vi.off != key.off {
		return nil
	}
	if sec, ok := vi.backing.(*sectionRef); !ok || sec.file != key.file {
		return nil
	}
	if err := as.win.Protect(va, blockSize, viewRead); err != nil {
		return as.mapErr(fmt.Errorf("lower the view at %#x: %w", va, err))
	}
	if as.aliasProt == nil {
		as.aliasProt = make(map[uint64]frameKey)
	}
	as.aliasProt[va] = key
	return nil
}

// lowerHits lowers the writable views that begin found. It reports the first
// failure.
func lowerHits(hits []viewHit, key frameKey) error {
	var first error
	for _, h := range hits {
		h.as.mu.Lock()
		if err := h.as.lowerAliasLocked(h.va, key); err != nil && first == nil {
			first = err
		}
		h.as.mu.Unlock()
	}
	return first
}

// relowerLocked lowers the writable view at va again when another copy of its
// frame exists. A block that returns to data state needs it. Callers hold as.mu.
func (as *addressSpace) relowerLocked(va uint64, key frameKey) error {
	if as.p.alias.otherCopy(key, as, va) {
		return as.lowerAliasLocked(va, key)
	}
	return nil
}

// aliasMappedLocked updates the index for a MapFile call. [guest, guest+length)
// now maps the file range that starts at off. A page with keep set kept its
// earlier view. Callers hold as.mu.
func (as *addressSpace) aliasMappedLocked(guest, length uint64, sec *sectionRef, off uint64, at hostarch.AccessType, keep []bool) error {
	for i, k := range keep {
		if !k {
			delete(as.aliasProt, guest+uint64(i)*blockSize)
		}
	}
	as.removeWriteViewsLocked(guest, guest+length)
	if !at.Write || sec.file == 0 {
		return nil
	}
	v := &writeView{as: as, va: guest, file: sec.file, off: off, size: length}
	i := sort.Search(len(as.wviews), func(i int) bool { return as.wviews[i].va > guest })
	as.wviews = slices.Insert(as.wviews, i, v)
	as.p.alias.addView(v)

	// A copy of a frame in the new range already exists. Lower its page now, in
	// runs, because each protection change can split the view.
	var failed error
	runStart, runLen := uint64(0), uint64(0)
	flush := func() {
		if runLen == 0 {
			return
		}
		if err := as.win.Protect(runStart, runLen, viewRead); err != nil {
			if failed == nil {
				failed = as.mapErr(fmt.Errorf("lower [%#x, %#x): %w", runStart, runStart+runLen, err))
			}
		} else {
			if as.aliasProt == nil {
				as.aliasProt = make(map[uint64]frameKey)
			}
			for a := runStart; a < runStart+runLen; a += blockSize {
				as.aliasProt[a] = frameKey{sec.file, off + (a - guest)}
			}
		}
		runLen = 0
	}
	for _, e := range as.p.alias.copiesIn(sec.file, off, length) {
		va := guest + (e.key.off - off)
		if keep[(va-guest)/blockSize] || (e.as == as && e.base == va) {
			flush()
			continue
		}
		if runLen != 0 && runStart+runLen != va {
			flush()
		}
		if runLen == 0 {
			runStart = va
		}
		runLen += blockSize
	}
	flush()
	return failed
}

// removeWriteViewsLocked removes the part of every writable view record that
// overlaps [start, end) from the address space and from the index. A record
// that sticks out of the range keeps its outer parts. Callers hold as.mu.
func (as *addressSpace) removeWriteViewsLocked(start, end uint64) {
	i := sort.Search(len(as.wviews), func(i int) bool { return as.wviews[i].va+as.wviews[i].size > start })
	j := i
	var pieces []*writeView
	for ; j < len(as.wviews) && as.wviews[j].va < end; j++ {
		v := as.wviews[j]
		as.p.alias.removeView(v)
		if v.va < start {
			pieces = append(pieces, &writeView{as: as, va: v.va, file: v.file, off: v.off, size: start - v.va})
		}
		if v.va+v.size > end {
			pieces = append(pieces, &writeView{as: as, va: end, file: v.file, off: v.off + (end - v.va), size: v.va + v.size - end})
		}
	}
	if i == j {
		return
	}
	as.wviews = slices.Replace(as.wviews, i, j, pieces...)
	for _, p := range pieces {
		as.p.alias.addView(p)
	}
}

// aliasUnmappedLocked updates the index for an unmap of [start, end). Callers
// hold as.mu.
func (as *addressSpace) aliasUnmappedLocked(start, end uint64) {
	as.removeWriteViewsLocked(start, end)
	if len(as.aliasProt) == 0 {
		return
	}
	if (end-start)/blockSize > uint64(len(as.aliasProt)) {
		for va := range as.aliasProt {
			if va >= start && va < end {
				delete(as.aliasProt, va)
			}
		}
		return
	}
	for va := start; va < end; va += blockSize {
		delete(as.aliasProt, va)
	}
}

// releaseAliasLocked removes every record of the address space from the index.
// Callers hold as.mu.
func (as *addressSpace) releaseAliasLocked() {
	for _, v := range as.wviews {
		as.p.alias.removeView(v)
	}
	as.wviews, as.aliasProt = nil, nil
}

// aliasWriteFault serves a write fault on a page that the engine lowered
// because a copy of its frame exists. It drops the copies, restores the write
// permission, and returns true so that the thread repeats the write. It
// returns false for any other fault. An error means that a copy or a view
// stayed in a state that the thread cannot leave, and the caller must stop the
// guest.
func (as *addressSpace) aliasWriteFault(addr uint64) (bool, error) {
	page := blockRound(addr)
	as.mu.Lock()
	key, ok := as.aliasProt[page]
	if ok && !as.aliasStillLoweredLocked(page, key) {
		delete(as.aliasProt, page)
		ok = false
	}
	as.mu.Unlock()
	if !ok {
		return false, nil
	}
	as.aliasFaults.Add(1)
	if err := as.p.alias.dropAll(key); err != nil {
		return true, err
	}
	as.mu.Lock()
	defer as.mu.Unlock()
	if k, ok := as.aliasProt[page]; !ok || k != key || !as.aliasStillLoweredLocked(page, key) {
		// Another call changed the page. The write repeats and faults again if
		// it still needs the engine.
		return true, nil
	}
	x := &as.p.alias
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.otherCopyLocked(key, as, page) {
		// A new copy appeared after the drop. The write faults again.
		return true, nil
	}
	if err := as.win.Protect(page, blockSize, viewReadWrite); err != nil {
		return true, as.mapErr(fmt.Errorf("restore the view at %#x: %w", page, err))
	}
	delete(as.aliasProt, page)
	return true, nil
}

// lowersOwnFrame reports whether the page at addr is a lowered view of the
// frame that the block at pc copies. A thread that stores through such a view
// would drop the copy that it runs, fetch the page again, lower the view
// again, and fault on the same store forever. The engine reports SIGSEGV for
// that store, as it does for a store into the page that the thread executes.
func (as *addressSpace) lowersOwnFrame(addr, pc uint64) bool {
	as.mu.Lock()
	defer as.mu.Unlock()
	key, ok := as.aliasProt[blockRound(addr)]
	if !ok {
		return false
	}
	blk := as.blocks[blockRound(pc)]
	if blk == nil {
		return false
	}
	k, ok := blk.frameID()
	return ok && k == key
}

// aliasStillLoweredLocked reports whether the page still maps key as a
// read-only view. Callers hold as.mu.
func (as *addressSpace) aliasStillLoweredLocked(page uint64, key frameKey) bool {
	vi, _, ok := as.win.Lookup(page)
	if !ok || vi.prot != viewRead || vi.off != key.off {
		return false
	}
	sec, ok := vi.backing.(*sectionRef)
	return ok && sec.file == key.file
}

// dropExecCopy returns the block of an installed copy to data state, as
// restoreData does for a write through the block itself. It is safe to call
// again for a copy that another call already dropped.
func (as *addressSpace) dropExecCopy(e *copyEntry) error {
	as.mu.Lock()
	defer as.mu.Unlock()
	blk := as.blocks[e.base]
	if as.released || blk == nil || blk.entry != e || blk.state != blockExec {
		// The block changed or left, so the entry is stale.
		as.p.alias.remove(e)
		return nil
	}
	return as.returnToDataLocked(blk)
}
