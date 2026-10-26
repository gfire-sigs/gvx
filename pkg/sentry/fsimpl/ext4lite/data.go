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

package ext4lite

import (
	"errors"
	"io"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// inlineXattrEntry is the size of the entry of the system.data attribute in
// the inode: 16 bytes of header and the name "data".
const inlineXattrEntry = 20

// maxFileSize is the largest file: 2^32-1 file blocks.
const maxFileSize = (uint64(1)<<32 - 1) * blockSize

// allBlocks is the first file block beyond every block of a file. A mapping
// that keeps every block uses it as its limit.
const allBlocks = maxLogicalBlock + 1

// ibodyData reads the attributes behind the extra fields of the inode. It
// returns the value of system.data, which holds the inline content past
// i_block. Every other attribute stays in the inode and keeps its place. An
// inline node has no room for such an attribute, because the inline limit
// assumes the inode holds only system.data.
func (n *node) ibodyData(raw []byte) ([]byte, error) {
	ents, err := parseIbodyXattrs(raw[ibodyOffset:])
	if err != nil {
		return nil, corrupt("inode %d: %v", n.ino, err)
	}
	var tail []byte
	var body []xattrEntry
	for _, e := range ents {
		if e.index == xattrIndexSystem && e.name == "data" {
			tail = e.value
			continue
		}
		e.inBody = true
		body = append(body, e)
	}
	if len(body) == 0 {
		return tail, nil
	}
	if n.flags&flagInlineData != 0 {
		return nil, corrupt("inline inode %d keeps the attribute %q in the inode", n.ino, joinXattrName(body[0].index, body[0].name))
	}
	if ibodySpace(body) > ibodySize {
		return nil, corrupt("inode %d: the attributes in the inode do not fit", n.ino)
	}
	n.xa = &xattrData{entries: body}
	return tail, nil
}

// parseInline reads the inline content of the inode. The first 60 bytes live
// in i_block. The rest lives in the value of the system.data attribute.
func (n *node) parseInline(raw []byte) error {
	if n.size > maxInline {
		return corrupt("inline inode %d has the size %d", n.ino, n.size)
	}
	tail, err := n.ibodyData(raw)
	if err != nil {
		return err
	}
	size := int(n.size)
	n.inline = make([]byte, size)
	copy(n.inline, raw[inBlock:inBlock+min(size, iBlockSize)])
	if size > iBlockSize {
		if len(tail) != size-iBlockSize {
			return corrupt("inline inode %d has %d bytes in the attribute, want %d", n.ino, len(tail), size-iBlockSize)
		}
		copy(n.inline[iBlockSize:], tail)
	}
	return nil
}

// serializeInline writes the inline content and the system.data attribute.
func (n *node) serializeInline(raw []byte) {
	copy(raw[inBlock:inBlock+iBlockSize], n.inline[:min(len(n.inline), iBlockSize)])
	var tail []byte
	if len(n.inline) > iBlockSize {
		tail = n.inline[iBlockSize:]
	}
	encodeIbodyXattrs(raw[ibodyOffset:], []xattrEntry{{index: xattrIndexSystem, name: "data", value: tail}})
}

// convertInlineLocked moves the inline content into extents. An empty file
// gets no block. It changes nothing when it fails.
func (n *node) convertInlineLocked() error {
	if n.flags&flagInlineData == 0 {
		return nil
	}
	var list []extent
	if len(n.inline) > 0 {
		blk, _, err := n.v.allocBlocks(0, 1)
		if err != nil {
			return err
		}
		buf := make([]byte, blockSize)
		copy(buf, n.inline)
		if _, err := n.v.hf.WriteAt(buf, int64(blk)*blockSize); err != nil {
			return joinCleanup(hostError(err), n.v.freeBlocks(blk, 1))
		}
		list = []extent{{lblk: 0, n: 1, pblk: blk}}
	}
	flags, inline := n.flags, n.inline
	n.flags = flags&^flagInlineData | flagExtents
	n.inline = nil
	if err := n.setExtentsLocked(list); err != nil {
		n.flags, n.inline = flags, inline
		if len(list) > 0 {
			return joinCleanup(err, n.v.freeBlocks(list[0].pblk, 1))
		}
		return err
	}
	n.nblocks += uint64(len(list))
	return nil
}

// readAt reads file content. It returns io.EOF at or beyond the end of the
// file. Holes and uninitialized blocks read as zeros.
func (n *node) readAt(p []byte, off int64) (int, error) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.readAtLocked(p, off)
}

func (n *node) readAtLocked(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, linuxerr.EINVAL
	}
	if uint64(off) >= n.size {
		return 0, io.EOF
	}
	if rem := n.size - uint64(off); uint64(len(p)) > rem {
		p = p[:rem]
	}
	if n.flags&flagInlineData != 0 {
		return copy(p, n.inline[off:]), nil
	}
	done := 0
	for done < len(p) {
		pos := uint64(off) + uint64(done)
		lblk := uint32(pos / blockSize)
		within := int(pos % blockSize)
		i := n.extentIndex(lblk)
		var span int
		if i < len(n.exts) && n.exts[i].lblk <= lblk {
			e := n.exts[i]
			span = min(len(p)-done, int(uint64(e.end()-lblk)*blockSize)-within)
			if e.uninit {
				clear(p[done : done+span])
			} else {
				phys := int64(e.pbn(lblk))*blockSize + int64(within)
				if _, err := n.v.hf.ReadAt(p[done:done+span], phys); err != nil {
					return done, hostError(err)
				}
			}
		} else {
			hole := uint64(maxLogicalBlock+1) * blockSize
			if i < len(n.exts) {
				hole = uint64(n.exts[i].lblk) * blockSize
			}
			span = min(len(p)-done, int(hole-pos))
			clear(p[done : done+span])
		}
		done += span
	}
	return done, nil
}

// writeAt writes p at off, allocates the blocks that it needs, and writes the
// data through to the host file. It extends the size of the file. It returns
// the number of bytes that it wrote and an error that explains a short write.
func (n *node) writeAt(p []byte, off int64) (int, error) {
	return n.writeRange(p, off, false)
}

// writeBackAt writes the part of p that lies below the current size. A page
// that a flush writes back never grows the file, even when a truncate shrank
// the file after the flush read its size.
func (n *node) writeBackAt(p []byte, off int64) (int, error) {
	// A write-back runs outside a guest operation when a flush or a read
	// triggers it, so it enters the gate itself. The gate accepts a nested entry.
	n.v.gate.enterInner()
	defer n.v.gate.exit()
	return n.writeRange(p, off, true)
}

// writeRange writes p at off. When the volume has freed space that waits for a
// flush, it returns errSpaceHeld. The caller flushes with the operation gate open
// and tries again, because a flush cannot run inside the gate.
func (n *node) writeRange(p []byte, off int64, back bool) (int, error) {
	return n.writeOnce(p, off, back)
}

// hasHeld reports whether freed blocks or inodes wait for a flush.
func (v *volume) hasHeld() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.heldBlocksTotal > 0 || v.heldInodesTotal > 0
}

// writeOnce writes as much of p at off as one mapping step allows. A back write
// stops at the current size.
func (n *node) writeOnce(p []byte, off int64, back bool) (int, error) {
	if off < 0 {
		return 0, linuxerr.EINVAL
	}
	if len(p) == 0 {
		return 0, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if back {
		if uint64(off) >= n.size {
			return 0, nil
		}
		p = p[:min(uint64(len(p)), n.size-uint64(off))]
	}
	end := uint64(off) + uint64(len(p))
	if end < uint64(off) || end > maxFileSize {
		return 0, linuxerr.EFBIG
	}
	if n.flags&flagInlineData != 0 {
		if end <= maxInline {
			if uint64(len(n.inline)) < end {
				n.inline = append(n.inline, make([]byte, end-uint64(len(n.inline)))...)
			}
			copy(n.inline[off:], p)
			n.size = max(n.size, end)
			n.markDirtyLocked()
			return len(p), nil
		}
		if err := n.convertInlineLocked(); err != nil {
			return 0, err
		}
	}
	if n.flags&flagExtents == 0 || n.isDir() {
		return 0, linuxerr.EINVAL
	}
	return n.writeExtentsLocked(p, uint64(off), end)
}

// writeExtentsLocked writes p, which ends at end, through the mapping of an
// extent node. It plans the mapping of the write, writes the data, and then
// installs the blocks that the data fills. A failed host write keeps only the
// blocks that it filled. The caller holds n.mu for writing.
func (n *node) writeExtentsLocked(p []byte, off, end uint64) (int, error) {
	plan := n.planLocked(off, end, false)
	var done uint64
	var werr error
	if plan.limit > off {
		w, err := n.writeListLocked(plan.list, p[:plan.limit-off], off)
		done, werr = uint64(w), err
	}
	cause := werr
	if cause == nil {
		cause = plan.err
	}
	keep, reported := uint64(allBlocks), done
	final := plan.list
	if cause != nil {
		keep, reported = cutAfterFailure(plan.fresh, off, done)
		final = spliceMapping(n.exts, plan.list, keep)
	}
	changed := !sameExtents(final, n.exts)
	if err := n.installMappingLocked(final, plan.fresh, keep); err != nil {
		if cause == nil {
			return 0, err
		}
		return 0, errors.Join(cause, err)
	}
	if reported > 0 {
		n.size = max(n.size, off+reported)
		changed = true
	}
	if changed {
		n.markDirtyLocked()
	}
	return int(reported), cause
}

// cutAfterFailure returns the first file block that a failed write keeps and
// the number of bytes that it reports. A fresh block counts as filled only when
// the write reached its last byte. A fresh block that the failure cut short is
// dropped, so no block stays mapped beyond the size of the file. A block that
// was uninitialized needs no such rule: writeListLocked counts whole runs, so
// wrote ends at a block boundary there.
func cutAfterFailure(fresh []extent, off, wrote uint64) (keep, reported uint64) {
	good := off + wrote
	if good%blockSize != 0 && isFreshBlock(fresh, good/blockSize) {
		good -= good % blockSize
	}
	good = max(good, off)
	return good / blockSize, good - off
}

// isFreshBlock reports whether file block lb lies in one of the fresh runs.
func isFreshBlock(fresh []extent, lb uint64) bool {
	for _, e := range fresh {
		if uint64(e.lblk) <= lb && lb < uint64(e.end()) {
			return true
		}
	}
	return false
}

// keptBlocks returns the number of blocks of the runs that lie below keep.
func keptBlocks(runs []extent, keep uint64) uint64 {
	var out uint64
	for _, r := range runs {
		if uint64(r.lblk) < keep {
			out += min(uint64(r.end()), keep) - uint64(r.lblk)
		}
	}
	return out
}

// installMappingLocked makes final the extent list of the node. The fresh runs
// below keep join the node and count as data blocks. Every other fresh run goes
// back to the pool. The node changes nothing when the install fails.
func (n *node) installMappingLocked(final, fresh []extent, keep uint64) error {
	if sameExtents(final, n.exts) {
		return n.v.freeRunsFrom(fresh, 0)
	}
	if err := n.setExtentsLocked(final); err != nil {
		return joinCleanup(err, n.v.freeRunsFrom(fresh, 0))
	}
	n.nblocks += keptBlocks(fresh, keep)
	// The runs above keep were never mapped. Only a damaged bitmap makes this
	// free fail, and fsckLite reports such damage.
	_ = n.v.freeRunsFrom(fresh, keep)
	return nil
}

// mapPlan is a change to the mapping of a node that a write or a fallocate
// makes. The node keeps its mapping until the caller installs the plan.
type mapPlan struct {
	// list is the mapping after the change. Its fresh runs are mapped, and the
	// uninitialized blocks of the write are initialized.
	list []extent
	// fresh lists the runs that the plan allocated and zeroed.
	fresh []extent
	// limit is the first byte of the range that the plan does not map. It is
	// the end of the range when the plan maps all of it.
	limit uint64
	// err explains why the plan stops before the end of the range.
	err error
}

// planLocked plans the mapping of the file blocks that [start, end) covers. A
// hole takes fresh blocks. The fresh blocks are zeroed where the range covers
// them only in part, or everywhere when zeroAll is set. An uninitialized block
// in the range becomes initialized, unless zeroAll is set. The caller holds
// n.mu for writing.
func (n *node) planLocked(start, end uint64, zeroAll bool) mapPlan {
	lb0, lb1 := uint32(start/blockSize), uint32((end+blockSize-1)/blockSize)
	p := mapPlan{limit: end}
	for cur := lb0; cur < lb1 && p.err == nil; {
		if e, ok := extentAt(n.exts, cur); ok {
			cur = e.end()
			continue
		}
		holeEnd := lb1
		if i := n.extentIndex(cur); i < len(n.exts) {
			holeEnd = min(holeEnd, n.exts[i].lblk)
		}
		for cur < holeEnd && p.err == nil {
			cur = n.fillLocked(&p, cur, holeEnd, start, end, zeroAll)
		}
	}
	p.limit = max(p.limit, start)
	convEnd := lb0
	if !zeroAll && p.limit > start {
		if err := n.zeroUninitEdges(start, p.limit); err != nil {
			p.err, p.limit = err, start
		} else {
			convEnd = min(lb1, uint32((p.limit+blockSize-1)/blockSize))
		}
	}
	if len(p.fresh) == 0 && convEnd == lb0 {
		p.list = n.exts
	} else {
		p.list = n.mapListLocked(p.fresh, lb0, convEnd)
	}
	if len(p.list) > maxTreeExtents {
		return mapPlan{
			list:  n.exts,
			limit: start,
			err:   joinCleanup(linuxerr.ENOSPC, n.v.freeRunsFrom(p.fresh, 0)),
		}
	}
	return p
}

// fillLocked allocates a fresh run at file block cur, which lies in a hole that
// ends at holeEnd. It records the run in p and returns the next file block. On
// failure it records the error and the limit, and it returns cur.
func (n *node) fillLocked(p *mapPlan, cur, holeEnd uint32, start, end uint64, zeroAll bool) uint32 {
	blk, got, err := n.v.allocBlocks(n.goalLocked(p.fresh, cur), min(holeEnd-cur, maxExtentLen))
	if err != nil {
		p.stop(cur, err)
		return cur
	}
	e := extent{lblk: cur, n: got, pblk: blk}
	if err := n.zeroEdges(e, start, end, zeroAll); err != nil {
		p.stop(cur, joinCleanup(err, n.v.freeBlocks(blk, got)))
		return cur
	}
	p.fresh = append(p.fresh, e)
	return cur + got
}

// stop ends the plan at file block cur with the error err.
func (p *mapPlan) stop(cur uint32, err error) {
	p.err = err
	p.limit = uint64(cur) * blockSize
}

// goalLocked returns the host block where a fresh run at file block cur should
// start. A sequential writer then gets one run, which follows the run before it
// when the host blocks are free.
func (n *node) goalLocked(fresh []extent, cur uint32) uint64 {
	if k := len(fresh) - 1; k >= 0 && fresh[k].end() == cur {
		return fresh[k].pend()
	}
	if cur > 0 {
		if e, ok := extentAt(n.exts, cur-1); ok {
			return e.pbn(cur-1) + 1
		}
	}
	if k := len(fresh) - 1; k >= 0 {
		return fresh[k].pend()
	}
	if k := len(n.exts) - 1; k >= 0 {
		return n.exts[k].pend()
	}
	return 0
}

// zeroEdges clears the first and the last block of a new extent when the write
// range [start, end) covers that block only in part. The blocks in the
// middle of the write get all their bytes from the write. With zeroAll, it
// clears every block of the extent, as fallocate needs.
func (n *node) zeroEdges(e extent, start, end uint64, zeroAll bool) error {
	if zeroAll {
		zero := make([]byte, 1<<20)
		for off := uint64(0); off < uint64(e.n)*blockSize; off += uint64(len(zero)) {
			chunk := zero[:min(uint64(len(zero)), uint64(e.n)*blockSize-off)]
			if _, err := n.v.hf.WriteAt(chunk, int64(e.pblk)*blockSize+int64(off)); err != nil {
				return hostError(err)
			}
		}
		return nil
	}
	zero := make([]byte, blockSize)
	for _, l := range []uint32{e.lblk, e.end() - 1} {
		bs, be := uint64(l)*blockSize, uint64(l+1)*blockSize
		if start <= bs && end >= be {
			continue
		}
		if _, err := n.v.hf.WriteAt(zero, int64(e.pbn(l))*blockSize); err != nil {
			return hostError(err)
		}
	}
	return nil
}

// zeroUninitEdges clears the uninitialized blocks that a write of [start, limit)
// covers only in part. The write initializes such a block, so the bytes that
// the write leaves out must read as zeros.
func (n *node) zeroUninitEdges(start, limit uint64) error {
	first, last := uint32(start/blockSize), uint32((limit-1)/blockSize)
	edges := []uint32{first}
	if last != first {
		edges = append(edges, last)
	}
	zero := make([]byte, blockSize)
	for _, lb := range edges {
		e, ok := extentAt(n.exts, lb)
		if !ok || !e.uninit {
			continue
		}
		bs, be := uint64(lb)*blockSize, uint64(lb+1)*blockSize
		if start <= bs && limit >= be {
			continue
		}
		if _, err := n.v.hf.WriteAt(zero, int64(e.pbn(lb))*blockSize); err != nil {
			return hostError(err)
		}
	}
	return nil
}

// writeListLocked writes p at off to the host blocks that list maps. It returns
// the number of bytes that it wrote before the first failure.
func (n *node) writeListLocked(list []extent, p []byte, off uint64) (int, error) {
	done := 0
	for done < len(p) {
		pos := off + uint64(done)
		lblk := uint32(pos / blockSize)
		within := int(pos % blockSize)
		e, ok := extentAt(list, lblk)
		if !ok {
			return done, corrupt("inode %d block %d lost its mapping", n.ino, lblk)
		}
		span := min(len(p)-done, int(uint64(e.end()-lblk)*blockSize)-within)
		if _, err := n.v.hf.WriteAt(p[done:done+span], int64(e.pbn(lblk))*blockSize+int64(within)); err != nil {
			return done, hostError(err)
		}
		done += span
	}
	return done, nil
}

// truncate sets the size of the file. Growing leaves a hole. Shrinking frees
// the blocks behind the new end and clears the tail of the last block.
func (n *node) truncate(size uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.truncateLocked(size)
}

func (n *node) truncateLocked(size uint64) error {
	if size > maxFileSize {
		return linuxerr.EFBIG
	}
	if n.flags&flagInlineData != 0 {
		if size == n.size {
			return nil
		}
		if size <= maxInline {
			if size < uint64(len(n.inline)) {
				n.inline = n.inline[:size]
			} else {
				n.inline = append(n.inline, make([]byte, size-uint64(len(n.inline)))...)
			}
			n.size = size
			n.markDirtyLocked()
			return nil
		}
		if err := n.convertInlineLocked(); err != nil {
			return err
		}
	}
	lb := uint32((size + blockSize - 1) / blockSize)
	if size == n.size {
		// Linux frees the blocks behind the end, which a keep-size fallocate maps.
		return n.freeRangeLocked(lb, maxLogicalBlock)
	}
	if size > n.size {
		n.size = size
		n.markDirtyLocked()
		return nil
	}
	if err := n.freeRangeLocked(lb, maxLogicalBlock); err != nil {
		return err
	}
	if rem := size % blockSize; rem != 0 {
		if phys, ok := n.physBlock(uint32(size / blockSize)); ok {
			zero := make([]byte, blockSize-rem)
			if _, err := n.v.hf.WriteAt(zero, int64(phys)*blockSize+int64(rem)); err != nil {
				return hostError(err)
			}
		}
	}
	n.size = size
	n.markDirtyLocked()
	return nil
}

// freeRangeLocked removes the file blocks [lb0, lb1) from the map and frees
// their host blocks. lb1 can be maxLogicalBlock for the rest of the file.
func (n *node) freeRangeLocked(lb0, lb1 uint32) error {
	list, freed := removeRange(n.exts, lb0, lb1)
	if len(freed) == 0 {
		return nil
	}
	if err := n.setExtentsLocked(list); err != nil {
		return err
	}
	var errs []error
	for _, f := range freed {
		n.nblocks -= uint64(f.n)
		errs = append(errs, n.v.freeBlocks(f.pblk, f.n))
	}
	return errors.Join(errs...)
}

// punchHole frees the whole blocks inside [off, off+length) and clears the
// partial blocks at the edges. The size does not change.
func (n *node) punchHole(off, length uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.flags&flagInlineData != 0 {
		end := min(off+length, uint64(len(n.inline)))
		if off < end {
			clear(n.inline[off:end])
			n.markDirtyLocked()
		}
		return nil
	}
	end := min(off+length, n.size)
	if off >= end {
		return nil
	}
	first, last := (off+blockSize-1)/blockSize, end/blockSize
	if first < last {
		if err := n.freeRangeLocked(uint32(first), uint32(last)); err != nil {
			return err
		}
	}
	for _, edge := range [][2]uint64{{off, min(end, first*blockSize)}, {max(off, last*blockSize), end}} {
		if edge[0] >= edge[1] {
			continue
		}
		lblk := uint32(edge[0] / blockSize)
		phys, ok := n.physBlock(lblk)
		if !ok {
			continue
		}
		zero := make([]byte, edge[1]-edge[0])
		if _, err := n.v.hf.WriteAt(zero, int64(phys)*blockSize+int64(edge[0]%blockSize)); err != nil {
			return hostError(err)
		}
	}
	n.markDirtyLocked()
	return nil
}

// preallocate maps blocks for [off, off+length) and fills new blocks with
// zeros. The size grows unless keepSize is set. A failed allocation keeps the
// blocks that it mapped, as Linux does, and it leaves the size as it was.
func (n *node) preallocate(off, length uint64, keepSize bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	end := off + length
	if end < off || end > maxFileSize {
		return linuxerr.EFBIG
	}
	if n.flags&flagInlineData != 0 {
		if end <= maxInline {
			if !keepSize && end > n.size {
				return n.truncateLocked(end)
			}
			return nil
		}
		if err := n.convertInlineLocked(); err != nil {
			return err
		}
	}
	plan := n.planLocked(off, end, true)
	if err := n.installMappingLocked(plan.list, plan.fresh, allBlocks); err != nil {
		return joinCleanup(plan.err, err)
	}
	if plan.err != nil {
		return plan.err
	}
	if !keepSize && end > n.size {
		n.size = end
		n.markDirtyLocked()
	}
	return nil
}

// seekData returns the first offset at or after off that holds data, or false
// when the rest of the file is a hole. An uninitialized block is a hole, as on
// Linux, until a write initializes it.
func (n *node) seekData(off uint64) (uint64, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if off >= n.size {
		return 0, false
	}
	if n.flags&flagInlineData != 0 {
		return off, true
	}
	for i := n.extentIndex(uint32(off / blockSize)); i < len(n.exts); i++ {
		e := n.exts[i]
		if e.uninit {
			continue
		}
		pos := max(off, uint64(e.lblk)*blockSize)
		if pos >= n.size {
			return 0, false
		}
		return pos, true
	}
	return 0, false
}

// seekHole returns the first offset at or after off that is a hole. An
// uninitialized block counts as a hole. The end of the file counts as a hole.
func (n *node) seekHole(off uint64) uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.flags&flagInlineData != 0 || off >= n.size {
		return n.size
	}
	lblk := uint32(off / blockSize)
	i := n.extentIndex(lblk)
	if i >= len(n.exts) || n.exts[i].lblk > lblk || n.exts[i].uninit {
		return off
	}
	end := n.exts[i].end()
	for i++; i < len(n.exts) && n.exts[i].lblk == end && !n.exts[i].uninit; i++ {
		end = n.exts[i].end()
	}
	return min(uint64(end)*blockSize, n.size)
}
