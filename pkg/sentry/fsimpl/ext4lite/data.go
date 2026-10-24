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

// ibodyData returns the value of the system.data attribute that sits behind the
// extra fields of the inode. This engine keeps every other attribute in an
// xattr block, so an image with another attribute in the inode is not valid.
func (n *node) ibodyData(raw []byte) ([]byte, error) {
	ents, err := parseIbodyXattrs(raw[ibodyOffset:])
	if err != nil {
		return nil, corrupt("inode %d: %v", n.ino, err)
	}
	var tail []byte
	for _, e := range ents {
		if e.index != xattrIndexSystem || e.name != "data" {
			return nil, corrupt("inode %d keeps the attribute %q in the inode, which ext4lite does not support", n.ino, joinXattrName(e.index, e.name))
		}
		tail = e.value
	}
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
// gets no block.
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
			_ = n.v.freeBlocks(blk, 1)
			return hostError(err)
		}
		list = []extent{{lblk: 0, n: 1, pblk: blk}}
		n.nblocks++
	}
	n.flags = n.flags&^flagInlineData | flagExtents
	n.inline = nil
	n.exts = nil
	if err := n.setExtentsLocked(list); err != nil {
		return err
	}
	n.markDirtyLocked()
	return nil
}

// readAt reads file content. It returns io.EOF at or beyond the end of the
// file. Holes read as zeros.
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
			phys := int64(e.pbn(lblk))*blockSize + int64(within)
			if _, err := n.v.hf.ReadAt(p[done:done+span], phys); err != nil {
				return done, hostError(err)
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
	done := 0
	for retry := 0; ; retry++ {
		w, err := n.writeOnce(p[done:], off+int64(done))
		done += w
		if errors.Is(err, errSpaceHeld) {
			if retry == 0 && n.v.hasHeld() {
				if serr := n.v.sync(); serr != nil {
					return done, serr
				}
				continue
			}
			err = linuxerr.ENOSPC
		}
		return done, err
	}
}

// hasHeld reports whether freed blocks or inodes wait for a flush.
func (v *volume) hasHeld() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.heldBlocksTotal > 0 || v.heldInodesTotal > 0
}

func (n *node) writeOnce(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, linuxerr.EINVAL
	}
	if len(p) == 0 {
		return 0, nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
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
	limit, allocErr := n.mapForWriteLocked(uint64(off), end, false)
	if limit > end {
		limit = end
	}
	var wrote int
	if limit > uint64(off) {
		w, err := n.writeMappedLocked(p[:limit-uint64(off)], off)
		wrote = w
		if err != nil {
			allocErr = err
		}
	}
	if wrote > 0 {
		n.size = max(n.size, uint64(off)+uint64(wrote))
		n.markDirtyLocked()
	}
	return wrote, allocErr
}

// mapForWriteLocked maps every hole of the file blocks that [start, end)
// covers. It returns the first byte offset that has no block because the
// allocation failed, which is end when it mapped everything.
func (n *node) mapForWriteLocked(start, end uint64, zeroAll bool) (uint64, error) {
	lb0, lb1 := uint32(start/blockSize), uint32((end+blockSize-1)/blockSize)
	list := n.exts
	var allocated []extent
	var firstErr error
	limit := end
	cur := lb0
	for cur < lb1 {
		i := n.extentIndex(cur)
		if i < len(n.exts) && n.exts[i].lblk <= cur {
			cur = n.exts[i].end()
			continue
		}
		holeEnd := lb1
		if i < len(n.exts) {
			holeEnd = min(holeEnd, n.exts[i].lblk)
		}
		for cur < holeEnd {
			goal := uint64(0)
			if prev, ok := n.physBlockInList(list, cur-1, cur > 0); ok {
				goal = prev + 1
			} else if len(list) > 0 {
				goal = list[len(list)-1].pend()
			}
			want := min(holeEnd-cur, maxExtentLen)
			blk, got, err := n.v.allocBlocks(goal, want)
			if err != nil {
				firstErr = err
				limit = uint64(cur) * blockSize
				break
			}
			e := extent{lblk: cur, n: got, pblk: blk}
			// A new block that the write covers only in part must start as zeros.
			if err := n.zeroEdges(e, start, end, zeroAll); err != nil {
				_ = n.v.freeBlocks(blk, got)
				firstErr = err
				limit = uint64(cur) * blockSize
				break
			}
			list = insertMapping(list, e)
			allocated = append(allocated, e)
			n.nblocks += uint64(got)
			cur += got
		}
		if firstErr != nil {
			break
		}
	}
	if len(allocated) > 0 {
		if err := n.setExtentsLocked(list); err != nil {
			for _, e := range allocated {
				_ = n.v.freeBlocks(e.pblk, e.n)
				n.nblocks -= uint64(e.n)
			}
			return start, err
		}
	}
	if limit < start {
		limit = start
	}
	return limit, firstErr
}

// physBlockInList is physBlock for a list that the caller builds.
func (n *node) physBlockInList(list []extent, lblk uint32, ok bool) (uint64, bool) {
	if !ok {
		return 0, false
	}
	for i := len(list) - 1; i >= 0; i-- {
		if list[i].lblk <= lblk {
			if list[i].end() > lblk {
				return list[i].pbn(lblk), true
			}
			return 0, false
		}
	}
	return 0, false
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

// writeMappedLocked writes p at off to the blocks that the extents map.
func (n *node) writeMappedLocked(p []byte, off int64) (int, error) {
	done := 0
	for done < len(p) {
		pos := uint64(off) + uint64(done)
		lblk := uint32(pos / blockSize)
		within := int(pos % blockSize)
		i := n.extentIndex(lblk)
		if i >= len(n.exts) || n.exts[i].lblk > lblk {
			return done, corrupt("inode %d block %d lost its mapping", n.ino, lblk)
		}
		e := n.exts[i]
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
	if size == n.size {
		return nil
	}
	if n.flags&flagInlineData != 0 {
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
	if size > n.size {
		n.size = size
		n.markDirtyLocked()
		return nil
	}
	lb := uint32((size + blockSize - 1) / blockSize)
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
	for _, f := range freed {
		n.nblocks -= uint64(f.n)
		if err := n.v.freeBlocks(f.pblk, f.n); err != nil {
			return err
		}
	}
	return nil
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
// zeros. The size grows unless keepSize is set.
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
	if _, err := n.mapForWriteLocked(off, end, true); err != nil {
		return err
	}
	if !keepSize && end > n.size {
		n.size = end
		n.markDirtyLocked()
	}
	return nil
}

// seekData returns the first offset at or after off that holds data, or false
// when the rest of the file is a hole.
func (n *node) seekData(off uint64) (uint64, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if off >= n.size {
		return 0, false
	}
	if n.flags&flagInlineData != 0 {
		return off, true
	}
	lblk := uint32(off / blockSize)
	i := n.extentIndex(lblk)
	if i >= len(n.exts) {
		return 0, false
	}
	if n.exts[i].lblk <= lblk {
		return off, true
	}
	pos := uint64(n.exts[i].lblk) * blockSize
	if pos >= n.size {
		return 0, false
	}
	return pos, true
}

// seekHole returns the first offset at or after off that is a hole. The end of
// the file counts as a hole.
func (n *node) seekHole(off uint64) uint64 {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if n.flags&flagInlineData != 0 || off >= n.size {
		return n.size
	}
	lblk := uint32(off / blockSize)
	i := n.extentIndex(lblk)
	if i >= len(n.exts) || n.exts[i].lblk > lblk {
		return off
	}
	end := n.exts[i].end()
	for i++; i < len(n.exts) && n.exts[i].lblk == end; i++ {
		end = n.exts[i].end()
	}
	return min(uint64(end)*blockSize, n.size)
}
