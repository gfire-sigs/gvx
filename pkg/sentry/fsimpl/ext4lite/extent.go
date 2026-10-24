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
	"sort"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// The extent tree of an inode has at most two levels. The root lives in
// i_block and holds up to four entries. With four extents or fewer, the root
// holds the extents (depth 0). With more, the root holds up to four index
// entries, and each index entry names a leaf block of up to 340 extents
// (depth 1). One file therefore has at most 1,360 extents.

// validExtent reports whether e names blocks that can hold file data. An
// extent never spans two groups, because the metadata of a group lies between
// the data of two groups.
func (v *volume) validExtent(e extent) bool {
	if e.n == 0 || e.n > maxExtentLen || uint64(e.lblk)+uint64(e.n) > 1<<32 {
		return false
	}
	blocks := v.blocksCountSnapshot()
	last := e.pblk + uint64(e.n) - 1
	return isValidDataBlock(e.pblk, blocks) && isValidDataBlock(last, blocks) && e.pblk/blocksPerGroup == last/blocksPerGroup
}

// blocksCountSnapshot returns the current number of blocks.
func (v *volume) blocksCountSnapshot() uint64 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.blocksCountLocked()
}

// checkExtentList verifies that the list is ordered, without overlap, and
// valid. A violation means that the image is damaged.
func (n *node) checkExtentList(list []extent) error {
	var next uint64
	for i, e := range list {
		if !n.v.validExtent(e) {
			return corrupt("inode %d extent %d (%d+%d at %d) is not valid", n.ino, i, e.lblk, e.n, e.pblk)
		}
		if uint64(e.lblk) < next {
			return corrupt("inode %d extent %d overlaps or precedes the extent before it", n.ino, i)
		}
		next = uint64(e.lblk) + uint64(e.n)
	}
	return nil
}

// parseExtents reads the extent tree that i_block holds.
func (n *node) parseExtents(raw []byte) error {
	root := raw[inBlock : inBlock+iBlockSize]
	if le.Uint16(root[0:]) != extMagic {
		return corrupt("inode %d has a bad extent header", n.ino)
	}
	entries, max, depth := int(le.Uint16(root[2:])), int(le.Uint16(root[4:])), int(le.Uint16(root[6:]))
	if max != rootExtents || entries > max {
		return corrupt("inode %d extent root has %d of %d entries", n.ino, entries, max)
	}
	var list []extent
	switch depth {
	case 0:
		for i := range entries {
			list = append(list, decodeExtent(root[extHeaderSize+i*extEntrySize:]))
		}
	case 1:
		for i := range entries {
			_, leaf := decodeExtentIdx(root[extHeaderSize+i*extEntrySize:])
			blocks := n.v.blocksCountSnapshot()
			if !isValidDataBlock(leaf, blocks) {
				return corrupt("inode %d extent leaf at block %d is not valid", n.ino, leaf)
			}
			var buf [blockSize]byte
			if _, err := n.v.hf.ReadAt(buf[:], int64(leaf)*blockSize); err != nil {
				return hostError(err)
			}
			if le.Uint16(buf[0:]) != extMagic || le.Uint16(buf[6:]) != 0 {
				return corrupt("inode %d extent leaf %d has a bad header", n.ino, leaf)
			}
			cnt, lmax := int(le.Uint16(buf[2:])), int(le.Uint16(buf[4:]))
			if lmax > leafExtents || cnt > lmax {
				return corrupt("inode %d extent leaf %d has %d of %d entries", n.ino, leaf, cnt, lmax)
			}
			for j := range cnt {
				list = append(list, decodeExtent(buf[extHeaderSize+j*extEntrySize:]))
			}
			n.leaves = append(n.leaves, leaf)
		}
	default:
		return corrupt("inode %d extent tree has depth %d", n.ino, depth)
	}
	if err := n.checkExtentList(list); err != nil {
		return err
	}
	n.exts = list
	n.nblocks = uint64(len(n.leaves))
	for _, e := range list {
		n.nblocks += uint64(e.n)
	}
	if n.fileACL != 0 {
		n.nblocks++
	}
	return nil
}

// serializeExtents writes the root of the tree into the 60 bytes of i_block.
func (n *node) serializeExtents(dst []byte) {
	clear(dst)
	if len(n.exts) <= rootExtents {
		encodeExtentHeader(dst, len(n.exts), rootExtents, 0)
		for i, e := range n.exts {
			encodeExtent(dst[extHeaderSize+i*extEntrySize:], e)
		}
		return
	}
	encodeExtentHeader(dst, len(n.leaves), rootExtents, 1)
	for i, leaf := range n.leaves {
		encodeExtentIdx(dst[extHeaderSize+i*extEntrySize:], n.exts[i*leafExtents].lblk, leaf)
	}
}

// leafImagesLocked returns the images of the leaf blocks.
func (n *node) leafImagesLocked() []blockWrite {
	var out []blockWrite
	for i, leaf := range n.leaves {
		part := n.exts[i*leafExtents : min(len(n.exts), (i+1)*leafExtents)]
		buf := make([]byte, blockSize)
		encodeExtentHeader(buf, len(part), leafExtents, 0)
		for j, e := range part {
			encodeExtent(buf[extHeaderSize+j*extEntrySize:], e)
		}
		out = append(out, blockWrite{leaf, buf})
	}
	return out
}

// setExtentsLocked installs list as the extent list and adjusts the leaf
// blocks to the new length. It changes nothing when it fails.
func (n *node) setExtentsLocked(list []extent) error {
	need := 0
	if len(list) > rootExtents {
		need = (len(list) + leafExtents - 1) / leafExtents
	}
	if need > rootExtents {
		return linuxerr.EFBIG
	}
	var added []uint64
	for len(n.leaves)+len(added) < need {
		goal := uint64(0)
		if len(list) > 0 {
			goal = list[0].pblk
		}
		blk, _, err := n.v.allocBlocks(goal, 1)
		if err != nil {
			for _, b := range added {
				_ = n.v.freeBlocks(b, 1)
			}
			return err
		}
		added = append(added, blk)
	}
	n.leaves = append(n.leaves, added...)
	n.nblocks += uint64(len(added))
	for len(n.leaves) > need {
		last := n.leaves[len(n.leaves)-1]
		n.leaves = n.leaves[:len(n.leaves)-1]
		n.nblocks--
		_ = n.v.freeBlocks(last, 1)
	}
	n.exts = list
	n.dirtyLeaf = true
	n.markDirtyLocked()
	return nil
}

// extentIndex returns the index of the first extent that ends after lblk.
func (n *node) extentIndex(lblk uint32) int {
	return sort.Search(len(n.exts), func(i int) bool { return n.exts[i].end() > lblk })
}

// physBlock returns the host block of file block lblk.
func (n *node) physBlock(lblk uint32) (uint64, bool) {
	i := n.extentIndex(lblk)
	if i < len(n.exts) && n.exts[i].lblk <= lblk {
		return n.exts[i].pbn(lblk), true
	}
	return 0, false
}

// appendMapping returns list with the run (lblk, n, pblk) inserted, merged
// with a neighbor when both the file blocks and the host blocks continue. The
// run must not overlap an extent of list.
func insertMapping(list []extent, e extent) []extent {
	i := sort.Search(len(list), func(i int) bool { return list[i].lblk >= e.lblk })
	out := make([]extent, 0, len(list)+1)
	out = append(out, list[:i]...)
	out = append(out, e)
	out = append(out, list[i:]...)
	// Merge with the neighbors.
	merged := out[:0:0]
	for _, x := range out {
		if k := len(merged) - 1; k >= 0 {
			p := merged[k]
			if p.end() == x.lblk && p.pend() == x.pblk && p.n+x.n <= maxExtentLen {
				merged[k].n += x.n
				continue
			}
		}
		merged = append(merged, x)
	}
	return merged
}

// removeRange returns list without the file blocks [lb0, lb1) and the list of
// the host runs that the removal frees.
func removeRange(list []extent, lb0, lb1 uint32) (out, freed []extent) {
	for _, e := range list {
		if e.end() <= lb0 || e.lblk >= lb1 {
			out = append(out, e)
			continue
		}
		if e.lblk < lb0 {
			out = append(out, extent{lblk: e.lblk, n: lb0 - e.lblk, pblk: e.pblk})
		}
		lo, hi := max(e.lblk, lb0), min(e.end(), lb1)
		freed = append(freed, extent{lblk: lo, n: hi - lo, pblk: e.pbn(lo)})
		if e.end() > lb1 {
			out = append(out, extent{lblk: lb1, n: e.end() - lb1, pblk: e.pbn(lb1)})
		}
	}
	return out, freed
}

// freeAllBlocksLocked releases every data block and every leaf block.
func (n *node) freeAllBlocksLocked() error {
	var first error
	for _, e := range n.exts {
		if err := n.v.freeBlocks(e.pblk, e.n); err != nil && first == nil {
			first = err
		}
	}
	for _, l := range n.leaves {
		if err := n.v.freeBlocks(l, 1); err != nil && first == nil {
			first = err
		}
	}
	return first
}
