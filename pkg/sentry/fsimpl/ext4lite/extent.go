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
	"cmp"
	"errors"
	"slices"
	"sort"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// The extent tree of an inode lives in i_block and in up to five levels of
// blocks below it (eh_depth 0..5). The root holds up to four entries. With four
// extents or fewer, the root holds the extents (depth 0). With more, each leaf
// block holds up to 340 extents, and intermediate index levels each hold up to
// 340 child pointers per block until the top level fits inside the four root
// slots.
//
// The engine writes a canonical tree: every leaf and index block is full except
// the last one of its level. A tree read from disk keeps its counts until an
// extent changes, so that a flush without a change writes the same tree that it
// read.

const (
	// uninitExtentOffset is added to the length of an uninitialized extent to
	// form its ee_len. An ee_len above maxExtentLen marks such an extent.
	uninitExtentOffset = maxExtentLen
	// maxUninitExtentLen is the longest uninitialized extent. Its ee_len value
	// must stay within 16 bits, so the length is at most 32767 blocks.
	maxUninitExtentLen = maxExtentLen - 1
	// maxExtentDepth is the maximum eh_depth of an extent tree in Linux ext4.
	maxExtentDepth = 5
)

// maxTreeExtents is the maximum number of extents that an inode can hold.
var maxTreeExtents = int(maxLogicalBlock)

// leafBlock is one extent leaf block. cnt is the number of extents it holds.
type leafBlock struct {
	blk uint64
	cnt int
}

// indexBlock is one index block of an extent tree. cnt is the number of child
// blocks of the level below it that it names.
type indexBlock struct {
	blk uint64
	cnt int
}

// maxLen returns the longest run that e may have, which depends on its kind.
func (e extent) maxLen() uint32 {
	if e.uninit {
		return maxUninitExtentLen
	}
	return maxExtentLen
}

// sub returns the part of e that covers the file blocks [lb0, lb1).
func (e extent) sub(lb0, lb1 uint32) extent {
	return extent{lblk: lb0, n: lb1 - lb0, pblk: e.pbn(lb0), uninit: e.uninit}
}

// validExtent reports whether e names blocks that can hold file data. An
// extent never spans two groups, because the metadata of a group lies between
// the data of two groups. Its file blocks end at or below 2^32-1, so end()
// never wraps.
func (v *volume) validExtent(e extent) bool {
	if e.n == 0 || e.n > e.maxLen() || uint64(e.lblk)+uint64(e.n) > maxLogicalBlock {
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
	var (
		list     []extent
		leaves   []leafBlock
		ixs      []indexBlock
		ixLevels [][]indexBlock
	)
	switch {
	case depth == 0:
		for i := range entries {
			list = append(list, decodeExtent(root[extHeaderSize+i*extEntrySize:]))
		}
	case depth >= 1 && depth <= maxExtentDepth:
		if entries == 0 {
			return corrupt("inode %d extent root names no child block", n.ino)
		}
		if depth >= 2 {
			ixLevels = make([][]indexBlock, depth-1)
		}
		var walk func(blk uint64, d int) error
		walk = func(blk uint64, d int) error {
			var buf [blockSize]byte
			cnt, err := n.readTreeBlock(blk, uint16(d), buf[:])
			if err != nil {
				return err
			}
			if d == 0 {
				list = appendLeafExtents(list, buf[:], cnt)
				leaves = append(leaves, leafBlock{blk: blk, cnt: cnt})
				return nil
			}
			ixLevels[d-1] = append(ixLevels[d-1], indexBlock{blk: blk, cnt: cnt})
			for j := range cnt {
				_, child := decodeExtentIdx(buf[extHeaderSize+j*extEntrySize:])
				if err := walk(child, d-1); err != nil {
					return err
				}
			}
			return nil
		}
		for i := range entries {
			_, blk := decodeExtentIdx(root[extHeaderSize+i*extEntrySize:])
			if err := walk(blk, depth-1); err != nil {
				return err
			}
		}
		for _, lvl := range ixLevels {
			ixs = append(ixs, lvl...)
		}
	default:
		return corrupt("inode %d extent tree has depth %d", n.ino, depth)
	}
	if err := n.checkExtentList(list); err != nil {
		return err
	}
	if err := n.checkTreeBlocks(list, leaves, ixs); err != nil {
		return err
	}
	n.exts, n.leaves, n.ixs, n.ixLevels = list, leaves, ixs, ixLevels
	n.nblocks = uint64(len(leaves) + len(ixs))
	for _, e := range list {
		n.nblocks += uint64(e.n)
	}
	if n.fileACL != 0 {
		n.nblocks++
	}
	return nil
}

// readTreeBlock reads the tree block blk into buf. Its header must name depth,
// and it must hold between one and leafExtents entries. It returns the count.
func (n *node) readTreeBlock(blk uint64, depth uint16, buf []byte) (int, error) {
	if !isValidDataBlock(blk, n.v.blocksCountSnapshot()) {
		return 0, corrupt("inode %d extent tree block %d is not valid", n.ino, blk)
	}
	if _, err := n.v.hf.ReadAt(buf, int64(blk)*blockSize); err != nil {
		return 0, hostError(err)
	}
	if le.Uint16(buf[0:]) != extMagic || le.Uint16(buf[6:]) != depth {
		return 0, corrupt("inode %d extent tree block %d has a bad header", n.ino, blk)
	}
	cnt, lmax := int(le.Uint16(buf[2:])), int(le.Uint16(buf[4:]))
	if lmax > leafExtents || cnt < 1 || cnt > lmax {
		return 0, corrupt("inode %d extent tree block %d has %d of %d entries", n.ino, blk, cnt, lmax)
	}
	return cnt, nil
}

// appendLeafExtents appends the first cnt extents of a leaf image to list.
func appendLeafExtents(list []extent, buf []byte, cnt int) []extent {
	for j := range cnt {
		list = append(list, decodeExtent(buf[extHeaderSize+j*extEntrySize:]))
	}
	return list
}

// checkTreeBlocks verifies that no tree block repeats, that no tree block is the
// xattr block, and that no tree block lies inside a data run of the file.
func (n *node) checkTreeBlocks(list []extent, leaves []leafBlock, ixs []indexBlock) error {
	if len(leaves) == 0 {
		return nil
	}
	blks := make([]uint64, 0, len(leaves)+len(ixs))
	for _, x := range ixs {
		blks = append(blks, x.blk)
	}
	for _, l := range leaves {
		blks = append(blks, l.blk)
	}
	slices.Sort(blks)
	runs := slices.Clone(list)
	slices.SortFunc(runs, func(a, b extent) int { return cmp.Compare(a.pblk, b.pblk) })
	for i, b := range blks {
		if i > 0 && blks[i-1] == b {
			return corrupt("inode %d extent tree block %d is named twice", n.ino, b)
		}
		if n.fileACL != 0 && b == n.fileACL {
			return corrupt("inode %d extent tree block %d is also the xattr block", n.ino, b)
		}
		k := sort.Search(len(runs), func(k int) bool { return runs[k].pend() > b })
		if k < len(runs) && runs[k].pblk <= b {
			return corrupt("inode %d extent tree block %d is also a data block", n.ino, b)
		}
	}
	return nil
}

// serializeExtents writes the root of the tree into the 60 bytes of i_block.
func (n *node) serializeExtents(dst []byte) {
	clear(dst)
	switch {
	case len(n.leaves) == 0:
		encodeExtentHeader(dst, len(n.exts), rootExtents, 0)
		for i, e := range n.exts {
			encodeExtent(dst[extHeaderSize+i*extEntrySize:], e)
		}
	case len(n.ixLevels) == 0:
		firsts := n.leafFirsts()
		encodeExtentHeader(dst, len(n.leaves), rootExtents, 1)
		for i, l := range n.leaves {
			encodeExtentIdx(dst[extHeaderSize+i*extEntrySize:], firsts[i], l.blk)
		}
	default:
		firsts := n.leafFirsts()
		for _, lvl := range n.ixLevels {
			firsts = levelFirsts(firsts, lvl)
		}
		top := n.ixLevels[len(n.ixLevels)-1]
		encodeExtentHeader(dst, len(top), rootExtents, 1+len(n.ixLevels))
		for j, x := range top {
			encodeExtentIdx(dst[extHeaderSize+j*extEntrySize:], firsts[j], x.blk)
		}
	}
}

// leafFirsts returns the first file block that each leaf names. Every leaf
// holds at least one extent, so each value comes from an extent.
func (n *node) leafFirsts() []uint32 {
	out := make([]uint32, len(n.leaves))
	k := 0
	for i, l := range n.leaves {
		out[i] = n.exts[k].lblk
		k += l.cnt
	}
	return out
}

// levelFirsts returns the first file block that each index block of lvl names,
// given the first file blocks of the child level below it.
func levelFirsts(childFirsts []uint32, lvl []indexBlock) []uint32 {
	out := make([]uint32, len(lvl))
	child := 0
	for j, x := range lvl {
		out[j] = childFirsts[child]
		child += x.cnt
	}
	return out
}

// leafImagesLocked returns the images of every tree block: the leaves and all
// index levels above them.
func (n *node) leafImagesLocked() []blockWrite {
	var out []blockWrite
	ext := 0
	childBlks := make([]uint64, len(n.leaves))
	for i, l := range n.leaves {
		buf := make([]byte, blockSize)
		encodeExtentHeader(buf, l.cnt, leafExtents, 0)
		for j, e := range n.exts[ext : ext+l.cnt] {
			encodeExtent(buf[extHeaderSize+j*extEntrySize:], e)
		}
		ext += l.cnt
		childBlks[i] = l.blk
		out = append(out, blockWrite{l.blk, buf})
	}
	if len(n.ixLevels) == 0 {
		return out
	}
	childFirsts := n.leafFirsts()
	for d, lvl := range n.ixLevels {
		nextBlks := make([]uint64, len(lvl))
		k := 0
		for i, x := range lvl {
			buf := make([]byte, blockSize)
			encodeExtentHeader(buf, x.cnt, leafExtents, d+1)
			for j := range x.cnt {
				encodeExtentIdx(buf[extHeaderSize+j*extEntrySize:], childFirsts[k+j], childBlks[k+j])
			}
			k += x.cnt
			nextBlks[i] = x.blk
			out = append(out, blockWrite{x.blk, buf})
		}
		childFirsts = levelFirsts(childFirsts, lvl)
		childBlks = nextBlks
	}
	return out
}

// treeBlocksLocked returns the block numbers of every tree block: the index
// blocks and the leaves. The caller holds n.mu.
func (n *node) treeBlocksLocked() []uint64 {
	out := make([]uint64, 0, len(n.ixs)+len(n.leaves))
	for _, x := range n.ixs {
		out = append(out, x.blk)
	}
	for _, l := range n.leaves {
		out = append(out, l.blk)
	}
	return out
}

// canonicalLevels returns the extent counts of the leaves and the child counts
// of each index level for n extents. Depth 0 has neither, depth 1 has leaves
// only, and depth D >= 2 has D-1 index levels.
func canonicalLevels(n int) (leaves []int, ixLevels [][]int) {
	if n <= rootExtents {
		return nil, nil
	}
	leaves = fullPacks(n, leafExtents)
	cur := leaves
	for len(cur) > rootExtents {
		next := fullPacks(len(cur), leafExtents)
		ixLevels = append(ixLevels, next)
		cur = next
	}
	return leaves, ixLevels
}

// fullPacks splits total into runs of per items. Every run is full except the
// last one.
func fullPacks(total, per int) []int {
	var out []int
	for ; total > 0; total -= per {
		out = append(out, min(total, per))
	}
	return out
}

// treeUpdate is the tree that a change builds before it installs. The node
// keeps its old tree until the update commits, so a failed change changes
// nothing.
type treeUpdate struct {
	list     []extent
	leaves   []leafBlock
	ixs      []indexBlock
	ixLevels [][]indexBlock
	// added lists the blocks that the update allocated.
	added []uint64
	// dropped lists the blocks of the old tree that the new tree does not use.
	dropped []uint64
}

// abandon frees the blocks that the update allocated. The caller calls it when
// the update does not commit.
func (u *treeUpdate) abandon(v *volume) error {
	var errs []error
	for _, b := range u.added {
		errs = append(errs, v.freeBlocks(b, 1))
	}
	return errors.Join(errs...)
}

// joinCleanup returns err, joined with the error of a cleanup that failed too.
func joinCleanup(err, cleanup error) error {
	if cleanup == nil {
		return err
	}
	return errors.Join(err, cleanup)
}

// prepareTreeLocked builds the canonical tree for list. A leaf or an index
// block keeps its position when reuse allows it. Every other position takes a
// block from alloc. It changes nothing of the node.
func (n *node) prepareTreeLocked(list []extent, reuse func(blk uint64) bool, alloc func(goal uint64) (uint64, error)) (treeUpdate, error) {
	if len(list) > maxTreeExtents {
		return treeUpdate{}, linuxerr.ENOSPC
	}
	leafCnt, ixLvls := canonicalLevels(len(list))
	if 1+len(ixLvls) > maxExtentDepth {
		return treeUpdate{}, linuxerr.ENOSPC
	}
	var goal uint64
	if len(list) > 0 {
		goal = list[0].pblk
	}
	u := treeUpdate{list: list}
	u.leaves = make([]leafBlock, len(leafCnt))
	for i, cnt := range leafCnt {
		if i < len(n.leaves) && reuse(n.leaves[i].blk) {
			u.leaves[i] = leafBlock{blk: n.leaves[i].blk, cnt: cnt}
			continue
		}
		blk, err := alloc(goal)
		if err != nil {
			return treeUpdate{}, joinCleanup(err, u.abandon(n.v))
		}
		u.added = append(u.added, blk)
		u.leaves[i] = leafBlock{blk: blk, cnt: cnt}
	}
	if len(ixLvls) > 0 {
		u.ixLevels = make([][]indexBlock, len(ixLvls))
	}
	j := 0
	for d, lvlCnt := range ixLvls {
		lvl := make([]indexBlock, len(lvlCnt))
		for k, cnt := range lvlCnt {
			if j < len(n.ixs) && reuse(n.ixs[j].blk) {
				lvl[k] = indexBlock{blk: n.ixs[j].blk, cnt: cnt}
			} else {
				blk, err := alloc(goal)
				if err != nil {
					return treeUpdate{}, joinCleanup(err, u.abandon(n.v))
				}
				u.added = append(u.added, blk)
				lvl[k] = indexBlock{blk: blk, cnt: cnt}
			}
			u.ixs = append(u.ixs, lvl[k])
			j++
		}
		u.ixLevels[d] = lvl
	}
	for i, l := range n.leaves {
		if i >= len(u.leaves) || u.leaves[i].blk != l.blk {
			u.dropped = append(u.dropped, l.blk)
		}
	}
	for j, x := range n.ixs {
		if j >= len(u.ixs) || u.ixs[j].blk != x.blk {
			u.dropped = append(u.dropped, x.blk)
		}
	}
	return u, nil
}

// commitTreeLocked installs the update and frees the blocks that it dropped.
// The caller holds n.mu for writing and has checked the update.
func (n *node) commitTreeLocked(u treeUpdate) {
	n.exts, n.leaves, n.ixs, n.ixLevels = u.list, u.leaves, u.ixs, u.ixLevels
	n.nblocks += uint64(len(u.added))
	for _, b := range u.dropped {
		n.nblocks--
		// A tree block of the node is allocated, so the free cannot fail unless
		// the bitmap is damaged. The next fsckLite reports that damage.
		_ = n.v.freeBlocks(b, 1)
	}
	n.dirtyLeaf = true
	n.markDirtyLocked()
}

// keepAll keeps every tree block at its position.
func keepAll(uint64) bool { return true }

// allocTreeBlock takes one block near goal for a tree.
func (n *node) allocTreeBlock(goal uint64) (uint64, error) {
	blk, _, err := n.v.allocBlocks(goal, 1)
	return blk, err
}

// setExtentsLocked installs list as the extent list and rebuilds the tree in
// canonical form. It changes nothing when it fails. The caller frees the data
// runs that list drops, and it counts the data runs that list adds.
func (n *node) setExtentsLocked(list []extent) error {
	u, err := n.prepareTreeLocked(list, keepAll, n.allocTreeBlock)
	if err != nil {
		return err
	}
	n.commitTreeLocked(u)
	return nil
}

// extentIndexIn returns the index of the first extent of list that ends after
// lblk.
func extentIndexIn(list []extent, lblk uint32) int {
	return sort.Search(len(list), func(i int) bool { return list[i].end() > lblk })
}

// extentAt returns the extent of list that maps the file block lblk.
func extentAt(list []extent, lblk uint32) (extent, bool) {
	i := extentIndexIn(list, lblk)
	if i < len(list) && list[i].lblk <= lblk {
		return list[i], true
	}
	return extent{}, false
}

// extentIndex returns the index of the first extent that ends after lblk.
func (n *node) extentIndex(lblk uint32) int {
	return extentIndexIn(n.exts, lblk)
}

// physBlock returns the host block of file block lblk.
func (n *node) physBlock(lblk uint32) (uint64, bool) {
	e, ok := extentAt(n.exts, lblk)
	if !ok {
		return 0, false
	}
	return e.pbn(lblk), true
}

// canJoin reports whether run b continues run a in both the file blocks and the
// host blocks. Both runs must have one kind, and the joined run must fit one
// extent.
func canJoin(a, b extent) bool {
	return a.end() == b.lblk && a.pend() == b.pblk && a.uninit == b.uninit && a.n+b.n <= a.maxLen()
}

// appendRun appends e to list. It joins e to the last run when canJoin allows.
func appendRun(list []extent, e extent) []extent {
	if k := len(list) - 1; k >= 0 && canJoin(list[k], e) {
		list[k].n += e.n
		return list
	}
	return append(list, e)
}

// insertMapping returns list with the run e inserted. It joins e to a neighbor
// when canJoin allows it. The run must not overlap an extent of list.
func insertMapping(list []extent, e extent) []extent {
	i := sort.Search(len(list), func(i int) bool { return list[i].lblk >= e.lblk })
	out := make([]extent, 0, len(list)+1)
	out = append(out, list[:i]...)
	out = append(out, e)
	out = append(out, list[i:]...)
	merged := out[:0]
	for _, x := range out {
		merged = appendRun(merged, x)
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
			out = append(out, e.sub(e.lblk, lb0))
		}
		lo, hi := max(e.lblk, lb0), min(e.end(), lb1)
		freed = append(freed, e.sub(lo, hi))
		if e.end() > lb1 {
			out = append(out, e.sub(lb1, e.end()))
		}
	}
	return out, freed
}

// mapListLocked returns the mapping of the node with the fresh runs added and
// with the uninitialized blocks of [lb0, lb1) made initialized. The fresh runs
// are sorted and lie in holes of the node.
func (n *node) mapListLocked(fresh []extent, lb0, lb1 uint32) []extent {
	base := make([]extent, 0, len(n.exts)+2)
	for _, e := range n.exts {
		if !e.uninit || e.end() <= lb0 || e.lblk >= lb1 {
			base = appendRun(base, e)
			continue
		}
		lo, hi := max(e.lblk, lb0), min(e.end(), lb1)
		if e.lblk < lo {
			base = appendRun(base, e.sub(e.lblk, lo))
		}
		base = appendRun(base, extent{lblk: lo, n: hi - lo, pblk: e.pbn(lo)})
		if hi < e.end() {
			base = appendRun(base, e.sub(hi, e.end()))
		}
	}
	out := make([]extent, 0, len(base)+len(fresh))
	i := 0
	for _, f := range fresh {
		for ; i < len(base) && base[i].lblk < f.lblk; i++ {
			out = appendRun(out, base[i])
		}
		out = appendRun(out, f)
	}
	for ; i < len(base); i++ {
		out = appendRun(out, base[i])
	}
	return out
}

// spliceMapping returns the mapping that keeps the blocks below keep from next
// and every other block from old. A failed write uses it to drop the blocks
// that it could not fill.
func spliceMapping(old, next []extent, keep uint64) []extent {
	var out []extent
	for _, e := range next {
		if uint64(e.lblk) >= keep {
			break
		}
		out = appendRun(out, e.sub(e.lblk, uint32(min(uint64(e.end()), keep))))
	}
	for _, e := range old {
		if uint64(e.end()) <= keep {
			continue
		}
		out = appendRun(out, e.sub(uint32(max(uint64(e.lblk), keep)), e.end()))
	}
	return out
}

// sameExtents reports whether two lists hold the same runs.
func sameExtents(a, b []extent) bool {
	return slices.Equal(a, b)
}

// freeRunsFrom frees the host blocks of the runs of list at or above the file
// block from. It returns the first error.
func (v *volume) freeRunsFrom(list []extent, from uint64) error {
	var errs []error
	for _, e := range list {
		if uint64(e.end()) <= from {
			continue
		}
		lo := max(uint64(e.lblk), from)
		errs = append(errs, v.freeBlocks(e.pbn(uint32(lo)), uint32(uint64(e.end())-lo)))
	}
	return errors.Join(errs...)
}

// freeAllBlocksLocked releases every data block and every tree block. It leaves
// the node without extents and without tree blocks.
func (n *node) freeAllBlocksLocked() error {
	var errs []error
	for _, e := range n.exts {
		errs = append(errs, n.v.freeBlocks(e.pblk, e.n))
	}
	for _, b := range n.treeBlocksLocked() {
		errs = append(errs, n.v.freeBlocks(b, 1))
	}
	n.exts, n.leaves, n.ixs, n.ixLevels = nil, nil, nil, nil
	return errors.Join(errs...)
}
