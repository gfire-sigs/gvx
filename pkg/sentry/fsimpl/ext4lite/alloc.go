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
	"fmt"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// errSpaceHeld reports that the volume has no allocatable block or inode,
// but freed blocks or inodes wait for the next flush. The caller flushes and
// tries again. Without a retry the error reads as ENOSPC.
var errSpaceHeld = errors.New("ext4lite: free space waits for the next flush")

// corrupt wraps linuxerr.EUCLEAN with a description of the failed check.
func corrupt(format string, args ...any) error {
	return fmt.Errorf("ext4lite: %s: %w", fmt.Sprintf(format, args...), linuxerr.EUCLEAN)
}

// group is the in-memory state of one block group.
//
// The allocator never reuses a block or an inode that the disk still records
// as used. A block that a guest frees before the next flush stays held until
// that flush ends. Without the hold, a crash could leave an inode on disk that
// names a block that another file has overwritten. A block that was never on
// disk returns to the pool at once. The fresh bitmaps mark the blocks and the
// inodes that the disk does not record yet.
type group struct {
	desc   groupDesc
	blocks bitmap
	inodes bitmap

	freshBlocks, heldBlocks *bitmap
	freshInodes, heldInodes *bitmap
	heldBlockCount          uint32
	heldInodeCount          uint32

	// dirty is set when the bitmaps or the descriptor differ from the disk.
	dirty bool
	// needsBackup is set for a new group that holds a superblock copy. The
	// next flush writes the copy.
	needsBackup bool
	// migDirty holds one bit for each 4 KiB block of the group that a write
	// changed since the last DrainDirtyBlocks. It is nil while no block is
	// marked. v.mu protects it.
	migDirty *bitmap
}

func (g *group) availBlocks() uint32 { return g.desc.freeBlocks - g.heldBlockCount }
func (g *group) availInodes() uint32 { return g.desc.freeInodes - g.heldInodeCount }

func lazyBitmap(p **bitmap) *bitmap {
	if *p == nil {
		*p = new(bitmap)
	}
	return *p
}

// newGroup returns the state of a fresh group number idx. Its metadata blocks
// are in use and every inode is free.
func newGroup(idx uint32) *group {
	g := &group{}
	metaBlocks := uint32(groupOverhead(idx)) + 2 + inodeTableBlocks
	for b := uint32(0); b < metaBlocks; b++ {
		g.blocks.set(b)
	}
	g.desc = groupDesc{
		blockBitmap: blockBitmapBlock(idx),
		inodeBitmap: inodeBitmapBlock(idx),
		inodeTable:  inodeTableStart(idx),
		freeBlocks:  blocksPerGroup - metaBlocks,
		freeInodes:  inodesPerGroup,
	}
	g.dirty = true
	g.needsBackup = hasSuper(idx) && idx > 0
	return g
}

// metaBlocksOf returns the number of metadata blocks of group idx.
func metaBlocksOf(idx uint32) uint32 { return uint32(groupOverhead(idx)) + 2 + inodeTableBlocks }

// allocBlocks takes up to want contiguous blocks. It prefers the run that
// starts at goal and otherwise takes the lowest free run, so that data stays
// dense and trailing groups empty out. It returns the start and the length of
// the run, which is at least 1.
func (v *volume) allocBlocks(goal uint64, want uint32) (uint64, uint32, error) {
	if want == 0 {
		return 0, 0, nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.allocBlocksLocked(goal, want)
}

func (v *volume) allocBlocksLocked(goal uint64, want uint32) (uint64, uint32, error) {
	if v.readOnly {
		return 0, 0, linuxerr.EROFS
	}
	for {
		if goal != 0 && goal < v.blocksCountLocked() && !isMetadataBlock(goal) {
			gi, off := uint32(goal/blocksPerGroup), uint32(goal%blocksPerGroup)
			g := v.groups[gi]
			if g.availBlocks() > 0 && !g.blocks.test(off) && (g.heldBlocks == nil || !g.heldBlocks.test(off)) {
				return v.takeRunLocked(gi, off, want)
			}
		}
		for gi, g := range v.groups {
			if g.availBlocks() == 0 {
				continue
			}
			off := g.blocks.firstFree(0, g.heldBlocks)
			if off >= blocksPerGroup {
				continue
			}
			return v.takeRunLocked(uint32(gi), off, want)
		}
		if v.heldBlocksTotal > 0 {
			return 0, 0, errSpaceHeld
		}
		if err := v.appendGroupLocked(); err != nil {
			return 0, 0, err
		}
	}
}

// takeRunLocked marks the free run that starts at off in group gi as used.
func (v *volume) takeRunLocked(gi, off, want uint32) (uint64, uint32, error) {
	g := v.groups[gi]
	n := g.blocks.freeRun(off, want, g.heldBlocks)
	start := groupStart(gi) + uint64(off)
	if err := v.ensureHostLocked(start + uint64(n)); err != nil {
		return 0, 0, err
	}
	fresh := lazyBitmap(&g.freshBlocks)
	for i := off; i < off+n; i++ {
		g.blocks.set(i)
		fresh.set(i)
	}
	g.desc.freeBlocks -= n
	v.freeBlocksTotal -= uint64(n)
	g.dirty = true
	return start, n, nil
}

// ensureHostLocked makes the host file cover every block below blockEnd on a
// tier that grows the file on demand.
func (v *volume) ensureHostLocked(blockEnd uint64) error {
	if v.hf.Tier() != tierFallback {
		return nil
	}
	need := int64(blockEnd) * blockSize
	if need <= v.hostBytes {
		return nil
	}
	if err := v.hf.EnsureSize(need); err != nil {
		return hostError(err)
	}
	size, err := v.hf.Size()
	if err != nil {
		return hostError(err)
	}
	v.hostBytes = size
	return nil
}

// freeBlocks returns n blocks from start to the pool. The blocks that the disk
// records as used stay held until the next flush ends.
func (v *volume) freeBlocks(start uint64, n uint32) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.freeBlocksLocked(start, n)
}

func (v *volume) freeBlocksLocked(start uint64, n uint32) error {
	for i := uint32(0); i < n; i++ {
		b := start + uint64(i)
		if !isValidDataBlock(b, v.blocksCountLocked()) {
			return corrupt("free of block %d outside the data area", b)
		}
		g := v.groups[b/blocksPerGroup]
		off := uint32(b % blocksPerGroup)
		if !g.blocks.test(off) {
			return corrupt("free of unallocated block %d", b)
		}
		g.blocks.clear(off)
		if g.freshBlocks != nil && g.freshBlocks.test(off) {
			g.freshBlocks.clear(off)
		} else {
			lazyBitmap(&g.heldBlocks).set(off)
			g.heldBlockCount++
			v.heldBlocksTotal++
		}
		g.desc.freeBlocks++
		v.freeBlocksTotal++
		g.dirty = true
	}
	return nil
}

// allocInode takes the lowest free inode number.
func (v *volume) allocInode(isDir bool) (uint32, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.readOnly {
		return 0, linuxerr.EROFS
	}
	for {
		for gi, g := range v.groups {
			if g.availInodes() == 0 {
				continue
			}
			idx := g.inodes.firstFree(0, g.heldInodes)
			if idx >= inodesPerGroup {
				continue
			}
			g.inodes.set(idx)
			lazyBitmap(&g.freshInodes).set(idx)
			g.desc.freeInodes--
			if isDir {
				g.desc.usedDirs++
			}
			v.freeInodesTotal--
			g.dirty = true
			return uint32(gi)*inodesPerGroup + idx + 1, nil
		}
		if v.heldInodesTotal > 0 {
			return 0, errSpaceHeld
		}
		if err := v.appendGroupLocked(); err != nil {
			return 0, err
		}
	}
}

// freeInode returns an inode number to the pool. The disk keeps the inode
// marked as used until the next flush ends, when it was in use before.
func (v *volume) freeInode(ino uint32, isDir bool) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if ino < firstIno || ino > uint32(len(v.groups))*inodesPerGroup {
		return corrupt("free of inode %d", ino)
	}
	gi, idx := (ino-1)/inodesPerGroup, (ino-1)%inodesPerGroup
	g := v.groups[gi]
	if !g.inodes.test(idx) {
		return corrupt("free of unallocated inode %d", ino)
	}
	g.inodes.clear(idx)
	if g.freshInodes != nil && g.freshInodes.test(idx) {
		g.freshInodes.clear(idx)
	} else {
		lazyBitmap(&g.heldInodes).set(idx)
		g.heldInodeCount++
		v.heldInodesTotal++
	}
	g.desc.freeInodes++
	if isDir && g.desc.usedDirs > 0 {
		g.desc.usedDirs--
	}
	v.freeInodesTotal++
	g.dirty = true
	return nil
}

// appendGroupLocked adds one 16 MiB block group at the end of the host file.
func (v *volume) appendGroupLocked() error {
	n := uint32(len(v.groups))
	if n >= maxGroups {
		return linuxerr.ENOSPC
	}
	if avail, err := v.hf.AvailBytes(); err == nil && avail < groupBytes {
		return linuxerr.ENOSPC
	}
	need := int64(n+1) * groupBytes
	if v.hf.Tier() == tierFallback {
		// The fallback tier extends the file on demand. The new group needs
		// its metadata area now.
		need = int64(groupStart(n)+uint64(metaBlocksOf(n))) * blockSize
	}
	if err := v.hf.EnsureSize(need); err != nil {
		return hostError(err)
	}
	size, err := v.hf.Size()
	if err != nil {
		return hostError(err)
	}
	v.hostBytes = size

	g := newGroup(n)
	v.groups = append(v.groups, g)
	v.freeBlocksTotal += uint64(g.desc.freeBlocks)
	v.freeInodesTotal += inodesPerGroup
	v.sbDirty = true
	v.descDirty = true
	if hasSuper(n) || descBlocks(n+1) != descBlocks(n) {
		v.resizeDirty = true
	}
	return nil
}

// groupIsEmpty reports whether group gi holds no block and no inode beyond
// its own metadata.
func (v *volume) groupIsEmpty(gi int) bool {
	g := v.groups[gi]
	return g.desc.freeBlocks == blocksPerGroup-metaBlocksOf(uint32(gi)) &&
		g.desc.freeInodes == inodesPerGroup &&
		g.heldBlockCount == 0 && g.heldInodeCount == 0
}

// trimGroupsLocked removes the empty groups at the end of the volume. It keeps
// group 0. It returns the number of removed groups. The caller flushes the
// metadata and then truncates the host file.
func (v *volume) trimGroupsLocked() int {
	removed := 0
	for len(v.groups) > 1 && v.groupIsEmpty(len(v.groups)-1) {
		gi := len(v.groups) - 1
		g := v.groups[gi]
		v.freeBlocksTotal -= uint64(g.desc.freeBlocks)
		v.freeInodesTotal -= uint64(g.desc.freeInodes)
		v.groups = v.groups[:gi]
		if hasSuper(uint32(gi)) || descBlocks(uint32(gi+1)) != descBlocks(uint32(gi)) {
			v.resizeDirty = true
		}
		removed++
	}
	if removed > 0 {
		v.sbDirty = true
		v.descDirty = true
	}
	return removed
}

// markWrittenLocked records that a write changed the bytes [off, off+n) of the
// host file. It sets the bit of every 4 KiB physical block that the range
// touches. A range beyond the last group has no bitmap, because the volume
// shrank, and the bits are dropped.
//
// Precondition: v.mu is held and v.migTracking is true.
func (v *volume) markWrittenLocked(off int64, n int) {
	if n <= 0 || off < 0 {
		return
	}
	first := uint64(off) / blockSize
	last := (uint64(off) + uint64(n) - 1) / blockSize
	for blk := first; blk <= last; blk++ {
		gi := blk / blocksPerGroup
		if gi >= uint64(len(v.groups)) {
			return
		}
		lazyBitmap(&v.groups[gi].migDirty).set(uint32(blk % blocksPerGroup))
	}
}

// allocatedExtentsLocked returns the allocated blocks of every group as runs of
// contiguous physical blocks in ascending order. A block is allocated when the
// block bitmap of its group has the bit. The bitmap marks the metadata blocks
// of the group, the file data, the directory blocks, the extent leaves, and
// the attribute blocks. A block that a guest freed and that waits for the next
// flush is free here.
//
// Precondition: v.mu is held.
func (v *volume) allocatedExtentsLocked() []BlockExtent {
	var out []BlockExtent
	for gi, g := range v.groups {
		out = appendBitmapRuns(out, groupStart(uint32(gi)), &g.blocks)
	}
	return out
}

// takeDirtyExtentsLocked returns the marked blocks of every group as runs and
// clears the marks.
//
// Precondition: v.mu is held.
func (v *volume) takeDirtyExtentsLocked() []BlockExtent {
	var out []BlockExtent
	for gi, g := range v.groups {
		if g.migDirty == nil {
			continue
		}
		out = appendBitmapRuns(out, groupStart(uint32(gi)), g.migDirty)
		g.migDirty = nil
	}
	return out
}

// appendBitmapRuns appends the runs of set bits of b to out. The bit i is the
// physical block start+i. A run that continues the last run of out joins it, so
// a run can cross the border between two groups.
func appendBitmapRuns(out []BlockExtent, start uint64, b *bitmap) []BlockExtent {
	for i := uint32(0); i < blocksPerGroup; {
		if !b.test(i) {
			i++
			continue
		}
		j := i + 1
		for j < blocksPerGroup && b.test(j) {
			j++
		}
		blk, n := start+uint64(i), uint64(j-i)
		if last := len(out) - 1; last >= 0 && out[last].Block+out[last].Count == blk {
			out[last].Count += n
		} else {
			out = append(out, BlockExtent{Block: blk, Count: n})
		}
		i = j
	}
	return out
}
