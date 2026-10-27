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

// A volume is a row of block groups of 4,096 blocks. Group g covers the blocks
// [g*4096, (g+1)*4096). Every meta-group of 64 block groups stores its 4 KiB
// descriptor block at the start of its first group (with backups in the second
// and last groups of the meta-group). A group that holds a superblock copy
// places the superblock at its first block, ahead of any descriptor block.
// The bitmaps, the inode table, and the data blocks follow.
//
//	+0                block bitmap (after superblock and meta_bg descriptor)
//	+1                inode bitmap
//	+2..+257          inode table
//	+258..+end        data and directory blocks
//
// The sparse_super feature limits the superblock copies to group 0, group 1,
// and the groups that are a power of 3, 5, or 7.

// isPowerOf reports whether n is a power of base, with the exponent 1 or more.
func isPowerOf(n, base uint32) bool {
	for {
		if n < base {
			return false
		}
		if n == base {
			return true
		}
		if n%base != 0 {
			return false
		}
		n /= base
	}
}

// hasSuper reports whether group g holds a copy of the superblock.
func hasSuper(g uint32) bool {
	if g <= 1 {
		return true
	}
	if g&1 == 0 {
		return false
	}
	return isPowerOf(g, 3) || isPowerOf(g, 5) || isPowerOf(g, 7)
}

// superBlocksOf returns 1 when group g holds a superblock copy, and 0 otherwise.
func superBlocksOf(g uint32) uint64 {
	if hasSuper(g) {
		return 1
	}
	return 0
}

// hasMetaDesc reports whether group g holds a primary or backup descriptor
// block of its meta-group.
func hasMetaDesc(g uint32) bool {
	rem := g % descsPerBlock
	return rem == 0 || rem == 1 || rem == descsPerBlock-1
}

// groupOverhead returns the number of blocks at the start of group g that hold
// a superblock copy and a meta-group descriptor block.
func groupOverhead(g uint32) uint64 {
	ov := superBlocksOf(g)
	if hasMetaDesc(g) {
		ov++
	}
	return ov
}

// primaryDescBlock returns the block that holds the primary copy of descriptor
// block bi.
func primaryDescBlock(bi uint32) uint64 {
	bg := bi * descsPerBlock
	return groupStart(bg) + superBlocksOf(bg)
}

// metaDescBlock returns the descriptor block inside group g of a meta-group.
func metaDescBlock(g uint32) uint64 {
	return groupStart(g) + superBlocksOf(g)
}

// inodesOfGroup returns the number of allocatable inodes in group g. Groups at
// or above maxInodeGroups hold data blocks only so that 32-bit inode numbers
// and s_inodes_count never overflow.
func inodesOfGroup(g uint32) uint32 {
	if g >= maxInodeGroups {
		return 0
	}
	return inodesPerGroup
}

func groupStart(g uint32) uint64 { return uint64(g) * blocksPerGroup }

func blockBitmapBlock(g uint32) uint64 { return groupStart(g) + groupOverhead(g) }
func inodeBitmapBlock(g uint32) uint64 { return blockBitmapBlock(g) + 1 }
func inodeTableStart(g uint32) uint64  { return blockBitmapBlock(g) + 2 }

// dataStartBlock returns the first block of group g that file data can use.
func dataStartBlock(g uint32) uint64 { return inodeTableStart(g) + inodeTableBlocks }

// descBlocks returns the number of descriptor blocks that groups groups need.
func descBlocks(groups uint32) uint32 {
	return (groups + descsPerBlock - 1) / descsPerBlock
}

// isMetadataBlock reports whether block b belongs to the superblock, the
// descriptor area, a bitmap, or an inode table of a volume of groups groups.
func isMetadataBlock(b uint64) bool {
	g := uint32(b / blocksPerGroup)
	return b%blocksPerGroup < groupOverhead(g)+2+inodeTableBlocks
}

// isValidDataBlock reports whether block b can hold file data, a directory
// block, an extent leaf, or an xattr block in a volume of blocksCount blocks.
// It rejects every block that overlaps the superblock, the descriptor area,
// a bitmap, or an inode table.
func isValidDataBlock(b, blocksCount uint64) bool {
	return b < blocksCount && !isMetadataBlock(b)
}

// inodeLocation returns the block and the byte offset of inode ino in the
// inode table. ino counts from 1.
func inodeLocation(ino uint32) (block uint64, off int) {
	idx := ino - 1
	g := idx / inodesPerGroup
	within := idx % inodesPerGroup
	return inodeTableStart(g) + uint64(within/inodesPerBlock), int(within%inodesPerBlock) * inodeSize
}
