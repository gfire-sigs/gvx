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

// The volume reserves 64 blocks behind the superblock for group descriptors:
// the blocks that the current groups need, and reserved blocks for growth.
// With the resize_inode feature, inode 7 lists the reserved blocks, so that
// e2fsck and the Linux kernel accept the layout. The inode has one double
// indirect block. That block names each reserved block. Each reserved block
// names its copy in every group that holds a superblock copy.
//
// The image of the inode follows from the number of groups. The volume builds
// it again at every flush after the number of groups changes. No file data
// ever moves when the volume grows.

const (
	resizeMode      = 0o100600
	resizePtrsPerBk = blockSize / 4
	// resizeSize is the size that mke2fs gives the resize inode: the largest
	// file that one double indirect block can address.
	resizeSize = (resizePtrsPerBk*resizePtrsPerBk + resizePtrsPerBk + 12) * blockSize
	// inBlockDind is the index of the double indirect pointer in i_block.
	inBlockDind = 13
)

// loadResizeInode reads the double indirect block of inode 7. A volume that
// was never flushed has none, and the next flush allocates one.
func (v *volume) loadResizeInode() error {
	blk, off := inodeLocation(resizeIno)
	var buf [blockSize]byte
	if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		return hostError(err)
	}
	raw := buf[off : off+inodeSize]
	dind := uint64(le.Uint32(raw[inBlock+inBlockDind*4:]))
	if dind == 0 {
		v.mu.Lock()
		v.resizeDirty = true
		v.mu.Unlock()
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if !isValidDataBlock(dind, v.blocksCountLocked()) {
		return corrupt("resize inode names block %d as its double indirect block", dind)
	}
	if !v.groups[dind/blocksPerGroup].blocks.test(uint32(dind % blocksPerGroup)) {
		return corrupt("resize inode block %d is not allocated", dind)
	}
	v.resizeDind = dind
	return nil
}

// buildResizeLocked adds the images of inode 7, of its double indirect block,
// and of the reserved descriptor blocks to the plan. The caller holds v.mu.
func (v *volume) buildResizeLocked(p *flushPlan) error {
	if v.resizeDind == 0 {
		start, _, err := v.allocBlocksLocked(0, 1)
		if err != nil {
			return err
		}
		v.resizeDind = start
	}
	groups := uint32(len(v.groups))
	d := descBlocks(groups)
	r := reservedGDTBlocks(groups)
	backups := backupGroups(groups)

	var dind [blockSize]byte
	for i := uint32(0); i < r; i++ {
		le.PutUint32(dind[((d+i)%resizePtrsPerBk)*4:], uint32(1+d+i))
	}
	p.resize = append(p.resize, blockWrite{v.resizeDind, dind[:]})
	for i := uint32(0); i < r; i++ {
		blk := uint64(1 + d + i)
		var rb [blockSize]byte
		for k, g := range backups {
			le.PutUint32(rb[k*4:], uint32(blk+groupStart(g)))
		}
		p.resize = append(p.resize, blockWrite{blk, rb[:]})
	}

	var im inodeImage
	im.ino = resizeIno
	raw := im.raw[:]
	t := le.Uint32(v.sb[sbMkfsTime:])
	le.PutUint16(raw[inMode:], resizeMode)
	size := uint64(resizeSize)
	le.PutUint32(raw[inSizeLo:], uint32(size))
	le.PutUint32(raw[inSizeHi:], uint32(size>>32))
	le.PutUint32(raw[inAtime:], t)
	le.PutUint32(raw[inCtime:], t)
	le.PutUint32(raw[inMtime:], t)
	le.PutUint16(raw[inLinks:], 1)
	le.PutUint32(raw[inBlocksLo:], (1+r+r*uint32(len(backups)))*(blockSize/512))
	le.PutUint32(raw[inBlock+inBlockDind*4:], uint32(v.resizeDind))
	le.PutUint16(raw[inExtraSize:], extraIsize)
	le.PutUint32(raw[inCrtime:], t)
	p.inodes = append(p.inodes, im)
	return nil
}
