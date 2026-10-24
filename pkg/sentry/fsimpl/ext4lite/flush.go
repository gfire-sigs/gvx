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

// The dirtyTracker of the specification is spread over three places. Every
// node registers itself in volume.dirtyNodes when a change needs a write.
// Every group has a dirty flag for its bitmaps and its descriptor. The volume
// has flags for the superblock, the descriptor area, and the resize inode.
//
// A flush follows the order that keeps a crash safe. The data blocks are
// already on the host, because every write system call writes them through to
// the host file. Then the flush writes the extent leaf blocks and the xattr
// blocks, then the inode table blocks, then the directory blocks, and last the
// bitmaps, the descriptors, and the superblock. A crash in the middle leaves
// a state that fsckLite repairs at the next mount: a directory entry never
// names an inode that the disk has not seen, and an inode never names a leaf
// that the disk has not seen.

import "slices"

// blockWrite is one 4 KiB block image for the host file.
type blockWrite struct {
	blk  uint64
	data []byte
}

// inodeImage is the image of one inode for the inode table.
type inodeImage struct {
	ino uint32
	raw [inodeSize]byte
}

// groupSnap records the holds that one flush releases when it succeeds.
type groupSnap struct {
	gi                     uint32
	heldBlocks, heldInodes *bitmap
}

// flushPlan collects the images of one flush.
type flushPlan struct {
	leaves   []blockWrite
	inodes   []inodeImage
	dirs     []blockWrite
	bitmaps  []blockWrite
	descs    []blockWrite
	resize   []blockWrite
	backups  []blockWrite
	super    blockWrite
	hasSuper bool
	backupOf []uint32

	nodes  []*node
	groups []groupSnap
	// snapshot of the flags that a failure restores
	sbDirty, descDirty, resizeDirty bool
}

// empty reports whether the plan writes nothing.
func (p *flushPlan) empty() bool {
	return len(p.leaves) == 0 && len(p.inodes) == 0 && len(p.dirs) == 0 && len(p.bitmaps) == 0 &&
		len(p.descs) == 0 && len(p.resize) == 0 && len(p.backups) == 0 && !p.hasSuper
}

// markDirty registers n for the next flush. The caller holds n.mu.
func (v *volume) markDirty(n *node) {
	v.nodeMu.Lock()
	v.dirtyNodes[n.ino] = n
	v.nodeMu.Unlock()
}

// sync writes every dirty metadata block in the strict order and flushes the
// host file. Callers write their own dirty data before they call sync.
func (v *volume) sync() error {
	v.flushMu.Lock()
	defer v.flushMu.Unlock()
	return v.flushLocked()
}

func (v *volume) flushLocked() error {
	if v.readOnly {
		return nil
	}
	plan := &flushPlan{}

	v.nodeMu.Lock()
	dirty := make([]*node, 0, len(v.dirtyNodes))
	for _, n := range v.dirtyNodes {
		dirty = append(dirty, n)
	}
	clear(v.dirtyNodes)
	v.nodeMu.Unlock()
	slices.SortFunc(dirty, func(a, b *node) int { return int(a.ino) - int(b.ino) })
	for _, n := range dirty {
		n.snapshot(plan)
	}
	plan.nodes = dirty

	v.mu.Lock()
	err := v.snapshotAllocLocked(plan)
	v.mu.Unlock()
	if err != nil {
		v.restorePlan(plan)
		return err
	}
	if plan.empty() {
		return nil
	}
	if err := plan.write(v.hf); err != nil {
		v.restorePlan(plan)
		return hostError(err)
	}
	if err := v.hf.Sync(); err != nil {
		v.restorePlan(plan)
		return hostError(err)
	}
	v.commitPlan(plan)
	v.evictIdle(plan.nodes)
	v.mu.Lock()
	v.flushedOnce = true
	v.mu.Unlock()
	return nil
}

// snapshotAllocLocked captures the bitmaps, the descriptors, the resize inode,
// and the superblock. The caller holds v.mu.
func (v *volume) snapshotAllocLocked(p *flushPlan) error {
	p.sbDirty, p.descDirty, p.resizeDirty = v.sbDirty, v.descDirty, v.resizeDirty

	if v.resizeDirty {
		if err := v.buildResizeLocked(p); err != nil {
			return err
		}
		v.resizeDirty = false
	}

	descBlocksDirty := make(map[uint32]bool)
	for gi, g := range v.groups {
		if !g.dirty && !v.descDirty {
			continue
		}
		if g.dirty {
			var bm [blockSize]byte
			g.blocks.encode(bm[:])
			fill(bm[bitmapWords*8:], 0xFF)
			p.bitmaps = append(p.bitmaps, blockWrite{g.desc.blockBitmap, bm[:]})
			var ib [blockSize]byte
			g.inodes.encode(ib[:])
			fill(ib[bitmapWords*8:], 0xFF)
			p.bitmaps = append(p.bitmaps, blockWrite{g.desc.inodeBitmap, ib[:]})
			descBlocksDirty[uint32(gi)/descsPerBlock] = true
			snap := groupSnap{gi: uint32(gi)}
			if g.heldBlocks != nil {
				c := *g.heldBlocks
				snap.heldBlocks = &c
			}
			if g.heldInodes != nil {
				c := *g.heldInodes
				snap.heldInodes = &c
			}
			p.groups = append(p.groups, snap)
			// The flush records every block that it writes now. A block that a
			// later free releases must wait for the next flush.
			g.freshBlocks, g.freshInodes = nil, nil
			g.dirty = false
		}
	}
	if v.descDirty {
		for i := uint32(0); i < descBlocks(uint32(len(v.groups))); i++ {
			descBlocksDirty[i] = true
		}
	}
	for bi := range descBlocksDirty {
		var blk [blockSize]byte
		for j := uint32(0); j < descsPerBlock; j++ {
			gi := bi*descsPerBlock + j
			if gi >= uint32(len(v.groups)) {
				break
			}
			v.groups[gi].desc.encode(blk[j*descSize:])
		}
		p.descs = append(p.descs, blockWrite{1 + uint64(bi), blk[:]})
	}
	slices.SortFunc(p.descs, func(a, b blockWrite) int { return int(a.blk) - int(b.blk) })

	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	p.super = blockWrite{0, b0[:]}
	p.hasSuper = v.sbDirty || len(p.bitmaps) > 0 || len(p.descs) > 0 || len(p.resize) > 0

	// A new group with a superblock copy gets its copy of block 0 and of the
	// descriptor blocks. Later flushes leave the copies as they are, as the
	// kernel does outside a resize.
	for gi, g := range v.groups {
		if !g.needsBackup {
			continue
		}
		g.needsBackup = false
		p.backupOf = append(p.backupOf, uint32(gi))
		start := groupStart(uint32(gi))
		cp := b0
		le.PutUint16(cp[superOffset+sbBlockGroupNr:], uint16(gi))
		p.backups = append(p.backups, blockWrite{start, cp[:]})
		for _, d := range p.descs {
			p.backups = append(p.backups, blockWrite{start + d.blk, d.data})
		}
		if len(p.descs) == 0 {
			for i := uint32(0); i < descBlocks(uint32(len(v.groups))); i++ {
				var blk [blockSize]byte
				for j := uint32(0); j < descsPerBlock; j++ {
					g2 := i*descsPerBlock + j
					if g2 >= uint32(len(v.groups)) {
						break
					}
					v.groups[g2].desc.encode(blk[j*descSize:])
				}
				p.backups = append(p.backups, blockWrite{start + 1 + uint64(i), blk[:]})
			}
		}
	}
	v.sbDirty, v.descDirty = false, false
	return nil
}

func fill(b []byte, x byte) {
	for i := range b {
		b[i] = x
	}
}

// fillSuperLocked refreshes the counters of the superblock image.
func (v *volume) fillSuperLocked() {
	blocks := v.blocksCountLocked()
	v.setSbU32(sbBlocksCountLo, uint32(blocks))
	v.setSbU32(sbBlocksCountHi, uint32(blocks>>32))
	v.setSbU32(sbInodesCount, uint32(len(v.groups))*inodesPerGroup)
	v.setSbU32(sbFreeBlocksLo, uint32(v.freeBlocksTotal))
	v.setSbU32(sbFreeBlocksHi, uint32(v.freeBlocksTotal>>32))
	v.setSbU32(sbFreeInodes, uint32(v.freeInodesTotal))
	v.setSbU16(sbReservedGDT, uint16(reservedGDTBlocks(uint32(len(v.groups)))))
	v.setSbU16(sbState, v.state)
	v.setSbU32(sbWtime, uint32(v.now().Unix()))
}

// write sends the images to the host file in the order of the specification.
func (p *flushPlan) write(hf hostFile) error {
	for _, w := range p.leaves {
		if _, err := hf.WriteAt(w.data, int64(w.blk)*blockSize); err != nil {
			return err
		}
	}
	if err := writeInodeImages(hf, p.inodes); err != nil {
		return err
	}
	for _, w := range p.dirs {
		if _, err := hf.WriteAt(w.data, int64(w.blk)*blockSize); err != nil {
			return err
		}
	}
	for _, list := range [][]blockWrite{p.resize, p.bitmaps, p.descs, p.backups} {
		for _, w := range list {
			if _, err := hf.WriteAt(w.data, int64(w.blk)*blockSize); err != nil {
				return err
			}
		}
	}
	if p.hasSuper {
		if _, err := hf.WriteAt(p.super.data, 0); err != nil {
			return err
		}
	}
	return nil
}

// writeInodeImages patches the inode table blocks. Each block holds 16 inodes.
func writeInodeImages(hf hostFile, imgs []inodeImage) error {
	byBlock := make(map[uint64][]*inodeImage)
	var order []uint64
	for i := range imgs {
		blk, _ := inodeLocation(imgs[i].ino)
		if _, ok := byBlock[blk]; !ok {
			order = append(order, blk)
		}
		byBlock[blk] = append(byBlock[blk], &imgs[i])
	}
	slices.Sort(order)
	var buf [blockSize]byte
	for _, blk := range order {
		if _, err := hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
			return err
		}
		for _, im := range byBlock[blk] {
			_, off := inodeLocation(im.ino)
			copy(buf[off:off+inodeSize], im.raw[:])
		}
		if _, err := hf.WriteAt(buf[:], int64(blk)*blockSize); err != nil {
			return err
		}
	}
	return nil
}

// commitPlan releases the holds that the flush covered.
func (v *volume) commitPlan(p *flushPlan) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, s := range p.groups {
		if s.gi >= uint32(len(v.groups)) {
			continue
		}
		g := v.groups[s.gi]
		if s.heldBlocks != nil && g.heldBlocks != nil {
			g.heldBlocks.andNot(s.heldBlocks)
			now := g.heldBlocks.count()
			v.heldBlocksTotal -= uint64(g.heldBlockCount - now)
			g.heldBlockCount = now
			if now == 0 {
				g.heldBlocks = nil
			}
		}
		if s.heldInodes != nil && g.heldInodes != nil {
			g.heldInodes.andNot(s.heldInodes)
			now := g.heldInodes.count()
			v.heldInodesTotal -= uint64(g.heldInodeCount - now)
			g.heldInodeCount = now
			if now == 0 {
				g.heldInodes = nil
			}
		}
	}
}

// restorePlan makes the next flush write again what a failed flush tried.
func (v *volume) restorePlan(p *flushPlan) {
	for _, n := range p.nodes {
		n.markAllDirty()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, s := range p.groups {
		if s.gi < uint32(len(v.groups)) {
			v.groups[s.gi].dirty = true
		}
	}
	v.sbDirty = v.sbDirty || p.sbDirty
	v.descDirty = v.descDirty || p.descDirty
	v.resizeDirty = v.resizeDirty || p.resizeDirty
	for _, gi := range p.backupOf {
		if gi < uint32(len(v.groups)) {
			v.groups[gi].needsBackup = true
		}
	}
}

// writeSuperblockNow writes block 0 and syncs the host file. The mount uses it
// to clear the valid bit before the first write of a guest.
func (v *volume) writeSuperblockNow() error {
	v.mu.Lock()
	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	v.sbDirty = false
	v.mu.Unlock()
	if _, err := v.hf.WriteAt(b0[:], 0); err != nil {
		return hostError(err)
	}
	return hostError(v.hf.Sync())
}
