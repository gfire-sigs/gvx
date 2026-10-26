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
	"fmt"
	"slices"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// fsckLite repairs a volume that has no journal to replay: a volume of an older
// release, a volume that a tool left unclean, and a volume that a split
// transaction left with the error flag. A crash can leave bitmaps that disagree
// with the inodes, inodes that no directory names, and directory entries that
// name an inode that the disk does not hold.
//
// fsckLite walks the tree from the root inode, trusts only what the walk
// reaches, and rebuilds the bitmaps, the free counts, and the link counts from
// it. It frees every unreachable inode and its blocks. It creates no lost+found
// directory.
//
// A damaged object below the root does not fail the mount. The walk drops the
// directory entry that names it and goes on, so the volume keeps every other
// file. A directory block that does not parse becomes an empty block. Only a
// root inode that is not a directory fails with EUCLEAN, because no tree is left
// to keep.

// fsckInode is what the walk records about one reachable inode.
type fsckInode struct {
	mode    uint16
	links   uint32
	refs    uint32
	subdirs uint32
	parent  uint32
	dotdot  uint32
}

// fsckDrop names a directory entry that the repair removes.
type fsckDrop struct {
	dir    *node
	name   string
	reason string
}

// loadDirTolerantLocked reads the blocks of a directory and replaces a block
// that does not parse with an empty block. An empty first block gets the entries
// . and .. again. A name that two blocks list stays in the first block. It
// reports whether it changed anything. The caller holds n.mu for writing.
func (n *node) loadDirTolerantLocked(parent uint32) (repaired bool) {
	d := n.dir
	if d.loaded {
		return false
	}
	nb := n.size / blockSize
	blocks := make([]*dirBlock, 0, min(nb, n.mappedBlocks()))
	index := make(map[string]*dirEntry)
	var buf [blockSize]byte
	for lb := uint32(0); uint64(lb) < nb; lb++ {
		names := make(map[string]*dirEntry)
		var blk *dirBlock
		if phys, ok := n.physBlock(lb); ok {
			if _, err := n.v.hf.ReadAt(buf[:], int64(phys)*blockSize); err == nil {
				if b, perr := n.parseDirBlock(buf[:], lb == 0, names); perr == nil {
					blk = b
					repaired = repaired || b.dirty
				}
			}
		}
		if blk == nil {
			repaired = true
			blk = &dirBlock{dirty: true}
			names = make(map[string]*dirEntry)
			if lb == 0 {
				self := &dirEntry{name: ".", ino: n.ino, ft: ftDir, off: 0, blk: blk}
				up := &dirEntry{name: "..", ino: parent, ft: ftDir, off: entryLen(1), blk: blk}
				blk.entries = []*dirEntry{self, up}
				blk.used = entryLen(1) + entryLen(2)
				names[".."], names["."] = up, self
			}
		}
		for name, e := range names {
			if _, dup := index[name]; dup {
				blk.entries = slices.DeleteFunc(blk.entries, func(x *dirEntry) bool { return x == e })
				blk.used -= entryLen(len(name))
				blk.dirty, repaired = true, true
				continue
			}
			index[name] = e
		}
		blocks = append(blocks, blk)
	}
	d.blocks, d.index, d.loaded = blocks, index, true
	return repaired
}

func (v *volume) fsckLite() error {
	if v.readOnly {
		return corrupt("the volume was not unmounted cleanly and cannot be repaired in a read-only mount")
	}
	v.fsckMode = true
	defer func() { v.fsckMode = false }()
	nGroups := uint32(len(v.groups))
	claimed := make([]bitmap, nGroups)
	// run is a range of blocks that one inode owns.
	type run struct {
		blk uint64
		n   uint32
	}
	claimRuns := func(runs []run, owner uint32) error {
		for _, r := range runs {
			for i := uint32(0); i < r.n; i++ {
				b := r.blk + uint64(i)
				if claimed[b/blocksPerGroup].test(uint32(b % blocksPerGroup)) {
					return corrupt("block %d of inode %d is also owned by another inode", b, owner)
				}
			}
		}
		for _, r := range runs {
			for i := uint32(0); i < r.n; i++ {
				b := r.blk + uint64(i)
				claimed[b/blocksPerGroup].set(uint32(b % blocksPerGroup))
			}
		}
		return nil
	}

	// The resize inode owns its double indirect block, and the journal inode
	// owns the journal.
	blk, off := inodeLocation(resizeIno)
	var buf [blockSize]byte
	if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		return hostError(err)
	}
	dind := uint64(le.Uint32(buf[off+inBlock+inBlockDind*4:]))
	if dind != 0 && isValidDataBlock(dind, uint64(nGroups)*blocksPerGroup) {
		if err := claimRuns([]run{{dind, 1}}, resizeIno); err != nil {
			return err
		}
	}
	if v.j != nil {
		for _, e := range v.j.extents {
			if err := claimRuns([]run{{e.pblk, e.n}}, journalIno); err != nil {
				return err
			}
		}
	}

	seen := make(map[uint32]*fsckInode)
	// The loads of neighbouring inodes share one inode table block.
	var table [blockSize]byte
	tableBlock := ^uint64(0)
	load := func(ino uint32) (*node, error) {
		if ino != rootIno && (ino < firstIno || ino > nGroups*inodesPerGroup) {
			return nil, corrupt("directory entry names inode %d", ino)
		}
		blk, off := inodeLocation(ino)
		if blk != tableBlock {
			if _, err := v.hf.ReadAt(table[:], int64(blk)*blockSize); err != nil {
				return nil, hostError(err)
			}
			tableBlock = blk
		}
		raw := slices.Clone(table[off : off+inodeSize])
		// A directory entry names the inode, so the inode lives. A crash between
		// the write of a deleted inode and the write of its directory leaves
		// such an entry, and the link count is rebuilt below.
		if le.Uint16(raw[inLinks:]) == 0 {
			le.PutUint16(raw[inLinks:], 1)
		}
		n, err := v.parseInode(ino, raw)
		if err != nil {
			return nil, err
		}
		n.dtime = 0
		return n, nil
	}
	xattrOwned := make(map[uint64]bool)
	take := func(n *node, parent uint32) error {
		var runs []run
		for _, e := range n.exts {
			runs = append(runs, run{e.pblk, e.n})
		}
		for _, l := range n.leaves {
			runs = append(runs, run{l.blk, 1})
		}
		for _, x := range n.ixs {
			runs = append(runs, run{x.blk, 1})
		}
		if n.fileACL != 0 {
			if !isValidDataBlock(n.fileACL, uint64(nGroups)*blocksPerGroup) {
				return corrupt("inode %d xattr block %d is not valid", n.ino, n.fileACL)
			}
			// Several inodes can name one xattr block.
			if !xattrOwned[n.fileACL] {
				runs = append(runs, run{n.fileACL, 1})
			}
		}
		if err := claimRuns(runs, n.ino); err != nil {
			return err
		}
		if n.fileACL != 0 {
			xattrOwned[n.fileACL] = true
		}
		seen[n.ino] = &fsckInode{mode: n.mode, links: n.links, parent: parent}
		return nil
	}

	root, err := load(rootIno)
	if err != nil {
		return err
	}
	if !root.isDir() {
		return corrupt("root inode is not a directory")
	}
	if err := take(root, rootIno); err != nil {
		return err
	}
	var drops []fsckDrop
	repairedDirs := make(map[uint32]*node)
	stack := []*node{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		info := seen[dir.ino]
		dir.mu.Lock()
		if dir.loadDirTolerantLocked(info.parent) {
			repairedDirs[dir.ino] = dir
			v.repairNotes = append(v.repairNotes, fmt.Sprintf("directory inode %d had a damaged block", dir.ino))
		}
		var entries []*dirEntry
		for _, b := range dir.dir.blocks {
			entries = append(entries, b.entries...)
		}
		dir.mu.Unlock()
		for _, e := range entries {
			switch e.name {
			case ".":
				continue
			case "..":
				info.dotdot = e.ino
				continue
			}
			drop := func(reason string) {
				drops = append(drops, fsckDrop{dir, e.name, reason})
			}
			if child := seen[e.ino]; child != nil {
				if child.mode&modeTypeMask == modeDir {
					drop("the directory is reachable twice")
					continue
				}
				child.refs++
				continue
			}
			n, err := load(e.ino)
			if err != nil {
				drop(err.Error())
				continue
			}
			if err := take(n, dir.ino); err != nil {
				drop(err.Error())
				continue
			}
			if ft := fileTypeOfMode(n.mode); e.ft != ft {
				e.ft = ft
				e.blk.dirty = true
				repairedDirs[dir.ino] = dir
			}
			if n.isDir() {
				info.subdirs++
				stack = append(stack, n)
			} else {
				seen[n.ino].refs = 1
			}
		}
	}
	// The rebuild runs first. A removal of an entry can free the last block of
	// a directory, and it checks the bitmap that the rebuild writes.
	if err := v.rebuildFromWalk(seen, claimed); err != nil {
		return err
	}
	for _, dr := range drops {
		if err := dr.dir.removeEntry(dr.name); err != nil {
			return err
		}
		repairedDirs[dr.dir.ino] = dr.dir
		v.repairNotes = append(v.repairNotes, fmt.Sprintf("dropped the entry %q of directory inode %d: %s", dr.name, dr.dir.ino, dr.reason))
	}
	// A repaired directory lives only in memory. The cache must hold it, so that
	// later loads see the repair and the next flush writes it.
	for ino, dir := range repairedDirs {
		dir.mu.Lock()
		dir.markDirtyLocked()
		dir.mu.Unlock()
		v.nodeMu.Lock()
		v.nodes[ino] = dir
		v.nodeMu.Unlock()
	}
	return nil
}

// rebuildFromWalk rewrites the bitmaps and the counts from what the walk of
// fsckLite reached, and it queues the repairs of the link counts and of the ..
// entries.
func (v *volume) rebuildFromWalk(seen map[uint32]*fsckInode, claimed []bitmap) error {
	nGroups := uint32(len(v.groups))
	v.mu.Lock()
	defer v.mu.Unlock()
	v.freeBlocksTotal, v.freeInodesTotal = 0, 0
	v.heldBlocksTotal, v.heldInodesTotal = 0, 0
	usedDirs := make([]uint32, nGroups)
	for ino, info := range seen {
		if info.mode&modeTypeMask == modeDir {
			usedDirs[(ino-1)/inodesPerGroup]++
		}
	}
	for gi, g := range v.groups {
		g.blocks, g.inodes = bitmap{}, bitmap{}
		g.freshBlocks, g.freshInodes, g.heldBlocks, g.heldInodes = nil, nil, nil, nil
		g.heldBlockCount, g.heldInodeCount = 0, 0
		for b := uint32(0); b < metaBlocksOf(uint32(gi)); b++ {
			g.blocks.set(b)
		}
		for b := uint32(0); b < blocksPerGroup; b++ {
			if claimed[gi].test(b) {
				g.blocks.set(b)
			}
		}
		if gi == 0 {
			for i := uint32(0); i < firstIno-1; i++ {
				g.inodes.set(i)
			}
		}
		g.desc.usedDirs = usedDirs[gi]
		g.dirty = true
	}
	for ino := range seen {
		g := v.groups[(ino-1)/inodesPerGroup]
		g.inodes.set((ino - 1) % inodesPerGroup)
	}
	for _, g := range v.groups {
		g.desc.freeBlocks = blocksPerGroup - g.blocks.count()
		g.desc.freeInodes = inodesPerGroup - g.inodes.count()
		v.freeBlocksTotal += uint64(g.desc.freeBlocks)
		v.freeInodesTotal += uint64(g.desc.freeInodes)
	}
	// The error flag and the orphan list describe the damage that the walk just
	// repaired. Every orphan is an unreachable inode, which the rebuild freed.
	v.state &^= stateError
	v.setSbU32(sbLastOrphan, 0)
	v.sbDirty, v.descDirty = true, true

	// Queue the repairs of the link counts and of the .. entries. The mount
	// applies them after it has loaded the root.
	for ino, info := range seen {
		want := info.refs
		if info.mode&modeTypeMask == modeDir {
			want = 2 + info.subdirs
		}
		if want == 0 {
			return corrupt("inode %d has no reference", ino)
		}
		if want > 0xFFFF {
			return linuxerr.EMLINK
		}
		if info.links != want {
			ino, want := ino, want
			v.fixups = append(v.fixups, func() error {
				n, err := v.getNode(ino)
				if err != nil {
					return err
				}
				defer v.putNode(n)
				n.mu.Lock()
				n.links = want
				n.markDirtyLocked()
				n.mu.Unlock()
				return nil
			})
		}
		if info.mode&modeTypeMask == modeDir && info.dotdot != info.parent {
			ino, parent := ino, info.parent
			v.fixups = append(v.fixups, func() error {
				n, err := v.getNode(ino)
				if err != nil {
					return err
				}
				defer v.putNode(n)
				return n.setParent(parent)
			})
		}
	}
	return nil
}

// runFixups applies the repairs that fsckLite queued.
func (v *volume) runFixups() error {
	fix := v.fixups
	v.fixups = nil
	for _, f := range fix {
		if err := f(); err != nil {
			return err
		}
	}
	return nil
}
