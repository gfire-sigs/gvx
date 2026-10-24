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

import "z.gfire.dev/gvx/pkg/errors/linuxerr"

// fsckLite repairs a volume that was not unmounted cleanly. The volume has no
// journal, so a crash can leave bitmaps that disagree with the inodes and
// inodes that no directory names. fsckLite walks the tree from the root
// inode, trusts only what the walk reaches, and rebuilds the bitmaps, the
// free counts, and the link counts from it. It frees every unreachable inode
// and its blocks. It creates no lost+found directory. An image that the walk
// proves to be damaged, with a directory cycle, a block that two inodes own,
// or a bad bound, fails with EUCLEAN and stays unchanged on the host.

// fsckInode is what the walk records about one reachable inode.
type fsckInode struct {
	mode    uint16
	links   uint32
	refs    uint32
	subdirs uint32
	parent  uint32
	dotdot  uint32
}

func (v *volume) fsckLite() error {
	if v.readOnly {
		return corrupt("the volume was not unmounted cleanly and cannot be repaired in a read-only mount")
	}
	nGroups := uint32(len(v.groups))
	claimed := make([]bitmap, nGroups)
	claim := func(blk uint64, n uint32, owner uint32) error {
		for i := uint32(0); i < n; i++ {
			b := blk + uint64(i)
			bm := &claimed[b/blocksPerGroup]
			off := uint32(b % blocksPerGroup)
			if bm.test(off) {
				return corrupt("block %d of inode %d is also owned by another inode", b, owner)
			}
			bm.set(off)
		}
		return nil
	}

	// The resize inode owns its double indirect block.
	blk, off := inodeLocation(resizeIno)
	var buf [blockSize]byte
	if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		return hostError(err)
	}
	dind := uint64(le.Uint32(buf[off+inBlock+inBlockDind*4:]))
	if dind != 0 && isValidDataBlock(dind, uint64(nGroups)*blocksPerGroup) {
		if err := claim(dind, 1, resizeIno); err != nil {
			return err
		}
	}

	seen := make(map[uint32]*fsckInode)
	load := func(ino uint32) (*node, error) {
		if ino != rootIno && (ino < firstIno || ino > nGroups*inodesPerGroup) {
			return nil, corrupt("directory entry names inode %d", ino)
		}
		blk, off := inodeLocation(ino)
		var b [blockSize]byte
		if _, err := v.hf.ReadAt(b[:], int64(blk)*blockSize); err != nil {
			return nil, hostError(err)
		}
		return v.parseInode(ino, b[off:off+inodeSize])
	}
	take := func(n *node, parent uint32) error {
		for _, e := range n.exts {
			if err := claim(e.pblk, e.n, n.ino); err != nil {
				return err
			}
		}
		for _, l := range n.leaves {
			if err := claim(l, 1, n.ino); err != nil {
				return err
			}
		}
		if n.fileACL != 0 {
			if !isValidDataBlock(n.fileACL, uint64(nGroups)*blocksPerGroup) {
				return corrupt("inode %d xattr block %d is not valid", n.ino, n.fileACL)
			}
			if err := claim(n.fileACL, 1, n.ino); err != nil {
				return err
			}
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
	stack := []*node{root}
	for len(stack) > 0 {
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		info := seen[dir.ino]
		dir.mu.Lock()
		err := dir.loadDirLocked()
		dir.mu.Unlock()
		if err != nil {
			return err
		}
		for _, b := range dir.dir.blocks {
			for _, e := range b.entries {
				switch e.name {
				case ".":
					continue
				case "..":
					info.dotdot = e.ino
					continue
				}
				if child := seen[e.ino]; child != nil {
					if child.mode&modeTypeMask == modeDir {
						return corrupt("directory inode %d is reachable twice, through inode %d", e.ino, dir.ino)
					}
					child.refs++
					continue
				}
				n, err := load(e.ino)
				if err != nil {
					return err
				}
				if err := take(n, dir.ino); err != nil {
					return err
				}
				if n.isDir() {
					info.subdirs++
					stack = append(stack, n)
				} else {
					seen[n.ino].refs = 1
				}
			}
		}
	}

	// Rebuild the bitmaps and the counts from the walk.
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
