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

// A guest can unlink a file and keep it open. The inode then has no link, but
// its blocks stay in use until the last descriptor closes. A crash in between
// would leak the blocks, because no directory names the inode, and a journaled
// volume has no tree walk to find them.
//
// ext4 solves this with the orphan list. The superblock field s_last_orphan
// names the first inode of a list, and the field i_dtime of each inode in the
// list names the next one. The mount frees every inode of the list. ext4lite
// keeps the same format, so the Linux kernel can clean the list too.
//
// The volume derives the list from the nodes that have no link and that a
// guest still holds. The snapshot of a flush rebuilds the chain when this set
// changes, so each transaction holds a consistent chain.

import (
	"slices"
)

// updateOrphans refreshes the set of orphan nodes from the nodes that the
// snapshot copied. When the set changes, it rebuilds the chain and adds the
// changed inodes to the plan. The gate is closed.
func (v *volume) updateOrphans(p *flushPlan, dirty []*node) {
	changed := false
	for _, n := range dirty {
		n.mu.Lock()
		live := n.links == 0 && !n.deleted && n.ino >= firstIno
		n.mu.Unlock()
		_, in := v.orphans[n.ino]
		switch {
		case live && !in:
			v.orphans[n.ino] = n
			changed = true
		case !live && in:
			delete(v.orphans, n.ino)
			n.mu.Lock()
			n.orphan = false
			n.mu.Unlock()
			changed = true
		}
	}
	if !changed {
		return
	}
	inos := make([]uint32, 0, len(v.orphans))
	for ino := range v.orphans {
		inos = append(inos, ino)
	}
	slices.Sort(inos)
	v.orphanHead = 0
	if len(inos) > 0 {
		v.orphanHead = inos[0]
	}
	for i, ino := range inos {
		var next uint32
		if i+1 < len(inos) {
			next = inos[i+1]
		}
		n := v.orphans[ino]
		n.mu.Lock()
		if !n.orphan || n.dtime != next {
			n.orphan = true
			n.dtime = next
			p.inodes = append(p.inodes, n.serializeLocked())
		}
		n.mu.Unlock()
	}
	p.orphanChanged = true
}

// cleanOrphans frees the inodes of the orphan list. A writable mount calls it
// after the volume loaded its groups. The frees go to the first transaction.
func (v *volume) cleanOrphans() (bool, error) {
	head := v.sbU32(sbLastOrphan)
	if head == 0 {
		return false, nil
	}
	inodes := v.numGroups() * inodesPerGroup
	seen := make(map[uint32]bool)
	for ino := head; ino != 0; {
		if ino < firstIno || ino > inodes || seen[ino] {
			// The rest of the chain is damaged. Dropping it leaks the inodes
			// that it names, and an offline check finds them.
			break
		}
		seen[ino] = true
		blk, off := inodeLocation(ino)
		var buf [blockSize]byte
		if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
			return false, hostError(err)
		}
		raw := buf[off : off+inodeSize]
		next := le.Uint32(raw[inDtime:])
		if le.Uint16(raw[inLinks:]) == 0 {
			// parseInode refuses an inode with no link. The orphan is about to
			// go, so the parse sees one link and the node then drops it.
			le.PutUint16(raw[inLinks:], 1)
			// A damaged orphan is not worth a failed mount. The inode and its
			// blocks stay allocated until an offline check finds them.
			if n, err := v.parseInode(ino, raw); err == nil {
				n.links = 0
				n.mu.Lock()
				_ = n.destroyLocked()
				n.mu.Unlock()
			}
		}
		ino = next
	}
	v.mu.Lock()
	v.setSbU32(sbLastOrphan, 0)
	v.sbDirty = true
	v.mu.Unlock()
	return true, nil
}
