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
)

// A clean unmount returns the unused tail of the host file to the host. The
// shutdown first moves the blocks of the trailing groups into free holes of
// lower groups, so that a volume that once held much data and now holds
// little shrinks. It moves blocks only. An inode keeps its number, so a group
// that holds an inode stays.

// errNoRoom reports that a relocation found no free block below the target.
var errNoRoom = errors.New("ext4lite: no free block below the compaction target")

// shutdownLocked ends a writable mount. The caller holds flushMu.
func (v *volume) shutdownLocked() error {
	var errs []error
	v.destroyUnlinkedNodes()
	if err := v.flushLocked(); err != nil {
		return err
	}
	if err := v.compactLocked(); err != nil {
		// The volume stays marked as not clean. The next mount runs fsckLite.
		errs = append(errs, err)
	}
	v.mu.Lock()
	removed := v.trimGroupsLocked()
	groups := len(v.groups)
	v.mu.Unlock()
	if removed > 0 {
		if err := v.flushLocked(); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}
	if v.hf.Tier() != tierFallback || removed > 0 {
		want := int64(groups) * groupBytes
		if size, err := v.hf.Size(); err == nil && size != want {
			if err := v.hf.Truncate(want); err != nil {
				return errors.Join(append(errs, hostError(err))...)
			}
		}
	} else if err := v.hf.EnsureSize(int64(groups) * groupBytes); err != nil {
		errs = append(errs, hostError(err))
	}
	if len(errs) == 0 {
		v.mu.Lock()
		v.state |= stateValid
		v.sbDirty = true
		v.mu.Unlock()
	}
	if err := v.writeSuperblockNow(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// destroyUnlinkedNodes frees the nodes that no directory names. A guest that
// unlinked a file and kept it open leaves such a node behind.
func (v *volume) destroyUnlinkedNodes() {
	v.nodeMu.Lock()
	var nodes []*node
	for _, n := range v.nodes {
		nodes = append(nodes, n)
	}
	v.nodeMu.Unlock()
	for _, n := range nodes {
		n.mu.Lock()
		if n.links == 0 && !n.deleted {
			_ = n.destroyLocked()
		}
		n.mu.Unlock()
	}
}

// compactTarget returns the first group whose blocks move to lower groups, or
// the number of groups when nothing moves. A group qualifies when it holds no
// inode and its used blocks fit into the free space below it.
func (v *volume) compactTarget() uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := uint32(len(v.groups))
	freeBelow := make([]uint64, n+1)
	for i, g := range v.groups {
		freeBelow[i+1] = freeBelow[i] + uint64(g.desc.freeBlocks)
	}
	lo := n
	var used uint64
	for gi := n - 1; gi >= 1; gi-- {
		g := v.groups[gi]
		if g.desc.freeInodes != inodesPerGroup || g.heldBlockCount != 0 {
			break
		}
		if v.resizeDind/blocksPerGroup == uint64(gi) {
			break
		}
		used += uint64(blocksPerGroup - metaBlocksOf(gi) - g.desc.freeBlocks)
		if used > freeBelow[gi] {
			break
		}
		lo = gi
	}
	return lo
}

// compactLocked moves the blocks of the trailing groups downward and flushes
// the result. The caller holds flushMu.
func (v *volume) compactLocked() error {
	lo := v.compactTarget()
	if lo >= v.numGroups() {
		return nil
	}
	low := uint64(lo) * blocksPerGroup
	var errs []error
	for _, ino := range v.allocatedInodes() {
		n, err := v.getNode(ino)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		n.mu.Lock()
		err = n.relocateLocked(low)
		n.mu.Unlock()
		v.putNode(n)
		if err == errNoRoom {
			break
		}
		if err != nil {
			errs = append(errs, err)
		}
	}
	if err := v.flushLocked(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// allocatedInodes lists the inode numbers that hold a file, a directory, or
// another object.
func (v *volume) allocatedInodes() []uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []uint32
	for gi, g := range v.groups {
		for idx := uint32(0); idx < inodesPerGroup; idx++ {
			if !g.inodes.test(idx) {
				continue
			}
			ino := uint32(gi)*inodesPerGroup + idx + 1
			if ino == rootIno || ino >= firstIno {
				out = append(out, ino)
			}
		}
	}
	return out
}

// relocateLocked moves every block of the node at or above low to a free block
// below low. The caller holds n.mu.
func (n *node) relocateLocked(low uint64) error {
	touched := n.fileACL >= low && n.fileACL != 0
	for _, l := range n.leaves {
		touched = touched || l >= low
	}
	for _, e := range n.exts {
		touched = touched || e.pblk >= low
	}
	if !touched {
		return nil
	}
	if n.isDir() {
		if err := n.loadDirLocked(); err != nil {
			return err
		}
		for _, b := range n.dir.blocks {
			b.dirty = true
		}
	}
	if n.fileACL >= low && n.fileACL != 0 {
		if _, err := n.xattrsLocked(); err != nil {
			return err
		}
		nb, err := n.moveBlock(n.fileACL, low)
		if err != nil {
			return err
		}
		n.fileACL = nb
		n.dirtyXattr = true
	}
	for i, l := range n.leaves {
		if l < low {
			continue
		}
		nb, err := n.moveBlock(l, low)
		if err != nil {
			return err
		}
		n.leaves[i] = nb
		n.dirtyLeaf = true
	}
	var list []extent
	for _, e := range n.exts {
		if e.pblk < low {
			list = insertMapping(list, e)
			continue
		}
		moved, err := n.moveExtent(e, low)
		for _, m := range moved {
			list = insertMapping(list, m)
		}
		if err != nil {
			// Keep the part that did not move.
			rest := e
			var done uint32
			for _, m := range moved {
				done += m.n
			}
			if done < e.n {
				rest = extent{lblk: e.lblk + done, n: e.n - done, pblk: e.pbn(e.lblk + done)}
				list = insertMapping(list, rest)
			}
			for _, e2 := range n.exts[indexAfter(n.exts, e):] {
				list = insertMapping(list, e2)
			}
			// A failure here leaves the volume marked as not clean, so the next
			// mount runs fsckLite.
			if serr := n.setExtentsLocked(list); serr != nil {
				err = errors.Join(err, serr)
			}
			n.markDirtyLocked()
			return err
		}
	}
	if err := n.setExtentsLocked(list); err != nil {
		return err
	}
	n.markDirtyLocked()
	return nil
}

// indexAfter returns the index of the extent after e in list.
func indexAfter(list []extent, e extent) int {
	for i := range list {
		if list[i].lblk == e.lblk {
			return i + 1
		}
	}
	return len(list)
}

// moveBlock copies one block to a free block below low and frees the old one.
func (n *node) moveBlock(blk, low uint64) (uint64, error) {
	dst, got, err := n.v.allocBlocks(0, 1)
	if err != nil {
		return 0, err
	}
	if dst >= low || got != 1 {
		_ = n.v.freeBlocks(dst, got)
		return 0, errNoRoom
	}
	var buf [blockSize]byte
	if _, err := n.v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		_ = n.v.freeBlocks(dst, 1)
		return 0, hostError(err)
	}
	if _, err := n.v.hf.WriteAt(buf[:], int64(dst)*blockSize); err != nil {
		_ = n.v.freeBlocks(dst, 1)
		return 0, hostError(err)
	}
	if err := n.v.freeBlocks(blk, 1); err != nil {
		return 0, err
	}
	return dst, nil
}

// moveExtent copies the blocks of e into free runs below low and frees the
// blocks of e that it copied. It returns the new extents, which cover the
// start of e when it fails in the middle.
func (n *node) moveExtent(e extent, low uint64) ([]extent, error) {
	var out []extent
	buf := make([]byte, 1<<20)
	for done := uint32(0); done < e.n; {
		dst, got, err := n.v.allocBlocks(0, e.n-done)
		if err != nil {
			return out, err
		}
		if dst >= low {
			_ = n.v.freeBlocks(dst, got)
			return out, errNoRoom
		}
		src := e.pblk + uint64(done)
		for off := uint64(0); off < uint64(got)*blockSize; off += uint64(len(buf)) {
			chunk := buf[:min(uint64(len(buf)), uint64(got)*blockSize-off)]
			if _, err := n.v.hf.ReadAt(chunk, int64(src)*blockSize+int64(off)); err != nil && !errors.Is(err, io.EOF) {
				_ = n.v.freeBlocks(dst, got)
				return out, hostError(err)
			}
			if _, err := n.v.hf.WriteAt(chunk, int64(dst)*blockSize+int64(off)); err != nil {
				_ = n.v.freeBlocks(dst, got)
				return out, hostError(err)
			}
		}
		if err := n.v.freeBlocks(src, got); err != nil {
			return out, err
		}
		out = append(out, extent{lblk: e.lblk + done, n: got, pblk: dst})
		done += got
	}
	return out, nil
}
