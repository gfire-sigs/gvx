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

// errNoRoom reports that the free space below the compaction target cannot hold
// a move. The inode stays where it is.
var errNoRoom = errors.New("ext4lite: no free block below the compaction target")

// shutdownLocked ends a writable mount. The caller holds flushMu.
func (v *volume) shutdownLocked() error {
	var errs []error
	v.destroyUnlinkedNodes()
	if err := v.flushLocked(); err != nil {
		return err
	}
	compactErr := v.compactLocked()
	if compactErr != nil {
		// The volume stays marked as not clean. The next mount runs fsckLite. An
		// inode that a failed move left in a trailing group still needs that group,
		// so the shutdown keeps every group and the host file size.
		errs = append(errs, compactErr)
	}
	removed := 0
	if compactErr == nil {
		v.mu.Lock()
		removed = v.trimGroupsLocked()
		v.mu.Unlock()
		if removed > 0 {
			if err := v.flushLocked(); err != nil {
				return errors.Join(append(errs, err)...)
			}
		}
	}
	v.mu.Lock()
	groups := len(v.groups)
	v.mu.Unlock()
	if v.j != nil {
		// The log must be empty before the host file shrinks. A later replay
		// would write the blocks of a removed group beyond the end of the file.
		if err := v.endSession(true); err != nil {
			return errors.Join(append(errs, err)...)
		}
	}
	want := int64(groups) * groupBytes
	if compactErr == nil && (v.hf.Tier() != tierFallback || removed > 0) {
		if size, err := v.hf.Size(); err == nil && size != want {
			if err := v.hf.Truncate(want); err != nil {
				return errors.Join(append(errs, hostError(err))...)
			}
		}
	} else if v.hf.Tier() == tierFallback {
		if err := v.hf.EnsureSize(want); err != nil {
			errs = append(errs, hostError(err))
		}
	}
	if v.j != nil {
		return errors.Join(errs...)
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
		if g.desc.freeInodes != inodesOfGroup(gi) || g.heldBlockCount != 0 {
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
// the result. An inode that cannot move stays where it is, and that is no
// error. The caller holds flushMu.
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
		if err != nil && !errors.Is(err, errNoRoom) {
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

// runMove is a data run that moves below the target. dst holds the new runs
// that replace src. Their file blocks are the blocks of src.
type runMove struct {
	src extent
	dst []extent
}

// relocateLocked moves every block of the node at or above low to a free block
// below low. It plans the whole move before it copies a block. A move that
// needs more extents than a tree holds is skipped. A move that lacks free
// blocks below low returns errNoRoom. Either way the node keeps its blocks. Any
// other failure rolls the plan back, so the node also keeps its blocks. The
// caller holds n.mu for writing.
func (n *node) relocateLocked(low uint64) (err error) {
	if !n.touchedAbove(low) {
		return nil
	}
	if n.isDir() {
		if err := n.loadDirLocked(); err != nil {
			return err
		}
	}
	if n.fileACL >= low {
		if _, err := n.xattrsLocked(); err != nil {
			return err
		}
	}
	var (
		moves     []runMove
		newList   []extent
		tree      treeUpdate
		newACL    uint64
		committed bool
	)
	defer func() {
		if !committed {
			err = joinCleanup(err, n.releaseMoveLocked(moves, tree, newACL))
		}
	}()

	// Plan the data runs. A run that lies below low stays where it is.
	for _, e := range n.exts {
		if e.pblk < low {
			newList = appendRun(newList, e)
			continue
		}
		dst, err := n.allocBelowLocked(low, e)
		if err != nil {
			return err
		}
		moves = append(moves, runMove{src: e, dst: dst})
		for _, d := range dst {
			newList = appendRun(newList, d)
		}
	}
	if len(newList) > maxTreeExtents {
		return nil
	}
	below := func(uint64) (uint64, error) { return n.allocBelowOneLocked(low) }
	tree, err = n.prepareTreeLocked(newList, func(blk uint64) bool { return blk < low }, below)
	if err != nil {
		return err
	}
	if n.fileACL >= low {
		if newACL, err = n.allocBelowOneLocked(low); err != nil {
			return err
		}
	}

	// Copy the data. The old runs stay allocated until the commit.
	for _, m := range moves {
		for _, d := range m.dst {
			if err := n.copyBlocks(m.src.pbn(d.lblk), d.pblk, d.n); err != nil {
				return err
			}
		}
	}

	// A shared xattr block stays for the other names. The node gives up its
	// name and writes its attributes to the new private block. A failure here
	// still rolls the plan back.
	sharedACL := newACL != 0 && n.xa != nil && n.xa.shared
	if sharedACL {
		if err := n.releaseShareLocked(); err != nil {
			return err
		}
		n.xa.shared = false
	}

	committed = true
	n.commitTreeLocked(tree)
	var errs []error
	for _, m := range moves {
		errs = append(errs, n.v.freeBlocks(m.src.pblk, m.src.n))
	}
	if newACL != 0 {
		if !sharedACL {
			errs = append(errs, n.v.freeBlocks(n.fileACL, 1))
		}
		n.fileACL = newACL
		n.dirtyXattr = true
	}
	if n.isDir() {
		for _, b := range n.dir.blocks {
			b.dirty = true
		}
	}
	return errors.Join(errs...)
}

// touchedAbove reports whether the node holds a block at or above low.
func (n *node) touchedAbove(low uint64) bool {
	if n.fileACL >= low {
		return true
	}
	for _, l := range n.leaves {
		if l.blk >= low {
			return true
		}
	}
	for _, x := range n.ixs {
		if x.blk >= low {
			return true
		}
	}
	for _, e := range n.exts {
		if e.pblk >= low {
			return true
		}
	}
	return false
}

// releaseMoveLocked frees the blocks that a move allocated and did not commit.
func (n *node) releaseMoveLocked(moves []runMove, tree treeUpdate, newACL uint64) error {
	var errs []error
	for _, m := range moves {
		for _, d := range m.dst {
			errs = append(errs, n.v.freeBlocks(d.pblk, d.n))
		}
	}
	errs = append(errs, tree.abandon(n.v))
	if newACL != 0 {
		errs = append(errs, n.v.freeBlocks(newACL, 1))
	}
	return errors.Join(errs...)
}

// allocBelowLocked takes free runs below low that hold the blocks of e. The
// returned runs carry the file blocks of e. A failure frees the runs that it
// took already.
func (n *node) allocBelowLocked(low uint64, e extent) ([]extent, error) {
	var out []extent
	for done := uint32(0); done < e.n; {
		blk, got, err := n.v.allocBlocks(0, e.n-done)
		if err == nil && blk >= low {
			err = joinCleanup(errNoRoom, n.v.freeBlocks(blk, got))
		}
		if err != nil {
			return nil, joinCleanup(err, n.releaseRuns(out))
		}
		out = append(out, extent{lblk: e.lblk + done, n: got, pblk: blk, uninit: e.uninit})
		done += got
	}
	return out, nil
}

// releaseRuns frees the host blocks of the runs.
func (n *node) releaseRuns(runs []extent) error {
	var errs []error
	for _, r := range runs {
		errs = append(errs, n.v.freeBlocks(r.pblk, r.n))
	}
	return errors.Join(errs...)
}

// allocBelowOneLocked takes one free block below low.
func (n *node) allocBelowOneLocked(low uint64) (uint64, error) {
	blk, got, err := n.v.allocBlocks(0, 1)
	if err != nil {
		return 0, err
	}
	if blk >= low {
		return 0, joinCleanup(errNoRoom, n.v.freeBlocks(blk, got))
	}
	return blk, nil
}

// copyBlocks copies count blocks from host block src to host block dst. A read
// past the end of the host file yields zeros.
func (n *node) copyBlocks(src, dst uint64, count uint32) error {
	buf := make([]byte, 1<<20)
	total := uint64(count) * blockSize
	for off := uint64(0); off < total; off += uint64(len(buf)) {
		chunk := buf[:min(uint64(len(buf)), total-off)]
		k, err := n.v.hf.ReadAt(chunk, int64(src)*blockSize+int64(off))
		if err != nil && !errors.Is(err, io.EOF) {
			return hostError(err)
		}
		clear(chunk[k:])
		if _, err := n.v.hf.WriteAt(chunk, int64(dst)*blockSize+int64(off)); err != nil {
			return hostError(err)
		}
	}
	return nil
}
