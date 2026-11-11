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

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/fsutilx"
)

// The fallocate modes that change the mapping of a file. A zero range, a
// collapse, and an insert only change the extent list and the size of the
// inode, so one transaction of the journal holds each of them. Only the bytes
// of a partial edge block change in place, as with a punch.

// allocOp is the operation that a fallocate mode selects.
type allocOp = fsutilx.FallocateOp

const (
	allocReserve  = fsutilx.FallocateReserve
	allocPunch    = fsutilx.FallocatePunchHole
	allocZero     = fsutilx.FallocateZeroRange
	allocCollapse = fsutilx.FallocateCollapseRange
	allocInsert   = fsutilx.FallocateInsertRange
)

// parseAllocMode validates a fallocate mode as the Linux function
// vfs_fallocate and the function ext4_fallocate do. The mode names one
// operation and the optional flag FALLOC_FL_KEEP_SIZE.
func parseAllocMode(mode uint64) (op allocOp, keepSize bool, err error) {
	return fsutilx.ParseFallocateMode(mode, fsutilx.Ext4FallocateModes)
}

// zeroRange makes the bytes of [off, off+length) read as zeros. A whole block
// of the range becomes part of an uninitialized extent, and a hole of the range
// gets new uninitialized blocks, as ext4 does. The bytes of a partial block at
// an edge are cleared in place, and only in a block that holds data. The size
// grows to the end of the range unless keepSize is set. The node changes
// nothing when the call fails. The caller checked that the end of the range
// lies within maxFileSize.
func (n *node) zeroRange(off, length uint64, keepSize bool) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	end := off + length
	if n.flags&flagInlineData != 0 {
		if end <= maxInline {
			if lo, hi := min(off, uint64(len(n.inline))), min(end, uint64(len(n.inline))); lo < hi {
				clear(n.inline[lo:hi])
				n.markDirtyLocked()
			}
			if !keepSize && end > n.size {
				return n.truncateLocked(end)
			}
			return nil
		}
		if err := n.convertInlineLocked(); err != nil {
			return err
		}
	}
	if n.flags&flagExtents == 0 || n.isDir() {
		return linuxerr.EINVAL
	}
	first, last := (off+blockSize-1)/blockSize, end/blockSize
	// A range inside one block has first above last. Its two edges then name
	// the same bytes, so one of them stays.
	edges := [][2]uint64{{off, min(end, first*blockSize)}, {max(off, last*blockSize), end}}
	if first > last {
		edges = edges[:1]
	}
	// The mapping goes first, because it is the step that can fail for lack of
	// space. A failed call then has changed no byte. The edge blocks lie outside
	// the blocks that the mapping converts.
	if first < last {
		list, fresh, err := n.zeroMappingLocked(uint32(first), uint32(last))
		if err != nil {
			return err
		}
		if err := n.installMappingLocked(list, fresh, allBlocks); err != nil {
			return err
		}
	}
	if err := n.clearEdgesLocked(edges); err != nil {
		n.markDirtyLocked()
		return err
	}
	if !keepSize && end > n.size {
		n.size = end
	}
	n.markDirtyLocked()
	return nil
}

// clearEdgesLocked clears each byte range of edges that lies in a block with
// data. A hole and an uninitialized block already read as zeros.
func (n *node) clearEdgesLocked(edges [][2]uint64) error {
	for _, edge := range edges {
		if edge[0] >= edge[1] {
			continue
		}
		lblk := uint32(edge[0] / blockSize)
		e, ok := extentAt(n.exts, lblk)
		if !ok || e.uninit {
			continue
		}
		zero := make([]byte, edge[1]-edge[0])
		if _, err := n.v.hf.WriteAt(zero, int64(e.pbn(lblk))*blockSize+int64(edge[0]%blockSize)); err != nil {
			return hostError(err)
		}
	}
	return nil
}

// zeroMappingLocked returns the extent list of the node after the file blocks
// [lb0, lb1) turn into uninitialized blocks, and the new runs that the list
// adds. A failure frees the new runs and returns no list. The caller installs
// the list and owns the new runs from then on.
func (n *node) zeroMappingLocked(lb0, lb1 uint32) (list, fresh []extent, err error) {
	out := make([]extent, 0, len(n.exts)+2)
	pos := lb0
	fill := func(until uint32) error {
		for pos < until {
			blk, got, err := n.v.allocBlocks(n.goalLocked(fresh, pos), min(until-pos, maxUninitExtentLen))
			if err != nil {
				return err
			}
			e := extent{lblk: pos, n: got, pblk: blk, uninit: true}
			fresh = append(fresh, e)
			out = appendRun(out, e)
			pos += got
		}
		return nil
	}
	for _, e := range n.exts {
		switch {
		case e.end() <= lb0:
			out = appendRun(out, e)
		case e.lblk >= lb1:
			if err = fill(lb1); err != nil {
				break
			}
			out = appendRun(out, e)
		default:
			lo, hi := max(e.lblk, lb0), min(e.end(), lb1)
			if e.lblk < lo {
				out = appendRun(out, e.sub(e.lblk, lo))
			}
			if err = fill(lo); err != nil {
				break
			}
			for mid := e.sub(lo, hi); mid.n > 0; {
				part := mid.sub(mid.lblk, mid.lblk+min(mid.n, maxUninitExtentLen))
				part.uninit = true
				out = appendRun(out, part)
				if part.n == mid.n {
					break
				}
				mid = mid.sub(part.end(), mid.end())
			}
			pos = hi
			if hi < e.end() {
				out = appendRun(out, e.sub(hi, e.end()))
			}
		}
		if err != nil {
			break
		}
	}
	if err == nil {
		err = fill(lb1)
	}
	if err == nil && len(out) > maxTreeExtents {
		err = linuxerr.ENOSPC
	}
	if err != nil {
		return nil, nil, joinCleanup(err, n.v.freeRunsFrom(fresh, 0))
	}
	return out, fresh, nil
}

// collapseRange removes the file blocks of [off, off+length) and moves the
// blocks behind them down. The size shrinks by length. Linux demands block
// alignment and a range that ends below the end of the file, because a range
// to the end is a truncate.
func (n *node) collapseRange(off, length uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if (off|length)%blockSize != 0 || off+length >= n.size {
		return linuxerr.EINVAL
	}
	if n.flags&flagExtents == 0 || n.isDir() {
		return linuxerr.EINVAL
	}
	lb0, lb1 := uint32(off/blockSize), uint32((off+length)/blockSize)
	kept, freed := removeRange(n.exts, lb0, lb1)
	list := make([]extent, 0, len(kept))
	for _, e := range kept {
		if e.lblk >= lb1 {
			e.lblk -= lb1 - lb0
		}
		list = appendRun(list, e)
	}
	if err := n.setExtentsLocked(list); err != nil {
		return err
	}
	var errs []error
	for _, f := range freed {
		n.nblocks -= uint64(f.n)
		errs = append(errs, n.v.freeBlocks(f.pblk, f.n))
	}
	n.size -= length
	n.markDirtyLocked()
	return errors.Join(errs...)
}

// insertRange opens a hole of length bytes at off. The blocks from off move up,
// and the size grows by length. Linux demands block alignment and an offset
// below the end of the file.
func (n *node) insertRange(off, length uint64) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if (off|length)%blockSize != 0 {
		return linuxerr.EINVAL
	}
	if length > maxFileSize-n.size {
		return linuxerr.EFBIG
	}
	if off >= n.size {
		return linuxerr.EINVAL
	}
	if err := n.convertInlineLocked(); err != nil {
		return err
	}
	if n.flags&flagExtents == 0 || n.isDir() {
		return linuxerr.EINVAL
	}
	lb0, shift := uint32(off/blockSize), uint32(length/blockSize)
	list := make([]extent, 0, len(n.exts)+1)
	for _, e := range n.exts {
		if e.end() <= lb0 {
			list = appendRun(list, e)
			continue
		}
		if uint64(e.end())+uint64(shift) > maxLogicalBlock {
			return linuxerr.EFBIG
		}
		if e.lblk < lb0 {
			list = appendRun(list, e.sub(e.lblk, lb0))
			e = e.sub(lb0, e.end())
		}
		e.lblk += shift
		list = appendRun(list, e)
	}
	if err := n.setExtentsLocked(list); err != nil {
		return err
	}
	n.size += length
	n.markDirtyLocked()
	return nil
}
