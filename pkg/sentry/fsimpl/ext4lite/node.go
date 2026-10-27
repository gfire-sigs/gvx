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
	"bytes"
	"sync"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// tstamp is a time with nanosecond resolution.
type tstamp struct {
	sec  int64
	nsec uint32
}

// encodeTime returns the seconds field and the extra field of an inode time.
// The extra field holds the nanoseconds above two bits of epoch.
func encodeTime(t tstamp) (lo, extra uint32) {
	epoch := uint32((t.sec-int64(int32(t.sec)))>>32) & 3
	return uint32(t.sec), t.nsec<<2 | epoch
}

// maxNsec is the largest valid nanosecond count of a timestamp.
const maxNsec = 999_999_999

// decodeTime returns the time of an inode time field. A hostile extra field can
// hold more nanoseconds than a second has, so the count is clamped.
func decodeTime(lo, extra uint32) tstamp {
	return tstamp{sec: int64(int32(lo)) + int64(extra&3)<<32, nsec: min(extra>>2, maxNsec)}
}

// node is the in-memory copy of one inode. The volume keeps one node for each
// inode number in use. The fields below mu are protected by mu.
//
// A regular file or a symlink starts with its content inside the inode. A write
// that does not fit moves the content to extents. A directory always uses
// extents. Special files hold no content.
type node struct {
	v   *volume
	ino uint32

	// refs counts the holders of the node. The volume protects it with
	// nodeMu.
	refs int

	mu sync.RWMutex

	mode  uint16
	uid   uint32
	gid   uint32
	links uint32
	flags uint32
	size  uint64
	atime tstamp
	mtime tstamp
	ctime tstamp
	// crtime is the creation time.
	crtime tstamp
	dtime  uint32
	gen    uint32
	rdev   uint32

	// inline holds the content while flags has flagInlineData.
	inline []byte
	// exts maps the file blocks that hold data. A file block that no extent
	// covers is a hole.
	exts []extent
	// leaves lists the extent leaf blocks in order. A tree read from disk may
	// hold fewer extents in a leaf than a full leaf does.
	leaves []leafBlock
	// ixs lists the index blocks of a tree of depth 2 or more in level order.
	ixs []indexBlock
	// ixLevels groups the index blocks by on-disk eh_depth (1..depth-1).
	ixLevels [][]indexBlock
	// nblocks counts the blocks that the inode owns: data, leaves, and the
	// xattr block.
	nblocks uint64

	dir *dirData
	xa  *xattrData

	// fileACL is the block of the xattr block, or 0.
	fileACL uint64
	// xattrRelease is the refcount write that this node owes for a shared
	// xattr block that it gave up. It stays set, so a later flush of the node
	// writes the current count again until the block is freed.
	xattrRelease *xattrRelease

	dirtyInode bool
	dirtyLeaf  bool
	dirtyXattr bool
	deleted    bool
	// orphan is true while the node is in the orphan list of the volume. The
	// field dtime then holds the next inode of the list.
	orphan bool
}

func (n *node) isDir() bool     { return n.mode&modeTypeMask == modeDir }
func (n *node) isRegular() bool { return n.mode&modeTypeMask == modeRegular }
func (n *node) isSymlink() bool { return n.mode&modeTypeMask == modeSymlink }

// hasContent reports whether the node type stores bytes in blocks or inline.
func (n *node) hasContent() bool { return n.isRegular() || n.isSymlink() || n.isDir() }

// fileType returns the directory entry type of the node.
func (n *node) fileType() uint8 { return fileTypeOfMode(n.mode) }

func fileTypeOfMode(mode uint16) uint8 {
	switch mode & modeTypeMask {
	case modeRegular:
		return ftRegular
	case modeDir:
		return ftDir
	case modeChar:
		return ftChar
	case modeBlock:
		return ftBlock
	case modeFIFO:
		return ftFIFO
	case modeSocket:
		return ftSocket
	case modeSymlink:
		return ftSymlink
	}
	return ftUnknown
}

// markDirtyLocked registers the inode for the next flush. The caller holds
// n.mu for writing.
func (n *node) markDirtyLocked() {
	n.dirtyInode = true
	n.v.markDirty(n)
}

// markAllDirty makes the next flush write every block of the node again. A
// failed flush calls it.
func (n *node) markAllDirty() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.dirtyInode = true
	n.dirtyLeaf = true
	n.dirtyXattr = true
	if n.dir != nil {
		for _, b := range n.dir.blocks {
			b.dirty = true
		}
	}
	n.v.markDirty(n)
}

// maxInline is the largest content that the inode holds without a block: the
// 60 bytes of i_block and the value of the system.data attribute in the space
// behind the extra fields. The attribute needs its magic number, one entry,
// and the four zero bytes that end the entry list.
const maxInline = iBlockSize + ibodySize - 4 - inlineXattrEntry - 4

// getNode returns the node of inode ino and adds a reference. The caller calls
// putNode once for each call.
func (v *volume) getNode(ino uint32) (*node, error) {
	v.nodeMu.Lock()
	if n, ok := v.nodes[ino]; ok {
		n.refs++
		v.nodeMu.Unlock()
		return n, nil
	}
	v.nodeMu.Unlock()

	n, err := v.loadNode(ino)
	if err != nil {
		return nil, err
	}
	v.nodeMu.Lock()
	defer v.nodeMu.Unlock()
	if existing, ok := v.nodes[ino]; ok {
		existing.refs++
		return existing, nil
	}
	n.refs = 1
	v.nodes[ino] = n
	return n, nil
}

// putNode drops a reference. The last reference of an unlinked node frees the
// storage of the node.
func (v *volume) putNode(n *node) {
	v.nodeMu.Lock()
	n.refs--
	last := n.refs == 0
	v.nodeMu.Unlock()
	if !last {
		return
	}
	// The last reference can drop after the unlink call returned, so the free
	// of the blocks and the inode enters the gate on its own.
	v.gate.enterInner()
	defer v.gate.exit()
	n.mu.Lock()
	unlinked := n.links == 0 && !n.deleted
	if unlinked {
		_ = n.destroyLocked()
	}
	dirty := n.dirtyInode || n.dirtyLeaf || n.dirtyXattr
	n.mu.Unlock()
	if !dirty {
		v.evict(n)
	}
}

// evict removes an idle clean node from the cache.
func (v *volume) evict(n *node) {
	v.nodeMu.Lock()
	defer v.nodeMu.Unlock()
	if n.refs == 0 && v.nodes[n.ino] == n {
		delete(v.nodes, n.ino)
	}
}

// evictIdle removes every idle node that the last flush wrote.
func (v *volume) evictIdle(nodes []*node) {
	for _, n := range nodes {
		n.mu.RLock()
		dirty := n.dirtyInode || n.dirtyLeaf || n.dirtyXattr
		n.mu.RUnlock()
		if !dirty {
			v.evict(n)
		}
	}
}

// newNode allocates an inode and returns an unlinked node with one reference.
// A regular file or symlink starts empty inside the inode. The caller sets
// the link count and links the node into a directory.
func (v *volume) newNode(mode uint16, uid, gid, rdev uint32, now tstamp) (*node, error) {
	isDir := mode&modeTypeMask == modeDir
	ino, err := v.allocInode(isDir)
	if err != nil {
		return nil, err
	}
	n := &node{
		v: v, ino: ino, mode: mode, uid: uid, gid: gid, rdev: rdev,
		atime: now, mtime: now, ctime: now, crtime: now,
		gen: uint32(now.nsec) ^ ino*2654435761,
	}
	switch {
	case isDir:
		n.flags = flagExtents
		n.dir = &dirData{index: make(map[string]*dirEntry)}
	case n.isRegular() || n.isSymlink():
		n.flags = flagInlineData
	}
	n.refs = 1
	v.nodeMu.Lock()
	v.nodes[ino] = n
	v.nodeMu.Unlock()
	n.mu.Lock()
	n.markDirtyLocked()
	n.mu.Unlock()
	return n, nil
}

// destroyLocked frees the blocks and the inode of an unlinked node. The caller
// holds n.mu for writing and no reference remains.
func (n *node) destroyLocked() error {
	var errs error
	if err := n.freeAllBlocksLocked(); err != nil {
		errs = err
	}
	if n.fileACL != 0 {
		if err := n.dropXattrBlockLocked(); err != nil && errs == nil {
			errs = err
		}
		n.fileACL = 0
	}
	if err := n.v.freeInode(n.ino, n.isDir()); err != nil && errs == nil {
		errs = err
	}
	n.deleted = true
	n.orphan = false
	n.nblocks = 0
	n.inline, n.exts, n.leaves, n.ixs, n.ixLevels = nil, nil, nil, nil, nil
	n.dir, n.xa = nil, nil
	n.markDirtyLocked()
	return errs
}

// loadNode reads inode ino from the inode table and checks it.
func (v *volume) loadNode(ino uint32) (*node, error) {
	v.mu.Lock()
	groups := uint32(len(v.groups))
	if ino < 1 || ino > groups*inodesPerGroup || (ino < firstIno && ino != rootIno) {
		v.mu.Unlock()
		return nil, corrupt("inode number %d is not valid", ino)
	}
	g := v.groups[(ino-1)/inodesPerGroup]
	allocated := g.inodes.test((ino - 1) % inodesPerGroup)
	v.mu.Unlock()
	if !allocated {
		return nil, corrupt("inode %d is not allocated", ino)
	}
	blk, off := inodeLocation(ino)
	var buf [blockSize]byte
	if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		return nil, hostError(err)
	}
	return v.parseInode(ino, buf[off:off+inodeSize])
}

// parseInode decodes and validates the raw inode.
func (v *volume) parseInode(ino uint32, raw []byte) (*node, error) {
	n := &node{v: v, ino: ino}
	n.mode = le.Uint16(raw[inMode:])
	n.uid = uint32(le.Uint16(raw[inUID:])) | uint32(le.Uint16(raw[inUIDHi:]))<<16
	n.gid = uint32(le.Uint16(raw[inGID:])) | uint32(le.Uint16(raw[inGIDHi:]))<<16
	n.links = uint32(le.Uint16(raw[inLinks:]))
	n.flags = le.Uint32(raw[inFlags:])
	n.size = uint64(le.Uint32(raw[inSizeLo:])) | uint64(le.Uint32(raw[inSizeHi:]))<<32
	n.dtime = le.Uint32(raw[inDtime:])
	n.gen = le.Uint32(raw[inGen:])
	n.fileACL = uint64(le.Uint32(raw[inFileACLLo:])) | uint64(le.Uint16(raw[inFileACLHi:]))<<32
	sectors := uint64(le.Uint32(raw[inBlocksLo:])) | uint64(le.Uint16(raw[inBlocksHi:]))<<32
	n.nblocks = sectors / (blockSize / 512)
	if extra := le.Uint16(raw[inExtraSize:]); extra < 28 {
		// A smaller extra area has no time fields. Read the seconds only.
		n.atime = decodeTime(le.Uint32(raw[inAtime:]), 0)
		n.ctime = decodeTime(le.Uint32(raw[inCtime:]), 0)
		n.mtime = decodeTime(le.Uint32(raw[inMtime:]), 0)
		n.crtime = n.ctime
	} else {
		n.atime = decodeTime(le.Uint32(raw[inAtime:]), le.Uint32(raw[inAtimeEx:]))
		n.ctime = decodeTime(le.Uint32(raw[inCtime:]), le.Uint32(raw[inCtimeEx:]))
		n.mtime = decodeTime(le.Uint32(raw[inMtime:]), le.Uint32(raw[inMtimeEx:]))
		n.crtime = decodeTime(le.Uint32(raw[inCrtime:]), le.Uint32(raw[inCrtimeEx:]))
	}
	if n.links == 0 {
		return nil, corrupt("inode %d is allocated and has no link", ino)
	}
	switch n.mode & modeTypeMask {
	case modeRegular, modeDir, modeSymlink:
		if err := n.parseContent(raw); err != nil {
			return nil, err
		}
	case modeChar, modeBlock:
		// i_block[0] holds the old encoding of a small device number. i_block[1]
		// holds the new encoding, which is the device number of the Sentry.
		if old := le.Uint32(raw[inBlock:]); old != 0 {
			n.rdev = old&0xFF | (old>>8&0xFF)<<8
		} else {
			n.rdev = le.Uint32(raw[inBlock+4:])
		}
	case modeFIFO, modeSocket:
	default:
		return nil, corrupt("inode %d has the mode %#o", ino, n.mode)
	}
	if !n.hasContent() {
		// A device or a pipe has no content, but it can keep attributes.
		if _, err := n.ibodyData(raw); err != nil {
			return nil, err
		}
	}
	if err := n.validateSize(); err != nil {
		return nil, err
	}
	if n.isDir() {
		n.dir = &dirData{index: make(map[string]*dirEntry)}
	}
	if err := n.readXattrRef(); err != nil {
		return nil, err
	}
	return n, nil
}

// validateSize checks the size of the node against its type. A directory must
// be covered by its extents, so the size never reaches a block that the inode
// does not map. The check runs after the content is parsed.
func (n *node) validateSize() error {
	switch {
	case n.isRegular():
		if n.size > maxFileSize {
			return corrupt("regular inode %d has the size %d", n.ino, n.size)
		}
	case n.isSymlink():
		if n.size == 0 || n.size > maxSymlinkTarget {
			return corrupt("symlink inode %d has the size %d", n.ino, n.size)
		}
	case n.isDir():
		blocks := n.size / blockSize
		if n.size == 0 || n.size%blockSize != 0 || n.flags&flagExtents == 0 || blocks > maxDirBlocks || !mappedPrefix(n.exts, blocks) {
			return corrupt("directory inode %d has the size %d or a bad format", n.ino, n.size)
		}
	}
	return nil
}

// fastSymlink reports whether the node is a symlink whose target is short
// enough for a fast symlink. ext4 keeps such a target in i_block with no flag
// set, and e2fsck rejects the inline form for it.
func (n *node) fastSymlink() bool {
	return n.isSymlink() && n.flags&flagInlineData != 0 && len(n.inline) > 0 && len(n.inline) < iBlockSize
}

// parseContent reads i_block as inline content or as an extent tree.
func (n *node) parseContent(raw []byte) error {
	if n.isSymlink() && n.flags&(flagInlineData|flagExtents) == 0 {
		// Compare the 64-bit size before the conversion to int, which can wrap.
		if n.size == 0 || n.size >= iBlockSize {
			return corrupt("fast symlink inode %d has a bad target size", n.ino)
		}
		size := int(n.size)
		if raw[inBlock+size] != 0 || bytes.IndexByte(raw[inBlock:inBlock+size], 0) >= 0 {
			return corrupt("fast symlink inode %d has a bad target", n.ino)
		}
		if _, err := n.ibodyData(raw); err != nil {
			return err
		}
		n.flags |= flagInlineData
		n.inline = bytes.Clone(raw[inBlock : inBlock+size])
		return nil
	}
	switch {
	case n.flags&flagInlineData != 0:
		if n.flags&flagExtents != 0 {
			return corrupt("inode %d has both the inline and the extent flag", n.ino)
		}
		if n.isDir() {
			return corrupt("directory inode %d stores its content inline", n.ino)
		}
		return n.parseInline(raw)
	case n.flags&flagExtents != 0:
		if _, err := n.ibodyData(raw); err != nil {
			return err
		}
		return n.parseExtents(raw)
	}
	return corrupt("inode %d has neither the inline nor the extent flag", n.ino)
}

// serialize returns the inode image. The caller holds n.mu.
func (n *node) serializeLocked() (im inodeImage) {
	im.ino = n.ino
	if n.deleted {
		return im
	}
	raw := im.raw[:]
	le.PutUint16(raw[inMode:], n.mode)
	le.PutUint16(raw[inUID:], uint16(n.uid))
	le.PutUint16(raw[inUIDHi:], uint16(n.uid>>16))
	le.PutUint16(raw[inGID:], uint16(n.gid))
	le.PutUint16(raw[inGIDHi:], uint16(n.gid>>16))
	le.PutUint32(raw[inSizeLo:], uint32(n.size))
	le.PutUint32(raw[inSizeHi:], uint32(n.size>>32))
	le.PutUint16(raw[inLinks:], uint16(n.links))
	sectors := n.nblocks * (blockSize / 512)
	le.PutUint32(raw[inBlocksLo:], uint32(sectors))
	le.PutUint16(raw[inBlocksHi:], uint16(sectors>>32))
	flags := n.flags
	if n.fastSymlink() {
		flags &^= flagInlineData
	}
	le.PutUint32(raw[inFlags:], flags)
	le.PutUint32(raw[inGen:], n.gen)
	le.PutUint32(raw[inFileACLLo:], uint32(n.fileACL))
	le.PutUint16(raw[inFileACLHi:], uint16(n.fileACL>>32))
	dtime := n.dtime
	if n.links == 0 && dtime == 0 && !n.orphan {
		// e2fsck expects a deletion time on an inode that no directory names.
		dtime = uint32(n.v.now().Unix())
	}
	le.PutUint32(raw[inDtime:], dtime)
	le.PutUint16(raw[inExtraSize:], extraIsize)
	at, ae := encodeTime(n.atime)
	ct, ce := encodeTime(n.ctime)
	mt, me := encodeTime(n.mtime)
	cr, cre := encodeTime(n.crtime)
	le.PutUint32(raw[inAtime:], at)
	le.PutUint32(raw[inAtimeEx:], ae)
	le.PutUint32(raw[inCtime:], ct)
	le.PutUint32(raw[inCtimeEx:], ce)
	le.PutUint32(raw[inMtime:], mt)
	le.PutUint32(raw[inMtimeEx:], me)
	le.PutUint32(raw[inCrtime:], cr)
	le.PutUint32(raw[inCrtimeEx:], cre)
	switch n.mode & modeTypeMask {
	case modeChar, modeBlock:
		major, minor := n.rdev>>8&0xFFF, n.rdev&0xFF|n.rdev>>12&0xFFF00
		if major < 256 && minor < 256 {
			le.PutUint32(raw[inBlock:], major<<8|minor)
		} else {
			le.PutUint32(raw[inBlock+4:], n.rdev)
		}
	default:
		if n.fastSymlink() {
			copy(raw[inBlock:inBlock+iBlockSize], n.inline)
		} else if n.flags&flagInlineData != 0 {
			n.serializeInline(raw)
		} else if n.flags&flagExtents != 0 {
			n.serializeExtents(raw[inBlock : inBlock+iBlockSize])
		}
	}
	n.encodeBodyXattrsLocked(raw)
	return im
}

// snapshot adds the images of the node to the plan and clears the dirty flags.
// It takes n.mu.
func (n *node) snapshot(p *flushPlan) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.dirtyInode && !n.dirtyLeaf && !n.dirtyXattr && !n.hasDirtyDirBlocks() {
		return
	}
	n.emitReleasedBlockLocked(p)
	if n.deleted {
		p.inodes = append(p.inodes, inodeImage{ino: n.ino})
		n.dirtyInode, n.dirtyLeaf, n.dirtyXattr = false, false, false
		return
	}
	if n.dirtyLeaf {
		p.leaves = append(p.leaves, n.leafImagesLocked()...)
		n.dirtyLeaf = false
	}
	if n.dirtyXattr {
		if w, ok := n.xattrBlockImageLocked(); ok {
			p.leaves = append(p.leaves, w)
		}
		n.dirtyXattr = false
	}
	p.inodes = append(p.inodes, n.serializeLocked())
	n.dirtyInode = false
	if n.dir != nil {
		p.dirs = append(p.dirs, n.dirBlockImagesLocked()...)
	}
}

func (n *node) hasDirtyDirBlocks() bool {
	if n.dir == nil {
		return false
	}
	for _, b := range n.dir.blocks {
		if b.dirty {
			return true
		}
	}
	return false
}

var errNotDir = linuxerr.ENOTDIR
