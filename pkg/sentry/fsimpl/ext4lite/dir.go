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
	"slices"
	"strings"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// A directory is a list of blocks. Each block holds ext4_dir_entry_2 records:
// a 4-byte inode number, a 2-byte record length, a 1-byte name length, a
// 1-byte file type, and the name. The directory has no hash tree. A lookup
// reads the whole directory once and then answers from a map.
//
// A record runs from the offset of its entry to the offset of the next live
// entry of the block, or to the end of the block. The bytes in front of the
// first entry form one empty record. Removing an entry hands its bytes to the
// record in front of it, so no other entry moves. The byte offset of an entry
// in the directory is its cookie, and that cookie stays valid while the entry
// lives.

// maxNameLen is the longest name of a directory entry.
const maxNameLen = 255

// maxDirBlocks caps a directory at 2^20 blocks, which is 4 GiB. A larger size
// in an inode is damage, and the engine refuses to grow a directory past it.
const maxDirBlocks = 1 << 20

// dirEntry is one live entry of a directory. off is its byte offset in blk.
type dirEntry struct {
	name string
	ino  uint32
	ft   uint8
	off  int
	blk  *dirBlock
}

// entryLen returns the record length of an entry with a name of nameLen bytes.
func entryLen(nameLen int) int { return roundUp4(8 + nameLen) }

// minEntryLen is the record length of the shortest valid directory entry.
const minEntryLen = 12

// dirBlock is one 4 KiB block of a directory. Its entries are in offset order.
type dirBlock struct {
	entries []*dirEntry
	// used is the sum of the record lengths that the live entries need.
	used  int
	idx   int
	dirty bool
}

// dirData is the in-memory form of a directory. It exists once the directory
// has been read.
type dirData struct {
	blocks []*dirBlock
	index  map[string]*dirEntry
	// firstFree is the lowest block index that has at least minEntryLen bytes
	// of free space.
	firstFree int
	loaded    bool
}

// dirEnt is one entry that a directory listing returns. next is the cookie of
// the entry after it.
type dirEnt struct {
	name string
	ino  uint32
	ft   uint8
	next uint64
}

// validName reports whether name can be a directory entry name.
func validName(name string) error {
	switch {
	case name == "" || strings.ContainsAny(name, "/\x00"):
		return linuxerr.EINVAL
	case len(name) > maxNameLen:
		return linuxerr.ENAMETOOLONG
	}
	return nil
}

// mappedBlocks returns the number of file blocks that the extents map.
func (n *node) mappedBlocks() uint64 {
	var total uint64
	for _, e := range n.exts {
		total += uint64(e.n)
	}
	return total
}

// mappedPrefix reports whether the sorted extent list maps every file block
// below nb.
func mappedPrefix(list []extent, nb uint64) bool {
	var next uint64
	for _, e := range list {
		if next >= nb {
			break
		}
		if uint64(e.lblk) > next {
			return false
		}
		next = max(next, uint64(e.end()))
	}
	return next >= nb
}

// loadDirLocked reads the blocks of the directory. The caller holds n.mu for
// writing. parseInode checked the size against the extents, so the capacity
// comes from the blocks that the extents map.
func (n *node) loadDirLocked() error {
	d := n.dir
	if d == nil {
		return linuxerr.ENOTDIR
	}
	if d.loaded {
		return nil
	}
	nb := n.size / blockSize
	blocks := make([]*dirBlock, 0, min(nb, n.mappedBlocks()))
	index := make(map[string]*dirEntry)
	var buf [blockSize]byte
	for lb := uint32(0); uint64(lb) < nb; lb++ {
		phys, ok := n.physBlock(lb)
		if !ok {
			return corrupt("directory inode %d has a hole at block %d", n.ino, lb)
		}
		if _, err := n.v.hf.ReadAt(buf[:], int64(phys)*blockSize); err != nil {
			return hostError(err)
		}
		blk, err := n.parseDirBlock(buf[:], lb == 0, index)
		if err != nil {
			return err
		}
		blk.idx = int(lb)
		blocks = append(blocks, blk)
	}
	d.blocks, d.index, d.loaded = blocks, index, true
	return nil
}

// parseDirBlock decodes one block and adds its live entries to index. Every
// record must obey the bounds, or the walk could loop or read outside the block.
// An empty record and a record behind a live entry carry no entry. The layout
// of the block then comes from the live entries alone.
func (n *node) parseDirBlock(buf []byte, first bool, index map[string]*dirEntry) (*dirBlock, error) {
	b := &dirBlock{}
	inodes := n.v.numGroups() * inodesPerGroup
	for off := 0; off < blockSize; {
		if off+8 > blockSize {
			return nil, corrupt("directory inode %d record at offset %d overruns the block", n.ino, off)
		}
		ino := le.Uint32(buf[off:])
		rec := int(le.Uint16(buf[off+4:]))
		nameLen := int(buf[off+6])
		ft := buf[off+7]
		if rec < 8 || rec%4 != 0 || off+rec > blockSize || 8+nameLen > rec {
			return nil, corrupt("directory inode %d record at offset %d has the length %d", n.ino, off, rec)
		}
		if ino != 0 {
			// The repair keeps the other entries of a block, and it skips an
			// entry that cannot be right. A mount that is not a repair refuses
			// the whole directory.
			if ino > inodes || (ino < firstIno && ino != rootIno) {
				if n.v.fsckMode {
					b.dirty = true
					off += rec
					continue
				}
				return nil, corrupt("directory inode %d entry names inode %d", n.ino, ino)
			}
			name := string(buf[off+8 : off+8+nameLen])
			if nameLen == 0 || strings.ContainsAny(name, "/\x00") {
				if n.v.fsckMode {
					b.dirty = true
					off += rec
					continue
				}
				return nil, corrupt("directory inode %d has an entry with the name %q", n.ino, name)
			}
			if _, dup := index[name]; dup {
				if n.v.fsckMode {
					b.dirty = true
					off += rec
					continue
				}
				return nil, corrupt("directory inode %d lists %q twice", n.ino, name)
			}
			e := &dirEntry{name: name, ino: ino, ft: ft, off: off, blk: b}
			b.entries = append(b.entries, e)
			b.used += entryLen(nameLen)
			index[name] = e
		}
		off += rec
	}
	if first {
		if len(b.entries) < 2 || b.entries[0].name != "." || b.entries[0].ino != n.ino || b.entries[1].name != ".." {
			return nil, corrupt("directory inode %d lacks the entries . and ..", n.ino)
		}
	}
	return b, nil
}

// dirBlockImagesLocked returns the images of the dirty directory blocks.
func (n *node) dirBlockImagesLocked() []blockWrite {
	var out []blockWrite
	for lb, b := range n.dir.blocks {
		if !b.dirty {
			continue
		}
		phys, ok := n.physBlock(uint32(lb))
		if !ok {
			continue
		}
		out = append(out, blockWrite{phys, b.image()})
		b.dirty = false
	}
	return out
}

// image encodes the block. Each record runs to the offset of the next live
// entry, so the last record reaches the end of the block. The bytes in front of
// the first entry form one empty record.
func (b *dirBlock) image() []byte {
	buf := make([]byte, blockSize)
	if len(b.entries) == 0 {
		le.PutUint16(buf[4:], blockSize)
		return buf
	}
	if first := b.entries[0].off; first > 0 {
		le.PutUint16(buf[4:], uint16(first))
	}
	for i, e := range b.entries {
		end := blockSize
		if i+1 < len(b.entries) {
			end = b.entries[i+1].off
		}
		le.PutUint32(buf[e.off:], e.ino)
		le.PutUint16(buf[e.off+4:], uint16(end-e.off))
		buf[e.off+6] = byte(len(e.name))
		buf[e.off+7] = e.ft
		copy(buf[e.off+8:], e.name)
	}
	return buf
}

// initDir gives a new directory its first block with the entries . and ..
// The caller sets the link count.
func (n *node) initDir(parent uint32) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	blk, _, err := n.v.allocBlocks(0, 1)
	if err != nil {
		return err
	}
	if err := n.setExtentsLocked([]extent{{lblk: 0, n: 1, pblk: blk}}); err != nil {
		_ = n.v.freeBlocks(blk, 1)
		return err
	}
	n.nblocks++
	n.size = blockSize
	b := &dirBlock{dirty: true}
	self := &dirEntry{name: ".", ino: n.ino, ft: ftDir, off: 0, blk: b}
	up := &dirEntry{name: "..", ino: parent, ft: ftDir, off: entryLen(1), blk: b}
	b.entries = []*dirEntry{self, up}
	b.used = entryLen(1) + entryLen(2)
	n.dir = &dirData{blocks: []*dirBlock{b}, index: map[string]*dirEntry{".": self, "..": up}, loaded: true}
	n.markDirtyLocked()
	return nil
}

// lookup returns the inode and the file type that name has in the directory.
func (n *node) lookup(name string) (uint32, uint8, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isDir() {
		return 0, 0, linuxerr.ENOTDIR
	}
	if err := n.loadDirLocked(); err != nil {
		return 0, 0, err
	}
	e, ok := n.dir.index[name]
	if !ok {
		return 0, 0, linuxerr.ENOENT
	}
	return e.ino, e.ft, nil
}

// place stores e at the first offset where its record fits, and reports whether
// the block had room. The bytes in front of the first entry come first. Each
// entry then offers the bytes behind its own record, up to the next entry.
func (b *dirBlock) place(e *dirEntry) bool {
	need := entryLen(len(e.name))
	if blockSize-b.used < need {
		return false
	}
	lead := blockSize
	if len(b.entries) > 0 {
		lead = b.entries[0].off
	}
	if lead >= need {
		e.off = 0
		b.insertAt(0, e)
		return true
	}
	for i, x := range b.entries {
		end := blockSize
		if i+1 < len(b.entries) {
			end = b.entries[i+1].off
		}
		at := x.off + entryLen(len(x.name))
		if end-at >= need {
			e.off = at
			b.insertAt(i+1, e)
			return true
		}
	}
	return false
}

// insertAt puts e at position i of the live entries, and sets the block of e.
func (b *dirBlock) insertAt(i int, e *dirEntry) {
	e.blk = b
	b.entries = slices.Insert(b.entries, i, e)
	b.used += entryLen(len(e.name))
	b.dirty = true
}

// remove takes e out of the block. The record of e joins the record in front
// of it, so the entries behind e keep their offsets.
func (b *dirBlock) remove(e *dirEntry) {
	i := slices.Index(b.entries, e)
	if i < 0 {
		return
	}
	b.entries = slices.Delete(b.entries, i, i+1)
	b.used -= entryLen(len(e.name))
	b.dirty = true
}

// emptyWithout reports whether the block holds no entry besides e.
func (b *dirBlock) emptyWithout(e *dirEntry) bool {
	return len(b.entries) == 0 || len(b.entries) == 1 && b.entries[0] == e
}

// addEntry adds name for inode ino. It returns EEXIST when name exists.
func (n *node) addEntry(name string, ino uint32, ft uint8) error {
	if err := validName(name); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isDir() {
		return linuxerr.ENOTDIR
	}
	if err := n.loadDirLocked(); err != nil {
		return err
	}
	if _, ok := n.dir.index[name]; ok {
		return linuxerr.EEXIST
	}
	e := &dirEntry{name: name, ino: ino, ft: ft}
	placed := false
	for i := n.dir.firstFree; i < len(n.dir.blocks); i++ {
		b := n.dir.blocks[i]
		if i == n.dir.firstFree && blockSize-b.used < minEntryLen {
			n.dir.firstFree = i + 1
			continue
		}
		if b.place(e) {
			placed = true
			if i == n.dir.firstFree && blockSize-b.used < minEntryLen {
				n.dir.firstFree = i + 1
			}
			break
		}
	}
	if !placed {
		b, err := n.appendDirBlockLocked()
		if err != nil {
			return err
		}
		if !b.place(e) {
			return corrupt("directory inode %d: an empty block has no room for %q", n.ino, name)
		}
	}
	n.dir.index[name] = e
	n.markDirtyLocked()
	return nil
}

// appendDirBlockLocked adds one empty block at the end of the directory.
func (n *node) appendDirBlockLocked() (*dirBlock, error) {
	if uint64(len(n.dir.blocks)) >= maxDirBlocks {
		return nil, linuxerr.ENOSPC
	}
	goal := uint64(0)
	if k := len(n.exts); k > 0 {
		goal = n.exts[k-1].pend()
	}
	phys, _, err := n.v.allocBlocks(goal, 1)
	if err != nil {
		return nil, err
	}
	lb := uint32(n.size / blockSize)
	if err := n.setExtentsLocked(insertMapping(n.exts, extent{lblk: lb, n: 1, pblk: phys})); err != nil {
		_ = n.v.freeBlocks(phys, 1)
		return nil, err
	}
	n.nblocks++
	n.size += blockSize
	b := &dirBlock{idx: len(n.dir.blocks), dirty: true}
	n.dir.blocks = append(n.dir.blocks, b)
	return b, nil
}

// removeEntry removes name from the directory. The blocks that the removal
// empties leave the end of the directory first, because that step can fail.
// It runs before the entry index changes, so a failure leaves the directory as
// it was.
func (n *node) removeEntry(name string) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isDir() {
		return linuxerr.ENOTDIR
	}
	if err := n.loadDirLocked(); err != nil {
		return err
	}
	e, ok := n.dir.index[name]
	if !ok || name == "." || name == ".." {
		return linuxerr.ENOENT
	}
	keep := len(n.dir.blocks)
	for keep > 1 && n.dir.blocks[keep-1].emptyWithout(e) {
		keep--
	}
	var freed []extent
	if keep < len(n.dir.blocks) {
		var err error
		if freed, err = n.dropTailLocked(keep); err != nil {
			return err
		}
	}
	e.blk.remove(e)
	if e.blk.idx < len(n.dir.blocks) && e.blk.idx < n.dir.firstFree && blockSize-e.blk.used >= minEntryLen {
		n.dir.firstFree = e.blk.idx
	}
	delete(n.dir.index, name)
	n.markDirtyLocked()
	// The mapping no longer names the freed blocks. A failure to free them
	// leaks blocks, and the directory stays consistent.
	return freeExtents(n.v, freed)
}

// dropTailLocked drops the directory blocks from index keep on. It checks that
// the bitmap holds every block that it frees, before it changes the mapping. It
// changes nothing when it returns an error. The caller frees the returned extents
// after its own changes.
func (n *node) dropTailLocked(keep int) ([]extent, error) {
	list, freed := removeRange(n.exts, uint32(keep), maxLogicalBlock)
	for _, f := range freed {
		if !n.v.blocksAllocated(f.pblk, f.n) {
			return nil, corrupt("directory inode %d maps blocks %d+%d that the bitmap does not hold", n.ino, f.pblk, f.n)
		}
	}
	if err := n.setExtentsLocked(list); err != nil {
		return nil, err
	}
	n.dir.blocks = n.dir.blocks[:keep]
	if n.dir.firstFree > keep {
		n.dir.firstFree = keep
	}
	n.size = uint64(keep) * blockSize
	for _, f := range freed {
		n.nblocks -= uint64(f.n)
	}
	return freed, nil
}

// freeExtents returns the blocks of the extents to the pool.
func freeExtents(v *volume, list []extent) error {
	var errs error
	for _, f := range list {
		errs = errors.Join(errs, v.freeBlocks(f.pblk, f.n))
	}
	return errs
}

// blocksAllocated reports whether the bitmap marks the n data blocks from start
// as used. freeBlocks refuses any other run, so a caller checks the run before
// it changes state that depends on the free.
func (v *volume) blocksAllocated(start uint64, n uint32) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	blocks := v.blocksCountLocked()
	for i := range n {
		b := start + uint64(i)
		if !isValidDataBlock(b, blocks) || !v.groups[b/blocksPerGroup].blocks.test(uint32(b%blocksPerGroup)) {
			return false
		}
	}
	return true
}

// replaceEntry points the existing entry name at another inode.
func (n *node) replaceEntry(name string, ino uint32, ft uint8) error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.loadDirLocked(); err != nil {
		return err
	}
	e, ok := n.dir.index[name]
	if !ok {
		return linuxerr.ENOENT
	}
	e.ino, e.ft = ino, ft
	e.blk.dirty = true
	n.markDirtyLocked()
	return nil
}

// setParent points the entry .. at the inode parent.
func (n *node) setParent(parent uint32) error {
	return n.replaceEntry("..", parent, ftDir)
}

// entriesFrom lists the live entries whose cookies are at or after pos, in
// directory order. Each entry carries the cookie of the entry after it. A
// position that names no entry resumes at the next entry, as ext4 does.
func (n *node) entriesFrom(pos uint64) ([]dirEnt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	if err := n.loadDirLocked(); err != nil {
		return nil, err
	}
	var out []dirEnt
	// appended reports that the previous entry is in out, so it needs the
	// cookie of the entry that follows it.
	appended := false
	for bi, b := range n.dir.blocks {
		base := uint64(bi) * blockSize
		for _, e := range b.entries {
			at := base + uint64(e.off)
			if appended {
				out[len(out)-1].next = at
			}
			appended = at >= pos
			if appended {
				out = append(out, dirEnt{name: e.name, ino: e.ino, ft: e.ft})
			}
		}
	}
	if appended {
		out[len(out)-1].next = n.size
	}
	return out, nil
}

// isEmptyDir reports whether the directory holds only . and ..
func (n *node) isEmptyDir() (bool, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if err := n.loadDirLocked(); err != nil {
		return false, err
	}
	return len(n.dir.index) == 2, nil
}
