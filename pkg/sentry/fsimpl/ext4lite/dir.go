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
	"strings"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// A directory is a list of blocks. Each block holds ext4_dir_entry_2 records:
// a 4-byte inode number, a 2-byte record length, a 1-byte name length, a
// 1-byte file type, and the name. The directory has no hash tree. A lookup
// reads the whole directory once and then answers from a map.

// maxNameLen is the longest name of a directory entry.
const maxNameLen = 255

// dirEntry is one live record of a directory.
type dirEntry struct {
	name string
	ino  uint32
	ft   uint8
	blk  *dirBlock
}

// entryLen returns the record length of an entry with a name of nameLen bytes.
func entryLen(nameLen int) int { return roundUp4(8 + nameLen) }

// dirBlock is one 4 KiB block of a directory.
type dirBlock struct {
	entries []*dirEntry
	// used is the sum of the record lengths of entries.
	used  int
	dirty bool
}

// dirData is the in-memory form of a directory. It exists once the directory
// has been read.
type dirData struct {
	blocks []*dirBlock
	index  map[string]*dirEntry
	loaded bool
}

// dirEnt is one entry that a directory listing returns.
type dirEnt struct {
	name string
	ino  uint32
	ft   uint8
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

// loadDirLocked reads the blocks of the directory. The caller holds n.mu for
// writing.
func (n *node) loadDirLocked() error {
	d := n.dir
	if d == nil {
		return linuxerr.ENOTDIR
	}
	if d.loaded {
		return nil
	}
	nb := n.size / blockSize
	blocks := make([]*dirBlock, 0, nb)
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
		blocks = append(blocks, blk)
	}
	d.blocks, d.index, d.loaded = blocks, index, true
	return nil
}

// parseDirBlock decodes one block and adds its entries to index. Every record
// must obey the bounds, or the walk could loop or read outside the block.
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
			if ino > inodes || (ino < firstIno && ino != rootIno) {
				return nil, corrupt("directory inode %d entry names inode %d", n.ino, ino)
			}
			name := string(buf[off+8 : off+8+nameLen])
			if nameLen == 0 || strings.ContainsAny(name, "/\x00") {
				return nil, corrupt("directory inode %d has an entry with the name %q", n.ino, name)
			}
			if _, dup := index[name]; dup {
				return nil, corrupt("directory inode %d lists %q twice", n.ino, name)
			}
			e := &dirEntry{name: name, ino: ino, ft: ft, blk: b}
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

// image encodes the block. The last record extends to the end of the block.
func (b *dirBlock) image() []byte {
	buf := make([]byte, blockSize)
	if len(b.entries) == 0 {
		le.PutUint16(buf[4:], blockSize)
		return buf
	}
	off := 0
	for i, e := range b.entries {
		rec := entryLen(len(e.name))
		if i == len(b.entries)-1 {
			rec = blockSize - off
		}
		le.PutUint32(buf[off:], e.ino)
		le.PutUint16(buf[off+4:], uint16(rec))
		buf[off+6] = byte(len(e.name))
		buf[off+7] = e.ft
		copy(buf[off+8:], e.name)
		off += rec
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
	self := &dirEntry{name: ".", ino: n.ino, ft: ftDir, blk: b}
	up := &dirEntry{name: "..", ino: parent, ft: ftDir, blk: b}
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
	need := entryLen(len(name))
	var blk *dirBlock
	if last := n.dir.blocks[len(n.dir.blocks)-1]; last.used+need <= blockSize {
		blk = last
	} else {
		for _, b := range n.dir.blocks {
			if b.used+need <= blockSize {
				blk = b
				break
			}
		}
	}
	if blk == nil {
		var err error
		if blk, err = n.appendDirBlockLocked(); err != nil {
			return err
		}
	}
	e := &dirEntry{name: name, ino: ino, ft: ft, blk: blk}
	blk.entries = append(blk.entries, e)
	blk.used += need
	blk.dirty = true
	n.dir.index[name] = e
	n.markDirtyLocked()
	return nil
}

// appendDirBlockLocked adds one empty block at the end of the directory.
func (n *node) appendDirBlockLocked() (*dirBlock, error) {
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
	b := &dirBlock{dirty: true}
	n.dir.blocks = append(n.dir.blocks, b)
	return b, nil
}

// removeEntry removes name from the directory.
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
	b := e.blk
	for i, x := range b.entries {
		if x == e {
			b.entries = append(b.entries[:i], b.entries[i+1:]...)
			break
		}
	}
	b.used -= entryLen(len(name))
	b.dirty = true
	delete(n.dir.index, name)
	// Free the empty blocks at the end of the directory.
	for k := len(n.dir.blocks) - 1; k > 0 && len(n.dir.blocks[k].entries) == 0; k-- {
		if err := n.freeRangeLocked(uint32(k), maxLogicalBlock); err != nil {
			return err
		}
		n.dir.blocks = n.dir.blocks[:k]
		n.size = uint64(k) * blockSize
	}
	n.markDirtyLocked()
	return nil
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

// entries returns the entries of the directory in storage order, including
// . and ..
func (n *node) entries() ([]dirEnt, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if !n.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	if err := n.loadDirLocked(); err != nil {
		return nil, err
	}
	var out []dirEnt
	for _, b := range n.dir.blocks {
		for _, e := range b.entries {
			out = append(out, dirEnt{e.name, e.ino, e.ft})
		}
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
