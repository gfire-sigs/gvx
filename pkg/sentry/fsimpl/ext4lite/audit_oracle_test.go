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

// auFsck is an independent checker for the ext4lite profile. It reads raw
// image bytes and uses its own copy of every offset, written from the ext4
// disk layout and not from ondisk.go. A clean image must pass in strict mode.
// A crashed image that the engine has not mounted yet only has to pass the
// structural checks of the mode that is not strict.

import (
	"encoding/binary"
	"fmt"
	"slices"
	"sort"
	"strings"
)

var auLE = binary.LittleEndian

// The values below come from the ext4 documentation, not from ondisk.go.
const (
	auBlock       = 4096
	auBPG         = 4096
	auIPG         = 4096
	auISize       = 256
	auDescSz      = 64
	auFirstIno    = 11
	auGDTBlocks   = 64
	auITableBlks  = auIPG * auISize / auBlock
	auSuperMagic  = 0xEF53
	auExtMagic    = 0xF30A
	auXattrMagic  = 0xEA020000
	auFlagExtents = 0x80000
	auFlagInline  = 0x10000000

	// Journal values from the ext4 and JBD2 documentation.
	auCompatJournal   = 0x4
	auIncompatRecover = 0x4
	auJournalMagic    = 0xC03B3998
	auJournalBlocks   = 1024
)

// auEnt is one object that the walk reaches.
type auEnt struct {
	ino   uint32
	mode  uint16
	links int
	size  uint64
	data  []byte // regular file content or symlink target
	names int    // number of directory entries that name the inode
	subs  int    // number of subdirectories of a directory
}

// auResult is what auFsck learns about an image.
type auResult struct {
	Problems []string
	Tree     map[string]*auEnt // path to object; the root is "/"
	Groups   int
	// FreeBlocks and FreeInodes count the clear bits of the bitmaps.
	FreeBlocks, FreeInodes uint64
	// Blocks maps every block that an inode owns to the owner.
	Blocks map[uint64]uint32
}

func (r *auResult) problemf(format string, args ...any) {
	if len(r.Problems) < 40 {
		r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
	}
}

// OK reports whether the check found no problem.
func (r *auResult) OK() bool { return len(r.Problems) == 0 }

func (r *auResult) String() string { return strings.Join(r.Problems, "\n") }

func auHasSuper(g int) bool {
	if g <= 1 {
		return true
	}
	for _, base := range []int{3, 5, 7} {
		for p := base; p <= g; p *= base {
			if p == g {
				return true
			}
		}
	}
	return false
}

func auOverhead(g int) int {
	if auHasSuper(g) {
		return 1 + auGDTBlocks
	}
	return 0
}

type auChecker struct {
	img    *auPages
	res    *auResult
	strict bool
	groups int
	blocks uint64
	claim  map[uint64]uint32
	ino    map[uint32]*auEnt
	// xattrRefs counts the inodes that name each xattr block.
	xattrRefs map[uint64]uint32
}

// auFsck checks img. In strict mode the bitmaps and the counters must match
// the tree exactly, as they do after a clean unmount. Otherwise the check
// ignores the bitmaps, the counters, and the unreachable inodes.
func auFsck(img *auPages, strict bool) (res *auResult) {
	res = &auResult{Tree: make(map[string]*auEnt), Blocks: make(map[uint64]uint32)}
	defer func() {
		if r := recover(); r != nil {
			res.problemf("the oracle panicked: %v", r)
		}
	}()
	c := &auChecker{img: img, res: res, strict: strict, claim: res.Blocks, ino: make(map[uint32]*auEnt), xattrRefs: make(map[uint64]uint32)}
	if !c.super() {
		return res
	}
	c.checkReserved()
	c.walk()
	if strict {
		c.bitmaps()
	}
	return res
}

func (c *auChecker) read(blk uint64, off, n int) []byte {
	b := make([]byte, n)
	c.img.readAt(b, int64(blk)*auBlock+int64(off))
	return b
}

func (c *auChecker) super() bool {
	r := c.res
	sb := c.read(0, 1024, 1024)
	if auLE.Uint16(sb[0x38:]) != auSuperMagic {
		r.problemf("superblock magic %#x", auLE.Uint16(sb[0x38:]))
		return false
	}
	want := map[string][2]uint32{
		"rev_level":        {auLE.Uint32(sb[0x4C:]), 1},
		"log_block_size":   {auLE.Uint32(sb[0x18:]), 2},
		"blocks_per_grp":   {auLE.Uint32(sb[0x20:]), auBPG},
		"inodes_per_grp":   {auLE.Uint32(sb[0x28:]), auIPG},
		"inode_size":       {uint32(auLE.Uint16(sb[0x58:])), auISize},
		"desc_size":        {uint32(auLE.Uint16(sb[0xFE:])), auDescSz},
		"first_ino":        {auLE.Uint32(sb[0x54:]), auFirstIno},
		"first_data_blk":   {auLE.Uint32(sb[0x14:]), 0},
		"feature_compat":   {auLE.Uint32(sb[0x5C:]) &^ auCompatJournal, 0x18},
		"feature_incompat": {auLE.Uint32(sb[0x60:]) &^ auIncompatRecover, 0x80C2},
		"feature_ro":       {auLE.Uint32(sb[0x64:]), 0x43},
	}
	for name, v := range want {
		if v[0] != v[1] {
			r.problemf("superblock %s = %#x, want %#x", name, v[0], v[1])
		}
	}
	blocks := uint64(auLE.Uint32(sb[0x04:])) | uint64(auLE.Uint32(sb[0x150:]))<<32
	if blocks == 0 || blocks%auBPG != 0 || blocks/auBPG > 4096 {
		r.problemf("blocks_count %d", blocks)
		return false
	}
	c.blocks = blocks
	c.groups = int(blocks / auBPG)
	r.Groups = c.groups
	if got := auLE.Uint32(sb[0x00:]); got != uint32(c.groups*auIPG) {
		r.problemf("inodes_count %d, want %d", got, c.groups*auIPG)
	}
	// The group descriptor area keeps 64 blocks. descBlocks of them hold
	// descriptors and the rest are reserved for growth.
	descBlocks := (c.groups + 63) / 64
	if got := int(auLE.Uint16(sb[0xCE:])); got != auGDTBlocks-descBlocks {
		r.problemf("reserved_gdt_blocks %d, want %d", got, auGDTBlocks-descBlocks)
	}
	if c.img.size < int64(blocks)*auBlock {
		r.problemf("host file has %d bytes, the volume has %d", c.img.size, int64(blocks)*auBlock)
	}
	if c.strict && auLE.Uint16(sb[0x3A:])&1 == 0 {
		r.problemf("a clean image must have the valid bit")
	}
	if c.strict && auLE.Uint32(sb[0x60:])&auIncompatRecover != 0 {
		r.problemf("a clean image must not ask for journal recovery")
	}
	return true
}

func (c *auChecker) desc(g int) []byte {
	return c.read(uint64(1+g/64), (g%64)*auDescSz, auDescSz)
}

func (c *auChecker) bitmapBlocks(g int) (bb, ib, it uint64) {
	base := uint64(g*auBPG + auOverhead(g))
	return base, base + 1, base + 2
}

// isMeta reports whether block b belongs to a superblock copy, the descriptor
// area, a bitmap, or an inode table.
func (c *auChecker) isMeta(b uint64) bool {
	g := int(b / auBPG)
	return int(b%auBPG) < auOverhead(g)+2+auITableBlks
}

func (c *auChecker) validData(b uint64) bool { return b < c.blocks && !c.isMeta(b) }

func (c *auChecker) inodeRaw(ino uint32) []byte {
	idx := uint64(ino - 1)
	g := idx / auIPG
	_, _, it := c.bitmapBlocks(int(g))
	in := idx % auIPG
	return c.read(it+in/16, int(in%16)*auISize, auISize)
}

func (c *auChecker) checkReserved() {
	for g := 0; g < c.groups; g++ {
		d := c.desc(g)
		bb, ib, it := c.bitmapBlocks(g)
		got := [3]uint64{
			uint64(auLE.Uint32(d[0x00:])) | uint64(auLE.Uint32(d[0x20:]))<<32,
			uint64(auLE.Uint32(d[0x04:])) | uint64(auLE.Uint32(d[0x24:]))<<32,
			uint64(auLE.Uint32(d[0x08:])) | uint64(auLE.Uint32(d[0x28:]))<<32,
		}
		if got != [3]uint64{bb, ib, it} {
			c.res.problemf("group %d descriptor places bitmaps and table at %v, want %v", g, got, [3]uint64{bb, ib, it})
		}
	}
	// The resize inode owns its double indirect block.
	raw := c.inodeRaw(7)
	if dind := uint64(auLE.Uint32(raw[0x28+13*4:])); dind != 0 {
		if !c.validData(dind) {
			c.res.problemf("resize inode names block %d", dind)
		} else {
			c.claim[dind] = 7
		}
	}
	c.checkJournal()
}

// extents returns the data extents of an inode in file order and the leaf
// blocks. It reports a problem for every violated rule.
type auExtent struct {
	lblk   uint32
	n      uint32
	pblk   uint64
	index  int
	uninit bool
}

func (c *auChecker) parseExtents(ino uint32, root []byte) (exts []auExtent, leaves []uint64) {
	r := c.res
	hdr := func(b []byte) (entries, max, depth int, ok bool) {
		if auLE.Uint16(b[0:]) != auExtMagic {
			r.problemf("inode %d: extent header magic %#x", ino, auLE.Uint16(b[0:]))
			return 0, 0, 0, false
		}
		return int(auLE.Uint16(b[2:])), int(auLE.Uint16(b[4:])), int(auLE.Uint16(b[6:])), true
	}
	entries, max, depth, ok := hdr(root)
	if !ok {
		return nil, nil
	}
	if max != 4 || entries > max {
		r.problemf("inode %d: root extent header has %d of %d entries", ino, entries, max)
		return nil, nil
	}
	leafExts := func(b []byte, n, maxN int) {
		for i := range n {
			e := b[12+12*i:]
			ln := uint32(auLE.Uint16(e[4:]))
			ee := auExtent{
				lblk:   auLE.Uint32(e[0:]),
				n:      ln,
				pblk:   uint64(auLE.Uint16(e[6:]))<<32 | uint64(auLE.Uint32(e[8:])),
				uninit: ln > 32768,
			}
			if ee.uninit {
				ee.n = ln - 32768
			}
			if ee.n == 0 || ee.n > 32768 {
				r.problemf("inode %d: extent length %d", ino, ee.n)
				continue
			}
			if !c.validData(ee.pblk) || !c.validData(ee.pblk+uint64(ee.n)-1) {
				r.problemf("inode %d: extent at block %d length %d leaves the data area", ino, ee.pblk, ee.n)
				continue
			}
			exts = append(exts, ee)
		}
		_ = maxN
	}
	// indexEntry returns the child block of entry i of an index block image.
	indexEntry := func(b []byte, i int) uint64 {
		return uint64(auLE.Uint32(b[12+12*i+4:])) | uint64(auLE.Uint16(b[12+12*i+8:]))<<32
	}
	// addLeaf reads the leaf that an index entry names and keeps its extents.
	addLeaf := func(leaf uint64) {
		if !c.validData(leaf) {
			r.problemf("inode %d: index entry names block %d", ino, leaf)
			return
		}
		leaves = append(leaves, leaf)
		lb := c.read(leaf, 0, auBlock)
		ln, lmax, ldepth, ok := hdr(lb)
		if !ok {
			return
		}
		if ldepth != 0 || lmax != 340 || ln > lmax {
			r.problemf("inode %d: leaf %d has depth %d, %d of %d entries", ino, leaf, ldepth, ln, lmax)
			return
		}
		if ln == 0 {
			r.problemf("inode %d: leaf %d is empty", ino, leaf)
		}
		leafExts(lb, ln, lmax)
	}
	switch depth {
	case 0:
		leafExts(root, entries, max)
	case 1:
		for i := range entries {
			addLeaf(indexEntry(root, i))
		}
	case 2:
		for i := range entries {
			ib := indexEntry(root, i)
			if !c.validData(ib) {
				r.problemf("inode %d: index entry names block %d", ino, ib)
				continue
			}
			leaves = append(leaves, ib)
			idx := c.read(ib, 0, auBlock)
			cnt, imax, idepth, ok := hdr(idx)
			if !ok {
				continue
			}
			if idepth != 1 || imax != 340 || cnt < 1 || cnt > imax {
				r.problemf("inode %d: index block %d has depth %d, %d of %d entries", ino, ib, idepth, cnt, imax)
				continue
			}
			for j := range cnt {
				addLeaf(indexEntry(idx, j))
			}
		}
	default:
		r.problemf("inode %d: extent depth %d", ino, depth)
		return nil, nil
	}
	for i := 1; i < len(exts); i++ {
		if uint64(exts[i].lblk) < uint64(exts[i-1].lblk)+uint64(exts[i-1].n) {
			r.problemf("inode %d: extents %d and %d overlap or are out of order", ino, i-1, i)
		}
	}
	return exts, leaves
}

// inlineData returns the content of an inline-data inode.
func (c *auChecker) inlineData(ino uint32, raw []byte, size uint64) []byte {
	if size > 128 {
		c.res.problemf("inode %d: inline size %d", ino, size)
		return nil
	}
	n := min(int(size), 60)
	out := append([]byte(nil), raw[0x28:0x28+n]...)
	if size <= 60 {
		return out
	}
	rest := int(size) - 60
	const ibody = 128 + 32
	if auLE.Uint32(raw[ibody:]) != auXattrMagic {
		c.res.problemf("inode %d: inline data has no xattr magic", ino)
		return nil
	}
	e := raw[ibody+4:]
	nameLen, idx := int(e[0]), e[1]
	offs, vsize := int(auLE.Uint16(e[2:])), int(auLE.Uint32(e[8:]))
	if idx != 7 || nameLen != 4 || string(e[16:16+nameLen]) != "data" {
		c.res.problemf("inode %d: first in-inode attribute is %d/%q", ino, idx, e[16:16+nameLen])
		return nil
	}
	if vsize != rest || ibody+4+offs+vsize > auISize {
		c.res.problemf("inode %d: system.data has %d bytes at %d, want %d", ino, vsize, offs, rest)
		return nil
	}
	return append(out, raw[ibody+4+offs:ibody+4+offs+vsize]...)
}

func (c *auChecker) own(ino uint32, blk uint64) {
	if prev, dup := c.claim[blk]; dup {
		c.res.problemf("block %d is owned by inodes %d and %d", blk, prev, ino)
		return
	}
	c.claim[blk] = ino
}

// load reads and checks one reachable inode. It returns nil on a fatal error.
func (c *auChecker) load(ino uint32, wantDirent uint8) (*auEnt, []byte, []auExtent) {
	r := c.res
	if ino < auFirstIno && ino != 2 || ino > uint32(c.groups*auIPG) {
		r.problemf("directory entry names inode %d", ino)
		return nil, nil, nil
	}
	raw := c.inodeRaw(ino)
	mode := auLE.Uint16(raw[0:])
	links := int(auLE.Uint16(raw[0x1A:]))
	size := uint64(auLE.Uint32(raw[0x04:])) | uint64(auLE.Uint32(raw[0x6C:]))<<32
	flags := auLE.Uint32(raw[0x20:])
	sectors := uint64(auLE.Uint32(raw[0x1C:])) | uint64(auLE.Uint16(raw[0x74:]))<<32
	acl := uint64(auLE.Uint32(raw[0x68:])) | uint64(auLE.Uint16(raw[0x76:]))<<32
	e := &auEnt{ino: ino, mode: mode, links: links, size: size}
	if links == 0 {
		r.problemf("inode %d is reachable and has no link", ino)
		return nil, nil, nil
	}
	if dt := auLE.Uint32(raw[0x14:]); dt != 0 {
		r.problemf("inode %d is reachable and has dtime %d", ino, dt)
	}
	if extra := auLE.Uint16(raw[0x80:]); extra != 32 {
		r.problemf("inode %d: extra_isize %d", ino, extra)
	}
	ft := map[uint16]uint8{0x8000: 1, 0x4000: 2, 0x2000: 3, 0x6000: 4, 0x1000: 5, 0xC000: 6, 0xA000: 7}[mode&0xF000]
	if ft == 0 {
		r.problemf("inode %d: mode %#o", ino, mode)
		return nil, nil, nil
	}
	if wantDirent != 0 && wantDirent != ft {
		r.problemf("inode %d: directory entry type %d, inode type %d", ino, wantDirent, ft)
	}
	var exts []auExtent
	var leaves []uint64
	switch ft {
	case 1, 2, 7:
		switch {
		case ft == 7 && flags&(auFlagExtents|auFlagInline) == 0:
			if size == 0 || size >= 60 {
				r.problemf("inode %d: fast symlink size %d", ino, size)
			} else {
				e.data = append([]byte(nil), raw[0x28:0x28+size]...)
			}
		case flags&auFlagInline != 0 && flags&auFlagExtents == 0 && ft != 2:
			e.data = c.inlineData(ino, raw, size)
		case flags&auFlagExtents != 0 && flags&auFlagInline == 0:
			exts, leaves = c.parseExtents(ino, raw[0x28:0x28+60])
		default:
			r.problemf("inode %d: flags %#x", ino, flags)
		}
	}
	nblocks := uint64(len(leaves))
	for _, l := range leaves {
		c.own(ino, l)
	}
	for _, x := range exts {
		nblocks += uint64(x.n)
		for i := uint32(0); i < x.n; i++ {
			c.own(ino, x.pblk+uint64(i))
		}
	}
	if acl != 0 {
		if !c.validData(acl) {
			r.problemf("inode %d: xattr block %d", ino, acl)
		} else {
			// Linux lets several inodes name one xattr block. The block counts
			// once in the bitmap, and its refcount counts the inodes.
			if c.xattrRefs[acl] == 0 {
				c.own(ino, acl)
			}
			c.xattrRefs[acl]++
			nblocks++
			hb := c.read(acl, 0, 32)
			if auLE.Uint32(hb[0:]) != auXattrMagic || auLE.Uint32(hb[8:]) != 1 {
				r.problemf("inode %d: xattr block header magic %#x blocks %d", ino, auLE.Uint32(hb[0:]), auLE.Uint32(hb[8:]))
			}
		}
	}
	if sectors != nblocks*8 {
		r.problemf("inode %d: i_blocks is %d sectors, the extents own %d blocks", ino, sectors, nblocks)
	}
	if ft == 1 || ft == 7 {
		if exts != nil || flags&auFlagExtents != 0 {
			e.data = c.fileBytes(exts, size)
		}
	}
	if ft == 2 && (size == 0 || size%auBlock != 0) {
		r.problemf("directory inode %d has size %d", ino, size)
	}
	return e, raw, exts
}

// fileBytes reads size bytes through the extents. A hole reads as zeros.
func (c *auChecker) fileBytes(exts []auExtent, size uint64) []byte {
	if size > 64<<20 {
		return nil
	}
	out := make([]byte, size)
	for _, x := range exts {
		for i := uint32(0); i < x.n; i++ {
			off := (uint64(x.lblk) + uint64(i)) * auBlock
			if off >= size {
				break
			}
			if !x.uninit {
				copy(out[off:], c.read(x.pblk+uint64(i), 0, int(min(auBlock, size-off))))
			}
		}
	}
	return out
}

type auDirEnt struct {
	name string
	ino  uint32
	ft   uint8
}

// dirEntries parses the directory blocks.
func (c *auChecker) dirEntries(ino uint32, exts []auExtent, size uint64) []auDirEnt {
	r := c.res
	var out []auDirEnt
	nblk := size / auBlock
	var next uint32
	for _, x := range exts {
		if x.lblk != next {
			r.problemf("directory %d has a hole at block %d", ino, next)
		}
		next = x.lblk + x.n
	}
	if uint64(next) != nblk {
		r.problemf("directory %d has %d blocks of extents, size says %d", ino, next, nblk)
	}
	for _, x := range exts {
		for i := uint32(0); i < x.n; i++ {
			blk := c.read(x.pblk+uint64(i), 0, auBlock)
			off := 0
			for off < auBlock {
				if off+8 > auBlock {
					r.problemf("directory %d block %d: entry at %d is cut", ino, x.lblk+i, off)
					break
				}
				di := auLE.Uint32(blk[off:])
				rl := int(auLE.Uint16(blk[off+4:]))
				nl := int(blk[off+6])
				ft := blk[off+7]
				if rl < 8 || rl%4 != 0 || off+rl > auBlock || 8+nl > rl {
					r.problemf("directory %d block %d: rec_len %d name_len %d at %d", ino, x.lblk+i, rl, nl, off)
					break
				}
				if di != 0 {
					if nl == 0 {
						r.problemf("directory %d block %d: empty name", ino, x.lblk+i)
					}
					name := string(blk[off+8 : off+8+nl])
					if strings.ContainsAny(name, "/\x00") {
						r.problemf("directory %d: bad name %q", ino, name)
					}
					out = append(out, auDirEnt{name: name, ino: di, ft: ft})
				}
				off += rl
			}
		}
	}
	return out
}

func (c *auChecker) walk() {
	r := c.res
	root, _, rexts := c.load(2, 0)
	if root == nil {
		return
	}
	if root.mode&0xF000 != 0x4000 {
		r.problemf("root is not a directory")
		return
	}
	r.Tree["/"] = root
	c.ino[2] = root
	type item struct {
		path   string
		e      *auEnt
		exts   []auExtent
		parent uint32
	}
	stack := []item{{"/", root, rexts, 2}}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		ents := c.dirEntries(it.e.ino, it.exts, it.e.size)
		if len(ents) < 2 || ents[0].name != "." || ents[1].name != ".." {
			r.problemf("directory %d does not start with . and ..", it.e.ino)
			continue
		}
		if ents[0].ino != it.e.ino {
			r.problemf("directory %d: . names %d", it.e.ino, ents[0].ino)
		}
		if ents[1].ino != it.parent {
			r.problemf("directory %d: .. names %d, parent is %d", it.e.ino, ents[1].ino, it.parent)
		}
		seen := map[string]bool{}
		for _, d := range ents[2:] {
			if seen[d.name] {
				r.problemf("directory %d: duplicate name %q", it.e.ino, d.name)
			}
			seen[d.name] = true
			if d.name == "." || d.name == ".." {
				r.problemf("directory %d: extra %q entry", it.e.ino, d.name)
				continue
			}
			path := it.path
			if path != "/" {
				path += "/"
			}
			path += d.name
			if prev := c.ino[d.ino]; prev != nil {
				if prev.mode&0xF000 == 0x4000 {
					r.problemf("directory %d is reachable twice (%q)", d.ino, path)
					continue
				}
				prev.names++
				r.Tree[path] = prev
				continue
			}
			e, _, exts := c.load(d.ino, d.ft)
			if e == nil {
				continue
			}
			e.names = 1
			c.ino[d.ino] = e
			r.Tree[path] = e
			if e.mode&0xF000 == 0x4000 {
				it.e.subs++
				stack = append(stack, item{path, e, exts, it.e.ino})
			}
		}
	}
	for path, e := range r.Tree {
		want := e.names
		if e.mode&0xF000 == 0x4000 {
			want = 2 + e.subs
		}
		if e.ino == 2 {
			want = 2 + e.subs
		}
		if e.links != want {
			r.problemf("%s (inode %d): link count %d, want %d", path, e.ino, e.links, want)
		}
	}
	for blk, refs := range c.xattrRefs {
		if got := auLE.Uint32(c.read(blk, 4, 4)); got != refs {
			r.problemf("xattr block %d has refcount %d, %d inodes name it", blk, got, refs)
		}
	}
}

// bitmaps checks the bitmaps and the counters of a clean image.
func (c *auChecker) bitmaps() {
	r := c.res
	sb := c.read(0, 1024, 1024)
	var totalFreeB, totalFreeI uint64
	for g := 0; g < c.groups; g++ {
		d := c.desc(g)
		bb, ib, _ := c.bitmapBlocks(g)
		bm := c.read(bb, 0, auBlock)
		im := c.read(ib, 0, auBlock)
		for i := 512; i < auBlock; i++ {
			if bm[i] != 0xFF || im[i] != 0xFF {
				r.problemf("group %d: bitmap padding byte %d is %#x/%#x", g, i, bm[i], im[i])
				break
			}
		}
		var freeB, freeI uint32
		for i := range auBPG {
			blk := uint64(g*auBPG + i)
			set := bm[i/8]>>(i%8)&1 == 1
			want := c.isMeta(blk)
			if _, owned := c.claim[blk]; owned {
				want = true
			}
			if set != want {
				r.problemf("block %d: bitmap says used=%v, tree says used=%v", blk, set, want)
			}
			if !set {
				freeB++
			}
		}
		dirs := uint32(0)
		for i := range auIPG {
			ino := uint32(g*auIPG + i + 1)
			set := im[i/8]>>(i%8)&1 == 1
			want := ino < auFirstIno || c.ino[ino] != nil
			if set != want {
				r.problemf("inode %d: bitmap says used=%v, tree says used=%v", ino, set, want)
			}
			if !set {
				freeI++
			}
			if e := c.ino[ino]; e != nil && e.mode&0xF000 == 0x4000 {
				dirs++
			}
		}
		gotB := uint32(auLE.Uint16(d[0x0C:])) | uint32(auLE.Uint16(d[0x2C:]))<<16
		gotI := uint32(auLE.Uint16(d[0x0E:])) | uint32(auLE.Uint16(d[0x2E:]))<<16
		gotD := uint32(auLE.Uint16(d[0x10:])) | uint32(auLE.Uint16(d[0x30:]))<<16
		if gotB != freeB || gotI != freeI || gotD != dirs {
			r.problemf("group %d counters: free blocks %d/%d, free inodes %d/%d, dirs %d/%d (descriptor/bitmap)", g, gotB, freeB, gotI, freeI, gotD, dirs)
		}
		totalFreeB += uint64(freeB)
		totalFreeI += uint64(freeI)
	}
	r.FreeBlocks, r.FreeInodes = totalFreeB, totalFreeI
	sbFreeB := uint64(auLE.Uint32(sb[0x0C:])) | uint64(auLE.Uint32(sb[0x158:]))<<32
	if sbFreeB != totalFreeB || uint64(auLE.Uint32(sb[0x10:])) != totalFreeI {
		r.problemf("superblock free counts %d blocks %d inodes, bitmaps say %d and %d", sbFreeB, auLE.Uint32(sb[0x10:]), totalFreeB, totalFreeI)
	}
	// Every superblock copy and descriptor copy must match the primary.
	for g := 1; g < c.groups; g++ {
		if !auHasSuper(g) {
			continue
		}
		start := uint64(g * auBPG)
		if auLE.Uint16(c.read(start, 0x38, 2)) != auSuperMagic {
			r.problemf("group %d: the superblock copy has no magic at byte 0x38 of its first block", g)
		} else if got := auLE.Uint16(c.read(start, 0x5A, 2)); int(got) != g {
			r.problemf("group %d: the superblock copy names group %d", g, got)
		}
		// The kernel leaves the copies as they are after a mkfs or a resize.
		// The counters in them go stale, so only the locations must match.
		for i := 1; i <= (c.groups+63)/64; i++ {
			pri, bak := c.read(uint64(i), 0, auBlock), c.read(start+uint64(i), 0, auBlock)
			for d := 0; d < 64 && (i-1)*64+d < c.groups; d++ {
				if !slices.Equal(pri[d*auDescSz:d*auDescSz+0x0C], bak[d*auDescSz:d*auDescSz+0x0C]) {
					r.problemf("group %d: descriptor %d of the copy places the group metadata elsewhere", g, (i-1)*64+d)
				}
			}
		}
	}
}

// auPaths returns the sorted paths of a result.
func (r *auResult) paths() []string {
	out := make([]string, 0, len(r.Tree))
	for p := range r.Tree {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
