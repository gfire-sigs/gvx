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

package oci

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/bits"
	"sort"
	"strings"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/erofs"
)

const (
	// maxSymlinkTarget is PATH_MAX. Longer targets are invalid on Linux.
	maxSymlinkTarget = 4096
	erofsInodeAlign  = 1 << EROFSInodeSlotBits

	// OpaqueXattrName is the overlayfs xattr that marks a directory opaque.
	OpaqueXattrName  = "trusted.overlay.opaque"
	opaqueXattrValue = "y"
)

// xattrKV is one extended attribute of an inode.
type xattrKV struct {
	name  string
	value []byte
}

// encodeXattrIbody returns the inline xattr area for xs, or nil when xs is
// empty. The area starts with a 12-byte header and holds entries aligned to
// four bytes. It matches the layout that Linux's erofs_getxattr() reads.
func encodeXattrIbody(xs []xattrKV) ([]byte, error) {
	if len(xs) == 0 {
		return nil, nil
	}
	sorted := make([]xattrKV, len(xs))
	copy(sorted, xs)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].name < sorted[j].name })

	out := make([]byte, erofs.XattrIbodyHeaderSize)
	for _, x := range sorted {
		index, suffix := splitXattrName(x.name)
		if len(suffix) > erofs.MaxNameLen {
			return nil, fmt.Errorf("oci: xattr name %q is too long", x.name)
		}
		if len(x.value) > math.MaxUint16 {
			return nil, fmt.Errorf("oci: xattr %q value of %d bytes is too large", x.name, len(x.value))
		}
		start := len(out)
		out = append(out, byte(len(suffix)), index, 0, 0)
		binary.LittleEndian.PutUint16(out[start+2:], uint16(len(x.value)))
		out = append(out, suffix...)
		out = append(out, x.value...)
		for len(out)%erofs.XattrAlign != 0 {
			out = append(out, 0)
		}
	}
	return out, nil
}

// splitXattrName maps a full xattr name to its EROFS name index and the
// suffix that the entry stores. Names outside the predefined prefixes use
// index 0 and store the whole name.
func splitXattrName(name string) (index uint8, suffix string) {
	switch {
	case name == linux.XATTR_NAME_POSIX_ACL_ACCESS:
		return erofs.XattrIndexPosixACLAccess, ""
	case name == linux.XATTR_NAME_POSIX_ACL_DEFAULT:
		return erofs.XattrIndexPosixACLDefault, ""
	case strings.HasPrefix(name, linux.XATTR_USER_PREFIX):
		return erofs.XattrIndexUser, name[len(linux.XATTR_USER_PREFIX):]
	case strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX):
		return erofs.XattrIndexTrusted, name[len(linux.XATTR_TRUSTED_PREFIX):]
	case strings.HasPrefix(name, linux.XATTR_SECURITY_PREFIX):
		return erofs.XattrIndexSecurity, name[len(linux.XATTR_SECURITY_PREFIX):]
	default:
		return 0, name
	}
}

// xattrIcount returns the i_xattr_icount field for an inline xattr area. The
// 12-byte header counts as one 4-byte unit.
func xattrIcount(ibody []byte) uint16 {
	return erofs.XattrIcount(uint32(len(ibody)))
}

// direntType returns the EROFS directory entry file type for mode.
func direntType(mode uint16) uint8 {
	switch mode & linux.S_IFMT {
	case linux.S_IFREG:
		return linux.FT_REG_FILE
	case linux.S_IFDIR:
		return linux.FT_DIR
	case linux.S_IFCHR:
		return linux.FT_CHRDEV
	case linux.S_IFBLK:
		return linux.FT_BLKDEV
	case linux.S_IFIFO:
		return linux.FT_FIFO
	case linux.S_IFSOCK:
		return linux.FT_SOCK
	case linux.S_IFLNK:
		return linux.FT_SYMLINK
	default:
		return linux.FT_UNKNOWN
	}
}

// planDirBlocks splits the sorted entry names of a directory into blocks. It
// returns the index of the first entry of each block and the number of bytes
// that the last block uses.
func planDirBlocks(names []string, bs int) (starts []int, lastUsed int, err error) {
	for i := 0; i < len(names); {
		count, namesLen := 0, 0
		for i+count < len(names) {
			l := len(names[i+count])
			if l == 0 || l > erofs.MaxNameLen {
				return nil, 0, fmt.Errorf("oci: invalid directory entry name length %d", l)
			}
			if (count+1)*EROFSDirentSize+namesLen+l > bs {
				break
			}
			namesLen += l
			count++
		}
		if count == 0 {
			return nil, 0, errors.New("oci: directory entry does not fit a block")
		}
		starts = append(starts, i)
		lastUsed = count*EROFSDirentSize + namesLen
		i += count
	}
	return starts, lastUsed, nil
}

// encodeDirBlock encodes entries into one directory block of used bytes.
func encodeDirBlock(dst []byte, names []string, nids []uint64, types []uint8) {
	nameOff := len(names) * EROFSDirentSize
	for i, name := range names {
		d := dst[i*EROFSDirentSize:]
		binary.LittleEndian.PutUint32(d[0:4], uint32(nids[i]))
		binary.LittleEndian.PutUint32(d[4:8], uint32(nids[i]>>32))
		binary.LittleEndian.PutUint16(d[8:10], uint16(nameOff))
		d[10] = types[i]
		d[11] = 0
		copy(dst[nameOff:], name)
		nameOff += len(name)
	}
}

// layoutNode holds the placement of one inode.
type layoutNode struct {
	n *fsNode

	ibody []byte
	// dataLayout is one of the erofsDataLayout constants.
	dataLayout uint8
	// inline holds the bytes stored after the inode and its xattrs.
	inline []byte
	// chunkMap is the number of 4-byte chunk map entries that follow the inode.
	chunkMap int

	// Directory plan.
	names  []string
	starts []int
	last   int

	// lateStart is the index of the first late block, relative to the first
	// block after the streamed file data. lateCount is the number of late
	// blocks. Directories and non-inlined symlinks use late blocks.
	lateStart uint32
	lateCount uint32

	metaOff uint64
}

// imageLayout is the placement of every inode of a layer.
type imageLayout struct {
	nodes     []*layoutNode
	lateBase  uint32
	metaBlk   uint32
	metaBytes uint64
	total     uint32
	chunked   bool
	bs        int
}

func sortedChildNames(d *fsNode) []string {
	names := make([]string, 0, len(d.children)+2)
	names = append(names, ".", "..")
	for name := range d.children {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// buildLayout orders the inodes, counts links, and assigns metadata offsets
// and late block indexes. It writes nothing.
func buildLayout(root *fsNode, dataEnd uint32, bs int) (*imageLayout, error) {
	l := &imageLayout{lateBase: dataEnd, bs: bs}
	blk := uint64(bs)

	// Pre-order walk. Root comes first so that its nid is zero, which the
	// 16-bit superblock root_nid field requires. A hardlinked inode appears
	// once but counts every directory entry that references it.
	stack := []*fsNode{root}
	for len(stack) > 0 {
		n := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if n.ino != 0 {
			continue
		}
		if len(l.nodes) >= math.MaxUint32-1 {
			return nil, errors.New("oci: too many inodes")
		}
		n.ino = uint32(len(l.nodes) + 1)
		ln := &layoutNode{n: n}
		l.nodes = append(l.nodes, ln)
		if !n.isDir() {
			continue
		}
		ln.names = sortedChildNames(n)
		n.nlink = 2
		for i := len(ln.names) - 1; i >= 0; i-- {
			name := ln.names[i]
			if name == "." || name == ".." {
				continue
			}
			child := n.children[name]
			if child.isDir() {
				n.nlink++
			} else {
				child.nlink++
			}
			stack = append(stack, child)
		}
	}

	var meta uint64
	var late uint32
	for _, ln := range l.nodes {
		n := ln.n
		xs := n.xattrs
		if n.isDir() && n.opaque {
			xs = append(append([]xattrKV(nil), xs...), xattrKV{name: OpaqueXattrName, value: []byte(opaqueXattrValue)})
		}
		var err error
		if ln.ibody, err = encodeXattrIbody(xs); err != nil {
			return nil, err
		}
		base := EROFSInodeExtendedSize + len(ln.ibody)

		switch {
		case n.isDir():
			var err error
			ln.starts, ln.last, err = planDirBlocks(ln.names, bs)
			if err != nil {
				return nil, err
			}
			nb := uint32(len(ln.starts))
			if ln.last < bs && base+ln.last <= bs {
				ln.dataLayout = erofs.InodeDataLayoutFlatInline
				ln.lateCount = nb - 1
			} else {
				ln.dataLayout = erofs.InodeDataLayoutFlatPlain
				ln.lateCount = nb
			}
			ln.lateStart = late
			late += ln.lateCount
		case n.isSymlink():
			ln.dataLayout = erofs.InodeDataLayoutFlatPlain
			if len(n.target) == 0 || len(n.target) >= maxSymlinkTarget {
				return nil, fmt.Errorf("oci: symlink target of %d bytes is invalid", len(n.target))
			}
			if base+len(n.target) <= bs {
				ln.dataLayout = erofs.InodeDataLayoutFlatInline
				ln.inline = []byte(n.target)
			} else {
				ln.lateStart = late
				ln.lateCount = 1
				late++
			}
		case n.isRegular():
			switch {
			case n.chunked:
				ln.dataLayout = erofs.InodeDataLayoutChunkBased
				ln.chunkMap = int((n.size + blk - 1) / blk)
				l.chunked = true
			default:
				ln.dataLayout = erofs.InodeDataLayoutFlatPlain
			}
		default:
			ln.dataLayout = erofs.InodeDataLayoutFlatPlain
		}

		inlineLen := len(ln.inline)
		if n.isDir() && ln.dataLayout == erofs.InodeDataLayoutFlatInline {
			inlineLen = ln.last
		}
		total := uint64(base + inlineLen + 4*ln.chunkMap)
		start := (meta + erofsInodeAlign - 1) &^ (erofsInodeAlign - 1)
		// The inode, its xattrs, and its inline data must not cross a block
		// boundary, as Linux requires.
		if total <= blk && start%blk+total > blk {
			start = (start + blk - 1) &^ (blk - 1)
		}
		ln.metaOff = start
		meta = start + total
	}

	l.metaBytes = meta
	l.metaBlk = l.lateBase + late
	metaBlocks := (meta + blk - 1) / blk
	end := uint64(l.metaBlk) + metaBlocks
	if end >= erofs.NullAddr {
		return nil, errors.New("oci: image exceeds the EROFS block address space")
	}
	l.total = uint32(end)
	return l, nil
}

// writeImage writes the late blocks, the metadata area, and the superblock.
// File data blocks are already in dst.
func writeImage(dst io.WriterAt, root *fsNode, l *imageLayout) error {
	nid := func(n *fsNode) uint64 {
		return l.nodes[n.ino-1].metaOff / erofsInodeAlign
	}

	// Late blocks: directory blocks and symlink targets.
	for _, ln := range l.nodes {
		n := ln.n
		if ln.lateCount == 0 {
			continue
		}
		buf := make([]byte, int(ln.lateCount)*l.bs)
		switch {
		case n.isDir():
			for b := range int(ln.lateCount) {
				fillDirBlock(buf[b*l.bs:(b+1)*l.bs], ln, b, nid)
			}
		case n.isSymlink():
			copy(buf, n.target)
		}
		off := (int64(l.lateBase) + int64(ln.lateStart)) * int64(l.bs)
		if _, err := dst.WriteAt(buf, off); err != nil {
			return fmt.Errorf("oci: write EROFS data blocks: %w", err)
		}
	}

	// Metadata area.
	mw := bufio.NewWriterSize(io.NewOffsetWriter(dst, int64(l.metaBlk)*int64(l.bs)), 1<<20)
	var pos uint64
	pad := func(to uint64) error {
		var zeros [erofsInodeAlign]byte
		for pos < to {
			n := min(to-pos, uint64(len(zeros)))
			if _, err := mw.Write(zeros[:n]); err != nil {
				return err
			}
			pos += n
		}
		return nil
	}
	for _, ln := range l.nodes {
		if err := pad(ln.metaOff); err != nil {
			return fmt.Errorf("oci: write EROFS metadata: %w", err)
		}
		var ino [EROFSInodeExtendedSize]byte
		encodeInode(ino[:], ln, l)
		if _, err := mw.Write(ino[:]); err != nil {
			return fmt.Errorf("oci: write EROFS inode: %w", err)
		}
		if _, err := mw.Write(ln.ibody); err != nil {
			return fmt.Errorf("oci: write EROFS xattrs: %w", err)
		}
		pos += uint64(EROFSInodeExtendedSize + len(ln.ibody))

		switch {
		case ln.n.isDir() && ln.dataLayout == erofs.InodeDataLayoutFlatInline:
			blk := make([]byte, l.bs)
			fillDirBlock(blk, ln, len(ln.starts)-1, nid)
			if _, err := mw.Write(blk[:ln.last]); err != nil {
				return fmt.Errorf("oci: write EROFS directory: %w", err)
			}
			pos += uint64(ln.last)
		case len(ln.inline) > 0:
			if _, err := mw.Write(ln.inline); err != nil {
				return fmt.Errorf("oci: write EROFS inline data: %w", err)
			}
			pos += uint64(len(ln.inline))
		case ln.chunkMap > 0:
			var entry [4]byte
			for _, r := range ln.n.runs {
				for k := uint32(0); k < r.n; k++ {
					addr := uint32(erofs.NullAddr)
					if r.start != erofs.NullAddr {
						addr = r.start + k
					}
					binary.LittleEndian.PutUint32(entry[:], addr)
					if _, err := mw.Write(entry[:]); err != nil {
						return fmt.Errorf("oci: write EROFS chunk map: %w", err)
					}
				}
			}
			pos += uint64(4 * ln.chunkMap)
		}
	}
	if err := pad((pos + uint64(l.bs) - 1) &^ (uint64(l.bs) - 1)); err != nil {
		return fmt.Errorf("oci: write EROFS metadata: %w", err)
	}
	if err := mw.Flush(); err != nil {
		return fmt.Errorf("oci: write EROFS metadata: %w", err)
	}

	block0 := make([]byte, l.bs)
	writeSuperBlock(block0[EROFSSuperBlockOffset:EROFSSuperBlockOffset+128], nid(root), uint64(len(l.nodes)), l.total, l.metaBlk, l.bs, l.chunked)
	if _, err := dst.WriteAt(block0, 0); err != nil {
		return fmt.Errorf("oci: write EROFS superblock: %w", err)
	}
	return nil
}

// fillDirBlock encodes block b of the directory described by ln into dst.
func fillDirBlock(dst []byte, ln *layoutNode, b int, nid func(*fsNode) uint64) {
	d := ln.n
	end := len(ln.names)
	if b+1 < len(ln.starts) {
		end = ln.starts[b+1]
	}
	names := ln.names[ln.starts[b]:end]
	nids := make([]uint64, len(names))
	types := make([]uint8, len(names))
	for i, name := range names {
		var child *fsNode
		switch name {
		case ".":
			child = d
		case "..":
			child = d.parent
		default:
			child = d.children[name]
		}
		nids[i] = nid(child)
		types[i] = direntType(child.mode)
	}
	encodeDirBlock(dst, names, nids, types)
}

func encodeInode(dst []byte, ln *layoutNode, l *imageLayout) {
	n := ln.n
	clear(dst)
	binary.LittleEndian.PutUint16(dst[0:2], uint16(ln.dataLayout)<<1|erofs.InodeLayoutExtended)
	binary.LittleEndian.PutUint16(dst[2:4], xattrIcount(ln.ibody))
	binary.LittleEndian.PutUint16(dst[4:6], n.mode)

	var size uint64
	var raw uint32
	switch {
	case n.isDir():
		size = uint64(len(ln.starts)-1)*uint64(l.bs) + uint64(ln.last)
		if ln.lateCount > 0 {
			raw = l.lateBase + ln.lateStart
		}
	case n.isSymlink():
		size = uint64(len(n.target))
		if ln.lateCount > 0 {
			raw = l.lateBase + ln.lateStart
		}
	case n.isRegular():
		size = n.size
		switch ln.dataLayout {
		case erofs.InodeDataLayoutChunkBased:
			// The low 16 bits hold the chunk format. Zero selects 4-byte
			// block map entries with chunks of one block.
			raw = 0
		default:
			if len(n.runs) > 0 {
				raw = n.runs[0].start
			}
		}
	default:
		raw = n.rdev
	}
	binary.LittleEndian.PutUint64(dst[8:16], size)
	binary.LittleEndian.PutUint32(dst[16:20], raw)
	binary.LittleEndian.PutUint32(dst[20:24], n.ino)
	binary.LittleEndian.PutUint32(dst[24:28], n.uid)
	binary.LittleEndian.PutUint32(dst[28:32], n.gid)
	binary.LittleEndian.PutUint64(dst[32:40], n.mtime)
	binary.LittleEndian.PutUint32(dst[40:44], n.mtimeNsec)
	binary.LittleEndian.PutUint32(dst[44:48], n.nlink)
}

func writeSuperBlock(dst []byte, rootNid uint64, inodes uint64, blocks uint32, metaBlockAddr uint32, bs int, chunked bool) {
	clear(dst)
	binary.LittleEndian.PutUint32(dst[0:4], EROFSSuperBlockMagicV1)
	dst[12] = uint8(bits.TrailingZeros(uint(bs)))
	binary.LittleEndian.PutUint16(dst[14:16], uint16(rootNid))
	binary.LittleEndian.PutUint64(dst[16:24], inodes)
	binary.LittleEndian.PutUint32(dst[36:40], blocks)
	binary.LittleEndian.PutUint32(dst[40:44], metaBlockAddr)
	copy(dst[64:80], "gvx-erofs")
	if chunked {
		binary.LittleEndian.PutUint32(dst[80:84], erofs.FeatureIncompatChunkedFile)
	}
}
