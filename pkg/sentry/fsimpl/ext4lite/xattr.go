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
	"sort"
	"strings"

	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// Extended attributes live in two places. The system.data attribute of an
// inline file lives in the inode, behind the extra fields. Every other
// attribute of an inode lives in one xattr block, which the inode names in
// i_file_acl. The block is never shared. The total size of the attributes of
// one inode stays below one block.

// Name indexes of the xattr entries.
const (
	xattrIndexUser      = 1
	xattrIndexPosixAcc  = 2
	xattrIndexPosixDef  = 3
	xattrIndexTrusted   = 4
	xattrIndexSecurity  = 6
	xattrIndexSystem    = 7
	xattrHeaderSize     = 32
	xattrEntryHeader    = 16
	maxXattrValue       = blockSize
	xattrBlockTerminate = 4
)

// xattrEntry is one attribute.
type xattrEntry struct {
	index uint8
	name  string
	value []byte
}

// xattrData holds the attributes of a node other than system.data.
type xattrData struct {
	entries     []xattrEntry
	blockLoaded bool
}

// xattrEntryLen returns the size of an entry with a name of nameLen bytes.
func xattrEntryLen(nameLen int) int { return roundUp4(xattrEntryHeader + nameLen) }

// xattrHash computes the hash that ext4 stores in an entry. The name is
// processed as unsigned bytes.
func xattrHash(name string, value []byte) uint32 {
	var h uint32
	for i := 0; i < len(name); i++ {
		h = h<<5 ^ h>>27 ^ uint32(name[i])
	}
	padded := make([]byte, roundUp4(len(value)))
	copy(padded, value)
	for i := 0; i < len(padded); i += 4 {
		h = h<<16 ^ h>>16 ^ le.Uint32(padded[i:])
	}
	return h
}

// sortXattrs orders entries as the kernel does: by index, name length, name.
func sortXattrs(es []xattrEntry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if a.index != b.index {
			return a.index < b.index
		}
		if len(a.name) != len(b.name) {
			return len(a.name) < len(b.name)
		}
		return a.name < b.name
	})
}

// parseXattrEntries decodes the entries that start at region[start]. Offsets
// of the values are relative to valueBase. A violation of the bounds is damage.
func parseXattrEntries(region []byte, start, valueBase int) ([]xattrEntry, error) {
	var out []xattrEntry
	off := start
	for {
		if off+4 > len(region) {
			return nil, errXattrCorrupt("entry list runs past the region")
		}
		if le.Uint32(region[off:]) == 0 {
			return out, nil
		}
		if off+xattrEntryHeader > len(region) {
			return nil, errXattrCorrupt("entry header runs past the region")
		}
		nameLen := int(region[off])
		index := region[off+1]
		voff := int(le.Uint16(region[off+2:]))
		inum := le.Uint32(region[off+4:])
		vsize := int(le.Uint32(region[off+8:]))
		if inum != 0 {
			return nil, errXattrCorrupt("value in an inode is not supported")
		}
		end := off + xattrEntryLen(nameLen)
		if end > len(region) {
			return nil, errXattrCorrupt("entry name runs past the region")
		}
		if vsize > maxXattrValue || valueBase+voff < 0 || valueBase+voff+vsize > len(region) {
			return nil, errXattrCorrupt("value runs past the region")
		}
		val := make([]byte, vsize)
		copy(val, region[valueBase+voff:])
		out = append(out, xattrEntry{index: index, name: string(region[off+xattrEntryHeader : off+xattrEntryHeader+nameLen]), value: val})
		off = end
	}
}

type xattrCorrupt string

func (e xattrCorrupt) Error() string { return "bad extended attributes: " + string(e) }

func errXattrCorrupt(s string) error { return xattrCorrupt(s) }

// parseIbodyXattrs decodes the attributes behind the extra inode fields. area
// is the rest of the inode, which starts with the magic number.
func parseIbodyXattrs(area []byte) ([]xattrEntry, error) {
	if len(area) < 4 || le.Uint32(area) != xattrMagic {
		return nil, nil
	}
	return parseXattrEntries(area, 4, 4)
}

// encodeIbodyXattrs writes the entries into area. The entries must fit.
func encodeIbodyXattrs(area []byte, es []xattrEntry) {
	clear(area)
	le.PutUint32(area, xattrMagic)
	off := 4
	valPos := len(area)
	for _, e := range es {
		vlen := roundUp4(len(e.value))
		valPos -= vlen
		area[off] = byte(len(e.name))
		area[off+1] = e.index
		if len(e.value) > 0 {
			le.PutUint16(area[off+2:], uint16(valPos-4))
			copy(area[valPos:], e.value)
		}
		le.PutUint32(area[off+8:], uint32(len(e.value)))
		le.PutUint32(area[off+12:], xattrHash(e.name, e.value))
		copy(area[off+xattrEntryHeader:], e.name)
		off += xattrEntryLen(len(e.name))
	}
}

// xattrBlockSize returns the encoded size of the entries in a block.
func xattrBlockSize(es []xattrEntry) int {
	total := xattrHeaderSize + xattrBlockTerminate
	for _, e := range es {
		total += xattrEntryLen(len(e.name)) + roundUp4(len(e.value))
	}
	return total
}

// encodeXattrBlock returns the image of an xattr block.
func encodeXattrBlock(es []xattrEntry) []byte {
	buf := make([]byte, blockSize)
	le.PutUint32(buf[0:], xattrMagic)
	le.PutUint32(buf[4:], 1)
	le.PutUint32(buf[8:], 1)
	sorted := append([]xattrEntry(nil), es...)
	sortXattrs(sorted)
	off := xattrHeaderSize
	valPos := blockSize
	var blockHash uint32
	for _, e := range sorted {
		vlen := roundUp4(len(e.value))
		valPos -= vlen
		buf[off] = byte(len(e.name))
		buf[off+1] = e.index
		if len(e.value) > 0 {
			le.PutUint16(buf[off+2:], uint16(valPos))
			copy(buf[valPos:], e.value)
		}
		le.PutUint32(buf[off+8:], uint32(len(e.value)))
		h := xattrHash(e.name, e.value)
		le.PutUint32(buf[off+12:], h)
		copy(buf[off+xattrEntryHeader:], e.name)
		off += xattrEntryLen(len(e.name))
		blockHash = blockHash<<16 ^ blockHash>>16 ^ h
	}
	le.PutUint32(buf[12:], blockHash)
	return buf
}

// xattrBlockImageLocked returns the image of the xattr block, when the node
// has one.
func (n *node) xattrBlockImageLocked() (blockWrite, bool) {
	if n.fileACL == 0 || n.xa == nil {
		return blockWrite{}, false
	}
	return blockWrite{n.fileACL, encodeXattrBlock(n.xa.entries)}, true
}

// xattrsLocked returns the attributes of the node and reads the block once.
func (n *node) xattrsLocked() (*xattrData, error) {
	if n.xa == nil {
		n.xa = &xattrData{}
	}
	if n.fileACL == 0 {
		n.xa.blockLoaded = true
	}
	if n.xa.blockLoaded {
		return n.xa, nil
	}
	if !isValidDataBlock(n.fileACL, n.v.blocksCountSnapshot()) {
		return nil, corrupt("inode %d xattr block %d is not valid", n.ino, n.fileACL)
	}
	var buf [blockSize]byte
	if _, err := n.v.hf.ReadAt(buf[:], int64(n.fileACL)*blockSize); err != nil {
		return nil, hostError(err)
	}
	if le.Uint32(buf[0:]) != xattrMagic || le.Uint32(buf[4:]) != 1 {
		return nil, corrupt("inode %d xattr block %d has a bad header", n.ino, n.fileACL)
	}
	es, err := parseXattrEntries(buf[:], xattrHeaderSize, 0)
	if err != nil {
		return nil, corrupt("inode %d: %v", n.ino, err)
	}
	n.xa.entries = append(n.xa.entries, es...)
	n.xa.blockLoaded = true
	return n.xa, nil
}

// splitXattrName maps a name such as user.foo to its index and its suffix.
func splitXattrName(full string) (uint8, string, bool) {
	switch full {
	case "system.posix_acl_access":
		return xattrIndexPosixAcc, "", true
	case "system.posix_acl_default":
		return xattrIndexPosixDef, "", true
	}
	for _, p := range []struct {
		prefix string
		index  uint8
	}{{"user.", xattrIndexUser}, {"trusted.", xattrIndexTrusted}, {"security.", xattrIndexSecurity}, {"system.", xattrIndexSystem}} {
		if strings.HasPrefix(full, p.prefix) && len(full) > len(p.prefix) {
			return p.index, full[len(p.prefix):], true
		}
	}
	return 0, "", false
}

// joinXattrName is the inverse of splitXattrName.
func joinXattrName(index uint8, name string) string {
	switch index {
	case xattrIndexUser:
		return "user." + name
	case xattrIndexPosixAcc:
		return "system.posix_acl_access"
	case xattrIndexPosixDef:
		return "system.posix_acl_default"
	case xattrIndexTrusted:
		return "trusted." + name
	case xattrIndexSecurity:
		return "security." + name
	case xattrIndexSystem:
		return "system." + name
	}
	return ""
}

// getXattr returns the value of the attribute full.
func (n *node) getXattr(full string) ([]byte, error) {
	idx, name, ok := splitXattrName(full)
	if !ok {
		return nil, linuxerr.EOPNOTSUPP
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	xa, err := n.xattrsLocked()
	if err != nil {
		return nil, err
	}
	for _, e := range xa.entries {
		if e.index == idx && e.name == name {
			return bytes.Clone(e.value), nil
		}
	}
	return nil, linuxerr.ENODATA
}

// listXattr returns the names of the attributes.
func (n *node) listXattr() ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	xa, err := n.xattrsLocked()
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range xa.entries {
		if name := joinXattrName(e.index, e.name); name != "" {
			out = append(out, name)
		}
	}
	return out, nil
}

// setXattr stores the attribute. With create, it fails with EEXIST when the
// attribute exists. With replace, it fails with ENODATA when it does not.
func (n *node) setXattr(full string, value []byte, create, replace bool) error {
	idx, name, ok := splitXattrName(full)
	if !ok || (idx == xattrIndexSystem && name == "data") {
		return linuxerr.EOPNOTSUPP
	}
	if len(name) > 255 {
		return linuxerr.ERANGE
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	xa, err := n.xattrsLocked()
	if err != nil {
		return err
	}
	pos := -1
	for i, e := range xa.entries {
		if e.index == idx && e.name == name {
			pos = i
		}
	}
	switch {
	case pos >= 0 && create:
		return linuxerr.EEXIST
	case pos < 0 && replace:
		return linuxerr.ENODATA
	}
	next := append([]xattrEntry(nil), xa.entries...)
	ent := xattrEntry{index: idx, name: name, value: bytes.Clone(value)}
	if pos >= 0 {
		next[pos] = ent
	} else {
		next = append(next, ent)
	}
	if xattrBlockSize(next) > blockSize {
		return linuxerr.ENOSPC
	}
	return n.installXattrsLocked(next)
}

// removeXattr deletes the attribute.
func (n *node) removeXattr(full string) error {
	idx, name, ok := splitXattrName(full)
	if !ok {
		return linuxerr.EOPNOTSUPP
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	xa, err := n.xattrsLocked()
	if err != nil {
		return err
	}
	for i, e := range xa.entries {
		if e.index == idx && e.name == name {
			next := append(append([]xattrEntry(nil), xa.entries[:i]...), xa.entries[i+1:]...)
			return n.installXattrsLocked(next)
		}
	}
	return linuxerr.ENODATA
}

// installXattrsLocked replaces the attribute list and adjusts the block.
func (n *node) installXattrsLocked(next []xattrEntry) error {
	switch {
	case len(next) > 0 && n.fileACL == 0:
		blk, _, err := n.v.allocBlocks(0, 1)
		if err != nil {
			return err
		}
		n.fileACL = blk
		n.nblocks++
	case len(next) == 0 && n.fileACL != 0:
		if err := n.v.freeBlocks(n.fileACL, 1); err != nil {
			return err
		}
		n.fileACL = 0
		n.nblocks--
	}
	n.xa.entries = next
	n.dirtyXattr = true
	n.markDirtyLocked()
	return nil
}
