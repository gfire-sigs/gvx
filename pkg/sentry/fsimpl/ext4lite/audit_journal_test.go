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

// This file is the independent view of the journal. It reads the JBD2 format
// from the kernel documentation with its own code. It replays a log the way
// the kernel does, so a test can check what Linux would see after a crash
// without the recovery code of the engine.

import (
	"encoding/binary"
	"fmt"
	"slices"
)

var auBE = binary.BigEndian

// auCRC32BE is the checksum of crc32_be in the Linux kernel, written bit by
// bit so that it shares nothing with the table in jbd2.go.
func auCRC32BE(crc uint32, p []byte) uint32 {
	for _, b := range p {
		crc ^= uint32(b) << 24
		for range 8 {
			if crc&0x80000000 != 0 {
				crc = crc<<1 ^ 0x04C11DB7
			} else {
				crc <<= 1
			}
		}
	}
	return crc
}

// auJInfo is what the oracle learns about the journal of an image.
type auJInfo struct {
	exts     []auExtent
	blocks   uint32
	maxlen   uint32
	first    uint32
	sequence uint32
	start    uint32
	compat   uint32
	incompat uint32
	uuid     [16]byte
}

// phys maps a journal block to a host block.
func (j *auJInfo) phys(pos uint32) (uint64, bool) {
	for _, e := range j.exts {
		if pos >= e.lblk && pos-e.lblk < e.n {
			return e.pblk + uint64(pos-e.lblk), true
		}
	}
	return 0, false
}

// auReadJournal parses inode 8 and the journal superblock. It returns nil when
// the image has no journal.
func auReadJournal(img *auPages) (*auJInfo, []string) {
	var sb [1024]byte
	img.readAt(sb[:], 1024)
	if auLE.Uint32(sb[0x5C:])&auCompatJournal == 0 {
		return nil, nil
	}
	c := &auChecker{img: img, res: &auResult{Tree: map[string]*auEnt{}, Blocks: map[uint64]uint32{}}, claim: map[uint64]uint32{}, ino: map[uint32]*auEnt{}}
	blocks := uint64(auLE.Uint32(sb[0x04:])) | uint64(auLE.Uint32(sb[0x150:]))<<32
	c.blocks, c.groups = blocks, int(blocks/auBPG)
	raw := c.inodeRaw(8)
	size := uint64(auLE.Uint32(raw[0x04:])) | uint64(auLE.Uint32(raw[0x6C:]))<<32
	exts, _ := c.parseExtents(8, raw[0x28:0x28+60])
	problems := append([]string(nil), c.res.Problems...)
	j := &auJInfo{exts: exts, blocks: uint32(size / auBlock)}
	var jsb [auBlock]byte
	if blk, ok := j.phys(0); ok {
		img.readAt(jsb[:], int64(blk)*auBlock)
	} else {
		return nil, append(problems, "the journal inode maps no block 0")
	}
	if auBE.Uint32(jsb[0:]) != auJournalMagic || auBE.Uint32(jsb[4:]) != 4 {
		return nil, append(problems, fmt.Sprintf("journal superblock magic %#x type %d", auBE.Uint32(jsb[0:]), auBE.Uint32(jsb[4:])))
	}
	j.maxlen = auBE.Uint32(jsb[0x10:])
	j.first = auBE.Uint32(jsb[0x14:])
	j.sequence = auBE.Uint32(jsb[0x18:])
	j.start = auBE.Uint32(jsb[0x1C:])
	j.compat = auBE.Uint32(jsb[0x24:])
	j.incompat = auBE.Uint32(jsb[0x28:])
	copy(j.uuid[:], jsb[0x30:0x40])
	if auBE.Uint32(jsb[0x0C:]) != auBlock {
		problems = append(problems, "journal block size is not 4096")
	}
	return j, problems
}

// auLogTxn is one committed transaction of the log.
type auLogTxn struct {
	tid     uint32
	writes  map[uint64][]byte // home block to image, in the order of the tags
	order   []uint64
	revoked []uint64
	blocks  uint32 // log blocks of the transaction
}

// auScanLog returns the committed transactions that a replay applies. It
// follows the kernel scan: sequence numbers must match, and a checksum
// mismatch ends the log.
func auScanLog(img *auPages, j *auJInfo) []auLogTxn {
	read := func(pos uint32) []byte {
		b := make([]byte, auBlock)
		if blk, ok := j.phys(pos); ok {
			img.readAt(b, int64(blk)*auBlock)
		}
		return b
	}
	tagBytes, recBytes := 8, 4
	if j.incompat&2 != 0 {
		tagBytes, recBytes = 12, 8
	}
	var out []auLogTxn
	pos, tid := j.start, j.sequence
	if pos == 0 {
		return nil
	}
	crc := ^uint32(0)
	cur := auLogTxn{tid: tid, writes: map[uint64][]byte{}}
	begin := pos
	for steps := uint32(0); steps < j.maxlen; steps++ {
		if pos < j.first || pos >= j.maxlen {
			break
		}
		b := read(pos)
		if auBE.Uint32(b[0:]) != auJournalMagic || auBE.Uint32(b[8:]) != tid {
			break
		}
		switch auBE.Uint32(b[4:]) {
		case 1:
			crc = auCRC32BE(crc, b)
			off := 12
			var tags []struct {
				blk   uint64
				flags uint16
			}
			for off+tagBytes <= auBlock {
				blk := uint64(auBE.Uint32(b[off:]))
				flags := auBE.Uint16(b[off+6:])
				if tagBytes == 12 {
					blk |= uint64(auBE.Uint32(b[off+8:])) << 32
				}
				tags = append(tags, struct {
					blk   uint64
					flags uint16
				}{blk, flags})
				off += tagBytes
				if flags&2 == 0 {
					off += 16
				}
				if flags&8 != 0 {
					break
				}
			}
			for k, t := range tags {
				d := read(pos + 1 + uint32(k))
				crc = auCRC32BE(crc, d)
				if t.flags&1 != 0 {
					auBE.PutUint32(d[0:], auJournalMagic)
				}
				if _, dup := cur.writes[t.blk]; !dup {
					cur.order = append(cur.order, t.blk)
				}
				cur.writes[t.blk] = d
			}
			pos += 1 + uint32(len(tags))
		case 5:
			n := int(auBE.Uint32(b[12:]))
			for off := 16; off+recBytes <= n && off+recBytes <= auBlock; off += recBytes {
				if recBytes == 8 {
					cur.revoked = append(cur.revoked, auBE.Uint64(b[off:]))
				} else {
					cur.revoked = append(cur.revoked, uint64(auBE.Uint32(b[off:])))
				}
			}
			pos++
		case 2:
			if j.compat&1 != 0 && b[12] != 0 && (b[12] != 1 || b[13] != 4 || auBE.Uint32(b[16:]) != crc) {
				return out
			}
			pos++
			cur.blocks = pos - begin
			out = append(out, cur)
			tid++
			cur = auLogTxn{tid: tid, writes: map[uint64][]byte{}}
			crc = ^uint32(0)
			begin = pos
		default:
			return out
		}
	}
	return out
}

// auReplayImage returns the image that a kernel replay leaves. It does not
// clear the journal, so the caller can still read the log.
func auReplayImage(img *auPages) (*auPages, []auLogTxn) {
	j, _ := auReadJournal(img)
	if j == nil {
		return img.clone(), nil
	}
	txns := auScanLog(img, j)
	revoked := map[uint64]uint32{}
	for _, t := range txns {
		for _, b := range t.revoked {
			revoked[b] = max(revoked[b], t.tid)
		}
	}
	out := img.clone()
	for _, t := range txns {
		for _, blk := range t.order {
			if r, ok := revoked[blk]; ok && r >= t.tid {
				continue
			}
			out.writeAt(t.writes[blk], int64(blk)*auBlock)
		}
	}
	return out, txns
}

// checkJournal verifies the journal inode and the journal superblock.
func (c *auChecker) checkJournal() {
	r := c.res
	sb := c.read(0, 1024, 1024)
	has := auLE.Uint32(sb[0x5C:])&auCompatJournal != 0
	raw := c.inodeRaw(8)
	if !has {
		if auLE.Uint16(raw[0:]) != 0 {
			r.problemf("inode 8 is in use and the volume has no journal flag")
		}
		return
	}
	if got := auLE.Uint32(sb[0xE0:]); got != 8 {
		r.problemf("s_journal_inum is %d", got)
	}
	if sb[0xFD] != 1 {
		r.problemf("s_jnl_backup_type is %d, want 1", sb[0xFD])
	}
	for i := range 15 {
		if auLE.Uint32(sb[0x10C+4*i:]) != auLE.Uint32(raw[0x28+4*i:]) {
			r.problemf("s_jnl_blocks[%d] differs from i_block[%d] of the journal inode", i, i)
		}
	}
	size := uint64(auLE.Uint32(raw[0x04:])) | uint64(auLE.Uint32(raw[0x6C:]))<<32
	if auLE.Uint32(sb[0x10C+4*15:]) != uint32(size>>32) || auLE.Uint32(sb[0x10C+4*16:]) != uint32(size) {
		r.problemf("s_jnl_blocks size words differ from the journal inode")
	}
	if auLE.Uint16(raw[0:]) != 0o100600 || auLE.Uint16(raw[0x1A:]) != 1 || auLE.Uint32(raw[0x20:]) != auFlagExtents {
		r.problemf("journal inode mode %#o links %d flags %#x", auLE.Uint16(raw[0:]), auLE.Uint16(raw[0x1A:]), auLE.Uint32(raw[0x20:]))
	}
	exts, leaves := c.parseExtents(8, raw[0x28:0x28+60])
	if len(leaves) != 0 {
		r.problemf("journal inode has an extent tree of depth 1")
	}
	var nblocks uint64
	for _, e := range exts {
		nblocks += uint64(e.n)
		for i := uint32(0); i < e.n; i++ {
			c.own(8, e.pblk+uint64(i))
		}
	}
	if nblocks*auBlock != size || nblocks < auJournalBlocks {
		r.problemf("journal inode has %d blocks and the size %d", nblocks, size)
	}
	if sectors := uint64(auLE.Uint32(raw[0x1C:])); sectors != nblocks*8 {
		r.problemf("journal inode i_blocks is %d sectors, want %d", sectors, nblocks*8)
	}
	j, problems := auReadJournal(c.img)
	for _, p := range problems {
		r.problemf("%s", p)
	}
	if j == nil {
		return
	}
	if j.maxlen != uint32(nblocks) || j.first != 1 {
		r.problemf("journal superblock has maxlen %d first %d for %d blocks", j.maxlen, j.first, nblocks)
	}
	if j.incompat&^3 != 0 || j.compat&^1 != 0 {
		r.problemf("journal features %#x/%#x", j.compat, j.incompat)
	}
	if !slices.Equal(j.uuid[:], sb[0x68:0x78]) {
		r.problemf("journal uuid differs from the file system uuid")
	}
	if c.strict && j.start != 0 {
		r.problemf("a clean image has a journal that still holds a log (start %d)", j.start)
	}
}
