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

// The journal format is the JBD2 format of the Linux kernel, so the kernel and
// e2fsck can replay a log that ext4lite wrote. Journal fields are big endian,
// unlike the fields of the file system. The journal is the file of inode 8. Its
// first block is the journal superblock, and the log follows. A transaction
// holds optional revoke blocks, then descriptor blocks that each precede the
// data blocks they list, then a commit block.

import (
	"encoding/binary"
	"errors"
)

var be = binary.BigEndian

const (
	jbd2Magic = 0xC03B3998

	jbd2BlockDescriptor = 1
	jbd2BlockCommit     = 2
	jbd2BlockSuperV1    = 3
	jbd2BlockSuperV2    = 4
	jbd2BlockRevoke     = 5

	// Journal feature flags that ext4lite understands.
	jbd2CompatChecksum   = 0x1
	jbd2IncompatRevoke   = 0x1
	jbd2Incompat64bit    = 0x2
	jbd2KnownCompat      = jbd2CompatChecksum
	jbd2KnownIncompat    = jbd2IncompatRevoke | jbd2Incompat64bit
	jbd2WrittenCompat    = jbd2CompatChecksum
	jbd2WrittenIncompat  = jbd2IncompatRevoke | jbd2Incompat64bit
	jbd2CRC32Checksum    = 1
	jbd2CRC32ChecksumLen = 4

	// Tag flags.
	jbd2FlagEscape   = 1
	jbd2FlagSameUUID = 2
	jbd2FlagDeleted  = 4
	jbd2FlagLastTag  = 8

	// Offsets inside the journal superblock.
	jsbBlocksize     = 0x0C
	jsbMaxlen        = 0x10
	jsbFirst         = 0x14
	jsbSequence      = 0x18
	jsbStart         = 0x1C
	jsbErrno         = 0x20
	jsbFeatureCompat = 0x24
	jsbFeatureIncomp = 0x28
	jsbFeatureRoComp = 0x2C
	jsbUUID          = 0x30
	jsbNrUsers       = 0x40

	// jbd2HeaderSize is the size of the header that starts every log block.
	jbd2HeaderSize = 12
	// jbd2TagSize is the size of one tag of a journal with 64-bit block numbers.
	jbd2TagSize = 12
	jbd2UUIDLen = 16
	// jbd2MaxTags is the number of tags in one descriptor block. The first tag
	// is followed by the 16 bytes of the file system UUID.
	jbd2MaxTags = (blockSize - jbd2HeaderSize - jbd2UUIDLen) / jbd2TagSize
	// jbd2RevokePerBlock is the number of 64-bit records in one revoke block.
	jbd2RevokePerBlock = (blockSize - 16) / 8

	// Commit block offsets.
	jcmChecksumType = 12
	jcmChecksumSize = 13
	jcmChecksum     = 16
	jcmCommitSec    = 48
	jcmCommitNsec   = 56

	// Fields and flags of the file system superblock that belong to the journal.
	compatHasJournal = 0x0004
	incompatRecover  = 0x0004
	sbJournalInum    = 0xE0
	sbLastOrphan     = 0xE8
	sbJnlBackupType  = 0xFD
	sbJnlBlocks      = 0x10C

	// journalBlocks is the size of the journal in blocks. 1024 blocks is the
	// smallest journal that the Linux kernel accepts.
	journalBlocks = 1024
	// journalIno is the reserved inode of the journal.
	journalIno = 8
)

var (
	errJournalCorrupt = errors.New("ext4lite: the journal is damaged")
	// errJournalTooBig reports a transaction that does not fit into the journal.
	errJournalTooBig = errors.New("ext4lite: the transaction does not fit into the journal")
)

// crc32beTable is the table of the big-endian CRC-32 that JBD2 uses for the
// checksum of a transaction. The algorithm has no reflection and no final
// inversion, as crc32_be of the Linux kernel.
var crc32beTable = func() (t [256]uint32) {
	for i := range t {
		c := uint32(i) << 24
		for range 8 {
			if c&0x80000000 != 0 {
				c = c<<1 ^ 0x04C11DB7
			} else {
				c <<= 1
			}
		}
		t[i] = c
	}
	return t
}()

// crc32be extends crc with p.
func crc32be(crc uint32, p []byte) uint32 {
	for _, b := range p {
		crc = crc<<8 ^ crc32beTable[byte(crc>>24)^b]
	}
	return crc
}

// journalSuper is the decoded journal superblock.
type journalSuper struct {
	blockType uint32
	maxlen    uint32
	first     uint32
	sequence  uint32
	start     uint32
	errno     int32
	compat    uint32
	incompat  uint32
	roCompat  uint32
	uuid      [16]byte
}

// encode returns the block image of the journal superblock.
func (s *journalSuper) encode() []byte {
	b := make([]byte, blockSize)
	be.PutUint32(b[0:], jbd2Magic)
	be.PutUint32(b[4:], jbd2BlockSuperV2)
	be.PutUint32(b[jsbBlocksize:], blockSize)
	be.PutUint32(b[jsbMaxlen:], s.maxlen)
	be.PutUint32(b[jsbFirst:], s.first)
	be.PutUint32(b[jsbSequence:], s.sequence)
	be.PutUint32(b[jsbStart:], s.start)
	be.PutUint32(b[jsbErrno:], uint32(s.errno))
	be.PutUint32(b[jsbFeatureCompat:], s.compat)
	be.PutUint32(b[jsbFeatureIncomp:], s.incompat)
	be.PutUint32(b[jsbFeatureRoComp:], s.roCompat)
	copy(b[jsbUUID:], s.uuid[:])
	be.PutUint32(b[jsbNrUsers:], 1)
	return b
}

// decodeJournalSuper parses and checks a journal superblock. It accepts only
// the features that ext4lite replays. blocks is the size of the journal file.
func decodeJournalSuper(b []byte, blocks uint32) (journalSuper, error) {
	var s journalSuper
	if be.Uint32(b[0:]) != jbd2Magic {
		return s, errJournalCorrupt
	}
	s.blockType = be.Uint32(b[4:])
	if s.blockType != jbd2BlockSuperV2 {
		return s, corrupt("journal superblock has the type %d, want %d", s.blockType, jbd2BlockSuperV2)
	}
	if got := be.Uint32(b[jsbBlocksize:]); got != blockSize {
		return s, corrupt("journal block size is %d", got)
	}
	s.maxlen = be.Uint32(b[jsbMaxlen:])
	s.first = be.Uint32(b[jsbFirst:])
	s.sequence = be.Uint32(b[jsbSequence:])
	s.start = be.Uint32(b[jsbStart:])
	s.errno = int32(be.Uint32(b[jsbErrno:]))
	s.compat = be.Uint32(b[jsbFeatureCompat:])
	s.incompat = be.Uint32(b[jsbFeatureIncomp:])
	s.roCompat = be.Uint32(b[jsbFeatureRoComp:])
	copy(s.uuid[:], b[jsbUUID:jsbUUID+16])
	if s.maxlen < journalBlocks || s.maxlen > blocks {
		return s, corrupt("journal length %d blocks, the journal file has %d", s.maxlen, blocks)
	}
	if s.first < 1 || s.first >= s.maxlen || (s.start != 0 && (s.start < s.first || s.start >= s.maxlen)) {
		return s, corrupt("journal log starts at %d, first block is %d of %d", s.start, s.first, s.maxlen)
	}
	if s.compat&^jbd2KnownCompat != 0 || s.incompat&^jbd2KnownIncompat != 0 || s.roCompat != 0 {
		return s, corrupt("journal uses unsupported features %#x/%#x/%#x", s.compat, s.incompat, s.roCompat)
	}
	return s, nil
}

// tagBytes returns the size of a tag in a journal with the features of s.
func (s *journalSuper) tagBytes() int {
	if s.incompat&jbd2Incompat64bit != 0 {
		return 12
	}
	return 8
}

// revokeRecordBytes returns the size of a revoke record.
func (s *journalSuper) revokeRecordBytes() int {
	if s.incompat&jbd2Incompat64bit != 0 {
		return 8
	}
	return 4
}

// logHeader writes the header of a log block.
func logHeader(b []byte, blockType, tid uint32) {
	be.PutUint32(b[0:], jbd2Magic)
	be.PutUint32(b[4:], blockType)
	be.PutUint32(b[8:], tid)
}

// jbd2Tag is one entry of a descriptor block.
type jbd2Tag struct {
	blk   uint64
	flags uint16
}

// journalTxn is the encoded form of one transaction.
type journalTxn struct {
	// buf holds every log block of the transaction in log order.
	buf []byte
	// blocks is the number of log blocks.
	blocks uint32
}

// encodeTxn builds the log blocks of a transaction. images are the metadata
// blocks to journal. revokes are the blocks that the transaction frees, so a
// replay never writes an older image of them again.
func encodeTxn(tid uint32, fsUUID [16]byte, images []blockWrite, revokes []uint64, commitTime int64) journalTxn {
	nRevoke := (len(revokes) + jbd2RevokePerBlock - 1) / jbd2RevokePerBlock
	nDesc := (len(images) + jbd2MaxTags - 1) / jbd2MaxTags
	total := nRevoke + nDesc + len(images) + 1
	buf := make([]byte, total*blockSize)
	pos := 0
	next := func() []byte {
		b := buf[pos*blockSize : (pos+1)*blockSize]
		pos++
		return b
	}

	for i := range nRevoke {
		b := next()
		logHeader(b, jbd2BlockRevoke, tid)
		part := revokes[i*jbd2RevokePerBlock : min(len(revokes), (i+1)*jbd2RevokePerBlock)]
		for k, blk := range part {
			be.PutUint64(b[16+8*k:], blk)
		}
		be.PutUint32(b[12:], uint32(16+8*len(part)))
	}

	crc := ^uint32(0)
	for i := range nDesc {
		desc := next()
		logHeader(desc, jbd2BlockDescriptor, tid)
		part := images[i*jbd2MaxTags : min(len(images), (i+1)*jbd2MaxTags)]
		off := jbd2HeaderSize
		dataStart := pos
		for k, w := range part {
			flags := uint16(0)
			if k > 0 {
				flags |= jbd2FlagSameUUID
			}
			if k == len(part)-1 {
				flags |= jbd2FlagLastTag
			}
			data := next()
			copy(data, w.data)
			if be.Uint32(data[0:]) == jbd2Magic {
				// The magic number at the start of a data block would look like
				// the start of a log block. The log stores it as zero.
				be.PutUint32(data[0:], 0)
				flags |= jbd2FlagEscape
			}
			be.PutUint32(desc[off:], uint32(w.blk))
			be.PutUint16(desc[off+6:], flags)
			be.PutUint32(desc[off+8:], uint32(w.blk>>32))
			off += jbd2TagSize
			if k == 0 {
				copy(desc[off:], fsUUID[:])
				off += jbd2UUIDLen
			}
		}
		crc = crc32be(crc, desc)
		for k := range part {
			crc = crc32be(crc, buf[(dataStart+k)*blockSize:(dataStart+k+1)*blockSize])
		}
	}

	cm := next()
	logHeader(cm, jbd2BlockCommit, tid)
	cm[jcmChecksumType] = jbd2CRC32Checksum
	cm[jcmChecksumSize] = jbd2CRC32ChecksumLen
	be.PutUint32(cm[jcmChecksum:], crc)
	be.PutUint64(cm[jcmCommitSec:], uint64(commitTime))
	return journalTxn{buf: buf, blocks: uint32(total)}
}

// replayedTxn is one committed transaction that the scan found.
type replayedTxn struct {
	tid     uint32
	tags    []replayTag
	revokes []uint64
}

// replayTag names one data block of a transaction in the log.
type replayTag struct {
	blk    uint64
	logPos uint32
	escape bool
}

// scanLog reads the committed transactions of the log. read returns the log
// block at the log position pos. The scan stops at the first block that is not
// part of a complete, valid transaction, as the kernel does.
func scanLog(s *journalSuper, read func(pos uint32) ([]byte, error)) ([]replayedTxn, error) {
	var out []replayedTxn
	pos, tid := s.start, s.sequence
	tagSize := s.tagBytes()
	recSize := s.revokeRecordBytes()
	crc := ^uint32(0)
	var cur replayedTxn
	cur.tid = tid
	steps := uint32(0)
	for {
		if steps++; steps > s.maxlen {
			return out, nil
		}
		if pos < s.first || pos >= s.maxlen {
			return out, nil
		}
		b, err := read(pos)
		if err != nil {
			return out, err
		}
		if be.Uint32(b[0:]) != jbd2Magic || be.Uint32(b[8:]) != tid {
			return out, nil
		}
		switch be.Uint32(b[4:]) {
		case jbd2BlockDescriptor:
			crc = crc32be(crc, b)
			off := jbd2HeaderSize
			first := true
			count := 0
			for off+tagSize <= blockSize {
				blk := uint64(be.Uint32(b[off:]))
				flags := be.Uint16(b[off+6:])
				if tagSize == 12 {
					blk |= uint64(be.Uint32(b[off+8:])) << 32
				}
				count++
				if pos+uint32(count) >= s.maxlen {
					return out, nil
				}
				cur.tags = append(cur.tags, replayTag{blk: blk, logPos: pos + uint32(count), escape: flags&jbd2FlagEscape != 0})
				off += tagSize
				if flags&jbd2FlagSameUUID == 0 {
					off += jbd2UUIDLen
				}
				first = false
				if flags&jbd2FlagLastTag != 0 {
					break
				}
			}
			if first {
				return out, nil
			}
			for k := range count {
				d, err := read(pos + 1 + uint32(k))
				if err != nil {
					return out, err
				}
				crc = crc32be(crc, d)
			}
			pos += 1 + uint32(count)
		case jbd2BlockRevoke:
			n := be.Uint32(b[12:])
			if n < 16 || n > blockSize {
				return out, nil
			}
			for off := 16; off+recSize <= int(n); off += recSize {
				if recSize == 8 {
					cur.revokes = append(cur.revokes, be.Uint64(b[off:]))
				} else {
					cur.revokes = append(cur.revokes, uint64(be.Uint32(b[off:])))
				}
			}
			pos++
		case jbd2BlockCommit:
			if s.compat&jbd2CompatChecksum != 0 && b[jcmChecksumType] != 0 {
				if b[jcmChecksumType] != jbd2CRC32Checksum || b[jcmChecksumSize] != jbd2CRC32ChecksumLen || be.Uint32(b[jcmChecksum:]) != crc {
					return out, nil
				}
			}
			out = append(out, cur)
			tid++
			cur = replayedTxn{tid: tid}
			crc = ^uint32(0)
			pos++
		default:
			return out, nil
		}
	}
}
