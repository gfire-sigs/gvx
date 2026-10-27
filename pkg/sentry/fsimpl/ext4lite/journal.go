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

// A flush writes the new images of the changed metadata blocks to the log as one
// transaction and flushes the host file. A crash then replays the transaction, so
// the volume shows the state before or after the flush, never a mix. The home
// blocks follow without a flush of their own, because the next flush of the host
// file makes them durable too.
//
// Only metadata goes through the log. When a transaction makes new blocks
// reachable, the flush first flushes the file data, as the ordered mode of ext4
// does. A transaction that frees a block that an earlier transaction of the same
// log holds writes a revoke record, or a replay would write the old metadata over
// new file data. The log is linear. When it is full, the journal flushes the home
// blocks and starts again with a higher sequence number.

import "sync/atomic"

// disableJournalUpgrade stops the mount from adding a journal to an old volume.
// The tests set it to run the legacy mode on a volume that has the room.
var disableJournalUpgrade atomic.Bool

// journal is the in-memory state of the journal of a mounted volume. The
// volume serializes access with flushMu, except for logged and inflight,
// which volume.mu protects.
type journal struct {
	super journalSuper
	// extents maps the blocks of the journal file to host blocks.
	extents []extent
	// leaves lists any extent leaf blocks of inode 8 when the journal uses a
	// depth-1 tree.
	leaves []uint64
	// head is the log position of the next transaction.
	head uint32
	// seq is the sequence number of the next transaction.
	seq uint32
	// logged holds the blocks that a transaction of the current log wrote.
	logged map[uint64]struct{}
	// unsynced is true while home writes wait for a host flush.
	unsynced bool
}

// holds reports whether host block blk belongs to the journal. A valid
// transaction never writes there. A replay that did would overwrite the log that
// it still reads, and a second replay after a crash would see another log.
func (j *journal) holds(blk uint64) bool {
	for _, l := range j.leaves {
		if blk == l {
			return true
		}
	}
	for _, e := range j.extents {
		if blk >= e.pblk && blk-e.pblk < uint64(e.n) {
			return true
		}
	}
	return false
}

// physBlock returns the host block of block pos of the journal file.
func (j *journal) physBlock(pos uint32) (uint64, bool) {
	for _, e := range j.extents {
		if pos >= e.lblk && pos-e.lblk < e.n {
			return e.pblk + uint64(pos-e.lblk), true
		}
	}
	return 0, false
}

// readLog reads block pos of the journal file.
func (v *volume) readLog(j *journal, pos uint32) ([]byte, error) {
	blk, ok := j.physBlock(pos)
	if !ok {
		return nil, corrupt("journal block %d is not mapped", pos)
	}
	b := make([]byte, blockSize)
	if _, err := v.hf.ReadAt(b, int64(blk)*blockSize); err != nil {
		return nil, hostError(err)
	}
	return b, nil
}

// writeLog writes consecutive blocks of the journal file from block pos. It
// issues one host write for each run of host blocks.
func (v *volume) writeLog(j *journal, pos uint32, data []byte) error {
	for len(data) > 0 {
		blk, ok := j.physBlock(pos)
		if !ok {
			return corrupt("journal block %d is not mapped", pos)
		}
		run := uint32(1)
		for uint64(run)*blockSize < uint64(len(data)) {
			next, ok := j.physBlock(pos + run)
			if !ok || next != blk+uint64(run) {
				break
			}
			run++
		}
		n := int(run) * blockSize
		if err := v.writeMeta(data[:n], int64(blk)*blockSize); err != nil {
			return err
		}
		data, pos = data[n:], pos+run
	}
	return nil
}

// writeMeta writes metadata to the host file. It marks the blocks for a live
// migration like every write, but it does not count as unsynced file data.
func (v *volume) writeMeta(p []byte, off int64) error {
	var err error
	if t, ok := v.hf.(*trackedFile); ok {
		_, err = t.writeMeta(p, off)
	} else {
		_, err = v.hf.WriteAt(p, off)
	}
	return hostError(err)
}

func (v *volume) fsUUID() (u [16]byte) {
	copy(u[:], v.sb[sbUUID:sbUUID+16])
	return u
}

// loadJournal reads the journal inode and the journal superblock. It returns
// nil when the volume has no journal.
func (v *volume) loadJournal() (*journal, error) {
	if le.Uint32(v.sb[sbFeatureCompat:])&compatHasJournal == 0 {
		return nil, nil
	}
	if got := le.Uint32(v.sb[sbJournalInum:]); got != journalIno {
		return nil, corrupt("journal inode is %d, want %d", got, journalIno)
	}
	blk, off := inodeLocation(journalIno)
	var buf [blockSize]byte
	if _, err := v.hf.ReadAt(buf[:], int64(blk)*blockSize); err != nil {
		return nil, hostError(err)
	}
	raw := buf[off : off+inodeSize]
	size := uint64(le.Uint32(raw[inSizeLo:])) | uint64(le.Uint32(raw[inSizeHi:]))<<32
	if le.Uint16(raw[inMode:])&modeTypeMask != modeRegular || size%blockSize != 0 || size/blockSize < journalBlocks {
		return nil, corrupt("journal inode has the size %d", size)
	}
	blocksCount := uint64(le.Uint32(v.sb[sbBlocksCountLo:])) | uint64(le.Uint32(v.sb[sbBlocksCountHi:]))<<32
	exts, leaves, err := v.parseJournalExtents(raw[inBlock:inBlock+iBlockSize], size/blockSize, blocksCount)
	if err != nil {
		return nil, err
	}
	j := &journal{extents: exts, leaves: leaves, logged: make(map[uint64]struct{})}
	blocks := uint32(min(size/blockSize, 1<<31))
	sb, err := v.readLog(j, 0)
	if err != nil {
		return nil, err
	}
	j.super, err = decodeJournalSuper(sb, blocks)
	if err != nil {
		return nil, err
	}
	// The journal must end inside the extents.
	if _, ok := j.physBlock(j.super.maxlen - 1); !ok {
		return nil, corrupt("journal length %d is not mapped", j.super.maxlen)
	}
	return j, nil
}

// parseJournalExtents reads the extents of the journal inode. The volume has
// not loaded its groups when it replays the journal, so the check cannot use
// the engine parser. The journal may sit in depth 0 (up to 4 extents in the
// inode) or depth 1 (up to 4 extent leaf blocks).
func (v *volume) parseJournalExtents(root []byte, blocks, volumeBlocks uint64) ([]extent, []uint64, error) {
	if le.Uint16(root[0:]) != extMagic {
		return nil, nil, corrupt("journal inode has no extent header")
	}
	entries, maxE, depth := int(le.Uint16(root[2:])), int(le.Uint16(root[4:])), le.Uint16(root[6:])
	if maxE != rootExtents || entries < 1 || entries > rootExtents || depth > 1 {
		return nil, nil, corrupt("journal inode has %d entries at depth %d", entries, depth)
	}
	var (
		out    []extent
		leaves []uint64
		next   uint64
	)
	addExt := func(e extent, idx int) error {
		if e.uninit || e.n == 0 || e.n > maxExtentLen || uint64(e.lblk) != next || e.pblk >= volumeBlocks ||
			e.pend() > volumeBlocks || isMetadataBlock(e.pblk) || isMetadataBlock(e.pend()-1) {
			return corrupt("journal extent %d (%d+%d at %d) is not valid", idx, e.lblk, e.n, e.pblk)
		}
		next += uint64(e.n)
		out = append(out, e)
		return nil
	}
	if depth == 0 {
		for i := range entries {
			if err := addExt(decodeExtent(root[extHeaderSize+extEntrySize*i:]), i); err != nil {
				return nil, nil, err
			}
		}
	} else {
		var leaf [blockSize]byte
		for i := range entries {
			_, lb := decodeExtentIdx(root[extHeaderSize+extEntrySize*i:])
			if lb >= volumeBlocks || isMetadataBlock(lb) {
				return nil, nil, corrupt("journal extent leaf %d is not valid", lb)
			}
			if _, err := v.hf.ReadAt(leaf[:], int64(lb)*blockSize); err != nil {
				return nil, nil, hostError(err)
			}
			if le.Uint16(leaf[0:]) != extMagic || le.Uint16(leaf[6:]) != 0 {
				return nil, nil, corrupt("journal extent leaf %d has a bad header", lb)
			}
			lcnt, lmax := int(le.Uint16(leaf[2:])), int(le.Uint16(leaf[4:]))
			if lmax != leafExtents || lcnt < 1 || lcnt > lmax {
				return nil, nil, corrupt("journal extent leaf %d has %d of %d entries", lb, lcnt, lmax)
			}
			leaves = append(leaves, lb)
			for j := range lcnt {
				if err := addExt(decodeExtent(leaf[extHeaderSize+extEntrySize*j:]), len(out)); err != nil {
					return nil, nil, err
				}
			}
		}
	}
	if next != blocks {
		return nil, nil, corrupt("journal extents cover %d blocks, the inode has %d", next, blocks)
	}
	return out, leaves, nil
}

// needsReplay reports whether the log can hold a transaction that the volume
// did not apply.
func (j *journal) needsReplay(sb []byte) bool {
	return j.super.start != 0 || le.Uint32(sb[sbFeatureIncompat:])&incompatRecover != 0
}

// replayJournal applies every committed transaction of the log to the home
// blocks, flushes the host file, and empties the log. The volume calls it
// before it reads any other metadata.
func (v *volume) replayJournal(j *journal) error {
	s := &j.super
	txns, err := scanLog(s, func(pos uint32) ([]byte, error) { return v.readLog(j, pos) })
	if err != nil {
		return err
	}
	revoked := make(map[uint64]uint32)
	for _, t := range txns {
		for _, b := range t.revokes {
			if t.tid > revoked[b] {
				revoked[b] = t.tid
			}
		}
	}
	// A transaction can grow or shrink the volume. The superblock image of the
	// last transaction that holds one tells the final size. A block beyond the
	// final size, or beyond the end of the host file, belongs to a group that
	// the log removed, or to a hostile log, and no replay writes it. The host
	// file bound also stops a log from growing the file with a hole.
	blocks := uint64(le.Uint32(v.sb[sbBlocksCountLo:])) | uint64(le.Uint32(v.sb[sbBlocksCountHi:]))<<32
	for i := len(txns) - 1; i >= 0; i-- {
		found := false
		for _, tag := range txns[i].tags {
			if tag.blk != 0 {
				continue
			}
			if rt, ok := revoked[0]; ok && rt >= txns[i].tid {
				continue
			}
			data, err := v.readLog(j, tag.logPos)
			if err != nil {
				return err
			}
			blocks = uint64(le.Uint32(data[superOffset+sbBlocksCountLo:])) | uint64(le.Uint32(data[superOffset+sbBlocksCountHi:]))<<32
			found = true
			break
		}
		if found {
			break
		}
	}
	hostSize, err := v.hf.Size()
	if err != nil {
		return hostError(err)
	}
	blocks = min(blocks, uint64(hostSize/blockSize), maxGroups*blocksPerGroup)
	for _, t := range txns {
		for _, tag := range t.tags {
			if rt, ok := revoked[tag.blk]; ok && rt >= t.tid {
				continue
			}
			if tag.blk >= blocks || j.holds(tag.blk) {
				continue
			}
			data, err := v.readLog(j, tag.logPos)
			if err != nil {
				return err
			}
			if tag.escape {
				be.PutUint32(data[0:], jbd2Magic)
			}
			if err := v.writeMeta(data, int64(tag.blk)*blockSize); err != nil {
				return err
			}
		}
	}
	if err := v.hf.Sync(); err != nil {
		return hostError(err)
	}
	next := s.sequence
	if len(txns) > 0 {
		next = txns[len(txns)-1].tid + 1
	}
	s.sequence, s.start = next, 0
	j.seq = next
	if err := v.writeLog(j, 0, s.encode()); err != nil {
		return err
	}
	if err := v.hf.Sync(); err != nil {
		return hostError(err)
	}
	// Block 0 of the volume can have changed.
	var b0 [blockSize]byte
	if _, err := v.hf.ReadAt(b0[:], 0); err != nil {
		return hostError(err)
	}
	copy(v.sb[:], b0[superOffset:superOffset+superSize])
	return nil
}

// startSession marks the log as in use. It sets the recovery flag in the
// superblock of the volume and the start of the log, and it flushes the host
// file. After the call, a crash makes the next mount run the log, and the
// first commit can follow. The caller holds flushMu or owns the volume.
func (v *volume) startSession() error {
	j := v.j
	j.super.start = j.super.first
	j.super.sequence = j.seq
	j.head = j.super.first
	clear(j.logged)
	v.state &^= stateValid
	v.setSbU32(sbFeatureIncompat, v.sbU32(sbFeatureIncompat)|incompatRecover)
	v.sbDirty = true
	v.mu.Lock()
	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	v.sbDirty = false
	v.mu.Unlock()
	if err := v.writeLog(j, 0, j.super.encode()); err != nil {
		return err
	}
	if err := v.writeMeta(b0[:], 0); err != nil {
		return err
	}
	return hostError(v.hf.Sync())
}

// resetLog flushes the home blocks and starts the log again. The caller holds
// flushMu.
func (v *volume) resetLog() error {
	j := v.j
	if j.unsynced {
		if err := v.hf.Sync(); err != nil {
			return hostError(err)
		}
		j.unsynced = false
	}
	j.super.start = j.super.first
	j.super.sequence = j.seq
	if err := v.writeLog(j, 0, j.super.encode()); err != nil {
		return err
	}
	if err := v.hf.Sync(); err != nil {
		return hostError(err)
	}
	j.head = j.super.first
	v.mu.Lock()
	clear(j.logged)
	v.mu.Unlock()
	return nil
}

// commitTxn writes the images and the revoke records as one transaction and
// flushes the host file. When barrier is true, it first flushes the file data
// that the guest wrote, so that a new block never becomes reachable before its
// data is durable. The caller holds flushMu.
func (v *volume) commitTxn(images []blockWrite, revokes []uint64, barrier bool) error {
	j := v.j
	need := txnBlocks(len(images), len(revokes))
	if need > j.super.maxlen-j.super.first {
		return errJournalTooBig
	}
	if j.head+need > j.super.maxlen {
		if err := v.resetLog(); err != nil {
			return err
		}
	}
	if barrier {
		if err := v.hf.Sync(); err != nil {
			return hostError(err)
		}
		j.unsynced = false
	}
	txn := encodeTxn(j.seq, v.fsUUID(), images, revokes, v.now().Unix())
	if err := v.writeLog(j, j.head, txn.buf); err != nil {
		return err
	}
	if err := v.hf.Sync(); err != nil {
		return hostError(err)
	}
	j.unsynced = false
	j.head += txn.blocks
	j.seq++
	v.mu.Lock()
	for _, w := range images {
		j.logged[w.blk] = struct{}{}
	}
	v.mu.Unlock()
	return nil
}

// txnBlocks returns the number of log blocks of a transaction.
func txnBlocks(images, revokes int) uint32 {
	nRevoke := (revokes + jbd2RevokePerBlock - 1) / jbd2RevokePerBlock
	nDesc := (images + jbd2MaxTags - 1) / jbd2MaxTags
	return uint32(nRevoke + nDesc + images + 1)
}

// endSession empties the log after a final checkpoint. The caller holds flushMu
// and has flushed every change to the home blocks.
func (v *volume) endSession(clean bool) error {
	j := v.j
	if j.unsynced {
		if err := v.hf.Sync(); err != nil {
			return hostError(err)
		}
		j.unsynced = false
	}
	j.super.start = 0
	j.super.sequence = j.seq
	if err := v.writeLog(j, 0, j.super.encode()); err != nil {
		return err
	}
	v.mu.Lock()
	v.setSbU32(sbFeatureIncompat, v.sbU32(sbFeatureIncompat)&^incompatRecover)
	if clean {
		v.state |= stateValid
	}
	v.fillSuperLocked()
	var b0 [blockSize]byte
	copy(b0[superOffset:], v.sb[:])
	v.sbDirty = false
	v.mu.Unlock()
	if err := v.writeMeta(b0[:], 0); err != nil {
		return err
	}
	return hostError(v.hf.Sync())
}

// findJournalRunLocked looks for a free run of journalBlocks blocks in group 0. It
// never grows the host file. The caller holds v.mu.
func (v *volume) findJournalRunLocked() (uint64, bool) {
	g := v.groups[0]
	off := uint32(0)
	for off < blocksPerGroup {
		off = g.blocks.firstFree(off, g.heldBlocks)
		if off >= blocksPerGroup {
			return 0, false
		}
		if n := g.blocks.freeRun(off, journalBlocks, g.heldBlocks); n >= journalBlocks {
			return uint64(off), true
		} else {
			off += max(n, 1)
		}
	}
	return 0, false
}

// createJournal allocates the journal in group 0 and adds its inode, its
// superblock, and the fields of the volume superblock to the volume. The caller
// flushes. It returns false when group 0 has no free run of the size of the
// journal. The volume then runs without a journal.
func (v *volume) createJournal(zero bool) (bool, error) {
	v.mu.Lock()
	start, ok := v.findJournalRunLocked()
	if !ok {
		v.mu.Unlock()
		return false, nil
	}
	g := v.groups[0]
	for i := uint32(0); i < journalBlocks; i++ {
		g.blocks.set(uint32(start) + i)
	}
	g.desc.freeBlocks -= journalBlocks
	v.freeBlocksTotal -= journalBlocks
	g.dirty = true
	v.mu.Unlock()

	// The blocks can hold the data of a deleted file. A stale block that looks
	// like a log block would replay as metadata, so the journal starts zeroed.
	if zero {
		zeros := make([]byte, 1<<20)
		for off := int64(0); off < journalBlocks*blockSize; off += int64(len(zeros)) {
			if err := v.writeMeta(zeros, int64(start)*blockSize+off); err != nil {
				return false, err
			}
		}
	}
	j := &journal{
		extents: []extent{{lblk: 0, n: journalBlocks, pblk: start}},
		logged:  make(map[uint64]struct{}),
		seq:     1,
	}
	j.super = journalSuper{
		blockType: jbd2BlockSuperV2,
		maxlen:    journalBlocks,
		first:     1,
		sequence:  1,
		compat:    jbd2WrittenCompat,
		incompat:  jbd2WrittenIncompat,
		uuid:      v.fsUUID(),
	}
	if err := v.writeLog(j, 0, j.super.encode()); err != nil {
		return false, err
	}
	v.j = j

	var im inodeImage
	im.ino = journalIno
	raw := im.raw[:]
	t := le.Uint32(v.sb[sbMkfsTime:])
	size := uint64(journalBlocks) * blockSize
	le.PutUint16(raw[inMode:], 0o100600)
	le.PutUint32(raw[inSizeLo:], uint32(size))
	le.PutUint32(raw[inSizeHi:], uint32(size>>32))
	le.PutUint32(raw[inAtime:], t)
	le.PutUint32(raw[inCtime:], t)
	le.PutUint32(raw[inMtime:], t)
	le.PutUint16(raw[inLinks:], 1)
	le.PutUint32(raw[inBlocksLo:], journalBlocks*(blockSize/512))
	le.PutUint32(raw[inFlags:], flagExtents)
	le.PutUint16(raw[inExtraSize:], extraIsize)
	le.PutUint32(raw[inCrtime:], t)
	// One extent covers the whole journal, so the root of the tree holds it.
	root := raw[inBlock : inBlock+iBlockSize]
	encodeExtentHeader(root, 1, rootExtents, 0)
	encodeExtent(root[extHeaderSize:], j.extents[0])
	v.journalInode = im

	// The superblock keeps a copy of the block map of the journal inode, for
	// the tools that cannot read the inode.
	v.mu.Lock()
	defer v.mu.Unlock()
	v.setSbU32(sbFeatureCompat, v.sbU32(sbFeatureCompat)|compatHasJournal)
	v.setSbU32(sbJournalInum, journalIno)
	for i := range 15 {
		v.setSbU32(sbJnlBlocks+4*i, le.Uint32(raw[inBlock+4*i:]))
	}
	v.setSbU32(sbJnlBlocks+4*15, uint32(size>>32))
	v.setSbU32(sbJnlBlocks+4*16, uint32(size))
	v.sb[sbJnlBackupType] = 1
	v.sbDirty = true
	v.pendingJournalInode = true
	for gi, g := range v.groups {
		if gi > 0 && hasSuper(uint32(gi)) {
			g.needsBackup = true
		}
	}
	return true, nil
}
