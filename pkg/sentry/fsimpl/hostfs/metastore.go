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

package hostfs

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"strings"
	"time"
)

// This file persists the .gvx_meta table. The table lives in memory in
// Workspace.meta. The file is an append-only journal of table changes with
// periodic compaction, in this layout:
//
//	header   "GVXMETA" and one version byte (4)
//	frame    length (u32, little endian), CRC-32C of the payload (u32), payload
//	payload  a sequence of operations
//	put      0x01, key, body length (uvarint), body
//	delete   0x02, key
//	key      kind byte, then the fields of the kind (see recKind)
//	body     binary fields of one record (see appendBody)
//
// One flush appends one frame, so a crash keeps the whole flush or none of it.
// A frame whose length runs past the end of the file, or whose checksum fails,
// is a torn tail: the reader ignores it and every byte after it.
//
// Multiple sandboxes that mount the same host directory coordinate access to
// .gvx_meta through a pre-opened .gvx_meta.lock file:
//   - Writers hold Workspace.flushMu and an exclusive OS advisory lock while
//     checking on-disk state, merging any peer appends or snapshots, and
//     appending or compacting via a unique .gvx_meta.tmp.<hex> staging file.
//   - .gvx_meta.lock carries a 16-byte little-endian (commitSeq, compactSeq)
//     header at offset 0 so peer workspaces detect external commits with one
//     lock-free 16-byte ReadAt and acquire a shared OS lock only when changes
//     actually occurred.

const (
	// journalMagic opens every journal file. The oldest JSON form opens with
	// a brace, so the first byte tells the two forms apart.
	journalMagic = "GVXMETA"
	// journalVersion is the version byte that follows journalMagic.
	journalVersion = 4
	journalHeader  = len(journalMagic) + 1

	frameHeader = 8
	// maxFrameBytes bounds the payload of one frame. A larger flush
	// compacts instead, because one frame keeps a flush atomic.
	maxFrameBytes = 32 << 20
	// snapshotFrameOps is the number of records in one frame of a snapshot.
	snapshotFrameOps = 2048

	// journalCompactFactor and journalCompactSlack bound the journal: it
	// compacts when its operations exceed factor times the live records
	// plus slack. A table of N records then occupies about three times the
	// snapshot at most.
	journalCompactFactor = 2
	journalCompactSlack  = 1024
	// journalMaxBytes compacts a journal that grew large through big records.
	journalMaxBytes = 64 << 20

	metaLockHeaderBytes = 16
)

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)

	// errMetaCorrupt reports a checksummed frame that holds malformed data.
	errMetaCorrupt = errors.New("hostfs: corrupt .gvx_meta record")
)

// metaJournal is the state of the journal file. Workspace.flushMu protects it
// after openWorkspace returns.
type metaJournal struct {
	// f is the open journal, or nil. It is opened for writing at the first
	// append.
	f *os.File
	// size is the length of the valid part of the file.
	size int64
	// ops is the number of operations in the file.
	ops int
	// compact marks a table on disk that the next flush must replace: an
	// older form, a torn tail, or a failed append.
	compact bool
	// converted marks a table that the loader built from an older form or
	// from the other key kind. The file keeps that form until the first
	// flush of a change, so a session without changes leaves it untouched.
	converted bool
	// hadFault records that loadMeta observed a torn tail or an earlier flush
	// failed mid-write, so the next successful compaction sweeps stale
	// .gvx_meta.tmp* leftovers while holding the exclusive lock.
	hadFault bool
	// slack replaces journalCompactSlack when positive. Tests set it.
	slack int
	// tempName is the per-workspace staging file name (.gvx_meta.tmp.<hex>).
	tempName string

	// Last-synced on-disk identity of .gvx_meta and .gvx_meta.lock sequences.
	hasDiskFile    bool
	diskFID        fileKey
	diskFIDOK      bool
	diskHostID     hostID
	diskMtime      int64
	lockCommitSeq  uint64
	lockCompactSeq uint64
}

func newMetaTempName() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return fmt.Sprintf("%s%x", metaTempPrefix, b[:])
}

// metaImage is the content of a .gvx_meta file.
type metaImage struct {
	// recs holds the records of the current form.
	recs map[recKey]*rec
	// paths holds the records of an older form, by guest path.
	paths map[string]POSIXAttr
	// legacy reports that the file has an older form.
	legacy bool
	// size is the length of the valid part of a journal.
	size int64
	// ops is the number of operations in a journal.
	ops int
	// torn reports bytes after the last valid frame.
	torn bool
}

// parseMeta decodes the content of a .gvx_meta file.
func parseMeta(raw []byte) (metaImage, error) {
	if len(raw) == 0 {
		return metaImage{recs: map[recKey]*rec{}}, nil
	}
	if raw[0] == '{' {
		return parseLegacyJSON(raw)
	}
	return parseJournal(raw)
}

func parseJournal(raw []byte) (metaImage, error) {
	if len(raw) < journalHeader && strings.HasPrefix(journalMagic+string(rune(journalVersion)), string(raw)) {
		// A prefix of the header holds no record. The next flush replaces it.
		return metaImage{recs: map[recKey]*rec{}, torn: true}, nil
	}
	if len(raw) < journalHeader || string(raw[:len(journalMagic)]) != journalMagic {
		return metaImage{}, fmt.Errorf("hostfs: %s has an unknown format", MetaFileName)
	}
	switch v := raw[len(journalMagic)]; v {
	case journalVersionV3:
		return parseJournalV3(raw)
	case journalVersion:
	default:
		return metaImage{}, fmt.Errorf("hostfs: %s has unsupported version %d", MetaFileName, v)
	}
	img := metaImage{recs: make(map[recKey]*rec), size: int64(journalHeader)}
	off := journalHeader
	for off < len(raw) {
		payload, ok := nextFrame(raw[off:])
		if !ok {
			img.torn = true
			break
		}
		n, err := applyFrame(payload, img.recs)
		if err != nil {
			return metaImage{}, err
		}
		img.ops += n
		off += frameHeader + len(payload)
		img.size = int64(off)
	}
	return img, nil
}

// applyFrame applies the operations of one frame to recs. It returns the
// number of operations.
func applyFrame(payload []byte, recs map[recKey]*rec) (int, error) {
	ops := 0
	for len(payload) > 0 {
		op, rest, ok := readOp(payload)
		if !ok {
			return ops, errMetaCorrupt
		}
		payload = rest
		if op.r == nil {
			delete(recs, op.key)
		} else {
			recs[op.key] = op.r
		}
		ops++
	}
	return ops, nil
}

// decodeFrameOps decodes all operations in one verified frame payload.
func decodeFrameOps(payload []byte) ([]metaOp, error) {
	var ops []metaOp
	for len(payload) > 0 {
		op, rest, ok := readOp(payload)
		if !ok {
			return nil, errMetaCorrupt
		}
		payload = rest
		ops = append(ops, op)
	}
	return ops, nil
}

// parseJournalTail decodes valid appended frames starting after journalHeader.
func parseJournalTail(tail []byte) (ops []metaOp, consumed int64, torn bool, err error) {
	off := 0
	for off < len(tail) {
		payload, ok := nextFrame(tail[off:])
		if !ok {
			torn = true
			break
		}
		frameOps, ferr := decodeFrameOps(payload)
		if ferr != nil {
			return nil, 0, false, ferr
		}
		ops = append(ops, frameOps...)
		off += frameHeader + len(payload)
	}
	return ops, int64(off), torn, nil
}

// appendFrame wraps payload in a frame at the end of buf.
func appendFrame(buf, payload []byte) []byte {
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(payload)))
	buf = binary.LittleEndian.AppendUint32(buf, crc32.Checksum(payload, castagnoli))
	return append(buf, payload...)
}

func readMetaLockSeqs(f *os.File) (commitSeq, compactSeq uint64, ok bool) {
	var buf [metaLockHeaderBytes]byte
	n, err := f.ReadAt(buf[:], 0)
	if n == 0 && (err == nil || errors.Is(err, io.EOF)) {
		return 0, 0, true
	}
	if n < metaLockHeaderBytes {
		return 0, 0, false
	}
	return binary.LittleEndian.Uint64(buf[:8]), binary.LittleEndian.Uint64(buf[8:16]), true
}

func writeMetaLockSeqs(f *os.File, commitSeq, compactSeq uint64) {
	var buf [metaLockHeaderBytes]byte
	binary.LittleEndian.PutUint64(buf[:8], commitSeq)
	binary.LittleEndian.PutUint64(buf[8:16], compactSeq)
	_, _ = f.WriteAt(buf[:], 0)
}

// openMetaLock pre-opens .gvx_meta.lock inside the metadata directory before
// hostlockdown.Apply() seals unbound opens. Read-only workspaces open an
// existing lock file O_RDONLY without creating one when absent.
func (w *Workspace) openMetaLock() error {
	if w.single != "" {
		return nil
	}
	metaDir := w.metaLockHost.rootDir()
	if w.readOnly {
		f, err := w.metaLockHost.openChildAt(metaDir, MetaLockFileName, os.O_RDONLY, 0)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("hostfs: open %s: %w", MetaLockFileName, err)
		}
		w.metaLock.Store(f)
		return nil
	}
	var (
		f   *os.File
		err error
	)
	for attempt := range 4 {
		f, err = w.metaLockHost.openChildAt(metaDir, MetaLockFileName, os.O_RDWR|os.O_CREATE, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, fs.ErrNotExist) || attempt == 3 {
			return fmt.Errorf("hostfs: open %s: %w", MetaLockFileName, err)
		}
		time.Sleep(time.Millisecond)
	}
	w.metaLock.Store(f)
	return nil
}

// tryOpenMetaLockReadOnlyLocked attaches .gvx_meta.lock on a read-only
// workspace once a writable peer creates it. Callers hold w.flushMu.
func (w *Workspace) tryOpenMetaLockReadOnlyLocked() *os.File {
	if lf := w.metaLock.Load(); lf != nil {
		return lf
	}
	if w.single != "" || w.closingAtomic.Load() {
		return nil
	}
	f, err := w.metaLockHost.openChildAt(w.metaLockHost.rootDir(), MetaLockFileName, os.O_RDONLY, 0)
	if err != nil {
		return nil
	}
	w.metaLock.Store(f)
	return f
}

func (w *Workspace) closeMetaLock() error {
	f := w.metaLock.Swap(nil)
	if f == nil {
		return nil
	}
	return f.Close()
}

func (w *Workspace) recordMetaDiskState(info hostInfo) {
	j := &w.journal
	j.hasDiskFile = true
	j.diskHostID = info.id
	j.diskMtime = info.mtime.UnixNano()
	if hasIdentity(info) {
		j.diskFID = w.storedMetaID(info.fid)
		j.diskFIDOK = true
	} else {
		j.diskFID = fileKey{}
		j.diskFIDOK = false
	}
}

func (w *Workspace) clearMetaDiskState() {
	j := &w.journal
	j.hasDiskFile = false
	j.diskFID = fileKey{}
	j.diskFIDOK = false
	j.diskHostID = hostID{}
	j.diskMtime = 0
}

func (w *Workspace) sameMetaFile(info hostInfo, lockUnchanged bool) bool {
	j := &w.journal
	if !j.hasDiskFile {
		return false
	}
	if w.metaStableIDs && j.diskFIDOK && hasIdentity(info) {
		return w.storedMetaID(info.fid) == j.diskFID && info.id == j.diskHostID
	}
	// Fallback when the volume lacks stable file identities: require matching
	// lock sequence state, host (dev, ino), and modification timestamp.
	return lockUnchanged && info.id == j.diskHostID && info.mtime.UnixNano() == j.diskMtime
}

func (w *Workspace) updateLockSeqState(commitSeq, compactSeq uint64) {
	w.journal.lockCommitSeq = commitSeq
	w.journal.lockCompactSeq = compactSeq
	w.lastLockCommit.Store(commitSeq)
	w.lastLockCompact.Store(compactSeq)
}

// loadMeta reads .gvx_meta into the table. A torn tail of the journal drops
// out, and the next flush replaces the file. A file of an older form, or of the
// other key kind, converts in memory and stays on disk until the next flush of
// a change.
func (w *Workspace) loadMeta() error {
	if lf := w.metaLock.Load(); lf != nil {
		if err := lockMetaShared(lf); err != nil {
			return fmt.Errorf("hostfs: lock %s: %w", MetaLockFileName, err)
		}
		defer func() { _ = unlockMeta(lf) }()
		if commitSeq, compactSeq, ok := readMetaLockSeqs(lf); ok {
			w.updateLockSeqState(commitSeq, compactSeq)
		}
	}
	f, err := w.metaHost.open(MetaFileName, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			w.journal.compact = true
			w.clearMetaDiskState()
			return nil
		}
		return fmt.Errorf("hostfs: open %s: %w", MetaFileName, err)
	}
	fInfo, statErr := w.metaHost.fstat(f)
	raw, err := io.ReadAll(f)
	closeErr := f.Close()
	if statErr != nil {
		return fmt.Errorf("hostfs: stat %s: %w", MetaFileName, statErr)
	}
	if err != nil {
		return fmt.Errorf("hostfs: read %s: %w", MetaFileName, err)
	}
	if closeErr != nil {
		return fmt.Errorf("hostfs: close %s: %w", MetaFileName, closeErr)
	}
	img, err := parseMeta(raw)
	if err != nil {
		return err
	}
	w.recordMetaDiskState(fInfo)
	w.journal.size, w.journal.ops = img.size, img.ops
	w.journal.compact = len(raw) == 0 || img.legacy || img.torn
	w.journal.hadFault = img.torn
	recs, converted := w.importImage(img)
	if converted {
		w.journal.compact = true
		w.journal.converted = true
	}
	for k, r := range recs {
		w.meta.load(k, r)
	}
	w.lastMetaCheckNano.Store(w.nowNano())
	return nil
}

// flushLoop coalesces bursts of mutations into one table write. It runs until
// Close stops it. A failed write stays pending: the next mutation, Sync, or
// Close retries and reports the error.
func (w *Workspace) flushLoop() {
	defer close(w.done)
	for {
		select {
		case <-w.stop:
			return
		case <-w.kick:
		}
		timer := time.NewTimer(w.coalesce)
		select {
		case <-w.stop:
			timer.Stop()
			return
		case <-timer.C:
		}
		_ = w.flushMeta()
	}
}

// flushMeta makes the table changes since the last flush durable. It does
// nothing when no record changed. Callers wait for any flush in progress, so a
// Sync that returns covers every mutation that completed before the call.
func (w *Workspace) flushMeta() error {
	if w.readOnly || w.single != "" {
		// A single-file workspace owns no directory, so it keeps its metadata
		// in memory and never writes .gvx_meta.
		return nil
	}
	w.flushMu.Lock()
	defer w.flushMu.Unlock()

	if w.meta.pending() == 0 {
		return nil
	}

	lf := w.metaLock.Load()
	if lf != nil {
		if err := lockMetaExclusive(lf); err != nil {
			return fmt.Errorf("hostfs: lock %s: %w", MetaLockFileName, err)
		}
		defer func() { _ = unlockMeta(lf) }()
	}

	forceCompact, diskCommit, diskCompact, syncErr := w.syncMetaLocked(lf, true)
	if syncErr != nil {
		return syncErr
	}

	pending := w.meta.pending()
	if pending == 0 {
		return nil
	}
	full := forceCompact || w.journal.compact || w.journalFull(pending)
	ops, dirty := w.meta.takeBatch(full)

	didCompact := false
	var err error
	if full {
		didCompact = true
		err = w.compactMeta(ops)
	} else {
		err = w.appendMeta(ops)
		if errors.Is(err, errFrameTooLarge) {
			// The batch cannot stay atomic in one frame. A snapshot can.
			var more []recKey
			ops, more = w.meta.takeBatch(true)
			dirty = append(dirty, more...)
			didCompact = true
			err = w.compactMeta(ops)
		}
	}
	if err != nil {
		// The changes stay pending. The records are read again at the next
		// flush, so a later change of the same key wins.
		w.journal.hadFault = true
		w.meta.restore(dirty)
		return err
	}
	w.journal.converted = false
	if lf != nil {
		nextCommit := max(w.journal.lockCommitSeq, diskCommit) + 1
		nextCompact := max(w.journal.lockCompactSeq, diskCompact)
		if didCompact {
			nextCompact++
		}
		w.updateLockSeqState(nextCommit, nextCompact)
		writeMetaLockSeqs(lf, nextCommit, nextCompact)
	}
	return nil
}

// syncMetaLocked brings w.meta and w.journal up to date with any .gvx_meta
// commits made by peer Workspaces. Callers hold w.flushMu and an OS lock on lf
// (exclusive when forWrite is true, shared when false).
func (w *Workspace) syncMetaLocked(lf *os.File, forWrite bool) (forceCompact bool, diskCommit, diskCompact uint64, err error) {
	j := &w.journal
	hasLockSeq := false
	if lf != nil {
		diskCommit, diskCompact, hasLockSeq = readMetaLockSeqs(lf)
	}

	diskInfo, statErr := w.metaHost.lstatAt(w.metaHost.rootDir(), MetaFileName)
	if statErr != nil {
		if isNotExist(statErr) {
			if j.hasDiskFile {
				_ = w.closeJournal()
				w.clearMetaDiskState()
				j.size, j.ops = 0, 0
				j.compact = true
				if w.meta.replaceClean(nil) {
					w.metaEpoch.Add(1)
				}
				return true, diskCommit, diskCompact, nil
			}
			return false, diskCommit, diskCompact, nil
		}
		return false, diskCommit, diskCompact, fmt.Errorf("hostfs: stat %s: %w", MetaFileName, statErr)
	}

	lockUnchanged := hasLockSeq && diskCommit == j.lockCommitSeq && diskCompact == j.lockCompactSeq
	sameFile := w.sameMetaFile(diskInfo, lockUnchanged)
	compactUnchanged := !hasLockSeq || diskCompact == j.lockCompactSeq

	// Fast path: identical file identity and byte length since our last sync.
	if sameFile && compactUnchanged && diskInfo.size == j.size {
		return false, diskCommit, diskCompact, nil
	}

	// Incremental peer append path: same .gvx_meta inode grew via appended frames.
	if sameFile && compactUnchanged && diskInfo.size > j.size && j.size >= int64(journalHeader) && (!forWrite || !j.compact) {
		torn, tailErr := w.applyAppendedTailLocked(diskInfo)
		if tailErr == nil {
			if torn && forWrite {
				j.compact = true
				j.hadFault = true
				return true, diskCommit, diskCompact, nil
			}
			return false, diskCommit, diskCompact, nil
		}
		// If the file converted or could not be parsed incrementally, fall
		// back to full snapshot reload below.
	}

	// Full snapshot reload path: .gvx_meta was created, compacted & renamed,
	// truncated, or resides on a volume without stable file identities.
	if err := w.reloadMetaFromDiskLocked(forWrite); err != nil {
		return false, diskCommit, diskCompact, err
	}
	return forWrite, diskCommit, diskCompact, nil
}

func (w *Workspace) applyAppendedTailLocked(diskInfo hostInfo) (torn bool, err error) {
	j := &w.journal
	delta := diskInfo.size - j.size
	if delta <= 0 {
		return false, nil
	}
	f, err := w.metaHost.openChildAt(w.metaHost.rootDir(), MetaFileName, os.O_RDONLY, 0)
	if err != nil {
		return false, err
	}
	tail := make([]byte, delta)
	readOff := j.size
	filled := 0
	for filled < len(tail) {
		n, rerr := f.ReadAt(tail[filled:], readOff+int64(filled))
		filled += n
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			_ = f.Close()
			return false, rerr
		}
		if n == 0 {
			break
		}
	}
	closeErr := f.Close()
	if closeErr != nil {
		return false, closeErr
	}
	tail = tail[:filled]
	ops, consumed, torn, err := parseJournalTail(tail)
	if err != nil {
		return false, err
	}
	if w.meta.applyExternal(ops) {
		w.metaEpoch.Add(1)
	}
	j.size += consumed
	j.ops += len(ops)
	w.recordMetaDiskState(diskInfo)
	return torn, nil
}

func (w *Workspace) reloadMetaFromDiskLocked(forWrite bool) error {
	j := &w.journal
	_ = w.closeJournal()
	f, err := w.metaHost.openChildAt(w.metaHost.rootDir(), MetaFileName, os.O_RDONLY, 0)
	if err != nil {
		if isNotExist(err) {
			w.clearMetaDiskState()
			j.size, j.ops = 0, 0
			j.compact = true
			if w.meta.replaceClean(nil) {
				w.metaEpoch.Add(1)
			}
			return nil
		}
		return fmt.Errorf("hostfs: open %s: %w", MetaFileName, err)
	}
	fInfo, statErr := w.metaHost.fstat(f)
	raw, readErr := io.ReadAll(f)
	closeErr := f.Close()
	if statErr != nil {
		return fmt.Errorf("hostfs: stat %s: %w", MetaFileName, statErr)
	}
	if readErr != nil {
		return fmt.Errorf("hostfs: read %s: %w", MetaFileName, readErr)
	}
	if closeErr != nil {
		return fmt.Errorf("hostfs: close %s: %w", MetaFileName, closeErr)
	}
	img, err := parseMeta(raw)
	if err != nil {
		return err
	}
	recs, converted := w.importImage(img)
	if w.meta.replaceClean(recs) {
		w.metaEpoch.Add(1)
	}
	w.recordMetaDiskState(fInfo)
	j.size, j.ops = img.size, img.ops
	j.compact = len(raw) == 0 || img.legacy || img.torn || converted || forWrite
	if img.torn {
		j.hadFault = true
	}
	return nil
}

// maybeRefreshMeta checks whether another sandbox committed changes to
// .gvx_meta and merges non-dirty records into w.meta. When .gvx_meta.lock is
// open, the unchanged fast path reads the 16-byte sequence header without
// taking w.flushMu or making any hostBackend call.
func (w *Workspace) maybeRefreshMeta(force bool) {
	if w == nil || w.single != "" || w.closingAtomic.Load() {
		return
	}
	if lf := w.metaLock.Load(); lf != nil {
		commitSeq, compactSeq, ok := readMetaLockSeqs(lf)
		if ok && commitSeq == w.lastLockCommit.Load() && compactSeq == w.lastLockCompact.Load() {
			return
		}
	} else if !force {
		now := w.nowNano()
		if now-w.lastMetaCheckNano.Load() < int64(cacheTTL) {
			return
		}
	}
	w.refreshMetaSlow()
}

func (w *Workspace) refreshMetaSlow() {
	if w.closingAtomic.Load() {
		return
	}
	w.flushMu.Lock()
	defer w.flushMu.Unlock()
	if w.closingAtomic.Load() {
		return
	}
	w.lastMetaCheckNano.Store(w.nowNano())

	lf := w.metaLock.Load()
	if lf == nil && w.readOnly {
		lf = w.tryOpenMetaLockReadOnlyLocked()
	}
	if lf != nil {
		if commitSeq, compactSeq, ok := readMetaLockSeqs(lf); ok {
			if commitSeq == w.journal.lockCommitSeq && compactSeq == w.journal.lockCompactSeq {
				w.updateLockSeqState(commitSeq, compactSeq)
				return
			}
		}
		if err := lockMetaShared(lf); err != nil {
			return
		}
		defer func() { _ = unlockMeta(lf) }()
	}

	_, diskCommit, diskCompact, err := w.syncMetaLocked(lf, false)
	if err == nil && lf != nil {
		w.updateLockSeqState(diskCommit, diskCompact)
	}
}

// journalFull reports whether the journal, with n more operations, passes its
// bound. Callers hold w.flushMu.
func (w *Workspace) journalFull(n int) bool {
	slack := journalCompactSlack
	if w.journal.slack > 0 {
		slack = w.journal.slack
	}
	return w.journal.ops+n > journalCompactFactor*w.meta.size()+slack || w.journal.size > journalMaxBytes
}

var errFrameTooLarge = errors.New("hostfs: metadata batch exceeds one frame")

// appendMeta writes ops as one frame at the end of the journal and flushes the
// file. Callers hold w.flushMu.
func (w *Workspace) appendMeta(ops []metaOp) error {
	var payload []byte
	for _, op := range ops {
		payload = appendOp(payload, op)
		if len(payload) > maxFrameBytes {
			return errFrameTooLarge
		}
	}
	frame := appendFrame(make([]byte, 0, frameHeader+len(payload)), payload)
	j := &w.journal
	if j.f == nil {
		f, err := w.metaHost.openChildAt(w.metaHost.rootDir(), MetaFileName, os.O_WRONLY, 0)
		if err != nil {
			j.compact = true
			return fmt.Errorf("hostfs: open %s for append: %w", MetaFileName, err)
		}
		j.f = f
	}
	var fault error
	if w.appendFault != nil {
		var n int
		if n, fault = w.appendFault(frame); fault != nil {
			frame = frame[:n]
		}
	}
	if _, err := j.f.WriteAt(frame, j.size); err != nil || fault != nil {
		err = errors.Join(err, fault)
		// The file can hold a partial frame now. A snapshot replaces it.
		j.compact = true
		return fmt.Errorf("hostfs: append to %s: %w", MetaFileName, err)
	}
	if err := j.f.Sync(); err != nil {
		j.compact = true
		return fmt.Errorf("hostfs: sync %s: %w", MetaFileName, err)
	}
	j.size += int64(len(frame))
	j.ops += len(ops)
	if info, statErr := w.metaHost.fstat(j.f); statErr == nil {
		w.recordMetaDiskState(info)
	}
	return nil
}

// compactMeta replaces .gvx_meta atomically with a snapshot of ops. The
// temporary file uses a per-workspace name in the same directory so concurrent
// sandboxes never collide and the final rename never crosses a volume. Callers
// hold w.flushMu and the exclusive OS lock on .gvx_meta.lock.
func (w *Workspace) compactMeta(ops []metaOp) (err error) {
	tempName := w.journal.tempName
	if tempName == "" {
		tempName = metaTempName
	}
	metaDir := w.metaHost.rootDir()
	f, err := w.metaHost.openChildAt(metaDir, tempName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("hostfs: create %s: %w", tempName, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = w.metaHost.unlinkAt(metaDir, tempName)
		}
	}()
	size, werr := writeSnapshot(f, ops)
	if werr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: write %s: %w", tempName, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: sync %s: %w", tempName, serr)
	}
	fInfo, statErr := w.metaHost.fstat(f)
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("hostfs: close %s: %w", tempName, cerr)
	}
	if statErr != nil {
		return fmt.Errorf("hostfs: stat %s: %w", tempName, statErr)
	}
	if w.beforeMetaRename != nil {
		if herr := w.beforeMetaRename(); herr != nil {
			return herr
		}
	}
	_ = w.closeJournal()
	if rerr := w.metaHost.renameAt(metaDir, tempName, metaDir, MetaFileName); rerr != nil {
		return fmt.Errorf("hostfs: replace %s: %w", MetaFileName, rerr)
	}
	renamed = true
	fInfo.size = size
	w.recordMetaDiskState(fInfo)
	w.journal.size, w.journal.ops = size, len(ops)
	if w.journal.hadFault {
		w.sweepStaleMetaTempsLocked()
		w.journal.hadFault = false
	}
	// The new file is not durable until the directory entry is. A failed
	// flush of the directory keeps the compaction pending, so the next flush
	// writes the file again instead of appending to a name that a crash can
	// still resolve to the old file.
	w.journal.compact = true
	if derr := w.metaHost.syncDir("."); derr != nil {
		return fmt.Errorf("hostfs: sync metadata directory: %w", derr)
	}
	w.journal.compact = false
	return nil
}

// sweepStaleMetaTempsLocked unlinks orphaned .gvx_meta.tmp or
// .gvx_meta.tmp.<hex> files left behind in the metadata directory by a crashed
// process, plus any crashed probe temporaries when MetaDir is external. Callers
// hold the exclusive OS lock on .gvx_meta.lock, so no live peer can be
// mid-compaction.
func (w *Workspace) sweepStaleMetaTempsLocked() {
	metaDir := w.metaHost.rootDir()
	entries, err := w.metaHost.readDirAt(metaDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.kind == hostKindRegular && (isMetaTempName(e.name) || (w.externalMeta && isEphemeralName(e.name))) {
			_ = w.metaHost.unlinkAt(metaDir, e.name)
		}
	}
}

// writeSnapshot writes the journal header and the records of ops to f. It
// returns the length of the file.
func writeSnapshot(f *os.File, ops []metaOp) (int64, error) {
	buf := make([]byte, 0, 1<<20)
	buf = append(buf, journalMagic...)
	buf = append(buf, journalVersion)
	size := int64(0)
	var payload []byte
	flush := func() error {
		if len(payload) == 0 {
			return nil
		}
		buf = appendFrame(buf, payload)
		payload = payload[:0]
		if len(buf) < 1<<20 {
			return nil
		}
		n, err := f.Write(buf)
		size += int64(n)
		buf = buf[:0]
		return err
	}
	for i, op := range ops {
		payload = appendOp(payload, op)
		if (i+1)%snapshotFrameOps == 0 || len(payload) > maxFrameBytes/2 {
			if err := flush(); err != nil {
				return size, err
			}
		}
	}
	if err := flush(); err != nil {
		return size, err
	}
	n, err := f.Write(buf)
	return size + int64(n), err
}

// closeJournal closes the append handle. Callers hold w.flushMu or own the
// Workspace exclusively.
func (w *Workspace) closeJournal() error {
	f := w.journal.f
	w.journal.f = nil
	if f == nil {
		return nil
	}
	return f.Close()
}
