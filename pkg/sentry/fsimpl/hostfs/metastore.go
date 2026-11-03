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
// A flush appends when the journal stays small and rewrites the file
// otherwise. The rewrite, called a compaction, writes a snapshot of the table
// to a temporary file, flushes it, renames it over .gvx_meta, and flushes the
// workspace directory. It runs when the journal holds more than
// journalCompactFactor times the live records plus journalCompactSlack, when
// the file passes journalMaxBytes, when no journal exists yet, and after a torn
// tail. The snapshot holds only record pointers, so the table lock covers a
// pointer copy and never the encoding or the disk write.
//
// Earlier releases wrote the table keyed by guest path: version 3 as a
// journal with JSON bodies, and older ones as one JSON document. The reader
// loads both. The loader converts them to the current form at open time, and
// the first flush of a changed session writes the current form, which an
// earlier release cannot read.

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
	// slack replaces journalCompactSlack when positive. Tests set it.
	slack int
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

// appendFrame wraps payload in a frame at the end of buf.
func appendFrame(buf, payload []byte) []byte {
	buf = binary.LittleEndian.AppendUint32(buf, uint32(len(payload)))
	buf = binary.LittleEndian.AppendUint32(buf, crc32.Checksum(payload, castagnoli))
	return append(buf, payload...)
}

// loadMeta reads .gvx_meta into the table. A torn tail of the journal drops
// out, and the next flush replaces the file. A file of an older form, or of the
// other key kind, converts in memory and stays on disk until the next flush of
// a change.
func (w *Workspace) loadMeta() error {
	f, err := w.host.open(MetaFileName, os.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			w.journal.compact = true
			return nil
		}
		return fmt.Errorf("hostfs: open %s: %w", MetaFileName, err)
	}
	raw, err := io.ReadAll(f)
	closeErr := f.Close()
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
	w.journal.size, w.journal.ops = img.size, img.ops
	w.journal.compact = len(raw) == 0 || img.legacy || img.torn
	recs, converted := w.importImage(img)
	if converted {
		w.journal.compact = true
		w.journal.converted = true
	}
	for k, r := range recs {
		w.meta.load(k, r)
	}
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

	pending := w.meta.pending()
	if pending == 0 {
		return nil
	}
	full := w.journal.compact || w.journalFull(pending)
	ops, dirty := w.meta.takeBatch(full)

	var err error
	if full {
		err = w.compactMeta(ops)
	} else {
		err = w.appendMeta(ops)
		if errors.Is(err, errFrameTooLarge) {
			// The batch cannot stay atomic in one frame. A snapshot can.
			var more []recKey
			ops, more = w.meta.takeBatch(true)
			dirty = append(dirty, more...)
			err = w.compactMeta(ops)
		}
	}
	if err != nil {
		// The changes stay pending. The records are read again at the next
		// flush, so a later change of the same key wins.
		w.meta.restore(dirty)
		return err
	}
	w.journal.converted = false
	return nil
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
		f, err := w.host.open(MetaFileName, os.O_WRONLY, 0)
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
	return nil
}

// compactMeta replaces .gvx_meta atomically with a snapshot of ops. The
// temporary file lives in the same directory, so the final rename never
// crosses a volume. Callers hold w.flushMu.
func (w *Workspace) compactMeta(ops []metaOp) (err error) {
	f, err := w.host.open(metaTempName, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("hostfs: create %s: %w", metaTempName, err)
	}
	renamed := false
	defer func() {
		if !renamed {
			_ = w.host.unlink(metaTempName)
		}
	}()
	size, werr := writeSnapshot(f, ops)
	if werr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: write %s: %w", metaTempName, werr)
	}
	if serr := f.Sync(); serr != nil {
		_ = f.Close()
		return fmt.Errorf("hostfs: sync %s: %w", metaTempName, serr)
	}
	if cerr := f.Close(); cerr != nil {
		return fmt.Errorf("hostfs: close %s: %w", metaTempName, cerr)
	}
	if w.beforeMetaRename != nil {
		if herr := w.beforeMetaRename(); herr != nil {
			return herr
		}
	}
	_ = w.closeJournal()
	if rerr := w.host.rename(metaTempName, MetaFileName); rerr != nil {
		return fmt.Errorf("hostfs: replace %s: %w", MetaFileName, rerr)
	}
	renamed = true
	w.journal.size, w.journal.ops = size, len(ops)
	// The new file is not durable until the directory entry is. A failed
	// flush of the directory keeps the compaction pending, so the next flush
	// writes the file again instead of appending to a name that a crash can
	// still resolve to the old file.
	w.journal.compact = true
	if derr := w.host.syncDir("."); derr != nil {
		return fmt.Errorf("hostfs: sync workspace directory: %w", derr)
	}
	w.journal.compact = false
	return nil
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
