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
	"io"
	"math"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
)

const (
	chunkShift = chunkcache.ChunkShift
	chunkSize  = chunkcache.ChunkSize
)

type cacheChunk = chunkcache.Chunk

// newChunk allocates the memory of one chunk. With ChunkMemory, the chunk lives
// in a memory file, which a platform can map into a guest process by file
// descriptor. Without it, the chunk lives on the Go heap.
func (c *fileData) newChunk() (*cacheChunk, error) {
	return chunkcache.NewChunk(c.ino.fs.vol.chunkMemory())
}

// fileData is the mapped-page cache of a regular file. The cache exists only
// while a mapping exists. The engine stays the source of truth for read and
// write system calls. Those calls write through to the engine and to the
// chunks that exist. A read first writes back the dirty chunks that it
// overlaps.
type fileData struct {
	ino *inode

	// active is set while the cache exists. The read path checks it without
	// taking locks.
	active atomic.Bool

	// mapsMu protects mappings. Lock order: mapsMu, then dataMu.
	mapsMu   sync.Mutex
	mappings memmap.MappingSet

	// dataMu protects the fields below. It comes before the lock of the node.
	dataMu       sync.Mutex
	chunks       map[uint64]*cacheChunk
	writableMaps int
	wbErr        error

	mf dataMemmapFile
}

func (c *fileData) init(ino *inode) {
	c.ino = ino
	c.mf.data = c
}

// fileSize returns the size of the file in bytes.
func (c *fileData) fileSize() uint64 {
	n := c.ino.n
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.size
}

// release drops the cache when the inode dies. The write-back happens first
// when flush is set. An unlinked file has no reader left, so it skips the
// write-back.
func (c *fileData) release(flush bool) error {
	var err error
	if flush {
		err = c.syncData()
	}
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	c.dropLocked()
	return err
}

// dropLocked frees every chunk.
func (c *fileData) dropLocked() {
	for _, ch := range c.chunks {
		ch.Release()
	}
	c.chunks = nil
	c.active.Store(false)
}

func (c *fileData) takeWritebackErr() error {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	err := c.wbErr
	c.wbErr = nil
	return err
}

// syncData writes back every dirty chunk and returns any earlier write-back
// failure that no caller observed.
func (c *fileData) syncData() error {
	if !c.active.Load() {
		return c.takeWritebackErr()
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	err := errors.Join(c.wbErr, c.flushLocked(0, math.MaxUint64))
	c.wbErr = nil
	return err
}

func (c *fileData) flushRange(start, end uint64) error {
	if !c.active.Load() {
		return nil
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	return c.flushLocked(start, end)
}

// flushLocked writes the dirty chunks that overlap [start, end) to the engine.
// A chunk stays dirty while a writable mapping exists, because the guest can
// modify it at any time. A page that holds only zeros and lies in a hole
// stays a hole.
func (c *fileData) flushLocked(start, end uint64) error {
	if len(c.chunks) == 0 {
		return nil
	}
	size := c.fileSize()
	var errs []error
	wrote := false
	for idx, ch := range c.chunks {
		base := idx << chunkShift
		if !ch.Dirty || base >= end || base+chunkSize <= start {
			continue
		}
		if base >= size {
			ch.Dirty = c.writableMaps > 0
			continue
		}
		limit := min(size-base, chunkSize)
		if err := c.writeChunkLocked(ch, base, limit, &wrote); err != nil {
			errs = append(errs, err)
			continue
		}
		ch.Dirty = c.writableMaps > 0
	}
	if wrote {
		c.ino.touchMCtime()
	}
	return errors.Join(errs...)
}

// writeChunkLocked writes the first limit bytes of ch, which sits at file
// offset base, page by page.
func (c *fileData) writeChunkLocked(ch *cacheChunk, base, limit uint64, wrote *bool) error {
	n := c.ino.n
	for off := uint64(0); off < limit; off += blockSize {
		page := ch.Buf[off:min(off+blockSize, limit)]
		if isZero(page) && holeAt(n, base+off) {
			continue
		}
		if _, err := n.writeAt(page, int64(base+off)); err != nil {
			return err
		}
		*wrote = true
	}
	return nil
}

// holeAt reports whether the block at file offset off has no data.
func holeAt(n *node, off uint64) bool {
	next, ok := n.seekData(off)
	return !ok || next >= off+blockSize
}

func isZero(p []byte) bool {
	for _, b := range p {
		if b != 0 {
			return false
		}
	}
	return true
}

// writeThrough copies bytes that a system call wrote to the engine into the
// chunks that exist, so mapped pages observe them. A write that starts beyond
// the old end of the file zeroes the gap in the chunks, because mapped writes
// beyond the end can leave stale bytes there.
func (c *fileData) writeThrough(oldSize uint64, off int64, p []byte) {
	if !c.active.Load() {
		return
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if uint64(off) > oldSize {
		c.zeroLocked(oldSize, uint64(off))
	}
	for len(p) > 0 {
		idx := uint64(off) >> chunkShift
		within := int(uint64(off) & (chunkSize - 1))
		n := min(len(p), chunkSize-within)
		if ch, ok := c.chunks[idx]; ok {
			copy(ch.Buf[within:within+n], p[:n])
		}
		off += int64(n)
		p = p[n:]
	}
}

// zeroLocked clears the cached bytes in [start, end).
func (c *fileData) zeroLocked(start, end uint64) {
	if end <= start {
		return
	}
	for idx := start >> chunkShift; idx <= (end-1)>>chunkShift; idx++ {
		ch, ok := c.chunks[idx]
		if !ok {
			continue
		}
		base := idx << chunkShift
		lo := max(start, base) - base
		hi := min(end, base+chunkSize) - base
		clear(ch.Buf[lo:hi])
	}
}

// punched clears the cached bytes of a range that fallocate turned into a
// hole.
func (c *fileData) punched(off, length uint64) {
	if !c.active.Load() {
		return
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	c.zeroLocked(off, off+length)
}

// truncated adjusts the cache after the engine changed the file size from old
// to size. A growth only zeroes the stale bytes in the cached chunks. A
// shrink drops the chunks beyond the new size after it invalidated the
// mappings. A mapping translated a chunk earlier and took its own reference
// when it did, so the memory outlives the chunk. Invalidate calls into the
// memory manager, which holds its own locks while it calls Translate, so
// dataMu must be free here.
func (c *fileData) truncated(old, size uint64) {
	if !c.active.Load() {
		return
	}
	if size >= old {
		c.dataMu.Lock()
		c.zeroLocked(old, size)
		c.dataMu.Unlock()
		return
	}
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()

	c.dataMu.Lock()
	var dropped []*cacheChunk
	for idx, ch := range c.chunks {
		base := idx << chunkShift
		switch {
		case base >= size:
			dropped = append(dropped, ch)
			delete(c.chunks, idx)
		case base+chunkSize > size:
			clear(ch.Buf[size-base:])
		}
	}
	c.dataMu.Unlock()

	pgend, _ := hostarch.PageRoundUp(size)
	c.mappings.Invalidate(memmap.MappableRange{Start: pgend, End: math.MaxUint64}, memmap.InvalidateOpts{})
	for _, ch := range dropped {
		ch.Release()
	}
}

// chunkLocked returns the chunk idx, loading it from the engine when absent.
func (c *fileData) chunkLocked(idx uint64) (*cacheChunk, error) {
	if ch, ok := c.chunks[idx]; ok {
		return ch, nil
	}
	if c.chunks == nil {
		return nil, linuxerr.ENODEV
	}
	ch, err := c.newChunk()
	if err != nil {
		return nil, err
	}
	if _, err := c.ino.n.readAt(ch.Buf, int64(idx<<chunkShift)); err != nil && !errors.Is(err, io.EOF) {
		ch.Release()
		return nil, err
	}
	c.chunks[idx] = ch
	return ch, nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (c *fileData) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.mappings.AddMapping(ms, ar, offset, writable)
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if c.chunks == nil {
		c.chunks = make(map[uint64]*cacheChunk)
		c.active.Store(true)
	}
	if writable {
		c.writableMaps++
	}
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping. The interface has no
// error result, so a write-back failure waits in wbErr for fsync or close.
func (c *fileData) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.mappings.RemoveMapping(ms, ar, offset, writable)
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if writable && c.writableMaps > 0 {
		c.writableMaps--
	}
	if err := c.flushLocked(0, math.MaxUint64); err != nil {
		c.wbErr = errors.Join(c.wbErr, err)
	}
	if c.mappings.IsEmpty() {
		c.dropLocked()
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (c *fileData) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return c.AddMapping(ctx, ms, dstAR, offset, writable)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (c *fileData) InvalidateUnsavable(ctx context.Context) error {
	return toLinuxErr(c.syncData())
}

// markDirtyLocked flags the chunks that overlap [start, end) as dirty.
func (c *fileData) markDirtyLocked(start, end uint64) {
	for idx := start >> chunkShift; idx <= (end-1)>>chunkShift; idx++ {
		if ch, ok := c.chunks[idx]; ok {
			ch.Dirty = true
		}
	}
}

// Translate implements memmap.Mappable.Translate.
func (c *fileData) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if c.chunks == nil {
		return nil, &memmap.BusError{Err: linuxerr.ENODEV}
	}
	// Constrain translations to the file size, rounded up to a page, so that
	// no translation reaches pages that a truncation removes.
	pgend, _ := hostarch.PageRoundUp(c.fileSize())
	var beyondEOF bool
	if required.End > pgend {
		if required.Start >= pgend {
			return nil, &memmap.BusError{Err: io.EOF}
		}
		beyondEOF = true
		required.End = pgend
	}
	if optional.End > pgend {
		optional.End = pgend
	}
	mr := chunkcache.MaxFillRange(required, optional)
	for idx := mr.Start >> chunkShift; idx <= (mr.End-1)>>chunkShift; idx++ {
		if _, err := c.chunkLocked(idx); err != nil {
			if idx<<chunkShift < required.End {
				return nil, &memmap.BusError{Err: toLinuxErr(err)}
			}
			mr.End = idx << chunkShift
			break
		}
	}
	perms := hostarch.ReadExecute
	if at.Write {
		// From now on the guest can dirty these pages at any time.
		c.markDirtyLocked(mr.Start, mr.End)
		perms.Write = true
	}
	ts := chunkcache.Translations(c.chunks, mr, perms, &c.mf)
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// dataMemmapFile exposes the chunks of a fileData as a memmap.File. Offsets
// are file offsets.
type dataMemmapFile struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback

	data *fileData
}

// IncRef implements memmap.File.IncRef.
func (mf *dataMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {}

// DecRef implements memmap.File.DecRef.
func (mf *dataMemmapFile) DecRef(fr memmap.FileRange) {}

// MapInternal implements memmap.File.MapInternal.
func (mf *dataMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	c := mf.data
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if fr.Length() == 0 {
		return safemem.BlockSeq{}, nil
	}
	var blocks []safemem.Block
	for off := fr.Start; off < fr.End; {
		idx := off >> chunkShift
		ch, err := c.chunkLocked(idx)
		if err != nil {
			return safemem.BlockSeq{}, &memmap.BusError{Err: toLinuxErr(err)}
		}
		base := idx << chunkShift
		end := min(fr.End-base, chunkSize)
		blocks = append(blocks, safemem.BlockFromSafeSlice(ch.Buf[off-base:end]))
		off = base + end
	}
	if at.Write {
		c.markDirtyLocked(fr.Start, fr.End)
	}
	return safemem.BlockSeqFromSlice(blocks), nil
}

// DataFD implements memmap.File.DataFD.
func (mf *dataMemmapFile) DataFD(fr memmap.FileRange) (int, error) {
	return -1, linuxerr.ENODEV
}

// FD implements memmap.File.FD.
func (mf *dataMemmapFile) FD() int {
	return -1
}
