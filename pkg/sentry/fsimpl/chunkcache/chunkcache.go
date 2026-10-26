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

// Package chunkcache provides the shared 64 KiB page-chunk cache and VFS2
// helpers used by hostfs and ext4lite.
package chunkcache

import (
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/atomicbitops"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/kernel/pipe"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	// ChunkShift is the log2 of the cache granule. The granule is a multiple of
	// every host page size and of the 4 KiB guest page size.
	ChunkShift = 16

	// ChunkSize is the byte size of one cached chunk.
	ChunkSize = 1 << ChunkShift

	// ChunkAlign is the alignment of a chunk in host memory.
	ChunkAlign = 16 << 10

	// MaxReadahead bounds how much of a mapping one Translate call loads.
	MaxReadahead = 64 << 10
)

// ChunkMemory supplies the memory for the chunks of mapped files. A platform
// that runs guest code in another process maps guest pages by file descriptor,
// so it cannot use Go heap memory.
type ChunkMemory interface {
	memmap.File

	// AllocateChunk returns a zeroed range of length bytes. The caller holds
	// one reference, which it drops with DecRef.
	AllocateChunk(length uint64) (memmap.FileRange, error)
}

type chunkMemoryBox struct {
	m ChunkMemory
}

// ChunkMemoryHolder stores a ChunkMemory reference atomically.
type ChunkMemoryHolder struct {
	ptr atomic.Pointer[chunkMemoryBox]
}

// Set stores mem as the active ChunkMemory.
func (h *ChunkMemoryHolder) Set(mem ChunkMemory) {
	h.ptr.Store(&chunkMemoryBox{m: mem})
}

// Get returns the active ChunkMemory, or nil.
func (h *ChunkMemoryHolder) Get() ChunkMemory {
	if b := h.ptr.Load(); b != nil {
		return b.m
	}
	return nil
}

// Chunk holds one 64 KiB cached slice of a regular file.
type Chunk struct {
	Buf   []byte
	Dirty bool

	// Mem and FR locate the chunk in shared memory. They are zero when Buf is
	// Go heap memory.
	Mem ChunkMemory
	FR  memmap.FileRange
}

// Release returns shared memory to its owner. The memory stays valid for the
// mappings that still hold a reference.
func (ch *Chunk) Release() {
	if ch.Mem != nil {
		ch.Mem.DecRef(ch.FR)
		ch.Mem = nil
	}
}

// NewChunk allocates the memory of one chunk. With ChunkMemory, the chunk
// lives in a memory file, which a platform can map into a guest process by
// file descriptor. Without it, the chunk lives on the Go heap.
func NewChunk(mem ChunkMemory) (*Chunk, error) {
	if mem == nil {
		return &Chunk{Buf: newChunkBuf()}, nil
	}
	fr, err := mem.AllocateChunk(ChunkSize)
	if err != nil {
		return nil, err
	}
	bs, err := mem.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		mem.DecRef(fr)
		return nil, err
	}
	if bs.NumBlocks() != 1 || bs.NumBytes() != ChunkSize {
		mem.DecRef(fr)
		return nil, fmt.Errorf("chunkcache: the chunk memory maps %d blocks of %d bytes, want one block of %d", bs.NumBlocks(), bs.NumBytes(), ChunkSize)
	}
	return &Chunk{Buf: bs.Head().ToSlice(), Mem: mem, FR: fr}, nil
}

// newChunkBuf allocates one chunk aligned to ChunkAlign. Go heap memory never
// moves, so slices handed to platforms stay valid for the chunk lifetime.
func newChunkBuf() []byte {
	raw := make([]byte, ChunkSize+ChunkAlign)
	skip := (ChunkAlign - int(uintptr(unsafe.Pointer(&raw[0]))%ChunkAlign)) % ChunkAlign
	return raw[skip : skip+ChunkSize : skip+ChunkSize]
}

// MaxFillRange bounds optional readahead to MaxReadahead while covering required.
func MaxFillRange(required, optional memmap.MappableRange) memmap.MappableRange {
	if required.Length() >= MaxReadahead {
		return required
	}
	if optional.Length() <= MaxReadahead {
		return optional
	}
	optional.Start = required.Start
	if optional.Length() <= MaxReadahead {
		return optional
	}
	optional.End = optional.Start + MaxReadahead
	return optional
}

// Translations describes where the pages of mr live. Heap chunks form one
// translation through heapFile. Chunks in shared memory need one translation
// each because the allocator places chunks apart. Every chunk in mr must exist
// before calling Translations.
func Translations(chunks map[uint64]*Chunk, mr memmap.MappableRange, perms hostarch.AccessType, heapFile memmap.File) []memmap.Translation {
	if chunks[mr.Start>>ChunkShift].Mem == nil {
		return []memmap.Translation{{
			Source: mr,
			File:   heapFile,
			Offset: mr.Start,
			Perms:  perms,
		}}
	}
	var ts []memmap.Translation
	for off := mr.Start; off < mr.End; {
		idx := off >> ChunkShift
		ch := chunks[idx]
		base := idx << ChunkShift
		end := min(mr.End, base+ChunkSize)
		ts = append(ts, memmap.Translation{
			Source: memmap.MappableRange{Start: off, End: end},
			File:   ch.Mem,
			Offset: ch.FR.Start + (off - base),
			Perms:  perms,
		})
		off = end
	}
	return ts
}

// ReadAtToBlocks reads from readAt at off into dsts and returns the number of
// bytes read, the updated offset, and any error.
func ReadAtToBlocks(dsts safemem.BlockSeq, off int64, readAt func(p []byte, off int64) (int, error)) (uint64, int64, error) {
	var done uint64
	var scratch []byte
	for ; !dsts.IsEmpty(); dsts = dsts.Tail() {
		dst := dsts.Head()
		var n int
		var err error
		if !dst.NeedSafecopy() {
			n, err = readAt(dst.ToSlice(), off)
		} else {
			if len(scratch) < dst.Len() {
				scratch = make([]byte, dst.Len())
			}
			var rn int
			rn, err = readAt(scratch[:dst.Len()], off)
			var werr error
			n, werr = safemem.Copy(dst, safemem.BlockFromSafeSlice(scratch[:rn]))
			if werr != nil {
				err = werr
			}
		}
		off += int64(n)
		done += uint64(n)
		if n != dst.Len() {
			if err == nil && done > 0 {
				err = io.EOF
			}
			return done, off, err
		}
	}
	return done, off, nil
}

// SeekRegular computes the new file offset for a regular file description.
func SeekRegular(curOff, offset int64, whence int32, fileSize func() (int64, error)) (int64, error) {
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = curOff + offset
	case linux.SEEK_END, linux.SEEK_DATA, linux.SEEK_HOLE:
		size, err := fileSize()
		if err != nil {
			return 0, err
		}
		switch whence {
		case linux.SEEK_END:
			newOff = size + offset
		case linux.SEEK_DATA:
			if offset < 0 || offset >= size {
				return 0, linuxerr.ENXIO
			}
			newOff = offset
		default:
			if offset < 0 || offset >= size {
				return 0, linuxerr.ENXIO
			}
			newOff = size
		}
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	return newOff, nil
}

// DirCursor tracks the snapshot and offset of an open directory description.
type DirCursor struct {
	mu       sync.Mutex
	snapshot []vfs.Dirent
	loaded   bool
	off      int64
}

// IterDirents iterates over the directory snapshot, calling load on the first
// read or after a rewind to offset zero.
func (c *DirCursor) IterDirents(cb vfs.IterDirentsCallback, load func() ([]vfs.Dirent, error)) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.loaded {
		snap, err := load()
		if err != nil {
			return err
		}
		c.snapshot = snap
		c.loaded = true
	}
	for c.off < int64(len(c.snapshot)) {
		if err := cb.Handle(c.snapshot[c.off]); err != nil {
			return err
		}
		c.off++
	}
	return nil
}

// SeekDir updates the directory offset and clears the cached snapshot when
// rewound to offset zero.
func (c *DirCursor) SeekDir(offset int64, whence int32) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = c.off + offset
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	if newOff == 0 {
		c.loaded = false
		c.snapshot = nil
	}
	c.off = newOff
	return newOff, nil
}

// TryIncRef increments refs when the current count is positive.
func TryIncRef(refs *atomicbitops.Int64) bool {
	for {
		r := refs.Load()
		if r <= 0 {
			return false
		}
		if refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

// CheckXattrPrefix accepts the user, trusted, and security extended attribute
// namespaces and rejects all other prefixes with EOPNOTSUPP.
func CheckXattrPrefix(name string) error {
	for _, prefix := range []string{linux.XATTR_USER_PREFIX, linux.XATTR_TRUSTED_PREFIX, linux.XATTR_SECURITY_PREFIX} {
		if strings.HasPrefix(name, prefix) {
			return nil
		}
	}
	return linuxerr.EOPNOTSUPP
}

// FilterXattrList filters extended attribute names for a caller with creds and
// validates that the null-terminated list fits within size when size is non-zero.
func FilterXattrList(all []string, creds *auth.Credentials, size uint64) ([]string, error) {
	haveCap := creds.HasRootCapability(linux.CAP_SYS_ADMIN)
	names := make([]string, 0, len(all))
	listSize := 0
	for _, name := range all {
		if CheckXattrPrefix(name) != nil {
			continue
		}
		if !haveCap && strings.HasPrefix(name, linux.XATTR_TRUSTED_PREFIX) {
			continue
		}
		names = append(names, name)
		listSize += len(name) + 1
	}
	if size != 0 && uint64(listSize) > size {
		return nil, linuxerr.ERANGE
	}
	return names, nil
}

// OpenSpecial opens a FIFO, character device, or block device node and returns
// ENXIO for sockets or unknown file types.
func OpenSpecial(ctx context.Context, rp *vfs.ResolvingPath, d *vfs.Dentry, opts *vfs.OpenOptions, mode uint32, p *pipe.VFSPipe, locks *vfs.FileLocks, major, minor uint32) (*vfs.FileDescription, error) {
	switch mode & linux.S_IFMT {
	case linux.S_IFIFO:
		return p.Open(ctx, rp.Mount(), d, opts.Flags, locks)
	case linux.S_IFCHR, linux.S_IFBLK:
		kind := vfs.CharDevice
		if mode&linux.S_IFMT == linux.S_IFBLK {
			kind = vfs.BlockDevice
		}
		return rp.VirtualFilesystem().OpenDeviceSpecialFile(ctx, rp.Mount(), d, kind, major, minor, opts)
	default:
		return nil, linuxerr.ENXIO
	}
}

// CacheBackend provides the filesystem-specific callbacks for a mapped-page cache.
type CacheBackend interface {
	ChunkMemory() ChunkMemory
	FileSizeLocked() uint64
	CanTranslateLocked(write bool) error
	PrepareAddMappingLocked() error
	ReadChunkAtLocked(dst []byte, off int64) error
	FlushLocked(start, end uint64) error
	DropBackendLocked()
	TranslateError(err error) error
}

// Cache holds the mapped-page chunks and mapping state of a regular file.
type Cache struct {
	backend CacheBackend

	Active atomic.Bool

	// MapsMu protects Mappings. Lock order: MapsMu, then DataMu.
	MapsMu   sync.Mutex
	Mappings memmap.MappingSet

	// DataMu protects the fields below.
	DataMu       sync.Mutex
	Chunks       map[uint64]*Chunk
	WritableMaps int
	WBErr        error

	mf dataMemmapFile
}

// Init binds the cache to b.
func (c *Cache) Init(b CacheBackend) {
	c.backend = b
	c.mf.cache = c
}

// DropLocked frees every chunk and releases backend state.
func (c *Cache) DropLocked() {
	for _, ch := range c.Chunks {
		ch.Release()
	}
	c.Chunks = nil
	c.Active.Store(false)
	c.backend.DropBackendLocked()
}

// TakeWritebackErr returns and clears any deferred write-back failure.
func (c *Cache) TakeWritebackErr() error {
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	err := c.WBErr
	c.WBErr = nil
	return err
}

// NoteWritebackErr records a write-back failure for the next fsync or close.
func (c *Cache) NoteWritebackErr(err error) {
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	c.WBErr = errors.Join(c.WBErr, err)
}

// SyncData writes back every dirty chunk and returns any deferred write-back error.
func (c *Cache) SyncData() error {
	if !c.Active.Load() {
		return c.TakeWritebackErr()
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	err := errors.Join(c.WBErr, c.backend.FlushLocked(0, math.MaxUint64))
	c.WBErr = nil
	return err
}

// FlushRange writes back dirty chunks that overlap [start, end).
func (c *Cache) FlushRange(start, end uint64) error {
	if !c.Active.Load() {
		return nil
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	return c.backend.FlushLocked(start, end)
}

// CopyThroughLocked copies p at off into any cached chunks that already exist.
func (c *Cache) CopyThroughLocked(off int64, p []byte) {
	for len(p) > 0 {
		idx := uint64(off) >> ChunkShift
		within := int(uint64(off) & (ChunkSize - 1))
		n := min(len(p), ChunkSize-within)
		if ch, ok := c.Chunks[idx]; ok {
			copy(ch.Buf[within:within+n], p[:n])
		}
		off += int64(n)
		p = p[n:]
	}
}

// ZeroLocked clears the cached bytes in [start, end).
func (c *Cache) ZeroLocked(start, end uint64) {
	if end <= start {
		return
	}
	for idx := start >> ChunkShift; idx <= (end-1)>>ChunkShift; idx++ {
		ch, ok := c.Chunks[idx]
		if !ok {
			continue
		}
		base := idx << ChunkShift
		lo := max(start, base) - base
		hi := min(end, base+ChunkSize) - base
		clear(ch.Buf[lo:hi])
	}
}

// Punched clears the cached bytes of a range that fallocate turned into a hole.
func (c *Cache) Punched(off, length uint64) {
	if !c.Active.Load() {
		return
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	c.ZeroLocked(off, off+length)
}

// ShrinkLocked removes chunks at or beyond size and clears any tail bytes.
func (c *Cache) ShrinkLocked(size uint64) []*Chunk {
	var dropped []*Chunk
	for idx, ch := range c.Chunks {
		base := idx << ChunkShift
		switch {
		case base >= size:
			dropped = append(dropped, ch)
			delete(c.Chunks, idx)
		case base+ChunkSize > size:
			clear(ch.Buf[size-base:])
		}
	}
	return dropped
}

// InvalidateShrink invalidates mappings beyond size and releases dropped chunks.
func (c *Cache) InvalidateShrink(size uint64, dropped []*Chunk) {
	pgend, _ := hostarch.PageRoundUp(size)
	c.Mappings.Invalidate(memmap.MappableRange{Start: pgend, End: math.MaxUint64}, memmap.InvalidateOpts{})
	for _, ch := range dropped {
		ch.Release()
	}
}

// ChunkLocked returns the chunk at idx, loading it from the backend when absent.
func (c *Cache) ChunkLocked(idx uint64) (*Chunk, error) {
	if ch, ok := c.Chunks[idx]; ok {
		return ch, nil
	}
	if err := c.backend.CanTranslateLocked(false); err != nil {
		return nil, err
	}
	ch, err := NewChunk(c.backend.ChunkMemory())
	if err != nil {
		return nil, err
	}
	if err := c.backend.ReadChunkAtLocked(ch.Buf, int64(idx<<ChunkShift)); err != nil && !errors.Is(err, io.EOF) {
		ch.Release()
		return nil, err
	}
	c.Chunks[idx] = ch
	return ch, nil
}

// AddMapping implements memmap.Mappable.AddMapping.
func (c *Cache) AddMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) error {
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if err := c.backend.PrepareAddMappingLocked(); err != nil {
		return c.backend.TranslateError(err)
	}
	c.Mappings.AddMapping(ms, ar, offset, writable)
	if writable {
		c.WritableMaps++
	}
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (c *Cache) RemoveMapping(ctx context.Context, ms memmap.MappingSpace, ar hostarch.AddrRange, offset uint64, writable bool) {
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.Mappings.RemoveMapping(ms, ar, offset, writable)
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if writable && c.WritableMaps > 0 {
		c.WritableMaps--
	}
	if err := c.backend.FlushLocked(0, math.MaxUint64); err != nil {
		c.WBErr = errors.Join(c.WBErr, err)
	}
	if c.Mappings.IsEmpty() {
		c.DropLocked()
	}
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (c *Cache) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR hostarch.AddrRange, offset uint64, writable bool) error {
	return c.AddMapping(ctx, ms, dstAR, offset, writable)
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (c *Cache) InvalidateUnsavable(ctx context.Context) error {
	return c.backend.TranslateError(c.SyncData())
}

// MarkDirtyLocked flags the chunks that overlap [start, end) as dirty.
func (c *Cache) MarkDirtyLocked(start, end uint64) {
	for idx := start >> ChunkShift; idx <= (end-1)>>ChunkShift; idx++ {
		if ch, ok := c.Chunks[idx]; ok {
			ch.Dirty = true
		}
	}
}

// Translate implements memmap.Mappable.Translate.
func (c *Cache) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if err := c.backend.CanTranslateLocked(at.Write); err != nil {
		return nil, &memmap.BusError{Err: err}
	}
	pgend, _ := hostarch.PageRoundUp(c.backend.FileSizeLocked())
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
	mr := MaxFillRange(required, optional)
	for idx := mr.Start >> ChunkShift; idx <= (mr.End-1)>>ChunkShift; idx++ {
		if _, err := c.ChunkLocked(idx); err != nil {
			if idx<<ChunkShift < required.End {
				return nil, &memmap.BusError{Err: c.backend.TranslateError(err)}
			}
			mr.End = idx << ChunkShift
			break
		}
	}
	perms := hostarch.ReadExecute
	if at.Write {
		c.MarkDirtyLocked(mr.Start, mr.End)
		perms.Write = true
	}
	ts := Translations(c.Chunks, mr, perms, &c.mf)
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// dataMemmapFile exposes the chunks of a Cache as a memmap.File.
type dataMemmapFile struct {
	memmap.DefaultMemoryType
	memmap.NoBufferedIOFallback

	cache *Cache
}

// IncRef implements memmap.File.IncRef.
func (mf *dataMemmapFile) IncRef(fr memmap.FileRange, memCgID uint32) {}

// DecRef implements memmap.File.DecRef.
func (mf *dataMemmapFile) DecRef(fr memmap.FileRange) {}

// MapInternal implements memmap.File.MapInternal.
func (mf *dataMemmapFile) MapInternal(fr memmap.FileRange, at hostarch.AccessType) (safemem.BlockSeq, error) {
	c := mf.cache
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if fr.Length() == 0 {
		return safemem.BlockSeq{}, nil
	}
	var blocks []safemem.Block
	for off := fr.Start; off < fr.End; {
		idx := off >> ChunkShift
		ch, err := c.ChunkLocked(idx)
		if err != nil {
			return safemem.BlockSeq{}, &memmap.BusError{Err: c.backend.TranslateError(err)}
		}
		base := idx << ChunkShift
		end := min(fr.End-base, ChunkSize)
		blocks = append(blocks, safemem.BlockFromSafeSlice(ch.Buf[off-base:end]))
		off = base + end
	}
	if at.Write {
		c.MarkDirtyLocked(fr.Start, fr.End)
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
