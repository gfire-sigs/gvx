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
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// regularFD implements vfs.FileDescriptionImpl for regular files.
type regularFD struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	dentry *dentry
	h      *hostHandle

	// mu protects off.
	mu  sync.Mutex
	off int64
	// dirSynced is set once a write through a synchronous description made
	// the directory entry durable. See durability.go.
	dirSynced atomic.Bool
}

// openHost opens the host file of d. It passes the entry that the lookup
// cached and the pinned handle of the directory, so it makes one host call
// and no second lookup. When the host no longer holds that regular file, it
// forgets the cached entry and resolves the path again, which gives the exact
// error.
func (d *dentry) openHost(flags int) (*hostHandle, error) {
	if d.fs.ws.single != "" {
		// The root is the one bound file. Resolve its name again, so a file
		// that a host editor replaced is the file that the guest opens.
		return d.fs.ws.openSingle(flags)
	}
	if d.inode.unlinked.Load() {
		if t := d.tmpOf(); t != nil {
			return d.fs.ws.openTmp(t, flags)
		}
	}
	rel := d.path()
	h, err := d.fs.ws.openHandleWithAttr(rel, d.inode.snapshot(), flags)
	if err == nil {
		return h, nil
	}
	d.inode.invalidateMeta()
	return d.fs.ws.openHandle(rel, flags)
}

// openRegular creates the file description of d. created is the handle of a
// file that OpenAt just created, or nil.
func (d *dentry) openRegular(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, created *hostHandle) (*vfs.FileDescription, error) {
	h := created
	writable := vfs.MayWriteFileWithOpenFlags(opts.Flags)
	if h == nil {
		hostFlags := os.O_RDONLY
		switch opts.Flags & linux.O_ACCMODE {
		case linux.O_WRONLY:
			hostFlags = os.O_WRONLY
		case linux.O_RDWR:
			hostFlags = os.O_RDWR
		}
		var err error
		h, err = d.openHost(hostFlags)
		if err != nil {
			return nil, translateHostError(err)
		}
	}
	fd := &regularFD{dentry: d, h: h}
	fd.LockFD.Init(&d.inode.locks)
	mnt := rp.Mount()
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), mnt, &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
		_ = h.decRef()
		return nil, err
	}
	if created == nil && opts.Flags&linux.O_TRUNC != 0 {
		if err := mnt.CheckBeginWrite(); err != nil {
			fd.vfsfd.DecRef(ctx)
			return nil, err
		}
		var truncHandle *hostHandle
		if writable {
			truncHandle = h
		}
		err := d.inode.truncate(d, truncHandle, 0)
		mnt.EndWrite()
		if err != nil {
			fd.vfsfd.DecRef(ctx)
			return nil, err
		}
	}
	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFD) Release(ctx context.Context) {
	// A close error at the last reference has no caller to report to. fsync
	// and close(2) through OnClose report write-back failures.
	_ = fd.h.decRef()
}

// OnClose implements vfs.FileDescriptionImpl.OnClose. It reports the write-back
// failure of a memory mapping that ended before the file description closed.
func (fd *regularFD) OnClose(ctx context.Context) error {
	return translateHostError(fd.dentry.inode.data.takeWritebackErr())
}

// Stat implements vfs.FileDescriptionImpl.Stat. It reads size, times, and link
// count from the open handle, so it stays correct after rename and unlink.
func (fd *regularFD) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	d := fd.dentry
	if err := d.refresh(); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
		return linux.Statx{}, err
	}
	e := d.inode.snapshot()
	info, err := fd.h.fstat(d.fs.ws.host)
	if err != nil {
		return linux.Statx{}, translateHostError(err)
	}
	e.info = info
	return d.inode.statxFor(e, d.fs.devMinor), nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *regularFD) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	d := fd.dentry
	if err := d.setStat(ctx, auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts, fd.h); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *regularFD) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.dentry.fs.statFS()
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, linuxerr.EOPNOTSUPP
	}
	n := dst.NumBytes()
	if n == 0 {
		return 0, nil
	}
	// Mapped pages that a guest wrote must reach the host file before the read.
	end := uint64(offset) + uint64(n)
	if end < uint64(offset) {
		end = math.MaxUint64
	}
	if err := fd.dentry.inode.data.flushRange(uint64(offset), end); err != nil {
		return 0, translateHostError(err)
	}
	r := hostFileReader{h: fd.h, off: offset}
	read, err := dst.CopyOutFrom(ctx, &r)
	switch {
	case err == nil:
		return read, nil
	case errors.Is(err, io.EOF):
		if read > 0 {
			return read, nil
		}
		return 0, io.EOF
	default:
		return read, translateHostError(err)
	}
}

// hostFileReader reads a host file at an offset straight into the blocks of a
// destination. It replaces io.NewSectionReader and safemem.FromIOReader, which
// together allocate two objects for each read.
type hostFileReader struct {
	h   *hostHandle
	off int64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks. A short read returns
// the error of ReadAt, which is io.EOF at the end of the file.
func (r *hostFileReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	var done uint64
	var scratch []byte
	for ; !dsts.IsEmpty(); dsts = dsts.Tail() {
		dst := dsts.Head()
		var n int
		var err error
		if !dst.NeedSafecopy() {
			n, err = r.h.readAt(dst.ToSlice(), r.off)
		} else {
			// ReadAt cannot write to memory that faults, so it reads into a
			// scratch buffer first.
			if len(scratch) < dst.Len() {
				scratch = make([]byte, dst.Len())
			}
			var rn int
			rn, err = r.h.readAt(scratch[:dst.Len()], r.off)
			var werr error
			n, werr = safemem.Copy(dst, safemem.BlockFromSafeSlice(scratch[:rn]))
			if werr != nil {
				err = werr
			}
		}
		r.off += int64(n)
		done += uint64(n)
		if n != dst.Len() {
			return done, err
		}
	}
	return done, nil
}

// Read implements vfs.FileDescriptionImpl.Read.
func (fd *regularFD) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	n, err := fd.PRead(ctx, dst, fd.off, opts)
	fd.off += n
	return n, err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (fd *regularFD) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	n, _, err := fd.pwrite(ctx, src, offset, opts)
	return n, err
}

// handleWriter writes to the host file and keeps the mapped-page cache
// coherent with what it wrote.
type handleWriter struct {
	fd  *regularFD
	off int64
}

func (w *handleWriter) Write(p []byte) (int, error) {
	n, err := w.fd.h.writeAt(p, w.off)
	if n > 0 {
		w.fd.dentry.inode.invalidateMeta()
		w.fd.dentry.inode.data.writeThrough(w.off, p[:n])
		w.off += int64(n)
	}
	return n, err
}

func (fd *regularFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, linuxerr.EINVAL
	}
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, offset, linuxerr.EOPNOTSUPP
	}
	d := fd.dentry
	ino := d.inode
	ino.wmu.Lock()
	defer ino.wmu.Unlock()
	// The host watcher must not mistake this write for a host write.
	ino.guestBegin()
	defer fd.h.guestEnd(ino)

	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		info, err := fd.h.fstat(d.fs.ws.host)
		if err != nil {
			return 0, offset, translateHostError(err)
		}
		offset = info.size
	}
	if limits.FromContext(ctx) != nil {
		limit, err := vfs.CheckLimit(ctx, offset, src.NumBytes())
		if err != nil {
			return 0, offset, err
		}
		src = src.TakeFirst64(limit)
	}
	if src.NumBytes() == 0 {
		return 0, offset, nil
	}
	w := &handleWriter{fd: fd, off: offset}
	n, err := src.CopyInTo(ctx, safemem.FromIOWriter{Writer: w})
	if err != nil {
		return n, offset + n, translateHostError(err)
	}
	// As with Linux, writing clears the set-user-ID and set-group-ID bits.
	if n > 0 {
		if mode := uint32(ino.mode()); vfs.ClearSUIDAndSGID(mode) != mode {
			m := vfs.ClearSUIDAndSGID(mode) & 0o7777
			if err := d.setAttr(&m, nil, nil); err != nil {
				return 0, offset, err
			}
			_ = d.refresh()
		}
	}
	if n > 0 && fd.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 {
		// The write bypasses the coalesce window of the metadata table.
		// Without a durable write the call cannot honour O_SYNC, so it reports
		// no progress, as Linux does for a failed generic_write_sync.
		if err := fd.syncWrite(offset, offset+n); err != nil {
			return 0, offset, translateHostError(err)
		}
	}
	return n, offset + n, nil
}

// Write implements vfs.FileDescriptionImpl.Write.
func (fd *regularFD) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	n, off, err := fd.pwrite(ctx, src, fd.off, opts)
	fd.off = off
	return n, err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
func (fd *regularFD) Seek(ctx context.Context, offset int64, whence int32) (int64, error) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = fd.off + offset
	case linux.SEEK_END, linux.SEEK_DATA, linux.SEEK_HOLE:
		info, err := fd.h.fstat(fd.dentry.fs.ws.host)
		if err != nil {
			return 0, translateHostError(err)
		}
		switch whence {
		case linux.SEEK_END:
			newOff = info.size + offset
		case linux.SEEK_DATA:
			if offset < 0 || offset >= info.size {
				return 0, linuxerr.ENXIO
			}
			newOff = offset
		default:
			if offset < 0 || offset >= info.size {
				return 0, linuxerr.ENXIO
			}
			newOff = info.size
		}
	default:
		return 0, linuxerr.EINVAL
	}
	if newOff < 0 {
		return 0, linuxerr.EINVAL
	}
	fd.off = newOff
	return newOff, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync. Both fsync and fdatasync
// bypass the coalesce window of the metadata table. They flush the mapped
// pages, the host file, the directory entry, and .gvx_meta, and they report
// every failure. See durability.go.
func (fd *regularFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	return translateHostError(fd.persist(true))
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := fd.dentry.inode.checkMapping(opts); err != nil {
		return err
	}
	writable := fd.vfsfd.IsWritable() && fd.vfsfd.IsReadable()
	if err := fd.dentry.inode.data.attachHandle(fd.h, writable); err != nil {
		return translateHostError(err)
	}
	if err := vfs.GenericConfigureMMap(&fd.vfsfd, &fd.dentry.inode.data, opts); err != nil {
		return err
	}
	opts.SentryOwnedContent = true
	return nil
}

// truncate sets the file size through h, or through a fresh handle when h is
// nil, and trims the mapped-page cache.
func (i *inode) truncate(d *dentry, h *hostHandle, size int64) error {
	if size < 0 {
		return linuxerr.EINVAL
	}
	if h == nil {
		opened, err := d.openHost(os.O_WRONLY)
		if err != nil {
			return translateHostError(err)
		}
		defer func() {
			_ = opened.decRef()
		}()
		h = opened
	}
	i.wmu.Lock()
	defer i.wmu.Unlock()
	i.guestBegin()
	f, err := h.acquire()
	if err != nil {
		i.guestEnd(hostInfo{}, false)
		return translateHostError(err)
	}
	truncErr := f.Truncate(size)
	i.guestEndFile(f)
	h.release()
	if truncErr != nil {
		return translateHostError(truncErr)
	}
	i.invalidateMeta()
	i.data.truncated(size)
	return nil
}

const (
	// chunkShift is the log2 of the cache granule. The granule is a multiple of
	// every host page size and of the 4 KiB guest page size.
	chunkShift = 16
	chunkSize  = 1 << chunkShift

	// chunkAlign is the alignment of a chunk in host memory. Platforms map
	// chunks into guest address spaces page by page.
	chunkAlign = 16 << 10

	// maxReadahead bounds how much of a mapping one Translate call loads.
	maxReadahead = 64 << 10
)

type cacheChunk struct {
	buf   []byte
	dirty bool

	// mem and fr locate the chunk in shared memory. They are zero when buf is
	// Go heap memory.
	mem ChunkMemory
	fr  memmap.FileRange
}

// release returns shared memory to its owner. The memory stays valid for the
// mappings that still hold a reference.
func (ch *cacheChunk) release() {
	if ch.mem != nil {
		ch.mem.DecRef(ch.fr)
		ch.mem = nil
	}
}

// newChunk allocates the memory of one chunk. With ChunkMemory, the chunk
// lives in a memory file, which a platform can map into a guest process by
// file descriptor. Without it, the chunk lives on the Go heap.
func (c *fileData) newChunk() (*cacheChunk, error) {
	mem := c.ino.fs.ws.chunkMemory()
	if mem == nil {
		return &cacheChunk{buf: newChunkBuf()}, nil
	}
	fr, err := mem.AllocateChunk(chunkSize)
	if err != nil {
		return nil, err
	}
	bs, err := mem.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		mem.DecRef(fr)
		return nil, err
	}
	if bs.NumBlocks() != 1 || bs.NumBytes() != chunkSize {
		mem.DecRef(fr)
		return nil, fmt.Errorf("hostfs: the chunk memory maps %d blocks of %d bytes, want one block of %d", bs.NumBlocks(), bs.NumBytes(), chunkSize)
	}
	return &cacheChunk{buf: bs.Head().ToSlice(), mem: mem, fr: fr}, nil
}

// newChunkBuf allocates one chunk aligned to chunkAlign. Go heap memory never
// moves, so slices handed to platforms stay valid for the chunk lifetime.
func newChunkBuf() []byte {
	raw := make([]byte, chunkSize+chunkAlign)
	skip := (chunkAlign - int(uintptr(unsafe.Pointer(&raw[0]))%chunkAlign)) % chunkAlign
	return raw[skip : skip+chunkSize : skip+chunkSize]
}

// fileData is the mapped-page cache of a regular file. The cache exists only
// while a mapping holds an attached handle. The host file stays the source of
// truth for read and write system calls. Writes go through to cached chunks.
// Reads first write back the dirty chunks that they overlap.
//
// A host process that changes the file is visible only while a guest inotify
// watch covers the file or its directory. The host watcher then drops the
// clean chunks through invalidateCleanChunks. Without a watch, chunks that
// are already loaded keep the old bytes.
//
// A directory rename can close the attached handle and reopen it at the new
// path. This is safe because the chunks live in Sentry memory, and the guest
// reads and writes them without the host file. A chunk that the guest changed
// stays dirty until a write-back writes it. A write-back goes through the
// handle, which waits for the reopen. See handle_registry.go.
type fileData struct {
	ino *inode

	// active is set while a handle is attached. The read path checks it
	// without taking locks.
	active atomic.Bool

	// mapsMu protects mappings. Lock order: mapsMu, then dataMu.
	mapsMu   sync.Mutex
	mappings memmap.MappingSet

	// dataMu protects the fields below.
	dataMu       sync.Mutex
	chunks       map[uint64]*cacheChunk
	size         int64
	mh           *hostHandle
	mhWritable   bool
	writableMaps int
	wbErr        error

	mf dataMemmapFile
}

func (c *fileData) init(ino *inode) {
	c.ino = ino
	c.mf.data = c
}

// attachHandle makes h the handle behind mapped pages. A writable handle
// replaces a read-only one, because only a writable handle can write back.
func (c *fileData) attachHandle(h *hostHandle, writable bool) error {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if c.mh != nil && (c.mhWritable || !writable) {
		return nil
	}
	if c.mh == nil {
		info, err := h.fstat(c.ino.fs.ws.host)
		if err != nil {
			return err
		}
		c.size = info.size
		c.chunks = make(map[uint64]*cacheChunk)
	}
	h.owner.Store(c)
	h.incRef()
	old := c.mh
	c.mh = h
	c.mhWritable = writable
	c.active.Store(true)
	if old != nil {
		_ = old.decRef()
	}
	return nil
}

// release drops the cache when the inode dies.
func (c *fileData) release() {
	_ = c.syncData()
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	c.dropLocked()
}

// dropLocked frees every chunk and the attached handle.
func (c *fileData) dropLocked() {
	for _, ch := range c.chunks {
		ch.release()
	}
	c.chunks = nil
	c.active.Store(false)
	if c.mh != nil {
		_ = c.mh.decRef()
		c.mh = nil
	}
	c.mhWritable = false
}

func (c *fileData) takeWritebackErr() error {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	err := c.wbErr
	c.wbErr = nil
	return err
}

// noteWritebackErr records a write-back failure that no caller can return, so
// the next fsync or close reports it.
func (c *fileData) noteWritebackErr(err error) {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	c.wbErr = errors.Join(c.wbErr, err)
}

// syncData writes back every dirty chunk and returns any earlier write-back
// failure that no caller observed.
func (c *fileData) syncData() error {
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

// flushLocked writes the dirty chunks that overlap [start, end) to the host
// file. A chunk stays dirty while a writable mapping exists, because the guest
// can modify it at any time.
func (c *fileData) flushLocked(start, end uint64) error {
	if len(c.chunks) == 0 || c.mh == nil {
		return nil
	}
	// The handle stays acquired from the first write to the end of the loop.
	// A directory rename cannot close the file in between. The loop takes no
	// lock of this package that the lock order places before the handle.
	var f *os.File
	var errs []error
	for idx, ch := range c.chunks {
		base := idx << chunkShift
		if !ch.dirty || base >= end || base+chunkSize <= start {
			continue
		}
		if base >= uint64(c.size) {
			ch.dirty = c.writableMaps > 0
			continue
		}
		n := uint64(c.size) - base
		if n > chunkSize {
			n = chunkSize
		}
		if f == nil {
			var err error
			if f, err = c.mh.acquire(); err != nil {
				return err
			}
			c.ino.guestBegin()
		}
		if _, err := f.WriteAt(ch.buf[:n], int64(base)); err != nil {
			errs = append(errs, err)
			continue
		}
		c.ino.invalidateMeta()
		ch.dirty = c.writableMaps > 0
	}
	if f != nil {
		c.ino.guestEndFile(f)
		c.mh.release()
	}
	return errors.Join(errs...)
}

// writeThrough copies bytes that a system call wrote to the host file into
// the chunks that exist, so mapped pages observe them.
func (c *fileData) writeThrough(off int64, p []byte) {
	if !c.active.Load() {
		return
	}
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if end := off + int64(len(p)); end > c.size {
		c.size = end
	}
	for len(p) > 0 {
		idx := uint64(off) >> chunkShift
		within := int(uint64(off) & (chunkSize - 1))
		n := min(len(p), chunkSize-within)
		if ch, ok := c.chunks[idx]; ok {
			copy(ch.buf[within:within+n], p[:n])
		}
		off += int64(n)
		p = p[n:]
	}
}

// truncated adjusts the cache after the host file changed size. It drops the
// chunks beyond the new size only after it invalidated the mappings. A mapping
// translated a chunk earlier and took its own reference when it did, so the
// memory outlives the chunk. Invalidate calls into the memory manager, which
// holds its own locks while it calls Translate, so dataMu must be free here.
func (c *fileData) truncated(size int64) {
	if !c.active.Load() {
		return
	}
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()

	c.dataMu.Lock()
	c.size = size
	var dropped []*cacheChunk
	for idx, ch := range c.chunks {
		base := int64(idx) << chunkShift
		switch {
		case base >= size:
			dropped = append(dropped, ch)
			delete(c.chunks, idx)
		case base+chunkSize > size:
			clear(ch.buf[size-base:])
		}
	}
	c.dataMu.Unlock()

	pgend, _ := hostarch.PageRoundUp(uint64(size))
	c.mappings.Invalidate(memmap.MappableRange{Start: pgend, End: math.MaxUint64}, memmap.InvalidateOpts{})
	for _, ch := range dropped {
		ch.release()
	}
}

// invalidateCleanChunks drops the cached state that a change by a host process
// made stale. It refreshes the cached size, drops every chunk that holds no
// guest modification, and invalidates every mapping, so the next access to a
// mapped page loads the chunk again from the host file. A chunk with a guest
// modification stays, because the next write-back would overwrite the host
// bytes at that offset anyway.
//
// The order follows truncated: the mappings go first, and the chunk memory
// goes after them, because a platform that mapped a chunk holds its own
// reference. Invalidate calls into the memory manager, which holds its own
// locks while it calls Translate, so dataMu must be free when it runs.
func (c *fileData) invalidateCleanChunks() {
	if !c.active.Load() {
		return
	}
	c.mapsMu.Lock()
	defer c.mapsMu.Unlock()

	c.dataMu.Lock()
	if c.mh == nil {
		c.dataMu.Unlock()
		return
	}
	if info, err := c.mh.fstat(c.ino.fs.ws.host); err == nil {
		c.size = info.size
	}
	var dropped []*cacheChunk
	for idx, ch := range c.chunks {
		base := int64(idx) << chunkShift
		switch {
		case !ch.dirty:
			dropped = append(dropped, ch)
			delete(c.chunks, idx)
		case base < c.size && base+chunkSize > c.size:
			clear(ch.buf[c.size-base:])
		}
	}
	c.dataMu.Unlock()

	c.mappings.InvalidateAll(memmap.InvalidateOpts{})
	for _, ch := range dropped {
		ch.release()
	}
}

// chunkLocked returns the chunk idx, loading it from the host file when absent.
func (c *fileData) chunkLocked(idx uint64) (*cacheChunk, error) {
	if ch, ok := c.chunks[idx]; ok {
		return ch, nil
	}
	if c.mh == nil {
		return nil, linuxerr.ENODEV
	}
	ch, err := c.newChunk()
	if err != nil {
		return nil, err
	}
	if _, err := c.mh.readAt(ch.buf, int64(idx<<chunkShift)); err != nil && !errors.Is(err, io.EOF) {
		ch.release()
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
	if writable {
		c.dataMu.Lock()
		c.writableMaps++
		c.dataMu.Unlock()
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
	return translateHostError(c.syncData())
}

func maxFillRange(required, optional memmap.MappableRange) memmap.MappableRange {
	if required.Length() >= maxReadahead {
		return required
	}
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.Start = required.Start
	if optional.Length() <= maxReadahead {
		return optional
	}
	optional.End = optional.Start + maxReadahead
	return optional
}

// markDirtyLocked flags the chunks that overlap [start, end) as dirty.
func (c *fileData) markDirtyLocked(start, end uint64) {
	for idx := start >> chunkShift; idx <= (end-1)>>chunkShift; idx++ {
		if ch, ok := c.chunks[idx]; ok {
			ch.dirty = true
		}
	}
}

// Translate implements memmap.Mappable.Translate.
func (c *fileData) Translate(ctx context.Context, required, optional memmap.MappableRange, at hostarch.AccessType) ([]memmap.Translation, error) {
	c.dataMu.Lock()
	defer c.dataMu.Unlock()
	if c.mh == nil {
		return nil, &memmap.BusError{Err: linuxerr.ENODEV}
	}
	if at.Write && !c.mhWritable {
		return nil, &memmap.BusError{Err: linuxerr.EACCES}
	}
	// Constrain translations to the file size, rounded up to a page, so that
	// no translation reaches pages that a truncation removes.
	pgend, _ := hostarch.PageRoundUp(uint64(c.size))
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
	mr := maxFillRange(required, optional)
	for idx := mr.Start >> chunkShift; idx <= (mr.End-1)>>chunkShift; idx++ {
		if _, err := c.chunkLocked(idx); err != nil {
			if idx<<chunkShift < required.End {
				return nil, &memmap.BusError{Err: translateHostError(err)}
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
	ts := c.translationsLocked(mr, perms)
	if beyondEOF {
		return ts, &memmap.BusError{Err: io.EOF}
	}
	return ts, nil
}

// translationsLocked describes where the pages of mr live. Heap chunks form one
// translation, and the heap file maps file offsets to chunk memory. Chunks in
// shared memory need one translation each, because the allocator places chunks
// apart. Every chunk of mr exists when this runs.
func (c *fileData) translationsLocked(mr memmap.MappableRange, perms hostarch.AccessType) []memmap.Translation {
	if c.chunks[mr.Start>>chunkShift].mem == nil {
		return []memmap.Translation{{
			Source: mr,
			File:   &c.mf,
			Offset: mr.Start,
			Perms:  perms,
		}}
	}
	var ts []memmap.Translation
	for off := mr.Start; off < mr.End; {
		idx := off >> chunkShift
		ch := c.chunks[idx]
		base := idx << chunkShift
		end := min(mr.End, base+chunkSize)
		ts = append(ts, memmap.Translation{
			Source: memmap.MappableRange{Start: off, End: end},
			File:   ch.mem,
			Offset: ch.fr.Start + (off - base),
			Perms:  perms,
		})
		off = end
	}
	return ts
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
			return safemem.BlockSeq{}, &memmap.BusError{Err: translateHostError(err)}
		}
		base := idx << chunkShift
		end := min(fr.End-base, chunkSize)
		blocks = append(blocks, safemem.BlockFromSafeSlice(ch.buf[off-base:end]))
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
