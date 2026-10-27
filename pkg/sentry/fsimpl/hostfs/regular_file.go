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
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// regularFD implements vfs.FileDescriptionImpl for regular files.
type regularFD struct {
	fileDescription

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
	fd := &regularFD{fileDescription: fileDescription{dentry: d, h: h}}
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
	return translateHostError(fd.dentry.inode.data.TakeWritebackErr())
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
	if err := fd.dentry.inode.data.FlushRange(uint64(offset), end); err != nil {
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
	done, off, err := chunkcache.ReadAtToBlocks(dsts, r.off, r.h.readAt)
	r.off = off
	return done, err
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
		if mode := uint32(ino.mode()); clearSUIDAndSGID(mode) != mode {
			m := clearSUIDAndSGID(mode) & 0o7777
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
	newOff, err := chunkcache.SeekRegular(fd.off, offset, whence, func() (int64, error) {
		info, err := fd.h.fstat(fd.dentry.fs.ws.host)
		if err != nil {
			return 0, translateHostError(err)
		}
		return info.size, nil
	})
	if err != nil {
		return 0, err
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
	fd.dentry.inode.data.reserveHandle(fd.h, writable)
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
	chunkShift = chunkcache.ChunkShift
	chunkSize  = chunkcache.ChunkSize
)

type cacheChunk = chunkcache.Chunk

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
	chunkcache.Cache
	ino *inode

	size            int64
	mh              *hostHandle
	mhWritable      bool
	pending         *hostHandle
	pendingWritable bool
}

func (c *fileData) init(ino *inode) {
	c.ino = ino
	c.Init(c)
}

func (c *fileData) ChunkMemory() chunkcache.ChunkMemory { return c.ino.fs.ws.chunkMemory() }
func (c *fileData) FileSizeLocked() uint64              { return uint64(c.size) }
func (c *fileData) TranslateError(err error) error      { return translateHostError(err) }

func (c *fileData) CanTranslateLocked(write bool) error {
	if c.mh == nil {
		return linuxerr.ENODEV
	}
	if write && !c.mhWritable {
		return linuxerr.EACCES
	}
	return nil
}

func (c *fileData) PrepareAddMappingLocked() error { return c.restoreHandleLocked() }

func (c *fileData) ReadChunkAtLocked(dst []byte, off int64) error {
	_, err := c.mh.readAt(dst, off)
	return err
}

func (c *fileData) DropBackendLocked() {
	if c.mh != nil {
		_ = c.mh.decRef()
		c.mh = nil
	}
	c.mhWritable = false
}

// attachHandle makes h the handle behind mapped pages. A writable handle
// replaces a read-only one, because only a writable handle can write back.
func (c *fileData) attachHandle(h *hostHandle, writable bool) error {
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	return c.attachLocked(h, writable)
}

// attachLocked is attachHandle for a caller that holds DataMu.
func (c *fileData) attachLocked(h *hostHandle, writable bool) error {
	if c.mh != nil && (c.mhWritable || !writable) {
		return nil
	}
	if c.mh == nil {
		info, err := h.fstat(c.ino.fs.ws.host)
		if err != nil {
			return err
		}
		c.size = info.size
		c.Chunks = make(map[uint64]*cacheChunk)
	}
	h.owner.Store(c)
	h.incRef()
	old := c.mh
	c.mh = h
	c.mhWritable = writable
	c.Active.Store(true)
	if old != nil {
		_ = old.decRef()
	}
	return nil
}

// reserveHandle keeps h for the AddMapping call that follows ConfigureMMap.
func (c *fileData) reserveHandle(h *hostHandle, writable bool) {
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if c.pending != nil {
		if c.pendingWritable || !writable {
			return
		}
		_ = c.pending.decRef()
	}
	h.incRef()
	c.pending = h
	c.pendingWritable = writable
}

// restoreHandleLocked attaches the reserved handle when no handle is attached.
func (c *fileData) restoreHandleLocked() error {
	p := c.pending
	if p == nil {
		return nil
	}
	writable := c.pendingWritable
	c.pending = nil
	c.pendingWritable = false
	err := c.attachLocked(p, writable)
	_ = p.decRef()
	return err
}

// release drops the cache when the inode dies.
func (c *fileData) release() {
	_ = c.SyncData()
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	c.DropLocked()
	if c.pending != nil {
		_ = c.pending.decRef()
		c.pending = nil
		c.pendingWritable = false
	}
}

// FlushLocked writes the dirty chunks that overlap [start, end) to the host
// file. A chunk stays dirty while a writable mapping exists, because the guest
// can modify it at any time.
func (c *fileData) FlushLocked(start, end uint64) error {
	if len(c.Chunks) == 0 || c.mh == nil {
		return nil
	}
	var f *os.File
	var errs []error
	for idx, ch := range c.Chunks {
		base := idx << chunkShift
		if !ch.Dirty || base >= end || base+chunkSize <= start {
			continue
		}
		if base >= uint64(c.size) {
			ch.Dirty = c.WritableMaps > 0
			continue
		}
		n := min(uint64(c.size)-base, chunkSize)
		if f == nil {
			var err error
			if f, err = c.mh.acquire(); err != nil {
				return err
			}
			c.ino.guestBegin()
		}
		if _, err := f.WriteAt(ch.Buf[:n], int64(base)); err != nil {
			errs = append(errs, err)
			continue
		}
		c.ino.invalidateMeta()
		ch.Dirty = c.WritableMaps > 0
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
	if !c.Active.Load() {
		return
	}
	c.DataMu.Lock()
	defer c.DataMu.Unlock()
	if end := off + int64(len(p)); end > c.size {
		c.size = end
	}
	c.CopyThroughLocked(off, p)
}

// truncated adjusts the cache after the host file changed size.
func (c *fileData) truncated(size int64) {
	if !c.Active.Load() {
		return
	}
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()
	c.DataMu.Lock()
	c.size = size
	dropped := c.ShrinkLocked(uint64(size))
	c.DataMu.Unlock()
	c.InvalidateShrink(uint64(size), dropped)
}

// invalidateCleanChunks drops the cached state that a change by a host process
// made stale.
func (c *fileData) invalidateCleanChunks() {
	if !c.Active.Load() {
		return
	}
	c.MapsMu.Lock()
	defer c.MapsMu.Unlock()

	c.DataMu.Lock()
	if c.mh == nil {
		c.DataMu.Unlock()
		return
	}
	if info, err := c.mh.fstat(c.ino.fs.ws.host); err == nil {
		c.size = info.size
	}
	var dropped []*cacheChunk
	for idx, ch := range c.Chunks {
		base := int64(idx) << chunkShift
		switch {
		case !ch.Dirty:
			dropped = append(dropped, ch)
			delete(c.Chunks, idx)
		case base < c.size && base+chunkSize > c.size:
			clear(ch.Buf[c.size-base:])
		}
	}
	c.DataMu.Unlock()

	c.Mappings.InvalidateAll(memmap.InvalidateOpts{})
	for _, ch := range dropped {
		ch.Release()
	}
}
