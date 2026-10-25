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

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/safemem"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/chunkcache"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// fileDescription holds the members that every file description of this
// filesystem shares. The nesting lets dirFD embed both default implementations
// without ambiguity.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	dentry *dentry
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (fd *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return fd.dentry.inode.statx(), nil
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (fd *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	d := fd.dentry
	if err := d.inode.setStat(ctx, auth.CredentialsFromContext(ctx), fd.vfsfd.Mount(), &opts); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// StatFS implements vfs.FileDescriptionImpl.StatFS.
func (fd *fileDescription) StatFS(ctx context.Context) (linux.Statfs, error) {
	return fd.dentry.fs.statfs(), nil
}

// regularFD implements vfs.FileDescriptionImpl for regular files.
type regularFD struct {
	fileDescription

	// mu protects off.
	mu  sync.Mutex
	off int64
}

// openRegular creates the file description of a regular file. The afterCreate
// flag is set when OpenAt just created the file.
func (d *dentry) openRegular(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, afterCreate bool) (*vfs.FileDescription, error) {
	fd := &regularFD{}
	fd.dentry = d
	fd.LockFD.Init(&d.inode.locks)
	mnt := rp.Mount()
	if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), mnt, &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
		return nil, err
	}
	if !afterCreate && opts.Flags&linux.O_TRUNC != 0 {
		if err := d.fs.beginWrite(mnt); err != nil {
			fd.vfsfd.DecRef(ctx)
			return nil, err
		}
		err := d.inode.truncate(0)
		mnt.EndWrite()
		if err != nil {
			fd.vfsfd.DecRef(ctx)
			return nil, err
		}
	}
	return &fd.vfsfd, nil
}

// Release implements vfs.FileDescriptionImpl.Release.
func (fd *regularFD) Release(ctx context.Context) {}

// OnClose implements vfs.FileDescriptionImpl.OnClose. It reports the write-back
// failure of a memory mapping that ended before the file description closed.
func (fd *regularFD) OnClose(ctx context.Context) error {
	return toLinuxErr(fd.dentry.inode.data.takeWritebackErr())
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
	ino := fd.dentry.inode
	// Mapped pages that a guest wrote must reach the engine before the read.
	end := uint64(offset) + uint64(n)
	if end < uint64(offset) {
		end = math.MaxUint64
	}
	if err := ino.data.flushRange(uint64(offset), end); err != nil {
		return 0, toLinuxErr(err)
	}
	r := nodeReader{n: ino.n, off: offset}
	read, err := dst.CopyOutFrom(ctx, &r)
	if read > 0 {
		ino.touchAtime(fd.vfsfd.Mount())
	}
	switch {
	case err == nil:
		return read, nil
	case errors.Is(err, io.EOF):
		if read > 0 {
			return read, nil
		}
		return 0, io.EOF
	default:
		return read, toLinuxErr(err)
	}
}

// nodeReader reads a node at an offset straight into the blocks of a
// destination.
type nodeReader struct {
	n   *node
	off int64
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks. A short read returns the
// error of the node, which is io.EOF at the end of the file.
func (r *nodeReader) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	done, off, err := chunkcache.ReadAtToBlocks(dsts, r.off, r.n.readAt)
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

// nodeWriter writes to a node and keeps the mapped-page cache coherent with
// what it wrote.
type nodeWriter struct {
	ino *inode
	off int64
}

func (w *nodeWriter) Write(p []byte) (int, error) {
	n := w.ino.n
	n.mu.RLock()
	oldSize := n.size
	n.mu.RUnlock()
	done, err := n.writeAt(p, w.off)
	if done > 0 {
		w.ino.data.writeThrough(oldSize, w.off, p[:done])
		w.off += int64(done)
	}
	return done, err
}

func (fd *regularFD) pwrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	if offset < 0 {
		return 0, offset, linuxerr.EINVAL
	}
	// RWF_DSYNC and RWF_SYNC behave as O_DSYNC and O_SYNC for this call.
	if opts.Flags&^(linux.RWF_HIPRI|linux.RWF_DSYNC|linux.RWF_SYNC) != 0 {
		return 0, offset, linuxerr.EOPNOTSUPP
	}
	d := fd.dentry
	ino := d.inode
	if d.fs.readOnly {
		return 0, offset, linuxerr.EROFS
	}
	ino.wmu.Lock()
	defer ino.wmu.Unlock()

	if fd.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		ino.n.mu.RLock()
		offset = int64(ino.n.size)
		ino.n.mu.RUnlock()
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
	w := &nodeWriter{ino: ino, off: offset}
	n, err := src.CopyInTo(ctx, safemem.FromIOWriter{Writer: w})
	if n > 0 {
		// As with Linux, a write clears the set-user-ID and set-group-ID bits
		// and removes the file capabilities.
		now := d.fs.now()
		ino.mutate(func(nd *node) {
			nd.mtime, nd.ctime = now, now
			nd.mode = uint16(vfs.ClearSUIDAndSGID(uint32(nd.mode)))
		})
		if err := ino.killCapability(); err != nil {
			return n, offset + n, err
		}
	}
	if err != nil {
		return n, offset + n, toLinuxErr(err)
	}
	durable := fd.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 || opts.Flags&(linux.RWF_DSYNC|linux.RWF_SYNC) != 0
	if n > 0 && durable {
		// Without a durable write the call cannot honour the sync flag, so it
		// reports no progress, as Linux does for a failed generic_write_sync.
		if err := d.fs.syncInode(ino); err != nil {
			return 0, offset, err
		}
	}
	return n, offset + n, nil
}

// killCapability removes the file capabilities after a write. It reads the
// attributes only when the node has any.
func (i *inode) killCapability() error {
	n := i.n
	n.mu.RLock()
	has := n.fileACL != 0 || (n.xa != nil && len(n.xa.entries) > 0)
	n.mu.RUnlock()
	if !has {
		return nil
	}
	if err := n.removeXattr(linux.XATTR_SECURITY_CAPABILITY); err != nil && !linuxerr.Equals(linuxerr.ENODATA, err) {
		return toLinuxErr(err)
	}
	return nil
}

// syncInode writes the dirty mapped data of ino to the engine and then flushes
// the volume in the strict order. It is the path of fsync, fdatasync, and of a
// write on an O_SYNC or O_DSYNC descriptor.
func (fs *filesystem) syncInode(ino *inode) error {
	var errs []error
	if err := ino.data.syncData(); err != nil {
		errs = append(errs, err)
	}
	if err := fs.v.sync(); err != nil {
		errs = append(errs, err)
	}
	return toLinuxErr(errors.Join(errs...))
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
	ino := fd.dentry.inode
	var newOff int64
	switch whence {
	case linux.SEEK_SET:
		newOff = offset
	case linux.SEEK_CUR:
		newOff = fd.off + offset
	case linux.SEEK_END:
		ino.n.mu.RLock()
		size := int64(ino.n.size)
		ino.n.mu.RUnlock()
		newOff = size + offset
	case linux.SEEK_DATA, linux.SEEK_HOLE:
		if offset < 0 {
			return 0, linuxerr.ENXIO
		}
		// A dirty mapped page over a hole counts as data only after the
		// engine stores it.
		if err := ino.data.flushRange(0, math.MaxUint64); err != nil {
			return 0, toLinuxErr(err)
		}
		ino.n.mu.RLock()
		size := int64(ino.n.size)
		ino.n.mu.RUnlock()
		if offset >= size {
			return 0, linuxerr.ENXIO
		}
		if whence == linux.SEEK_DATA {
			pos, ok := ino.n.seekData(uint64(offset))
			if !ok {
				return 0, linuxerr.ENXIO
			}
			newOff = int64(pos)
		} else {
			newOff = int64(ino.n.seekHole(uint64(offset)))
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

// Sync implements vfs.FileDescriptionImpl.Sync. Both fsync and fdatasync write
// the dirty mapped data first and then flush the volume in the strict order,
// so a directory entry never points to an inode that the host file lacks.
func (fd *regularFD) Sync(ctx context.Context, opts vfs.SyncOptions) error {
	return fd.dentry.fs.syncInode(fd.dentry.inode)
}

// Allocate implements vfs.FileDescriptionImpl.Allocate. It supports mode 0,
// FALLOC_FL_KEEP_SIZE, and FALLOC_FL_PUNCH_HOLE with FALLOC_FL_KEEP_SIZE.
func (fd *regularFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	const supported = linux.FALLOC_FL_KEEP_SIZE | linux.FALLOC_FL_PUNCH_HOLE
	if mode&^supported != 0 {
		return linuxerr.EOPNOTSUPP
	}
	punch := mode&linux.FALLOC_FL_PUNCH_HOLE != 0
	keepSize := mode&linux.FALLOC_FL_KEEP_SIZE != 0
	if punch && !keepSize {
		return linuxerr.EOPNOTSUPP
	}
	if length == 0 || offset > math.MaxInt64 || length > math.MaxInt64 {
		return linuxerr.EINVAL
	}
	if offset+length < offset || offset+length > math.MaxInt64 {
		return linuxerr.EFBIG
	}
	d := fd.dentry
	ino := d.inode
	if err := d.fs.beginWrite(fd.vfsfd.Mount()); err != nil {
		return err
	}
	defer fd.vfsfd.Mount().EndWrite()
	ino.wmu.Lock()
	defer ino.wmu.Unlock()
	if punch {
		// Dirty mapped pages in the range reach the engine first, so the punch
		// removes them as well.
		if err := ino.data.flushRange(offset, offset+length); err != nil {
			return toLinuxErr(err)
		}
		if err := ino.n.punchHole(offset, length); err != nil {
			return toLinuxErr(err)
		}
		ino.data.punched(offset, length)
		ino.touchMCtime()
		return nil
	}
	ino.n.mu.RLock()
	old := ino.n.size
	ino.n.mu.RUnlock()
	if err := ino.n.preallocate(offset, length, keepSize); err != nil {
		return toLinuxErr(err)
	}
	ino.n.mu.RLock()
	size := ino.n.size
	ino.n.mu.RUnlock()
	ino.data.truncated(old, size)
	ino.touchMCtime()
	return nil
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (fd *regularFD) ConfigureMMap(ctx context.Context, opts *memmap.MMapOpts) error {
	if err := vfs.GenericConfigureMMap(&fd.vfsfd, &fd.dentry.inode.data, opts); err != nil {
		return err
	}
	opts.SentryOwnedContent = true
	return nil
}
