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
		err := d.fs.writeOp(mnt, func() error { return d.inode.truncate(0) })
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
	return toLinuxErr(fd.dentry.inode.data.TakeWritebackErr())
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (fd *regularFD) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	if offset < 0 {
		return 0, linuxerr.EINVAL
	}
	if err := checkRWFlags(opts.Flags); err != nil {
		return 0, err
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
	if err := ino.flushMapped(uint64(offset), end); err != nil {
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
	if err := checkRWFlags(opts.Flags); err != nil {
		return 0, offset, err
	}
	d := fd.dentry
	if d.fs.readOnly {
		return 0, offset, linuxerr.EROFS
	}
	// A write that finds no free block while freed blocks wait for a flush
	// flushes once with the gate open and writes the rest.
	cur, pos := src, offset
	var total int64
	var werr error
	for retry := 0; ; retry++ {
		n, end, err := fd.pwriteGated(ctx, cur, pos, opts)
		total += n
		finalOff, werr = end, err
		if !errors.Is(err, errSpaceHeld) || retry > 0 || !d.fs.v.hasHeld() {
			break
		}
		if serr := d.fs.v.sync(); serr != nil {
			return total, finalOff, toLinuxErr(serr)
		}
		cur, pos = cur.DropFirst64(n), end
	}
	if werr != nil {
		return total, finalOff, toLinuxErr(werr)
	}
	durable := fd.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 || opts.Flags&(linux.RWF_DSYNC|linux.RWF_SYNC) != 0
	if total > 0 && durable {
		// Without a durable write the call cannot honour the sync flag, so it
		// reports no progress, as Linux does for a failed generic_write_sync.
		if err := d.fs.syncInode(d.inode); err != nil {
			return 0, offset, err
		}
	}
	return total, finalOff, nil
}

// pwriteGated writes in the operation gate. It returns the bytes that it wrote,
// the offset behind them, and the raw error of the engine, so that pwrite can
// recognize a request that waits for a flush. The gate comes before wmu, as in
// every other operation.
func (fd *regularFD) pwriteGated(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (written, finalOff int64, err error) {
	d := fd.dentry
	ino := d.inode
	if err := d.fs.v.throttle(); err != nil {
		return 0, offset, err
	}
	d.fs.v.gate.enterOp()
	defer d.fs.v.gate.exit()
	ino.wmu.Lock()
	defer ino.wmu.Unlock()

	if appendsWrite(fd.vfsfd.StatusFlags(), opts.Flags) {
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
			nd.mode = writeClearPrivsMode(ctx, nd.mode, nd.uid, nd.gid)
		})
		if err := ino.killCapability(); err != nil {
			return n, offset + n, err
		}
	}
	return n, offset + n, err
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
//
// The write-back of mapped data needs ino.wmu. The flush of the volume runs
// without it. The flush waits until no operation runs in the gate, and a write
// that already entered the gate waits for ino.wmu, so a flush under ino.wmu
// would wait for that write without end.
func (fs *filesystem) syncInode(ino *inode) error {
	var errs []error
	ino.wmu.Lock()
	err := ino.data.SyncData()
	ino.wmu.Unlock()
	if err != nil {
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
		if err := ino.flushMapped(0, math.MaxUint64); err != nil {
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

// Allocate implements vfs.FileDescriptionImpl.Allocate. It serves the modes of
// ext4: a reservation (mode 0 and FALLOC_FL_KEEP_SIZE), FALLOC_FL_PUNCH_HOLE
// with FALLOC_FL_KEEP_SIZE, FALLOC_FL_ZERO_RANGE with or without
// FALLOC_FL_KEEP_SIZE, FALLOC_FL_COLLAPSE_RANGE, and FALLOC_FL_INSERT_RANGE.
// The checks and their order follow vfs_fallocate and ext4_fallocate.
func (fd *regularFD) Allocate(ctx context.Context, mode, offset, length uint64) error {
	if length == 0 || offset > math.MaxInt64 || length > math.MaxInt64 {
		return linuxerr.EINVAL
	}
	op, keepSize, err := parseAllocMode(mode)
	if err != nil {
		return err
	}
	if offset+length < offset || offset+length > maxFileSize {
		return linuxerr.EFBIG
	}
	d := fd.dentry
	ino := d.inode
	if !keepSize && limits.FromContext(ctx) != nil && (op == allocReserve || op == allocZero && offset+length > ino.size()) {
		// Like Linux, a call that grows the file past RLIMIT_FSIZE fails whole.
		// The system call turns the error into SIGXFSZ and EFBIG.
		limit, err := vfs.CheckLimit(ctx, int64(offset), int64(length))
		if err != nil {
			return err
		}
		if limit < int64(length) {
			return linuxerr.ErrExceedsFileSizeLimit
		}
	}
	return d.fs.writeOp(fd.vfsfd.Mount(), func() error { return fd.allocateLocked(ino, op, offset, length, keepSize) })
}

// ServesFallocateModes marks the description for the fallocate system call. The
// call forwards a mode other than 0 only to a description with this method.
func (fd *regularFD) ServesFallocateModes() {}

// size returns the size of the file.
func (i *inode) size() uint64 {
	i.n.mu.RLock()
	defer i.n.mu.RUnlock()
	return i.n.size
}

// allocateLocked runs a validated fallocate in the operation gate. The gate
// comes before wmu, as in every operation. Dirty mapped pages in the range reach
// the engine first, so the engine change covers them as well.
func (fd *regularFD) allocateLocked(ino *inode, op allocOp, offset, length uint64, keepSize bool) error {
	ino.wmu.Lock()
	defer ino.wmu.Unlock()
	old := ino.size()
	switch op {
	case allocPunch:
		if err := ino.data.FlushRange(offset, offset+length); err != nil {
			return toLinuxErr(err)
		}
		if err := ino.n.punchHole(offset, length); err != nil {
			return toLinuxErr(err)
		}
		ino.data.Punched(offset, length)
	case allocZero:
		if err := ino.data.FlushRange(offset, offset+length); err != nil {
			return toLinuxErr(err)
		}
		if err := ino.n.zeroRange(offset, length, keepSize); err != nil {
			return toLinuxErr(err)
		}
		ino.data.Punched(offset, length)
		ino.data.truncated(old, ino.size())
	case allocCollapse, allocInsert:
		// Every byte from the offset on moves. The cache writes back, changes,
		// and reloads under its own locks, so a mapped store never falls between.
		change := ino.n.collapseRange
		if op == allocInsert {
			change = ino.n.insertRange
		}
		if err := ino.data.ShiftFrom(offset, func() error { return change(offset, length) }); err != nil {
			return toLinuxErr(err)
		}
	default:
		if err := ino.n.preallocate(offset, length, keepSize); err != nil {
			return toLinuxErr(err)
		}
		ino.data.truncated(old, ino.size())
	}
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
