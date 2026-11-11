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
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.lock()
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return err
	}
	d.IncRef()
	fs.unlock(ctx)
	defer d.DecRef(ctx)
	if err := d.setStat(ctx, rp.Credentials(), rp.Mount(), &opts, nil); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}

// setStat applies opts to d. h is the open host handle when the caller is a
// file description, which lets truncation work on an unlinked file.
//
// Preconditions: fs.mu is not held.
func (d *dentry) setStat(ctx context.Context, creds *auth.Credentials, mnt *vfs.Mount, opts *vfs.SetStatOptions, h *hostHandle) error {
	e := d.inode.snapshot()
	if err := vfs.CheckSetStat(ctx, creds, opts, linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)); err != nil {
		return err
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if d.fs.ws.ReadOnly() {
		return linuxerr.EROFS
	}
	if err := d.applyTruncateStat(opts, e, h); err != nil {
		return err
	}
	if err := d.applyModeAndOwnerStat(opts, e); err != nil {
		return err
	}
	if err := d.applyTimestampStat(&opts.Stat); err != nil {
		return err
	}
	d.inode.invalidateMeta()
	return d.refresh()
}

func (d *dentry) applyTruncateStat(opts *vfs.SetStatOptions, e entry, h *hostHandle) error {
	if opts.Stat.Mask&linux.STATX_SIZE == 0 {
		return nil
	}
	if err := checkTruncateFileType(uint32(e.attr.Mode)); err != nil {
		return err
	}
	if opts.NeedWritePerm {
		// truncate(2), unlike ftruncate(2), needs write access to the
		// file and so fails while a process executes it.
		if err := d.inode.checkWritable(); err != nil {
			return err
		}
	}
	return d.inode.truncate(d, h, int64(opts.Stat.Size))
}

func (d *dentry) applyModeAndOwnerStat(opts *vfs.SetStatOptions, e entry) error {
	stat := &opts.Stat
	var mode, uid, gid *uint32
	if stat.Mask&linux.STATX_MODE != 0 {
		m := uint32(stat.Mode) & 0o7777
		mode = &m
	}
	if stat.Mask&linux.STATX_UID != 0 {
		uid = &stat.UID
	}
	if stat.Mask&linux.STATX_GID != 0 {
		gid = &stat.GID
	}
	if opts.ClearPrivs && !d.inode.isDir() {
		m := clearSUIDAndSGID(uint32(e.attr.Mode)) & 0o7777
		if mode != nil {
			m = clearSUIDAndSGID(*mode|e.attr.Mode&linux.S_IFMT) & 0o7777
		}
		mode = &m
	}
	if mode == nil && uid == nil && gid == nil {
		return nil
	}
	return d.setAttr(mode, uid, gid)
}

func (d *dentry) applyTimestampStat(stat *linux.Statx) error {
	if stat.Mask&(linux.STATX_ATIME|linux.STATX_MTIME) == 0 {
		return nil
	}
	now := time.Now()
	var at, mt *time.Time
	if stat.Mask&linux.STATX_ATIME != 0 {
		t := statxTime(stat.Atime, now)
		at = &t
	}
	if stat.Mask&linux.STATX_MTIME != 0 {
		t := statxTime(stat.Mtime, now)
		mt = &t
	}
	if d.isDead() {
		return linuxerr.ENOENT
	}
	d.inode.guestBegin()
	err := d.fs.ws.chtimes(d.path(), at, mt)
	d.inode.guestEndPath(d.path())
	if err != nil {
		return translateHostError(err)
	}
	return nil
}

func (d *dentry) isDead() bool {
	d.fs.mu.Lock()
	defer d.fs.mu.Unlock()
	return d.dead
}

// setAttr changes virtual attributes. A dentry that no longer has a name
// updates only the inode snapshot that open files see.
func (d *dentry) setAttr(mode, uid, gid *uint32) error {
	if !d.isDead() {
		if err := d.fs.ws.setAttr(d.path(), mode, uid, gid); err != nil {
			return translateHostError(err)
		}
		d.inode.invalidateMeta()
		return nil
	}
	d.inode.attrMu.Lock()
	defer d.inode.attrMu.Unlock()
	a := &d.inode.cur.attr
	if mode != nil {
		a.Mode = a.Mode&linux.S_IFMT | *mode&0o7777
	}
	if uid != nil {
		a.UID = *uid
	}
	if gid != nil {
		a.GID = *gid
	}
	a.Ctime = time.Now().UnixNano()
	return nil
}

// refresh updates the inode snapshot from the host after a change. It makes
// no host call while the cached snapshot is valid.
func (d *dentry) refresh() error {
	return d.refreshAs(false)
}

// refreshIdentity is refresh for a caller that takes the size and the times
// from an open handle. A write leaves the cached snapshot valid for it.
func (d *dentry) refreshIdentity() error {
	return d.refreshAs(true)
}

func (d *dentry) refreshAs(identityOnly bool) error {
	if d.isDead() {
		return nil
	}
	now := d.fs.ws.nowNano()
	if identityOnly && d.inode.identityFresh(now) || !identityOnly && d.inode.metaFresh(now) {
		return nil
	}
	seq := d.inode.beginMeta()
	e, err := d.fs.ws.lookupPath(d.path())
	if err != nil {
		return translateHostError(err)
	}
	if d.inode.matches(e) {
		d.inode.commitMeta(e, seq, now+int64(cacheTTL))
	}
	return nil
}

// StatAt implements vfs.FilesystemImpl.StatAt.
func (fs *filesystem) StatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.StatOptions) (linux.Statx, error) {
	fs.lock()
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return linux.Statx{}, err
	}
	e := d.inode.snapshot()
	stat := d.inode.statxFor(e, fs.devMinor)
	if e.isDir() {
		stat.Nlink = d.dirLinks(e, stat.Nlink)
	}
	fs.unlock(ctx)
	rp.AddMountRootAttr(&d.vfsd, &stat)
	return stat, nil
}

// statxFor builds the stat result for entry e of this inode.
func (i *inode) statxFor(e entry, devMinor uint32) linux.Statx {
	info := e.info
	nlink := info.nlink
	switch {
	case i.unlinked.Load():
		// No name reaches the file. Linux and macOS report this through
		// fstat. A Windows file keeps a link count while a handle stays
		// open, and a named temporary file keeps its host name.
		nlink = 0
	case e.isDir() && nlink < 2:
		nlink = 2
	}
	btime := info.btime
	if btime.IsZero() {
		btime = info.mtime
	}
	mtime := info.mtime
	if e.attr.Mtime > mtime.UnixNano() {
		mtime = time.Unix(0, e.attr.Mtime)
	}
	ctime := info.ctime
	if e.attr.Ctime > ctime.UnixNano() {
		ctime = time.Unix(0, e.attr.Ctime)
	}
	blocks := uint64(info.blocks)
	if blocks == 0 && info.size > 0 {
		blocks = (uint64(info.size) + 511) / 512
	}
	rdevMajor, rdevMinor := unpackRdev(e.attr.Rdev)
	return newHostfsStatx(hostfsStatxAttr{
		Blksize:   4096,
		Nlink:     nlink,
		UID:       e.attr.UID,
		GID:       e.attr.GID,
		Mode:      uint16(e.attr.Mode),
		Ino:       i.ino,
		Size:      uint64(info.size),
		Blocks:    blocks,
		Atime:     statxTimestamp(info.atime),
		Mtime:     statxTimestamp(mtime),
		Ctime:     statxTimestamp(ctime),
		Btime:     statxTimestamp(btime),
		DevMajor:  0,
		DevMinor:  devMinor,
		RdevMajor: rdevMajor,
		RdevMinor: rdevMinor,
	})
}

// StatFSAt implements vfs.FilesystemImpl.StatFSAt. It reports the capacity of
// the host volume.
func (fs *filesystem) StatFSAt(ctx context.Context, rp *vfs.ResolvingPath) (linux.Statfs, error) {
	fs.lock()
	_, err := fs.resolveLocked(ctx, rp)
	fs.unlock(ctx)
	if err != nil {
		return linux.Statfs{}, err
	}
	return fs.statFS()
}

// GetPosixACLAt implements vfs.FilesystemImpl.GetPosixACLAt.
//
// hostfs does not enforce POSIX ACLs, so every file has none. The overlay
// filesystem reads the ACLs of each layer on every lookup and on mount. An
// error would make hostfs unusable as an overlay layer.
func (fs *filesystem) GetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType) (*vfs.PosixACL, error) {
	fs.lock()
	_, err := fs.resolveLocked(ctx, rp)
	fs.unlock(ctx)
	return nil, err
}

// SetPosixACLAt implements vfs.FilesystemImpl.SetPosixACLAt.
func (fs *filesystem) SetPosixACLAt(ctx context.Context, rp *vfs.ResolvingPath, t vfs.ACLType, acl *vfs.PosixACL, clearSGID bool) (*vfs.PosixACL, linux.FileMode, error) {
	return nil, 0, linuxerr.EOPNOTSUPP
}
