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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	// minTimeSec and maxTimeSec bound the seconds that an inode stores. The
	// on-disk format holds a signed 32-bit value and two bits of epoch.
	minTimeSec = -(1 << 31)
	maxTimeSec = 3<<32 + 1<<31 - 1
)

func statxTimestamp(t tstamp) linux.StatxTimestamp {
	return linux.StatxTimestamp{Sec: t.sec, Nsec: t.nsec}
}

// timeFromStatx converts a timestamp of a set-time request. The value now
// replaces UTIME_NOW.
func timeFromStatx(ts linux.StatxTimestamp, now tstamp) tstamp {
	if ts.Nsec == linux.UTIME_NOW {
		return now
	}
	return tstamp{sec: min(max(ts.Sec, minTimeSec), maxTimeSec), nsec: ts.Nsec}
}

// statx builds the stat result of the inode.
func (i *inode) statx() linux.Statx {
	a := i.attr()
	st := linux.Statx{
		Mask:     linux.STATX_BASIC_STATS | linux.STATX_BTIME,
		Blksize:  blockSize,
		Nlink:    a.links,
		UID:      a.uid,
		GID:      a.gid,
		Mode:     a.mode,
		Ino:      uint64(i.ino),
		Size:     a.size,
		Blocks:   a.nblocks * (blockSize / 512),
		Atime:    statxTimestamp(a.atime),
		Mtime:    statxTimestamp(a.mtime),
		Ctime:    statxTimestamp(a.ctime),
		Btime:    statxTimestamp(a.crtime),
		DevMajor: linux.UNNAMED_MAJOR,
		DevMinor: i.fs.devMinor,
	}
	if i.kind == modeChar || i.kind == modeBlock {
		st.RdevMajor, st.RdevMinor = decodeRdev(a.rdev)
	}
	return st
}

// touchAtime sets the access time to now. A mount with noatime and a read-only
// volume keep the old time.
func (i *inode) touchAtime(mnt *vfs.Mount) {
	if i.fs.readOnly || mnt.Options().Flags.NoATime {
		return
	}
	if err := mnt.CheckBeginWrite(); err != nil {
		return
	}
	defer mnt.EndWrite()
	now := i.fs.now()
	i.mutate(func(n *node) { n.atime = now })
}

// truncate sets the size of a regular file and trims the mapped-page cache.
func (i *inode) truncate(size uint64) error {
	i.wmu.Lock()
	defer i.wmu.Unlock()
	return i.truncateLocked(size)
}

// truncateLocked is truncate for a caller that holds i.wmu.
func (i *inode) truncateLocked(size uint64) error {
	i.n.mu.RLock()
	old := i.n.size
	i.n.mu.RUnlock()
	if err := i.n.truncate(size); err != nil {
		return toLinuxErr(err)
	}
	i.data.truncated(old, size)
	i.touchMCtime()
	return nil
}

// setStat applies opts to the inode. The caller holds no filesystem lock,
// because a truncation calls into the memory manager.
func (i *inode) setStat(ctx context.Context, creds *auth.Credentials, mnt *vfs.Mount, opts *vfs.SetStatOptions) error {
	stat := &opts.Stat
	mask := stat.Mask
	if mask == 0 {
		return nil
	}
	if mask&^(linux.STATX_MODE|linux.STATX_UID|linux.STATX_GID|linux.STATX_ATIME|linux.STATX_MTIME|linux.STATX_CTIME|linux.STATX_SIZE) != 0 {
		return linuxerr.EPERM
	}
	mode, uid, gid := i.owner()
	if err := vfs.CheckSetStat(ctx, creds, opts, mode, nil, uid, gid); err != nil {
		return err
	}
	if opts.NeedWritePerm {
		// truncate(2) needs write access, so it fails on a file that a process
		// executes.
		if err := i.writeCount.CheckWrite(); err != nil {
			return err
		}
	}
	return i.fs.writeOp(mnt, func() error {
		bumpC := false
		if mask&linux.STATX_SIZE != 0 {
			switch {
			case i.isDir():
				return linuxerr.EISDIR
			case !i.isRegular():
				return linuxerr.EINVAL
			}
			if err := i.truncate(stat.Size); err != nil {
				return err
			}
		}
		now := i.fs.now()
		clearPrivs := opts.ClearPrivs
		i.mutate(func(n *node) {
			if mask&linux.STATX_UID != 0 {
				n.uid = stat.UID
				bumpC = true
			}
			if mask&linux.STATX_GID != 0 {
				n.gid = stat.GID
				bumpC = true
			}
			if mask&linux.STATX_MODE != 0 {
				m := (n.mode & modeTypeMask) | uint16(stat.Mode&0o7777)
				if clearPrivs {
					m = clearSUIDAndSGID(m)
					clearPrivs = false
				}
				n.mode = m
				bumpC = true
			}
			if clearPrivs {
				n.mode = clearSUIDAndSGID(n.mode)
				bumpC = true
			}
			if mask&linux.STATX_ATIME != 0 {
				n.atime = timeFromStatx(stat.Atime, now)
				bumpC = true
			}
			if mask&linux.STATX_MTIME != 0 {
				n.mtime = timeFromStatx(stat.Mtime, now)
				bumpC = true
			}
			if mask&linux.STATX_CTIME != 0 {
				n.ctime = timeFromStatx(stat.Ctime, now)
				bumpC = false
			}
			if bumpC {
				n.ctime = now
			}
		})
		if opts.ClearPrivs {
			// A change of the content or the owner removes the file capabilities.
			if err := i.n.removeXattr(linux.XATTR_SECURITY_CAPABILITY); err != nil && !linuxerr.Equals(linuxerr.ENODATA, err) {
				return toLinuxErr(err)
			}
		}
		return nil
	})
}

// SetStatAt implements vfs.FilesystemImpl.SetStatAt.
func (fs *filesystem) SetStatAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.SetStatOptions) error {
	fs.lock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return err
	}
	d.IncRef()
	fs.unlock(ctx)
	defer d.DecRef(ctx)
	if err := d.inode.setStat(ctx, rp.Credentials(), rp.Mount(), &opts); err != nil {
		return err
	}
	if ev := vfs.InotifyEventFromStatMask(opts.Stat.Mask); ev != 0 {
		d.InotifyWithParent(ctx, ev, 0, vfs.InodeEvent)
	}
	return nil
}
