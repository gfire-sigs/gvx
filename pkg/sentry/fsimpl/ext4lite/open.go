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
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		return nil, linuxerr.EOPNOTSUPP
	}

	if opts.Flags&linux.O_CREAT == 0 {
		fs.lock(ctx)
		d, err := fs.resolveLocked(ctx, rp)
		if err != nil {
			fs.unlock(ctx)
			return nil, err
		}
		d.IncRef()
		fs.unlock(ctx)
		defer d.DecRef(ctx)
		return d.open(ctx, rp, &opts, false)
	}

	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	fs.lock(ctx)
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.unlock(ctx)
			unlocked = true
		}
	}
	defer unlock()
	if rp.Done() {
		// Reject attempts to open the mount root with O_CREAT.
		if rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.open(ctx, rp, &opts, false)
	}
afterTrailingSymlink:
	parent, err := fs.walkParentDirLocked(ctx, rp, start)
	if err != nil {
		return nil, err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, err
	}
	if rp.MustBeDir() {
		return nil, linuxerr.EISDIR
	}
	name := rp.Component()
	child, followed, err := fs.stepLocked(ctx, rp, parent)
	if followed {
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		if err != nil {
			return nil, err
		}
		start = parent
		goto afterTrailingSymlink
	}
	if linuxerr.Equals(linuxerr.ENOENT, err) {
		if name == "." || name == ".." {
			return nil, linuxerr.EISDIR
		}
		if parent.dead {
			return nil, linuxerr.ENOENT
		}
		if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
			return nil, err
		}
		mnt := rp.Mount()
		if err := fs.beginWrite(mnt); err != nil {
			return nil, err
		}
		defer mnt.EndWrite()
		uid, gid, _ := parent.inode.newOwner(rp.Credentials())
		ino, err := fs.newChildLocked(parent, name, modeRegular|uint16(opts.Mode&0o7777), uid, gid, 0, nil)
		if err != nil {
			return nil, err
		}
		child = fs.newDentryLocked(parent, name, ino)
		child.IncRef()
		defer child.DecRef(ctx)
		unlock()
		fd, err := child.open(ctx, rp, &opts, true)
		if err != nil {
			return nil, err
		}
		fd.SetCreated()
		parent.inode.watches.Notify(ctx, name, linux.IN_CREATE, 0, vfs.PathEvent, false)
		return fd, nil
	}
	if err != nil {
		return nil, err
	}
	if mustCreate {
		return nil, linuxerr.EEXIST
	}
	if rp.MustBeDir() && !child.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	child.IncRef()
	defer child.DecRef(ctx)
	unlock()
	return child.open(ctx, rp, &opts, false)
}

// open creates the file description of d. The afterCreate flag is set when
// OpenAt just created the file, which skips the permission checks as Linux does.
//
// Preconditions: no filesystem lock is held.
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, afterCreate bool) (*vfs.FileDescription, error) {
	ats := vfs.AccessTypesForOpenFlags(opts)
	ino := d.inode
	if opts.FileExec && !ino.isRegular() && !ino.isSymlink() {
		// Only regular files execute. Reject before the open can block on a
		// FIFO, as fs/namei.c:may_open() does. A symlink gets ELOOP below.
		return nil, linuxerr.EACCES
	}
	if !afterCreate {
		if err := ino.checkPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
		if ats.MayWrite() && ino.isRegular() {
			if d.fs.readOnly {
				return nil, linuxerr.EROFS
			}
			// A file that a process executes rejects writers, and O_TRUNC
			// counts as a write.
			if err := ino.writeCount.CheckWrite(); err != nil {
				return nil, err
			}
		}
	}
	switch ino.kind {
	case modeRegular:
		return d.openRegular(ctx, rp, opts, afterCreate)
	case modeDir:
		return d.openDir(ctx, rp, opts, ats)
	case modeSymlink:
		// A symlink opens only with O_PATH, which the VFS handles.
		return nil, linuxerr.ELOOP
	default:
		return d.openSpecial(ctx, rp, opts)
	}
}
