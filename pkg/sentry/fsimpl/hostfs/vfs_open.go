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
	iofs "io/fs"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// OpenAt implements vfs.FilesystemImpl.OpenAt.
func (fs *filesystem) OpenAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_TMPFILE != 0 {
		return fs.openTmpfile(ctx, rp, opts)
	}
	if opts.Flags&linux.O_CREAT == 0 {
		return fs.openExistingAt(ctx, rp, &opts)
	}
	return fs.openCreateAt(ctx, rp, &opts)
}

func (fs *filesystem) openExistingAt(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	fs.lock()
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		fs.unlock(ctx)
		return nil, err
	}
	d.IncRef()
	fs.unlock(ctx)
	defer d.DecRef(ctx)
	return d.open(ctx, rp, opts, nil)
}

func (fs *filesystem) openCreateAt(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions) (*vfs.FileDescription, error) {
	mustCreate := opts.Flags&linux.O_EXCL != 0
	start := rp.Start().Impl().(*dentry)
	fs.lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.unlock(ctx)
			unlocked = true
		}
	}
	defer unlock()

	if rp.Done() {
		if rp.MustBeDir() {
			return nil, linuxerr.EISDIR
		}
		if mustCreate {
			return nil, linuxerr.EEXIST
		}
		if err := fs.refreshLocked(start); err != nil {
			return nil, err
		}
		start.IncRef()
		defer start.DecRef(ctx)
		unlock()
		return start.open(ctx, rp, opts, nil)
	}

	retriedExist := false
	for {
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
			continue
		}
		if linuxerr.Equals(linuxerr.ENOENT, err) {
			createdChild, createdHandle, retry, createErr := fs.createChildForOpenLocked(rp, parent, name, opts.Mode, mustCreate, retriedExist)
			if retry {
				retriedExist = true
				start = parent
				continue
			}
			if createErr != nil {
				return nil, createErr
			}
			defer createdChild.DecRef(ctx)
			unlock()
			fd, err := createdChild.open(ctx, rp, opts, createdHandle)
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
		return child.open(ctx, rp, opts, nil)
	}
}

func (fs *filesystem) createChildForOpenLocked(rp *vfs.ResolvingPath, parent *dentry, name string, mode linux.FileMode, mustCreate, retriedExist bool) (*dentry, *hostHandle, bool, error) {
	if name == "." || name == ".." {
		return nil, nil, false, linuxerr.EISDIR
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return nil, nil, false, err
	}
	if err := rp.Mount().CheckBeginWrite(); err != nil {
		return nil, nil, false, err
	}
	defer rp.Mount().EndWrite()
	rel := joinRelPath(parent.relPath, name)
	uid, gid, _ := newOwner(parent.inode, rp.Credentials())
	f, e, err := fs.ws.createHandle(rel, uint32(mode)&0o7777, uint32(uid), uint32(gid))
	if errors.Is(err, iofs.ErrExist) && !mustCreate && !retriedExist {
		// A host process created the name after the negative entry. Drop
		// the entry and resolve the name again, once.
		parent.inode.negDel(name)
		return nil, nil, true, nil
	}
	if err != nil {
		return nil, nil, false, translateHostError(err)
	}
	parent.inode.negDel(name)
	parent.inode.invalidateMeta()
	child := fs.attachChildLocked(parent, name, rel, e, fs.ws.nowNano()+int64(cacheTTL))
	child.IncRef()
	return child, f, false, nil
}

// open creates the file description for d. created is the host handle of a
// file that OpenAt just created, or nil.
//
// Preconditions: fs.mu is not held.
func (d *dentry) open(ctx context.Context, rp *vfs.ResolvingPath, opts *vfs.OpenOptions, created *hostHandle) (*vfs.FileDescription, error) {
	closeCreated := func() {
		if created != nil {
			_ = created.decRef()
		}
	}
	ats := vfs.AccessTypesForOpenFlags(opts)
	if opts.FileExec && !d.inode.isRegular() && !d.inode.isSymlink() {
		closeCreated()
		return nil, linuxerr.EACCES
	}
	if created == nil {
		if err := d.inode.checkPermissions(rp.Credentials(), ats); err != nil {
			return nil, err
		}
		// Linux rejects a write open of a running program. The check covers
		// O_TRUNC, which AccessTypesForOpenFlags folds into the write access.
		if ats.MayWrite() {
			if err := d.inode.checkWritable(); err != nil {
				return nil, err
			}
		}
	}
	switch {
	case d.inode.isRegular():
		return d.openRegular(ctx, rp, opts, created)
	case d.inode.isDir():
		closeCreated()
		if opts.Flags&linux.O_CREAT != 0 || ats&vfs.MayWrite != 0 {
			return nil, linuxerr.EISDIR
		}
		if opts.Flags&linux.O_DIRECT != 0 {
			return nil, linuxerr.EINVAL
		}
		fd := &dirFD{}
		fd.dentry = d
		fd.LockFD.Init(&d.inode.locks)
		if err := fd.vfsfd.Init(fd, opts.Flags, rp.Credentials(), rp.Mount(), &d.vfsd, &vfs.FileDescriptionOptions{AllowDirectIO: true}); err != nil {
			return nil, err
		}
		return &fd.vfsfd, nil
	case d.inode.isSpecial():
		closeCreated()
		return d.openSpecial(ctx, rp, opts)
	default:
		closeCreated()
		// Symlinks open only with O_PATH, which the VFS layer handles.
		return nil, linuxerr.ELOOP
	}
}
