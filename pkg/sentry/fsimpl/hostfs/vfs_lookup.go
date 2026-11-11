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

	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// lookupChildLocked finds name in parent. The returned error is a Linux errno.
//
// Consistency contract: a result that this filesystem produced or confirmed
// stays valid for cacheTTL without a host call. A guest mutation of the entry,
// of a hard link to it, or of its parent drops the result at once. A listing
// of the parent drops the missing names and the entries that now name another
// host object. A change by a host process, or through another mount of the
// same host directory, shows up after cacheTTL at the latest.
func (fs *filesystem) lookupChildLocked(parent *dentry, name string) (*dentry, error) {
	now := fs.ws.nowNano()
	child := parent.children[name]
	if child != nil {
		if child.inode.metaFresh(now) {
			return child, nil
		}
	} else if parent.inode.negHit(name, now) {
		return nil, linuxerr.ENOENT
	}
	var seq uint64
	if child != nil {
		seq = child.inode.beginMeta()
	}
	e, err := fs.ws.lookupIn(parent.relPath, name)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) {
			if child != nil {
				fs.dropLocked(child)
			}
			parent.inode.negAdd(name, now)
		}
		return nil, translateLookupError(err)
	}
	until := now + int64(cacheTTL)
	if child != nil {
		if child.inode.matches(e) {
			child.inode.commitMeta(e, seq, until)
			return child, nil
		}
		fs.dropLocked(child)
	}
	return fs.attachChildLocked(parent, name, joinRelPath(parent.relPath, name), e, until), nil
}

// refreshLocked revalidates d against the host. It makes no host call while
// the cached metadata of d is valid.
func (fs *filesystem) refreshLocked(d *dentry) error {
	if d.dead {
		return nil
	}
	now := fs.ws.nowNano()
	if d.inode.metaFresh(now) {
		return nil
	}
	seq := d.inode.beginMeta()
	e, err := fs.ws.lookupPath(d.relPath)
	if err != nil {
		if errors.Is(err, iofs.ErrNotExist) && d != fs.root {
			fs.dropLocked(d)
		}
		return translateLookupError(err)
	}
	if !d.inode.matches(e) {
		if d != fs.root {
			fs.dropLocked(d)
		}
		return linuxerr.ENOENT
	}
	d.inode.commitMeta(e, seq, now+int64(cacheTTL))
	return nil
}

// stepLocked resolves rp.Component() below d. The Boolean result reports that
// a symbolic link was followed.
//
// Preconditions: fs.mu is held and !rp.Done().
func (fs *filesystem) stepLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, bool, error) {
	if !d.inode.isDir() {
		return nil, false, linuxerr.ENOTDIR
	}
	if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return nil, false, err
	}
	name := rp.Component()
	if name == "." {
		rp.Advance()
		return d, false, nil
	}
	if name == ".." {
		if isRoot, err := rp.CheckRoot(ctx, &d.vfsd); err != nil {
			return nil, false, err
		} else if isRoot || d.parent == nil {
			rp.Advance()
			return d, false, nil
		}
		parent := d.parent
		if err := rp.CheckMount(ctx, &parent.vfsd); err != nil {
			return nil, false, err
		}
		rp.Advance()
		return parent, false, nil
	}
	if len(name) > maxFilenameLen {
		return nil, false, linuxerr.ENAMETOOLONG
	}
	child, err := fs.lookupChildLocked(d, name)
	if err != nil {
		return nil, false, err
	}
	if err := rp.CheckMount(ctx, &child.vfsd); err != nil {
		return nil, false, err
	}
	if child.inode.isSymlink() && rp.ShouldFollowSymlink() {
		followed, err := rp.HandleSymlink(child.inode.snapshot().attr.Symlink)
		return d, followed, err
	}
	rp.Advance()
	return child, false, nil
}

// walkParentDirLocked resolves all but the last component of rp to a
// directory. It does not check that the caller may search the result.
//
// Preconditions: fs.mu is held and !rp.Done().
func (fs *filesystem) walkParentDirLocked(ctx context.Context, rp *vfs.ResolvingPath, d *dentry) (*dentry, error) {
	for !rp.Final() {
		next, _, err := fs.stepLocked(ctx, rp, d)
		if err != nil {
			return nil, err
		}
		d = next
	}
	if !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// resolveLocked resolves rp to an existing file.
//
// Preconditions: fs.mu is held.
func (fs *filesystem) resolveLocked(ctx context.Context, rp *vfs.ResolvingPath) (*dentry, error) {
	start := rp.Start().Impl().(*dentry)
	d := start
	if d.inode.isSymlink() && rp.Done() && rp.ShouldFollowSymlink() {
		if _, err := rp.HandleSymlink(d.inode.snapshot().attr.Symlink); err != nil {
			return nil, err
		}
	} else {
		for !rp.Done() {
			next, _, err := fs.stepLocked(ctx, rp, d)
			if err != nil {
				return nil, err
			}
			d = next
		}
		if d == start {
			if err := fs.refreshLocked(d); err != nil {
				return nil, err
			}
		}
	}
	if rp.MustBeDir() && !d.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	return d, nil
}

// AccessAt implements vfs.FilesystemImpl.AccessAt.
func (fs *filesystem) AccessAt(ctx context.Context, rp *vfs.ResolvingPath, creds *auth.Credentials, ats vfs.AccessTypes) error {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return err
	}
	if err := d.inode.checkPermissions(creds, ats); err != nil {
		return err
	}
	if ats.MayWrite() && fs.ws.ReadOnly() {
		return linuxerr.EROFS
	}
	return vfs.CheckMountAccess(rp, ats, d.inode.mode())
}

// GetDentryAt implements vfs.FilesystemImpl.GetDentryAt.
func (fs *filesystem) GetDentryAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.GetDentryOptions) (*vfs.Dentry, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if opts.CheckSearchable {
		if !d.inode.isDir() {
			return nil, linuxerr.ENOTDIR
		}
		if err := d.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
			return nil, err
		}
	}
	d.IncRef()
	return &d.vfsd, nil
}

// GetParentDentryAt implements vfs.FilesystemImpl.GetParentDentryAt.
func (fs *filesystem) GetParentDentryAt(ctx context.Context, rp *vfs.ResolvingPath) (*vfs.Dentry, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return nil, err
	}
	d.IncRef()
	return &d.vfsd, nil
}

// ReadlinkAt implements vfs.FilesystemImpl.ReadlinkAt.
func (fs *filesystem) ReadlinkAt(ctx context.Context, rp *vfs.ResolvingPath) (string, error) {
	fs.lock()
	defer fs.unlock(ctx)
	d, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return "", err
	}
	if !d.inode.isSymlink() {
		return "", linuxerr.EINVAL
	}
	return d.inode.snapshot().attr.Symlink, nil
}

// PrependPath implements vfs.FilesystemImpl.PrependPath.
func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	mnt := vd.Mount()
	d := vd.Dentry().Impl().(*dentry)
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if mnt != nil && &d.vfsd == mnt.Root() {
			return nil
		}
		if d.dead {
			return vfs.PrependPathSyntheticError{}
		}
		if d.parent == nil {
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}

// IsDescendant implements vfs.FilesystemImpl.IsDescendant.
func (fs *filesystem) IsDescendant(vfsroot, vd vfs.VirtualDentry) bool {
	if vfsroot.Mount() != vd.Mount() {
		return false
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return isAncestorLocked(vfsroot.Dentry().Impl().(*dentry), vd.Dentry().Impl().(*dentry))
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// InotifyWithParent implements vfs.DentryImpl.InotifyWithParent.
func (d *dentry) InotifyWithParent(ctx context.Context, events, cookie uint32, et vfs.EventType) {
	if parent, name := d.names(); parent != nil {
		parent.inode.watches.Notify(ctx, name, events, cookie, et, false)
	}
	d.inode.watches.Notify(ctx, "", events, cookie, et, false)
}

// AdmitInotifyWatch is called by inotify_add_watch(2) before a new guest watch
// joins d. It attaches the host watch and returns ENOSPC when the workspace
// already watches as many other objects as the cap allows (see watchlimit.go).
func (d *dentry) AdmitInotifyWatch() error {
	err := d.fs.ws.watchDentry(d)
	if err == nil {
		return nil
	}
	if linuxerr.Equals(linuxerr.ENOSPC, err) {
		return linuxerr.ENOSPC
	}
	d.fs.ws.logWatchRefusal(d, err)
	return nil
}

// Watches implements vfs.DentryImpl.Watches.
func (d *dentry) Watches() *vfs.Watches {
	if err := d.fs.ws.watchDentry(d); err != nil {
		d.fs.ws.logWatchRefusal(d, err)
	}
	return &d.inode.watches
}

// OnZeroWatches implements vfs.DentryImpl.OnZeroWatches.
func (d *dentry) OnZeroWatches(ctx context.Context) {
	d.fs.ws.unwatchDentry(d)
}

// dropLocked removes d and its cached children from the tree after the host
// object they described changed or vanished.
func (fs *filesystem) dropLocked(d *dentry) {
	for _, c := range d.children {
		fs.dropLocked(c)
	}
	fs.detachLocked(d)
	deferDecRef(fs, fs.vfsfs.VirtualFilesystem().InvalidateDentry(context.Background(), &d.vfsd))
}

// detachLocked removes d from its parent's child map and drops the cache
// reference. Open files and mounts keep the dentry alive.
func (fs *filesystem) detachLocked(d *dentry) {
	if d.dead {
		return
	}
	d.dead = true
	if d.parent != nil && d.parent.children[d.name] == d {
		delete(d.parent.children, d.name)
	}
	d.decRefLocked()
}

// pruneLocked drops dentries that only the cache references.
func (fs *filesystem) pruneLocked(d *dentry) {
	for _, c := range d.children {
		fs.pruneLocked(c)
	}
	if d != fs.root && len(d.children) == 0 && d.refs.Load() == 1 && !d.inode.pinnedLocked() {
		fs.detachLocked(d)
	}
}

func (fs *filesystem) maybePruneLocked() {
	if fs.dentryCount < fs.pruneAt {
		return
	}
	fs.pruneLocked(fs.root)
	if fs.dentryCount > fs.pruneAt/2 {
		fs.pruneAt *= 2
	}
}

// attachChildLocked creates the dentry for entry e below parent. A non-zero
// until marks the metadata of a new inode as valid up to that time.
func (fs *filesystem) attachChildLocked(parent *dentry, name, rel string, e entry, until int64) *dentry {
	fs.maybePruneLocked()
	ino := fs.inodeForLocked(e, rel)
	fresh := ino.refs == 0
	d := fs.newDentryLocked(parent, name, rel, ino)
	if fresh && until != 0 {
		ino.markValid(until)
	}
	return d
}
