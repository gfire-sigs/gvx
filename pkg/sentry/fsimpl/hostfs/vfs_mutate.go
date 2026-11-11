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
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// newOwner returns the owner of a new child: the filesystem IDs of the caller,
// as inode_init_owner uses, with the group inherited from a set-group-ID
// parent directory. The filesystem IDs differ from the effective IDs in an
// overlay upper layer, where the mounter's credentials carry the fsuid of the
// caller.
func newOwner(parent *inode, creds *auth.Credentials) (auth.KUID, auth.KGID, bool) {
	e := parent.snapshot()
	if linux.FileMode(e.attr.Mode)&linux.ModeSetGID != 0 {
		return creds.FilesystemKUID, auth.KGID(e.attr.GID), true
	}
	return creds.FilesystemKUID, creds.FilesystemKGID, false
}

// doCreateAt checks that creating a file at rp is permitted, then calls create.
//
// Preconditions: !rp.Done() and rp.ShouldFollowSymlink() is false for the last
// component.
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name, rel string) error) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EEXIST
	}
	if len(name) > maxFilenameLen {
		return linuxerr.ENAMETOOLONG
	}
	if _, err := fs.lookupChildLocked(parent, name); err == nil {
		return linuxerr.EEXIST
	} else if !linuxerr.Equals(linuxerr.ENOENT, err) {
		return err
	}
	if !dir && rp.MustBeDir() {
		return linuxerr.ENOENT
	}
	if parent.dead {
		return linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
		return err
	}
	if err := create(parent, name, joinRelPath(parent.relPath, name)); err != nil {
		if linuxerr.Equals(linuxerr.EEXIST, err) {
			// The name exists on the host, so a negative entry is stale.
			parent.inode.negDel(name)
		}
		return err
	}
	parent.inode.negDel(name)
	parent.inode.invalidateMeta()
	ev := linux.IN_CREATE
	if dir {
		ev |= linux.IN_ISDIR
	}
	parent.inode.watches.Notify(ctx, name, uint32(ev), 0, vfs.InodeEvent, false)
	return nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt. It creates a real host hard
// link: both names share one host file, one inode number, and one link count.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name, rel string) error {
		if rp.Mount() != vd.Mount() {
			return linuxerr.EXDEV
		}
		src := vd.Dentry().Impl().(*dentry)
		if src.dead {
			// An unnamed file from O_TMPFILE is the only dead file that can
			// gain a name.
			return fs.linkTmpLocked(rp.Credentials(), src, parent, name, rel)
		}
		if src.inode.isDir() {
			return linuxerr.EPERM
		}
		e := src.inode.snapshot()
		if err := vfs.MayLink(rp.Credentials(), linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)); err != nil {
			return err
		}
		if err := fs.ws.link(src.relPath, rel); err != nil {
			return translateHostError(err)
		}
		// The link count of the shared inode changed.
		src.inode.invalidateMeta()
		src.inode.fs.ws.watchNoteInode(src.inode)
		src.inode.watches.Notify(ctx, "", linux.IN_ATTRIB, 0, vfs.InodeEvent, false)
		return nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true, func(parent *dentry, name, rel string) error {
		uid, gid, inherit := newOwner(parent.inode, rp.Credentials())
		mode := uint32(opts.Mode) & 0o7777
		if inherit {
			mode |= linux.S_ISGID
		}
		if err := fs.ws.mkdir(rel, mode, uint32(uid), uint32(gid)); err != nil {
			return translateHostError(err)
		}
		return nil
	})
}

// SymlinkAt implements vfs.FilesystemImpl.SymlinkAt. Symbolic links live in
// .gvx_meta: the host never receives a link, so no host link can leave the
// workspace.
func (fs *filesystem) SymlinkAt(ctx context.Context, rp *vfs.ResolvingPath, target string) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name, rel string) error {
		uid, gid, _ := newOwner(parent.inode, rp.Credentials())
		if err := fs.ws.symlink(target, rel, uint32(uid), uint32(gid)); err != nil {
			return translateHostError(err)
		}
		return nil
	})
}

// mayDelete reports whether creds may remove child from parent.
func mayDelete(creds *auth.Credentials, parent, child *inode) error {
	if err := parent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	pe, ce := parent.snapshot(), child.snapshot()
	return vfs.CheckDeleteSticky(creds, linux.FileMode(pe.attr.Mode), auth.KUID(pe.attr.UID), auth.KUID(ce.attr.UID), auth.KGID(ce.attr.GID))
}

// isAncestorLocked reports whether anc is d or an ancestor of d.
func isAncestorLocked(anc, d *dentry) bool {
	for ; d != nil; d = d.parent {
		if d == anc {
			return true
		}
	}
	return false
}

// RenameAt implements vfs.FilesystemImpl.RenameAt.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	fs.lock()
	defer fs.unlock(ctx)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	newName, err := validateRenameRequest(rp, oldParentVD, opts)
	if err != nil {
		return err
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()

	oldParent := oldParentVD.Dentry().Impl().(*dentry)
	if opts.Flags&linux.RENAME_EXCHANGE != 0 {
		return fs.exchangeAt(ctx, rp, newParent, newName, oldParent, oldName, opts)
	}

	renamed, replaced, noop, err := fs.resolveRenameTargetsLocked(rp, oldParent, oldName, newParent, newName, opts)
	if err != nil || noop {
		return err
	}
	return fs.executeRenameAtLocked(ctx, rp, oldParent, oldName, newParent, newName, renamed, replaced, opts)
}

func validateRenameRequest(rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, opts vfs.RenameOptions) (string, error) {
	if err := checkRenameFlags(opts.Flags); err != nil {
		return "", err
	}
	if opts.Flags&linux.RENAME_WHITEOUT != 0 {
		// Linux asks for CAP_MKNOD in the initial user namespace, because
		// the whiteout is a device node.
		creds := rp.Credentials()
		if !creds.HasCapabilityIn(linux.CAP_MKNOD, creds.UserNamespace.Root()) {
			return "", linuxerr.EPERM
		}
	}
	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return "", linuxerr.EEXIST
		}
		return "", linuxerr.EBUSY
	}
	if len(newName) > maxFilenameLen {
		return "", linuxerr.ENAMETOOLONG
	}
	if rp.Mount() != oldParentVD.Mount() {
		return "", linuxerr.EXDEV
	}
	return newName, nil
}

func (fs *filesystem) resolveRenameTargetsLocked(rp *vfs.ResolvingPath, oldParent *dentry, oldName string, newParent *dentry, newName string, opts vfs.RenameOptions) (renamed, replaced *dentry, noop bool, err error) {
	creds := rp.Credentials()
	if err := oldParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return nil, nil, false, err
	}
	renamed, err = fs.lookupChildLocked(oldParent, oldName)
	if err != nil {
		return nil, nil, false, err
	}
	if err := mayDelete(creds, oldParent.inode, renamed.inode); err != nil {
		return nil, nil, false, err
	}
	if renamed.inode.isDir() {
		if isAncestorLocked(renamed, newParent) {
			return nil, nil, false, linuxerr.EINVAL
		}
		if oldParent != newParent {
			if err := renamed.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
				return nil, nil, false, err
			}
		}
	} else if opts.MustBeDir || rp.MustBeDir() {
		return nil, nil, false, linuxerr.ENOTDIR
	}
	if err := newParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return nil, nil, false, err
	}
	replaced, err = fs.lookupChildLocked(newParent, newName)
	if err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
		return nil, nil, false, err
	}
	if err != nil {
		replaced = nil
	}
	if replaced != nil {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return nil, nil, false, linuxerr.EEXIST
		}
		if err := mayDelete(creds, newParent.inode, replaced.inode); err != nil {
			return nil, nil, false, err
		}
		if replaced.inode.isDir() {
			if !renamed.inode.isDir() {
				return nil, nil, false, linuxerr.EISDIR
			}
		} else if rp.MustBeDir() || renamed.inode.isDir() {
			return nil, nil, false, linuxerr.ENOTDIR
		}
		if renamed == replaced || (renamed.inode == replaced.inode && !renamed.inode.isDir()) {
			return nil, nil, true, nil
		}
	}
	if newParent.dead {
		return nil, nil, false, linuxerr.ENOENT
	}
	return renamed, replaced, false, nil
}

func (fs *filesystem) executeRenameAtLocked(ctx context.Context, rp *vfs.ResolvingPath, oldParent *dentry, oldName string, newParent *dentry, newName string, renamed, replaced *dentry, opts vfs.RenameOptions) error {
	oldRel := joinRelPath(oldParent.relPath, oldName)
	newRel := joinRelPath(newParent.relPath, newName)
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	var replacedVFSD *vfs.Dentry
	if replaced != nil {
		replacedVFSD = &replaced.vfsd
	}
	handle, err := vfsObj.PrepareRenameDentry(mntns, &renamed.vfsd, replacedVFSD)
	if err != nil {
		return err
	}
	vfsObj.RenameBegin(&handle)
	var replacedLinks uint32
	if replaced != nil {
		replacedLinks = fs.specialLinksLocked(replaced)
	}
	whiteout := opts.Flags&linux.RENAME_WHITEOUT != 0
	var renameErr error
	if whiteout {
		renameErr = fs.ws.renameWhiteout(oldRel, newRel)
	} else {
		renameErr = fs.ws.rename(oldRel, newRel)
	}
	if renameErr != nil {
		vfsObj.AbortRenameDentry(&handle, &renamed.vfsd, replacedVFSD)
		return translateHostError(renameErr)
	}
	now := fs.ws.nowNano()
	renamed.inode.invalidateMeta()
	oldParent.inode.invalidateMeta()
	newParent.inode.invalidateMeta()
	if whiteout {
		oldParent.inode.negDel(oldName)
	} else {
		oldParent.inode.negAdd(oldName, now)
	}
	newParent.inode.negDel(newName)
	if replaced != nil {
		replaced.inode.invalidateMeta()
		replaced.inode.noteReplaced()
		fs.retireSpecialLocked(replaced.inode, replacedLinks)
		fs.detachLocked(replaced)
	}
	fs.moveLocked(renamed, newParent, newName, newRel)
	fs.ws.watchNoteInode(renamed.inode)
	deferDecRef(fs, vfsObj.CommitRenameReplaceDentry(ctx, &handle, &renamed.vfsd, replacedVFSD))
	vfs.InotifyRename(ctx, &renamed.inode.watches, &oldParent.inode.watches, &newParent.inode.watches, oldName, newName, renamed.inode.isDir())
	return nil
}

// moveLocked re-parents d and rewrites the cached path of d and of every
// cached descendant. Open files and later lookups then agree on the new names.
func (fs *filesystem) moveLocked(d, newParent *dentry, newName, newRel string) {
	oldParent := d.parent
	if oldParent.children[d.name] == d {
		delete(oldParent.children, d.name)
	}
	if newParent.children == nil {
		newParent.children = make(map[string]*dentry)
	}
	newParent.children[newName] = d
	newParent.refs.Add(1)
	d.nameMu.Lock()
	d.parent = newParent
	d.name = newName
	d.nameMu.Unlock()
	fs.rewritePathLocked(d, newRel)
	oldParent.decRefLocked()
}

func (fs *filesystem) rewritePathLocked(d *dentry, rel string) {
	d.nameMu.Lock()
	d.relPath = rel
	d.nameMu.Unlock()
	for name, c := range d.children {
		fs.rewritePathLocked(c, joinRelPath(rel, name))
	}
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." {
		return linuxerr.EINVAL
	}
	if name == ".." {
		return linuxerr.ENOTEMPTY
	}
	child, err := fs.lookupChildLocked(parent, name)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, parent.inode, child.inode); err != nil {
		return err
	}
	if !child.inode.isDir() {
		return linuxerr.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	if err := fs.ws.rmdir(child.relPath); err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return translateHostError(err)
	}
	parent.inode.invalidateMeta()
	parent.inode.negAdd(name, fs.ws.nowNano())
	for _, c := range child.children {
		fs.dropLocked(c)
	}
	fs.detachLocked(child)
	parent.inode.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true)
	deferDecRef(fs, vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt. The host removes the name
// at once, even while file descriptions keep the file open.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock()
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	name := rp.Component()
	if name == "." || name == ".." {
		return linuxerr.EISDIR
	}
	child, err := fs.lookupChildLocked(parent, name)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, parent.inode, child.inode); err != nil {
		return err
	}
	if child.inode.isDir() {
		return linuxerr.EISDIR
	}
	if rp.MustBeDir() {
		return linuxerr.ENOTDIR
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return err
	}
	defer mnt.EndWrite()
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	links := fs.specialLinksLocked(child)
	last, err := fs.ws.unlinkLast(child.relPath)
	if err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return translateHostError(err)
	}
	fs.retireSpecialLocked(child.inode, links)
	if last {
		child.inode.noteUnlinked()
	}
	child.inode.invalidateMeta()
	parent.inode.invalidateMeta()
	parent.inode.negAdd(name, fs.ws.nowNano())
	// Notify before the dentry dies, or the watches would be dropped first.
	fs.ws.watchNoteInode(child.inode)
	vfs.InotifyRemoveChild(ctx, &child.inode.watches, &parent.inode.watches, name)
	fs.detachLocked(child)
	deferDecRef(fs, vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}
