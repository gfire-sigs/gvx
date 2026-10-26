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

// newOwner returns the owner of a new child: the credentials of the caller,
// with the group of a parent that has the set-group-ID bit. The Boolean result
// reports that inheritance.
func (i *inode) newOwner(creds *auth.Credentials) (auth.KUID, auth.KGID, bool) {
	mode, _, gid := i.owner()
	if mode&linux.ModeSetGID != 0 {
		return creds.EffectiveKUID, gid, true
	}
	return creds.EffectiveKUID, creds.EffectiveKGID, false
}

// newChildLocked creates a node and links it into parent. The init function
// writes the content of the node before the node becomes visible. When any step
// fails, the engine frees the node, because it has no link.
func (fs *filesystem) newChildLocked(parent *dentry, name string, mode uint16, uid auth.KUID, gid auth.KGID, rdev uint32, init func(n *node) error) (*inode, error) {
	n, err := fs.v.newNode(mode, uint32(uid), uint32(gid), rdev, fs.now())
	if err != nil {
		return nil, toLinuxErr(err)
	}
	fail := func(err error) (*inode, error) {
		n.mu.Lock()
		n.links = 0
		n.mu.Unlock()
		fs.v.putNode(n)
		return nil, toLinuxErr(err)
	}
	if init != nil {
		if err := init(n); err != nil {
			return fail(err)
		}
	}
	isDir := mode&modeTypeMask == modeDir
	n.mu.Lock()
	n.links = 1
	if isDir {
		n.links = 2
	}
	n.markDirtyLocked()
	n.mu.Unlock()
	if err := parent.inode.n.addEntry(name, n.ino, n.fileType()); err != nil {
		return fail(err)
	}
	now := fs.now()
	parent.inode.mutate(func(p *node) {
		if isDir {
			p.links++
		}
		p.mtime, p.ctime = now, now
	})
	return fs.inodeForNodeLocked(n), nil
}

// doCreateAt checks that creating a file at rp is permitted, then calls
// create. The create function links the new inode into parent and returns it.
//
// Preconditions: !rp.Done() and rp.ShouldFollowSymlink() is false for the last
// component.
func (fs *filesystem) doCreateAt(ctx context.Context, rp *vfs.ResolvingPath, dir bool, create func(parent *dentry, name string) (*inode, error)) error {
	fs.lock(ctx)
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
	if len(name) > maxNameLen {
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
	var ino *inode
	if err := fs.writeOp(rp.Mount(), func() error {
		if err := parent.inode.checkPermissions(rp.Credentials(), vfs.MayWrite); err != nil {
			return err
		}
		var err error
		ino, err = create(parent, name)
		return err
	}); err != nil {
		return err
	}
	fs.newDentryLocked(parent, name, ino)
	ev := uint32(linux.IN_CREATE)
	if dir {
		ev |= linux.IN_ISDIR
	}
	parent.inode.watches.Notify(ctx, name, ev, 0, vfs.InodeEvent, false)
	return nil
}

// LinkAt implements vfs.FilesystemImpl.LinkAt.
func (fs *filesystem) LinkAt(ctx context.Context, rp *vfs.ResolvingPath, vd vfs.VirtualDentry) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name string) (*inode, error) {
		if rp.Mount() != vd.Mount() {
			return nil, linuxerr.EXDEV
		}
		src := vd.Dentry().Impl().(*dentry)
		if src.dead {
			return nil, linuxerr.ENOENT
		}
		si := src.inode
		if si.isDir() {
			return nil, linuxerr.EPERM
		}
		a := si.attr()
		if a.links == 0 {
			return nil, linuxerr.ENOENT
		}
		if a.links >= maxLinks {
			return nil, linuxerr.EMLINK
		}
		if err := vfs.MayLink(rp.Credentials(), linux.FileMode(a.mode), nil, auth.KUID(a.uid), auth.KGID(a.gid)); err != nil {
			return nil, err
		}
		if err := parent.inode.n.addEntry(name, si.ino, fileTypeOfMode(si.kind)); err != nil {
			return nil, toLinuxErr(err)
		}
		si.addLinks(1)
		parent.inode.touchMCtime()
		si.watches.Notify(ctx, "", linux.IN_ATTRIB, 0, vfs.InodeEvent, false)
		return si, nil
	})
}

// MkdirAt implements vfs.FilesystemImpl.MkdirAt.
func (fs *filesystem) MkdirAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MkdirOptions) error {
	return fs.doCreateAt(ctx, rp, true, func(parent *dentry, name string) (*inode, error) {
		if parent.inode.attr().links >= maxLinks {
			return nil, linuxerr.EMLINK
		}
		uid, gid, inherit := parent.inode.newOwner(rp.Credentials())
		mode := modeDir | uint16(opts.Mode&0o7777)
		if inherit {
			mode |= linux.S_ISGID
		}
		return fs.newChildLocked(parent, name, mode, uid, gid, 0, func(n *node) error {
			return n.initDir(parent.inode.ino)
		})
	})
}

// MknodAt implements vfs.FilesystemImpl.MknodAt.
func (fs *filesystem) MknodAt(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.MknodOptions) error {
	return fs.doCreateAt(ctx, rp, false, func(parent *dentry, name string) (*inode, error) {
		uid, gid, _ := parent.inode.newOwner(rp.Credentials())
		perm := uint16(opts.Mode & 0o7777)
		var kind uint16
		var rdev uint32
		switch opts.Mode.FileType() {
		case linux.S_IFREG, 0:
			kind = modeRegular
		case linux.S_IFIFO:
			kind = modeFIFO
		case linux.S_IFSOCK:
			kind = modeSocket
		case linux.S_IFCHR, linux.S_IFBLK:
			if opts.DevMajor > 0xfff || opts.DevMinor > 0xfffff {
				return nil, linuxerr.EINVAL
			}
			kind = modeChar
			if opts.Mode.FileType() == linux.S_IFBLK {
				kind = modeBlock
			}
			rdev = encodeRdev(opts.DevMajor, opts.DevMinor)
		default:
			return nil, linuxerr.EINVAL
		}
		ino, err := fs.newChildLocked(parent, name, kind|perm, uid, gid, rdev, nil)
		if err != nil {
			return nil, err
		}
		if kind == modeSocket {
			ino.ep = opts.Endpoint
		}
		return ino, nil
	})
}

// mayDelete reports whether creds may remove child from parent.
func mayDelete(creds *auth.Credentials, parent, child *inode) error {
	if err := parent.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	pmode, puid, _ := parent.owner()
	_, cuid, cgid := child.owner()
	return vfs.CheckDeleteSticky(creds, pmode, puid, cuid, cgid)
}

// UnlinkAt implements vfs.FilesystemImpl.UnlinkAt. A file that a descriptor
// keeps open stays usable. The engine frees its storage when the last
// descriptor closes.
func (fs *filesystem) UnlinkAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	// Linux looks up the name before it checks the write permission of the
	// parent, so a name that is too long fails first.
	name := rp.Component()
	if len(name) > maxNameLen {
		return linuxerr.ENAMETOOLONG
	}
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
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
	if err := fs.beginWrite(mnt); err != nil {
		return err
	}
	defer fs.endWrite(mnt)
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	if err := parent.inode.n.removeEntry(name); err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return toLinuxErr(err)
	}
	child.inode.addLinks(-1)
	parent.inode.touchMCtime()
	// Notify before the dentry dies, or the watches would drop first.
	vfs.InotifyRemoveChild(ctx, &child.inode.watches, &parent.inode.watches, name)
	fs.detachLocked(ctx, child)
	fs.deferDecRef(vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}

// RmdirAt implements vfs.FilesystemImpl.RmdirAt.
func (fs *filesystem) RmdirAt(ctx context.Context, rp *vfs.ResolvingPath) error {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	parent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	creds := rp.Credentials()
	name := rp.Component()
	if len(name) > maxNameLen {
		return linuxerr.ENAMETOOLONG
	}
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
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
	empty, err := child.inode.n.isEmptyDir()
	if err != nil {
		return toLinuxErr(err)
	}
	if !empty {
		return linuxerr.ENOTEMPTY
	}
	mnt := rp.Mount()
	if err := fs.beginWrite(mnt); err != nil {
		return err
	}
	defer fs.endWrite(mnt)
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	if err := vfsObj.PrepareDeleteDentry(mntns, &child.vfsd); err != nil {
		return err
	}
	if err := parent.inode.n.removeEntry(name); err != nil {
		vfsObj.AbortDeleteDentry(&child.vfsd)
		return toLinuxErr(err)
	}
	// The directory loses its own link and the link of its name. The parent
	// loses the link of the entry "..".
	child.inode.mutate(func(n *node) { n.links = 0 })
	now := fs.now()
	parent.inode.mutate(func(n *node) {
		if n.links > 0 {
			n.links--
		}
		n.mtime, n.ctime = now, now
	})
	parent.inode.watches.Notify(ctx, name, linux.IN_DELETE|linux.IN_ISDIR, 0, vfs.InodeEvent, true)
	fs.detachLocked(ctx, child)
	fs.deferDecRef(vfsObj.CommitDeleteDentry(ctx, &child.vfsd))
	return nil
}

// renameStep is one engine change of a rename with the change that undoes it.
type renameStep struct {
	do   func() error
	undo func()
}

// runSteps runs the steps in order. When a step fails, it undoes the finished
// steps in reverse order and returns the error.
func runSteps(steps []renameStep) error {
	for i, s := range steps {
		if err := s.do(); err != nil {
			for j := i - 1; j >= 0; j-- {
				steps[j].undo()
			}
			return toLinuxErr(err)
		}
	}
	return nil
}

// RenameAt implements vfs.FilesystemImpl.RenameAt. It supports
// RENAME_NOREPLACE and RENAME_EXCHANGE. RENAME_WHITEOUT returns EINVAL, as in
// tmpfs.
func (fs *filesystem) RenameAt(ctx context.Context, rp *vfs.ResolvingPath, oldParentVD vfs.VirtualDentry, oldName string, opts vfs.RenameOptions) error {
	fs.lock(ctx)
	defer fs.unlock(ctx)
	newParent, err := fs.walkParentDirLocked(ctx, rp, rp.Start().Impl().(*dentry))
	if err != nil {
		return err
	}
	if opts.Flags&^(linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE) != 0 {
		return linuxerr.EINVAL
	}
	if opts.Flags&(linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE) == linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE {
		return linuxerr.EINVAL
	}
	exchange := opts.Flags&linux.RENAME_EXCHANGE != 0
	newName := rp.Component()
	if newName == "." || newName == ".." {
		if opts.Flags&linux.RENAME_NOREPLACE != 0 {
			return linuxerr.EEXIST
		}
		return linuxerr.EBUSY
	}
	if len(newName) > maxNameLen || len(oldName) > maxNameLen {
		return linuxerr.ENAMETOOLONG
	}
	mnt := rp.Mount()
	if mnt != oldParentVD.Mount() {
		return linuxerr.EXDEV
	}
	return fs.writeOp(mnt, func() error {
		creds := rp.Credentials()
		oldParent := oldParentVD.Dentry().Impl().(*dentry)
		if err := oldParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
			return err
		}
		renamed, err := fs.lookupChildLocked(oldParent, oldName)
		if err != nil {
			return err
		}
		if err := mayDelete(creds, oldParent.inode, renamed.inode); err != nil {
			return err
		}
		if renamed.inode.isDir() {
			if isAncestorLocked(renamed, newParent) {
				return linuxerr.EINVAL
			}
			if oldParent != newParent {
				// Writability is needed to change the entry "..".
				if err := renamed.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
					return err
				}
			}
		} else if !exchange && (opts.MustBeDir || rp.MustBeDir()) {
			return linuxerr.ENOTDIR
		}
		if err := newParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
			return err
		}
		replaced, err := fs.lookupChildLocked(newParent, newName)
		if err != nil {
			if !linuxerr.Equals(linuxerr.ENOENT, err) {
				return err
			}
			replaced = nil
		}
		crossDir := oldParent != newParent
		switch {
		case replaced == nil && exchange:
			return linuxerr.ENOENT
		case replaced == nil:
			if renamed.inode.isDir() && crossDir && newParent.inode.attr().links >= maxLinks {
				return linuxerr.EMLINK
			}
		case opts.Flags&linux.RENAME_NOREPLACE != 0:
			return linuxerr.EEXIST
		default:
			if err := mayDelete(creds, newParent.inode, replaced.inode); err != nil {
				return err
			}
			if err := fs.checkReplaceLocked(creds, rp, opts, renamed, replaced, oldParent, newParent, exchange); err != nil {
				return err
			}
		}
		if newParent.dead {
			return linuxerr.ENOENT
		}
		// A rename of a file onto itself, or onto another name of the same file,
		// changes nothing.
		if replaced != nil && (renamed == replaced || (renamed.inode == replaced.inode && !renamed.inode.isDir())) {
			return nil
		}

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
		if exchange {
			err = fs.exchangeEntries(oldParent, oldName, renamed, newParent, newName, replaced)
		} else {
			err = fs.moveEntries(oldParent, oldName, renamed, newParent, newName, replaced)
		}
		if err != nil {
			vfsObj.AbortRenameDentry(&handle, &renamed.vfsd, replacedVFSD)
			return err
		}
		if exchange {
			fs.adjustExchangeLinks(oldParent, newParent, renamed, replaced)
			fs.exchangeDentriesLocked(ctx, renamed, replaced)
			vfsObj.CommitRenameExchangeDentry(&handle, &renamed.vfsd, replacedVFSD)
			replaced.inode.touchCtime()
			vfs.InotifyRename(ctx, &renamed.inode.watches, &oldParent.inode.watches, &newParent.inode.watches, oldName, newName, renamed.inode.isDir())
			vfs.InotifyRename(ctx, &replaced.inode.watches, &newParent.inode.watches, &oldParent.inode.watches, newName, oldName, replaced.inode.isDir())
		} else {
			if replaced != nil {
				if replaced.inode.isDir() {
					// The replaced directory loses its links and the entry "..".
					replaced.inode.mutate(func(n *node) { n.links = 0 })
					newParent.inode.addLinks(-1)
				} else {
					replaced.inode.addLinks(-1)
				}
				fs.detachLocked(ctx, replaced)
			}
			if renamed.inode.isDir() && crossDir {
				oldParent.inode.addLinks(-1)
				newParent.inode.addLinks(1)
			}
			fs.moveLocked(ctx, renamed, newParent, newName)
			fs.deferDecRef(vfsObj.CommitRenameReplaceDentry(ctx, &handle, &renamed.vfsd, replacedVFSD))
			vfs.InotifyRename(ctx, &renamed.inode.watches, &oldParent.inode.watches, &newParent.inode.watches, oldName, newName, renamed.inode.isDir())
		}
		oldParent.inode.touchMCtime()
		if crossDir {
			newParent.inode.touchMCtime()
		}
		renamed.inode.touchCtime()
		return nil
	})
}

// checkReplaceLocked applies the type rules of a rename that replaces or
// exchanges an existing name.
func (fs *filesystem) checkReplaceLocked(creds *auth.Credentials, rp *vfs.ResolvingPath, opts vfs.RenameOptions, renamed, replaced, oldParent, newParent *dentry, exchange bool) error {
	crossDir := oldParent != newParent
	if exchange {
		// An exchange with an ancestor would cut that ancestor from the tree.
		if isAncestorLocked(replaced, renamed) {
			return linuxerr.EINVAL
		}
		if rp.MustBeDir() && !replaced.inode.isDir() {
			return linuxerr.ENOTDIR
		}
		if opts.MustBeDir && !renamed.inode.isDir() {
			return linuxerr.ENOTDIR
		}
		if !crossDir {
			return nil
		}
		if replaced.inode.isDir() {
			if err := replaced.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
			if !renamed.inode.isDir() && oldParent.inode.attr().links >= maxLinks {
				return linuxerr.EMLINK
			}
		} else if renamed.inode.isDir() && newParent.inode.attr().links >= maxLinks {
			return linuxerr.EMLINK
		}
		return nil
	}
	if replaced.inode.isDir() {
		if !renamed.inode.isDir() {
			return linuxerr.EISDIR
		}
		empty, err := replaced.inode.n.isEmptyDir()
		if err != nil {
			return toLinuxErr(err)
		}
		if !empty {
			return linuxerr.ENOTEMPTY
		}
		return nil
	}
	if rp.MustBeDir() || renamed.inode.isDir() {
		return linuxerr.ENOTDIR
	}
	return nil
}

// moveEntries changes the directory entries for a plain rename. It adds the
// new name before it removes the old name, so a failure never loses the file.
func (fs *filesystem) moveEntries(oldParent *dentry, oldName string, renamed *dentry, newParent *dentry, newName string, replaced *dentry) error {
	ri := renamed.inode
	rft := fileTypeOfMode(ri.kind)
	var steps []renameStep
	if ri.isDir() && oldParent != newParent {
		steps = append(steps, renameStep{
			do:   func() error { return ri.n.setParent(newParent.inode.ino) },
			undo: func() { _ = ri.n.setParent(oldParent.inode.ino) },
		})
	}
	if replaced != nil {
		pi := replaced.inode
		pft := fileTypeOfMode(pi.kind)
		steps = append(steps, renameStep{
			do:   func() error { return newParent.inode.n.replaceEntry(newName, ri.ino, rft) },
			undo: func() { _ = newParent.inode.n.replaceEntry(newName, pi.ino, pft) },
		})
	} else {
		steps = append(steps, renameStep{
			do:   func() error { return newParent.inode.n.addEntry(newName, ri.ino, rft) },
			undo: func() { _ = newParent.inode.n.removeEntry(newName) },
		})
	}
	steps = append(steps, renameStep{
		do:   func() error { return oldParent.inode.n.removeEntry(oldName) },
		undo: func() { _ = oldParent.inode.n.addEntry(oldName, ri.ino, rft) },
	})
	return runSteps(steps)
}

// exchangeEntries swaps two directory entries for RENAME_EXCHANGE.
func (fs *filesystem) exchangeEntries(oldParent *dentry, oldName string, renamed *dentry, newParent *dentry, newName string, replaced *dentry) error {
	ri, pi := renamed.inode, replaced.inode
	rft, pft := fileTypeOfMode(ri.kind), fileTypeOfMode(pi.kind)
	var steps []renameStep
	if oldParent != newParent {
		if ri.isDir() {
			steps = append(steps, renameStep{
				do:   func() error { return ri.n.setParent(newParent.inode.ino) },
				undo: func() { _ = ri.n.setParent(oldParent.inode.ino) },
			})
		}
		if pi.isDir() {
			steps = append(steps, renameStep{
				do:   func() error { return pi.n.setParent(oldParent.inode.ino) },
				undo: func() { _ = pi.n.setParent(newParent.inode.ino) },
			})
		}
	}
	steps = append(steps,
		renameStep{
			do:   func() error { return oldParent.inode.n.replaceEntry(oldName, pi.ino, pft) },
			undo: func() { _ = oldParent.inode.n.replaceEntry(oldName, ri.ino, rft) },
		},
		renameStep{
			do:   func() error { return newParent.inode.n.replaceEntry(newName, ri.ino, rft) },
			undo: func() { _ = newParent.inode.n.replaceEntry(newName, pi.ino, pft) },
		},
	)
	return runSteps(steps)
}

// adjustExchangeLinks moves the link of the entry ".." when exactly one of the
// exchanged files is a directory and the parents differ.
func (fs *filesystem) adjustExchangeLinks(oldParent, newParent, renamed, replaced *dentry) {
	if oldParent == newParent {
		return
	}
	switch {
	case renamed.inode.isDir() && !replaced.inode.isDir():
		oldParent.inode.addLinks(-1)
		newParent.inode.addLinks(1)
	case !renamed.inode.isDir() && replaced.inode.isDir():
		newParent.inode.addLinks(-1)
		oldParent.inode.addLinks(1)
	}
}

// exchangeDentriesLocked swaps the places of two dentries in the tree.
func (fs *filesystem) exchangeDentriesLocked(ctx context.Context, a, b *dentry) {
	pa, na, pb, nb := a.parent, a.name, b.parent, b.name
	if pa.children[na] == a {
		delete(pa.children, na)
	}
	if pb.children[nb] == b {
		delete(pb.children, nb)
	}
	if pa.children == nil {
		pa.children = make(map[string]*dentry)
	}
	if pb.children == nil {
		pb.children = make(map[string]*dentry)
	}
	pb.children[nb] = a
	pa.children[na] = b
	// Each dentry holds a reference on its parent. Take the new references
	// before the old ones drop.
	pa.refs.Add(1)
	pb.refs.Add(1)
	a.nameMu.Lock()
	b.nameMu.Lock()
	a.parent, a.name = pb, nb
	b.parent, b.name = pa, na
	b.nameMu.Unlock()
	a.nameMu.Unlock()
	pa.decRefLocked(ctx)
	pb.decRefLocked(ctx)
}

// encodeRdev packs a device number in the Linux 32-bit format.
func encodeRdev(major, minor uint32) uint32 {
	return minor&0xff | major<<8 | (minor&^0xff)<<12
}

// decodeRdev is the inverse of encodeRdev.
func decodeRdev(rdev uint32) (major, minor uint32) {
	return rdev >> 8 & 0xfff, rdev&0xff | rdev>>12&0xfff00
}
