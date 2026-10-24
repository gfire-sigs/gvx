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
	"fmt"
	"io/fs"
	"os"
	"strings"
	"sync/atomic"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// This file implements the flags of renameat2(2) that go beyond a plain
// rename: RENAME_EXCHANGE and RENAME_WHITEOUT. RENAME_NOREPLACE needs no host
// support and lives in RenameAt.
//
// RENAME_EXCHANGE swaps two entries. The host does it in one call when
// WorkspaceCaps.NativeRenameSwap is set: renameat2 on Linux and renameatx_np
// on macOS. Windows has no such call. There the swap takes three renames
// through a file named "~gvx~swap.<id>" in the directory of the first entry,
// and Workspace.mu keeps every guest call out while it runs. OpenWorkspace
// removes the swap file of a process that died in between.
//
// A swap leaves the stored name of every entry as it was. The host entry under
// the stored name of the first guest name now holds the object of the second
// guest name. The records of .gvx_meta, the stored-name table, the pinned
// directory handles, and the open-handle registry follow the objects.
//
// RENAME_WHITEOUT moves the source and leaves a whiteout at the old name. The
// whiteout is a character device 0:0, which special_node.go creates.

// swapSeq makes the names of swap files unique in one process.
var swapSeq atomic.Uint64

// newSwapLeaf returns the name of a swap file in the internal namespace.
func newSwapLeaf() string {
	return fmt.Sprintf("%s%x.%x", ephemeralSwapPrefix, os.Getpid(), swapSeq.Add(1))
}

// swapScratch is a guest path that no entry can have, because it holds a NUL
// byte. The stored-name table uses it as the middle step of a swap.
const swapScratch = "\x00swap"

// checkRenameFlags applies the combination rules of renameat2(2). The flags
// RENAME_NOREPLACE and RENAME_WHITEOUT exclude RENAME_EXCHANGE. Unknown bits
// are invalid.
func checkRenameFlags(flags uint32) error {
	const known = linux.RENAME_NOREPLACE | linux.RENAME_EXCHANGE | linux.RENAME_WHITEOUT
	if flags&^known != 0 {
		return linuxerr.EINVAL
	}
	if flags&linux.RENAME_EXCHANGE != 0 && flags&(linux.RENAME_NOREPLACE|linux.RENAME_WHITEOUT) != 0 {
		return linuxerr.EINVAL
	}
	return nil
}

// renameWhiteout moves oldRel to newRel and leaves a whiteout at oldRel, in
// one critical section of w.mu. A failure to create the whiteout moves the
// source back.
func (w *Workspace) renameWhiteout(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	if err := w.checkMetaRoomLocked(oldRel); err != nil {
		return err
	}
	if err := w.renameLocked(oldRel, newRel); err != nil {
		return err
	}
	if err := w.createWhiteoutLocked(oldRel); err != nil {
		if back := w.renameLocked(newRel, oldRel); back != nil {
			return errors.Join(err, back)
		}
		return err
	}
	return nil
}

// exchange swaps the entries aRel and bRel. Both must exist.
func (w *Workspace) exchange(aRel, bRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.exchangeLocked(aRel, bRel)
}

// exchangeLocked is exchange for a caller that holds w.mu for writing.
func (w *Workspace) exchangeLocked(aRel, bRel string) error {
	if err := w.checkWritableLocked(aRel, bRel); err != nil {
		return err
	}
	if aRel == "." || bRel == "." {
		return fs.ErrInvalid
	}
	a, err := w.lookupLocked(aRel)
	if err != nil {
		return err
	}
	b, err := w.lookupLocked(bRel)
	if err != nil {
		return err
	}
	if aRel == bRel {
		return nil
	}
	if a.isDir() && strings.HasPrefix(bRel, aRel+"/") || b.isDir() && strings.HasPrefix(aRel, bRel+"/") {
		return errInvalidMove
	}
	if !a.virtual && !b.virtual && a.info.id == b.info.id && !a.isDir() {
		// Two names of one file: the swap changes nothing.
		return nil
	}
	switch {
	case a.virtual && b.virtual:
		w.swapMetaLocked(aRel, bRel)
	case a.virtual:
		if err := w.exchangeVirtualLocked(bRel, aRel); err != nil {
			return err
		}
	case b.virtual:
		if err := w.exchangeVirtualLocked(aRel, bRel); err != nil {
			return err
		}
	default:
		if err := w.exchangeHostLocked(aRel, bRel, a.isDir(), b.isDir()); err != nil {
			return err
		}
	}
	w.markDirtyLocked()
	return nil
}

// exchangeVirtualLocked swaps the host entry hostRel with the virtual symbolic
// link virtRel. The link exists only in .gvx_meta, so no host call can swap
// the two. The host entry moves to the name of the link, and the link takes the
// old name of the host entry.
func (w *Workspace) exchangeVirtualLocked(hostRel, virtRel string) error {
	saved := w.meta[virtRel]
	delete(w.meta, virtRel)
	if err := w.renameLocked(hostRel, virtRel); err != nil {
		w.meta[virtRel] = saved
		return err
	}
	w.meta[hostRel] = saved
	return nil
}

// exchangeHostLocked swaps two host entries. aDir and bDir tell which of them
// is a directory.
func (w *Workspace) exchangeHostLocked(aRel, bRel string, aDir, bDir bool) error {
	aParent, aName := splitParent(aRel)
	bParent, bName := splitParent(bRel)
	aHost, err := w.hostPath(aRel)
	if err != nil {
		return err
	}
	bHost, err := w.hostPath(bRel)
	if err != nil {
		return err
	}
	// A pinned descriptor follows its directory to the other name, and Windows
	// refuses to move a directory with an open handle below it.
	var qa, qb *quiescedTree
	if aDir {
		w.closeSubtreeHandlesLocked(aRel)
		qa = w.handles.quiesce(aRel)
	}
	if bDir {
		w.closeSubtreeHandlesLocked(bRel)
		qb = w.handles.quiesce(bRel)
	}
	if err := w.hostExchange(aHost, bHost); err != nil {
		_ = qa.finish(false, "")
		_ = qb.finish(false, "")
		return err
	}
	// The stored names stay in their directories, so the listing snapshots of
	// the parents stay valid. The names mark the guest mutation for the host
	// watcher.
	w.watchNoteName(aParent, aName)
	w.watchNoteName(bParent, bName)
	w.dropDirNamesLocked(aRel)
	w.dropDirNamesLocked(bRel)
	w.moveAltTree(aRel, swapScratch)
	w.moveAltTree(bRel, aRel)
	w.moveAltTree(swapScratch, bRel)
	// The open handles follow their files. A file keeps its handles, and a
	// directory moves the handles below it.
	w.handles.swapFiles(aRel, bRel)
	_ = qa.finish(true, bRel)
	_ = qb.finish(true, aRel)
	w.swapMetaLocked(aRel, bRel)
	return nil
}

// hostExchange swaps the host entries aHost and bHost with the native call, or
// with three renames when the volume has no such call.
func (w *Workspace) hostExchange(aHost, bHost string) error {
	if w.caps.NativeRenameSwap {
		return w.host.exchange(aHost, bHost)
	}
	return w.swapThroughTemp(aHost, bHost)
}

// swapThroughTemp swaps two host entries with three renames through a swap
// file in the directory of the first entry. Each rename moves an entry to a
// free name, so no rename replaces anything. A failure puts the entries back.
// The caller holds w.mu for writing, so no guest call sees the middle states.
func (w *Workspace) swapThroughTemp(aHost, bHost string) error {
	dir, _ := splitParent(aHost)
	tmp := hostChild(dir, newSwapLeaf())
	if err := w.host.rename(aHost, tmp); err != nil {
		return err
	}
	if err := w.host.rename(bHost, aHost); err != nil {
		return errors.Join(err, w.host.rename(tmp, aHost))
	}
	if err := w.host.rename(tmp, bHost); err != nil {
		undo := errors.Join(w.host.rename(aHost, bHost), w.host.rename(tmp, aHost))
		return errors.Join(err, undo)
	}
	return nil
}

// swapMetaLocked swaps the .gvx_meta records of the entries aRel and bRel and
// of every entry below them. The entries cannot nest. Callers hold w.mu for
// writing.
func (w *Workspace) swapMetaLocked(aRel, bRel string) {
	aPrefix, bPrefix := aRel+"/", bRel+"/"
	moved := make(map[string]POSIXAttr)
	for k, m := range w.meta {
		switch {
		case k == aRel:
			moved[bRel] = m
		case k == bRel:
			moved[aRel] = m
		case strings.HasPrefix(k, aPrefix):
			moved[bRel+"/"+strings.TrimPrefix(k, aPrefix)] = m
		case strings.HasPrefix(k, bPrefix):
			moved[aRel+"/"+strings.TrimPrefix(k, bPrefix)] = m
		default:
			continue
		}
		delete(w.meta, k)
	}
	for k, m := range moved {
		w.meta[k] = m
	}
	w.markDirtyLocked()
}

// swapFiles swaps the paths of the open handles of the two files aRel and bRel.
// A nil registry ignores the call.
func (r *winHandleRegistry) swapFiles(aRel, bRel string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for h := range r.handles {
		switch h.path {
		case aRel:
			h.path = bRel
		case bRel:
			h.path = aRel
		}
	}
}

// exchangeAt implements RenameAt with RENAME_EXCHANGE. The caller holds fs.mu
// and a write reference on the mount, and it resolved newParent and newName
// from rp.
func (fs *filesystem) exchangeAt(ctx context.Context, rp *vfs.ResolvingPath, newParent *dentry, newName string, oldParent *dentry, oldName string, opts vfs.RenameOptions) error {
	creds := rp.Credentials()
	if err := oldParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	a, err := fs.lookupChildLocked(oldParent, oldName)
	if err != nil {
		return err
	}
	if err := mayDelete(creds, oldParent.inode, a.inode); err != nil {
		return err
	}
	if err := newParent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return err
	}
	b, err := fs.lookupChildLocked(newParent, newName)
	if err != nil {
		// Both names must exist. ENOENT stands for a missing new name.
		return err
	}
	if err := mayDelete(creds, newParent.inode, b.inode); err != nil {
		return err
	}
	if opts.MustBeDir && !a.inode.isDir() || rp.MustBeDir() && !b.inode.isDir() {
		return linuxerr.ENOTDIR
	}
	if a == b || (a.inode == b.inode && !a.inode.isDir()) {
		// A name swapped with itself, or with another name of the same file,
		// changes nothing.
		return nil
	}
	// A directory cannot move below itself, in either direction.
	if a.inode.isDir() && isAncestorLocked(a, newParent) || b.inode.isDir() && isAncestorLocked(b, oldParent) {
		return linuxerr.EINVAL
	}
	if oldParent != newParent {
		// Moving a directory to another parent changes its entry "..", which
		// needs write permission on the directory.
		if a.inode.isDir() {
			if err := a.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
		if b.inode.isDir() {
			if err := b.inode.checkPermissions(creds, vfs.MayWrite); err != nil {
				return err
			}
		}
	}
	if oldParent.dead || newParent.dead {
		return linuxerr.ENOENT
	}

	oldRel := joinRelPath(oldParent.relPath, oldName)
	newRel := joinRelPath(newParent.relPath, newName)
	vfsObj := rp.VirtualFilesystem()
	mntns := vfs.MountNamespaceFromContext(ctx)
	defer mntns.DecRef(ctx)
	handle, err := vfsObj.PrepareRenameDentry(mntns, &a.vfsd, &b.vfsd)
	if err != nil {
		return err
	}
	vfsObj.RenameBegin(&handle)
	if err := fs.ws.exchange(oldRel, newRel); err != nil {
		vfsObj.AbortRenameDentry(&handle, &a.vfsd, &b.vfsd)
		return translateHostError(err)
	}
	// Both objects, and both parents, change times. The names stay taken.
	a.inode.invalidateMeta()
	b.inode.invalidateMeta()
	oldParent.inode.invalidateMeta()
	newParent.inode.invalidateMeta()
	fs.exchangeDentriesLocked(a, b, oldRel, newRel)
	fs.ws.watchNoteInode(a.inode)
	fs.ws.watchNoteInode(b.inode)
	vfsObj.CommitRenameExchangeDentry(&handle, &a.vfsd, &b.vfsd)
	vfs.InotifyRename(ctx, &a.inode.watches, &oldParent.inode.watches, &newParent.inode.watches, oldName, newName, a.inode.isDir())
	vfs.InotifyRename(ctx, &b.inode.watches, &newParent.inode.watches, &oldParent.inode.watches, newName, oldName, b.inode.isDir())
	return nil
}

// exchangeDentriesLocked swaps the places of two dentries in the tree. The
// dentry a takes the path bRel, and b takes aRel. The cached paths of the
// descendants follow.
func (fs *filesystem) exchangeDentriesLocked(a, b *dentry, aRel, bRel string) {
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
	// Each dentry holds a reference on its parent. The new references come
	// before the old ones drop, so no parent dies in between.
	pa.refs.Add(1)
	pb.refs.Add(1)
	a.nameMu.Lock()
	b.nameMu.Lock()
	a.parent, a.name = pb, nb
	b.parent, b.name = pa, na
	b.nameMu.Unlock()
	a.nameMu.Unlock()
	fs.rewritePathLocked(a, bRel)
	fs.rewritePathLocked(b, aRel)
	pa.decRefLocked()
	pb.decRefLocked()
}
