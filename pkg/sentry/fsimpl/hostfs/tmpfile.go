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
	"fmt"
	"io/fs"
	"os"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// This file implements open(2) with O_TMPFILE: a regular file that has no name
// in the namespace. The file dies with its last reference, unless the guest
// links it into the namespace first.
//
// A linkable file (O_TMPFILE without O_EXCL) needs a host name, because the
// guest links it with linkat on /proc/self/fd, and the host seccomp rule of
// the host filesystem forbids linkat with AT_EMPTY_PATH. hostfs therefore
// creates a hidden "~gvx~tmp.<id>" file in the directory, marks the inode as
// unlinked, and removes the host file when the last reference goes away. A
// link renames the host file to the new name. OpenWorkspace removes the files
// that a killed process left behind.
//
// A file that the guest can never link (O_TMPFILE with O_EXCL) needs no host
// name. Linux uses a native O_TMPFILE file. When the volume refuses it,
// Linux creates the named file and removes the name at once. macOS and
// Windows keep the named file until the last reference goes away.

// tmpSeq makes the names of temporary files unique in one process.
var tmpSeq atomic.Uint64

// newTmpLeaf returns a name in the internal namespace. The process number and
// the time keep names of different runs apart.
func newTmpLeaf() string {
	return fmt.Sprintf("%s%x.%x.%x", ephemeralTmpPrefix, os.Getpid(), time.Now().UnixNano(), tmpSeq.Add(1))
}

// tmpFile is the host state of an unnamed file.
type tmpFile struct {
	// parent is the directory dentry that holds the host name of the file.
	// The tmpFile holds one reference on it, so the cached path of the
	// directory follows every rename of the directory. It is nil when the
	// host holds no name. Protected by fs.mu.
	parent *dentry
	// leaf is the host name of the file inside that directory, or empty when
	// the host holds no name.
	leaf string
	// linkable reports that the guest may link the file into the namespace.
	linkable bool
}

// named reports that the host holds a name for the file.
func (t *tmpFile) named() bool {
	return t.leaf != ""
}

// tmpPaths returns the path that the handle registry holds for the open
// handles of the file, and the host path of the file. The paths follow the
// current path of the directory of the file. The caller holds w.mu.
func (w *Workspace) tmpPaths(t *tmpFile) (rel, hostPath string, err error) {
	dir := t.parent.path()
	hostDir, err := w.hostPath(dir)
	if err != nil {
		return "", "", err
	}
	return joinRelPath(dir, t.leaf), hostChild(hostDir, t.leaf), nil
}

// createTmp creates an unnamed file in the guest directory parentRel and
// returns its open handle and entry. The entry has the mode perm and the owner
// uid and gid. The file has no .gvx_meta record until the guest links it.
// The result leaf is the host name of the file, which is empty when the host
// holds none.
func (w *Workspace) createTmp(parentRel string, perm, uid, gid uint32, linkable bool) (h *hostHandle, e entry, leaf string, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(parentRel); err != nil {
		return nil, entry{}, "", err
	}
	pin, err := w.acquirePin(parentRel)
	if err != nil {
		return nil, entry{}, "", err
	}
	defer w.releasePin(pin)

	attr := POSIXAttr{Mode: linux.S_IFREG | perm&0o7777, UID: uid, GID: gid}
	// A host with a handle registry never has a native unnamed file, and
	// the registry could not reopen such a file after a directory rename.
	if !linkable && w.handles == nil {
		f, err := w.host.openAnonAt(pin.h)
		if err == nil {
			info, err := w.host.fstat(f)
			if err != nil {
				_ = f.Close()
				return nil, entry{}, "", err
			}
			return w.wrapLocked("", f, os.O_RDWR), entry{attr: attr, info: info}, "", nil
		}
		if !anonUnsupported(err) {
			return nil, entry{}, "", err
		}
	}

	hostDir, err := w.hostPath(parentRel)
	if err != nil {
		return nil, entry{}, "", err
	}
	leaf = newTmpLeaf()
	hostPath := hostChild(hostDir, leaf)
	f, err := w.host.openChildAt(pin.h, leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, entry{}, "", err
	}
	if !linkable && tmpfileUnlinkAtOnce {
		if err := w.host.unlink(hostPath); err != nil {
			_ = f.Close()
			_ = w.host.unlink(hostPath)
			return nil, entry{}, "", err
		}
		leaf = ""
	}
	info, err := w.host.fstat(f)
	if err != nil {
		_ = f.Close()
		if leaf != "" {
			_ = w.host.unlink(hostPath)
		}
		return nil, entry{}, "", err
	}
	registered := ""
	if leaf != "" {
		registered = joinRelPath(parentRel, leaf)
	}
	return w.wrapLocked(registered, f, os.O_RDWR), entry{attr: attr, info: info}, leaf, nil
}

// openTmp opens the named temporary file t again, as an open of its
// /proc/self/fd path does. A file without a host name cannot open again.
func (w *Workspace) openTmp(t *tmpFile, flags int) (*hostHandle, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return nil, os.ErrClosed
	}
	if !t.named() {
		return nil, fs.ErrNotExist
	}
	rel, hostPath, err := w.tmpPaths(t)
	if err != nil {
		return nil, err
	}
	f, err := w.host.open(hostPath, flags&^(os.O_CREATE|os.O_EXCL), 0)
	if err != nil {
		return nil, err
	}
	return w.wrapLocked(rel, f, flags), nil
}

// linkTmp gives the named temporary file t the guest path rel. It renames the
// host file and records attr in .gvx_meta. A native unnamed file cannot link,
// because it has no host name. The caller holds no lock of Workspace.
func (w *Workspace) linkTmp(t *tmpFile, rel string, attr POSIXAttr) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return errIsDir
	}
	if err := w.checkParentDirLocked(rel); err != nil {
		return err
	}
	if err := w.checkMetaRoomLocked(rel); err != nil {
		return err
	}
	oldRel, oldHost, err := w.tmpPaths(t)
	if err != nil {
		return err
	}
	dst, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return err
	}
	if err := w.host.rename(oldHost, dst); err != nil {
		return err
	}
	w.handles.moveFile(oldRel, rel)
	w.meta[rel] = attr
	w.markDirtyLocked()
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// removeTmp unlinks the host file of a named temporary file that nobody links
// any more.
func (w *Workspace) removeTmp(t *tmpFile) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	rel, hostPath, err := w.tmpPaths(t)
	if err != nil {
		return
	}
	w.handles.detach(rel)
	// The file is a private temporary file. A failure leaves a hidden file
	// that the next OpenWorkspace removes.
	_ = w.host.unlink(hostPath)
}

// releaseTmp removes the host file of an unnamed file when the inode dies, and
// drops the reference on the directory. Callers hold fs.mu.
func (i *inode) releaseTmp() {
	t := i.tmp
	if t == nil {
		return
	}
	i.tmp = nil
	if t.named() {
		i.fs.ws.removeTmp(t)
		t.parent.decRefLocked()
	}
}

// tmpOf returns the temporary file state of d, or nil.
func (d *dentry) tmpOf() *tmpFile {
	d.fs.mu.Lock()
	defer d.fs.mu.Unlock()
	return d.inode.tmp
}

// newTmpDentryLocked returns a dentry without a parent for the unnamed file
// with the entry e. The dentry stays out of the tree and counts as dead until
// a link gives it a name. The dentry holds one reference for the caller. A
// named file keeps a reference on its directory until the file dies or gets a
// name.
func (fs *filesystem) newTmpDentryLocked(e entry, t *tmpFile) *dentry {
	ino := fs.inodeForLocked(e, ".")
	ino.tmp = t
	ino.unlinked.Store(true)
	if t.named() {
		t.parent.refs.Add(1)
	}
	d := fs.newDentryLocked(nil, "", joinRelPath(".", "O_TMPFILE"), ino)
	d.dead = true
	return d
}

// openTmpfile implements OpenAt with O_TMPFILE. The path names the directory
// for the new file.
func (fs *filesystem) openTmpfile(ctx context.Context, rp *vfs.ResolvingPath, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	if opts.Flags&linux.O_ACCMODE == linux.O_RDONLY {
		return nil, linuxerr.EINVAL
	}
	fs.lock()
	unlocked := false
	unlock := func() {
		if !unlocked {
			fs.unlock(ctx)
			unlocked = true
		}
	}
	defer unlock()
	parent, err := fs.resolveLocked(ctx, rp)
	if err != nil {
		return nil, err
	}
	if !parent.inode.isDir() {
		return nil, linuxerr.ENOTDIR
	}
	creds := rp.Credentials()
	if err := parent.inode.checkPermissions(creds, vfs.MayWrite|vfs.MayExec); err != nil {
		return nil, err
	}
	if parent.dead {
		return nil, linuxerr.ENOENT
	}
	mnt := rp.Mount()
	if err := mnt.CheckBeginWrite(); err != nil {
		return nil, err
	}
	defer mnt.EndWrite()
	uid, gid, _ := newOwner(parent.inode, creds)
	h, e, leaf, err := fs.ws.createTmp(parent.relPath, uint32(opts.Mode)&0o7777, uint32(uid), uint32(gid), opts.Flags&linux.O_EXCL == 0)
	if err != nil {
		return nil, translateHostError(err)
	}
	parent.inode.invalidateMeta()
	t := &tmpFile{leaf: leaf, linkable: opts.Flags&linux.O_EXCL == 0}
	if leaf != "" {
		t.parent = parent
	}
	d := fs.newTmpDentryLocked(e, t)
	unlock()
	// The dentry holds one reference for this call. The file description
	// takes its own, and this one drops when the call returns.
	defer d.DecRef(ctx)
	// The flags describe the directory and the creation, not the file.
	opts.Flags &^= linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_EXCL
	return d.open(ctx, rp, &opts, h)
}

// linkTmpLocked links the unnamed file that src names as parent/name. It
// gives src, which the open files hold, the new name, so later calls through
// those files act on the new path. Callers hold fs.mu.
func (fs *filesystem) linkTmpLocked(creds *auth.Credentials, src, parent *dentry, name, rel string) error {
	ino := src.inode
	t := ino.tmp
	if t == nil || !t.linkable || !t.named() {
		// The file has no host name, or the guest created it with O_EXCL.
		return linuxerr.ENOENT
	}
	e := ino.snapshot()
	if err := vfs.MayLink(creds, linux.FileMode(e.attr.Mode), nil, auth.KUID(e.attr.UID), auth.KGID(e.attr.GID)); err != nil {
		return err
	}
	if err := fs.ws.linkTmp(t, rel, e.attr); err != nil {
		return translateHostError(err)
	}
	ino.tmp = nil
	t.parent.decRefLocked()
	ino.unlinked.Store(false)
	ino.invalidateMeta()
	src.nameMu.Lock()
	src.parent, src.name, src.relPath = parent, name, rel
	src.nameMu.Unlock()
	src.dead = false
	if parent.children == nil {
		parent.children = make(map[string]*dentry)
	}
	parent.children[name] = src
	// The parent keeps a reference for the child, and the child map keeps one.
	parent.refs.Add(1)
	src.refs.Add(1)
	return nil
}
