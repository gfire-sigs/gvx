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
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// checkWritableLocked rejects mutations of read-only workspaces and of the
// hidden metadata names.
func (w *Workspace) checkWritableLocked(rels ...string) error {
	if w.readOnly {
		return ErrReadOnly
	}
	if w.closed {
		return os.ErrClosed
	}
	for _, rel := range rels {
		if isReservedPath(rel) {
			return errReservedName
		}
		if w.single != "" && rel != "." {
			return fs.ErrNotExist
		}
	}
	return nil
}

// checkParentDirLocked verifies that the parent of rel is a host directory. It
// opens or finds the pinned handle of that directory.
func (w *Workspace) checkParentDirLocked(rel string) error {
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return err
	}
	w.releasePin(pin)
	return nil
}

// createTargetLocked returns the host path and the stored name for a new entry
// at rel. It fails with fs.ErrExist when an entry that the guest can see, or a
// virtual symlink, holds the name. A hidden host clutter file at the name goes
// away first. Callers hold w.mu for writing.
func (w *Workspace) createTargetLocked(rel string) (hostRel, leaf string, err error) {
	if _, r := w.virtualAtLocked(rel); r != nil {
		return "", "", fs.ErrExist
	}
	p, err := w.locateLocked(rel)
	if err != nil {
		return "", "", err
	}
	if p.found {
		if !p.clutter {
			return "", "", fs.ErrExist
		}
		hostRel, err = w.hostPath(rel)
		if err != nil {
			return "", "", err
		}
		leaf = leafOf(hostRel)
		pin, err := w.parentPinLocked(rel)
		if err != nil {
			return "", "", err
		}
		defer w.releasePin(pin)
		if err := w.host.unlinkAt(pin.h, leaf); err != nil && !isNotExist(err) {
			return "", "", err
		}
		return hostRel, leaf, nil
	}
	if p.collided && !w.stateful {
		// The host holds the name under another case, and hostfs cannot tell
		// it apart.
		return "", "", fs.ErrExist
	}
	parent, _ := splitParent(rel)
	hostDir, err := w.hostPath(parent)
	if err != nil {
		return "", "", err
	}
	return hostChild(hostDir, p.create), p.create, nil
}

func hostOpenFlags(flags int) (int, error) {
	const allowed = os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREATE | os.O_EXCL | os.O_TRUNC
	if flags&^allowed != 0 {
		return 0, fmt.Errorf("hostfs: unsupported open flags %#x: %w", flags&^allowed, fs.ErrInvalid)
	}
	return flags, nil
}

// OpenFile opens a regular file inside the pinned workspace. Unlike os.OpenFile
// it never follows links. A created file gets the virtual mode mode and owner
// 0:0.
func (w *Workspace) OpenFile(relPath string, flags int, mode uint32) (*os.File, error) {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return nil, err
	}
	if _, err := hostOpenFlags(flags); err != nil {
		return nil, err
	}
	if flags&os.O_CREATE != 0 {
		f, _, err := w.createFile(cleanRel, mode&0o7777, 0, 0)
		if err == nil || flags&os.O_EXCL != 0 || !errors.Is(err, fs.ErrExist) {
			return f, err
		}
	}
	if w.readOnly && flags&(os.O_WRONLY|os.O_RDWR|os.O_TRUNC) != 0 {
		return nil, ErrReadOnly
	}
	f, _, err := w.openRegular(cleanRel, flags)
	return f, err
}

// openRegular opens an existing regular file.
func (w *Workspace) openRegular(rel string, flags int) (*os.File, entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.openRegularLocked(rel, flags)
}

// openRegularLocked is openRegular for a caller that holds w.mu.
func (w *Workspace) openRegularLocked(rel string, flags int) (*os.File, entry, error) {
	e, err := w.lookupLocked(rel)
	if err != nil {
		return nil, entry{}, err
	}
	if e.isDir() {
		return nil, entry{}, errIsDir
	}
	f, err := w.openRegularWithAttrLocked(rel, e, flags)
	if err != nil {
		return nil, entry{}, err
	}
	return f, e, nil
}

// createFile creates a regular file that must not exist and returns it open for
// reading and writing. Host files stay owner-only: guest permissions are
// virtual, and the sentry process must always be able to reopen them.
func (w *Workspace) createFile(rel string, perm, uid, gid uint32) (*os.File, entry, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.createFileLocked(rel, perm, uid, gid)
}

// createFileLocked is createFile for a caller that holds w.mu for writing.
func (w *Workspace) createFileLocked(rel string, perm, uid, gid uint32) (*os.File, entry, error) {
	if err := w.checkWritableLocked(rel); err != nil {
		return nil, entry{}, err
	}
	if rel == "." {
		return nil, entry{}, errIsDir
	}
	if err := w.checkMetaRoom(recKey{}); err != nil {
		return nil, entry{}, err
	}
	_, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return nil, entry{}, err
	}
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return nil, entry{}, err
	}
	defer w.releasePin(pin)
	f, err := w.host.openChildAt(pin.h, leaf, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, entry{}, err
	}
	info, err := w.host.fstat(f)
	if err != nil {
		_ = f.Close()
		_ = w.host.unlinkAt(pin.h, leaf)
		return nil, entry{}, err
	}
	attr := POSIXAttr{Mode: linux.S_IFREG | perm&0o7777, UID: uid, GID: gid}
	key := w.keyOf(rel, info)
	w.putRec(key, attr, rel)
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return f, entry{attr: attr, info: info, key: key}, nil
}

// WriteFile writes data to relPath inside the workspace root and records mode
// in .gvx_meta.
func (w *Workspace) WriteFile(relPath string, data []byte, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	f, _, err := w.createFile(cleanRel, mode, 0, 0)
	created := err == nil
	if errors.Is(err, fs.ErrExist) {
		if w.readOnly {
			return ErrReadOnly
		}
		f, _, err = w.openRegular(cleanRel, os.O_WRONLY|os.O_TRUNC)
	}
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if !created {
		return w.Chmod(cleanRel, mode)
	}
	return nil
}

// ReadFile reads the contents of relPath inside the workspace root.
func (w *Workspace) ReadFile(relPath string) ([]byte, error) {
	f, err := w.OpenFile(relPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = f.Close()
	}()
	return io.ReadAll(f)
}

// MkdirAll creates a directory hierarchy inside the pinned workspace.
func (w *Workspace) MkdirAll(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	if w.readOnly {
		return ErrReadOnly
	}
	if cleanRel == "." {
		return nil
	}
	cur := ""
	for _, part := range strings.Split(cleanRel, "/") {
		cur = joinRelPath(cur, part)
		err := w.mkdir(cur, mode, 0, 0)
		if err != nil && !errors.Is(err, fs.ErrExist) {
			return err
		}
		if errors.Is(err, fs.ErrExist) {
			e, lerr := w.lookup(cur)
			if lerr != nil {
				return lerr
			}
			if !e.isDir() {
				return errNotDir
			}
		}
	}
	return nil
}

// mkdir creates one directory with the virtual mode, owner, and group.
func (w *Workspace) mkdir(rel string, mode, uid, gid uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrExist
	}
	if err := w.checkMetaRoom(recKey{}); err != nil {
		return err
	}
	_, leaf, err := w.createTargetLocked(rel)
	if err != nil {
		return err
	}
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return err
	}
	defer w.releasePin(pin)
	if err := w.host.mkdirAt(pin.h, leaf); err != nil {
		return err
	}
	key := recKey{kind: kindPath, path: rel}
	if !w.pathKeys {
		// mkdir returns no identity, so one stat of the new directory reads it.
		info, err := w.host.lstatAt(pin.h, leaf)
		if err != nil {
			_ = w.host.rmdirAt(pin.h, leaf)
			return err
		}
		key = w.keyOf(rel, info)
	}
	w.putRec(key, POSIXAttr{Mode: linux.S_IFDIR | mode&0o7777, UID: uid, GID: gid}, rel)
	parent, name := splitParent(rel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// Mkdir creates a single directory at relPath inside the pinned workspace.
func (w *Workspace) Mkdir(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.mkdir(cleanRel, mode, 0, 0)
}

// Chmod updates the virtual POSIX mode bits for relPath. The host file mode
// never changes: the sentry process must keep access to the file.
func (w *Workspace) Chmod(relPath string, mode uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	m := mode & 0o7777
	return w.setAttr(cleanRel, &m, nil, nil)
}

// Chown updates the virtual POSIX UID and GID for relPath.
func (w *Workspace) Chown(relPath string, uid, gid uint32) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.setAttr(cleanRel, nil, &uid, &gid)
}

// setAttr changes virtual attributes. A hard-linked file keeps one set of
// attributes: all its names share one record, except for an entry without a
// file identity, where setAttr copies the change to every other recorded path
// of the same host file.
func (w *Workspace) setAttr(rel string, mode, uid, gid *uint32) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	cur := e.attr
	if e.virtual {
		if uid != nil {
			cur.UID = *uid
		}
		if gid != nil {
			cur.GID = *gid
		}
		cur.Ctime = now
		w.putRec(e.key, cur, rel)
		return nil
	}
	if e.isSymlink() {
		// A host symlink has no record to hold ownership.
		return errNotPermitted
	}
	if mode != nil {
		cur.Mode = cur.Mode&linux.S_IFMT | *mode&0o7777
	}
	if uid != nil {
		cur.UID = *uid
	}
	if gid != nil {
		cur.GID = *gid
	}
	cur.Ctime = now
	if err := w.checkMetaRoom(e.key); err != nil {
		return err
	}
	w.putRec(e.key, cur, rel)
	if e.key.isPath() && e.info.nlink > 1 && !e.isDir() {
		if err := w.propagateLinkAttrLocked(rel, e.info.id, cur); err != nil {
			return err
		}
	}
	return nil
}

// propagateLinkAttrLocked copies attr to every other recorded path that names
// the same host file. Only entries without file identities need it.
func (w *Workspace) propagateLinkAttrLocked(skip string, id hostID, attr POSIXAttr) error {
	if id == (hostID{}) {
		return nil
	}
	for _, k := range w.meta.keys() {
		if k.kind != kindPath || k.path == skip {
			continue
		}
		hostRel, err := w.hostPath(k.path)
		if err != nil {
			continue
		}
		info, err := w.host.lstat(hostRel)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotDir) {
				continue
			}
			return err
		}
		if info.id == id && info.kind == hostKindRegular {
			w.putRec(k, attr, k.path)
		}
	}
	return nil
}

// Symlink records a guest symbolic link in .gvx_meta. The host never receives
// a link. The target may be absolute or climb above the workspace, because the
// Sentry VFS resolves it in the guest namespace. Only an empty target and a
// target with a NUL byte fail.
func (w *Workspace) Symlink(target, linkRelPath string) error {
	cleanLink, err := CleanRelativePath(linkRelPath)
	if err != nil {
		return err
	}
	return w.symlink(target, cleanLink, 0, 0)
}

func (w *Workspace) symlink(target, rel string, uid, gid uint32) error {
	if err := validateGuestSymlinkTarget(target); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrExist
	}
	if err := w.checkParentDirLocked(rel); err != nil {
		return err
	}
	if err := w.checkMetaRoom(recKey{}); err != nil {
		return err
	}
	if _, _, err := w.createTargetLocked(rel); err != nil {
		return err
	}
	key, err := w.nameKeyLocked(rel)
	if err != nil {
		return err
	}
	now := time.Now().UnixNano()
	w.putRec(key, POSIXAttr{
		Mode:    linux.S_IFLNK | 0o777,
		UID:     uid,
		GID:     gid,
		Symlink: target,
		Atime:   now,
		Mtime:   now,
		Ctime:   now,
	}, rel)
	parent, _ := splitParent(rel)
	w.touchDirLocked(parent, now)
	return nil
}

func validateSymlinkTarget(linkRelPath, target string) error {
	targetSlash := target
	if hostSeparatorIsBackslash {
		targetSlash = strings.ReplaceAll(target, "\\", "/")
	}
	if strings.HasPrefix(targetSlash, "/") {
		return ErrPathTraversal
	}
	linkDir := path.Dir(linkRelPath)
	joined := path.Clean(path.Join(linkDir, targetSlash))
	if joined == ".." || strings.HasPrefix(joined, "../") || path.IsAbs(joined) {
		return ErrPathTraversal
	}
	return nil
}
