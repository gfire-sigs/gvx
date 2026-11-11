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
	"io/fs"
	"os"
	"strings"
	"time"
)

// Rename atomically renames oldRel to newRel inside the workspace using POSIX
// rename semantics (even when oldRel or newRel has open file descriptors) and
// updates .gvx_meta.
func (w *Workspace) Rename(oldRel, newRel string) error {
	cleanOld, err := CleanRelativePath(oldRel)
	if err != nil {
		return err
	}
	cleanNew, err := CleanRelativePath(newRel)
	if err != nil {
		return err
	}
	return w.rename(cleanOld, cleanNew)
}

// rename moves oldRel to newRel with POSIX semantics.
func (w *Workspace) rename(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.renameLocked(oldRel, newRel)
}

// renameLocked is rename for a caller that holds w.mu for writing.
func (w *Workspace) renameLocked(oldRel, newRel string) error {
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	if oldRel == "." || newRel == "." {
		return fs.ErrInvalid
	}
	src, err := w.lookupLocked(oldRel)
	if err != nil {
		return err
	}
	if oldRel == newRel {
		return nil
	}
	if src.isDir() && strings.HasPrefix(newRel, oldRel+"/") {
		return errInvalidMove
	}
	if err := w.checkParentDirLocked(newRel); err != nil {
		return err
	}

	dst, dstProbe, dstErr := w.lookupProbeLocked(newRel)
	dstExists := dstErr == nil
	if dstErr != nil && !errors.Is(dstErr, fs.ErrNotExist) {
		return dstErr
	}

	srcPath, dstPath, dstLeaf, err := w.resolveRenameHostPathsLocked(oldRel, newRel, src, dstProbe, dstExists)
	if err != nil {
		return err
	}
	noop, err := w.validateRenameDestinationLocked(newRel, dstPath, src, dst, dstExists)
	if err != nil || noop {
		return err
	}

	if err := w.executeRenameOnHostLocked(oldRel, newRel, srcPath, dstPath, dstLeaf, src, dst, dstExists); err != nil {
		return err
	}

	now := time.Now().UnixNano()
	w.moveRecordLocked(src, dst, dstExists, oldRel, newRel, now)
	if src.virtual {
		oldParent, _ := splitParent(oldRel)
		newParent, _ := splitParent(newRel)
		w.touchDirLocked(oldParent, now)
		if !dstExists || dst.virtual {
			w.touchDirLocked(newParent, now)
		}
	}
	return nil
}

// resolveRenameHostPathsLocked computes the host paths and destination leaf for a rename.
func (w *Workspace) resolveRenameHostPathsLocked(oldRel, newRel string, src entry, dstProbe hostProbe, dstExists bool) (srcPath, dstPath, dstLeaf string, err error) {
	oldParent, _ := splitParent(oldRel)
	newParent, newName := splitParent(newRel)
	if !src.virtual {
		if srcPath, err = w.hostPath(oldRel); err != nil {
			return "", "", "", err
		}
	}
	dstLeaf = dstProbe.create
	if !dstExists && dstProbe.collided {
		switch {
		case dstProbe.occupant != "" && !src.virtual && strings.EqualFold(oldParent, newParent) && dstProbe.occupant == leafOf(srcPath):
			if dstLeaf, err = w.codec.leafForm(newName); err != nil {
				return "", "", "", err
			}
		case dstProbe.occupant == "" && !strings.EqualFold(oldRel, newRel):
			return "", "", "", fs.ErrExist
		}
	}
	if dstExists || dstLeaf == "" {
		if dstLeaf, err = w.hostLeaf(newParent, newName); err != nil {
			return "", "", "", err
		}
	}
	newHostDir, err := w.hostPath(newParent)
	if err != nil {
		return "", "", "", err
	}
	return srcPath, hostChild(newHostDir, dstLeaf), dstLeaf, nil
}

// validateRenameDestinationLocked enforces POSIX type rules on an existing destination.
func (w *Workspace) validateRenameDestinationLocked(newRel, dstPath string, src, dst entry, dstExists bool) (noop bool, err error) {
	if !dstExists {
		return false, nil
	}
	if !src.virtual && !dst.virtual && src.info.id == dst.info.id && !src.isDir() {
		return true, nil
	}
	switch {
	case src.isDir() && !dst.isDir():
		return false, errNotDir
	case !src.isDir() && dst.isDir():
		return false, errIsDir
	case src.isDir():
		return false, w.purgeEmptyDirLocked(newRel, dstPath)
	}
	return false, nil
}

// executeRenameOnHostLocked performs the host rename or unlink and updates directory name caches and handles.
func (w *Workspace) executeRenameOnHostLocked(oldRel, newRel, srcPath, dstPath, dstLeaf string, src, dst entry, dstExists bool) error {
	oldParent, oldName := splitParent(oldRel)
	newParent, newName := splitParent(newRel)
	var quiesced *quiescedTree

	if src.virtual {
		if dstExists && !dst.virtual {
			if err := w.host.unlink(dstPath); err != nil {
				return err
			}
			w.removeDirNameLocked(newParent, newName, dstLeaf)
		}
	} else {
		if src.isDir() {
			w.closeSubtreeHandlesLocked(oldRel)
		}
		if dstExists && dst.isDir() && !dst.virtual {
			w.closeSubtreeHandlesLocked(newRel)
		}
		if dstExists && dst.isDir() && !dst.virtual && !hostRenameReplacesDir {
			if err := w.host.rmdir(dstPath); err != nil {
				return err
			}
		}
		if src.isDir() {
			quiesced = w.handles.quiesce(oldRel)
		}
		srcLeaf := leafOf(srcPath)
		if err := w.renameHostLocked(oldRel, newRel, srcLeaf, dstLeaf); err != nil {
			_ = quiesced.finish(false, "")
			return err
		}
		w.removeDirNameLocked(oldParent, oldName, srcLeaf)
		w.addDirNameLocked(newParent, newName, dstLeaf)
		if src.isDir() {
			w.dropDirNamesLocked(oldRel)
		}
		if dstExists && dst.isDir() {
			w.dropDirNamesLocked(newRel)
		}
	}

	w.dropAltTree(newRel)
	w.moveAltTree(oldRel, newRel)
	w.dropAlt(oldParent, oldName)
	if !src.virtual {
		w.setAlt(newParent, newName, dstLeaf)
		if src.isDir() {
			_ = quiesced.finish(true, newRel)
		} else {
			if dstExists {
				w.handles.detach(newRel)
			}
			w.handles.moveFile(oldRel, newRel)
		}
	}
	return nil
}

// moveRecordLocked updates the metadata table after a rename. Callers hold w.mu for writing.
func (w *Workspace) moveRecordLocked(src, dst entry, dstExists bool, oldRel, newRel string, now int64) {
	if dstExists {
		if dst.key.isPath() || dst.virtual || dst.isDir() || dst.info.nlink <= 1 {
			w.meta.del(dst.key)
		}
		delete(w.dirTimes, dst.key)
	}
	if src.key.isPath() {
		w.meta.del(recKey{kind: kindPath, path: newRel})
	}
	delete(w.dirTimes, src.key)
	if src.virtual {
		w.meta.del(src.key)
		if nk, err := w.nameKeyLocked(newRel); err == nil {
			attr := src.attr
			attr.Ctime = now
			w.putRec(nk, attr, newRel)
		}
		return
	}
	if r := w.meta.get(src.key); r != nil {
		attr := r.attr
		attr.Ctime = now
		nk := src.key
		if nk.isPath() {
			w.meta.del(src.key)
			nk = recKey{kind: kindPath, path: newRel}
		}
		w.putRec(nk, attr, newRel)
	}
	if src.isDir() && w.meta.hasPathRecs() {
		w.meta.moveTree(oldRel, newRel)
	}
}

// link creates a hard link. The new path shares the host file and its
// attributes with oldRel.
func (w *Workspace) link(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	src, err := w.lookupLocked(oldRel)
	if err != nil {
		return err
	}
	if src.isDir() || src.virtual || src.isSymlink() {
		return errNotPermitted
	}
	if err := w.checkParentDirLocked(newRel); err != nil {
		return err
	}
	oldParent, oldName := splitParent(oldRel)
	srcLeaf, err := w.hostLeaf(oldParent, oldName)
	if err != nil {
		return err
	}
	if src.key.isPath() {
		if err := w.checkMetaRoom(recKey{}); err != nil {
			return err
		}
	}
	_, leaf, err := w.createTargetLocked(newRel)
	if err != nil {
		return err
	}
	if err := w.pinnedPairLocked(oldRel, newRel, func(oldDir, newDir hostDirHandle) error {
		return w.host.linkAt(oldDir, srcLeaf, newDir, leaf)
	}); err != nil {
		return err
	}
	if src.key.isPath() {
		w.putRec(recKey{kind: kindPath, path: newRel}, src.attr, newRel)
	}
	parent, name := splitParent(newRel)
	w.setAlt(parent, name, leaf)
	w.addDirNameLocked(parent, name, leaf)
	return nil
}

// Unlink removes a non-directory from the workspace using POSIX delete
// semantics (even when relPath has open handles) and updates .gvx_meta.
func (w *Workspace) Unlink(relPath string) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.unlink(cleanRel)
}

func (w *Workspace) unlink(rel string) error {
	_, err := w.unlinkLast(rel)
	return err
}

// unlinkLast is unlink that also reports whether the call removed the last
// name of the file. A file with another hard link, and a virtual symbolic
// link, report false.
func (w *Workspace) unlinkLast(rel string) (last bool, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return false, err
	}
	if rel == "." {
		return false, errIsDir
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return false, err
	}
	if e.isDir() {
		return false, errIsDir
	}
	if !e.virtual {
		parent, name := splitParent(rel)
		leaf, err := w.hostLeaf(parent, name)
		if err != nil {
			return false, err
		}
		if err := w.unlinkHostLocked(rel, leaf, false); err != nil {
			return false, err
		}
		last = e.info.nlink <= 1
		w.handles.detach(rel)
		w.removeDirNameLocked(parent, name, leaf)
		w.dropAlt(parent, name)
		if last || e.key.isPath() {
			w.meta.del(e.key)
		}
		return last, nil
	}
	parent, _ := splitParent(rel)
	w.touchDirLocked(parent, time.Now().UnixNano())
	w.meta.del(e.key)
	return last, nil
}

// Rmdir removes an empty directory at relPath inside the pinned workspace.
func (w *Workspace) Rmdir(relPath string) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.rmdir(cleanRel)
}

func (w *Workspace) rmdir(rel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	if rel == "." {
		return fs.ErrInvalid
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	if !e.isDir() {
		return errNotDir
	}
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return err
	}
	if err := w.purgeEmptyDirLocked(rel, hostRel); err != nil {
		return err
	}
	// Windows refuses to remove a directory that has an open handle.
	w.closeSubtreeHandlesLocked(rel)
	if err := w.unlinkHostLocked(rel, leafOf(hostRel), true); err != nil {
		return err
	}
	w.meta.del(e.key)
	delete(w.dirTimes, e.key)
	parent, name := splitParent(rel)
	w.removeDirNameLocked(parent, name, leafOf(hostRel))
	w.dropDirNamesLocked(rel)
	w.dropAltTree(rel)
	return nil
}

// Truncate changes the size of the regular file at relPath.
func (w *Workspace) Truncate(relPath string, size int64) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	if w.readOnly {
		return ErrReadOnly
	}
	f, _, err := w.openRegular(cleanRel, os.O_WRONLY)
	if err != nil {
		return err
	}
	truncErr := setFileSize(f, size)
	closeErr := f.Close()
	return errors.Join(truncErr, closeErr)
}

// syncDir flushes the host directory that holds rel's children, so a
// completed create, rename, or unlink survives a host crash.
func (w *Workspace) syncDir(rel string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return os.ErrClosed
	}
	pin, err := w.acquirePin(rel)
	if err != nil {
		return err
	}
	defer w.releasePin(pin)
	return w.host.syncDirAt(pin.h)
}

// chtimes sets host timestamps of a host file, or the recorded timestamps of
// a virtual symlink. A nil time stays unchanged.
func (w *Workspace) chtimes(rel string, atime, mtime *time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(rel); err != nil {
		return err
	}
	e, err := w.lookupLocked(rel)
	if err != nil {
		return err
	}
	if e.virtual {
		m := e.attr
		if atime != nil {
			m.Atime = atime.UnixNano()
		}
		if mtime != nil {
			m.Mtime = mtime.UnixNano()
		}
		m.Ctime = time.Now().UnixNano()
		w.putRec(e.key, m, rel)
		return nil
	}
	if err := w.chtimesHostLocked(rel, atime, mtime); err != nil {
		return err
	}
	if mtime != nil {
		delete(w.dirTimes, e.key)
		if r := w.meta.get(e.key); r != nil && r.attr.Mtime != 0 {
			a := r.attr
			a.Mtime = 0
			w.putRec(e.key, a, rel)
		}
	}
	return nil
}

// renameHostLocked renames the stored entry srcLeaf of the guest path oldRel
// to dstLeaf below the directory of newRel, through the pinned handles of
// both directories. Callers hold w.mu for writing.
func (w *Workspace) renameHostLocked(oldRel, newRel, srcLeaf, dstLeaf string) error {
	return w.pinnedPairLocked(oldRel, newRel, func(oldDir, newDir hostDirHandle) error {
		return w.host.renameAt(oldDir, srcLeaf, newDir, dstLeaf)
	})
}

// pinnedPairLocked runs fn with the pinned handles of the directories that
// hold oldRel and newRel. Callers hold w.mu.
func (w *Workspace) pinnedPairLocked(oldRel, newRel string, fn func(oldDir, newDir hostDirHandle) error) error {
	oldPin, err := w.parentPinLocked(oldRel)
	if err != nil {
		return err
	}
	defer w.releasePin(oldPin)
	newPin, err := w.parentPinLocked(newRel)
	if err != nil {
		return err
	}
	defer w.releasePin(newPin)
	return fn(oldPin.h, newPin.h)
}

// unlinkHostLocked removes the stored entry leaf of the guest path rel from
// its host directory, through the pinned handle of that directory. Callers
// hold w.mu for writing.
func (w *Workspace) unlinkHostLocked(rel, leaf string, dir bool) error {
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return err
	}
	defer w.releasePin(pin)
	if dir {
		return w.host.rmdirAt(pin.h, leaf)
	}
	return w.host.unlinkAt(pin.h, leaf)
}

// chtimesHostLocked sets the host times of rel through the pinned handle of its
// directory. The workspace root has no such directory, so it takes the path
// call. Callers hold w.mu for writing.
func (w *Workspace) chtimesHostLocked(rel string, atime, mtime *time.Time) error {
	if rel == "." {
		return w.host.chtimes(rel, atime, mtime)
	}
	parent, name := splitParent(rel)
	leaf, err := w.hostLeaf(parent, name)
	if err != nil {
		return err
	}
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return err
	}
	defer w.releasePin(pin)
	return w.host.chtimesAt(pin.h, leaf, atime, mtime)
}
