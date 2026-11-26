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
	_, err = w.rename(cleanOld, cleanNew)
	return err
}

// rename moves oldRel to newRel with POSIX semantics and returns any host
// symbolic links that were demoted to virtual entries (including on partial
// rollback errors).
func (w *Workspace) rename(oldRel, newRel string) ([]demotedSymlink, error) {
	w.maybeRefreshMeta(false)
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.renameLocked(oldRel, newRel, false, nil, 0)
}

// renameLocked is rename for a caller that holds w.mu for writing. When
// haveLock is true, the caller already holds w.flushMu and an exclusive lock
// on lf. extraMetaBytes reserves room for caller-owned metadata writes (such
// as a RENAME_WHITEOUT device record).
func (w *Workspace) renameLocked(oldRel, newRel string, haveLock bool, lf *os.File, extraMetaBytes int64) ([]demotedSymlink, error) {
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return nil, err
	}
	if oldRel == "." || newRel == "." {
		return nil, fs.ErrInvalid
	}
	if oldRel == newRel {
		if _, err := w.lookupLocked(oldRel); err != nil {
			return nil, err
		}
		return nil, nil
	}
	// Fast path for renaming a virtual symlink without taking .gvx_meta.lock:
	// moving a virtual record never creates or moves a host symlink or host dir.
	if w.meta.hasNames() {
		if k, r := w.virtualAtLocked(oldRel); r != nil {
			return nil, w.renameVirtualSrcLocked(oldRel, newRel, virtualEntry(k, r))
		}
	}
	return w.renameHostEntryLocked(oldRel, newRel, haveLock, lf, extraMetaBytes)
}

// renameVirtualSrcLocked renames a virtual symlink src from oldRel to newRel.
// Callers hold w.mu for writing.
func (w *Workspace) renameVirtualSrcLocked(oldRel, newRel string, src entry) error {
	if err := w.checkParentDirLocked(newRel); err != nil {
		return err
	}
	dst, dstProbe, dstErr := w.lookupProbeLocked(newRel)
	dstExists := dstErr == nil
	if dstErr != nil && !errors.Is(dstErr, fs.ErrNotExist) {
		return dstErr
	}
	_, dstPath, dstLeaf, err := w.resolveRenameHostPathsLocked(oldRel, newRel, src, dstProbe, dstExists)
	if err != nil {
		return err
	}
	noop, err := w.validateRenameDestinationLocked(newRel, dstPath, src, dst, dstExists)
	if err != nil || noop {
		return err
	}
	oldParent, oldName := splitParent(oldRel)
	newParent, newName := splitParent(newRel)
	if dstExists && !dst.virtual {
		if err := w.host.unlink(dstPath); err != nil {
			return err
		}
		w.removeDirNameLocked(newParent, newName, dstLeaf)
	}
	w.dropAltTree(newRel)
	w.moveAltTree(oldRel, newRel)
	w.dropAlt(oldParent, oldName)

	now := time.Now().UnixNano()
	w.moveRecordLocked(src, dst, dstExists, oldRel, newRel, now)
	w.touchDirLocked(oldParent, now)
	if !dstExists || dst.virtual {
		w.touchDirLocked(newParent, now)
	}
	return nil
}

// probeRenameSourceLocked resolves oldRel through pin and constructs the live
// entry via entryFromInfoAt (rejecting hostKindOther, handling hostKindSpecial,
// and validating host symlink targets). Callers hold w.mu and .gvx_meta.lock.
func (w *Workspace) probeRenameSourceLocked(oldParent, oldName, oldRel string, pin *dirPin) (entry, string, error) {
	probe, err := w.locateIn(oldParent, oldName, pin, func(leaf string) (hostInfo, error) {
		return w.host.lstatAt(pin.h, leaf)
	})
	if err != nil {
		return entry{}, "", err
	}
	if !probe.found || probe.hidden {
		return entry{}, "", probe.missingError(oldRel)
	}
	src, err := w.entryFromInfoAt(oldRel, probe.leaf, pin, probe.info)
	if err != nil {
		return entry{}, "", err
	}
	return src, probe.leaf, nil
}

// renameHostEntryLocked executes every non-virtual rename under the
// cross-sandbox metadata lock, holding one parent pin across lstatAt and
// renameAt so concurrent peer sandboxes or pin sweeps cannot swap a regular
// file into a host symlink or directory between lookup and renameAt.
func (w *Workspace) renameHostEntryLocked(oldRel, newRel string, haveLock bool, lockedLF *os.File, extraMetaBytes int64) ([]demotedSymlink, error) {
	var demoted []demotedSymlink
	err := w.withMetaExclusiveOrReuseLocked(haveLock, lockedLF, func(lf *os.File) error {
		if serr := w.syncMetaIfChangedLocked(lf); serr != nil {
			return serr
		}
		if w.meta.hasNames() {
			if k, r := w.virtualAtLocked(oldRel); r != nil {
				if verr := w.renameVirtualSrcLocked(oldRel, newRel, virtualEntry(k, r)); verr != nil {
					return verr
				}
				_ = w.flushMetaLocked(lf)
				return nil
			}
		}

		oldParent, oldName := splitParent(oldRel)
		newParent, newName := splitParent(newRel)

		var oldPin *dirPin
		var perr error
		if oldParent == newParent {
			oldPin, perr = w.acquirePin(oldParent)
		} else {
			oldPin, perr = w.acquireFreshPin(oldParent)
		}
		if perr != nil {
			return perr
		}
		defer func() {
			if oldPin != nil {
				w.releasePin(oldPin)
			}
		}()

		src, srcLeaf, err := w.probeRenameSourceLocked(oldParent, oldName, oldRel, oldPin)
		if err != nil {
			return err
		}

		// When a same-parent rename turns out to target a host symlink or
		// directory, upgrade to a freshly verified parent pin from root and
		// re-probe before checking containment.
		if oldParent == newParent && (src.isSymlink() || src.isDir()) {
			w.releasePin(oldPin)
			oldPin = nil
			oldPin, perr = w.acquireFreshPin(oldParent)
			if perr != nil {
				return perr
			}
			src, srcLeaf, err = w.probeRenameSourceLocked(oldParent, oldName, oldRel, oldPin)
			if err != nil {
				return err
			}
		}

		if src.isDir() && strings.HasPrefix(newRel, oldRel+"/") {
			return errInvalidMove
		}
		if oldParent != newParent {
			if err := w.checkParentDirLocked(newRel); err != nil {
				return err
			}
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

		// Fast O(1) path for same-parent non-symlink, non-directory renames:
		// oldPin was held continuously from probeRenameSourceLocked through
		// renameAt under .gvx_meta.lock.
		if oldParent == newParent && !src.isSymlink() && !src.isDir() {
			if rerr := w.host.renameAt(oldPin.h, srcLeaf, oldPin.h, dstLeaf); rerr != nil {
				return rerr
			}
			w.finishNonDirHostRenameLocked(oldParent, oldName, newParent, newName, oldRel, newRel, srcLeaf, dstLeaf, src, dst, dstExists)
			if dstExists && dst.virtual {
				_ = w.flushMetaLocked(lf)
			}
			return nil
		}

		var badDstLeaf map[string]struct{}
		if dstLeaf != newName {
			badDstLeaf = map[string]struct{}{newRel: {}}
		}

		switch src.info.kind {
		case hostKindSymlink:
			safe := !(dstExists && dst.virtual && w.dstVirtualHostCollidesLocked(newRel))
			if safe {
				_, safe = w.hostSymlinkSafeAtLocked(newRel, dstLeaf, src.attr.Symlink, nil, badDstLeaf)
			}
			if !safe {
				var derr error
				demoted, derr = w.demoteSingleSymlinkRenameLocked(lf, oldRel, newRel, srcPath, dstLeaf, src, dst, dstExists, extraMetaBytes)
				return derr
			}
			newPin, perr := w.acquireFreshPin(newParent)
			if perr != nil {
				return perr
			}
			defer w.releasePin(newPin)
			if rerr := w.host.renameAt(oldPin.h, srcLeaf, newPin.h, dstLeaf); rerr != nil {
				return rerr
			}
			w.finishNonDirHostRenameLocked(oldParent, oldName, newParent, newName, oldRel, newRel, srcLeaf, dstLeaf, src, dst, dstExists)
			if dstExists && dst.virtual {
				_ = w.flushMetaLocked(lf)
			}
			return nil

		case hostKindDir:
			overrides := map[string]string{newRel: oldRel, oldRel: ""}
			cands, serr := w.scanDirHostSymlinksLocked(oldRel, newRel, overrides, badDstLeaf)
			if serr != nil {
				return serr
			}
			demotedRecs, partial, derr := w.demoteCandidatesInPlaceLocked(lf, cands, extraMetaBytes)
			if derr != nil {
				demoted = partial
				return derr
			}

			w.closeSubtreeHandlesLocked(oldRel)
			if dstExists && dst.isDir() && !dst.virtual {
				w.closeSubtreeHandlesLocked(newRel)
			}
			newPin, perr := w.acquireFreshPin(newParent)
			if perr != nil {
				demoted = w.rollbackDemotedLocked(lf, demotedRecs)
				return perr
			}
			defer w.releasePin(newPin)

			if dstExists && dst.isDir() && !dst.virtual && !hostRenameReplacesDir {
				if rerr := w.host.rmdirAt(newPin.h, dstLeaf); rerr != nil {
					demoted = w.rollbackDemotedLocked(lf, demotedRecs)
					return rerr
				}
			}
			quiesced := w.handles.quiesce(oldRel)
			if rerr := w.host.renameAt(oldPin.h, srcLeaf, newPin.h, dstLeaf); rerr != nil {
				_ = quiesced.finish(false, "")
				demoted = w.rollbackDemotedLocked(lf, demotedRecs)
				return rerr
			}
			w.removeDirNameLocked(oldParent, oldName, srcLeaf)
			w.addDirNameLocked(newParent, newName, dstLeaf)
			w.dropDirNamesLocked(oldRel)
			if dstExists && dst.isDir() {
				w.dropDirNamesLocked(newRel)
			}
			w.dropAltTree(newRel)
			w.moveAltTree(oldRel, newRel)
			w.dropAlt(oldParent, oldName)
			w.setAlt(newParent, newName, dstLeaf)
			_ = quiesced.finish(true, newRel)

			w.moveRecordLocked(src, dst, dstExists, oldRel, newRel, time.Now().UnixNano())
			if len(demotedRecs) > 0 || (dstExists && dst.virtual) {
				_ = w.flushMetaLocked(lf)
			}
			if len(demotedRecs) > 0 {
				demoted = w.finalizeDemotedLocked(demotedRecs)
			}
			return nil

		case hostKindRegular, hostKindSpecial:
			newPin, perr := w.acquireFreshPin(newParent)
			if perr != nil {
				return perr
			}
			defer w.releasePin(newPin)
			if rerr := w.host.renameAt(oldPin.h, srcLeaf, newPin.h, dstLeaf); rerr != nil {
				return rerr
			}
			w.finishNonDirHostRenameLocked(oldParent, oldName, newParent, newName, oldRel, newRel, srcLeaf, dstLeaf, src, dst, dstExists)
			if dstExists && dst.virtual {
				_ = w.flushMetaLocked(lf)
			}
			return nil

		default:
			return ErrPathTraversal
		}
	})
	return demoted, err
}

// finishNonDirHostRenameLocked updates caches, handles, and metadata after a
// non-directory host rename succeeds. Callers hold w.mu for writing.
func (w *Workspace) finishNonDirHostRenameLocked(oldParent, oldName, newParent, newName, oldRel, newRel, srcLeaf, dstLeaf string, src, dst entry, dstExists bool) {
	w.removeDirNameLocked(oldParent, oldName, srcLeaf)
	w.addDirNameLocked(newParent, newName, dstLeaf)
	w.dropAltTree(newRel)
	w.moveAltTree(oldRel, newRel)
	w.dropAlt(oldParent, oldName)
	w.setAlt(newParent, newName, dstLeaf)
	if dstExists {
		w.handles.detach(newRel)
	}
	w.handles.moveFile(oldRel, newRel)
	w.moveRecordLocked(src, dst, dstExists, oldRel, newRel, time.Now().UnixNano())
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

// link creates a hard link under the cross-sandbox metadata lock, verifying
// the live source entry through a continuously held parent pin so a peer
// sandbox cannot replace oldRel with a host symlink before linkAt executes.
func (w *Workspace) link(oldRel, newRel string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.checkWritableLocked(oldRel, newRel); err != nil {
		return err
	}
	if oldRel == "." {
		return errNotPermitted
	}
	if newRel == "." {
		return fs.ErrExist
	}
	return w.withMetaExclusiveLocked(func(lf *os.File) error {
		if serr := w.syncMetaIfChangedLocked(lf); serr != nil {
			return serr
		}
		if w.meta.hasNames() {
			if _, vr := w.virtualAtLocked(oldRel); vr != nil {
				return errNotPermitted
			}
		}
		oldParent, oldName := splitParent(oldRel)
		newParent, newName := splitParent(newRel)

		var oldPin *dirPin
		var err error
		if oldParent == newParent {
			oldPin, err = w.acquirePin(oldParent)
		} else {
			oldPin, err = w.acquireFreshPin(oldParent)
		}
		if err != nil {
			return err
		}
		defer w.releasePin(oldPin)

		probe, err := w.locateIn(oldParent, oldName, oldPin, func(leaf string) (hostInfo, error) {
			return w.host.lstatAt(oldPin.h, leaf)
		})
		if err != nil {
			return err
		}
		if !probe.found || probe.hidden {
			return probe.missingError(oldRel)
		}
		if probe.info.kind == hostKindOther {
			return ErrPathTraversal
		}
		if probe.info.kind != hostKindRegular {
			return errNotPermitted
		}
		src, err := w.entryFromInfoAt(oldRel, probe.leaf, oldPin, probe.info)
		if err != nil {
			return err
		}
		if src.isDir() || src.virtual || src.isSymlink() {
			return errNotPermitted
		}
		srcLeaf := probe.leaf

		newPin := oldPin
		if oldParent != newParent {
			if err := w.checkParentDirLocked(newRel); err != nil {
				return err
			}
			newPin, err = w.acquireFreshPin(newParent)
			if err != nil {
				return err
			}
			defer w.releasePin(newPin)
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
		if err := w.host.linkAt(oldPin.h, srcLeaf, newPin.h, leaf); err != nil {
			return err
		}
		if src.key.isPath() {
			w.putRec(recKey{kind: kindPath, path: newRel}, src.attr, newRel)
		}
		w.setAlt(newParent, newName, leaf)
		w.addDirNameLocked(newParent, newName, leaf)
		return nil
	})
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
	w.maybeRefreshMeta(false)
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
// Chtimes updates the access and modification times of relPath inside the
// workspace without following symbolic links. A nil time leaves that timestamp
// unchanged.
func (w *Workspace) Chtimes(relPath string, atime, mtime *time.Time) error {
	cleanRel, err := CleanRelativePath(relPath)
	if err != nil {
		return err
	}
	return w.chtimes(cleanRel, atime, mtime)
}

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
