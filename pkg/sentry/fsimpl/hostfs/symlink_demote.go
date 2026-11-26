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
	"os"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// demotedSymlink reports a host symbolic link whose backing representation
// changed during a rename or exchange operation (demoted to virtual, or
// re-materialized with a new host inode identity during rollback) so the VFS
// layer can update its cached dentry/inode in place.
type demotedSymlink struct {
	rel   string
	entry entry
}

// hostSymlinkCandidate describes a visible host symbolic link that cannot
// remain a native host link at its post-operation path destRel.
type hostSymlinkCandidate struct {
	srcRel    string
	destRel   string
	parentRel string
	guestName string
	leaf      string
	target    string
	info      hostInfo
	attr      POSIXAttr
	oldKey    recKey
}

// demotedRecord retains enough state to roll back an in-place demotion if the
// host rename or exchange subsequently fails.
type demotedRecord struct {
	cand       hostSymlinkCandidate
	virtKey    recKey
	virtAttr   POSIXAttr
	prevVirt   *rec
	prevHost   *rec
	hostUnlink bool
}

// withMetaExclusiveOrReuseLocked executes fn under w.flushMu and an exclusive
// .gvx_meta.lock. When haveLock is true, the caller already holds both locks
// and passes lf through without re-locking. Callers hold w.mu for writing.
func (w *Workspace) withMetaExclusiveOrReuseLocked(haveLock bool, lf *os.File, fn func(lf *os.File) error) error {
	if haveLock {
		return fn(lf)
	}
	return w.withMetaExclusiveLocked(fn)
}

// openRawHostDirLocked walks raw host directory components starting at the
// pinned workspace root without applying guest-name visibility filters or
// cached pin shortcuts. When owned is true, the caller must close h via
// w.host.closeDir(h).
func (w *Workspace) openRawHostDirLocked(rawHostRel string) (h hostDirHandle, owned bool, err error) {
	if rawHostRel == "" || rawHostRel == "." {
		return w.host.rootDir(), false, nil
	}
	cur := w.host.rootDir()
	curOwned := false
	for _, part := range strings.Split(rawHostRel, "/") {
		next, _, oerr := w.host.openDirAt(cur, part)
		if curOwned {
			_ = w.host.closeDir(cur)
		}
		if oerr != nil {
			return 0, false, oerr
		}
		cur = next
		curOwned = true
	}
	return cur, curOwned, nil
}

// scanDirHostSymlinksLocked walks the host directory tree rooted at srcDir
// iteratively on raw host directory handles (closing each handle right after
// readDirAt to bound open FDs) and inspects every host symbolic link:
//   - Hidden-name subdirectories and hidden-name symlinks are traversed rather
//     than skipped. Any host symlink that is outside the workspace boundary,
//     hidden by name, or shadowed by a virtual symlink while unsafe at destRel
//     causes ErrPathTraversal so a rename or exchange cannot unhide, retarget,
//     or leave an unsafe host link on disk.
//   - Visible host symlinks that would violate hostSymlinkSafeAtLocked at
//     destRel are returned for durable pre-move demotion.
//
// Callers hold w.mu for writing and the exclusive metadata lock.
func (w *Workspace) scanDirHostSymlinksLocked(srcDir, dstDir string, overrides map[string]string, badDstLeaf map[string]struct{}) ([]hostSymlinkCandidate, error) {
	srcHostRel, err := w.hostPath(srcDir)
	if err != nil {
		return nil, err
	}
	type scanFrame struct {
		rawHostRel    string
		guestRel      string
		hiddenSubtree bool
	}
	var cands []hostSymlinkCandidate
	stack := []scanFrame{{rawHostRel: srcHostRel, guestRel: srcDir}}
	for len(stack) > 0 {
		cur := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		var (
			pin    *dirPin
			dirH   hostDirHandle
			owned  bool
			dirKey recKey
		)
		if !cur.hiddenSubtree {
			if p, perr := w.acquireFreshPin(cur.guestRel); perr == nil {
				pin = p
				dirH = p.h
				dirKey = w.dirKeyOf(p, cur.guestRel)
			}
		}
		if pin == nil {
			var oerr error
			dirH, owned, oerr = w.openRawHostDirLocked(cur.rawHostRel)
			if oerr != nil {
				if isNotExist(oerr) {
					continue
				}
				return nil, oerr
			}
			dirInfo, ferr := w.host.fstatDir(dirH)
			if ferr != nil {
				if owned {
					_ = w.host.closeDir(dirH)
				}
				return nil, ferr
			}
			dirKey = w.keyOf(cur.guestRel, dirInfo)
		}
		releaseCur := func() {
			if pin != nil {
				w.releasePin(pin)
			} else if owned {
				_ = w.host.closeDir(dirH)
			}
		}
		entries, rerr := w.host.readDirAt(dirH)
		if rerr != nil {
			releaseCur()
			return nil, rerr
		}

		var subDirs []scanFrame
		for _, e := range entries {
			if e.kind == hostKindRegular && cur.rawHostRel == "." && w.isReservedPath(e.name) {
				continue
			}
			hiddenName := w.hiddenByName(e.name)
			switch e.kind {
			case hostKindDir:
				guest := w.listName(cur.guestRel, e.name)
				shadowed := w.meta.has(dirKey.withName(guest))
				subDirs = append(subDirs, scanFrame{
					rawHostRel:    joinRelPath(cur.rawHostRel, e.name),
					guestRel:      joinRelPath(cur.guestRel, guest),
					hiddenSubtree: cur.hiddenSubtree || hiddenName || shadowed,
				})
			case hostKindSymlink:
				guest := w.listName(cur.guestRel, e.name)
				subRel := joinRelPath(cur.guestRel, guest)
				target, lerr := w.host.readlinkAt(dirH, e.name)
				if lerr != nil {
					if isNotExist(lerr) {
						continue
					}
					releaseCur()
					return nil, lerr
				}
				if validateSymlinkTarget(subRel, target) != nil {
					releaseCur()
					return nil, ErrPathTraversal
				}
				suffix := strings.TrimPrefix(subRel, srcDir)
				destSubRel := dstDir + suffix
				_, safe := w.hostSymlinkSafeAtLocked(destSubRel, e.name, target, overrides, badDstLeaf)

				if cur.hiddenSubtree || hiddenName {
					if !safe {
						releaseCur()
						return nil, ErrPathTraversal
					}
					// Keep hidden-name entries out of .gvx_meta.
					continue
				}
				if w.meta.has(dirKey.withName(guest)) {
					// A virtual symlink shadows this host link in guest view;
					// refuse moving the directory if the shadowed host link
					// would become unsafe at its destination.
					if !safe {
						releaseCur()
						return nil, ErrPathTraversal
					}
					continue
				}
				if safe {
					continue
				}
				info, serr := w.host.lstatAt(dirH, e.name)
				if serr != nil {
					if isNotExist(serr) {
						continue
					}
					releaseCur()
					return nil, serr
				}
				attr := w.effectiveSymlinkAttr(subRel, info, target)
				cands = append(cands, hostSymlinkCandidate{
					srcRel:    subRel,
					destRel:   destSubRel,
					parentRel: cur.guestRel,
					guestName: guest,
					leaf:      e.name,
					target:    target,
					info:      info,
					attr:      attr,
					oldKey:    w.keyOf(subRel, info),
				})
			}
		}
		releaseCur()
		stack = append(stack, subDirs...)
	}
	return cands, nil
}

// buildVirtualSymlinkAttr constructs the virtual .gvx_meta attribute record
// for a demoted host symbolic link, preserving UID, GID, xattrs, and times.
func buildVirtualSymlinkAttr(attr POSIXAttr, info hostInfo, now int64) POSIXAttr {
	atime := now
	if !info.atime.IsZero() {
		atime = info.atime.UnixNano()
	}
	mtime := now
	if !info.mtime.IsZero() {
		mtime = info.mtime.UnixNano()
	}
	return POSIXAttr{
		Mode:    linux.S_IFLNK | 0o777,
		UID:     attr.UID,
		GID:     attr.GID,
		Symlink: attr.Symlink,
		Xattrs:  attr.Xattrs,
		Atime:   atime,
		Mtime:   mtime,
		Ctime:   now,
	}
}

// demoteCandidatesInPlaceLocked converts each candidate host symlink into a
// virtual symlink at its current path srcRel before the host rename or
// exchange executes:
//  1. Checks .gvx_meta memory room for all candidates plus extraMetaBytes.
//  2. Inserts all virtual symlink records and flushes .gvx_meta durably before
//     unlinking any host symlink, closing any crash-loss or peer-ENOENT window.
//  3. Unlinks each host symlink via a fresh pinned directory handle and removes
//     any superseded host-symlink metadata record.
//
// Callers hold w.mu for writing, w.flushMu, and an exclusive lock on lf.
func (w *Workspace) demoteCandidatesInPlaceLocked(lf *os.File, cands []hostSymlinkCandidate, extraMetaBytes int64) ([]demotedRecord, []demotedSymlink, error) {
	if len(cands) == 0 {
		return nil, nil, nil
	}
	now := time.Now().UnixNano()
	recs := make([]demotedRecord, len(cands))
	needBytes := extraMetaBytes

	for i, c := range cands {
		pin, err := w.acquireFreshPin(c.parentRel)
		if err != nil {
			return nil, nil, err
		}
		vk := w.dirKeyOf(pin, c.parentRel).withName(c.guestName)
		w.releasePin(pin)
		vAttr := buildVirtualSymlinkAttr(c.attr, c.info, now)
		if !w.meta.has(vk) {
			needBytes += recSize(vk, &rec{attr: vAttr, hint: c.srcRel})
		}
		var prevHost *rec
		if c.oldKey != (recKey{}) {
			prevHost = w.meta.get(c.oldKey)
		}
		recs[i] = demotedRecord{
			cand:     c,
			virtKey:  vk,
			virtAttr: vAttr,
			prevVirt: w.meta.get(vk),
			prevHost: prevHost,
		}
	}
	if err := w.checkMetaRoomBytes(needBytes); err != nil {
		return nil, nil, err
	}

	// Step 1: Write virtual records and flush durably before any host unlink.
	for i := range recs {
		r := &recs[i]
		w.putRec(r.virtKey, r.virtAttr, r.cand.srcRel)
	}
	if err := w.flushMetaLocked(lf); err != nil {
		for i := range recs {
			r := &recs[i]
			if r.prevVirt != nil {
				w.meta.put(r.virtKey, r.prevVirt)
			} else {
				w.meta.del(r.virtKey)
			}
		}
		return nil, nil, err
	}

	// Step 2: Unlink each host symlink and remove its superseded host record.
	for i := range recs {
		r := &recs[i]
		pin, err := w.acquireFreshPin(r.cand.parentRel)
		if err != nil {
			remaining := w.rollbackDemotedLocked(lf, recs)
			return nil, remaining, err
		}
		uerr := w.host.unlinkAt(pin.h, r.cand.leaf)
		w.releasePin(pin)
		if uerr != nil && !isNotExist(uerr) {
			remaining := w.rollbackDemotedLocked(lf, recs)
			return nil, remaining, uerr
		}
		r.hostUnlink = true
		w.removeDirNameLocked(r.cand.parentRel, r.cand.guestName, r.cand.leaf)
		w.dropAlt(r.cand.parentRel, r.cand.guestName)
		if r.cand.oldKey != (recKey{}) && r.cand.oldKey != r.virtKey && (r.cand.oldKey.isPath() || r.cand.info.nlink <= 1) {
			w.meta.del(r.cand.oldKey)
		}
	}
	return recs, nil, nil
}

// rollbackDemotedLocked attempts to restore host symlinks that were demoted in
// place after a subsequent host operation failed. It returns VFS updates both
// for items that stayed virtual (for example on Windows or ENOSPC) and for
// items re-materialized on the host with a new host inode identity.
func (w *Workspace) rollbackDemotedLocked(lf *os.File, recs []demotedRecord) []demotedSymlink {
	if len(recs) == 0 {
		return nil
	}
	var updates []demotedSymlink
	for i := range recs {
		r := &recs[i]
		if !r.hostUnlink {
			if r.prevVirt != nil {
				w.meta.put(r.virtKey, r.prevVirt)
			} else {
				w.meta.del(r.virtKey)
			}
			continue
		}
		restored := false
		var newInfo hostInfo
		var newKey recKey
		if pin, err := w.acquireFreshPin(r.cand.parentRel); err == nil {
			if serr := w.host.symlinkAt(pin.h, r.cand.leaf, r.cand.target); serr == nil {
				if info, lerr := w.host.lstatAt(pin.h, r.cand.leaf); lerr == nil {
					restored = true
					newInfo = info
					newKey = w.keyOf(r.cand.srcRel, info)
					w.setAlt(r.cand.parentRel, r.cand.guestName, r.cand.leaf)
					w.addDirNameLocked(r.cand.parentRel, r.cand.guestName, r.cand.leaf)
					if r.prevHost != nil {
						w.putRec(newKey, r.prevHost.attr, r.cand.srcRel)
					}
				} else {
					_ = w.host.unlinkAt(pin.h, r.cand.leaf)
				}
			}
			w.releasePin(pin)
		}
		if restored {
			if r.prevVirt != nil {
				w.meta.put(r.virtKey, r.prevVirt)
			} else {
				w.meta.del(r.virtKey)
			}
			updates = append(updates, demotedSymlink{
				rel: r.cand.srcRel,
				entry: entry{
					attr: w.effectiveSymlinkAttr(r.cand.srcRel, newInfo, r.cand.target),
					info: newInfo,
					key:  newKey,
				},
			})
			continue
		}
		// Keep the virtual record in .gvx_meta so the symlink is never lost.
		vr := &rec{attr: r.virtAttr, hint: r.cand.srcRel}
		updates = append(updates, demotedSymlink{
			rel:   r.cand.srcRel,
			entry: virtualEntry(r.virtKey, vr),
		})
	}
	_ = w.flushMetaLocked(lf)
	return updates
}

// finalizeDemotedLocked builds the final demotedSymlink list at post-operation
// paths after a directory rename or exchange succeeds, resolving each moved
// link's live virtual record key under its final parent directory.
func (w *Workspace) finalizeDemotedLocked(recs []demotedRecord) []demotedSymlink {
	if len(recs) == 0 {
		return nil
	}
	out := make([]demotedSymlink, 0, len(recs))
	for i := range recs {
		r := &recs[i]
		vk, err := w.nameKeyLocked(r.cand.destRel)
		if err != nil {
			vk = r.virtKey
		}
		vr := w.meta.get(vk)
		if vr == nil {
			vr = &rec{attr: r.virtAttr, hint: r.cand.destRel}
		}
		out = append(out, demotedSymlink{
			rel:   r.cand.destRel,
			entry: virtualEntry(vk, vr),
		})
	}
	return out
}

// demoteSingleSymlinkRenameLocked moves a host symlink from oldRel to newRel by
// converting it directly into a virtual symlink at newRel without ever creating
// a host symlink at newRel. Callers hold w.mu, w.flushMu, and exclusive lf.
func (w *Workspace) demoteSingleSymlinkRenameLocked(lf *os.File, oldRel, newRel, srcPath, dstLeaf string, src, dst entry, dstExists bool, extraMetaBytes int64) ([]demotedSymlink, error) {
	oldParent, oldName := splitParent(oldRel)
	newParent, newName := splitParent(newRel)
	srcLeaf := leafOf(srcPath)

	oldPin, err := w.acquireFreshPin(oldParent)
	if err != nil {
		return nil, err
	}
	defer w.releasePin(oldPin)
	newPin, err := w.acquireFreshPin(newParent)
	if err != nil {
		return nil, err
	}
	defer w.releasePin(newPin)

	now := time.Now().UnixNano()
	newKey := w.dirKeyOf(newPin, newParent).withName(newName)
	vAttr := buildVirtualSymlinkAttr(src.attr, src.info, now)
	needBytes := extraMetaBytes
	if !w.meta.has(newKey) {
		needBytes += recSize(newKey, &rec{attr: vAttr, hint: newRel})
	}
	if err := w.checkMetaRoomBytes(needBytes); err != nil {
		return nil, err
	}

	prevNew := w.meta.get(newKey)
	var prevHost *rec
	if src.key != (recKey{}) {
		prevHost = w.meta.get(src.key)
	}
	// Step 1: Persist the virtual record at newRel before any host unlink so a
	// crash cannot lose the link.
	w.putRec(newKey, vAttr, newRel)
	if err := w.flushMetaLocked(lf); err != nil {
		if prevNew != nil {
			w.meta.put(newKey, prevNew)
		} else {
			w.meta.del(newKey)
		}
		return nil, err
	}

	// Step 2: Remove the old host symlink.
	if err := w.host.unlinkAt(oldPin.h, srcLeaf); err != nil {
		if prevNew != nil {
			w.meta.put(newKey, prevNew)
		} else {
			w.meta.del(newKey)
		}
		_ = w.flushMetaLocked(lf)
		return nil, err
	}

	// Step 3: Remove any existing host destination.
	if dstExists && !dst.virtual {
		if err := w.host.unlinkAt(newPin.h, dstLeaf); err != nil && !isNotExist(err) {
			// Roll back: restore destination virtual record (if any) and try to
			// restore src on host; if host restore fails, keep src virtual at oldRel.
			if prevNew != nil {
				w.meta.put(newKey, prevNew)
			} else {
				w.meta.del(newKey)
			}
			var updates []demotedSymlink
			restored := false
			if serr := w.host.symlinkAt(oldPin.h, srcLeaf, src.attr.Symlink); serr == nil {
				if newInfo, lerr := w.host.lstatAt(oldPin.h, srcLeaf); lerr == nil {
					restored = true
					newSrcKey := w.keyOf(oldRel, newInfo)
					if src.key != (recKey{}) && src.key != newSrcKey && (src.key.isPath() || src.info.nlink <= 1) {
						w.meta.del(src.key)
					}
					if prevHost != nil {
						w.putRec(newSrcKey, prevHost.attr, oldRel)
					}
					updates = []demotedSymlink{{
						rel: oldRel,
						entry: entry{
							attr: w.effectiveSymlinkAttr(oldRel, newInfo, src.attr.Symlink),
							info: newInfo,
							key:  newSrcKey,
						},
					}}
				} else {
					_ = w.host.unlinkAt(oldPin.h, srcLeaf)
				}
			}
			if !restored {
				w.removeDirNameLocked(oldParent, oldName, srcLeaf)
				w.dropAlt(oldParent, oldName)
				if src.key != (recKey{}) && (src.key.isPath() || src.info.nlink <= 1) {
					w.meta.del(src.key)
				}
				oldKey := w.dirKeyOf(oldPin, oldParent).withName(oldName)
				w.putRec(oldKey, vAttr, oldRel)
				updates = []demotedSymlink{{
					rel:   oldRel,
					entry: virtualEntry(oldKey, &rec{attr: vAttr, hint: oldRel}),
				}}
			}
			_ = w.flushMetaLocked(lf)
			return updates, err
		}
		w.removeDirNameLocked(newParent, newName, dstLeaf)
		w.handles.detach(newRel)
	}

	// Step 4: Clean up superseded metadata records and caches.
	if dstExists && dst.key != newKey {
		if dst.key.isPath() || dst.virtual || dst.isDir() || dst.info.nlink <= 1 {
			w.meta.del(dst.key)
		}
		delete(w.dirTimes, dst.key)
	}
	if src.key != (recKey{}) && src.key != newKey && (src.key.isPath() || src.info.nlink <= 1) {
		w.meta.del(src.key)
	}
	delete(w.dirTimes, src.key)
	w.removeDirNameLocked(oldParent, oldName, srcLeaf)
	w.dropAlt(oldParent, oldName)
	w.dropAlt(newParent, newName)
	w.touchDirLocked(oldParent, now)
	if !dstExists || dst.virtual {
		w.touchDirLocked(newParent, now)
	}
	_ = w.flushMetaLocked(lf)

	return []demotedSymlink{{
		rel:   newRel,
		entry: virtualEntry(newKey, &rec{attr: vAttr, hint: newRel}),
	}}, nil
}

// dstVirtualHostCollidesLocked reports whether a host entry occupies newRel
// when the guest destination is a virtual symlink. Callers hold w.mu.
func (w *Workspace) dstVirtualHostCollidesLocked(newRel string) bool {
	p, err := w.locateLocked(newRel)
	if err != nil {
		return true
	}
	return p.found || p.collided
}
