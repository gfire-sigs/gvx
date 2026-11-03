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

const (
	// maxDirPins bounds the open directory handles of one Workspace. A
	// Workspace closes the least recently used idle handle above this bound.
	maxDirPins = 256

	// pinIdleTime is the idle time after which sweepPins closes a pinned
	// directory handle. A handle that stays open blocks a delete of its
	// directory by a host process that does not use POSIX delete semantics.
	pinIdleTime = 5 * time.Second

	// cacheTTL is the longest time that hostfs trusts a cached lookup result
	// without a host call. See the consistency contract of lookupChildLocked.
	cacheTTL = time.Second
)

// dirPin is one pinned directory handle of a Workspace. The Workspace owns
// the handle: it closes the handle when the pin retires and no caller holds
// the pin, and Workspace.Close retires every pin.
//
// All fields except h, id, and root are protected by Workspace.pinMu.
type dirPin struct {
	h  hostDirHandle
	id hostID
	// root marks the pin of the workspace root. The host backend owns that
	// handle, so the pin never closes it.
	root bool

	refs    int
	lastUse int64
	// checkedAt is the time at which the host last confirmed that the parent
	// directory holds this directory under this name.
	checkedAt int64
	retired   bool
}

// acquirePin returns the pinned handle of the directory rel and the caller
// holds one reference on it. A missing pin opens lazily below the pin of the
// parent directory with one openDirAt call, so a lookup below a warm
// directory needs no walk. The caller MUST call releasePin.
//
// The lockdown rule allows this open after hostlockdown.Apply. The open runs
// openat or NtCreateFile relative to a directory handle that exists already,
// and never opens an unbound host path.
//
// The pin of rel stands for the directory that rel named when the pin opened.
// A pin older than cacheTTL gets one lstatAt call in its parent before the
// next use, and a pin whose name now holds another object retires with its
// subtree and opens again. A host swap of a directory therefore reaches
// lookups, mutations, and the Workspace methods after cacheTTL at the latest.
// A descriptor that the guest opened below the directory before the swap
// keeps the old directory, as an openat on an open directory does on POSIX.
// Workspace.pinMu is a leaf lock: no pin call takes Workspace.mu.
func (w *Workspace) acquirePin(rel string) (*dirPin, error) {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	return w.acquirePinLocked(rel, false)
}

// acquirePinHeld is acquirePin for a caller that holds w.mu. The name
// resolution then reads .gvx_meta without a try-lock.
func (w *Workspace) acquirePinHeld(rel string) (*dirPin, error) {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	return w.acquirePinLocked(rel, true)
}

// acquirePinLocked is acquirePin for a caller that holds w.pinMu. heldMu
// reports that the caller holds w.mu as well.
func (w *Workspace) acquirePinLocked(rel string, heldMu bool) (*dirPin, error) {
	if w.pinsClosed {
		return nil, os.ErrClosed
	}
	if rel == "." {
		return &w.rootPin, nil
	}
	now := w.nowNano()
	p := w.pins[rel]
	if p != nil && now-p.checkedAt < int64(cacheTTL) {
		p.refs++
		p.lastUse = now
		return p, nil
	}
	parentRel, name := splitParent(rel)
	parent, err := w.acquirePinLocked(parentRel, heldMu)
	if err != nil {
		return nil, err
	}
	if p != nil {
		if w.pinStillNamedLocked(parentRel, parent, name, p, heldMu) {
			w.releasePinLocked(parent)
			p.checkedAt = now
			p.refs++
			p.lastUse = now
			return p, nil
		}
		w.retireSubtreeLocked(rel)
	}
	h, info, err := w.openDirNamed(parentRel, parent, name, heldMu)
	w.releasePinLocked(parent)
	if err != nil {
		return nil, err
	}
	if info.kind != hostKindDir {
		_ = w.host.closeDir(h)
		return nil, errNotDir
	}
	w.evictPinsLocked()
	p = &dirPin{h: h, id: info.id, refs: 1, lastUse: now, checkedAt: now}
	w.pins[rel] = p
	w.armSweepLocked()
	return p, nil
}

// pinStillNamedLocked reports whether the directory name below the pinned
// directory parent is still the directory that p holds open. A host process
// can move a directory away and put another one under its name. The caller
// holds w.pinMu.
func (w *Workspace) pinStillNamedLocked(parentRel string, parent *dirPin, name string, p *dirPin, heldMu bool) bool {
	probe, err := w.locateIn(parentRel, name, parent, heldMu, func(leaf string) (hostInfo, error) {
		return w.host.lstatAt(parent.h, leaf)
	})
	return err == nil && probe.found && !probe.hidden && probe.info.kind == hostKindDir && probe.info.id == p.id
}

// openDirNamed opens the directory name of the guest directory parentRel
// through the pinned handle parent. It resolves the stored host name and fails
// when the host stores the directory under another case or form. The caller
// holds w.pinMu, and the name resolution takes only the lock of the name
// snapshots. heldMu reports that the caller holds w.mu.
func (w *Workspace) openDirNamed(parentRel string, parent *dirPin, name string, heldMu bool) (h hostDirHandle, info hostInfo, err error) {
	opened := false
	closeOpened := func() {
		if opened {
			_ = w.host.closeDir(h)
			opened = false
		}
	}
	probe, err := w.locateIn(parentRel, name, parent, heldMu, func(leaf string) (hostInfo, error) {
		closeOpened()
		oh, oinfo, oerr := w.host.openDirAt(parent.h, leaf)
		if oerr != nil {
			return hostInfo{}, oerr
		}
		h, opened = oh, true
		return oinfo, nil
	})
	if err != nil {
		closeOpened()
		return h, hostInfo{}, err
	}
	if !probe.found || probe.hidden {
		closeOpened()
		return h, hostInfo{}, probe.missingError(joinRelPath(parentRel, name))
	}
	return h, probe.info, nil
}

// holdPin returns the existing pin of rel with one reference, or nil. It
// never opens a handle.
func (w *Workspace) holdPin(rel string) *dirPin {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	if w.pinsClosed {
		return nil
	}
	if rel == "." {
		return &w.rootPin
	}
	p := w.pins[rel]
	if p != nil {
		p.refs++
	}
	return p
}

func (w *Workspace) releasePin(p *dirPin) {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	w.releasePinLocked(p)
}

func (w *Workspace) releasePinLocked(p *dirPin) {
	if p.root {
		return
	}
	p.refs--
	if p.refs == 0 && p.retired {
		_ = w.host.closeDir(p.h)
	}
}

// retirePinLocked removes the pin of rel from the table. The handle closes at
// once when no caller holds the pin, and at the last release otherwise.
func (w *Workspace) retirePinLocked(rel string, p *dirPin) error {
	if w.pins[rel] == p {
		delete(w.pins, rel)
	}
	p.retired = true
	if p.refs == 0 {
		return w.host.closeDir(p.h)
	}
	return nil
}

// closeSubtreeHandlesLocked closes the pinned directory handles of rel and of
// every directory below it. Windows refuses to rename or remove a directory
// that has an open handle, so rename and rmdir call this first. The next
// lookup below the directory reopens the handles lazily. On Unix a pinned
// descriptor follows its directory to the new name, so the same call keeps
// the table free of handles that name a moved or removed directory.
//
// The caller holds w.mu for writing, so no lookup holds a pin.
func (w *Workspace) closeSubtreeHandlesLocked(rel string) {
	w.watchQuiesce(rel)
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	w.retireSubtreeLocked(rel)
}

func (w *Workspace) retireSubtreeLocked(rel string) {
	prefix := rel + "/"
	for k, p := range w.pins {
		if rel == "." || k == rel || strings.HasPrefix(k, prefix) {
			_ = w.retirePinLocked(k, p)
		}
	}
}

// checkPin retires the pins of the path rel and of its descendants when the
// host no longer names the pinned directory at rel. A lookup of rel calls it
// with the identity of the directory that it found, or with isDir false when
// rel is missing or names another kind of entry.
func (w *Workspace) checkPin(rel string, id hostID, isDir bool) {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	p := w.pins[rel]
	switch {
	case p == nil:
	case !isDir || p.id != id:
		w.retireSubtreeLocked(rel)
	default:
		// The lookup went through a confirmed parent pin and found the same
		// directory under the name, so the pin needs no check of its own.
		p.checkedAt = w.nowNano()
	}
}

// evictPinsLocked makes room for one more pin. It retires the idle pin that
// was used least recently.
func (w *Workspace) evictPinsLocked() {
	for len(w.pins) >= maxDirPins {
		var oldestRel string
		var oldest *dirPin
		for k, p := range w.pins {
			if p.refs == 0 && (oldest == nil || p.lastUse < oldest.lastUse) {
				oldestRel, oldest = k, p
			}
		}
		if oldest == nil {
			return
		}
		_ = w.retirePinLocked(oldestRel, oldest)
	}
}

// armSweepLocked schedules one sweepPins call when none is pending.
func (w *Workspace) armSweepLocked() {
	if w.sweepArmed || w.pinsClosed {
		return
	}
	w.sweepArmed = true
	w.sweepTimer = time.AfterFunc(pinIdleTime, w.sweepPins)
}

// sweepPins closes the pins that no caller used for pinIdleTime. It re-arms
// itself while pins remain.
func (w *Workspace) sweepPins() {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	w.sweepArmed = false
	if w.pinsClosed {
		return
	}
	now := w.nowNano()
	for k, p := range w.pins {
		if p.refs == 0 && now-p.lastUse >= int64(pinIdleTime) {
			_ = w.retirePinLocked(k, p)
		}
	}
	if len(w.pins) > 0 {
		w.armSweepLocked()
	}
}

// closePins retires every pin and stops the sweep. Later pin calls fail with
// os.ErrClosed. Workspace.Close calls it after it marks the Workspace closed,
// when no caller holds a pin.
func (w *Workspace) closePins() error {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	w.pinsClosed = true
	if w.sweepTimer != nil {
		w.sweepTimer.Stop()
	}
	var errs []error
	for k, p := range w.pins {
		if err := w.retirePinLocked(k, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// lookupIn resolves name below the directory parentRel through the pinned
// handle of that directory. It returns the same entry as lookup for the
// joined path, with one host call when the pin of the directory exists.
func (w *Workspace) lookupIn(parentRel, name string) (entry, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return entry{}, os.ErrClosed
	}
	rel := joinRelPath(parentRel, name)
	if isReservedPath(rel) {
		return entry{}, fs.ErrNotExist
	}
	pin, err := w.acquirePinHeld(parentRel)
	if err != nil {
		return entry{}, err
	}
	defer w.releasePin(pin)
	// An open pin proves that the parent is a directory.
	if m, ok := w.meta[rel]; ok && m.Symlink != "" {
		return virtualEntry(m), nil
	}
	p, err := w.locateIn(parentRel, name, pin, true, func(leaf string) (hostInfo, error) {
		return w.host.lstatAt(pin.h, leaf)
	})
	if err != nil {
		return entry{}, err
	}
	if !p.found || p.hidden {
		w.checkPin(rel, hostID{}, false)
		return entry{}, p.missingError(rel)
	}
	w.checkPin(rel, p.info.id, p.info.kind == hostKindDir)
	return w.entryFromInfo(rel, p.info)
}

// lookupPath is lookup through pinned handles. The path "." names the
// workspace root, which has no parent directory.
func (w *Workspace) lookupPath(rel string) (entry, error) {
	if rel == "." {
		return w.lookup(rel)
	}
	parent, name := splitParent(rel)
	return w.lookupIn(parent, name)
}

// openRegularWithAttr opens the regular file rel, whose entry e the caller
// resolved already, through the pinned handle of its directory. It makes no
// second lookup and walks no path. The open fails when the host no longer
// holds a regular file under that name, and the caller then falls back to
// openRegular.
func (w *Workspace) openRegularWithAttr(rel string, e entry, flags int) (*os.File, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.openRegularWithAttrLocked(rel, e, flags)
}

// openRegularWithAttrLocked is openRegularWithAttr for a caller that holds
// w.mu.
func (w *Workspace) openRegularWithAttrLocked(rel string, e entry, flags int) (*os.File, error) {
	if w.closed {
		return nil, os.ErrClosed
	}
	if e.isDir() {
		return nil, errIsDir
	}
	if e.isSymlink() {
		return nil, ErrPathTraversal
	}
	if rel == "." {
		// The root has no directory that holds it. In single-file mode it is
		// the bound file, which the host backend opens by its stored name.
		return w.host.open(rel, flags&^(os.O_CREATE|os.O_EXCL), 0)
	}
	parent, name := splitParent(rel)
	leaf, err := w.hostLeaf(parent, name)
	if err != nil {
		return nil, err
	}
	pin, err := w.acquirePinHeld(parent)
	if err != nil {
		return nil, err
	}
	defer w.releasePin(pin)
	return w.host.openChildAt(pin.h, leaf, flags&^(os.O_CREATE|os.O_EXCL), 0)
}

// locateLocked finds the host entry of the guest path rel through the pinned
// handle of its directory. It does not handle the workspace root. A missing
// or unusable directory fails like a missing entry. Callers hold w.mu.
func (w *Workspace) locateLocked(rel string) (hostProbe, error) {
	parent, name := splitParent(rel)
	pin, err := w.acquirePinHeld(parent)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return hostProbe{}, err
		}
		// A missing directory holds no entry.
		leaf, lerr := w.hostLeaf(parent, name)
		if lerr != nil {
			return hostProbe{}, lerr
		}
		return hostProbe{collided: errors.Is(err, errNameMismatch), create: leaf, err: err}, nil
	}
	defer w.releasePin(pin)
	return w.locateIn(parent, name, pin, true, func(leaf string) (hostInfo, error) {
		return w.host.lstatAt(pin.h, leaf)
	})
}

// parentPinLocked returns the pinned handle of the directory that holds rel.
// A successful call proves that the directory exists and that it is a
// directory. The caller MUST call releasePin and holds w.mu.
func (w *Workspace) parentPinLocked(rel string) (*dirPin, error) {
	parent, _ := splitParent(rel)
	return w.acquirePinHeld(parent)
}
