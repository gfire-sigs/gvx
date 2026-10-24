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
	"strings"

	"golang.org/x/text/unicode/norm"
)

// This file maps guest paths to host paths for Workspace.
//
// Every Workspace method takes guest paths, and .gvx_meta keys are guest
// paths. The host boundary is the only place that translates a name: each host
// call receives the result of hostPath or hostLeaf. A host name is the stored
// name of the entry, which is not always the plain encoding of the guest name.
//
// Lookups follow an optimistic rule. A lookup first asks the host for form 0 of
// the guest name, or for the stored name that the alternate-name table holds.
// That costs one host call, the same as on a host without translation. A
// listing of the directory runs only when the host answer is ambiguous:
//
//   - the host resolved the name to an entry with another case or another
//     Unicode form,
//   - the host reported no entry, but .gvx_meta or the alternate-name table
//     knows a record for the name, or the name is not ASCII on a volume that
//     normalizes Unicode.
//
// A name without any of these signs does not exist, so a lookup of a missing
// name stays at one host call. The limit of this rule: an entry that another
// tool created under a "~gvx~" name, without a .gvx_meta record and without a
// listing of its directory, can show up in a listing but not in a direct lookup
// of its name. A listing teaches the alternate-name table that name.

const (
	// maxAltNames bounds the alternate-name table. A dropped entry returns
	// the next time a listing or a lookup with a .gvx_meta record finds it.
	maxAltNames = 1 << 16
)

// altKey names one entry by its guest directory and guest name.
type altKey struct {
	dir, name string
}

// dirAux holds the secondary indexes of a directory snapshot. Workspace builds
// them on demand and drops them when the snapshot changes.
type dirAux struct {
	// fold maps the fold key of a stored name to the stored name.
	fold map[string]string
	// nfc maps the NFC form of a stored non-ASCII name to the stored name.
	nfc map[string]string
}

// hostProbe is the result of locating one guest name on the host.
type hostProbe struct {
	// found reports that the host holds an entry for the guest name.
	found bool
	// info is the host metadata of that entry.
	info hostInfo
	// hidden reports that the guest must not see the entry.
	hidden bool
	// clutter reports that the entry is hidden host clutter.
	clutter bool
	// collided reports that the host resolved the name to another entry.
	collided bool
	// occupant is the stored name of that entry, when known.
	occupant string
	// create is the host name for a new entry, when found is false.
	create string
	// err is the host error that explains a missing entry.
	err error
}

// guestName maps a host entry name to the guest name. The mapping needs no
// state. A malformed name comes back unchanged, and isHostClutter hides it.
func (w *Workspace) guestName(host string) string {
	return w.codec.ToGuest(host)
}

// altLeaf returns the stored name that differs from form 0 for an entry.
func (w *Workspace) altLeaf(dir, name string) (string, bool) {
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	leaf, ok := w.altNames[altKey{dir, name}]
	return leaf, ok
}

// setAlt records the stored name of an entry. A stored name that equals form
// 0 needs no record.
func (w *Workspace) setAlt(dir, name, leaf string) {
	if !w.stateful {
		return
	}
	form0, err := w.codec.leafForm(name)
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	key := altKey{dir, name}
	if err != nil || leaf == form0 {
		delete(w.altNames, key)
		return
	}
	if w.altNames == nil || len(w.altNames) >= maxAltNames {
		w.altNames = make(map[altKey]string)
	}
	w.altNames[key] = leaf
}

// dropAlt forgets the stored name of one entry.
func (w *Workspace) dropAlt(dir, name string) {
	if !w.stateful {
		return
	}
	w.nameMu.Lock()
	delete(w.altNames, altKey{dir, name})
	w.nameMu.Unlock()
}

// dropAltTree forgets the stored names of the entry rel and of every entry
// below it.
func (w *Workspace) dropAltTree(rel string) {
	if !w.stateful {
		return
	}
	parent, name := splitParent(rel)
	prefix := rel + "/"
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	delete(w.altNames, altKey{parent, name})
	for k := range w.altNames {
		if k.dir == rel || strings.HasPrefix(k.dir, prefix) {
			delete(w.altNames, k)
		}
	}
}

// moveAltTree moves the stored names of the entries below oldRel to newRel. The
// stored name of oldRel itself dies, because a rename gives that entry a new
// name.
func (w *Workspace) moveAltTree(oldRel, newRel string) {
	if !w.stateful {
		return
	}
	prefix := oldRel + "/"
	w.nameMu.Lock()
	defer w.nameMu.Unlock()
	var moved []altKey
	for k := range w.altNames {
		if k.dir == oldRel || strings.HasPrefix(k.dir, prefix) {
			moved = append(moved, k)
		}
	}
	for _, k := range moved {
		leaf := w.altNames[k]
		delete(w.altNames, k)
		w.altNames[altKey{newRel + strings.TrimPrefix(k.dir, oldRel), k.name}] = leaf
	}
}

// hostLeaf returns the stored name for the guest name below parentRel, or the
// name for a new entry when no record says otherwise. It makes no host call.
func (w *Workspace) hostLeaf(parentRel, name string) (string, error) {
	if !w.codec.active {
		return name, nil
	}
	if w.stateful {
		if leaf, ok := w.altLeaf(parentRel, name); ok {
			return leaf, nil
		}
	}
	return w.codec.leafForm(name)
}

// hostPath returns the host path of the guest path rel. It makes no host call
// and no allocation when every component is its own host name.
func (w *Workspace) hostPath(rel string) (string, error) {
	if !w.codec.active || rel == "." {
		return rel, nil
	}
	var out []byte
	changed := false
	for start := 0; start < len(rel); {
		end := len(rel)
		if i := strings.IndexByte(rel[start:], '/'); i >= 0 {
			end = start + i
		}
		parent := "."
		if start > 0 {
			parent = rel[:start-1]
		}
		leaf, err := w.hostLeaf(parent, rel[start:end])
		if err != nil {
			return "", err
		}
		if !changed && leaf != rel[start:end] {
			changed = true
			out = append(out, rel[:start]...)
		}
		if changed {
			out = append(out, leaf...)
			if end < len(rel) {
				out = append(out, '/')
			}
		}
		start = end + 1
	}
	if !changed {
		return rel, nil
	}
	return string(out), nil
}

// hostChild joins a host directory path and a stored name.
func hostChild(hostDir, leaf string) string {
	return joinRelPath(hostDir, leaf)
}

// leafOf returns the last component of a host path.
func leafOf(hostPath string) string {
	_, leaf := splitParent(hostPath)
	return leaf
}

// mayHaveAlt reports whether a missing entry can still exist under another
// stored name: .gvx_meta or the alternate-name table knows the name, or the
// volume treats Unicode forms alike and the name has non-ASCII bytes. A caller
// that does not hold w.mu passes locked false. The check then reads
// .gvx_meta only when a try-lock succeeds, because the caller holds pinMu and
// the lock order puts w.mu first.
func (w *Workspace) mayHaveAlt(parentRel, name string, locked bool) bool {
	if !w.stateful {
		return false
	}
	if w.caps.UnicodeNormalized && !isASCII(name) {
		return true
	}
	if locked {
		if _, ok := w.meta[joinRelPath(parentRel, name)]; ok {
			return true
		}
	} else if w.mu.TryRLock() {
		_, ok := w.meta[joinRelPath(parentRel, name)]
		w.mu.RUnlock()
		if ok {
			return true
		}
	}
	_, ok := w.altLeaf(parentRel, name)
	return ok
}

// statLeaf runs the host call for one stored name. A path-based caller joins
// the host directory. A pinned caller passes the directory handle.
type statLeaf func(leaf string) (hostInfo, error)

// locateIn finds the host entry of the guest name below parentRel. pin is the
// pinned handle of the directory, or nil. The flag locked reports that the
// caller holds w.mu. The watcher opens pins without that lock, and a pin opens
// directories only.
func (w *Workspace) locateIn(parentRel, name string, pin *dirPin, locked bool, stat statLeaf) (hostProbe, error) {
	leaf, err := w.hostLeaf(parentRel, name)
	if err != nil {
		return hostProbe{}, err
	}
	info, statErr := stat(leaf)
	statOK := statErr == nil
	collided := false
	switch {
	case statErr == nil:
		if !w.needsExactCheck() {
			return w.foundProbe(parentRel, leaf, info), nil
		}
		ok, err := w.exactNameIn(parentRel, leaf, pin)
		if err != nil {
			return hostProbe{}, err
		}
		if ok {
			return w.foundProbe(parentRel, leaf, info), nil
		}
		collided = true
		statErr = nameMismatch(joinRelPath(parentRel, name))
	case errors.Is(statErr, errNameMismatch):
		collided = true
	case errors.Is(statErr, fs.ErrNotExist):
		if !w.mayHaveAlt(parentRel, name, locked) {
			return hostProbe{create: leaf, err: statErr}, nil
		}
	default:
		return hostProbe{}, statErr
	}
	if !w.stateful {
		return hostProbe{collided: collided, create: leaf, err: statErr}, nil
	}

	res, err := w.resolveStored(parentRel, pin, name, collided)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The directory vanished: the entry does not exist.
			return hostProbe{create: leaf, err: statErr}, nil
		}
		return hostProbe{}, err
	}
	if res.found {
		if res.stored == leaf {
			if statOK {
				// A new read of the directory shows the name that the host
				// call found, so the first listing was stale.
				return w.foundProbe(parentRel, leaf, info), nil
			}
			// The snapshot names the leaf that the host call rejected, so the
			// snapshot is stale.
			w.dropAlt(parentRel, name)
			return hostProbe{create: leaf, err: statErr}, nil
		}
		info, err := stat(res.stored)
		if err == nil {
			w.setAlt(parentRel, name, res.stored)
			return w.foundProbe(parentRel, res.stored, info), nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return hostProbe{}, err
		}
		// The entry vanished after the listing.
		w.dropAlt(parentRel, name)
		return hostProbe{create: leaf, err: statErr}, nil
	}
	w.dropAlt(parentRel, name)
	return hostProbe{
		collided: collided || res.occupant != "",
		occupant: res.occupant,
		create:   res.create,
		err:      statErr,
	}, nil
}

// foundProbe builds the probe of an entry that the host holds under leaf.
func (w *Workspace) foundProbe(parentRel, leaf string, info hostInfo) hostProbe {
	p := hostProbe{found: true, info: info}
	switch {
	case w.hiddenByName(leaf):
		p.hidden = true
	case w.isClutterLocked(parentRel, leaf, info):
		p.hidden, p.clutter = true, true
	}
	return p
}

// missingError returns the error for an entry that the guest cannot see.
func (p hostProbe) missingError(rel string) error {
	switch {
	case p.collided:
		return nameMismatch(rel)
	case p.err != nil && !p.found:
		return p.err
	}
	return fs.ErrNotExist
}

// locateLocked finds the host entry of the guest path rel. It does not handle
// the workspace root.
func (w *Workspace) locateLocked(rel string) (hostProbe, error) {
	parent, name := splitParent(rel)
	hostDir, err := w.hostPath(parent)
	if err != nil {
		return hostProbe{}, err
	}
	return w.locateIn(parent, name, nil, true, func(leaf string) (hostInfo, error) {
		return w.host.lstat(hostChild(hostDir, leaf))
	})
}

// storedMatch is the answer of resolveStored.
type storedMatch struct {
	found    bool
	stored   string
	occupant string
	create   string
}

// resolveStored finds the stored name of a guest name in the listing of
// parentRel. When no entry matches, it also picks the name for a new entry.
// force marks that the host showed an entry for the name, so a missing match
// in a cached listing triggers one new read.
func (w *Workspace) resolveStored(parentRel string, pin *dirPin, name string, force bool) (storedMatch, error) {
	forms, err := w.codec.forms(name)
	if err != nil {
		return storedMatch{}, err
	}
	var res storedMatch
	for attempt := range 2 {
		snap, fresh, err := w.snapshotDir(parentRel, pin, attempt == 1)
		if err != nil {
			return storedMatch{}, err
		}
		w.nameMu.Lock()
		res = w.matchSnapshotLocked(snap, name, forms)
		w.nameMu.Unlock()
		if res.found || fresh || !force {
			break
		}
	}
	return res, nil
}

// matchSnapshotLocked matches a guest name against a directory snapshot.
// Callers hold w.nameMu.
func (w *Workspace) matchSnapshotLocked(snap *dirNames, name string, forms []string) storedMatch {
	for _, f := range forms {
		if _, ok := snap.names[f]; ok {
			return storedMatch{found: true, stored: f}
		}
	}
	aux := w.auxLocked(snap)
	if w.caps.UnicodeNormalized && !isASCII(name) {
		if stored, ok := aux.nfc[norm.NFC.String(name)]; ok {
			return storedMatch{found: true, stored: stored}
		}
	}
	res := storedMatch{}
	if w.codec.foldCase {
		res.occupant = aux.fold[foldKey(forms[0], w.caps.UnicodeNormalized)]
	}
	res.create, _ = w.codec.ToHost(name, func(host string) bool {
		if w.codec.foldCase {
			_, ok := aux.fold[foldKey(host, w.caps.UnicodeNormalized)]
			return ok
		}
		_, ok := snap.names[host]
		return ok
	})
	if res.create == "" {
		res.create = forms[0]
	}
	return res
}

// auxLocked returns the secondary indexes of a snapshot. Callers hold w.nameMu.
func (w *Workspace) auxLocked(snap *dirNames) *dirAux {
	if snap.aux != nil {
		return snap.aux
	}
	aux := &dirAux{}
	if w.codec.foldCase {
		aux.fold = make(map[string]string, len(snap.names))
	}
	if w.caps.UnicodeNormalized {
		aux.nfc = make(map[string]string)
	}
	for n := range snap.names {
		if aux.fold != nil {
			aux.fold[foldKey(n, w.caps.UnicodeNormalized)] = n
		}
		if aux.nfc != nil && !isASCII(n) && !strings.HasPrefix(n, codecPrefix) {
			aux.nfc[norm.NFC.String(n)] = n
		}
	}
	snap.aux = aux
	return aux
}

// listName returns the guest name of a visible host entry. The caller hides
// the entries that isHiddenLocked reports. On a volume that normalizes
// Unicode, an unescaped NFD name shows as NFC, unless .gvx_meta records the
// NFD name as the name that the guest created. Callers hold w.mu.
func (w *Workspace) listName(dirRel, leaf string) string {
	if !w.codec.active {
		return leaf
	}
	if strings.HasPrefix(leaf, codecPrefix) {
		return w.codec.ToGuest(leaf)
	}
	if w.caps.UnicodeNormalized && !isASCII(leaf) {
		if n := norm.NFC.String(leaf); n != leaf {
			if _, explicit := w.meta[joinRelPath(dirRel, leaf)]; !explicit {
				return n
			}
		}
	}
	return leaf
}

// hiddenByName reports whether the name of a host entry alone hides it from
// the guest. The internal names of hostfs are hidden on every host. On a host
// with name translation, a name with the codec prefix is hidden too when the
// codec never writes it: a malformed escape, or a name that no form of the
// decoded guest name matches.
func (w *Workspace) hiddenByName(leaf string) bool {
	if !strings.HasPrefix(leaf, codecPrefix) {
		return false
	}
	if isEphemeralName(leaf) {
		return true
	}
	if !w.codec.active {
		return false
	}
	_, ok := w.codec.canonicalGuest(leaf)
	return !ok
}

// isHiddenLocked reports whether the guest must not see the host entry leaf
// of the directory dirRel. Callers hold w.mu.
func (w *Workspace) isHiddenLocked(dirRel, leaf string, info hostInfo) bool {
	return w.hiddenByName(leaf) || w.isClutterLocked(dirRel, leaf, info)
}
