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

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// errMissingIdentity reports a host that returned no file identity for a new
// file or directory, which a record of the entry needs.
var errMissingIdentity = errors.New("hostfs: the host reported no file identity")

// This file maps host entries to the keys of .gvx_meta records and reads the
// records back. A volume with trustworthy file identities keys records on the
// identity, and any other volume keys them on the guest path. See recKind.

// storedID returns the identity as .gvx_meta stores it. The device of the
// workspace root becomes zero, so a volume that gets another device number
// after a reboot keeps its records.
func (w *Workspace) storedID(k fileKey) fileKey {
	if k.dev == w.rootDev {
		k.dev = 0
	}
	return k
}

// rawID returns the identity as the host backend reports it.
func (w *Workspace) rawID(k fileKey) fileKey {
	if k.dev == 0 {
		k.dev = w.rootDev
	}
	return k
}

// keyOf returns the key of the record of the host entry rel, whose host
// metadata is info. On a volume with identities, an entry that no stat
// described has a zero identity, and keyed reports false for it.
func (w *Workspace) keyOf(rel string, info hostInfo) recKey {
	if w.pathKeys {
		return recKey{kind: kindPath, path: rel}
	}
	return recKey{kind: kindInode, id: w.storedID(info.fid)}
}

// keyed reports whether info carries what keyOf needs.
func (w *Workspace) keyed(info hostInfo) bool {
	return w.pathKeys || !info.fid.isZero()
}

// dirKeyOf returns the key of the directory rel whose pinned handle is pin.
func (w *Workspace) dirKeyOf(pin *dirPin, rel string) recKey {
	if w.pathKeys {
		return recKey{kind: kindPath, path: rel}
	}
	return recKey{kind: kindInode, id: pin.key}
}

// nameKeyLocked returns the key of the virtual symbolic link at rel. It reads
// the identity of the parent directory from its pinned handle. It fails when
// the parent directory does not exist. Callers hold w.mu.
func (w *Workspace) nameKeyLocked(rel string) (recKey, error) {
	if w.pathKeys {
		parent, name := splitParent(rel)
		return recKey{kind: kindPathName, path: parent, name: name}, nil
	}
	pin, err := w.parentPinLocked(rel)
	if err != nil {
		return recKey{}, err
	}
	defer w.releasePin(pin)
	_, name := splitParent(rel)
	return recKey{kind: kindName, id: pin.key, name: name}, nil
}

// virtualAtLocked returns the record of the virtual symbolic link at rel, or
// nil when the guest has no such link. A table without links answers without a
// pin. A missing parent directory holds no link. Callers hold w.mu.
func (w *Workspace) virtualAtLocked(rel string) (recKey, *rec) {
	if !w.meta.hasNames() {
		return recKey{}, nil
	}
	k, err := w.nameKeyLocked(rel)
	if err != nil {
		return recKey{}, nil
	}
	return k, w.meta.get(k)
}

// virtualIn is virtualAtLocked for the entry name of the directory parentRel,
// whose pinned handle the caller holds.
func (w *Workspace) virtualIn(pin *dirPin, parentRel, name string) (recKey, *rec) {
	if !w.meta.hasNames() {
		return recKey{}, nil
	}
	k := w.dirKeyOf(pin, parentRel).withName(name)
	return k, w.meta.get(k)
}

// recOf returns the record of the host entry rel, or nil. A record that the
// guest saw at another path gets its hint corrected. A file without a record
// at a path where a vanished file left one takes that record over. See adopt.
// Callers hold w.mu.
func (w *Workspace) recOf(rel string, info hostInfo) *rec {
	if !w.keyed(info) {
		return nil
	}
	k := w.keyOf(rel, info)
	if r := w.meta.get(k); r != nil {
		// A host process that moved the file, or a rename of a parent
		// directory, leaves the hint behind. A file with several names has
		// no single path, so its hint stays.
		if !w.pathKeys && r.hint != rel && info.nlink <= 1 {
			w.meta.setHint(k, r, rel)
		}
		return r
	}
	if w.pathKeys {
		return nil
	}
	return w.adopt(rel, k, info)
}

// adopt gives the file at rel the record of a file that has vanished from rel.
// A host editor saves a file by writing a temporary file and renaming it over
// the old one, which leaves the new file without a record. The record that
// last sat at rel moves to the new file when its file is gone for good. A file
// that still exists elsewhere keeps its record, and the new file starts without
// one.
func (w *Workspace) adopt(rel string, k recKey, info hostInfo) *rec {
	if w.readOnly || info.nlink > 1 || (info.kind != hostKindRegular && info.kind != hostKindDir) {
		return nil
	}
	oldKey, old := w.meta.byHint(rel)
	if old == nil || oldKey == k || oldKey.id.dev != k.id.dev {
		return nil
	}
	if (old.attr.Mode&linux.S_IFMT == linux.S_IFDIR) != (info.kind == hostKindDir) {
		return nil
	}
	// A file that is older than the record cannot replace the recorded file.
	if oldKey.id.btime != 0 && k.id.btime != 0 && k.id.btime < oldKey.id.btime {
		return nil
	}
	alive, where := w.recordFileExists(oldKey, rel)
	if alive {
		w.meta.setHint(oldKey, old, where)
		return nil
	}
	adopted := old.withHint(rel)
	w.meta.del(oldKey)
	w.meta.put(k, adopted)
	return adopted
}

// recordFileExists reports whether the file of the record under key still
// exists on the host. The second result is the guest path at which the file
// lives when the call found it, or empty when it is unknown. An answer that the
// host cannot give counts as alive, because a record must survive a failed
// check. Callers hold w.mu.
func (w *Workspace) recordFileExists(key recKey, rel string) (bool, string) {
	if w.caps.ExistsByID {
		found, err := w.host.existsByID(w.rawID(key.id))
		return found || err != nil, ""
	}
	// Without a lookup by identity, the listing of the directory is the proof.
	// A file that a host process renamed inside its directory still shows.
	parent, _ := splitParent(rel)
	pin, err := w.acquirePin(parent)
	if err != nil {
		return true, ""
	}
	defer w.releasePin(pin)
	entries, err := w.host.readDirAt(pin.h)
	if err != nil {
		return true, ""
	}
	for _, e := range entries {
		if e.ino == key.id.ino {
			return true, joinRelPath(parent, w.codec.ToGuest(e.name))
		}
	}
	return false, ""
}

// knowsGuestPath reports whether the table holds a record that the guest saw
// at the path rel. A volume that folds case or normalizes Unicode can store
// such a name under another form, so the answer widens a host lookup. The hint
// can be stale after a rename of a parent directory, which only costs the
// lookup an extra directory read.
func (w *Workspace) knowsGuestPath(rel string) bool {
	if w.pathKeys {
		return w.meta.has(recKey{kind: kindPath, path: rel})
	}
	_, r := w.meta.byHint(rel)
	return r != nil
}

// ownsEntry reports whether .gvx_meta holds a record for the host entry leaf
// of the directory dirRel. The guest created such an entry, so hostfs shows it
// even when its name looks like host clutter. A stat result names the record
// by identity. Without one, the hint of the record names it.
func (w *Workspace) ownsEntry(dirRel, leaf string, info hostInfo) bool {
	if !w.pathKeys && !info.fid.isZero() {
		return w.meta.has(w.keyOf("", info))
	}
	return w.knowsGuestPath(joinRelPath(dirRel, w.codec.ToGuest(leaf)))
}

// putRec stores a record for the host entry or link under k. It keeps the
// guest path as the hint.
func (w *Workspace) putRec(k recKey, attr POSIXAttr, hint string) {
	w.meta.put(k, &rec{attr: attr, hint: hint})
}

// checkMetaRoom fails with errMetaFull when the table has no memory left for a
// record under k. A record that exists needs no room. Every mutation that can
// add a record calls it before the first host change, so a refused mutation
// leaves no host file without a record. A zero key stands for a record that
// does not exist yet.
func (w *Workspace) checkMetaRoom(k recKey) error {
	if w.meta.memBytes() < w.maxMetaBytes || (k != recKey{} && w.meta.has(k)) {
		return nil
	}
	return errMetaFull
}
