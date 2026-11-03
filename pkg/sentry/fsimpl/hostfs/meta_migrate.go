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
	"maps"
	"slices"
)

// This file converts a loaded .gvx_meta image to the key kind of the volume.
// Two sources need it: a table of an earlier release, which keys on guest
// paths, and a table of the other key kind, which appears when the volume of
// a workspace gains or loses trustworthy identities. The conversion runs once
// at open time. It reads the host once for each record. It does not write the
// file: the first flush of a changed session writes the converted table.

// importImage returns the records of img in the key kind of the volume. The
// second result reports that the records differ from the file, so the next
// flush must rewrite the file.
func (w *Workspace) importImage(img metaImage) (map[recKey]*rec, bool) {
	if img.paths != nil {
		return w.convertPaths(img.paths, false), true
	}
	foreign := false
	for k := range img.recs {
		if k.isPath() != w.pathKeys {
			foreign = true
			break
		}
	}
	if !foreign {
		return img.recs, false
	}
	// A record of the other kind converts through its hint, which names the
	// guest path. A record of the wanted kind stays. A path record of a volume
	// with identities stays a path record when its entry has no identity, so
	// the table mixes both kinds there. Every open converts such a record
	// again, and a table that the conversion leaves as it is stays unchanged
	// on disk. A path record whose entry is absent stays too, because the
	// entry can sit on a file system that is not mounted yet. The collector
	// removes it later.
	paths := make(map[string]POSIXAttr)
	out := make(map[recKey]*rec, len(img.recs))
	for k, r := range img.recs {
		switch {
		case k.isPath() == w.pathKeys:
			out[k] = r
		case k.kind == kindPath:
			paths[k.path] = r.attr
		case k.kind == kindPathName:
			paths[joinRelPath(k.path, k.name)] = r.attr
		case r.hint != "":
			paths[r.hint] = r.attr
		}
	}
	for k, r := range w.convertPaths(paths, true) {
		out[k] = r
	}
	if maps.EqualFunc(out, img.recs, func(*rec, *rec) bool { return true }) {
		return img.recs, false
	}
	return out, true
}

// convertPaths builds the records for the guest paths of an earlier release,
// or for the path records of a table. A volume without identities keeps the
// paths as keys. A volume with identities reads the identity of each path from
// the host. A path whose entry has no identity keeps a path record. A path that
// the host proves absent, or that now names another kind of entry, gets no
// record, because the record had no owner. With keepLost set, an absent path
// keeps its path record, because its file system can be unmounted for now. A
// path that the host fails to answer for, such as one below a directory that
// denies access, keeps its record as a path record. The next open converts it
// again. A virtual symbolic link needs the identity of its parent directory.
// Hard links of one file collapse into one record, and the record with the
// latest change time wins.
func (w *Workspace) convertPaths(paths map[string]POSIXAttr, keepLost bool) map[recKey]*rec {
	out := make(map[recKey]*rec, len(paths))
	pathRecord := func(p string, a POSIXAttr) {
		if a.Symlink != "" {
			parent, name := splitParent(p)
			out[recKey{kind: kindPathName, path: parent, name: name}] = &rec{attr: a, hint: p}
			return
		}
		out[recKey{kind: kindPath, path: p}] = &rec{attr: a, hint: p}
	}
	if w.pathKeys {
		for p, a := range paths {
			pathRecord(p, a)
		}
		return out
	}
	// dirID returns the identity of a directory. A directory without one
	// answers errNoIdentity, and the links below it keep path records.
	dirs := map[string]fileKey{".": w.rootKey.id}
	dirID := func(rel string) (fileKey, error) {
		if id, ok := dirs[rel]; ok {
			return id, nil
		}
		info, err := w.statGuestPath(rel)
		switch {
		case err != nil:
			return fileKey{}, err
		case info.kind != hostKindDir:
			return fileKey{}, errNotDir
		case !hasIdentity(info):
			return fileKey{}, errNoIdentity
		}
		id := w.storedID(info.fid)
		dirs[rel] = id
		return id, nil
	}
	keep := func(err error) bool {
		return !entryLost(err) || keepLost
	}
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		a := paths[p]
		if a.Symlink != "" {
			parent, name := splitParent(p)
			id, err := dirID(parent)
			switch {
			case err == nil:
				out[recKey{kind: kindName, id: id, name: name}] = &rec{attr: a, hint: p}
			case errors.Is(err, errNoIdentity) || keep(err):
				pathRecord(p, a)
			}
			continue
		}
		info, err := w.statGuestPath(p)
		if err == nil && info.kind != hostKindRegular && info.kind != hostKindDir {
			err = errNotDir
		}
		if err != nil {
			if keep(err) {
				pathRecord(p, a)
			}
			continue
		}
		k := w.keyOf(p, info)
		if k.isPath() {
			pathRecord(p, a)
			continue
		}
		if old := out[k]; old != nil && old.attr.Ctime >= a.Ctime {
			continue
		}
		out[k] = &rec{attr: a, hint: p}
	}
	return out
}

// errNoIdentity reports a directory that has no trustworthy identity.
var errNoIdentity = errors.New("hostfs: the entry has no file identity")

// entryLost reports a host answer that proves that a path no longer names a
// file or a directory: the path is absent, or a component is not a directory.
// Any other error says nothing about the path.
func entryLost(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotDir)
}

// statGuestPath reads the host metadata of the guest path rel by a walk from
// the root. It runs at open time, before any guest call, so it takes no lock
// and uses no pin.
func (w *Workspace) statGuestPath(rel string) (hostInfo, error) {
	hostRel, err := w.hostPath(rel)
	if err != nil {
		return hostInfo{}, err
	}
	return w.host.lstat(hostRel)
}
