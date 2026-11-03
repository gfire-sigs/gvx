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
		return w.convertPaths(img.paths), true
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
	// guest path. A record of the wanted kind stays.
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
	for k, r := range w.convertPaths(paths) {
		out[k] = r
	}
	return out, true
}

// convertPaths builds the records for the guest paths of an earlier release.
// A volume without identities keeps the paths as keys. A volume with identities
// reads the identity of each path from the host. A path that no longer names a
// file or directory gets no record, because the record had no owner. A virtual
// symbolic link needs the identity of its parent directory. Hard links of one
// file collapse into one record, and the record with the latest change time
// wins.
func (w *Workspace) convertPaths(paths map[string]POSIXAttr) map[recKey]*rec {
	out := make(map[recKey]*rec, len(paths))
	if w.pathKeys {
		for p, a := range paths {
			if a.Symlink != "" {
				parent, name := splitParent(p)
				out[recKey{kind: kindPathName, path: parent, name: name}] = &rec{attr: a, hint: p}
				continue
			}
			out[recKey{kind: kindPath, path: p}] = &rec{attr: a, hint: p}
		}
		return out
	}
	dirs := map[string]fileKey{".": w.rootKey.id}
	dirID := func(rel string) (fileKey, bool) {
		if id, ok := dirs[rel]; ok {
			return id, true
		}
		info, err := w.statGuestPath(rel)
		if err != nil || info.kind != hostKindDir || info.fid.isZero() {
			return fileKey{}, false
		}
		id := w.storedID(info.fid)
		dirs[rel] = id
		return id, true
	}
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		a := paths[p]
		if a.Symlink != "" {
			parent, name := splitParent(p)
			if id, ok := dirID(parent); ok {
				out[recKey{kind: kindName, id: id, name: name}] = &rec{attr: a, hint: p}
			}
			continue
		}
		info, err := w.statGuestPath(p)
		if err != nil || (info.kind != hostKindRegular && info.kind != hostKindDir) || info.fid.isZero() {
			continue
		}
		k := w.keyOf(p, info)
		if old := out[k]; old != nil && old.attr.Ctime >= a.Ctime {
			continue
		}
		out[k] = &rec{attr: a, hint: p}
	}
	return out
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
