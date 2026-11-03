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
	"slices"
	"testing"
)

// metaRecordAt returns the record that the table holds for the guest path rel.
// It reads the table only: a record belongs to the path of its hint on a volume
// with file identities, and to its key on a volume with paths.
func metaRecordAt(w *Workspace, rel string) (POSIXAttr, bool) {
	if w.pathKeys {
		if r := w.meta.get(recKey{kind: kindPath, path: rel}); r != nil {
			return r.attr, true
		}
		parent, name := splitParent(rel)
		if r := w.meta.get(recKey{kind: kindPathName, path: parent, name: name}); r != nil {
			return r.attr, true
		}
		return POSIXAttr{}, false
	}
	if _, r := w.meta.byHint(rel); r != nil {
		return r.attr, true
	}
	return POSIXAttr{}, false
}

// metaRecordOf returns the record that belongs to the entry at the guest path
// rel, found through the host lookup of the entry. It sees a record by
// identity, so it ignores the hint.
func metaRecordOf(w *Workspace, rel string) (POSIXAttr, bool) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	e, err := w.lookupLocked(rel)
	if err != nil {
		return POSIXAttr{}, false
	}
	if r := w.meta.get(e.key); r != nil {
		return r.attr, true
	}
	return POSIXAttr{}, false
}

// metaSnapshot returns the records of the entries that the guest sees, by
// guest path. A record that no entry owns, such as the record of a deleted
// file, is missing from the result. The call reads each entry through
// lookup, so it names records by the current path even when the hint of a
// record is stale after a rename of a parent directory.
func metaSnapshot(t testing.TB, w *Workspace) map[string]POSIXAttr {
	t.Helper()
	paths, err := w.ListEntries()
	if err != nil {
		t.Fatalf("ListEntries: %v", err)
	}
	out := make(map[string]POSIXAttr, len(paths))
	for _, p := range paths {
		e, err := w.lookup(p)
		if err != nil {
			t.Fatalf("lookup(%s): %v", p, err)
		}
		if r := w.meta.get(e.key); r != nil {
			out[p] = r.attr
		}
	}
	return out
}

// metaKeys returns the sorted guest paths of the records of a workspace.
func metaKeys(w *Workspace) []string {
	paths := w.meta.paths()
	slices.Sort(paths)
	return paths
}
