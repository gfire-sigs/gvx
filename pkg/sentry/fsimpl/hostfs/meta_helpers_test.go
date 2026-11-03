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

// rawRecords reads the records that the .gvx_meta file at path holds, without
// the host tree. ReadMeta resolves records through the tree and leaves out the
// record of a file that is gone, so a test that must see a leaked or a wrong
// record on disk reads the journal itself.
func rawRecords(t testing.TB, path string) map[recKey]*rec {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := parseMeta(raw)
	if err != nil {
		t.Fatalf("parseMeta(%s): %v", path, err)
	}
	return img.recs
}

// requireDiskMatchesMemory fails when the journal and the table of the
// workspace hold different keys or different modes.
func requireDiskMatchesMemory(t testing.TB, ws *Workspace, path string) {
	t.Helper()
	disk := rawRecords(t, path)
	mem := ws.meta.keys()
	for _, k := range mem {
		d, ok := disk[k]
		if !ok {
			t.Errorf("record %+v is in memory and not on disk", k)
			continue
		}
		if m := ws.meta.get(k); m.attr.Mode != d.attr.Mode || m.attr.UID != d.attr.UID {
			t.Errorf("record %+v has mode %o uid %d on disk and %o uid %d in memory", k, d.attr.Mode, d.attr.UID, m.attr.Mode, m.attr.UID)
		}
	}
	if len(disk) != len(mem) {
		t.Errorf("the journal holds %d records and the table %d: a record leaked or is missing", len(disk), len(mem))
	}
}
