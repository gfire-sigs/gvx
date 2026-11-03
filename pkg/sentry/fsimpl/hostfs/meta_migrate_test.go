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
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// encodeV3 returns the bytes of a .gvx_meta file in the path-keyed journal form
// of version 3 with one frame, as the release before the identity keys wrote
// it.
func encodeV3(entries map[string]POSIXAttr) []byte {
	var payload []byte
	for _, k := range slices.Sorted(maps.Keys(entries)) {
		body, err := json.Marshal(entries[k])
		if err != nil {
			panic(err)
		}
		payload = append(payload, 1)
		payload = binary.AppendUvarint(payload, uint64(len(k)))
		payload = append(payload, k...)
		payload = binary.AppendUvarint(payload, uint64(len(body)))
		payload = append(payload, body...)
	}
	out := append([]byte(journalMagic), journalVersionV3)
	return appendFrame(out, payload)
}

// encodeLegacyJSON returns the JSON document of schema version 2.
func encodeLegacyJSON(entries map[string]POSIXAttr) []byte {
	raw, err := json.Marshal(struct {
		Version int                  `json:"version"`
		Entries map[string]POSIXAttr `json:"entries"`
	}{2, entries})
	if err != nil {
		panic(err)
	}
	return raw
}

// pathKeyedHostTree creates the host entries that the records of
// pathKeyedEntries describe, except for the entries that name no host object.
func pathKeyedHostTree(t *testing.T, dir string) {
	t.Helper()
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "d/b", "h1"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(dir, "h1"), filepath.Join(dir, "h2")); err != nil {
		t.Skipf("the volume has no hard links: %v", err)
	}
}

func pathKeyedEntries() map[string]POSIXAttr {
	return map[string]POSIXAttr{
		"a":       {Mode: linux.S_IFREG | 0o751, UID: 5, GID: 6, Xattrs: map[string][]byte{"user.k": []byte("v")}},
		"d":       {Mode: linux.S_IFDIR | 0o750, UID: 1, GID: 2},
		"d/b":     {Mode: linux.S_IFREG | 0o640, UID: 3},
		"h1":      {Mode: linux.S_IFREG | 0o600, UID: 9, Ctime: 5},
		"h2":      {Mode: linux.S_IFREG | 0o600, UID: 9, Ctime: 5},
		"d/s":     {Mode: linux.S_IFLNK | 0o777, Symlink: "tgt", Mtime: 7, Ctime: 7},
		"gone":    {Mode: linux.S_IFREG | 0o600},
		"nodir/s": {Mode: linux.S_IFLNK | 0o777, Symlink: "x"},
	}
}

func TestOlderFormsConvertAtOpenAndStayOnDiskUntilAWrite(t *testing.T) {
	forms := map[string]func(map[string]POSIXAttr) []byte{
		"version 3 journal": encodeV3,
		"JSON document":     encodeLegacyJSON,
	}
	for name, encode := range forms {
		t.Run(name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			pathKeyedHostTree(t, dir)
			old := encode(pathKeyedEntries())
			path := filepath.Join(dir, MetaFileName)
			if err := os.WriteFile(path, old, 0o600); err != nil {
				t.Fatal(err)
			}

			ws := plainWS(t, dir, workspaceOptions{})
			if ws.pathKeys {
				t.Skip("the volume has no usable file identities")
			}
			requireMode(t, ws, "a", 0o751, 5)
			requireMode(t, ws, "d", 0o750, 1)
			requireMode(t, ws, "d/b", 0o640, 3)
			// Two names of one file collapse into one record that both share.
			requireMode(t, ws, "h1", 0o600, 9)
			requireMode(t, ws, "h2", 0o600, 9)
			if target, err := ws.Readlink("d/s"); err != nil || target != "tgt" {
				t.Fatalf("Readlink(d/s) = (%q, %v), want the converted virtual link", target, err)
			}

			// A session without a write leaves the old file as it was.
			if err := ws.Close(); err != nil {
				t.Fatal(err)
			}
			if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, old) {
				t.Fatalf("the file changed without a write that reached the flush (read error %v)", err)
			}
		})
	}
}

func TestFirstFlushWritesTheConvertedTable(t *testing.T) {
	forms := map[string]func(map[string]POSIXAttr) []byte{
		"version 3 journal": encodeV3,
		"JSON document":     encodeLegacyJSON,
	}
	for name, encode := range forms {
		t.Run(name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			pathKeyedHostTree(t, dir)
			path := filepath.Join(dir, MetaFileName)
			if err := os.WriteFile(path, encode(pathKeyedEntries()), 0o600); err != nil {
				t.Fatal(err)
			}
			ws := plainWS(t, dir, workspaceOptions{})
			if ws.pathKeys {
				t.Skip("the volume has no usable file identities")
			}
			if err := ws.Chmod("a", 0o700); err != nil {
				t.Fatal(err)
			}
			if err := ws.Chmod("h1", 0o644); err != nil {
				t.Fatal(err)
			}
			requireMode(t, ws, "h2", 0o644, 9)
			mustSync(t, ws)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.HasPrefix(raw, []byte(journalMagic)) || raw[len(journalMagic)] != journalVersion {
				t.Fatalf("the first flush of a changed session wrote %q, want the current journal version %d", raw[:min(len(raw), journalHeader)], journalVersion)
			}
			table := readMetaTable(t, path)
			for _, name := range []string{"a", "d", "d/b", "h1", "h2", "d/s"} {
				if _, ok := table[name]; !ok {
					t.Errorf("record %s is missing after the conversion", name)
				}
			}
			for _, name := range []string{"gone", "nodir/s"} {
				if _, ok := table[name]; ok {
					t.Errorf("record %s names no host object and survived the conversion", name)
				}
			}
			if got := table["a"]; got.Mode&0o7777 != 0o700 || got.UID != 5 || string(got.Xattrs["user.k"]) != "v" {
				t.Errorf("record a = %+v, want mode 700, owner 5, and the attribute that the old file held", got)
			}
		})
	}
}

func TestCrashDuringConversionOfTheVersionThreeJournalKeepsTheOldFile(t *testing.T) {
	dir := resolvedTempDir(t)
	pathKeyedHostTree(t, dir)
	old := encodeV3(pathKeyedEntries())
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	crash := errors.New("simulated crash before the rename")
	armed := true
	ws := plainWS(t, dir, workspaceOptions{beforeMetaRename: func() error {
		if armed {
			return crash
		}
		return nil
	}})
	if err := ws.Chmod("a", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := ws.Sync(); !errors.Is(err, crash) {
		t.Fatalf("Sync = %v, want the simulated crash", err)
	}
	if raw, err := os.ReadFile(path); err != nil || !bytes.Equal(raw, old) {
		t.Fatalf("the old file changed although the rename never ran (read error %v)", err)
	}
	armed = false
	mustSync(t, ws)
	if raw, err := os.ReadFile(path); err != nil || raw[len(journalMagic)] != journalVersion {
		t.Fatalf("the retry did not write the current form (read error %v)", err)
	}
}

func TestOlderFormsKeepPathRecordsOnAVolumeWithoutIdentities(t *testing.T) {
	dir := resolvedTempDir(t)
	pathKeyedHostTree(t, dir)
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, encodeV3(pathKeyedEntries()), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := plainWS(t, dir, workspaceOptions{pathKeys: true})
	requireMode(t, ws, "a", 0o751, 5)
	requireMode(t, ws, "h2", 0o600, 9)
	if target, err := ws.Readlink("d/s"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/s) = (%q, %v)", target, err)
	}
	// The table keeps every record, as it did before, until the collector
	// proves a record dead. The collector waits for the first flush, which
	// replaces the older file.
	if got := metaKeys(ws); !slices.Contains(got, "gone") || !slices.Contains(got, "nodir/s") {
		t.Fatalf("records = %q, want the unresolved records kept for the collector", got)
	}
	ws.orphanPass()
	if got := metaKeys(ws); !slices.Contains(got, "gone") {
		t.Fatalf("records = %q: the collector ran before the first flush replaced the older file", got)
	}
	if err := ws.Chmod("a", 0o700); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	ws.orphanPass()
	if got := metaKeys(ws); slices.Contains(got, "gone") || slices.Contains(got, "nodir/s") {
		t.Fatalf("records after one pass = %q, want the dead records collected", got)
	}
}

func TestConversionKeepsTheRecordOfAPathThatTheHostDeniedAccessTo(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("the test needs a directory that the process cannot search")
	}
	dir := resolvedTempDir(t)
	locked := filepath.Join(dir, "locked")
	if err := os.Mkdir(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"locked/f", "other"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, MetaFileName)
	old := encodeV3(map[string]POSIXAttr{
		"locked/f": {Mode: linux.S_IFREG | 0o4755, UID: 42},
		"other":    {Mode: linux.S_IFREG | 0o600},
	})
	if err := os.WriteFile(path, old, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	ws := plainWS(t, dir, workspaceOptions{})
	if ws.pathKeys {
		t.Skip("the volume has no usable file identities")
	}
	if err := ws.Chmod("other", 0o640); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	// The collector must not treat the foreign record as dead, however often
	// it runs.
	ws.orphanPass()
	if err := ws.Chmod("other", 0o644); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := parseMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	r := img.recs[recKey{kind: kindPath, path: "locked/f"}]
	if r == nil {
		t.Fatalf("the table on disk lost the record of locked/f: %v", slices.Collect(maps.Keys(img.recs)))
	}
	if r.attr.Mode&0o7777 != 0o4755 || r.attr.UID != 42 {
		t.Fatalf("record of locked/f = mode %o uid %d, want 4755 and 42", r.attr.Mode&0o7777, r.attr.UID)
	}

	if err := os.Chmod(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	requireMode(t, reopened, "locked/f", 0o4755, 42)
	requireMode(t, reopened, "other", 0o644, 0)
}

func TestTableConvertsWhenTheVolumeChangesItsKeyKind(t *testing.T) {
	dir := resolvedTempDir(t)
	byPath := plainWS(t, dir, workspaceOptions{pathKeys: true})
	mustWriteFile(t, byPath, "f", 0o751)
	if err := byPath.Mkdir("d", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := byPath.Symlink("t", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustSync(t, byPath)
	if err := byPath.Close(); err != nil {
		t.Fatal(err)
	}

	byID := plainWS(t, dir, workspaceOptions{})
	if byID.pathKeys {
		t.Skip("the volume has no usable file identities")
	}
	requireMode(t, byID, "f", 0o751, 0)
	requireMode(t, byID, "d", 0o750, 0)
	if target, err := byID.Readlink("d/l"); err != nil || target != "t" {
		t.Fatalf("Readlink(d/l) = (%q, %v) after the table gained identity keys", target, err)
	}
	if err := byID.Chmod("f", 0o700); err != nil {
		t.Fatal(err)
	}
	mustSync(t, byID)
	if err := byID.Close(); err != nil {
		t.Fatal(err)
	}

	back := plainWS(t, dir, workspaceOptions{pathKeys: true})
	requireMode(t, back, "f", 0o700, 0)
	requireMode(t, back, "d", 0o750, 0)
	if target, err := back.Readlink("d/l"); err != nil || target != "t" {
		t.Fatalf("Readlink(d/l) = (%q, %v) after the table went back to path keys", target, err)
	}
}
