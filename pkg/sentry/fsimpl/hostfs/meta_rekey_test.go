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
	"path/filepath"
	"testing"
	"time"
)

// writeBirthTimeKeys rewrites the journal at path so that every key and every
// parent identity carries a birth time, as an earlier build wrote them on
// macOS.
func writeBirthTimeKeys(t *testing.T, path string) {
	t.Helper()
	const birth = 1_700_000_000_123_456_789
	var payload []byte
	for k, r := range rawRecords(t, path) {
		if k.kind == kindInode || k.kind == kindName {
			k.id.btime = birth
		}
		r = r.withLoc(r.hint, fileKey{dev: r.parent.dev, ino: r.parent.ino, btime: birth}, r.leaf)
		payload = appendOp(payload, metaOp{key: k, r: r})
	}
	raw := appendFrame(append([]byte(journalMagic), journalVersion), payload)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRecordsKeyedOnTheBirthTimeByAnEarlierBuildStillApply(t *testing.T) {
	// A build that keyed macOS records on the birth time wrote tables whose
	// keys never match a stat now. Without the match, the directory that holds
	// a guest created tree shows the 0700 mode of its host directory, and a
	// guest user other than the owner cannot enter it.
	if keysCarryBirthTime {
		t.Skip("the key of this platform holds the birth time")
	}
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chown("d", 1234, 5); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("tgt", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o751)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	writeBirthTimeKeys(t, filepath.Join(dir, MetaFileName))

	reopened := plainWS(t, dir, workspaceOptions{})
	requireMode(t, reopened, "d", 0o755, 1234)
	requireMode(t, reopened, "d/f", 0o751, 0)
	if target, err := reopened.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) = (%q, %v), want tgt", target, err)
	}
	// A host editor save below the directory finds the leaf of the record
	// through the identity of its parent, which no longer has a birth time.
	if err := os.WriteFile(filepath.Join(dir, "d", "f.tmp"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "d", "f.tmp"), filepath.Join(dir, "d", "f")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, reopened, "d/f", 0o751, 0)
}

var epoch2020 = time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)

func TestSettingTimesBeforeCreationKeepsTheLinksOfADirectory(t *testing.T) {
	// tar x, cp -a, and rsync -a set the times of a directory after they fill
	// it. APFS lowers the birth time then. The key holds no birth time on
	// macOS, so the links of the directory keep their key.
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("tgt", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o751)
	if err := ws.chtimes("d", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if target, err := ws.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) after chtimes = (%q, %v), want tgt", target, err)
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	if target, err := reopened.Readlink("d/l"); err != nil || target != "tgt" {
		t.Fatalf("Readlink(d/l) after reopen = (%q, %v), want tgt", target, err)
	}
	requireMode(t, reopened, "d", 0o755, 0)
	requireMode(t, reopened, "d/f", 0o751, 0)
}

func TestSettingTimesBeforeCreationThenRenamingAnAncestorKeepsTheFileRecord(t *testing.T) {
	// A package manager extracts to a staging directory, sets the times, and
	// renames the directory. APFS lowers the birth times of the entries, and
	// the records keep their keys.
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("stage", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "stage/f", 0o755)
	if err := ws.Chown("stage/f", 1234, 5); err != nil {
		t.Fatal(err)
	}
	if err := ws.chtimes("stage/f", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if err := ws.chtimes("stage", &epoch2020, &epoch2020); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("stage", "pkg"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "pkg/f", 0o755, 1234)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	requireMode(t, plainWS(t, dir, workspaceOptions{}), "pkg/f", 0o755, 1234)
}

func TestHostMoveToAnotherDirectoryKeepsTheRecordAtTheNewPath(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	if err := os.Rename(filepath.Join(dir, "a", "x"), filepath.Join(dir, "b", "x")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "b/x", 0o751, 0)
}

func TestRepairedHintReachesTheFileWithTheNextFlushOfAChange(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	mustSync(t, ws)
	diskHint := func() string {
		for _, r := range rawRecords(t, filepath.Join(dir, MetaFileName)) {
			if r.attr.Mode&0o7777 == 0o751 {
				return r.hint
			}
		}
		t.Fatal("no record with mode 751 on disk")
		return ""
	}

	if err := os.Rename(filepath.Join(dir, "a", "x"), filepath.Join(dir, "b", "x")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "b/x", 0o751, 0)
	if _, r := ws.meta.byHint("b/x"); r == nil {
		t.Fatal("the read did not repair the hint of the moved file in memory")
	}
	if n := ws.meta.pending(); n != 0 {
		t.Fatalf("a repaired hint made %d records pending, want 0", n)
	}
	mustSync(t, ws)
	if got := diskHint(); got != "a/x" {
		t.Fatalf("hint on disk after a flush without a change = %q, want a/x", got)
	}

	mustWriteFile(t, ws, "other", 0o600)
	mustSync(t, ws)
	if got := diskHint(); got != "b/x" {
		t.Fatalf("hint on disk after the flush of another change = %q, want b/x", got)
	}
}

func TestHostFileAtAnOldNameNeverGainsSetuid(t *testing.T) {
	for name, replace := range map[string]func(t *testing.T, dir string){
		"delete and create": func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, "x")); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "x"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"save by rename": func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "x.tmp"), []byte("new"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(filepath.Join(dir, "x.tmp"), filepath.Join(dir, "x")); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := resolvedTempDir(t)
			ws := plainWS(t, dir, workspaceOptions{})
			requireStableIDs(t, ws)
			mustWriteFile(t, ws, "x", 0o4755)
			if err := ws.Chown("x", 1234, 0); err != nil {
				t.Fatal(err)
			}
			replace(t, dir)
			attr, _, err := ws.Stat("x")
			if err != nil || attr.Mode&0o6000 != 0 {
				t.Fatalf("Stat(x) = (%+v, %v), want no set-user-ID and no set-group-ID bit on a file that a host process wrote", attr, err)
			}
		})
	}
}

func TestHostDirectoryAtAnOldNameNeverGainsSetgid(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chmod("d", 0o2775); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "d")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o755); err != nil {
		t.Fatal(err)
	}
	attr, _, err := ws.Stat("d")
	if err != nil || attr.Mode&0o6000 != 0 {
		t.Fatalf("Stat(d) = (%+v, %v), want no set-group-ID bit on a directory that a host process made", attr, err)
	}
}

func TestSameNameInAnotherDirectoryNeverAdoptsTheRecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	if err := os.Remove(filepath.Join(dir, "a", "x")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b", "x"), []byte("n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if attr, _, err := ws.Stat("b/x"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(b/x) = (%+v, %v): a file in another directory adopted the record of a/x", attr, err)
	}
}

func TestDirectoryRenameDoesNotBreakAdoptionBelowIt(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/doc", 0o751)
	if err := ws.Rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	// The editor saves into the renamed directory.
	if err := os.WriteFile(filepath.Join(dir, "e", "doc.tmp"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "e", "doc.tmp"), filepath.Join(dir, "e", "doc")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "e/doc", 0o751, 0)
}

// An exchange moves each record to the other name, so the directory and the
// leaf of the record must follow. A host editor that saves over one of the
// names adopts by that position.
func TestExchangeThenHostEditorSaveKeepsBothRecords(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if ws.pathKeys {
		t.Skip("a volume with path keys keeps the record under the path")
	}
	for _, d := range []string{"a", "b"} {
		if err := ws.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustWriteFile(t, ws, "a/x", 0o751)
	if err := ws.Chown("a/x", 7, 8); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "b/y", 0o640)
	if err := ws.Chown("b/y", 9, 8); err != nil {
		t.Fatal(err)
	}
	if err := ws.exchange("a/x", "b/y"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "a/x", 0o640, 9)
	requireMode(t, ws, "b/y", 0o751, 7)

	// An editor saves over a/x.
	if err := os.WriteFile(filepath.Join(dir, "a", "x.tmp"), []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "a", "x.tmp"), filepath.Join(dir, "a", "x")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "a/x", 0o640, 9)
	requireMode(t, ws, "b/y", 0o751, 7)
}
