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

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// These tests model an entry of a child file system inside a workspace whose
// own volume has file identities. The entry reports no identity, so its records
// key on the guest path while the records of every other entry key on the
// identity. See mixedWS.

func hasPathRecord(ws *Workspace, rel string) bool {
	return ws.meta.has(recKey{kind: kindPath, path: rel})
}

func hasPathLink(ws *Workspace, rel string) bool {
	parent, name := splitParent(rel)
	return ws.meta.has(recKey{kind: kindPathName, path: parent, name: name})
}

// requireIdentityRecord fails unless the record of rel keys on an identity.
func requireIdentityRecord(t *testing.T, ws *Workspace, rel string) {
	t.Helper()
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	e, err := ws.lookupLocked(rel)
	if err != nil {
		t.Fatalf("lookup(%s): %v", rel, err)
	}
	if e.key.kind != kindInode || ws.meta.get(e.key) == nil {
		t.Fatalf("record of %s = key %+v, want a record under an identity key", rel, e.key)
	}
}

func TestEntriesWithoutIdentityKeepRecordsByPath(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if err := ws.Mkdir("id", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "id/f", 0o751)
	if err := ws.Symlink("tgt", "id/l"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Mkdir("npdir", 0o700); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "npdir/f", 0o640)
	if err := ws.Chown("npdir/f", 7, 8); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chmod("npdir", 0o711); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("tgt2", "npdir/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "npfile", 0o600)
	if err := ws.Chown("npfile", 9, 10); err != nil {
		t.Fatal(err)
	}

	for _, rel := range []string{"npdir", "npdir/f", "npfile"} {
		if !hasPathRecord(ws, rel) {
			t.Errorf("no path record for %s", rel)
		}
	}
	if !hasPathLink(ws, "npdir/l") {
		t.Error("no path record for the link npdir/l")
	}
	requireIdentityRecord(t, ws, "id")
	requireIdentityRecord(t, ws, "id/f")
	check := func(ws *Workspace) {
		t.Helper()
		requireMode(t, ws, "id/f", 0o751, 0)
		requireMode(t, ws, "npdir", 0o711, 0)
		requireMode(t, ws, "npdir/f", 0o640, 7)
		requireMode(t, ws, "npfile", 0o600, 9)
		for rel, want := range map[string]string{"id/l": "tgt", "npdir/l": "tgt2"} {
			if got, err := ws.Readlink(rel); err != nil || got != want {
				t.Fatalf("Readlink(%s) = (%q, %v), want %q", rel, got, err, want)
			}
		}
	}
	check(ws)

	// Both kinds survive a restart and a pass of the collector.
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := mixedWS(t, dir)
	if reopened.journal.converted {
		t.Fatal("a table of identity records and path records for nameless entries is marked as converted")
	}
	for range 3 {
		reopened.orphanPass()
	}
	check(reopened)
	for _, rel := range []string{"npdir", "npdir/f", "npfile"} {
		if !hasPathRecord(reopened, rel) {
			t.Errorf("path record of %s lost across a reopen", rel)
		}
	}
}

func TestRenamingADirectoryWithoutIdentityMovesItsRecords(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if err := ws.Mkdir("npdir", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Mkdir("npdir/sub", 0o750); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "npdir/sub/f", 0o751)
	if err := ws.Symlink("tgt", "npdir/l"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("npdir", "npnew"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "npnew", 0o755, 0)
	requireMode(t, ws, "npnew/sub", 0o750, 0)
	requireMode(t, ws, "npnew/sub/f", 0o751, 0)
	if got, err := ws.Readlink("npnew/l"); err != nil || got != "tgt" {
		t.Fatalf("Readlink(npnew/l) = (%q, %v), want tgt", got, err)
	}
	for _, rel := range []string{"npdir", "npdir/sub", "npdir/sub/f"} {
		if hasPathRecord(ws, rel) {
			t.Errorf("record of %s stayed at the old path", rel)
		}
	}
	if hasPathLink(ws, "npdir/l") {
		t.Error("link record stayed at the old path")
	}
}

func TestRenamingADirectoryWithIdentityMovesPathRecordsBelowIt(t *testing.T) {
	// A mount point of a child file system sits below a directory that has an
	// identity. The mount keeps its own entries by path.
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if err := ws.Mkdir("outer", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Mkdir("outer/npmnt", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "outer/npmnt/f", 0o751)
	if err := ws.Rename("outer", "moved"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "moved/npmnt/f", 0o751, 0)
	if hasPathRecord(ws, "outer/npmnt/f") {
		t.Error("the path record stayed below the old name of the directory")
	}
}

func TestHardLinksOfAnEntryWithoutIdentityShareAttributes(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	mustWriteFile(t, ws, "npa", 0o644)
	if err := ws.link("npa", "npb"); err != nil {
		t.Skipf("the volume of the temporary directory has no hard links: %v", err)
	}
	if !hasPathRecord(ws, "npb") {
		t.Fatal("the new name has no record of its own")
	}
	if err := ws.Chmod("npb", 0o600); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "npa", 0o600, 0)
	requireMode(t, ws, "npb", 0o600, 0)
	if err := ws.Unlink("npa"); err != nil {
		t.Fatal(err)
	}
	if hasPathRecord(ws, "npa") {
		t.Error("the record of a removed name stayed")
	}
	requireMode(t, ws, "npb", 0o600, 0)
}

func TestEntriesWithoutIdentityThroughTheGuest(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	e := mountEnv(t, ws, dir)
	e.mustMkdir("npd")
	e.writeFile("npd/f", []byte("x"))
	e.chmod("npd/f", 0o751)
	if err := e.setStat("npd/f", linux.Statx{Mask: linux.STATX_UID | linux.STATX_GID, UID: 11, GID: 12}); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("npd/f", "trusted.tag", "kept")
	e.mustSetXattr("npd", "trusted.dir", "dirval")
	if err := e.symlink("npd/l", "target"); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("npd/f"); st.Mode&0o7777 != 0o751 || st.UID != 11 || st.GID != 12 {
		t.Fatalf("stat(npd/f) = mode %o uid %d gid %d, want 751 11 12", st.Mode&0o7777, st.UID, st.GID)
	}
	if got := e.mustGetXattr("npd/f", "trusted.tag"); got != "kept" {
		t.Fatalf("attribute of npd/f = %q, want kept", got)
	}

	// A rename of the directory moves the records and the attributes.
	if err := e.rename("npd", "npe"); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("npe/f"); st.Mode&0o7777 != 0o751 || st.UID != 11 {
		t.Fatalf("stat(npe/f) after the rename = mode %o uid %d, want 751 11", st.Mode&0o7777, st.UID)
	}
	if got := e.mustGetXattr("npe/f", "trusted.tag"); got != "kept" {
		t.Fatalf("attribute of npe/f after the rename = %q, want kept", got)
	}
	if got := e.mustGetXattr("npe", "trusted.dir"); got != "dirval" {
		t.Fatalf("attribute of npe after the rename = %q, want dirval", got)
	}
	if got, err := e.readlink("npe/l"); err != nil || got != "target" {
		t.Fatalf("readlink(npe/l) after the rename = (%q, %v), want target", got, err)
	}

	// An exchange swaps the records of two directories with their contents.
	e.mustMkdir("npx")
	e.writeFile("npx/g", []byte("y"))
	e.chmod("npx/g", 0o600)
	if err := e.renameFlags("npe", "npx", linux.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("npx/f"); st.Mode&0o7777 != 0o751 || st.UID != 11 {
		t.Fatalf("stat(npx/f) after the exchange = mode %o uid %d, want 751 11", st.Mode&0o7777, st.UID)
	}
	if st := e.mustStat("npe/g"); st.Mode&0o7777 != 0o600 {
		t.Fatalf("stat(npe/g) after the exchange = mode %o, want 600", st.Mode&0o7777)
	}
	if got, err := e.readlink("npx/l"); err != nil || got != "target" {
		t.Fatalf("readlink(npx/l) after the exchange = (%q, %v), want target", got, err)
	}

	// Removal drops the records.
	if err := e.unlink("npx/f"); err != nil {
		t.Fatal(err)
	}
	if hasPathRecord(ws, "npx/f") {
		t.Error("the record of an unlinked entry stayed")
	}
}

func TestCollectorTreatsPathRecordsByTheWalk(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if err := ws.Mkdir("npdir", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "npdir/keep", 0o751)
	mustWriteFile(t, ws, "npdir/gone", 0o752)
	if err := ws.Symlink("tgt", "npdir/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "idfile", 0o753)
	if err := os.Remove(filepath.Join(dir, "npdir", "gone")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		ws.orphanPass()
	}
	if hasPathRecord(ws, "npdir/gone") {
		t.Error("the collector kept the path record of a deleted entry")
	}
	for _, rel := range []string{"npdir", "npdir/keep"} {
		if !hasPathRecord(ws, rel) {
			t.Errorf("the collector removed the live path record of %s", rel)
		}
	}
	if !hasPathLink(ws, "npdir/l") {
		t.Error("the collector removed the link of a live directory")
	}
	requireMode(t, ws, "idfile", 0o753, 0)

	// Deleting the directory with its contents removes the rest.
	if err := os.RemoveAll(filepath.Join(dir, "npdir")); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		ws.orphanPass()
	}
	for _, rel := range []string{"npdir", "npdir/keep"} {
		if hasPathRecord(ws, rel) {
			t.Errorf("the collector kept the path record of %s after its directory vanished", rel)
		}
	}
	if hasPathLink(ws, "npdir/l") {
		t.Error("the collector kept the link of a vanished directory")
	}
}

func TestPathRecordOfAnAbsentEntrySurvivesAnOpen(t *testing.T) {
	// The file system of the entry can be unmounted while the workspace
	// opens, so an absent path keeps its record until the collector proves the
	// loss.
	dir := resolvedTempDir(t)
	ws := mixedWS(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if err := ws.Mkdir("npmnt", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "npmnt/f", 0o751)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "npmnt"), filepath.Join(dir, "away")); err != nil {
		t.Fatal(err)
	}
	reopened := mixedWS(t, dir)
	if !hasPathRecord(reopened, "npmnt/f") {
		t.Fatal("an open dropped the path record of an absent entry")
	}
	if err := os.Rename(filepath.Join(dir, "away"), filepath.Join(dir, "npmnt")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, reopened, "npmnt/f", 0o751, 0)
}

func TestIdentityPassWalksForPathRecords(t *testing.T) {
	// A host that opens files by identity (Windows) answers for the identity
	// records. The path records of nameless entries still need the walk.
	dir := resolvedTempDir(t)
	ws, host := mixedWSHost(t, dir)
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	host.scanExists = true
	ws.caps.ExistsByID = true
	mustWriteFile(t, ws, "npkeep", 0o751)
	mustWriteFile(t, ws, "npgone", 0o752)
	mustWriteFile(t, ws, "idkeep", 0o753)
	mustWriteFile(t, ws, "idgone", 0o754)
	for _, name := range []string{"npgone", "idgone"} {
		if err := os.Remove(filepath.Join(dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	for range 3 {
		ws.orphanPass()
	}
	if hasPathRecord(ws, "npgone") {
		t.Error("the identity pass kept the path record of a deleted entry")
	}
	if !hasPathRecord(ws, "npkeep") {
		t.Error("the identity pass removed the live path record")
	}
	requireMode(t, ws, "idkeep", 0o753, 0)
	if n := ws.meta.size(); n != 2 {
		t.Errorf("the table holds %d records, want 2 (npkeep, idkeep)", n)
	}
}
