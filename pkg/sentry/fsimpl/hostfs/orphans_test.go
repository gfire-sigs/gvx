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
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
)

// forEachKeyKind runs fn for a workspace that keys its records on file
// identities and for one that keys them on guest paths.
func forEachKeyKind(t *testing.T, fn func(t *testing.T, opts workspaceOptions)) {
	t.Helper()
	t.Run("file identities", func(t *testing.T) { fn(t, workspaceOptions{}) })
	t.Run("guest paths", func(t *testing.T) { fn(t, workspaceOptions{pathKeys: true}) })
}

// flakyHost fails chosen host calls. A listing or an identity lookup fails
// with a transient error. A lookup by name fails with a permission error.
type flakyHost struct {
	hostBackend
	// failListing fails every directory listing. failIDs fails every lookup
	// by identity. A pass that walks the tree meets the first, and a pass that
	// asks the host about each identity meets the second.
	failListing atomic.Bool
	failIDs     atomic.Bool
	failName    atomic.Value // string: the name whose lstat fails
}

var (
	errTransient = errors.New("transient host error")
	errDenied    = fs.ErrPermission
)

func (f *flakyHost) readDirAt(dir hostDirHandle) ([]hostDirEntry, error) {
	if f.failListing.Load() {
		return nil, errTransient
	}
	return f.hostBackend.readDirAt(dir)
}

func (f *flakyHost) existsByID(key fileKey) (bool, error) {
	if f.failIDs.Load() {
		return false, errTransient
	}
	return f.hostBackend.existsByID(key)
}

func (f *flakyHost) failing(name string) bool {
	n, _ := f.failName.Load().(string)
	return n != "" && n == name
}

func (f *flakyHost) lstat(rel string) (hostInfo, error) {
	if f.failing(rel) {
		return hostInfo{}, errDenied
	}
	return f.hostBackend.lstat(rel)
}

func (f *flakyHost) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	if f.failing(name) {
		return hostInfo{}, errDenied
	}
	return f.hostBackend.lstatAt(dir, name)
}

func TestOpenKeepsTheRecordsOfMissingHostObjectsUntilTheCollectorRuns(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "a", 0o644)
		mustWriteFile(t, ws, "b", 0o644)
		if err := ws.Mkdir("d", 0o755); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, ws, "d/c", 0o644)
		if err := ws.Mkdir("keepdir", 0o755); err != nil {
			t.Fatal(err)
		}
		for _, link := range []string{"d/link", "link2", "keepdir/link3"} {
			if err := ws.Symlink("t", link); err != nil {
				t.Fatal(err)
			}
		}
		mustSync(t, ws)
		if err := ws.Close(); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(dir, "a")); err != nil {
			t.Fatal(err)
		}
		if err := os.RemoveAll(filepath.Join(dir, "d")); err != nil {
			t.Fatal(err)
		}

		reopened := plainWS(t, dir, opts)
		all := []string{"a", "b", "d", "d/c", "d/link", "keepdir", "keepdir/link3", "link2"}
		if got := metaKeys(reopened); !slices.Equal(got, all) {
			t.Fatalf("records after open = %q, want every record: open checks none against the host", got)
		}

		reopened.orphanPass()
		want := []string{"b", "keepdir", "keepdir/link3", "link2"}
		if got := metaKeys(reopened); !slices.Equal(got, want) {
			t.Fatalf("records after one pass = %q, want %q", got, want)
		}
		if got := listNames(t, reopened, "."); !slices.Equal(got, []string{"b", "keepdir", "link2"}) {
			t.Fatalf("listing = %q", got)
		}
	})
}

// listNames returns the sorted names that the guest sees in the directory rel.
func listNames(t testing.TB, ws *Workspace, rel string) []string {
	t.Helper()
	entries, err := ws.listDir(rel)
	if err != nil {
		t.Fatalf("listDir(%s): %v", rel, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.name)
	}
	return names
}

func TestCollectorRemovalReachesTheFile(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "gone", 0o644)
		mustWriteFile(t, ws, "kept", 0o644)
		mustSync(t, ws)
		if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
			t.Fatal(err)
		}
		ws.orphanPass()
		// A new record forces a flush, which writes the table without the
		// collected record.
		if err := ws.Chmod("kept", 0o600); err != nil {
			t.Fatal(err)
		}
		mustSync(t, ws)
		raw, err := os.ReadFile(filepath.Join(dir, MetaFileName))
		if err != nil {
			t.Fatal(err)
		}
		img, err := parseMeta(raw)
		if err != nil {
			t.Fatal(err)
		}
		hints := map[string]bool{}
		for k, r := range img.recs {
			if k.kind == kindPath {
				hints[k.path] = true
			} else {
				hints[r.hint] = true
			}
		}
		if hints["gone"] || !hints["kept"] {
			t.Fatalf("records on disk = %v, want kept without gone", hints)
		}
	})
}

func TestCollectorKeepsEveryRecordAfterATransientListingError(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		host := &flakyHost{}
		opts.wrapHost = func(b hostBackend) hostBackend {
			host.hostBackend = b
			return host
		}
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "gone", 0o644)
		mustWriteFile(t, ws, "kept", 0o644)
		if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
			t.Fatal(err)
		}

		host.failListing.Store(true)
		host.failIDs.Store(true)
		for range 3 {
			ws.orphanPass()
		}
		if got := metaKeys(ws); !slices.Equal(got, []string{"gone", "kept"}) {
			t.Fatalf("records after passes that met a host error = %q, want both: an error never deletes a record", got)
		}
		host.failListing.Store(false)
		host.failIDs.Store(false)
		ws.orphanPass()
		if got := metaKeys(ws); !slices.Equal(got, []string{"kept"}) {
			t.Fatalf("records after a clean pass = %q, want [kept]", got)
		}
	})
}

func TestCollectorKeepsARecordWhenTheLastLookupFails(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		host := &flakyHost{}
		opts.wrapHost = func(b hostBackend) hostBackend {
			host.hostBackend = b
			return host
		}
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "gone", 0o644)
		mustWriteFile(t, ws, "kept", 0o644)
		if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
			t.Fatal(err)
		}
		// The pass misses the record of gone. The confirming lookup of its
		// path then fails with a permission error, which proves nothing.
		host.failName.Store("gone")
		ws.orphanPass()
		if got := metaKeys(ws); !slices.Equal(got, []string{"gone", "kept"}) {
			t.Fatalf("records = %q, want both while the lookup of gone fails", got)
		}
		host.failName.Store("")
		ws.orphanPass()
		if got := metaKeys(ws); !slices.Equal(got, []string{"kept"}) {
			t.Fatalf("records = %q, want [kept] once the lookup works", got)
		}
	})
}

func TestCollectorKeepsTheRecordOfAFileThatAHostProcessMoved(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if ws.pathKeys {
		t.Skip("a volume without file identities loses the record of a moved file by design")
	}
	mustWriteFile(t, ws, "name", 0o751)
	if err := os.Mkdir(filepath.Join(dir, "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "name"), filepath.Join(dir, "elsewhere", "moved")); err != nil {
		t.Fatal(err)
	}
	ws.orphanPass()
	requireMode(t, ws, "elsewhere/moved", 0o751, 0)
}

func TestCollectorKeepsRecordsOfADirectoryThatAHostProcessMovedAway(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS refuses a host rename of a directory that holds an open handle of hostfs")
	}
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	if ws.pathKeys {
		t.Skip("a volume without file identities loses the records of a moved directory by design")
	}
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o751)
	// This lookup opens the pinned handle of d. The handle follows the
	// directory when the host renames it.
	requireMode(t, ws, "d/f", 0o751, 0)
	if err := os.Rename(filepath.Join(dir, "d"), filepath.Join(dir, "d2")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "d"), 0o700); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		ws.orphanPass()
	}
	requireMode(t, ws, "d2/f", 0o751, 0)
}

func TestCollectorDoesNotTouchAnOlderFileUntilTheFirstWrite(t *testing.T) {
	dir := resolvedTempDir(t)
	v3 := encodeV3(map[string]POSIXAttr{"a": {Mode: 0o100640}, "missing": {Mode: 0o100600}})
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, MetaFileName)
	if err := os.WriteFile(path, v3, 0o600); err != nil {
		t.Fatal(err)
	}
	ws := plainWS(t, dir, workspaceOptions{})
	for range 3 {
		ws.orphanPass()
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(path); err != nil || string(raw) != string(v3) {
		t.Fatalf(".gvx_meta changed in a session without a write (read error %v)", err)
	}
}

func TestCollectorDoesNothingOnAReadOnlyWorkspace(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	mustWriteFile(t, ws, "gone", 0o644)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	ro, err := openWorkspace(dir, true, workspaceOptions{noOrphanGC: true})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		ro.orphanPass()
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(filepath.Join(dir, MetaFileName))
	if err != nil || string(after) != string(before) {
		t.Fatalf(".gvx_meta of a read-only workspace changed (read error %v)", err)
	}
}

func TestCollectorLeavesARecordThatTheGuestRecreated(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "f", 0o751)
		if err := os.Remove(filepath.Join(dir, "f")); err != nil {
			t.Fatal(err)
		}
		ws.orphanPass()
		// The first pass collected the old record. The guest creates the name
		// again, and the next pass must keep the new record.
		if err := ws.Unlink("f"); err != nil && !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		mustWriteFile(t, ws, "f", 0o600)
		ws.orphanPass()
		requireMode(t, ws, "f", 0o600, 0)
	})
}

func TestCollectorSkipsADirectoryThatTheHostDeniesAccessTo(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("the test needs a directory that the process cannot read")
	}
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, opts)
		mustWriteFile(t, ws, "gone", 0o644)
		mustWriteFile(t, ws, "kept", 0o644)
		if err := ws.Mkdir("locked", 0o755); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, ws, "locked/f", 0o644)
		if err := ws.Symlink("t", "locked/link"); err != nil {
			t.Fatal(err)
		}
		mustSync(t, ws)
		if err := ws.Close(); err != nil {
			t.Fatal(err)
		}

		locked := filepath.Join(dir, "locked")
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
		if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
			t.Fatal(err)
		}

		// A new session has no cached pin of the directory.
		reopened := plainWS(t, dir, opts)
		reopened.orphanPass()
		want := []string{"kept", "locked", "locked/f", "locked/link"}
		if got := metaKeys(reopened); !slices.Equal(got, want) {
			t.Fatalf("records after a pass that met an unreadable directory = %q, want %q", got, want)
		}
	})
}

func TestOnePassBoundsTheTableAfterAMassDeletion(t *testing.T) {
	const files = 2000
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, opts)
		for i := range files {
			mustWriteFile(t, ws, fmt.Sprintf("f%04d", i), 0o640)
		}
		if got := ws.meta.size(); got != files {
			t.Fatalf("records before the deletion = %d, want %d", got, files)
		}
		for i := range files {
			if err := os.Remove(filepath.Join(dir, fmt.Sprintf("f%04d", i))); err != nil {
				t.Fatal(err)
			}
		}
		ws.orphanPass()
		if got := ws.meta.size(); got != 0 {
			t.Fatalf("records after one pass = %d, want 0", got)
		}
	})
}

func TestShortSessionCollectsTheRecordOfAFileThatTheHostDeleted(t *testing.T) {
	forEachKeyKind(t, func(t *testing.T, opts workspaceOptions) {
		dir := resolvedTempDir(t)
		first := plainWS(t, dir, opts)
		mustWriteFile(t, first, "gone", 0o640)
		mustWriteFile(t, first, "kept", 0o640)
		mustSync(t, first)
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}

		ws := plainWS(t, dir, opts)
		if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
			t.Fatal(err)
		}
		ws.orphanPass()
		if got := metaKeys(ws); !slices.Equal(got, []string{"kept"}) {
			t.Fatalf("records after one pass of a session without a guest write = %q, want [kept]", got)
		}
	})
}
