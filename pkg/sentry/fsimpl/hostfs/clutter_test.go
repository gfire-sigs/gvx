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
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

// clutterOptions returns the options of a workspace that follows the clutter
// rules of the host operating system goos.
func clutterOptions(goos string) workspaceOptions {
	return workspaceOptions{coalesce: defaultCoalesceWindow, hostOS: goos}
}

func newClutterEnv(t *testing.T, goos string) *env {
	t.Helper()
	return newEnvOpts(t, clutterOptions(goos))
}

// appleDouble returns the content of an AppleDouble file with size bytes.
func appleDouble(size int) []byte {
	return append(bytes.Clone(appleDoubleMagic[:]), make([]byte, size-len(appleDoubleMagic))...)
}

func writeHost(t *testing.T, e *env, rel string, data []byte) {
	t.Helper()
	if err := os.WriteFile(e.host(rel), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMacHostClutterIsHidden(t *testing.T) {
	e := newClutterEnv(t, hostOSDarwin)
	e.writeFile("keep", []byte("k"))
	writeHost(t, e, ".DS_Store", []byte("finder"))
	writeHost(t, e, "._keep", appleDouble(120))
	writeHost(t, e, "._exact", appleDouble(appleDoubleMaxSize))
	writeHost(t, e, "._plain", []byte("this is not AppleDouble data"))
	writeHost(t, e, "._big", appleDouble(appleDoubleMaxSize+1))
	writeHost(t, e, "._", appleDouble(16))
	writeHost(t, e, "Thumbs.db", []byte("explorer"))
	if err := os.Mkdir(e.host("sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(e.host("sub/.DS_Store"), 0o700); err != nil {
		t.Fatal(err)
	}

	want := []string{"._", "._big", "._plain", "Thumbs.db", "keep", "sub"}
	if got := e.readdir("."); !slices.Equal(got, want) {
		t.Fatalf("listing = %q, want %q", got, want)
	}
	for _, name := range []string{".DS_Store", "._keep", "._exact"} {
		if _, err := e.stat(name); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat %q = %v, want ENOENT", name, err)
		}
		_, err := e.open(name, linux.O_RDONLY, 0)
		wantErrno(t, "open "+name, err, linuxerr.ENOENT)
	}
	for _, name := range []string{"._plain", "._big", "._", "Thumbs.db", "sub/.DS_Store"} {
		e.mustStat(name)
	}
	// A directory named like clutter is no clutter.
	if got := e.readdir("sub"); !slices.Equal(got, []string{".DS_Store"}) {
		t.Fatalf("listing of sub = %q", got)
	}
}

func TestWindowsHostClutterIsHidden(t *testing.T) {
	e := newClutterEnv(t, hostOSWindows)
	e.writeFile("keep", []byte("k"))
	writeHost(t, e, "Thumbs.db", []byte("explorer"))
	writeHost(t, e, "THUMBS.DB", []byte("explorer"))
	writeHost(t, e, ".DS_Store", []byte("finder"))
	writeHost(t, e, "._keep", appleDouble(64))
	got := e.readdir(".")
	// A host that folds case holds one of the two Thumbs.db names. Both are
	// clutter under the rule, so neither shows.
	for _, hidden := range []string{"Thumbs.db", "THUMBS.DB"} {
		if slices.Contains(got, hidden) {
			t.Fatalf("listing = %q, want %q hidden", got, hidden)
		}
	}
	for _, shown := range []string{".DS_Store", "._keep", "keep"} {
		if !slices.Contains(got, shown) {
			t.Fatalf("listing = %q, want %q shown", got, shown)
		}
	}
}

func TestLinuxHostShowsAllShellFiles(t *testing.T) {
	e := newClutterEnv(t, "linux")
	for _, name := range []string{".DS_Store", "Thumbs.db"} {
		writeHost(t, e, name, []byte("x"))
	}
	writeHost(t, e, "._x", appleDouble(32))
	if got, want := e.readdir("."), []string{".DS_Store", "._x", "Thumbs.db"}; !slices.Equal(got, want) {
		t.Fatalf("listing = %q, want %q", got, want)
	}
}

func TestMetaOwnedClutterNamesStayVisible(t *testing.T) {
	e := newClutterEnv(t, hostOSDarwin)
	// The guest creates the file itself, so .gvx_meta owns the name.
	e.writeFile(".DS_Store", []byte("guest"))
	e.writeFile("._owned", appleDouble(40))
	if got := e.readdir("."); !slices.Equal(got, []string{".DS_Store", "._owned"}) {
		t.Fatalf("listing = %q, want the guest-created clutter names", got)
	}
	if got := e.readFile(".DS_Store"); string(got) != "guest" {
		t.Fatalf(".DS_Store = %q", got)
	}

	// A host clutter file at a name that the guest wants goes away first.
	e2 := newClutterEnv(t, hostOSDarwin)
	writeHost(t, e2, ".DS_Store", []byte("finder"))
	fd, err := e2.open(".DS_Store", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("create over hidden clutter: %v", err)
	}
	fd.DecRef(e2.ctx)
	if got := e2.readFile(".DS_Store"); len(got) != 0 {
		t.Fatalf(".DS_Store = %q, want the new empty file", got)
	}
	if got := e2.readdir("."); !slices.Equal(got, []string{".DS_Store"}) {
		t.Fatalf("listing = %q, want the guest file", got)
	}
}

func TestRmdirPurgesVerifiedClutter(t *testing.T) {
	for _, tc := range []struct {
		goos  string
		files map[string][]byte
	}{
		{hostOSDarwin, map[string][]byte{".DS_Store": []byte("f"), "._a": appleDouble(50)}},
		{hostOSWindows, map[string][]byte{"Thumbs.db": []byte("t")}},
	} {
		t.Run(tc.goos, func(t *testing.T) {
			e := newClutterEnv(t, tc.goos)
			e.mustMkdir("d")
			for name, data := range tc.files {
				writeHost(t, e, "d/"+name, data)
			}
			if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("d")); err != nil {
				t.Fatalf("rmdir of a directory with only clutter: %v", err)
			}
			if _, err := os.Lstat(e.host("d")); !os.IsNotExist(err) {
				t.Fatalf("host directory after rmdir: %v", err)
			}

			// A visible entry keeps the directory and its clutter.
			e.mustMkdir("e")
			e.writeFile("e/visible", []byte("v"))
			for name, data := range tc.files {
				writeHost(t, e, "e/"+name, data)
			}
			wantErrno(t, "rmdir of a directory with a visible entry", e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("e")), linuxerr.ENOTEMPTY)
			for name := range tc.files {
				if _, err := os.Lstat(e.host("e/" + name)); err != nil {
					t.Fatalf("clutter file %q after the refused rmdir: %v", name, err)
				}
			}
			// The rm -rf order: remove the visible entry, then the directory.
			if err := e.unlink("e/visible"); err != nil {
				t.Fatal(err)
			}
			if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("e")); err != nil {
				t.Fatalf("rmdir after the unlink: %v", err)
			}

			// A rename onto an empty directory purges its clutter too.
			e.mustMkdir("src")
			e.writeFile("src/f", []byte("moved"))
			e.mustMkdir("dst")
			for name, data := range tc.files {
				writeHost(t, e, "dst/"+name, data)
			}
			if err := e.rename("src", "dst"); err != nil {
				t.Fatalf("rename onto a directory with only clutter: %v", err)
			}
			if got := e.readFile("dst/f"); string(got) != "moved" {
				t.Fatalf("dst/f = %q", got)
			}
		})
	}
}

func TestRmdirKeepsUnverifiedClutterLookalikes(t *testing.T) {
	e := newClutterEnv(t, hostOSDarwin)
	e.mustMkdir("d")
	writeHost(t, e, "d/._notes", []byte("user data that looks like clutter"))
	wantErrno(t, "rmdir with a lookalike", e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("d")), linuxerr.ENOTEMPTY)
	if _, err := os.Lstat(e.host("d/._notes")); err != nil {
		t.Fatalf("the lookalike was deleted: %v", err)
	}
}

func TestIsHostClutterDecidesByRulesAndContent(t *testing.T) {
	reg := func(size int64) hostInfo { return hostInfo{kind: hostKindRegular, size: size} }
	e := newClutterEnv(t, hostOSDarwin)
	writeHost(t, e, "._real", appleDouble(30))
	writeHost(t, e, "._fake", []byte("0123456789"))
	tests := []struct {
		name string
		info hostInfo
		want bool
	}{
		{".DS_Store", reg(10), true},
		{".DS_Store", hostInfo{kind: hostKindDir}, false},
		{".DS_Store", hostInfo{}, true},
		{"._real", reg(30), true},
		{"._real", reg(appleDoubleMaxSize + 1), false},
		{"._fake", reg(10), false},
		{"._missing", hostInfo{}, true},
		{"Thumbs.db", reg(1), false},
		{"plain", reg(1), false},
	}
	for _, tc := range tests {
		if got := e.ws.isHostClutter(".", tc.name, tc.info); got != tc.want {
			t.Errorf("isHostClutter(%q, kind %d, size %d) = %v, want %v", tc.name, tc.info.kind, tc.info.size, got, tc.want)
		}
	}
	// A record in .gvx_meta makes the name visible.
	e.writeFile("._owned", appleDouble(30))
	if e.ws.isHostClutter(".", "._owned", reg(30)) {
		t.Error("isHostClutter reports a name that .gvx_meta owns")
	}
	if name, ok := e.ws.hostVisibleName(".", "._owned", reg(30)); !ok || name != "._owned" {
		t.Errorf("hostVisibleName(._owned) = (%q, %v)", name, ok)
	}
}

func metaKeys(w *Workspace) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var keys []string
	for k := range w.meta {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func TestOpenWorkspaceSweepsInternalFilesOfAKilledProcess(t *testing.T) {
	opts := clutterOptions("linux")
	e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)
	e.mustMkdir("sub")
	e.writeFile("sub/file", []byte("f"))
	e.writeFile("root-file", []byte("r"))
	closeEnv()

	// The killed process left these behind.
	leftovers := []string{"~gvx~tmp.1", "~gvx~swap.2", "sub/~gvx~tmp.3"}
	for _, rel := range leftovers {
		writeHost(t, e, rel, []byte("old"))
	}
	if err := os.Mkdir(e.host("~gvx~swap.dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeHost(t, e, "~gvx~swap.dir/guest-data", []byte("data"))
	// A directory without a record keeps its leftovers: the sweep covers the
	// root and the directories that hold a record.
	if err := os.Mkdir(e.host("unknown"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeHost(t, e, "unknown/~gvx~tmp.4", []byte("old"))
	// A name that only looks similar stays.
	writeHost(t, e, "~gvx~tmpfile", []byte("keep"))

	e2, _ := openEnvAt(t, e.dir, opts)
	for _, rel := range leftovers {
		if _, err := os.Lstat(e2.host(rel)); !os.IsNotExist(err) {
			t.Errorf("leftover %q after open: %v", rel, err)
		}
	}
	for _, rel := range []string{"~gvx~swap.dir/guest-data", "unknown/~gvx~tmp.4", "~gvx~tmpfile", "sub/file", "root-file"} {
		if _, err := os.Lstat(e2.host(rel)); err != nil {
			t.Errorf("%q after open: %v", rel, err)
		}
	}
}

func TestReadOnlyWorkspaceSweepsNothing(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(dir+"/~gvx~tmp.1", []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := openWorkspace(dir, true, workspaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	if _, err := os.Lstat(dir + "/~gvx~tmp.1"); err != nil {
		t.Fatalf("a read-only open removed the leftover: %v", err)
	}
}

func TestOpenWorkspacePrunesRecordsOfMissingHostObjects(t *testing.T) {
	opts := clutterOptions("linux")
	e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)
	e.writeFile("a", []byte("a"))
	e.writeFile("b", []byte("b"))
	e.mustMkdir("d")
	e.writeFile("d/c", []byte("c"))
	e.mustMkdir("keepdir")
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("d/link"), "c"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link2"), "b"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("keepdir/link3"), "x"); err != nil {
		t.Fatal(err)
	}
	closeEnv()

	if err := os.Remove(e.host("a")); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(e.host("d")); err != nil {
		t.Fatal(err)
	}
	e2, _ := openEnvAt(t, e.dir, opts)
	want := []string{"b", "keepdir", "keepdir/link3", "link2"}
	if got := metaKeys(e2.ws); !slices.Equal(got, want) {
		t.Fatalf("records after open = %q, want %q", got, want)
	}
	if got := e2.readdir("."); !slices.Equal(got, []string{"b", "keepdir", "link2"}) {
		t.Fatalf("listing = %q", got)
	}
}

// failLstatHost fails the lstat of one path with a transient error.
type failLstatHost struct {
	hostBackend
	rel string
}

func (f failLstatHost) lstat(rel string) (hostInfo, error) {
	if rel == f.rel {
		return hostInfo{}, fmt.Errorf("lstat %q: %w", rel, fs.ErrPermission)
	}
	return f.hostBackend.lstat(rel)
}

func TestPruningNeverDeletesRecordsOnATransientError(t *testing.T) {
	opts := clutterOptions("linux")
	e, closeEnv := openEnvAt(t, resolvedTempDir(t), opts)
	e.writeFile("b", []byte("b"))
	e.writeFile("gone", []byte("g"))
	closeEnv()
	if err := os.Remove(e.host("gone")); err != nil {
		t.Fatal(err)
	}

	flaky := opts
	flaky.wrapHost = func(b hostBackend) hostBackend { return failLstatHost{b, "b"} }
	ws, err := openWorkspace(e.dir, false, flaky)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	// The lstat of "b" failed with a permission error, so its record stays.
	// The record of the missing file goes.
	if got := metaKeys(ws); !slices.Equal(got, []string{"b"}) {
		t.Fatalf("records after open = %q, want [b]", got)
	}
}

func TestFlushPrunesRecordsOfMissingHostObjects(t *testing.T) {
	e := newClutterEnv(t, "linux")
	e.writeFile("x", []byte("x"))
	e.writeFile("y", []byte("y"))
	e.mustMkdir("p")
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("p/l"), "x"); err != nil {
		t.Fatal(err)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.host("x")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(e.host("p")); err != nil {
		t.Fatal(err)
	}
	// A mutation marks the table dirty, and the flush checks the records.
	if err := e.ws.Chmod("y", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.host(MetaFileName))
	if err != nil {
		t.Fatal(err)
	}
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	var keys []string
	for k := range parsed.Entries {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	if !slices.Equal(keys, []string{"y"}) {
		t.Fatalf("flushed records = %q, want [y]", keys)
	}
}

func TestMetaSchemaVersionOneStillLoads(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(dir+"/f", []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	v1 := `{"version":1,"entries":{"f":{"mode":33152,"uid":5,"gid":6}}}`
	if err := os.WriteFile(dir+"/"+MetaFileName, []byte(v1), 0o600); err != nil {
		t.Fatal(err)
	}
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	st := e.mustStat("f")
	if st.UID != 5 || st.GID != 6 || st.Mode&0o7777 != 0o600 {
		t.Fatalf("stat of f = uid %d gid %d mode %o, want 5 6 600", st.UID, st.GID, st.Mode&0o7777)
	}
	if err := e.ws.Chown("f", 7, 8); err != nil {
		t.Fatal(err)
	}
	closeEnv()
	raw, err := os.ReadFile(dir + "/" + MetaFileName)
	if err != nil {
		t.Fatal(err)
	}
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Version != 2 {
		t.Fatalf("version after the first write = %d, want 2", parsed.Version)
	}
}

func TestMetaSchemaVersionTwoKeepsXattrs(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(dir+"/f", []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	// "dmFs" is the base64 text of "val".
	v2 := `{"version":2,"entries":{"f":{"mode":33188,"uid":0,"gid":0,"xattrs":{"user.k":"dmFs"}}}}`
	if err := os.WriteFile(dir+"/"+MetaFileName, []byte(v2), 0o600); err != nil {
		t.Fatal(err)
	}
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	entry, err := e.ws.lookup("f")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(entry.attr.Xattrs["user.k"]); got != "val" {
		t.Fatalf("xattr user.k = %q, want val", got)
	}
	if err := e.ws.Chmod("f", 0o640); err != nil {
		t.Fatal(err)
	}
	closeEnv()
	raw, err := os.ReadFile(dir + "/" + MetaFileName)
	if err != nil {
		t.Fatal(err)
	}
	var parsed metaStoreFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	if got := string(parsed.Entries["f"].Xattrs["user.k"]); parsed.Version != 2 || got != "val" {
		t.Fatalf("after the rewrite: version %d, xattr %q, want 2 and val", parsed.Version, got)
	}
}
