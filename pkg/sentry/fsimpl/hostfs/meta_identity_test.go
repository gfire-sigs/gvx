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
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
)

// identityHost wraps a host backend and rewrites the file identity that each
// stat reports. A test uses it to model a host that reuses an inode number or
// that reports no usable identity, which a real volume does not let a test
// control.
type identityHost struct {
	hostBackend

	mu      sync.Mutex
	rewrite func(hostInfo) hostInfo
	// nameless, when set, picks the leaf names whose entries report no
	// identity, as an entry of a child file system does. So does every entry
	// below such a directory. The host learns the inode numbers of these
	// entries when a call names them. See markNameless.
	nameless func(name string) bool
	bad      map[uint64]struct{}
	// rewriteList, when set, rewrites the entries that a listing through a
	// pinned handle returns.
	rewriteList func(hostDirEntry) hostDirEntry
	// scanExists answers existsByID with a walk of the tree, as a host that
	// opens a file by identity does.
	scanExists bool
}

func (h *identityHost) existsByID(key fileKey) (bool, error) {
	if !h.scanExists {
		return h.hostBackend.existsByID(key)
	}
	var walk func(dir string) bool
	walk = func(dir string) bool {
		entries, err := h.hostBackend.readDir(dir)
		if err != nil {
			return false
		}
		for _, e := range entries {
			rel := hostChild(dir, e.name)
			info, err := h.hostBackend.lstat(rel)
			if err != nil {
				continue
			}
			if info.fid == key || (e.kind == hostKindDir && walk(rel)) {
				return true
			}
		}
		return false
	}
	return walk("."), nil
}

func (h *identityHost) readDirAt(dir hostDirHandle) ([]hostDirEntry, error) {
	entries, err := h.hostBackend.readDirAt(dir)
	h.mu.Lock()
	rewrite := h.rewriteList
	h.mu.Unlock()
	if err != nil || rewrite == nil {
		return entries, err
	}
	out := make([]hostDirEntry, len(entries))
	for i, e := range entries {
		out[i] = rewrite(e)
	}
	return out, nil
}

func (h *identityHost) set(rewrite func(hostInfo) hostInfo) {
	h.mu.Lock()
	h.rewrite = rewrite
	h.mu.Unlock()
}

func (h *identityHost) apply(info hostInfo, err error) (hostInfo, error) {
	if err != nil {
		return info, err
	}
	h.mu.Lock()
	rewrite := h.rewrite
	_, bad := h.bad[info.fid.ino]
	h.mu.Unlock()
	if rewrite != nil {
		info = rewrite(info)
	}
	if bad {
		info.fidOK = false
	}
	return info, nil
}

// markNameless records the inode number of the entry that the call named when
// the entry is nameless itself or sits below a nameless directory.
func (h *identityHost) markNameless(parentIno uint64, rels []string, ino uint64) {
	if h.nameless == nil || ino == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	_, below := h.bad[parentIno]
	for _, name := range rels {
		below = below || h.nameless(name)
	}
	if below {
		if h.bad == nil {
			h.bad = make(map[uint64]struct{})
		}
		h.bad[ino] = struct{}{}
	}
}

func (h *identityHost) markPath(rel string, info hostInfo) {
	h.markNameless(0, strings.Split(rel, "/"), info.fid.ino)
}

func (h *identityHost) markAt(dir hostDirHandle, name string, info hostInfo) {
	if h.nameless == nil {
		return
	}
	parent, err := h.hostBackend.fstatDir(dir)
	if err != nil {
		return
	}
	h.markNameless(parent.fid.ino, []string{name}, info.fid.ino)
}

func (h *identityHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	f, err := h.hostBackend.open(rel, flags, perm)
	if err == nil {
		if info, serr := h.hostBackend.fstat(f); serr == nil {
			h.markPath(rel, info)
		}
	}
	return f, err
}

func (h *identityHost) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	f, err := h.hostBackend.openChildAt(dir, name, flags, perm)
	if err == nil {
		if info, serr := h.hostBackend.fstat(f); serr == nil {
			h.markAt(dir, name, info)
		}
	}
	return f, err
}

func (h *identityHost) lstat(rel string) (hostInfo, error) {
	info, err := h.hostBackend.lstat(rel)
	if err == nil && rel != "." {
		h.markPath(rel, info)
	}
	return h.apply(info, err)
}

func (h *identityHost) fstat(f *os.File) (hostInfo, error) {
	return h.apply(h.hostBackend.fstat(f))
}

func (h *identityHost) fstatDir(dir hostDirHandle) (hostInfo, error) {
	return h.apply(h.hostBackend.fstatDir(dir))
}

func (h *identityHost) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	info, err := h.hostBackend.lstatAt(dir, name)
	if err == nil {
		h.markAt(dir, name, info)
	}
	return h.apply(info, err)
}

func (h *identityHost) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	handle, info, err := h.hostBackend.openDirAt(dir, name)
	if err != nil {
		return handle, info, err
	}
	h.markAt(dir, name, info)
	info, _ = h.apply(info, nil)
	return handle, info, nil
}

// identityWS opens a workspace on dir whose stat results pass through the
// returned identityHost. The workspace never flushes on its own and runs no
// background collector, so a test controls both.
func identityWS(t testing.TB, dir string) (*Workspace, *identityHost) {
	t.Helper()
	host := &identityHost{}
	ws := journalWS(t, dir, workspaceOptions{
		noOrphanGC: true,
		wrapHost: func(b hostBackend) hostBackend {
			host.hostBackend = b
			return host
		},
	})
	requireStableIDs(t, ws)
	return ws, host
}

// mixedWS opens a workspace on dir whose entries named with the prefix "np",
// and every entry below a directory with such a name, report no file identity.
// They key their records on the guest path, as the entries of a file system
// that the guest mounts inside the workspace do. Every other entry keeps its
// identity.
func mixedWS(t testing.TB, dir string) *Workspace {
	t.Helper()
	ws, _ := mixedWSHost(t, dir)
	return ws
}

// mixedWSHost is mixedWS that also returns the host wrapper.
func mixedWSHost(t testing.TB, dir string) (*Workspace, *identityHost) {
	t.Helper()
	host := &identityHost{nameless: func(name string) bool { return strings.HasPrefix(name, "np") }}
	ws := journalWS(t, dir, workspaceOptions{
		noOrphanGC: true,
		wrapHost: func(b hostBackend) hostBackend {
			host.hostBackend = b
			return host
		},
	})
	return ws, host
}

// plainWS opens a workspace that flushes only at Sync and Close and runs no
// background collector.
func plainWS(t testing.TB, dir string, opts workspaceOptions) *Workspace {
	t.Helper()
	opts.noOrphanGC = true
	return journalWS(t, dir, opts)
}

// requireStableIDs skips the test when the temporary directory volume keys its
// records by path.
func requireStableIDs(t testing.TB, ws *Workspace) {
	t.Helper()
	if ws.pathKeys {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
}

// requireMode fails unless the path has the given permission bits and owner.
func requireMode(t testing.TB, ws *Workspace, rel string, mode, uid uint32) {
	t.Helper()
	attr, _, err := ws.Stat(rel)
	if err != nil {
		t.Fatalf("Stat(%s): %v", rel, err)
	}
	if attr.Mode&0o7777 != mode || attr.UID != uid {
		t.Fatalf("Stat(%s) = mode %o uid %d, want mode %o uid %d", rel, attr.Mode&0o7777, attr.UID, mode, uid)
	}
}

func TestHostRenameOfAFileKeepsItsRecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	mustWriteFile(t, ws, "before", 0o751)
	if err := ws.Chown("before", 7, 8); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "before"), filepath.Join(dir, "after")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "after", 0o751, 7)

	// The record also survives a restart.
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	requireMode(t, reopened, "after", 0o751, 7)
}

func TestHostRenameOfADirectoryKeepsTheRecordsBelowIt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS refuses a host rename of a directory that holds an open handle of hostfs")
	}
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	if err := ws.Mkdir("old", 0o750); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "old/file", 0o640)
	if err := ws.Symlink("target", "old/link"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chown("old/file", 3, 4); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "old/file", 0o640, 3)

	if err := os.Rename(filepath.Join(dir, "old"), filepath.Join(dir, "new")); err != nil {
		t.Fatal(err)
	}
	// The pinned handle of the old directory expires after one second. A
	// fresh workspace opens its handles from the new name.
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	requireMode(t, reopened, "new", 0o750, 0)
	requireMode(t, reopened, "new/file", 0o640, 3)
	if target, err := reopened.Readlink("new/link"); err != nil || target != "target" {
		t.Fatalf("Readlink(new/link) = (%q, %v), want the target of the virtual link that moved with its directory", target, err)
	}
}

func TestNewHostFileAtAnOldPathDoesNotInheritTheRecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	mustWriteFile(t, ws, "name", 0o751)
	if err := ws.Chown("name", 7, 8); err != nil {
		t.Fatal(err)
	}
	// A host process moves the file aside and puts a new file under the name.
	if err := os.Rename(filepath.Join(dir, "name"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "name"), []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if attr, _, err := ws.Stat("name"); err != nil || attr.UID != 0 || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(name) = (%+v, %v), want the defaults of a host file and not the record of the moved file", attr, err)
	}
	requireMode(t, ws, "moved", 0o751, 7)
}

func TestHostEditorSaveByRenameKeepsTheRecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	mustWriteFile(t, ws, "doc", 0o751)
	if err := ws.Chown("doc", 7, 8); err != nil {
		t.Fatal(err)
	}
	// An editor writes a temporary file and renames it over the document.
	if err := os.WriteFile(filepath.Join(dir, "doc.tmp"), []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "doc.tmp"), filepath.Join(dir, "doc")); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "doc", 0o751, 7)

	// The adoption is durable.
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	requireMode(t, plainWS(t, dir, workspaceOptions{}), "doc", 0o751, 7)
}

func TestHostEditorSaveByRenameKeepsExtendedAttributes(t *testing.T) {
	e, _, clock := newCountEnv(t)
	e.writeFile("doc", []byte("v1"))
	e.chmod("doc", 0o751)
	// A Linux host stores user.* attributes on the host file, which the editor
	// replaces. The meta store holds trusted.* attributes on every host.
	e.mustSetXattr("doc", "trusted.tag", "kept")

	if err := os.WriteFile(e.host("doc.tmp"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(e.host("doc.tmp"), e.host("doc")); err != nil {
		t.Fatal(err)
	}
	// The cached lookup of doc stays valid for one second.
	clock.advance(2 * cacheTTL)
	if st := e.mustStat("doc"); st.Mode&0o7777 != 0o751 {
		t.Fatalf("mode of doc after the host save = %o, want 751", st.Mode&0o7777)
	}
	if got := e.mustGetXattr("doc", "trusted.tag"); got != "kept" {
		t.Fatalf("attribute trusted.tag of doc after the host save = %q, want kept", got)
	}
}

func TestSaveByRenameDoesNotStealTheRecordOfAFileThatStillExists(t *testing.T) {
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	mustWriteFile(t, ws, "a", 0o751)
	// The host renames a to b, and a stranger file takes the name a.
	if err := os.Rename(filepath.Join(dir, "a"), filepath.Join(dir, "b")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a"), []byte("other"), 0o640); err != nil {
		t.Fatal(err)
	}
	if attr, _, err := ws.Stat("a"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(a) = (%+v, %v): the new file took the record of b", attr, err)
	}
	requireMode(t, ws, "b", 0o751, 0)
	// The answer stays the same on the next look.
	if attr, _, err := ws.Stat("a"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("second Stat(a) = (%+v, %v): the new file took the record of b", attr, err)
	}
}

func TestReusedInodeNumberDoesNotInheritARecord(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, host := identityWS(t, dir)
	mustWriteFile(t, ws, "recorded", 0o751)
	recorded, err := ws.host.lstat("recorded")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fresh"), []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	fresh, err := ws.host.lstat("fresh")
	if err != nil {
		t.Fatal(err)
	}

	// The host reports the inode number of the recorded file for the new file,
	// with a later birth time, as ext4 does after a delete and a create.
	host.set(func(info hostInfo) hostInfo {
		if info.fid == fresh.fid {
			info.fid = recorded.fid
			info.fid.btime++
		}
		return info
	})
	if attr, _, err := ws.Stat("fresh"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(fresh) = (%+v, %v): a new file that reuses an inode number inherited the record", attr, err)
	}

	// The same birth time makes the same key, so the record applies. The birth
	// time is what separates the two files.
	host.set(func(info hostInfo) hostInfo {
		if info.fid == fresh.fid {
			info.fid = recorded.fid
		}
		return info
	})
	if attr, _, err := ws.Stat("fresh"); err != nil || attr.Mode&0o7777 != 0o751 {
		t.Fatalf("Stat(fresh) with the identity of the recorded file = (%+v, %v), want mode 751", attr, err)
	}
}

// A file system can give the inode number of a deleted file to a new file. The
// listing then shows the number of the recorded file, and only the birth time
// tells the two files apart.
func TestListedInodeNumberOfAReplacedFileDoesNotKeepTheRecordAlive(t *testing.T) {
	if !keysCarryBirthTime {
		t.Skip("the key holds no birth time here, and the inode number of a deleted file is never reused")
	}
	dir := resolvedTempDir(t)
	ws, host := identityWS(t, dir)
	if ws.caps.ExistsByID {
		t.Skip("the host asks by identity and lists nothing")
	}
	mustWriteFile(t, ws, "doc", 0o751)
	if err := ws.Chown("doc", 7, 8); err != nil {
		t.Fatal(err)
	}
	recorded, err := ws.host.lstat("doc")
	if err != nil {
		t.Fatal(err)
	}
	// An editor saves over doc.
	if err := os.WriteFile(filepath.Join(dir, "doc.tmp"), []byte("saved"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "doc.tmp"), filepath.Join(dir, "doc")); err != nil {
		t.Fatal(err)
	}
	fresh, err := ws.host.lstat("doc")
	if err != nil {
		t.Fatal(err)
	}
	// The new file reuses the inode number of the recorded file.
	reused := recorded.fid
	reused.btime++
	host.set(func(info hostInfo) hostInfo {
		if info.fid == fresh.fid {
			info.fid = reused
		}
		return info
	})
	host.mu.Lock()
	host.rewriteList = func(e hostDirEntry) hostDirEntry {
		if e.name == "doc" {
			e.ino = recorded.fid.ino
		}
		return e
	}
	host.mu.Unlock()
	requireMode(t, ws, "doc", 0o751, 7)
}

func TestListedFileWithTheIdentityOfTheRecordKeepsTheRecordAlive(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, _ := identityWS(t, dir)
	if ws.caps.ExistsByID {
		t.Skip("the host asks by identity and lists nothing")
	}
	mustWriteFile(t, ws, "doc", 0o751)
	// The recorded file moves to another name of its directory, and a new file
	// takes the name doc. The listing shows the recorded file with its full
	// identity.
	if err := os.Rename(filepath.Join(dir, "doc"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc"), []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	if attr, _, err := ws.Stat("doc"); err != nil || attr.Mode&0o7777 == 0o751 {
		t.Fatalf("Stat(doc) = (%+v, %v): the new file took the record of the moved file", attr, err)
	}
	requireMode(t, ws, "moved", 0o751, 0)
}

func TestVolumeWithoutFileIdentitiesKeepsRecordsByPath(t *testing.T) {
	dir := resolvedTempDir(t)
	host := &identityHost{}
	host.set(func(info hostInfo) hostInfo {
		info.fidOK = false
		return info
	})
	ws := journalWS(t, dir, workspaceOptions{noOrphanGC: true, wrapHost: func(b hostBackend) hostBackend {
		host.hostBackend = b
		return host
	}})
	if ws.Caps().StableIDs {
		t.Fatal("Caps().StableIDs = true for a volume whose files report no usable identity")
	}
	mustWriteFile(t, ws, "name", 0o751)
	if err := ws.Chown("name", 7, 8); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "name"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "name"), []byte("new"), 0o640); err != nil {
		t.Fatal(err)
	}
	// The records stay as earlier releases kept them: by path.
	requireMode(t, ws, "name", 0o751, 7)
	if attr, _, err := ws.Stat("moved"); err != nil || attr.UID != 0 {
		t.Fatalf("Stat(moved) = (%+v, %v), want the defaults of a host file", attr, err)
	}
}

func TestVolumeWithIdentitiesReportsStableIDs(t *testing.T) {
	ws := plainWS(t, resolvedTempDir(t), workspaceOptions{})
	if !ws.Caps().StableIDs {
		t.Skip("the volume of the temporary directory has no usable file identities")
	}
	if ws.pathKeys {
		t.Fatal("a volume with stable identities keys its records by path")
	}
}

func TestPathKeysMoveRecordsWithADirectoryRename(t *testing.T) {
	ws := plainWS(t, resolvedTempDir(t), workspaceOptions{pathKeys: true})
	if err := ws.Mkdir("d", 0o750); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o640)
	if err := ws.Symlink("t", "d/l"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "e", 0o750, 0)
	requireMode(t, ws, "e/f", 0o640, 0)
	if target, err := ws.Readlink("e/l"); err != nil || target != "t" {
		t.Fatalf("Readlink(e/l) = (%q, %v), want the virtual link below the renamed directory", target, err)
	}
}

func TestPathKeysShareAHardLinkChangeWithEveryName(t *testing.T) {
	ws := plainWS(t, resolvedTempDir(t), workspaceOptions{pathKeys: true})
	mustWriteFile(t, ws, "a", 0o644)
	if err := ws.link("a", "b"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chmod("a", 0o600); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "b", 0o600, 0)
}

func TestSettingAnEarlierModificationTimeKeepsTheRecord(t *testing.T) {
	// APFS lowers the birth time of a file when a process sets an earlier
	// modification time, as tar, cp -p, and git do. The identity of the file
	// must not follow the birth time there.
	past := time.Date(2020, 1, 2, 3, 4, 5, 0, time.UTC)
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	mustWriteFile(t, ws, "guest", 0o751)
	mustWriteFile(t, ws, "host", 0o750)
	if err := ws.chtimes("guest", &past, &past); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(dir, "host"), past, past); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "guest", 0o751, 0)
	requireMode(t, ws, "host", 0o750, 0)

	// The record also survives a restart and a pass of the collector.
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	for range 3 {
		reopened.orphanPass()
	}
	requireMode(t, reopened, "guest", 0o751, 0)
	requireMode(t, reopened, "host", 0o750, 0)
}

func TestHardLinkChangeShowsThroughEveryName(t *testing.T) {
	ws := plainWS(t, resolvedTempDir(t), workspaceOptions{})
	mustWriteFile(t, ws, "a", 0o644)
	for _, name := range []string{"b", "c"} {
		if err := ws.link("a", name); err != nil {
			t.Fatal(err)
		}
	}
	if err := ws.Chmod("b", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chown("c", 9, 10); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "b", "c"} {
		attr, _, err := ws.Stat(name)
		if err != nil || attr.Mode&0o7777 != 0o600 || attr.UID != 9 || attr.GID != 10 {
			t.Fatalf("Stat(%s) = (%+v, %v), want mode 600 and owner 9:10 through every name", name, attr, err)
		}
	}
	// The record lives as long as one name does.
	if err := ws.Unlink("a"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Unlink("b"); err != nil {
		t.Fatal(err)
	}
	requireMode(t, ws, "c", 0o600, 9)
}

// metaScans returns the number of whole-table operations so far.
func metaScans(ws *Workspace) int64 {
	return ws.meta.scans.Load()
}

func TestGuestCallsNeverScanTheTable(t *testing.T) {
	ws := plainWS(t, resolvedTempDir(t), workspaceOptions{})
	if ws.pathKeys {
		t.Skip("a volume without file identities pays the scans")
	}
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	for i := range 20 {
		mustWriteFile(t, ws, fmt.Sprintf("d/f%d", i), 0o644)
	}
	if err := ws.Symlink("t", "d/link"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "a", 0o644)
	if err := ws.link("a", "b"); err != nil {
		t.Fatal(err)
	}

	before := metaScans(ws)
	if _, err := ws.listDir("d"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chmod("a", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ws.Chown("b", 1, 2); err != nil {
		t.Fatal(err)
	}
	if err := ws.Rename("e/f3", "e/g3"); err != nil {
		t.Fatal(err)
	}
	if err := ws.Unlink("e/f4"); err != nil {
		t.Fatal(err)
	}
	if got := metaScans(ws) - before; got != 0 {
		t.Fatalf("a listing, a directory rename, hard link changes, a rename, and an unlink scanned the table %d times, want 0", got)
	}
}

func journalOps(t testing.TB, path string) int {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	img, err := parseMeta(raw)
	if err != nil {
		t.Fatal(err)
	}
	return img.ops
}

func TestDirectoryRenameCostDoesNotGrowWithItsSubtree(t *testing.T) {
	// File keys and timestamps use varints, so two separate host directories
	// can differ by a few bytes for one appended record.
	const maxSingleRecordBytes = 200
	const maxVarintDiff = 16
	cost := func(children int) (calls int, opsAdded int, journalGrowth int64) {
		dir := resolvedTempDir(t)
		ch := &countingHost{}
		ws := plainWS(t, dir, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		}})
		requireStableIDs(t, ws)
		if err := ws.Mkdir("d", 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range children {
			mustWriteFile(t, ws, fmt.Sprintf("d/f%d", i), 0o644)
		}
		mustSync(t, ws)
		path := filepath.Join(dir, MetaFileName)
		beforeBytes := fileSize(t, path)
		beforeOps := journalOps(t, path)
		ch.reset()
		if err := ws.Rename("d", "e"); err != nil {
			t.Fatal(err)
		}
		calls = ch.total()
		mustSync(t, ws)
		return calls, journalOps(t, path) - beforeOps, fileSize(t, path) - beforeBytes
	}
	smallCalls, smallOps, smallGrowth := cost(3)
	largeCalls, largeOps, largeGrowth := cost(300)
	if largeCalls != smallCalls {
		t.Errorf("renaming a directory with 300 children made %d host calls, and with 3 children %d, want equal", largeCalls, smallCalls)
	}
	if smallOps != 1 || largeOps != 1 {
		t.Errorf("renaming a directory appended %d ops (3 children) and %d ops (300 children), want 1 each", smallOps, largeOps)
	}
	if smallGrowth <= 0 || smallGrowth > maxSingleRecordBytes || largeGrowth <= 0 || largeGrowth > maxSingleRecordBytes {
		t.Errorf("renaming a directory grew .gvx_meta by %d bytes (3 children) and %d bytes (300 children), want 1..%d each", smallGrowth, largeGrowth, maxSingleRecordBytes)
	}
	diff := largeGrowth - smallGrowth
	if diff < 0 {
		diff = -diff
	}
	if diff > maxVarintDiff {
		t.Errorf("renaming a directory with 300 children grew .gvx_meta by %d bytes, and with 3 children by %d, diff %d exceeds varint bound %d", largeGrowth, smallGrowth, diff, maxVarintDiff)
	}
}

func TestHardLinkChangeCostDoesNotGrowWithTheTable(t *testing.T) {
	cost := func(records int) int {
		ch := &countingHost{}
		ws := plainWS(t, resolvedTempDir(t), workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		}})
		requireStableIDs(t, ws)
		mustWriteFile(t, ws, "a", 0o644)
		for _, name := range []string{"b", "c", "d"} {
			if err := ws.link("a", name); err != nil {
				t.Fatal(err)
			}
		}
		for i := range records {
			mustWriteFile(t, ws, fmt.Sprintf("other%d", i), 0o644)
		}
		ch.reset()
		if err := ws.Chmod("b", 0o600); err != nil {
			t.Fatal(err)
		}
		return ch.total()
	}
	if small, large := cost(5), cost(500); small != large {
		t.Fatalf("chmod of a hard link made %d host calls beside 500 records and %d beside 5, want equal", large, small)
	}
}

func TestListingCostDoesNotGrowWithTheTable(t *testing.T) {
	cost := func(records int) int {
		ch := &countingHost{}
		ws := plainWS(t, resolvedTempDir(t), workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		}})
		if err := ws.Mkdir("listed", 0o755); err != nil {
			t.Fatal(err)
		}
		mustWriteFile(t, ws, "listed/f", 0o644)
		if err := ws.Symlink("t", "listed/l"); err != nil {
			t.Fatal(err)
		}
		if err := ws.Mkdir("elsewhere", 0o755); err != nil {
			t.Fatal(err)
		}
		for i := range records {
			mustWriteFile(t, ws, fmt.Sprintf("elsewhere/f%d", i), 0o644)
		}
		// The first listing warms the pinned handle of the directory.
		if _, err := ws.listDir("listed"); err != nil {
			t.Fatal(err)
		}
		ch.reset()
		entries, err := ws.listDir("listed")
		if err != nil || len(entries) != 2 {
			t.Fatalf("listDir = (%v, %v), want the file and the virtual link", entries, err)
		}
		return ch.total()
	}
	if small, large := cost(5), cost(500); small != large {
		t.Fatalf("a listing made %d host calls beside 500 records and %d beside 5, want equal", large, small)
	}
}

func TestOpenMakesNoHostCallForEachRecord(t *testing.T) {
	cost := func(records int) int {
		dir := resolvedTempDir(t)
		ws := plainWS(t, dir, workspaceOptions{})
		for i := range records {
			mustWriteFile(t, ws, fmt.Sprintf("f%d", i), 0o644)
		}
		mustSync(t, ws)
		if err := ws.Close(); err != nil {
			t.Fatal(err)
		}
		ch := &countingHost{}
		reopened := plainWS(t, dir, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		}})
		_ = reopened
		return ch.total()
	}
	if small, large := cost(3), cost(300); small != large {
		t.Fatalf("opening a workspace with 300 records made %d host calls, and with 3 records %d, want equal: no check of the records", large, small)
	}
}

func TestVirtualLinkSurvivesAHostRenameOfItsDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS refuses a host rename of a directory that holds an open handle of hostfs")
	}
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	if err := ws.Mkdir("d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := ws.Symlink("target", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "d"), filepath.Join(dir, "e")); err != nil {
		t.Fatal(err)
	}
	reopened := plainWS(t, dir, workspaceOptions{})
	if target, err := reopened.Readlink("e/l"); err != nil || target != "target" {
		t.Fatalf("Readlink(e/l) = (%q, %v), want the link to follow its directory", target, err)
	}
	if _, err := reopened.Readlink("d/l"); err == nil {
		t.Fatal("Readlink(d/l) succeeded after the directory moved away")
	}
}

func TestReadMetaNamesRecordsByTheCurrentPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("NTFS refuses a host rename of a directory that holds an open handle of hostfs")
	}
	dir := resolvedTempDir(t)
	ws := plainWS(t, dir, workspaceOptions{})
	requireStableIDs(t, ws)
	if err := ws.Mkdir("d", 0o750); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "d/f", 0o640)
	if err := ws.Symlink("t", "d/l"); err != nil {
		t.Fatal(err)
	}
	mustWriteFile(t, ws, "gone", 0o600)
	mustSync(t, ws)
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "d"), filepath.Join(dir, "e")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(dir, "gone")); err != nil {
		t.Fatal(err)
	}
	table := readMetaTable(t, filepath.Join(dir, MetaFileName))
	if table["e"].Mode&linux.S_IFMT != linux.S_IFDIR || table["e/f"].Mode&0o7777 != 0o640 || table["e/l"].Symlink != "t" {
		t.Fatalf("table = %v, want the records of the renamed directory under its new name", table)
	}
	for _, stale := range []string{"d", "d/f", "d/l", "gone"} {
		if _, ok := table[stale]; ok {
			t.Errorf("table holds %q, which names no entry on the host", stale)
		}
	}
}
