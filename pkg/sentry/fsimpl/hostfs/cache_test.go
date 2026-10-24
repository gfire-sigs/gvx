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
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// countingHost wraps a host backend and counts every call that reaches it.
// The case flags override the answers of the wrapped backend when set.
type countingHost struct {
	hostBackend

	mu    sync.Mutex
	calls map[string]int

	insensitive *bool
	verified    *bool
}

func (c *countingHost) count(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.calls == nil {
		c.calls = make(map[string]int)
	}
	c.calls[name]++
}

// reset forgets the calls so far.
func (c *countingHost) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
}

func (c *countingHost) got(name string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[name]
}

func (c *countingHost) total() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, v := range c.calls {
		n += v
	}
	return n
}

// dump lists the counted calls for a failure message.
func (c *countingHost) dump() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var parts []string
	for k, v := range c.calls {
		parts = append(parts, fmt.Sprintf("%s=%d", k, v))
	}
	sort.Strings(parts)
	return "[" + strings.Join(parts, " ") + "]"
}

func (c *countingHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	c.count("open")
	return c.hostBackend.open(rel, flags, perm)
}

func (c *countingHost) openDir(rel string) (*os.File, error) {
	c.count("openDir")
	return c.hostBackend.openDir(rel)
}

func (c *countingHost) lstat(rel string) (hostInfo, error) {
	c.count("lstat")
	return c.hostBackend.lstat(rel)
}

func (c *countingHost) fstat(f *os.File) (hostInfo, error) {
	c.count("fstat")
	return c.hostBackend.fstat(f)
}

func (c *countingHost) mkdir(rel string) error {
	c.count("mkdir")
	return c.hostBackend.mkdir(rel)
}

func (c *countingHost) unlink(rel string) error {
	c.count("unlink")
	return c.hostBackend.unlink(rel)
}

func (c *countingHost) rmdir(rel string) error {
	c.count("rmdir")
	return c.hostBackend.rmdir(rel)
}

func (c *countingHost) rename(oldRel, newRel string) error {
	c.count("rename")
	return c.hostBackend.rename(oldRel, newRel)
}

func (c *countingHost) link(oldRel, newRel string) error {
	c.count("link")
	return c.hostBackend.link(oldRel, newRel)
}

func (c *countingHost) readlink(rel string) (string, error) {
	c.count("readlink")
	return c.hostBackend.readlink(rel)
}

func (c *countingHost) readDir(rel string) ([]hostDirEntry, error) {
	c.count("readDir")
	return c.hostBackend.readDir(rel)
}

func (c *countingHost) syncDir(rel string) error {
	c.count("syncDir")
	return c.hostBackend.syncDir(rel)
}

func (c *countingHost) chtimes(rel string, atime, mtime *time.Time) error {
	c.count("chtimes")
	return c.hostBackend.chtimes(rel, atime, mtime)
}

func (c *countingHost) caseInsensitive() bool {
	if c.insensitive != nil {
		return *c.insensitive
	}
	return c.hostBackend.caseInsensitive()
}

func (c *countingHost) caseVerified() bool {
	if c.verified != nil {
		return *c.verified
	}
	return c.hostBackend.caseVerified()
}

func (c *countingHost) openDirAt(dir hostDirHandle, name string) (hostDirHandle, hostInfo, error) {
	c.count("openDirAt")
	return c.hostBackend.openDirAt(dir, name)
}

func (c *countingHost) closeDir(dir hostDirHandle) error {
	c.count("closeDir")
	return c.hostBackend.closeDir(dir)
}

func (c *countingHost) fstatDir(dir hostDirHandle) (hostInfo, error) {
	c.count("fstatDir")
	return c.hostBackend.fstatDir(dir)
}

func (c *countingHost) lstatAt(dir hostDirHandle, name string) (hostInfo, error) {
	c.count("lstatAt")
	return c.hostBackend.lstatAt(dir, name)
}

func (c *countingHost) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	c.count("openChildAt")
	return c.hostBackend.openChildAt(dir, name, flags, perm)
}

// testClock is the monotonic clock of the cache expiry in tests.
type testClock struct {
	ns atomic.Int64
}

func (c *testClock) now() int64 {
	return c.ns.Load()
}

func (c *testClock) advance(d time.Duration) {
	c.ns.Add(int64(d))
}

// newCountEnv mounts a workspace whose host backend counts calls and whose
// clock only moves when the test advances it.
func newCountEnv(t *testing.T) (*env, *countingHost, *testClock) {
	t.Helper()
	ch := &countingHost{}
	clock := &testClock{}
	clock.ns.Store(int64(time.Hour))
	e := newEnvOpts(t, workspaceOptions{
		coalesce: defaultCoalesceWindow,
		clock:    clock.now,
		wrapHost: func(b hostBackend) hostBackend {
			ch.hostBackend = b
			return ch
		},
	})
	return e, ch, clock
}

// pinCount reports the number of pinned directory handles.
func (w *Workspace) pinCount() int {
	w.pinMu.Lock()
	defer w.pinMu.Unlock()
	return len(w.pins)
}

const deepPath = "a/b/c/d/f.c"

// makeDeepFile creates deepPath and warms every cache that a later lookup of
// the path uses.
func makeDeepFile(t *testing.T, e *env) {
	t.Helper()
	for _, d := range []string{"a", "a/b", "a/b/c", "a/b/c/d"} {
		e.mustMkdir(d)
	}
	e.writeFile(deepPath, []byte("x"))
	// The creation invalidated the metadata of the directory and the file.
	e.mustStat(deepPath)
}

func TestWarmLookupOfDeepPathMakesNoHostCalls(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	makeDeepFile(t, e)

	ch.reset()
	e.mustStat(deepPath)
	if n := ch.total(); n != 0 {
		t.Fatalf("warm stat of %s made %d host calls %s, want 0", deepPath, n, ch.dump())
	}
	ch.reset()
	e.mustStat(deepPath)
	e.mustStat("a/b/c")
	e.mustStat("a")
	if n := ch.total(); n != 0 {
		t.Fatalf("repeated warm stats made %d host calls %s, want 0", n, ch.dump())
	}
}

func TestWarmOpenOfDeepPathMakesOneHostCall(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	makeDeepFile(t, e)
	e.mustOpen(deepPath, linux.O_RDONLY).DecRef(e.ctx)

	ch.reset()
	fd := e.mustOpen(deepPath, linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	if n, want := ch.got("openChildAt"), 1; n != want || ch.total() != want {
		t.Fatalf("warm open made host calls %s, want exactly one openChildAt", ch.dump())
	}
	if got := e.readAll(fd); string(got) != "x" {
		t.Fatalf("read = %q, want x", got)
	}
}

func TestUncachedOpenUsesResolvedEntryAndPinnedDirectory(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	makeDeepFile(t, e)
	// A write marks the cached metadata of the file stale.
	e.writeFile(deepPath, []byte("xy"))

	ch.reset()
	fd := e.mustOpen(deepPath, linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	if ch.got("lstatAt") != 1 || ch.got("openChildAt") != 1 {
		t.Fatalf("open of a stale entry made host calls %s, want one lstatAt and one openChildAt", ch.dump())
	}
	// A path walk would show as a path call. The open must make none.
	for _, name := range []string{"lstat", "open", "openDir", "readDir"} {
		if n := ch.got(name); n != 0 {
			t.Fatalf("open made %d %s calls %s, want 0: the open must not walk the path", n, name, ch.dump())
		}
	}
}

func TestMissingNameCostsOneHostCallThenNone(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	makeDeepFile(t, e)
	const missing = "a/b/c/d/missing.h"

	ch.reset()
	_, err := e.stat(missing)
	wantErrno(t, "first stat of a missing name", err, linuxerr.ENOENT)
	if ch.total() != 1 || ch.got("lstatAt") != 1 {
		t.Fatalf("first stat of a missing name made host calls %s, want one lstatAt", ch.dump())
	}
	ch.reset()
	_, err = e.stat(missing)
	wantErrno(t, "second stat of a missing name", err, linuxerr.ENOENT)
	if n := ch.total(); n != 0 {
		t.Fatalf("second stat of a missing name made %d host calls %s, want 0", n, ch.dump())
	}
}

func TestCreationIsVisibleAfterNegativeEntry(t *testing.T) {
	e, _, _ := newCountEnv(t)
	e.mustMkdir("dir")
	e.writeFile("dir/src", []byte("s"))

	creators := map[string]func(name string) error{
		"file": func(name string) error {
			fd, err := e.open(name, linux.O_CREAT|linux.O_WRONLY|linux.O_EXCL, 0o644)
			if err == nil {
				fd.DecRef(e.ctx)
			}
			return err
		},
		"mkdir": e.mkdir,
		"mknod": func(name string) error {
			return e.vfsObj.MknodAt(e.ctx, e.creds, e.pop(name), &vfs.MknodOptions{Mode: linux.S_IFREG | 0o644})
		},
		"symlink": func(name string) error {
			return e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop(name), "src")
		},
		"link":   func(name string) error { return e.link("dir/src", name) },
		"rename": func(name string) error { return e.rename("dir/moving", name) },
	}
	for kind, create := range creators {
		name := "dir/new-" + kind
		if kind == "rename" {
			e.writeFile("dir/moving", []byte("m"))
		}
		_, err := e.stat(name)
		wantErrno(t, kind+": stat before creation", err, linuxerr.ENOENT)
		if err := create(name); err != nil {
			t.Fatalf("%s: create %s: %v", kind, name, err)
		}
		if _, err := e.stat(name); err != nil {
			t.Fatalf("%s: stat after creation: %v, want the new name to be visible", kind, err)
		}
	}
	// The renamed source is gone, and its name is cached as missing.
	_, err := e.stat("dir/moving")
	wantErrno(t, "stat of the renamed source", err, linuxerr.ENOENT)
}

func TestUnlinkAndRecreateStayConsistent(t *testing.T) {
	e, _, _ := newCountEnv(t)
	e.writeFile("f", []byte("one"))
	e.mustStat("f")
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	_, err := e.stat("f")
	wantErrno(t, "stat after unlink", err, linuxerr.ENOENT)
	e.writeFile("f", []byte("three"))
	if st := e.mustStat("f"); st.Size != 5 {
		t.Fatalf("size after recreation = %d, want 5", st.Size)
	}
}

func TestWriteTruncateAndChmodInvalidateCachedMetadata(t *testing.T) {
	e, _, _ := newCountEnv(t)
	e.writeFile("f", []byte("a"))
	if st := e.mustStat("f"); st.Size != 1 {
		t.Fatalf("size = %d, want 1", st.Size)
	}

	fd := e.mustOpen("f", linux.O_WRONLY|linux.O_APPEND)
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("bcd")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	fd.DecRef(e.ctx)
	if st := e.mustStat("f"); st.Size != 4 {
		t.Fatalf("size after write = %d, want 4", st.Size)
	}

	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_SIZE, Size: 2}); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Size != 2 {
		t.Fatalf("size after truncate = %d, want 2", st.Size)
	}

	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Mode&0o7777 != 0o600 {
		t.Fatalf("mode after chmod = %o, want 600", st.Mode&0o7777)
	}

	// A hard link shares the inode, so a write through one name shows through
	// the other name at once.
	if err := e.link("f", "g"); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("g"); st.Nlink != 2 {
		t.Fatalf("link count = %d, want 2", st.Nlink)
	}
	e.writeFile("g", []byte("longer"))
	if st := e.mustStat("f"); st.Size != 6 {
		t.Fatalf("size through the other name = %d, want 6", st.Size)
	}
	if err := e.unlink("g"); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Nlink != 1 {
		t.Fatalf("link count after unlink = %d, want 1", st.Nlink)
	}
}

func TestDirectoryRenameClosesAndReopensPinnedHandles(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	e.writeFile("a/b/f", []byte("payload"))
	e.mustStat("a/b/f")
	pinned := e.ws.pinCount()
	if pinned < 2 {
		t.Fatalf("pinned directory handles = %d, want a and a/b", pinned)
	}

	ch.reset()
	if err := e.rename("a", "z"); err != nil {
		t.Fatalf("rename of a directory with pinned handles: %v", err)
	}
	if got := ch.got("closeDir"); got != pinned {
		t.Fatalf("rename closed %d pinned handles, want %d", got, pinned)
	}
	if got := e.ws.pinCount(); got != 0 {
		t.Fatalf("pinned handles after the rename = %d, want 0", got)
	}

	ch.reset()
	if got := e.readFile("z/b/f"); string(got) != "payload" {
		t.Fatalf("read after rename = %q", got)
	}
	if got := ch.got("openDirAt"); got != 2 {
		t.Fatalf("lookup after the rename reopened %d handles, want 2 (lazy reopen)", got)
	}
	_, err := e.stat("a/b/f")
	wantErrno(t, "stat of the old path", err, linuxerr.ENOENT)
}

func TestRmdirClosesPinnedHandlesOfTheDirectory(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	e.mustMkdir("p")
	e.mustMkdir("p/q")
	// A lookup below p/q pins it.
	_, err := e.stat("p/q/none")
	wantErrno(t, "stat below p/q", err, linuxerr.ENOENT)
	if got := e.ws.pinCount(); got != 2 {
		t.Fatalf("pinned handles = %d, want p and p/q", got)
	}

	ch.reset()
	if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("p/q")); err != nil {
		t.Fatalf("rmdir of a pinned directory: %v", err)
	}
	if got := ch.got("closeDir"); got != 1 {
		t.Fatalf("rmdir closed %d handles, want the one of p/q", got)
	}
	if got := e.ws.pinCount(); got != 1 {
		t.Fatalf("pinned handles after rmdir = %d, want 1", got)
	}
	_, err = e.stat("p/q")
	wantErrno(t, "stat of the removed directory", err, linuxerr.ENOENT)
}

func TestWorkspaceCloseReleasesEveryPinnedHandle(t *testing.T) {
	e, ch, _ := newCountEnv(t)
	makeDeepFile(t, e)
	if e.ws.pinCount() == 0 {
		t.Fatal("no pinned handle after lookups")
	}
	opened := ch.got("openDirAt")

	if err := e.ws.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := ch.got("closeDir"); got != opened {
		t.Fatalf("Close released %d of %d pinned handles", got, opened)
	}
	if got := e.ws.pinCount(); got != 0 {
		t.Fatalf("pinned handles after Close = %d, want 0", got)
	}
	if _, err := e.ws.lookupIn("a", "b"); err == nil {
		t.Fatal("lookupIn on a closed workspace succeeded")
	}
}

func TestIdlePinnedHandlesAreSwept(t *testing.T) {
	e, ch, clock := newCountEnv(t)
	makeDeepFile(t, e)
	opened := ch.got("openDirAt")

	e.ws.sweepPins()
	if got := ch.got("closeDir"); got != 0 {
		t.Fatalf("sweep closed %d handles that were in use a moment ago", got)
	}
	clock.advance(pinIdleTime)
	e.ws.sweepPins()
	if got := ch.got("closeDir"); got != opened {
		t.Fatalf("sweep closed %d of %d idle handles", got, opened)
	}
	if got := e.ws.pinCount(); got != 0 {
		t.Fatalf("pinned handles after the sweep = %d, want 0", got)
	}
	// A later lookup reopens what it needs.
	clock.advance(cacheTTL)
	e.mustStat(deepPath)
}

func TestPinnedHandlesAreBounded(t *testing.T) {
	e, _, _ := newCountEnv(t)
	for i := range maxDirPins + 20 {
		d := fmt.Sprintf("d%d", i)
		e.mustMkdir(d)
		// A lookup below the directory pins it.
		if _, err := e.stat(d + "/x"); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat %s/x = %v, want ENOENT", d, err)
		}
	}
	if got := e.ws.pinCount(); got > maxDirPins {
		t.Fatalf("pinned handles = %d, want at most %d", got, maxDirPins)
	}
}

func TestHostChangesBecomeVisibleAfterTheCacheLifetime(t *testing.T) {
	e, _, clock := newCountEnv(t)
	e.writeFile("grow", []byte("one"))
	e.mustStat("grow")
	_, err := e.stat("late")
	wantErrno(t, "stat of a name that does not exist yet", err, linuxerr.ENOENT)

	if err := os.WriteFile(e.host("grow"), []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.host("late"), []byte("l"), 0o600); err != nil {
		t.Fatal(err)
	}

	clock.advance(cacheTTL + time.Millisecond)
	if st := e.mustStat("grow"); st.Size != 14 {
		t.Fatalf("size after the cache lifetime = %d, want 14", st.Size)
	}
	if _, err := e.stat("late"); err != nil {
		t.Fatalf("stat of a host-created name after the cache lifetime: %v", err)
	}
}

func TestListingRevalidatesCachedEntries(t *testing.T) {
	e, _, _ := newCountEnv(t)
	e.writeFile("grow", []byte("one"))
	e.mustStat("grow")
	_, err := e.stat("late")
	wantErrno(t, "stat of a name that does not exist yet", err, linuxerr.ENOENT)

	if err := os.WriteFile(e.host("grow"), []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.host("late"), []byte("l"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The clock does not move: only the listing can reveal the changes.
	e.readdir(".")
	if st := e.mustStat("grow"); st.Size != 14 {
		t.Fatalf("size after a listing = %d, want 14", st.Size)
	}
	if _, err := e.stat("late"); err != nil {
		t.Fatalf("stat of a host-created name after a listing: %v", err)
	}
}

func TestExistingNameCreatedOnTheHostIsOpenedNotRefused(t *testing.T) {
	e, _, _ := newCountEnv(t)
	_, err := e.stat("late")
	wantErrno(t, "stat before the host creates the name", err, linuxerr.ENOENT)
	if err := os.WriteFile(e.host("late"), []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The negative entry is stale. A create without O_EXCL must open the file.
	fd, err := e.open("late", linux.O_CREAT|linux.O_RDONLY, 0o644)
	if err != nil {
		t.Fatalf("open with O_CREAT of a host-created name: %v", err)
	}
	defer fd.DecRef(e.ctx)
	if got := e.readAll(fd); string(got) != "host" {
		t.Fatalf("read = %q, want host", got)
	}
	// With O_EXCL the name exists, so the call fails.
	_, err = e.open("late", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
	wantErrno(t, "O_EXCL of an existing name", err, linuxerr.EEXIST)
}

func TestBackendThatVerifiesCaseSkipsTheListing(t *testing.T) {
	yes, no := true, false
	run := func(t *testing.T, verified bool) *countingHost {
		e, ch, _ := newCountEnv(t)
		ch.insensitive = &yes
		if verified {
			ch.verified = &yes
		} else {
			ch.verified = &no
		}
		e.mustMkdir("dir")
		e.writeFile("dir/f", []byte("x"))
		ch.reset()
		e.mustStat("dir/f")
		e.mustStat("dir")
		return ch
	}
	if ch := run(t, true); ch.got("readDir") != 0 || ch.got("fstatDir") != 0 {
		t.Fatalf("a backend that verifies case still listed or stat the directory %s", ch.dump())
	}
	if ch := run(t, false); ch.got("readDir") == 0 {
		t.Fatalf("a case-insensitive backend without verification never listed the directory %s", ch.dump())
	}
}

func TestDirectoryListingFollowsMutationsInPlace(t *testing.T) {
	yes, no := true, false
	e, ch, _ := newCountEnv(t)
	ch.insensitive, ch.verified = &yes, &no
	// OpenWorkspace lists the root once to sweep the internal files of a
	// killed process. The count below starts after that call.
	ch.reset()
	e.mustMkdir("dir")
	e.writeFile("dir/first", []byte("1"))
	// The first lookup of an existing name lists the workspace root for the
	// name dir, and lists dir for the name first.
	e.mustStat("dir/first")
	if got := ch.got("readDir"); got != 2 {
		t.Fatalf("first lookups listed directories %d times, want 2", got)
	}

	ch.reset()
	for i := range 20 {
		name := fmt.Sprintf("dir/f%d", i)
		e.writeFile(name, []byte("x"))
		e.mustStat(name)
		if i%3 == 0 {
			moved := fmt.Sprintf("dir/g%d", i)
			if err := e.rename(name, moved); err != nil {
				t.Fatal(err)
			}
			e.mustStat(moved)
			if _, err := e.stat(name); !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Fatalf("stat of the renamed source %s = %v, want ENOENT", name, err)
			}
		}
		if i%5 == 0 {
			if err := e.unlink(name); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Fatal(err)
			}
		}
	}
	if got := ch.got("readDir"); got != 0 {
		t.Fatalf("single-entry mutations caused %d directory listings, want 0", got)
	}

	// A directory rename moves a whole subtree of listings.
	e.mustMkdir("dir/sub")
	e.writeFile("dir/sub/x", []byte("x"))
	e.mustStat("dir/sub/x")
	if err := e.rename("dir/sub", "dir/sub2"); err != nil {
		t.Fatal(err)
	}
	e.mustStat("dir/sub2/x")
	_, err := e.stat("dir/sub/x")
	wantErrno(t, "stat below the old directory name", err, linuxerr.ENOENT)
}

func TestCaseRulesHoldAcrossMutationsOnFoldingHost(t *testing.T) {
	e, _, _ := newCountEnv(t)
	if !e.ws.host.caseInsensitive() && !hostFoldsCase(t, e.dir) {
		t.Skip("the host file system is case-sensitive")
	}
	e.writeFile("File", []byte("x"))
	e.mustStat("File")
	_, err := e.stat("file")
	wantErrno(t, "stat with another case", err, linuxerr.ENOENT)

	if err := e.rename("File", "other"); err != nil {
		t.Fatal(err)
	}
	_, err = e.stat("File")
	wantErrno(t, "stat of the old name", err, linuxerr.ENOENT)
	e.mustStat("other")

	// The host now stores "other", and a creation under the old name with
	// another case must produce that exact name.
	e.writeFile("file", []byte("y"))
	e.mustStat("file")
	_, err = e.stat("File")
	wantErrno(t, "stat with the case of the removed name", err, linuxerr.ENOENT)
	if got := e.readdir("."); fmt.Sprint(got) != "[file other]" {
		t.Fatalf("listing = %v, want [file other]", got)
	}
}
