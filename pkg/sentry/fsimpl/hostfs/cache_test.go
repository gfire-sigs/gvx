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

package hostfs_test

import (
	"fmt"
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

const deepPath = "a/b/c/d/f.c"

// makeDeepFile creates deepPath and warms every cache that a later lookup of
// the path uses.
func makeDeepFile(t *testing.T, e *hostfs.TestEnv) {
	t.Helper()
	for _, d := range []string{"a", "a/b", "a/b/c", "a/b/c/d"} {
		e.MustMkdir(d)
	}
	e.WriteFile(deepPath, []byte("x"))
	// The creation invalidated the metadata of the directory and the file.
	e.MustStat(deepPath)
	// On a host that does not count directory links, the first stat of a
	// directory lists it once (dirlinks.go).
	for _, d := range []string{"a", "a/b", "a/b/c", "a/b/c/d"} {
		e.MustStat(d)
	}
}

func TestWarmLookupOfDeepPathMakesNoHostCalls(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)

	ch.Reset()
	e.MustStat(deepPath)
	if n := ch.Total(); n != 0 {
		t.Fatalf("warm stat of %s made %d host calls %s, want 0", deepPath, n, ch.Dump())
	}
	ch.Reset()
	e.MustStat(deepPath)
	e.MustStat("a/b/c")
	e.MustStat("a")
	if n := ch.Total(); n != 0 {
		t.Fatalf("repeated warm stats made %d host calls %s, want 0", n, ch.Dump())
	}
}

func TestWarmOpenOfDeepPathMakesOneHostCall(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)
	e.MustOpen(deepPath, linux.O_RDONLY).DecRef(e.Ctx())

	ch.Reset()
	fd := e.MustOpen(deepPath, linux.O_RDONLY)
	defer fd.DecRef(e.Ctx())
	if n, want := ch.Got("openChildAt"), 1; n != want || ch.Total() != want {
		t.Fatalf("warm open made host calls %s, want exactly one openChildAt", ch.Dump())
	}
	if got := e.ReadAll(fd); string(got) != "x" {
		t.Fatalf("read = %q, want x", got)
	}
}

func TestUncachedOpenUsesResolvedEntryAndPinnedDirectory(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)
	// A write marks the cached metadata of the file stale.
	e.WriteFile(deepPath, []byte("xy"))

	ch.Reset()
	fd := e.MustOpen(deepPath, linux.O_RDONLY)
	defer fd.DecRef(e.Ctx())
	if ch.Got("lstatAt") != 1 || ch.Got("openChildAt") != 1 {
		t.Fatalf("open of a stale entry made host calls %s, want one lstatAt and one openChildAt", ch.Dump())
	}
	// A path walk would show as a path call. The open must make none.
	for name := range hostfs.PathCallsForTest {
		if n := ch.Got(name); n != 0 {
			t.Fatalf("open made %d %s calls %s, want 0: the open must not walk the path", n, name, ch.Dump())
		}
	}
}

func TestMissingNameCostsOneHostCallThenNone(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)
	const missing = "a/b/c/d/missing.h"

	ch.Reset()
	_, err := e.Stat(missing)
	hostfs.WantErrnoForTest(t, "first stat of a missing name", err, linuxerr.ENOENT)
	if ch.Total() != 1 || ch.Got("lstatAt") != 1 {
		t.Fatalf("first stat of a missing name made host calls %s, want one lstatAt", ch.Dump())
	}
	ch.Reset()
	_, err = e.Stat(missing)
	hostfs.WantErrnoForTest(t, "second stat of a missing name", err, linuxerr.ENOENT)
	if n := ch.Total(); n != 0 {
		t.Fatalf("second stat of a missing name made %d host calls %s, want 0", n, ch.Dump())
	}
}

func TestCreationIsVisibleAfterNegativeEntry(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	e.MustMkdir("dir")
	e.WriteFile("dir/src", []byte("s"))

	creators := map[string]func(name string) error{
		"file": func(name string) error {
			fd, err := e.Open(name, linux.O_CREAT|linux.O_WRONLY|linux.O_EXCL, 0o644)
			if err == nil {
				fd.DecRef(e.Ctx())
			}
			return err
		},
		"mkdir": e.Mkdir,
		"mknod": func(name string) error {
			return e.Mknod(name, linux.S_IFREG|0o644)
		},
		"symlink": func(name string) error {
			return e.Symlink(name, "src")
		},
		"link":   func(name string) error { return e.Link("dir/src", name) },
		"rename": func(name string) error { return e.Rename("dir/moving", name) },
	}
	for kind, create := range creators {
		name := "dir/new-" + kind
		if kind == "rename" {
			e.WriteFile("dir/moving", []byte("m"))
		}
		_, err := e.Stat(name)
		hostfs.WantErrnoForTest(t, kind+": stat before creation", err, linuxerr.ENOENT)
		if err := create(name); err != nil {
			t.Fatalf("%s: create %s: %v", kind, name, err)
		}
		if _, err := e.Stat(name); err != nil {
			t.Fatalf("%s: stat after creation: %v, want the new name to be visible", kind, err)
		}
	}
	// The renamed source is gone, and its name is cached as missing.
	_, err := e.Stat("dir/moving")
	hostfs.WantErrnoForTest(t, "stat of the renamed source", err, linuxerr.ENOENT)
}

func TestUnlinkAndRecreateStayConsistent(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	e.WriteFile("f", []byte("one"))
	e.MustStat("f")
	if err := e.Unlink("f"); err != nil {
		t.Fatal(err)
	}
	_, err := e.Stat("f")
	hostfs.WantErrnoForTest(t, "stat after unlink", err, linuxerr.ENOENT)
	e.WriteFile("f", []byte("three"))
	if st := e.MustStat("f"); st.Size != 5 {
		t.Fatalf("size after recreation = %d, want 5", st.Size)
	}
}

func TestWriteTruncateAndChmodInvalidateCachedMetadata(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	e.WriteFile("f", []byte("a"))
	if st := e.MustStat("f"); st.Size != 1 {
		t.Fatalf("size = %d, want 1", st.Size)
	}

	fd := e.MustOpen("f", linux.O_WRONLY|linux.O_APPEND)
	if _, err := fd.Write(e.Ctx(), usermem.BytesIOSequence([]byte("bcd")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	fd.DecRef(e.Ctx())
	if st := e.MustStat("f"); st.Size != 4 {
		t.Fatalf("size after write = %d, want 4", st.Size)
	}

	if err := e.SetStat("f", linux.Statx{Mask: linux.STATX_SIZE, Size: 2}); err != nil {
		t.Fatal(err)
	}
	if st := e.MustStat("f"); st.Size != 2 {
		t.Fatalf("size after truncate = %d, want 2", st.Size)
	}

	if err := e.SetStat("f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if st := e.MustStat("f"); st.Mode&0o7777 != 0o600 {
		t.Fatalf("mode after chmod = %o, want 600", st.Mode&0o7777)
	}

	// A hard link shares the inode, so a write through one name shows through
	// the other name at once.
	if err := e.Link("f", "g"); err != nil {
		t.Fatal(err)
	}
	if st := e.MustStat("g"); st.Nlink != 2 {
		t.Fatalf("link count = %d, want 2", st.Nlink)
	}
	e.WriteFile("g", []byte("longer"))
	if st := e.MustStat("f"); st.Size != 6 {
		t.Fatalf("size through the other name = %d, want 6", st.Size)
	}
	if err := e.Unlink("g"); err != nil {
		t.Fatal(err)
	}
	if st := e.MustStat("f"); st.Nlink != 1 {
		t.Fatalf("link count after unlink = %d, want 1", st.Nlink)
	}
}

func TestDirectoryRenameClosesAndReopensPinnedHandles(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	e.MustMkdir("a")
	e.MustMkdir("a/b")
	e.WriteFile("a/b/f", []byte("payload"))
	e.MustStat("a/b/f")
	pinned := e.PinCount()
	if pinned < 2 {
		t.Fatalf("pinned directory handles = %d, want a and a/b", pinned)
	}

	ch.Reset()
	if err := e.Rename("a", "z"); err != nil {
		t.Fatalf("rename of a directory with pinned handles: %v", err)
	}
	if got := ch.Got("closeDir"); got != pinned {
		t.Fatalf("rename closed %d pinned handles, want %d", got, pinned)
	}
	if got := e.PinCount(); got != 0 {
		t.Fatalf("pinned handles after the rename = %d, want 0", got)
	}

	ch.Reset()
	if got := e.ReadFile("z/b/f"); string(got) != "payload" {
		t.Fatalf("read after rename = %q", got)
	}
	if got := ch.Got("openDirAt"); got != 2 {
		t.Fatalf("lookup after the rename reopened %d handles, want 2 (lazy reopen)", got)
	}
	_, err := e.Stat("a/b/f")
	hostfs.WantErrnoForTest(t, "stat of the old path", err, linuxerr.ENOENT)
}

func TestRmdirClosesPinnedHandlesOfTheDirectory(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	e.MustMkdir("p")
	e.MustMkdir("p/q")
	// A lookup below p/q pins it.
	_, err := e.Stat("p/q/none")
	hostfs.WantErrnoForTest(t, "stat below p/q", err, linuxerr.ENOENT)
	if got := e.PinCount(); got != 2 {
		t.Fatalf("pinned handles = %d, want p and p/q", got)
	}

	ch.Reset()
	if err := e.Rmdir("p/q"); err != nil {
		t.Fatalf("rmdir of a pinned directory: %v", err)
	}
	if got := ch.Got("closeDir"); got != 1 {
		t.Fatalf("rmdir closed %d handles, want the one of p/q", got)
	}
	if got := e.PinCount(); got != 1 {
		t.Fatalf("pinned handles after rmdir = %d, want 1", got)
	}
	_, err = e.Stat("p/q")
	hostfs.WantErrnoForTest(t, "stat of the removed directory", err, linuxerr.ENOENT)
}

func TestWorkspaceCloseReleasesEveryPinnedHandle(t *testing.T) {
	e, ch, clock := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)
	if e.PinCount() == 0 {
		t.Fatal("no pinned handle after lookups")
	}
	opened := ch.Got("openDirAt")

	if err := e.CloseWorkspace(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := ch.Got("closeDir"); got != opened {
		t.Fatalf("Close released %d of %d pinned handles", got, opened)
	}
	if got := e.PinCount(); got != 0 {
		t.Fatalf("pinned handles after Close = %d, want 0", got)
	}
	clock.Advance(hostfs.CacheTTLForTest + time.Millisecond)
	if _, err := e.Stat("a/b"); err == nil {
		t.Fatal("stat on a closed workspace succeeded")
	}
}

func TestIdlePinnedHandlesAreSwept(t *testing.T) {
	e, ch, clock := hostfs.NewCountEnvForTest(t)
	makeDeepFile(t, e)
	opened := ch.Got("openDirAt")

	e.SweepPins()
	if got := ch.Got("closeDir"); got != 0 {
		t.Fatalf("sweep closed %d handles that were in use a moment ago", got)
	}
	clock.Advance(hostfs.PinIdleTimeForTest)
	e.SweepPins()
	if got := ch.Got("closeDir"); got != opened {
		t.Fatalf("sweep closed %d of %d idle handles", got, opened)
	}
	if got := e.PinCount(); got != 0 {
		t.Fatalf("pinned handles after the sweep = %d, want 0", got)
	}
	// A later lookup reopens what it needs.
	clock.Advance(hostfs.CacheTTLForTest)
	e.MustStat(deepPath)
}

func TestPinnedHandlesAreBounded(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	for i := range hostfs.MaxDirPinsForTest + 20 {
		d := fmt.Sprintf("d%d", i)
		e.MustMkdir(d)
		// A lookup below the directory pins it.
		if _, err := e.Stat(d + "/x"); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat %s/x = %v, want ENOENT", d, err)
		}
	}
	if got := e.PinCount(); got > hostfs.MaxDirPinsForTest {
		t.Fatalf("pinned handles = %d, want at most %d", got, hostfs.MaxDirPinsForTest)
	}
}

func TestHostChangesBecomeVisibleAfterTheCacheLifetime(t *testing.T) {
	e, _, clock := hostfs.NewCountEnvForTest(t)
	e.WriteFile("grow", []byte("one"))
	e.MustStat("grow")
	_, err := e.Stat("late")
	hostfs.WantErrnoForTest(t, "stat of a name that does not exist yet", err, linuxerr.ENOENT)

	if err := os.WriteFile(e.Host("grow"), []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Host("late"), []byte("l"), 0o600); err != nil {
		t.Fatal(err)
	}

	clock.Advance(hostfs.CacheTTLForTest + time.Millisecond)
	if st := e.MustStat("grow"); st.Size != 14 {
		t.Fatalf("size after the cache lifetime = %d, want 14", st.Size)
	}
	if _, err := e.Stat("late"); err != nil {
		t.Fatalf("stat of a host-created name after the cache lifetime: %v", err)
	}
}

func TestListingRevalidatesNamesAndReplacedEntries(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	e.WriteFile("grow", []byte("one"))
	e.MustStat("grow")
	_, err := e.Stat("late")
	hostfs.WantErrnoForTest(t, "stat of a name that does not exist yet", err, linuxerr.ENOENT)

	// A host process replaces grow with another file and creates late.
	if err := os.WriteFile(e.Host("grow.new"), []byte("longer content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(e.Host("grow.new"), e.Host("grow")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(e.Host("late"), []byte("l"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The clock does not move: only the listing can reveal the changes.
	e.Readdir(".")
	if st := e.MustStat("grow"); st.Size != 14 {
		t.Fatalf("size of the replaced file after a listing = %d, want 14", st.Size)
	}
	if _, err := e.Stat("late"); err != nil {
		t.Fatalf("stat of a host-created name after a listing: %v", err)
	}
}

func TestListingKeepsMetadataOfUnchangedEntries(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	for i := range 20 {
		e.WriteFile(fmt.Sprintf("f%d", i), []byte("x"))
	}
	for _, name := range e.Readdir(".") {
		e.MustStat(name)
	}

	ch.Reset()
	for _, name := range e.Readdir(".") {
		e.MustStat(name)
	}
	if got := ch.Got("lstatAt"); got != 0 {
		t.Fatalf("listing and stat of 20 unchanged entries made %d lstatAt calls %s, want 0", got, ch.Dump())
	}
}

func TestExistingNameCreatedOnTheHostIsOpenedNotRefused(t *testing.T) {
	e, _, _ := hostfs.NewCountEnvForTest(t)
	_, err := e.Stat("late")
	hostfs.WantErrnoForTest(t, "stat before the host creates the name", err, linuxerr.ENOENT)
	if err := os.WriteFile(e.Host("late"), []byte("host"), 0o600); err != nil {
		t.Fatal(err)
	}

	// The negative entry is stale. A create without O_EXCL must open the file.
	fd, err := e.Open("late", linux.O_CREAT|linux.O_RDONLY, 0o644)
	if err != nil {
		t.Fatalf("open with O_CREAT of a host-created name: %v", err)
	}
	defer fd.DecRef(e.Ctx())
	if got := e.ReadAll(fd); string(got) != "host" {
		t.Fatalf("read = %q, want host", got)
	}
	// With O_EXCL the name exists, so the call fails.
	_, err = e.Open("late", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
	hostfs.WantErrnoForTest(t, "O_EXCL of an existing name", err, linuxerr.EEXIST)
}

func TestBackendThatVerifiesCaseSkipsTheListing(t *testing.T) {
	run := func(t *testing.T, verified bool) *hostfs.CountingHost {
		e, ch, _ := hostfs.NewCountEnvForTest(t)
		ch.SetCaseFlags(true, verified)
		e.MustMkdir("dir")
		e.WriteFile("dir/f", []byte("x"))
		// On a host that does not count directory links, the first stat of
		// a directory lists it once (dirlinks.go). That listing is not the
		// case check that this test measures.
		e.MustStat("dir")
		ch.Reset()
		e.MustStat("dir/f")
		e.MustStat("dir")
		return ch
	}
	if ch := run(t, true); ch.Listings() != 0 || ch.Got("fstatDir") != 0 {
		t.Fatalf("a backend that verifies case still listed or stat the directory %s", ch.Dump())
	}
	if ch := run(t, false); ch.Listings() == 0 {
		t.Fatalf("a case-insensitive backend without verification never listed the directory %s", ch.Dump())
	}
}

func TestDirectoryListingFollowsMutationsInPlace(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	ch.SetCaseFlags(true, false)
	// OpenWorkspace lists the root once to sweep the internal files of a
	// killed process. The count below starts after that call.
	ch.Reset()
	e.MustMkdir("dir")
	e.WriteFile("dir/first", []byte("1"))
	// The first lookup of an existing name lists the workspace root for the
	// name dir, and lists dir for the name first.
	e.MustStat("dir/first")
	if got := ch.Listings(); got != 2 {
		t.Fatalf("first lookups listed directories %d times, want 2", got)
	}

	ch.Reset()
	for i := range 20 {
		name := fmt.Sprintf("dir/f%d", i)
		e.WriteFile(name, []byte("x"))
		e.MustStat(name)
		if i%3 == 0 {
			moved := fmt.Sprintf("dir/g%d", i)
			if err := e.Rename(name, moved); err != nil {
				t.Fatal(err)
			}
			e.MustStat(moved)
			if _, err := e.Stat(name); !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Fatalf("stat of the renamed source %s = %v, want ENOENT", name, err)
			}
		}
		if i%5 == 0 {
			if err := e.Unlink(name); err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
				t.Fatal(err)
			}
		}
	}
	if got := ch.Listings(); got != 0 {
		t.Fatalf("single-entry mutations caused %d directory listings, want 0", got)
	}

	// A directory rename moves a whole subtree of listings.
	e.MustMkdir("dir/sub")
	e.WriteFile("dir/sub/x", []byte("x"))
	e.MustStat("dir/sub/x")
	if err := e.Rename("dir/sub", "dir/sub2"); err != nil {
		t.Fatal(err)
	}
	e.MustStat("dir/sub2/x")
	_, err := e.Stat("dir/sub/x")
	hostfs.WantErrnoForTest(t, "stat below the old directory name", err, linuxerr.ENOENT)
}

func TestCaseRulesHoldAcrossMutationsOnFoldingHost(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	if !ch.CaseInsensitive() && !hostfs.HostFoldsCaseForTest(t, e.Dir()) {
		t.Skip("the host file system is case-sensitive")
	}
	e.WriteFile("File", []byte("x"))
	e.MustStat("File")
	_, err := e.Stat("file")
	hostfs.WantErrnoForTest(t, "stat with another case", err, linuxerr.ENOENT)

	if err := e.Rename("File", "other"); err != nil {
		t.Fatal(err)
	}
	_, err = e.Stat("File")
	hostfs.WantErrnoForTest(t, "stat of the old name", err, linuxerr.ENOENT)
	e.MustStat("other")

	// The host now stores "other", and a creation under the old name with
	// another case must produce that exact name.
	e.WriteFile("file", []byte("y"))
	e.MustStat("file")
	_, err = e.Stat("File")
	hostfs.WantErrnoForTest(t, "stat with the case of the removed name", err, linuxerr.ENOENT)
	if got := e.Readdir("."); fmt.Sprint(got) != "[file other]" {
		t.Fatalf("listing = %v, want [file other]", got)
	}
}

func TestStatOfOpenFileAfterWriteNeedsNoLookup(t *testing.T) {
	e, ch, _ := hostfs.NewCountEnvForTest(t)
	e.WriteFile("f", []byte("x"))
	fd := e.MustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.Ctx())
	before := e.MustStat("f")

	if _, err := fd.Write(e.Ctx(), usermem.BytesIOSequence([]byte("more data")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	ch.Reset()
	st, err := fd.Stat(e.Ctx(), vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatalf("fstat: %v", err)
	}
	if st.Size != 9 {
		t.Fatalf("fstat size after the write = %d, want 9", st.Size)
	}
	if n := ch.Got("lstatAt"); n != 0 {
		t.Fatalf("fstat after a write made %d lstatAt calls %s, want 0", n, ch.Dump())
	}

	// A stat of the path must still read the host: the host chose the new times.
	after := e.MustStat("f")
	if after.Size != 9 {
		t.Fatalf("stat size after the write = %d, want 9", after.Size)
	}
	if after.Mtime.Sec < before.Mtime.Sec {
		t.Fatalf("stat mtime went back from %v to %v", before.Mtime, after.Mtime)
	}
}
