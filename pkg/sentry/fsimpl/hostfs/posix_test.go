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
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

func (e *env) setStat(p string, stat linux.Statx) error {
	return e.vfsObj.SetStatAt(e.ctx, e.creds, e.pop(p), &vfs.SetStatOptions{Stat: stat})
}

func TestHardLinkSharesInodeAndAttributes(t *testing.T) {
	e := newEnv(t)
	e.writeFile("a", []byte("one"))
	if err := e.link("a", "b"); err != nil {
		t.Fatalf("link a b: %v", err)
	}
	a, b := e.mustStat("a"), e.mustStat("b")
	if a.Ino != b.Ino || a.Nlink != 2 || b.Nlink != 2 {
		t.Fatalf("stat a = (ino %d, nlink %d), b = (ino %d, nlink %d), want one inode with nlink 2", a.Ino, a.Nlink, b.Ino, b.Nlink)
	}
	hostA, err := os.Stat(e.host("a"))
	if err != nil {
		t.Fatal(err)
	}
	hostB, err := os.Stat(e.host("b"))
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(hostA, hostB) {
		t.Fatalf("host files a and b are not one file")
	}

	// A write through one name shows through the other.
	fd := e.mustOpen("b", linux.O_WRONLY|linux.O_TRUNC)
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("two")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	fd.DecRef(e.ctx)
	if got := e.readFile("a"); string(got) != "two" {
		t.Fatalf("read a = %q, want two", got)
	}

	// Mode and owner belong to the inode.
	mode := linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID, Mode: 0o600, UID: 1001, GID: 1002}
	if err := e.setStat("a", mode); err != nil {
		t.Fatalf("setstat a: %v", err)
	}
	if st := e.mustStat("b"); st.Mode&0o7777 != 0o600 || st.UID != 1001 || st.GID != 1002 {
		t.Fatalf("stat b = mode %o uid %d gid %d, want 0600 1001 1002", st.Mode&0o7777, st.UID, st.GID)
	}

	// Attributes survive unlinking one name and a reload of the table.
	if err := e.unlink("a"); err != nil {
		t.Fatalf("unlink a: %v", err)
	}
	if st := e.mustStat("b"); st.Nlink != 1 || st.Mode&0o7777 != 0o600 {
		t.Fatalf("stat b after unlink a = nlink %d mode %o, want 1 0600", st.Nlink, st.Mode&0o7777)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	ws2, err := OpenWorkspace(e.dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws2.Close() }()
	if attr, _, err := ws2.Stat("b"); err != nil || attr.Mode&0o7777 != 0o600 || attr.UID != 1001 {
		t.Fatalf("reloaded b = (%+v, %v)", attr, err)
	}

	wantErrno(t, "link onto existing name", e.link("b", "b"), linuxerr.EEXIST)
	e.mustMkdir("dir")
	wantErrno(t, "link of directory", e.link("dir", "dir2"), linuxerr.EPERM)
}

func TestRenamePopulatedDirectoryKeepsOpenFilesAndDentries(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.mustMkdir("d/sub")
	e.writeFile("d/sub/f", []byte("payload"))
	fd := e.mustOpen("d/sub/f", linux.O_RDWR)
	subVD, err := e.vfsObj.GetDentryAt(e.ctx, e.creds, e.pop("d/sub"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	released := false
	release := func() {
		if !released {
			released = true
			fd.DecRef(e.ctx)
			subVD.DecRef(e.ctx)
		}
	}
	defer release()

	if err := e.rename("d", "e"); err != nil {
		if runtime.GOOS == "windows" && errors.Is(err, linuxerr.EACCES) {
			// NTFS is expected to refuse the rename of a directory that has an
			// open descendant. The guest sees EACCES, and nothing moved. Closing
			// the descendants must make the same rename work.
			wantErrno(t, "old path after the refused rename", func() error { _, err := e.stat("d/sub/f"); return err }(), nil)
			release()
			if err := e.rename("d", "e"); err != nil {
				t.Fatalf("rename d e after closing the descendants: %v", err)
			}
			if got := e.readFile("e/sub/f"); string(got) != "payload" {
				t.Fatalf("read new path = %q", got)
			}
			t.Skip("NTFS refuses to rename a directory with an open descendant, as expected")
		}
		t.Fatalf("rename d e: %v", err)
	}
	wantErrno(t, "stat old path", func() error { _, err := e.stat("d/sub/f"); return err }(), linuxerr.ENOENT)
	if got := e.readFile("e/sub/f"); string(got) != "payload" {
		t.Fatalf("read new path = %q", got)
	}
	// The open descriptor still reaches the file and reports the new name.
	if got := e.readAll(fd); string(got) != "payload" {
		t.Fatalf("read open fd = %q", got)
	}
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("PAYLOAD!!")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("write open fd: %v", err)
	}
	if raw, err := os.ReadFile(e.host("e/sub/f")); err != nil || string(raw) != "PAYLOAD!!" {
		t.Fatalf("host file = (%q, %v)", raw, err)
	}
	if p, err := e.vfsObj.PathnameWithDeleted(e.ctx, e.root, fd.VirtualDentry()); err != nil || p != "/e/sub/f" {
		t.Fatalf("pathname of open fd = (%q, %v), want /e/sub/f", p, err)
	}
	if p, err := e.vfsObj.PathnameWithDeleted(e.ctx, e.root, subVD); err != nil || p != "/e/sub" {
		t.Fatalf("pathname of cached directory = (%q, %v), want /e/sub", p, err)
	}
	// Changes through the open dentry reach the table under the new key.
	if err := e.setStat("e/sub/f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o700}); err != nil {
		t.Fatal(err)
	}
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Mode&0o7777 != 0o700 || st.Size != 9 {
		t.Fatalf("fd stat = (mode %o size %d, %v), want 0700 and size 9", st.Mode&0o7777, st.Size, err)
	}
	if attr, _, err := e.ws.Stat("e/sub/f"); err != nil || attr.Mode&0o7777 != 0o700 {
		t.Fatalf("workspace stat of new key = (%+v, %v)", attr, err)
	}
}

func TestRenameTypeRules(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("dir")
	e.mustMkdir("empty")
	e.mustMkdir("full")
	e.writeFile("full/x", []byte("x"))
	e.writeFile("file", []byte("f"))
	e.writeFile("other", []byte("o"))

	wantErrno(t, "file over directory", e.rename("file", "dir"), linuxerr.EISDIR)
	wantErrno(t, "directory over file", e.rename("dir", "file"), linuxerr.ENOTDIR)
	wantErrno(t, "directory over non-empty directory", e.rename("dir", "full"), linuxerr.ENOTEMPTY)
	wantErrno(t, "directory into itself", e.rename("dir", "dir/inner"), linuxerr.EINVAL)
	wantErrno(t, "missing source", e.rename("nothing", "x"), linuxerr.ENOENT)

	if err := e.rename("dir", "empty"); err != nil {
		t.Fatalf("directory over empty directory: %v", err)
	}
	wantErrno(t, "old directory", func() error { _, err := e.stat("dir"); return err }(), linuxerr.ENOENT)
	if err := e.rename("file", "other"); err != nil {
		t.Fatalf("file over file: %v", err)
	}
	if got := e.readFile("other"); string(got) != "f" {
		t.Fatalf("other = %q, want f", got)
	}
	err := e.vfsObj.RenameAt(e.ctx, e.creds, e.pop("other"), e.pop("empty"), &vfs.RenameOptions{Flags: linux.RENAME_NOREPLACE})
	wantErrno(t, "RENAME_NOREPLACE onto existing", err, linuxerr.EEXIST)
	err = e.vfsObj.RenameAt(e.ctx, e.creds, e.pop("other"), e.pop("fresh"), &vfs.RenameOptions{Flags: linux.RENAME_NOREPLACE})
	if err != nil {
		t.Fatalf("RENAME_NOREPLACE to fresh name: %v", err)
	}
	err = e.vfsObj.RenameAt(e.ctx, e.creds, e.pop("fresh"), e.pop("fresh2"), &vfs.RenameOptions{Flags: linux.RENAME_EXCHANGE})
	wantErrno(t, "RENAME_EXCHANGE onto a missing name", err, linuxerr.ENOENT)
}

func TestRenameOverVirtualSymlinkAndOntoSameFile(t *testing.T) {
	e := newEnv(t)
	e.writeFile("target", []byte("t"))
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link"), "target"); err != nil {
		t.Fatal(err)
	}
	e.writeFile("src", []byte("s"))
	if err := e.rename("src", "link"); err != nil {
		t.Fatalf("rename file over virtual symlink: %v", err)
	}
	if st := e.mustStat("link"); st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("link type = %o, want regular file", st.Mode&linux.S_IFMT)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link2"), "target"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("link2", "target"); err != nil {
		t.Fatalf("rename virtual symlink over file: %v", err)
	}
	if st, err := e.lstat("target"); err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Fatalf("lstat target = (%o, %v), want symlink", st.Mode&linux.S_IFMT, err)
	}
	if _, err := os.Lstat(e.host("target")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host still has target: %v", err)
	}

	e.writeFile("n1", []byte("n"))
	if err := e.link("n1", "n2"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("n1", "n2"); err != nil {
		t.Fatalf("rename onto another name of the same file: %v", err)
	}
	if _, err := e.stat("n1"); err != nil {
		t.Fatalf("both names must remain after a no-op rename: %v", err)
	}
}

func TestUnlinkWhileOpen(t *testing.T) {
	e := newEnv(t)
	e.writeFile("pack", []byte("pack-data"))
	fd := e.mustOpen("pack", linux.O_RDWR)
	defer fd.DecRef(e.ctx)

	if err := e.unlink("pack"); err != nil {
		t.Fatalf("unlink open file: %v", err)
	}
	wantErrno(t, "stat after unlink", func() error { _, err := e.stat("pack"); return err }(), linuxerr.ENOENT)
	if got := e.readAll(fd); string(got) != "pack-data" {
		t.Fatalf("read unlinked file = %q", got)
	}
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Mode&0o7777 != 0o644 || st.Size != 9 {
		t.Fatalf("fd stat of unlinked file = (mode %o size %d, %v)", st.Mode&0o7777, st.Size, err)
	}
	// Windows reports the link count of a delete-pending file as the volume
	// driver decides, so only POSIX hosts must show zero.
	if runtime.GOOS != "windows" && st.Nlink != 0 {
		t.Fatalf("link count of unlinked file = %d, want 0", st.Nlink)
	}
	// A new file under the old name is independent.
	e.writeFile("pack", []byte("new"))
	if got := e.readAll(fd); string(got) != "pack-data" {
		t.Fatalf("old fd after name reuse = %q", got)
	}
	if got := e.readFile("pack"); string(got) != "new" {
		t.Fatalf("new file = %q", got)
	}
	// An unlinked file accepts attribute changes through its open descriptor.
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE | linux.STATX_SIZE, Mode: 0o600, Size: 4}}); err != nil {
		t.Fatalf("setstat on unlinked file: %v", err)
	}
	if got := e.readAll(fd); string(got) != "pack" {
		t.Fatalf("truncated unlinked file = %q", got)
	}
}

func TestRenameOverOpenFile(t *testing.T) {
	e := newEnv(t)
	e.writeFile("index", []byte("git-staged-tree-v1"))
	e.writeFile("index.lock", []byte("git-staged-tree-v2"))
	if err := e.setStat("index.lock", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	old := e.mustOpen("index", linux.O_RDONLY)
	defer old.DecRef(e.ctx)

	if err := e.rename("index.lock", "index"); err != nil {
		t.Fatalf("rename over open file: %v", err)
	}
	if got := e.readAll(old); string(got) != "git-staged-tree-v1" {
		t.Fatalf("old descriptor = %q, want v1", got)
	}
	if got := e.readFile("index"); string(got) != "git-staged-tree-v2" {
		t.Fatalf("new open = %q, want v2", got)
	}
	if st := e.mustStat("index"); st.Mode&0o7777 != 0o600 {
		t.Fatalf("index mode = %o, want the renamed file's 0600", st.Mode&0o7777)
	}
	wantErrno(t, "old lock name", func() error { _, err := e.stat("index.lock"); return err }(), linuxerr.ENOENT)
}

func TestVirtualSymlinksStayOffTheHost(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("sub")
	e.writeFile("sub/hello.txt", []byte("hi"))
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/link"), "hello.txt"); err != nil {
		t.Fatal(err)
	}
	if got := e.readFile("sub/link"); string(got) != "hi" {
		t.Fatalf("read through symlink = %q", got)
	}
	if target, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("sub/link")); err != nil || target != "hello.txt" {
		t.Fatalf("readlink = (%q, %v)", target, err)
	}
	if _, err := os.Lstat(e.host("sub/link")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("symlink reached the host: %v", err)
	}
	if st, err := e.lstat("sub/link"); err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK || st.Size != 9 {
		t.Fatalf("lstat = (mode %o size %d, %v)", st.Mode&linux.S_IFMT, st.Size, err)
	}
	wantErrno(t, "symlink onto existing name", e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/hello.txt"), "x"), linuxerr.EEXIST)
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/up"), "../../out"); err != nil {
		t.Fatalf("escaping relative target = %v, want success", err)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/abs"), "/etc/passwd"); err != nil {
		t.Fatalf("absolute target = %v, want success", err)
	}
	wantErrno(t, "empty target", e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/none"), ""), linuxerr.ENOENT)
	wantErrno(t, "target with a NUL byte", e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("sub/nul"), "a\x00b"), linuxerr.EINVAL)
	for _, name := range []string{"sub/up", "sub/abs"} {
		if err := e.unlink(name); err != nil {
			t.Fatal(err)
		}
	}
	wantErrno(t, "rmdir of a symlink", e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("sub/link")), linuxerr.ENOTDIR)

	// A directory that holds a virtual symlink is not empty.
	wantErrno(t, "rmdir with symlink inside", e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("sub")), linuxerr.ENOTEMPTY)
	if err := e.unlink("sub/link"); err != nil {
		t.Fatal(err)
	}
	if err := e.unlink("sub/hello.txt"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("sub")); err != nil {
		t.Fatalf("rmdir of empty directory: %v", err)
	}
}

func TestHostSymlinksNeverTraversed(t *testing.T) {
	e := newEnv(t)
	outside := t.TempDir()
	if err := os.WriteFile(outside+"/secret", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	e.mustMkdir("sub")
	e.writeFile("sub/file", []byte("inside"))
	for name, target := range map[string]string{
		"abs":   outside,
		"up":    "../../..",
		"inner": "sub",
	} {
		if err := os.Symlink(target, e.host(name)); err != nil {
			t.Skipf("host cannot create symbolic links: %v", err)
		}
	}

	wantErrno(t, "stat of absolute host symlink", func() error { _, err := e.lstat("abs"); return err }(), linuxerr.EACCES)
	wantErrno(t, "open through absolute host symlink", func() error { _, err := e.open("abs/secret", linux.O_RDONLY, 0); return err }(), linuxerr.EACCES)
	wantErrno(t, "stat of escaping relative host symlink", func() error { _, err := e.lstat("up"); return err }(), linuxerr.EACCES)

	// An intra-workspace host link resolves through the VFS, which follows it
	// as a symbolic link. The host layer never resolves it.
	if got := e.readFile("inner/file"); string(got) != "inside" {
		t.Fatalf("read through inner host link = %q", got)
	}
	for _, rel := range []string{"abs/secret", "inner/file"} {
		if _, err := e.ws.host.open(rel, os.O_RDONLY, 0); !errors.Is(err, ErrPathTraversal) {
			t.Fatalf("host.open(%q) = %v, want ErrPathTraversal", rel, err)
		}
		if _, err := e.ws.host.lstat(rel); !errors.Is(err, ErrPathTraversal) {
			t.Fatalf("host.lstat(%q) = %v, want ErrPathTraversal", rel, err)
		}
	}
	if _, err := e.ws.host.open("abs", os.O_RDONLY, 0); err == nil {
		t.Fatalf("host.open of a symbolic link succeeded")
	}
	if got := e.readdir("."); fmt.Sprint(got) != "[inner sub up]" && fmt.Sprint(got) != "[inner sub]" {
		t.Fatalf("root listing = %v, want inner and sub (escaping links hidden)", got)
	}
}

func TestDirectoryReplacedBySymlinkDoesNotEscape(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("inside"))
	outside := t.TempDir()
	if err := os.WriteFile(outside+"/f", []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirFD := e.mustOpen("d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dirFD.DecRef(e.ctx)
	if err := os.Rename(e.host("d"), e.host("d.moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, e.host("d")); err != nil {
		t.Skipf("host cannot create symbolic links: %v", err)
	}
	if _, err := e.ws.OpenFile("d/f", os.O_RDONLY, 0); !errors.Is(err, ErrPathTraversal) {
		t.Fatalf("OpenFile through swapped directory = %v, want ErrPathTraversal", err)
	}
	// A lookup stays valid for cacheTTL, and the guest opened d before the swap,
	// so the open may still reach the directory that the guest saw: the pinned
	// handle names that object, not the path. It must never reach the outside
	// file. TestHostSwapOfPinnedDirectoryIsNoticedAfterTheCacheLifetime covers
	// the refusal after the cache expires.
	fd, err := e.open("d/f", linux.O_RDONLY, 0)
	if err != nil {
		wantErrno(t, "vfs open through swapped directory", err, linuxerr.EACCES)
		return
	}
	defer fd.DecRef(e.ctx)
	if got := string(e.readAll(fd)); got == "outside" {
		t.Fatalf("vfs open through the swapped directory read %q from outside the workspace", got)
	}
}

func TestConcurrentRenameOpenStat(t *testing.T) {
	e := newEnv(t)
	e.writeFile("x", []byte("content"))
	const workers = 6
	const rounds = 120
	var wg sync.WaitGroup
	errs := make(chan error, workers*rounds)
	for w := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range rounds {
				var err error
				switch (w + i) % 4 {
				case 0:
					err = e.rename("x", "y")
				case 1:
					err = e.rename("y", "x")
				case 2:
					var fd *vfs.FileDescription
					name := "x"
					if i%2 == 0 {
						name = "y"
					}
					fd, err = e.open(name, linux.O_RDONLY, 0)
					if err == nil {
						buf := make([]byte, 16)
						n, rerr := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
						if rerr != nil || string(buf[:n]) != "content" {
							errs <- fmt.Errorf("read = (%q, %v)", buf[:n], rerr)
						}
						fd.DecRef(e.ctx)
					}
				default:
					_, err = e.stat("x")
				}
				if err != nil && !linuxerr.Equals(linuxerr.ENOENT, err) {
					errs <- err
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent operation: %v", err)
	}
	_, errX := e.stat("x")
	_, errY := e.stat("y")
	if (errX == nil) == (errY == nil) {
		t.Fatalf("exactly one of x and y must exist: stat x = %v, stat y = %v", errX, errY)
	}
}

func TestChmodChangesOnlyVirtualMode(t *testing.T) {
	e := newEnv(t)
	hostFile := e.host("pre")
	if err := os.WriteFile(hostFile, []byte("pre"), 0o640); err != nil {
		t.Fatal(err)
	}
	e.writeFile("made", []byte("made"))
	wantHost := map[string]os.FileMode{}
	for _, name := range []string{"pre", "made"} {
		info, err := os.Stat(e.host(name))
		if err != nil {
			t.Fatal(err)
		}
		wantHost[name] = info.Mode().Perm()
	}
	for _, name := range []string{"pre", "made"} {
		if err := e.setStat(name, linux.Statx{Mask: linux.STATX_MODE, Mode: 0o000}); err != nil {
			t.Fatalf("chmod %s: %v", name, err)
		}
		if st := e.mustStat(name); st.Mode&0o7777 != 0 {
			t.Fatalf("guest mode of %s = %o, want 0", name, st.Mode&0o7777)
		}
		info, err := os.Stat(e.host(name))
		if err != nil || info.Mode().Perm() != wantHost[name] {
			t.Fatalf("host mode of %s = (%v, %v), want %v", name, info.Mode().Perm(), err, wantHost[name])
		}
		// The sentry can still open the file, so a later chmod can restore it.
		if err := e.setStat(name, linux.Statx{Mask: linux.STATX_MODE, Mode: 0o644}); err != nil {
			t.Fatalf("restore mode of %s: %v", name, err)
		}
		if got := e.readFile(name); len(got) == 0 {
			t.Fatalf("file %s lost its content", name)
		}
	}
}

func TestPermissionChecksUseVirtualMode(t *testing.T) {
	e := newEnv(t)
	ns := e.creds.UserNamespace
	user := auth.NewUserCredentials(1000, 1000, nil, nil, ns)
	e.mustMkdir("locked")
	if err := e.setStat("locked", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o555}); err != nil {
		t.Fatal(err)
	}
	e.writeFile("secret", []byte("s"))
	if err := e.setStat("secret", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}

	_, err := e.vfsObj.OpenAt(e.ctx, user, e.pop("locked/new"), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
	wantErrno(t, "create in read-only directory", err, linuxerr.EACCES)
	_, err = e.vfsObj.OpenAt(e.ctx, user, e.pop("secret"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	wantErrno(t, "read of mode 0600 file", err, linuxerr.EACCES)
	wantErrno(t, "mkdir in read-only directory", e.vfsObj.MkdirAt(e.ctx, user, e.pop("locked/d"), &vfs.MkdirOptions{Mode: 0o755}), linuxerr.EACCES)
	wantErrno(t, "unlink in read-only directory", e.vfsObj.UnlinkAt(e.ctx, user, e.pop("secret")), linuxerr.EACCES)
	wantErrno(t, "chmod by non-owner", e.vfsObj.SetStatAt(e.ctx, user, e.pop("secret"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}}), linuxerr.EPERM)

	// Files created by an unprivileged user are owned by that user.
	if err := e.setStat(".", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	fd, err := e.vfsObj.OpenAt(e.ctx, user, e.pop("owned"), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o640})
	if err != nil {
		t.Fatalf("create by user: %v", err)
	}
	fd.DecRef(e.ctx)
	if st := e.mustStat("owned"); st.UID != 1000 || st.GID != 1000 || st.Mode&0o7777 != 0o640 {
		t.Fatalf("owned = uid %d gid %d mode %o, want 1000 1000 0640", st.UID, st.GID, st.Mode&0o7777)
	}
}

func TestReservedMetadataNamesAreHidden(t *testing.T) {
	e := newEnv(t)
	e.writeFile("visible", []byte("v"))
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.host(MetaFileName)); err != nil {
		t.Fatalf("meta file missing on the host after Sync: %v", err)
	}
	for _, name := range []string{MetaFileName, metaTempName, ".GVX_META"} {
		wantErrno(t, "stat "+name, func() error { _, err := e.stat(name); return err }(), linuxerr.ENOENT)
		_, err := e.open(name, linux.O_CREAT|linux.O_WRONLY, 0o644)
		wantErrno(t, "create "+name, err, linuxerr.EPERM)
		wantErrno(t, "mkdir "+name, e.mkdir(name), linuxerr.EPERM)
		wantErrno(t, "rename onto "+name, e.rename("visible", name), linuxerr.EPERM)
		wantErrno(t, "unlink "+name, e.unlink(name), linuxerr.ENOENT)
	}
	if got := e.readdir("."); len(got) != 1 || got[0] != "visible" {
		t.Fatalf("root listing = %v, want only visible", got)
	}
}

func TestCaseSensitiveNamesOnTheGuestView(t *testing.T) {
	e := newEnv(t)
	e.writeFile("Readme", []byte("upper"))
	wantErrno(t, "lookup with other case", func() error { _, err := e.stat("readme"); return err }(), linuxerr.ENOENT)
	_, err := e.open("readme", linux.O_RDONLY, 0)
	wantErrno(t, "open with other case", err, linuxerr.ENOENT)

	// Names that differ only in case coexist, also on a host that folds case.
	// The codec stores a later name under an escaped host name.
	e.writeFile("readme", []byte("lower"))
	e.writeFile("README", []byte("third"))
	for name, want := range map[string]string{"Readme": "upper", "readme": "lower", "README": "third"} {
		if got := e.readFile(name); string(got) != want {
			t.Fatalf("%s = %q, want %q", name, got, want)
		}
	}
	if got := e.readdir("."); fmt.Sprint(got) != "[README Readme readme]" {
		t.Fatalf("listing = %v, want the three names with their own case", got)
	}
	if err := e.unlink("readme"); err != nil {
		t.Fatal(err)
	}
	if err := e.unlink("README"); err != nil {
		t.Fatal(err)
	}

	// A rename onto a case variant creates the new name beside the old one.
	e.writeFile("other", []byte("o"))
	if err := e.rename("other", "README"); err != nil {
		t.Fatalf("rename onto a case variant: %v", err)
	}
	if got := e.readFile("Readme"); string(got) != "upper" {
		t.Fatalf("Readme = %q after the rename", got)
	}
	if got := e.readFile("README"); string(got) != "o" {
		t.Fatalf("README = %q after the rename", got)
	}
	if err := e.unlink("README"); err != nil {
		t.Fatal(err)
	}

	// Renaming only the case works.
	if err := e.rename("Readme", "README"); err != nil {
		t.Fatalf("case-only rename: %v", err)
	}
	if got := e.readdir("."); fmt.Sprint(got) != "[README]" {
		t.Fatalf("listing after case rename = %v, want [README]", got)
	}
	if got := e.readFile("README"); string(got) != "upper" {
		t.Fatalf("README = %q after the case rename", got)
	}
}

// hostFoldsCase reports whether dir resolves names case-insensitively.
func hostFoldsCase(t *testing.T, dir string) bool {
	t.Helper()
	probe := dir + "/.CaseProbe"
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(probe) }()
	_, err := os.Lstat(dir + "/.caseprobe")
	return err == nil
}

func TestDirectoryIterationSurvivesDeletion(t *testing.T) {
	e := newEnv(t)
	for i := range 12 {
		e.writeFile(fmt.Sprintf("f%02d", i), []byte("x"))
	}
	fd := e.mustOpen(".", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)

	errStop := errors.New("stop")
	var seen []string
	collect := func(limit int) error {
		return fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
			if limit == 0 {
				return errStop
			}
			limit--
			if d.Name != "." && d.Name != ".." {
				seen = append(seen, d.Name)
			}
			return nil
		}))
	}
	if err := collect(8); !errors.Is(err, errStop) {
		t.Fatalf("first read = %v, want stop", err)
	}
	// The guest deletes what it already read, as rm -rf does.
	for _, name := range seen {
		if err := e.unlink(name); err != nil {
			t.Fatal(err)
		}
	}
	if err := collect(1 << 20); err != nil {
		t.Fatalf("second read: %v", err)
	}
	if len(seen) != 12 {
		t.Fatalf("saw %d entries (%v), want all 12 exactly once", len(seen), seen)
	}
	uniq := map[string]bool{}
	for _, n := range seen {
		uniq[n] = true
	}
	if len(uniq) != 12 {
		t.Fatalf("duplicate entries in %v", seen)
	}
	// Rewinding observes the current directory.
	if _, err := fd.Seek(e.ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	var after []string
	if err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			after = append(after, d.Name)
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if len(after) != 6 {
		t.Fatalf("after rewind saw %v, want the 6 surviving entries", after)
	}
	if len(seen) != 12 || len(uniq) != 12 {
		t.Fatalf("iteration saw %d names, %d distinct", len(seen), len(uniq))
	}
}

func TestTruncateAndTimestamps(t *testing.T) {
	e := newEnv(t)
	e.writeFile("t", []byte("0123456789"))
	if err := e.setStat("t", linux.Statx{Mask: linux.STATX_SIZE, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if got := e.readFile("t"); string(got) != "0123" {
		t.Fatalf("after truncate = %q", got)
	}
	fd := e.mustOpen("t", linux.O_RDWR|linux.O_TRUNC)
	fd.DecRef(e.ctx)
	if got := e.readFile("t"); len(got) != 0 {
		t.Fatalf("after O_TRUNC = %q", got)
	}
	want := linux.StatxTimestamp{Sec: 1_700_000_000, Nsec: 123_000_000}
	if err := e.setStat("t", linux.Statx{Mask: linux.STATX_MTIME | linux.STATX_ATIME, Mtime: want, Atime: want}); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("t"); st.Mtime.Sec != want.Sec || st.Atime.Sec != want.Sec {
		t.Fatalf("times = (%v, %v), want %v", st.Mtime, st.Atime, want)
	}
	// A virtual symlink keeps its own timestamps in the table.
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("l"), "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SetStatAt(e.ctx, e.creds, e.pop("l"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MTIME, Mtime: want}}); err != nil {
		t.Fatalf("utimens of symlink: %v", err)
	}
	if st, err := e.lstat("l"); err != nil || st.Mtime.Sec != want.Sec {
		t.Fatalf("symlink mtime = (%v, %v)", st.Mtime, err)
	}
}

func TestDentryCachePruningKeepsOpenFiles(t *testing.T) {
	e := newEnv(t)
	for i := range 40 {
		e.writeFile(fmt.Sprintf("p%02d", i), []byte("x"))
	}
	fd := e.mustOpen("p07", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	hfs := e.root.Mount().Filesystem().Impl().(*filesystem)
	hfs.mu.Lock()
	hfs.pruneAt = 8
	hfs.mu.Unlock()
	// Creating a dentry above the threshold triggers a prune.
	e.writeFile("trigger", []byte("t"))
	for i := range 40 {
		e.mustStat(fmt.Sprintf("p%02d", i))
	}
	hfs.mu.Lock()
	count := hfs.dentryCount
	hfs.mu.Unlock()
	if count > 20 {
		t.Fatalf("dentry cache holds %d entries after pruning", count)
	}
	if got := e.readAll(fd); string(got) != "x" {
		t.Fatalf("open file after pruning = %q", got)
	}
	if got := e.readFile("p07"); string(got) != "x" {
		t.Fatalf("reopened file after pruning = %q", got)
	}
}

type recordingSpace struct {
	mu          sync.Mutex
	invalidated []hostarch.AddrRange

	// onInvalidate runs inside Invalidate, before the call returns. Tests use
	// it to observe the state of the file cache at that moment.
	onInvalidate func()
}

func (s *recordingSpace) Invalidate(ar hostarch.AddrRange, opts memmap.InvalidateOpts) {
	s.mu.Lock()
	s.invalidated = append(s.invalidated, ar)
	hook := s.onInvalidate
	s.mu.Unlock()
	if hook != nil {
		hook()
	}
}

func (e *env) mapFile(fd *vfs.FileDescription, length uint64, writable bool) (memmap.Mappable, *recordingSpace, hostarch.AddrRange) {
	e.t.Helper()
	opts := &memmap.MMapOpts{Length: length, Offset: 0, Perms: hostarch.ReadWrite, MaxPerms: hostarch.ReadWrite}
	if err := fd.ConfigureMMap(e.ctx, opts); err != nil {
		e.t.Fatalf("ConfigureMMap: %v", err)
	}
	ms := &recordingSpace{}
	ar := hostarch.AddrRange{Start: 0x10000, End: 0x10000 + hostarch.Addr(length)}
	if err := opts.Mappable.AddMapping(e.ctx, ms, ar, 0, writable); err != nil {
		e.t.Fatalf("AddMapping: %v", err)
	}
	return opts.Mappable, ms, ar
}

// TestMappingSurvivesTheLastUnmapOfAnotherThread replays the interleaving that
// made git pack-objects die of SIGBUS. Thread B configures a mapping of a file
// that thread A has mapped. Thread A unmaps its mapping, which was the last
// one, before thread B adds its mapping. The page fault of B must still find a
// handle.
func TestMappingSurvivesTheLastUnmapOfAnotherThread(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		e.writeFile("loose", []byte("twenty-six bytes of data."))
		fd := e.mustOpen("loose", linux.O_RDONLY)
		defer fd.DecRef(e.ctx)
		const length = hostarch.PageSize

		first, msA, arA := e.mapFile(fd, length, false)

		optsB := &memmap.MMapOpts{Length: length, Perms: hostarch.Read, MaxPerms: hostarch.Read, Private: true}
		if err := fd.ConfigureMMap(e.ctx, optsB); err != nil {
			t.Fatalf("ConfigureMMap B: %v", err)
		}
		first.RemoveMapping(e.ctx, msA, arA, 0, false)
		msB := &recordingSpace{}
		arB := hostarch.AddrRange{Start: 0x30000, End: 0x30000 + length}
		if err := optsB.Mappable.AddMapping(e.ctx, msB, arB, 0, false); err != nil {
			t.Fatalf("AddMapping B: %v", err)
		}
		required := memmap.MappableRange{Start: 0, End: hostarch.PageSize}
		ts, err := optsB.Mappable.Translate(e.ctx, required, required, hostarch.Read)
		if err != nil || len(ts) == 0 {
			t.Fatalf("Translate after the other mapping ended = (%v, %v), want a translation", ts, err)
		}

		// The last unmap releases every handle again.
		optsB.Mappable.RemoveMapping(e.ctx, msB, arB, 0, false)
		data := &fd.Impl().(*regularFD).dentry.inode.data
		data.DataMu.Lock()
		held := data.mh != nil || data.pending != nil
		data.DataMu.Unlock()
		if held {
			t.Fatalf("the file data still holds a handle after the last unmap")
		}
	})
}

func TestMappedPagesWriteBackAndStayCoherent(t *testing.T) {
	forEachChunkMode(t, testMappedPagesWriteBackAndStayCoherent)
}

func testMappedPagesWriteBackAndStayCoherent(t *testing.T, e *env) {
	content := bytes.Repeat([]byte("a"), 3*hostarch.PageSize+100)
	e.writeFile("m", content)
	fd := e.mustOpen("m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, uint64(len(content)), true)

	rw := hostarch.ReadWrite
	required := memmap.MappableRange{Start: 0, End: hostarch.PageSize}
	optional := memmap.MappableRange{Start: 0, End: 4 * hostarch.PageSize}
	ts, err := m.Translate(e.ctx, required, optional, rw)
	if err != nil || len(ts) == 0 {
		t.Fatalf("Translate = (%v, %v)", ts, err)
	}
	if !ts[0].Perms.Write {
		t.Fatalf("translation perms = %v, want write", ts[0].Perms)
	}
	view := func(off, length uint64) []byte {
		for _, tr := range ts {
			if off < tr.Source.Start || off+length > tr.Source.End {
				continue
			}
			start := tr.Offset + off - tr.Source.Start
			bs, err := tr.File.MapInternal(memmap.FileRange{Start: start, End: start + length}, rw)
			if err != nil {
				t.Fatalf("MapInternal: %v", err)
			}
			if bs.NumBlocks() != 1 {
				t.Fatalf("MapInternal returned %d blocks", bs.NumBlocks())
			}
			return bs.Head().ToSlice()
		}
		t.Fatalf("no translation covers [%d, %d): %v", off, off+length, ts)
		return nil
	}
	copy(view(0, 8), "mapped!!")

	// A read system call sees the mapped write.
	buf := make([]byte, 8)
	if n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{}); err != nil || n != 8 || string(buf) != "mapped!!" {
		t.Fatalf("pread after mapped write = (%q, %d, %v)", buf, n, err)
	}
	if raw, err := os.ReadFile(e.host("m")); err != nil || string(raw[:8]) != "mapped!!" {
		t.Fatalf("host content after pread = (%q, %v)", raw[:8], err)
	}

	// A write system call shows through the mapped page.
	if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte("syscall!")), 16, vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := string(view(16, 8)); got != "syscall!" {
		t.Fatalf("mapped view after pwrite = %q", got)
	}

	// Mapped writes that no read observed reach the host at unmap.
	copy(view(100, 5), "later")
	m.RemoveMapping(e.ctx, ms, ar, 0, true)
	if raw, err := os.ReadFile(e.host("m")); err != nil || string(raw[100:105]) != "later" {
		t.Fatalf("host content after unmap = (%q, %v)", raw[100:105], err)
	}
	if err := fd.OnClose(e.ctx); err != nil {
		t.Fatalf("OnClose after clean write-back: %v", err)
	}

	// Beyond the end of the file a translation is a bus error.
	m2, ms2, ar2 := e.mapFile(fd, 8*hostarch.PageSize, false)
	_, err = m2.Translate(e.ctx, memmap.MappableRange{Start: 6 * hostarch.PageSize, End: 7 * hostarch.PageSize}, memmap.MappableRange{Start: 0, End: 8 * hostarch.PageSize}, hostarch.Read)
	var bus *memmap.BusError
	if !errors.As(err, &bus) {
		t.Fatalf("Translate beyond EOF = %v, want BusError", err)
	}
	m2.RemoveMapping(e.ctx, ms2, ar2, 0, false)
}

func TestTruncateInvalidatesMappings(t *testing.T) {
	forEachChunkMode(t, testTruncateInvalidatesMappings)
}

func testTruncateInvalidatesMappings(t *testing.T, e *env) {
	e.writeFile("m", bytes.Repeat([]byte("z"), 4*hostarch.PageSize))
	fd := e.mustOpen("m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, 4*hostarch.PageSize, true)
	if _, err := m.Translate(e.ctx, memmap.MappableRange{Start: 0, End: hostarch.PageSize}, memmap.MappableRange{Start: 0, End: 4 * hostarch.PageSize}, hostarch.ReadWrite); err != nil {
		t.Fatal(err)
	}
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: hostarch.PageSize + 10}}); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	ms.mu.Lock()
	got := append([]hostarch.AddrRange(nil), ms.invalidated...)
	ms.mu.Unlock()
	if len(got) == 0 || got[0].Start != ar.Start+2*hostarch.PageSize {
		t.Fatalf("invalidated ranges = %v, want a range starting at the second page boundary", got)
	}
	_, err := m.Translate(e.ctx, memmap.MappableRange{Start: 3 * hostarch.PageSize, End: 4 * hostarch.PageSize}, memmap.MappableRange{Start: 0, End: 4 * hostarch.PageSize}, hostarch.Read)
	var bus *memmap.BusError
	if !errors.As(err, &bus) {
		t.Fatalf("Translate after truncate = %v, want BusError", err)
	}
	m.RemoveMapping(e.ctx, ms, ar, 0, true)
}

func TestSyncReportsHostFlushFailure(t *testing.T) {
	e := newEnv(t)
	e.writeFile("s", []byte("data"))
	fd := e.mustOpen("s", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	injected := errors.New("injected flush failure")
	fd.Impl().(*regularFD).h.syncFn = func() error { return injected }
	if err := fd.Sync(e.ctx); err == nil {
		t.Fatalf("Sync with failing host flush returned nil")
	} else if !linuxerr.Equals(linuxerr.EIO, err) {
		t.Fatalf("Sync error = %v, want EIO", err)
	}
	// O_SYNC writes report no progress when the flush fails.
	sfd := e.mustOpen("s", linux.O_RDWR|linux.O_SYNC)
	defer sfd.DecRef(e.ctx)
	sfd.Impl().(*regularFD).h.syncFn = func() error { return injected }
	n, err := sfd.Write(e.ctx, usermem.BytesIOSequence([]byte("more")), vfs.WriteOptions{})
	if err == nil || n != 0 {
		t.Fatalf("O_SYNC write with failing flush = (%d, %v), want (0, error)", n, err)
	}
}

func TestMappedWriteBackFailureSurfacesAtSyncAndClose(t *testing.T) {
	forEachChunkMode(t, testMappedWriteBackFailureSurfacesAtSyncAndClose)
}

func testMappedWriteBackFailureSurfacesAtSyncAndClose(t *testing.T, e *env) {
	e.writeFile("w", bytes.Repeat([]byte("q"), hostarch.PageSize))
	fd := e.mustOpen("w", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, hostarch.PageSize, true)
	ts, err := m.Translate(e.ctx, memmap.MappableRange{Start: 0, End: hostarch.PageSize}, memmap.MappableRange{Start: 0, End: hostarch.PageSize}, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	bs, err := ts[0].File.MapInternal(memmap.FileRange{Start: ts[0].Offset, End: ts[0].Offset + 4}, hostarch.ReadWrite)
	if err != nil {
		t.Fatal(err)
	}
	copy(bs.Head().ToSlice(), "boom")
	// Closing the host handle makes the write-back fail, which models a
	// full disk or a revoked handle.
	if err := fd.Impl().(*regularFD).h.f.Close(); err != nil {
		t.Fatal(err)
	}
	m.RemoveMapping(e.ctx, ms, ar, 0, true)
	if err := fd.OnClose(e.ctx); err == nil {
		t.Fatalf("OnClose after a failed write-back returned nil")
	}
	if err := fd.OnClose(e.ctx); err != nil {
		t.Fatalf("a reported write-back failure repeated: %v", err)
	}
}

func TestMetadataFlushIsAtomicUnderCrash(t *testing.T) {
	dir := t.TempDir()
	crash := errors.New("simulated crash before rename")
	ws, err := openWorkspace(dir, false, workspaceOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := ws.WriteFile("f", []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := ws.Sync(); err != nil {
		t.Fatalf("first Sync: %v", err)
	}
	ws.beforeMetaRename = func() error { return crash }
	if err := ws.Chmod("f", 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ws.Sync(); !errors.Is(err, crash) {
		t.Fatalf("Sync = %v, want the simulated crash", err)
	}

	// A new process loads the previous complete table.
	again, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatalf("reload after crash: %v", err)
	}
	attr, _, err := again.Stat("f")
	if err != nil || attr.Mode&0o7777 != 0o640 {
		t.Fatalf("reloaded mode = (%+v, %v), want the old 0640", attr, err)
	}
	if got, err := again.ListEntries(); err != nil || len(got) != 1 || got[0] != "f" {
		t.Fatalf("listing = (%v, %v): metadata files must stay hidden", got, err)
	}
	_ = again.Close()

	// The crash left a torn temporary file. It never replaces the table, and
	// the next successful flush overwrites it.
	if err := os.WriteFile(dir+"/"+metaTempName, []byte(`{"version":1,"entr`), 0o600); err != nil {
		t.Fatal(err)
	}
	ws.beforeMetaRename = nil
	if err := ws.Sync(); err != nil {
		t.Fatalf("Sync after crash: %v", err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = final.Close() }()
	if attr, _, err := final.Stat("f"); err != nil || attr.Mode&0o7777 != 0o600 {
		t.Fatalf("final mode = (%+v, %v), want 0600", attr, err)
	}
	if _, err := os.Stat(dir + "/" + metaTempName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary file remains after a successful flush: %v", err)
	}
}

func TestMetadataWritesCoalesceAndFlushOnSync(t *testing.T) {
	dir := t.TempDir()
	var renames int
	var mu sync.Mutex
	ws, err := openWorkspace(dir, false, workspaceOptions{
		coalesce: 1 << 62, // The timer never fires, so only Sync and Close flush.
		beforeMetaRename: func() error {
			mu.Lock()
			renames++
			mu.Unlock()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 40 {
		if err := ws.WriteFile(fmt.Sprintf("f%d", i), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	before := renames
	mu.Unlock()
	if before != 0 {
		t.Fatalf("%d table writes happened before Sync", before)
	}
	if err := ws.Sync(); err != nil {
		t.Fatal(err)
	}
	if err := ws.Sync(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := renames
	mu.Unlock()
	if got != 1 {
		t.Fatalf("40 mutations and two Syncs caused %d table writes, want 1", got)
	}
	if err := ws.WriteFile("late", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	reloaded, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reloaded.Close() }()
	if attr, _, err := reloaded.Stat("late"); err != nil || attr.Mode&0o7777 != 0o600 {
		t.Fatalf("mutation before Close was lost: (%+v, %v)", attr, err)
	}
}

func TestMetadataFlushesInTheBackground(t *testing.T) {
	dir := t.TempDir()
	flushed := make(chan struct{}, 8)
	ws, err := openWorkspace(dir, false, workspaceOptions{
		coalesce: 1,
		beforeMetaRename: func() error {
			flushed <- struct{}{}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	if err := ws.WriteFile("bg", []byte("x"), 0o611); err != nil {
		t.Fatal(err)
	}
	<-flushed
	// The hook runs before the rename, so wait for the flush to finish by
	// requesting another one, which serialises behind the first.
	if err := ws.Sync(); err != nil {
		t.Fatal(err)
	}
	other, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = other.Close() }()
	if attr, _, err := other.Stat("bg"); err != nil || attr.Mode&0o7777 != 0o611 {
		t.Fatalf("background flush did not persist: (%+v, %v)", attr, err)
	}
}

func TestWorkspaceRejectsInvalidMetadataFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/"+MetaFileName, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if ws, err := OpenWorkspace(dir, false); err == nil {
		_ = ws.Close()
		t.Fatalf("OpenWorkspace accepted a corrupt metadata file")
	}
	if err := os.WriteFile(dir+"/"+MetaFileName, []byte(`{"version":99,"entries":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if ws, err := OpenWorkspace(dir, false); err == nil {
		_ = ws.Close()
		t.Fatalf("OpenWorkspace accepted an unknown metadata version")
	}
}

func TestReadOnlyWorkspaceRejectsMutationsThroughTheVFS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/f", []byte("ro"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	if got := e.readFile("f"); string(got) != "ro" {
		t.Fatalf("read = %q", got)
	}
	_, err = e.open("g", linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create on read-only workspace", err, linuxerr.EROFS)
	wantErrno(t, "unlink on read-only workspace", e.unlink("f"), linuxerr.EROFS)
	wantErrno(t, "mkdir on read-only workspace", e.mkdir("d"), linuxerr.EROFS)
	wantErrno(t, "rename on read-only workspace", e.rename("f", "h"), linuxerr.EROFS)
	wantErrno(t, "chmod on read-only workspace", e.setStat("f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}), linuxerr.EROFS)
}

func TestVirtualMetadataUpdatesCtimeAndClearsBlockSocketPrivileges(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("data"))
	if err := e.link("f", "f_link"); err != nil {
		t.Fatalf("link: %v", err)
	}
	before := e.mustStat("f")
	time.Sleep(2 * time.Millisecond)

	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatalf("chmod f: %v", err)
	}
	afterF := e.mustStat("f")
	afterLink := e.mustStat("f_link")
	if afterF.Ctime.ToNsec() <= before.Ctime.ToNsec() {
		t.Fatalf("chmod did not advance ctime: before=%d after=%d", before.Ctime.ToNsec(), afterF.Ctime.ToNsec())
	}
	if afterLink.Ctime.ToNsec() != afterF.Ctime.ToNsec() {
		t.Fatalf("hard link ctime mismatch: f=%d f_link=%d", afterF.Ctime.ToNsec(), afterLink.Ctime.ToNsec())
	}

	// Verify ClearPrivs on S_IFBLK (0x6000) and S_IFSOCK (0xc000).
	if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("blk"), &vfs.MknodOptions{
		Mode:     linux.FileMode(linux.S_IFBLK | linux.S_ISUID | linux.S_ISGID | 0o770),
		DevMajor: 1,
		DevMinor: 2,
	}); err != nil {
		t.Fatalf("mknod blk: %v", err)
	}
	if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("sock"), &vfs.MknodOptions{
		Mode: linux.FileMode(linux.S_IFSOCK | linux.S_ISUID | linux.S_ISGID | 0o770),
	}); err != nil {
		t.Fatalf("mknod sock: %v", err)
	}
	for _, name := range []string{"blk", "sock"} {
		if err := e.vfsObj.SetStatAt(e.ctx, e.creds, e.pop(name), &vfs.SetStatOptions{
			Stat:       linux.Statx{Mask: linux.STATX_UID, UID: 1000},
			ClearPrivs: true,
		}); err != nil {
			t.Fatalf("chown %s: %v", name, err)
		}
		if got := e.mustStat(name).Mode & (linux.S_ISUID | linux.S_ISGID); got != 0 {
			t.Fatalf("%s retained set-ID bits %#o after ClearPrivs", name, got)
		}
	}
}

func TestVirtualSymlinkUpdatesParentDirMtimeAndCtime(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("dir")
	t0 := e.mustStat("dir")
	time.Sleep(2 * time.Millisecond)

	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("dir/sym"), "target"); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	t1 := e.mustStat("dir")
	if t1.Mtime.ToNsec() <= t0.Mtime.ToNsec() || t1.Ctime.ToNsec() <= t0.Ctime.ToNsec() {
		t.Fatalf("symlink did not advance dir mtime/ctime: before=(%d,%d) after=(%d,%d)",
			t0.Mtime.ToNsec(), t0.Ctime.ToNsec(), t1.Mtime.ToNsec(), t1.Ctime.ToNsec())
	}

	time.Sleep(2 * time.Millisecond)
	if err := e.unlink("dir/sym"); err != nil {
		t.Fatalf("unlink sym: %v", err)
	}
	t2 := e.mustStat("dir")
	if t2.Mtime.ToNsec() <= t1.Mtime.ToNsec() || t2.Ctime.ToNsec() <= t1.Ctime.ToNsec() {
		t.Fatalf("unlink sym did not advance dir mtime/ctime: before=(%d,%d) after=(%d,%d)",
			t1.Mtime.ToNsec(), t1.Ctime.ToNsec(), t2.Mtime.ToNsec(), t2.Ctime.ToNsec())
	}

	// Explicit utimensat on the directory can set an earlier mtime.
	past := linux.StatxTimestamp{Sec: 1700000000, Nsec: 0}
	if err := e.setStat("dir", linux.Statx{Mask: linux.STATX_MTIME, Mtime: past}); err != nil {
		t.Fatalf("utimensat dir: %v", err)
	}
	if got := e.mustStat("dir").Mtime.Sec; got != past.Sec {
		t.Fatalf("dir mtime after utimensat = %d, want %d", got, past.Sec)
	}
}

func TestUtimensatOmitPreservesUnchangedTimestamp(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("x"))
	orig := e.mustStat("f")

	const date1 = 1900000000
	const date2 = 1950000000
	if err := e.setStat("f", linux.Statx{
		Mask:  linux.STATX_ATIME,
		Atime: linux.StatxTimestamp{Sec: date1, Nsec: 0},
		Mtime: linux.StatxTimestamp{Nsec: linux.UTIME_OMIT},
	}); err != nil {
		t.Fatalf("utimensat atime only: %v", err)
	}
	st1 := e.mustStat("f")
	if st1.Atime.Sec != date1 || st1.Mtime.Sec != orig.Mtime.Sec {
		t.Fatalf("after atime-only utimensat: atime=%d (want %d), mtime=%d (want %d)",
			st1.Atime.Sec, date1, st1.Mtime.Sec, orig.Mtime.Sec)
	}

	if err := e.setStat("f", linux.Statx{
		Mask:  linux.STATX_MTIME,
		Atime: linux.StatxTimestamp{Nsec: linux.UTIME_OMIT},
		Mtime: linux.StatxTimestamp{Sec: date2, Nsec: 0},
	}); err != nil {
		t.Fatalf("utimensat mtime only: %v", err)
	}
	st2 := e.mustStat("f")
	if st2.Atime.Sec != date1 || st2.Mtime.Sec != date2 {
		t.Fatalf("after mtime-only utimensat: atime=%d (want %d), mtime=%d (want %d)",
			st2.Atime.Sec, date1, st2.Mtime.Sec, date2)
	}
}
