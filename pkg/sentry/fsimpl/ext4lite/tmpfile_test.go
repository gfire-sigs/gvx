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

package ext4lite

import (
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// openTmpfile opens an unnamed file in the directory dir, as open(dir,
// O_TMPFILE|flags, mode) does.
func (e *env) openTmpfile(dir string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return e.vfsObj.OpenAt(e.ctx, e.creds, e.fpop(dir), &vfs.OpenOptions{
		Flags: linux.O_TMPFILE | linux.O_DIRECTORY | flags,
		Mode:  mode,
	})
}

func (e *env) mustOpenTmpfile(dir string, flags uint32, mode linux.FileMode) *vfs.FileDescription {
	e.t.Helper()
	fd, err := e.openTmpfile(dir, flags, mode)
	if err != nil {
		e.t.Fatalf("open %q with O_TMPFILE: %v", dir, err)
	}
	return e.own(fd)
}

// linkDescription links the file of fd as p, as linkat(fd, "", AT_FDCWD, p,
// AT_EMPTY_PATH) does. A link through /proc/self/fd resolves to the same
// dentry.
func (e *env) linkDescription(fd *vfs.FileDescription, p string) error {
	old := &vfs.PathOperation{Root: e.root, Start: fd.VirtualDentry(), Path: fspath.Path{}}
	return e.vfsObj.LinkAt(e.ctx, e.creds, old, e.pop(p))
}

func (e *env) freeBlocks() uint64 {
	e.fs.v.mu.Lock()
	defer e.fs.v.mu.Unlock()
	return e.fs.v.freeBlocksTotal
}

func TestTmpfileHasNoNameAndDiesAtTheLastClose(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	base := e.freeBlocks()
	fd := e.mustOpenTmpfile("d", linux.O_RDWR, 0o640)
	data := pattern(4, 300*1024)
	e.write(fd, data)

	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	if st.Nlink != 0 || st.Mode != linux.S_IFREG|0o640 || st.Size != uint64(len(data)) {
		t.Fatalf("fstat = nlink %d, mode %#o, size %d; want nlink 0, mode %#o, size %d", st.Nlink, st.Mode, st.Size, linux.S_IFREG|0o640, len(data))
	}
	if names := e.readdir("d"); len(names) != 0 {
		t.Fatalf("the directory lists %v, want no entry", names)
	}
	wantBytes(t, "content of the open file", e.readAll(fd), data)
	if got := e.freeBlocks(); got >= base {
		t.Fatalf("free blocks %d with the file open, want fewer than %d", got, base)
	}

	e.closeOwned()
	if got := e.freeBlocks(); got < base {
		t.Fatalf("free blocks %d after the last close, want at least %d: the file must free its blocks", got, base)
	}
	requireCleanImage(t, e)
}

func TestTmpfileLinksWithAnEmptyPath(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	fd := e.mustOpenTmpfile("d", linux.O_RDWR, 0o600)
	data := pattern(6, 50_000)
	e.write(fd, data)

	if err := e.linkDescription(fd, "d/named"); err != nil {
		t.Fatalf("link of an O_TMPFILE file: %v", err)
	}
	if st := e.mustStat("d/named"); st.Nlink != 1 || st.Size != uint64(len(data)) {
		t.Fatalf("named file: nlink %d, size %d; want nlink 1, size %d", st.Nlink, st.Size, len(data))
	}
	// The description keeps working, and a second name is a hard link.
	e.pwrite(fd, []byte("late"), 0)
	copy(data, "late")
	wantBytes(t, "content through the name", e.readFile("d/named"), data)
	if err := e.linkDescription(fd, "d/second"); err != nil {
		t.Fatalf("second link of the file: %v", err)
	}
	if st := e.mustStat("d/second"); st.Nlink != 2 {
		t.Fatalf("nlink %d after the second link, want 2", st.Nlink)
	}

	e = requireCleanImage(t, e)
	wantBytes(t, "content after a remount", e.readFile("d/second"), data)
	if st := e.mustStat("d/named"); st.Nlink != 2 {
		t.Fatalf("nlink %d after a remount, want 2", st.Nlink)
	}
}

func TestTmpfileWithExclRefusesALink(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmpfile(".", linux.O_RDWR|linux.O_EXCL, 0o600)
	e.write(fd, []byte("data"))
	wantErrno(t, "link of an O_TMPFILE|O_EXCL file", e.linkDescription(fd, "named"), linuxerr.ENOENT)
	if names := e.readdir("."); len(names) != 0 {
		t.Fatalf("the root lists %v, want no entry", names)
	}
}

func TestUnlinkedFileStillRefusesALink(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("data"))
	fd := e.own(e.mustOpen("f", linux.O_RDWR))
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	wantErrno(t, "link of an unlinked file", e.linkDescription(fd, "g"), linuxerr.ENOENT)
}

func TestTmpfileUsesTheCallerAndTheGroupOfTheDirectory(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	if err := e.setStat("d", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_GID, Mode: 0o2777, GID: 77}); err != nil {
		t.Fatal(err)
	}
	user := userCreds(1000, 1000)
	fd, err := e.vfsObj.OpenAt(e.ctx, user, e.fpop("d"), &vfs.OpenOptions{Flags: linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_WRONLY, Mode: 0o4000})
	if err != nil {
		t.Fatalf("open by an unprivileged user: %v", err)
	}
	e.own(fd)
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil {
		t.Fatal(err)
	}
	if st.UID != 1000 || st.GID != 77 || st.Mode&0o7777 != 0o4000 {
		t.Fatalf("owner %d:%d with mode %#o, want 1000:77 with mode %#o", st.UID, st.GID, st.Mode&0o7777, 0o4000)
	}
	// A file that O_TMPFILE creates opens for writing even with mode 0.
	e.write(fd, []byte("x"))
}

func TestTmpfileNeedsAWritableDirectory(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("closed")
	if err := e.setStat("closed", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o555}); err != nil {
		t.Fatal(err)
	}
	user := userCreds(1000, 1000)
	_, err := e.vfsObj.OpenAt(e.ctx, user, e.fpop("closed"), &vfs.OpenOptions{Flags: linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_RDWR, Mode: 0o600})
	wantErrno(t, "O_TMPFILE in a directory without write permission", err, linuxerr.EACCES)

	e.writeFile("plain", []byte("x"))
	_, err = e.openTmpfile("plain", linux.O_RDWR, 0o600)
	wantErrno(t, "O_TMPFILE on a regular file", err, linuxerr.ENOTDIR)

	_, err = e.openTmpfile("missing", linux.O_RDWR, 0o600)
	wantErrno(t, "O_TMPFILE in a missing directory", err, linuxerr.ENOENT)
}

func TestTmpfileInARemovedDirectoryFails(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("gone")
	dir := e.own(e.mustOpen("gone", linux.O_RDONLY|linux.O_DIRECTORY))
	if err := e.rmdir("gone"); err != nil {
		t.Fatal(err)
	}
	pop := &vfs.PathOperation{Root: e.root, Start: dir.VirtualDentry(), Path: fspath.Path{}}
	_, err := e.vfsObj.OpenAt(e.ctx, e.creds, pop, &vfs.OpenOptions{Flags: linux.O_TMPFILE | linux.O_DIRECTORY | linux.O_RDWR, Mode: 0o600})
	wantErrno(t, "O_TMPFILE in a removed directory", err, linuxerr.ENOENT)
}

func TestTmpfileNeedsAWritableVolume(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("x"))
	e = e.remount()
	e.unmount()
	ro := openEnv(t, e.path, VolumeOptions{ReadOnly: true}, vfs.MountOptions{})
	_, err := ro.openTmpfile(".", linux.O_RDWR, 0o600)
	wantErrno(t, "O_TMPFILE on a read-only volume", err, linuxerr.EROFS)
}

// TestCrashLeavesNoTmpfileBehind clones the image while an unnamed file is
// open. The clone is the disk after a power failure. The orphan list names the
// file, so the next mount frees its blocks, and e2fsck finds nothing wrong.
func TestCrashLeavesNoTmpfileBehind(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/keep", pattern(1, 20_000))
	if err := e.fs.syncAll(); err != nil {
		t.Fatal(err)
	}
	// A mount counts the free blocks differently from a running volume, so the
	// reference is a mount of the image before the unnamed file exists.
	base := openEnv(t, cloneImage(t, e.fs.v), VolumeOptions{}, vfs.MountOptions{}).freeBlocks()
	fd := e.mustOpenTmpfile("d", linux.O_RDWR, 0o600)
	e.write(fd, pattern(2, 500_000))
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.freeBlocks(); got >= base {
		t.Fatalf("free blocks %d with the unnamed file on disk, want fewer than %d", got, base)
	}

	// e2fsck changes its copy, so the engine mounts a second copy.
	requireRecoverableImage(t, cloneImage(t, e.fs.v))
	c := openEnv(t, cloneImage(t, e.fs.v), VolumeOptions{}, vfs.MountOptions{})
	if got := c.freeBlocks(); got != base {
		t.Fatalf("free blocks %d after the crash, want %d: the mount must free the unnamed file", got, base)
	}
	if names := c.readdir("d"); len(names) != 1 || names[0] != "keep" {
		t.Fatalf("directory after the crash lists %v, want [keep]", names)
	}
	wantBytes(t, "durable file", c.readFile("d/keep"), pattern(1, 20_000))
}

// TestCrashAfterLinkKeepsTheNamedFile links an unnamed file after its orphan
// entry reached the disk, flushes, and clones the image. The inode left the
// orphan list, so the clone holds a normal file, and e2fsck must find no
// inode with a deletion time and a link. A second unnamed file stays open, so
// the first inode has a successor in the list, which is the deletion time that
// the link must clear.
func TestCrashAfterLinkKeepsTheNamedFile(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmpfile(".", linux.O_RDWR, 0o600)
	e.mustOpenTmpfile(".", linux.O_RDWR, 0o600)
	data := pattern(3, 100_000)
	e.write(fd, data)
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	if err := e.linkDescription(fd, "named"); err != nil {
		t.Fatal(err)
	}
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}

	clone := cloneImage(t, e.fs.v)
	requireRecoverableImage(t, clone)
	c := openEnv(t, clone, VolumeOptions{}, vfs.MountOptions{})
	wantBytes(t, "named file after the crash", c.readFile("named"), data)
	if st := c.mustStat("named"); st.Nlink != 1 {
		t.Fatalf("nlink %d after the crash, want 1", st.Nlink)
	}
}

// TestTmpfileLinkNeedsOwnershipOrAccess gives a user the descriptor of an
// unnamed file that the user does not own. Like any hard link, the link of such
// a file fails with EPERM when the user can neither read nor write it.
func TestTmpfileLinkNeedsOwnershipOrAccess(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	if err := e.setStat("d", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}); err != nil {
		t.Fatal(err)
	}
	fd := e.mustOpenTmpfile("d", linux.O_RDWR, 0o600)
	user := userCreds(1000, 1000)
	old := &vfs.PathOperation{Root: e.root, Start: fd.VirtualDentry(), Path: fspath.Path{}}
	wantErrno(t, "link of a file that the caller cannot use", e.vfsObj.LinkAt(e.ctx, user, old, e.pop("d/x")), linuxerr.EPERM)
	if names := e.readdir("d"); len(names) != 0 {
		t.Fatalf("the directory lists %v after the refused link", names)
	}
}
