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
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/socket/unix/transport"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

// This file tests the extended operations of GVXIP-001 section 4.1, 4.3, and
// 6: guest symbolic links, RENAME_EXCHANGE, RENAME_WHITEOUT, fallocate,
// O_TMPFILE, the link count of an unlinked file, ETXTBSY, volume space, and
// the durability contract. The platform files hold the host-specific parts.

func (e *env) renameFlags(oldPath, newPath string, flags uint32) error {
	return e.vfsObj.RenameAt(e.ctx, e.creds, e.pop(oldPath), e.pop(newPath), &vfs.RenameOptions{Flags: flags})
}

func (e *env) symlink(p, target string) error {
	return e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop(p), target)
}

func (e *env) readlink(p string) (string, error) {
	return e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop(p))
}

func (e *env) chmod(p string, mode uint16) {
	e.t.Helper()
	if err := e.setStat(p, linux.Statx{Mask: linux.STATX_MODE, Mode: mode}); err != nil {
		e.t.Fatalf("chmod %q: %v", p, err)
	}
}

func (e *env) perm(p string) uint16 {
	e.t.Helper()
	return e.mustStat(p).Mode & 0o7777
}

func (e *env) pwriteAt(fd *vfs.FileDescription, off int64, data string) {
	e.t.Helper()
	if n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte(data)), off, vfs.WriteOptions{}); err != nil || int(n) != len(data) {
		e.t.Fatalf("pwrite(%q) = (%d, %v)", data, n, err)
	}
}

// hostRead returns the content of a host file of the workspace.
func (e *env) hostRead(p string) string {
	e.t.Helper()
	raw, err := os.ReadFile(e.host(p))
	if err != nil {
		e.t.Fatalf("host read %q: %v", p, err)
	}
	return string(raw)
}

// hostEntries lists the names that the host holds in a workspace directory.
func (e *env) hostEntries(p string) []string {
	e.t.Helper()
	ents, err := os.ReadDir(e.host(p))
	if err != nil {
		e.t.Fatalf("host list %q: %v", p, err)
	}
	var names []string
	for _, ent := range ents {
		if ent.Name() == MetaFileName {
			continue
		}
		names = append(names, ent.Name())
	}
	return names
}

// probedCaps returns the capabilities that the probe finds on the test volume.
func probedCaps(t *testing.T) WorkspaceCaps {
	t.Helper()
	ws, err := openWorkspace(resolvedTempDir(t), false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	caps := ws.Caps()
	if err := ws.Close(); err != nil {
		t.Fatal(err)
	}
	return caps
}

// extVariants model the host rules that change how an operation runs. The
// native variant uses the volume of the test host. The others switch the
// translation paths on, so every host exercises them.
var extVariants = []struct {
	name  string
	tweak func(*WorkspaceCaps)
}{
	{"native", func(*WorkspaceCaps) {}},
	{"swapfile", func(c *WorkspaceCaps) { c.NativeRenameSwap = false }},
	{"registry", func(c *WorkspaceCaps) { c.LocksOpenDirMove = true }},
	{"registry-swapfile", func(c *WorkspaceCaps) { c.LocksOpenDirMove = true; c.NativeRenameSwap = false }},
	{"emulated-allocate", func(c *WorkspaceCaps) { c.NativeFallocate = false }},
}

func newExtEnv(t *testing.T, tweak func(*WorkspaceCaps)) *env {
	t.Helper()
	caps := probedCaps(t)
	tweak(&caps)
	return newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow, caps: &caps})
}

// forEachExtVariant runs fn once for each variant that names one of names.
func forEachExtVariant(t *testing.T, names []string, fn func(t *testing.T, e *env)) {
	t.Helper()
	for _, v := range extVariants {
		if !slices.Contains(names, v.name) {
			continue
		}
		t.Run(v.name, func(t *testing.T) { fn(t, newExtEnv(t, v.tweak)) })
	}
}

var exchangeVariants = []string{"native", "swapfile", "registry", "registry-swapfile"}

// ---- Guest symbolic links (section 4.1) ----

func TestGuestSymlinkTargetsAreUnrestricted(t *testing.T) {
	e := newEnv(t)
	for name, target := range map[string]string{
		"python":  "/usr/bin/python3",
		"up":      "../..",
		"deep":    "../../../../etc/passwd",
		"dotroot": "/",
		"long":    "a/b/c/d/e/f/g/../../../../../../../../x",
	} {
		if err := e.symlink(name, target); err != nil {
			t.Fatalf("symlink %q -> %q: %v", name, target, err)
		}
		if got, err := e.readlink(name); err != nil || got != target {
			t.Fatalf("readlink %q = (%q, %v), want %q", name, got, err, target)
		}
		st, err := e.lstat(name)
		if err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK || st.Size != uint64(len(target)) {
			t.Fatalf("lstat %q = (mode %o, size %d, %v)", name, st.Mode&linux.S_IFMT, st.Size, err)
		}
		if _, err := os.Lstat(e.host(name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("symlink %q reached the host: %v", name, err)
		}
	}
	wantErrno(t, "empty target", e.symlink("empty", ""), linuxerr.ENOENT)
	wantErrno(t, "target with NUL", e.symlink("nul", "a\x00b"), linuxerr.EINVAL)
	wantErrno(t, "existing name", e.symlink("python", "/x"), linuxerr.EEXIST)
	if _, err := os.Lstat(e.host("empty")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused symlink left a host entry: %v", err)
	}

	// The host directory holds no link at all.
	for _, name := range e.hostEntries(".") {
		t.Fatalf("host entry %q after guest symlinks, want none", name)
	}
}

// TestGuestSymlinkResolvesInTheGuestNamespace proves that the VFS resolves a
// target in the guest mount namespace. The host file that a climbing target
// names on the host stays unreachable.
func TestGuestSymlinkResolvesInTheGuestNamespace(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(filepath.Dir(e.dir), "outside-secret")
	if err := os.WriteFile(outside, []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	e.mustMkdir("usr")
	e.mustMkdir("usr/bin")
	e.writeFile("usr/bin/python3", []byte("guest python"))
	e.writeFile("outside-secret", []byte("guest file"))
	e.mustMkdir("work")
	if err := e.symlink("work/py", "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	// The name of the host file is the same string. The link climbs above
	// "work" and then above the root of the mount, where ".." stays at the
	// root.
	if err := e.symlink("work/secret", "../../../outside-secret"); err != nil {
		t.Fatal(err)
	}

	if got := e.readFile("work/py"); string(got) != "guest python" {
		t.Fatalf("read through the absolute link = %q, want the guest file", got)
	}
	if got := e.readFile("work/secret"); string(got) != "guest file" {
		t.Fatalf("read through the climbing link = %q, want the guest file and never the host file", got)
	}

	// With no guest file of that name the climbing link dangles, although a
	// host file of that name exists outside the workspace.
	if err := e.unlink("outside-secret"); err != nil {
		t.Fatal(err)
	}
	_, err := e.open("work/secret", linux.O_RDONLY, 0)
	wantErrno(t, "open of a dangling climbing link", err, linuxerr.ENOENT)
	if raw, err := os.ReadFile(outside); err != nil || string(raw) != "host secret" {
		t.Fatalf("the host file changed: (%q, %v)", raw, err)
	}
	for _, name := range e.hostEntries("work") {
		t.Fatalf("host entry %q in work, want none: guest links never reach the host", name)
	}
}

func TestGuestSymlinkSurvivesAReopen(t *testing.T) {
	dir := resolvedTempDir(t)
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err := e.symlink("python", "/usr/bin/python3"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink("up", "../.."); err != nil {
		t.Fatal(err)
	}
	closeEnv()
	e2, _ := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	for name, want := range map[string]string{"python": "/usr/bin/python3", "up": "../.."} {
		if got, err := e2.readlink(name); err != nil || got != want {
			t.Fatalf("readlink %q after reopen = (%q, %v), want %q", name, got, err, want)
		}
	}
}

// ---- RENAME_EXCHANGE ----

func TestExchangeFiles(t *testing.T) {
	forEachExtVariant(t, exchangeVariants, func(t *testing.T, e *env) {
		e.writeFile("a", []byte("AAAA"))
		e.writeFile("b", []byte("BB"))
		e.chmod("a", 0o600)
		e.chmod("b", 0o640)
		inoA, inoB := e.mustStat("a").Ino, e.mustStat("b").Ino
		fdA := e.mustOpen("a", linux.O_RDWR)
		defer fdA.DecRef(e.ctx)
		fdB := e.mustOpen("b", linux.O_RDWR)
		defer fdB.DecRef(e.ctx)

		if err := e.renameFlags("a", "b", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if got := e.readFile("a"); string(got) != "BB" {
			t.Fatalf("a = %q, want BB", got)
		}
		if got := e.readFile("b"); string(got) != "AAAA" {
			t.Fatalf("b = %q, want AAAA", got)
		}
		// The metadata travels with the object.
		if got := e.perm("a"); got != 0o640 {
			t.Fatalf("mode of a = %o, want 640", got)
		}
		if got := e.perm("b"); got != 0o600 {
			t.Fatalf("mode of b = %o, want 600", got)
		}
		if got := e.mustStat("a").Ino; got != inoB {
			t.Fatalf("inode of a = %d, want %d", got, inoB)
		}
		if got := e.mustStat("b").Ino; got != inoA {
			t.Fatalf("inode of b = %d, want %d", got, inoA)
		}
		// The host holds the swapped content under the same names.
		if got := e.hostRead("a"); got != "BB" {
			t.Fatalf("host a = %q, want BB", got)
		}
		// Open descriptors follow their file to the other name.
		if got := e.readAll(fdA); string(got) != "AAAA" {
			t.Fatalf("descriptor of the old a reads %q, want AAAA", got)
		}
		e.pwriteAt(fdA, 0, "Z")
		if got := e.readFile("b"); string(got) != "ZAAA" {
			t.Fatalf("b after a write through the old descriptor of a = %q, want ZAAA", got)
		}
		if e.ws.handles != nil {
			if got := e.registered(fdA); got != "b" {
				t.Fatalf("registered path of the old a = %q, want b", got)
			}
			if got := e.registered(fdB); got != "a" {
				t.Fatalf("registered path of the old b = %q, want a", got)
			}
		}
		// The metadata reaches the table on disk.
		if err := e.ws.Sync(); err != nil {
			t.Fatal(err)
		}
		ws2, err := openWorkspace(e.dir, true, workspaceOptions{coalesce: defaultCoalesceWindow})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ws2.Close() }()
		if attr, _, err := ws2.Stat("a"); err != nil || attr.Mode&0o7777 != 0o640 {
			t.Fatalf("reloaded mode of a = (%+v, %v), want 640", attr, err)
		}
	})
}

func TestExchangeDirectories(t *testing.T) {
	forEachExtVariant(t, exchangeVariants, func(t *testing.T, e *env) {
		e.mustMkdir("d1")
		e.mustMkdir("d1/sub")
		e.mustMkdir("d2")
		e.writeFile("d1/x", []byte("x1"))
		e.writeFile("d1/sub/y", []byte("y1"))
		e.writeFile("d2/z", []byte("z2"))
		e.chmod("d1/x", 0o600)
		e.chmod("d1", 0o700)
		e.chmod("d2", 0o750)
		// Warm the caches with the old names.
		e.mustStat("d1/sub/y")
		e.mustStat("d2/z")
		fdX := e.mustOpen("d1/x", linux.O_RDWR)
		defer fdX.DecRef(e.ctx)
		fdY := e.mustOpen("d1/sub/y", linux.O_RDWR)
		defer fdY.DecRef(e.ctx)
		dirFD := e.mustOpen("d1", linux.O_RDONLY|linux.O_DIRECTORY)
		defer dirFD.DecRef(e.ctx)

		if err := e.renameFlags("d1", "d2", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if got := e.readdir("d1"); !slices.Equal(got, []string{"z"}) {
			t.Fatalf("d1 = %v, want [z]", got)
		}
		if got := e.readdir("d2"); !slices.Equal(got, []string{"sub", "x"}) {
			t.Fatalf("d2 = %v, want [sub x]", got)
		}
		if got := e.readFile("d2/x"); string(got) != "x1" {
			t.Fatalf("d2/x = %q, want x1", got)
		}
		if got := e.readFile("d2/sub/y"); string(got) != "y1" {
			t.Fatalf("d2/sub/y = %q, want y1", got)
		}
		if got := e.readFile("d1/z"); string(got) != "z2" {
			t.Fatalf("d1/z = %q, want z2", got)
		}
		if got := e.perm("d2"); got != 0o700 {
			t.Fatalf("mode of d2 = %o, want 700 (the mode of the old d1)", got)
		}
		if got := e.perm("d1"); got != 0o750 {
			t.Fatalf("mode of d1 = %o, want 750", got)
		}
		if got := e.perm("d2/x"); got != 0o600 {
			t.Fatalf("mode of d2/x = %o, want 600", got)
		}
		e.mustStat("d1/z")
		wantErrno(t, "old name below the swapped directory", func() error { _, err := e.stat("d1/x"); return err }(), linuxerr.ENOENT)

		// Descriptors of files below the directory follow it.
		e.pwriteAt(fdX, 0, "X")
		if got := e.hostRead("d2/x"); got != "X1" {
			t.Fatalf("host d2/x = %q, want X1", got)
		}
		if got := e.pread(fdY, 0, 2); string(got) != "y1" {
			t.Fatalf("descriptor below the swapped directory reads %q, want y1", got)
		}
		if e.ws.handles != nil {
			if got := e.registered(fdX); got != "d2/x" {
				t.Fatalf("registered path of x = %q, want d2/x", got)
			}
			if got := e.registered(fdY); got != "d2/sub/y" {
				t.Fatalf("registered path of y = %q, want d2/sub/y", got)
			}
		}
		// The open directory description lists the content of its object.
		var names []string
		err := dirFD.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
			if d.Name != "." && d.Name != ".." {
				names = append(names, d.Name)
			}
			return nil
		}))
		if err != nil {
			t.Fatal(err)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"sub", "x"}) {
			t.Fatalf("the old d1 description lists %v, want [sub x]", names)
		}
	})
}

func TestExchangeDirectoryAndFile(t *testing.T) {
	forEachExtVariant(t, exchangeVariants, func(t *testing.T, e *env) {
		e.mustMkdir("dir")
		e.writeFile("dir/inner", []byte("in"))
		e.writeFile("file", []byte("plain"))
		if err := e.renameFlags("dir", "file", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange(dir, file): %v", err)
		}
		if st := e.mustStat("dir"); st.Mode&linux.S_IFMT != linux.S_IFREG {
			t.Fatalf("dir is now mode %o, want a file", st.Mode&linux.S_IFMT)
		}
		if got := e.readFile("dir"); string(got) != "plain" {
			t.Fatalf("dir = %q, want plain", got)
		}
		if st := e.mustStat("file"); st.Mode&linux.S_IFMT != linux.S_IFDIR {
			t.Fatalf("file is now mode %o, want a directory", st.Mode&linux.S_IFMT)
		}
		if got := e.readFile("file/inner"); string(got) != "in" {
			t.Fatalf("file/inner = %q, want in", got)
		}
		// The other order swaps back.
		if err := e.renameFlags("file", "dir", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange(file, dir): %v", err)
		}
		if got := e.readFile("dir/inner"); string(got) != "in" {
			t.Fatalf("dir/inner after the second swap = %q", got)
		}
		if got := e.readFile("file"); string(got) != "plain" {
			t.Fatalf("file after the second swap = %q", got)
		}
	})
}

func TestExchangeAcrossParents(t *testing.T) {
	forEachExtVariant(t, exchangeVariants, func(t *testing.T, e *env) {
		e.mustMkdir("p")
		e.mustMkdir("q")
		e.mustMkdir("p/dir")
		e.writeFile("p/dir/f", []byte("deep"))
		e.writeFile("q/leaf", []byte("leaf"))
		if err := e.renameFlags("p/dir", "q/leaf", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange: %v", err)
		}
		if got := e.readFile("q/leaf/f"); string(got) != "deep" {
			t.Fatalf("q/leaf/f = %q, want deep", got)
		}
		if got := e.readFile("p/dir"); string(got) != "leaf" {
			t.Fatalf("p/dir = %q, want leaf", got)
		}
		if got := e.readdir("p"); !slices.Equal(got, []string{"dir"}) {
			t.Fatalf("p = %v", got)
		}
		if got := e.readdir("q"); !slices.Equal(got, []string{"leaf"}) {
			t.Fatalf("q = %v", got)
		}
	})
}

func TestExchangeWithVirtualSymlinks(t *testing.T) {
	forEachExtVariant(t, exchangeVariants, func(t *testing.T, e *env) {
		e.writeFile("f", []byte("file"))
		e.mustMkdir("d")
		e.writeFile("d/child", []byte("c"))
		if err := e.symlink("s", "/usr/bin/python3"); err != nil {
			t.Fatal(err)
		}
		if err := e.symlink("t", "../.."); err != nil {
			t.Fatal(err)
		}

		// Host entry with a link.
		if err := e.renameFlags("f", "s", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange(file, link): %v", err)
		}
		if got, err := e.readlink("f"); err != nil || got != "/usr/bin/python3" {
			t.Fatalf("readlink f = (%q, %v)", got, err)
		}
		if got := e.readFile("s"); string(got) != "file" {
			t.Fatalf("s = %q, want file", got)
		}
		if _, err := os.Lstat(e.host("f")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the link reached the host under f: %v", err)
		}
		// Directory with a link.
		if err := e.renameFlags("d", "t", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange(dir, link): %v", err)
		}
		if got, err := e.readlink("d"); err != nil || got != "../.." {
			t.Fatalf("readlink d = (%q, %v)", got, err)
		}
		if got := e.readFile("t/child"); string(got) != "c" {
			t.Fatalf("t/child = %q, want c", got)
		}
		// Two links.
		if err := e.renameFlags("f", "d", linux.RENAME_EXCHANGE); err != nil {
			t.Fatalf("exchange(link, link): %v", err)
		}
		if got, err := e.readlink("f"); err != nil || got != "../.." {
			t.Fatalf("readlink f = (%q, %v)", got, err)
		}
		if got, err := e.readlink("d"); err != nil || got != "/usr/bin/python3" {
			t.Fatalf("readlink d = (%q, %v)", got, err)
		}
	})
}

func TestExchangeRules(t *testing.T) {
	forEachExtVariant(t, []string{"native", "swapfile"}, func(t *testing.T, e *env) {
		e.writeFile("a", []byte("a"))
		e.writeFile("b", []byte("b"))
		e.mustMkdir("d")
		e.mustMkdir("d/inner")
		e.writeFile("d/x", []byte("x"))
		x := uint32(linux.RENAME_EXCHANGE)

		wantErrno(t, "missing new name", e.renameFlags("a", "missing", x), linuxerr.ENOENT)
		wantErrno(t, "missing old name", e.renameFlags("missing", "a", x), linuxerr.ENOENT)
		wantErrno(t, "directory into itself", e.renameFlags("d", "d/inner", x), linuxerr.EINVAL)
		wantErrno(t, "inner directory with the outer", e.renameFlags("d/inner", "d", x), linuxerr.EINVAL)
		wantErrno(t, "with RENAME_NOREPLACE", e.renameFlags("a", "b", x|linux.RENAME_NOREPLACE), linuxerr.EINVAL)
		wantErrno(t, "with RENAME_WHITEOUT", e.renameFlags("a", "b", x|linux.RENAME_WHITEOUT), linuxerr.EINVAL)
		wantErrno(t, "unknown flag", e.renameFlags("a", "b", 1<<20), linuxerr.EINVAL)
		wantErrno(t, "dot", e.renameFlags("a", "d/.", x), linuxerr.EBUSY)
		// A name with a trailing slash must name a directory.
		wantErrno(t, "file named as a directory", e.renameFlags("d", "a/", x), linuxerr.ENOTDIR)
		// Nothing changed.
		if got := e.readFile("a"); string(got) != "a" {
			t.Fatalf("a = %q after refused exchanges", got)
		}

		// Two names of one file stay as they are.
		if err := e.link("a", "a2"); err != nil {
			t.Fatal(err)
		}
		if err := e.renameFlags("a", "a2", x); err != nil {
			t.Fatalf("exchange of two names of one file: %v", err)
		}
		if got := e.readFile("a2"); string(got) != "a" {
			t.Fatalf("a2 = %q", got)
		}
		// A name exchanged with itself is a no-op.
		if err := e.renameFlags("b", "b", x); err != nil {
			t.Fatalf("exchange with itself: %v", err)
		}
	})
}

func TestExchangeNeedsNoPrivilegeAcrossOwners(t *testing.T) {
	e := newEnv(t)
	e.writeFile("a", []byte("a"))
	e.writeFile("b", []byte("b"))
	user := auth.NewUserCredentials(1000, 1000, nil, nil, e.creds.UserNamespace)
	err := e.vfsObj.RenameAt(e.ctx, user, e.pop("a"), e.pop("b"), &vfs.RenameOptions{Flags: linux.RENAME_EXCHANGE})
	wantErrno(t, "exchange in a directory that the user cannot write", err, linuxerr.EACCES)
	if got := e.readFile("a"); string(got) != "a" {
		t.Fatalf("a = %q after the refused exchange", got)
	}
}

func TestExchangeNotifiesBothNamesAndLeavesNoEcho(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/a", []byte("AAAA"))
	w.writeFile("d/b", []byte("BB"))
	w.add("d", hostEventMask)
	w.settle()

	if err := w.renameFlags("d/a", "d/b", linux.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	evs := w.drain()
	want := []string{"MOVED_FROM a", "MOVED_TO b", "MOVED_FROM b", "MOVED_TO a"}
	if got := eventNames(evs); !slices.Equal(got, want) {
		t.Fatalf("exchange events = %q, want %q", got, want)
	}
	// The from and the to event of one rename share a cookie.
	if evs[0].cookie != evs[1].cookie || evs[2].cookie != evs[3].cookie {
		t.Fatalf("cookies %d %d %d %d: from and to of one rename must share a cookie", evs[0].cookie, evs[1].cookie, evs[2].cookie, evs[3].cookie)
	}
	w.sync()
	w.expectNone("echo of the exchange")
}

// ---- RENAME_WHITEOUT ----

func TestRenameWhiteout(t *testing.T) {
	e := newEnv(t)
	e.writeFile("src", []byte("data"))
	e.chmod("src", 0o640)
	if err := e.renameFlags("src", "dst", linux.RENAME_WHITEOUT); err != nil {
		t.Fatalf("rename with whiteout: %v", err)
	}
	if got := e.readFile("dst"); string(got) != "data" {
		t.Fatalf("dst = %q, want data", got)
	}
	if got := e.perm("dst"); got != 0o640 {
		t.Fatalf("mode of dst = %o, want 640", got)
	}
	st, err := e.lstat("src")
	if err != nil {
		t.Fatalf("lstat of the whiteout: %v", err)
	}
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.RdevMajor != 0 || st.RdevMinor != 0 {
		t.Fatalf("whiteout = (mode %o, rdev %d:%d), want a character device 0:0", st.Mode&linux.S_IFMT, st.RdevMajor, st.RdevMinor)
	}
	_, err = e.open("src", linux.O_RDONLY, 0)
	wantErrno(t, "open of the whiteout", err, linuxerr.ENXIO)
	if got := e.readdir("."); !slices.Equal(got, []string{"dst", "src"}) {
		t.Fatalf("listing = %v, want [dst src]", got)
	}
	// The host holds an empty placeholder, so listings stay consistent.
	if fi, err := os.Stat(e.host("src")); err != nil || fi.Size() != 0 {
		t.Fatalf("host placeholder = (%v, %v), want an empty file", fi, err)
	}

	// The whiteout is an entry: it blocks a rename without replacement and
	// goes away with unlink.
	e.writeFile("other", []byte("o"))
	wantErrno(t, "NOREPLACE onto the whiteout", e.renameFlags("other", "src", linux.RENAME_NOREPLACE), linuxerr.EEXIST)
	if err := e.unlink("src"); err != nil {
		t.Fatalf("unlink of the whiteout: %v", err)
	}
	wantErrno(t, "whiteout after unlink", func() error { _, err := e.lstat("src"); return err }(), linuxerr.ENOENT)
	if _, err := os.Lstat(e.host("src")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host placeholder after unlink: %v", err)
	}
}

func TestRenameWhiteoutRules(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("dir")
	e.writeFile("dir/f", []byte("f"))
	e.writeFile("over", []byte("old"))
	e.writeFile("file", []byte("new"))

	// A directory moves with its content, and a whiteout holds the old name.
	if err := e.renameFlags("dir", "moved", linux.RENAME_WHITEOUT); err != nil {
		t.Fatalf("rename of a directory with whiteout: %v", err)
	}
	if got := e.readFile("moved/f"); string(got) != "f" {
		t.Fatalf("moved/f = %q", got)
	}
	if st := e.mustStat("dir"); st.Mode&linux.S_IFMT != linux.S_IFCHR {
		t.Fatalf("old directory name has mode %o, want a whiteout", st.Mode&linux.S_IFMT)
	}
	// A rename over an existing name replaces it, as without the flag.
	if err := e.renameFlags("file", "over", linux.RENAME_WHITEOUT); err != nil {
		t.Fatalf("rename over a file with whiteout: %v", err)
	}
	if got := e.readFile("over"); string(got) != "new" {
		t.Fatalf("over = %q, want new", got)
	}
	// RENAME_NOREPLACE combines with the whiteout.
	e.writeFile("n1", []byte("n"))
	if err := e.renameFlags("n1", "n2", linux.RENAME_WHITEOUT|linux.RENAME_NOREPLACE); err != nil {
		t.Fatalf("whiteout with NOREPLACE: %v", err)
	}
	e.writeFile("n3", []byte("n"))
	wantErrno(t, "whiteout with NOREPLACE onto a name", e.renameFlags("n3", "n2", linux.RENAME_WHITEOUT|linux.RENAME_NOREPLACE), linuxerr.EEXIST)
	if got := e.readFile("n3"); string(got) != "n" {
		t.Fatalf("n3 = %q after the refused rename", got)
	}

	// A caller without CAP_MKNOD gets EPERM, and nothing moves.
	user := auth.NewUserCredentials(1000, 1000, nil, nil, e.creds.UserNamespace)
	err := e.vfsObj.RenameAt(e.ctx, user, e.pop("n3"), e.pop("n4"), &vfs.RenameOptions{Flags: linux.RENAME_WHITEOUT})
	wantErrno(t, "whiteout without CAP_MKNOD", err, linuxerr.EPERM)
	if got := e.readFile("n3"); string(got) != "n" {
		t.Fatalf("n3 = %q after the refused rename", got)
	}
}

func TestRenameWhiteoutPersistsAndLeavesNoEcho(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/src", []byte("s"))
	w.add("d", hostEventMask)
	w.settle()
	if err := w.renameFlags("d/src", "d/dst", linux.RENAME_WHITEOUT); err != nil {
		t.Fatal(err)
	}
	if got, want := eventNames(w.drain()), []string{"MOVED_FROM src", "MOVED_TO dst"}; !slices.Equal(got, want) {
		t.Fatalf("whiteout rename events = %q, want %q", got, want)
	}
	w.sync()
	w.expectNone("echo of the whiteout rename")

	if err := w.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	ws2, err := openWorkspace(w.dir, true, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws2.Close() }()
	attr, _, err := ws2.Stat("d/src")
	if err != nil || attr.Mode&linux.S_IFMT != linux.S_IFCHR {
		t.Fatalf("reloaded whiteout = (%+v, %v), want a character device", attr, err)
	}
}

// ---- fallocate ----

func allocate(e *env, fd *vfs.FileDescription, mode, off, length uint64) error {
	return fd.Allocate(e.ctx, mode, off, length)
}

const (
	keepSize = linux.FALLOC_FL_KEEP_SIZE
	punch    = linux.FALLOC_FL_PUNCH_HOLE | linux.FALLOC_FL_KEEP_SIZE
)

func TestAllocateModes(t *testing.T) {
	forEachExtVariant(t, []string{"native", "emulated-allocate"}, func(t *testing.T, e *env) {
		content := bytes.Repeat([]byte{0xAB}, 3*hostarch.PageSize)
		e.writeFile("f", content)
		fd := e.mustOpen("f", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		size := func() int64 { return int64(e.mustStat("f").Size) }

		// Mode 0 grows the file and never shrinks it.
		if err := allocate(e, fd, 0, 0, uint64(len(content))/2); err != nil || size() != int64(len(content)) {
			t.Fatalf("allocate inside the file = %v, size %d, want %d", err, size(), len(content))
		}
		if err := allocate(e, fd, 0, uint64(len(content)), 4*hostarch.PageSize); err != nil || size() != int64(len(content)+4*hostarch.PageSize) {
			t.Fatalf("allocate past the end = %v, size %d", err, size())
		}
		if got := e.hostRead("f"); len(got) != len(content)+4*hostarch.PageSize || got[:len(content)] != string(content) {
			t.Fatalf("host file after growth has %d bytes with changed content", len(got))
		}
		if !bytes.Equal(e.pread(fd, int64(len(content)), 16), make([]byte, 16)) {
			t.Fatalf("the grown range does not read as zeros")
		}

		// KEEP_SIZE never moves the end of the file.
		before := size()
		if err := allocate(e, fd, keepSize, uint64(before), 8*hostarch.PageSize); err != nil || size() != before {
			t.Fatalf("allocate with KEEP_SIZE = %v, size %d, want %d", err, size(), before)
		}

		// Everything else is refused.
		wantErrno(t, "PUNCH_HOLE without KEEP_SIZE", allocate(e, fd, linux.FALLOC_FL_PUNCH_HOLE, 0, 10), linuxerr.EOPNOTSUPP)
		wantErrno(t, "ZERO_RANGE", allocate(e, fd, linux.FALLOC_FL_ZERO_RANGE, 0, 10), linuxerr.EOPNOTSUPP)
		wantErrno(t, "COLLAPSE_RANGE", allocate(e, fd, linux.FALLOC_FL_COLLAPSE_RANGE, 0, 10), linuxerr.EOPNOTSUPP)
		wantErrno(t, "zero length", allocate(e, fd, 0, 0, 0), linuxerr.EINVAL)
		wantErrno(t, "huge offset", allocate(e, fd, 0, 1<<63, 1), linuxerr.EINVAL)
		wantErrno(t, "overflowing range", allocate(e, fd, 0, 1<<62, 1<<62), linuxerr.EFBIG)
		ro := e.mustOpen("f", linux.O_RDONLY)
		defer ro.DecRef(e.ctx)
		wantErrno(t, "read-only description", allocate(e, ro, 0, 0, 10), linuxerr.EBADF)
	})
}

func TestAllocatePunchHole(t *testing.T) {
	forEachExtVariant(t, []string{"native", "emulated-allocate"}, func(t *testing.T, e *env) {
		const length = 8 * hostarch.PageSize
		content := bytes.Repeat([]byte{0xAB}, length)
		e.writeFile("f", content)
		fd := e.mustOpen("f", linux.O_RDWR)
		defer fd.DecRef(e.ctx)

		check := func(what string, zeroFrom, zeroTo int) {
			t.Helper()
			want := bytes.Clone(content)
			clear(want[zeroFrom:zeroTo])
			if got := e.pread(fd, 0, length); !bytes.Equal(got, want) {
				t.Fatalf("%s: read content differs from the expectation", what)
			}
			if got := e.hostRead("f"); got != string(want) {
				t.Fatalf("%s: host content differs from the expectation", what)
			}
			if got := e.mustStat("f").Size; got != length {
				t.Fatalf("%s: size = %d, want %d (a punch keeps the size)", what, got, length)
			}
		}
		// A range of whole host pages, then an unaligned range.
		hostPage := os.Getpagesize()
		if err := allocate(e, fd, punch, uint64(hostPage), uint64(hostPage)); err != nil {
			t.Fatalf("punch of a whole page: %v", err)
		}
		copy(content[hostPage:2*hostPage], make([]byte, hostPage))
		check("aligned punch", hostPage, 2*hostPage)
		if err := allocate(e, fd, punch, 100, 300); err != nil {
			t.Fatalf("unaligned punch: %v", err)
		}
		clear(content[100:400])
		check("unaligned punch", 100, 400)
		// A range that runs past the end of the file keeps the size.
		if err := allocate(e, fd, punch, length-100, 1<<20); err != nil {
			t.Fatalf("punch past the end: %v", err)
		}
		clear(content[length-100:])
		check("punch past the end", length-100, length)
	})
}

// TestAllocatePunchHoleKeepsMappedPagesCoherent punches a hole below a
// writable mapping that holds guest writes that no read system call saw.
func TestAllocatePunchHoleKeepsMappedPagesCoherent(t *testing.T) {
	forEachChunkMode(t, func(t *testing.T, e *env) {
		testAllocateMappedCoherence(t, e)
	})
	t.Run("emulated", func(t *testing.T) {
		testAllocateMappedCoherence(t, newExtEnv(t, func(c *WorkspaceCaps) { c.NativeFallocate = false }))
	})
}

func testAllocateMappedCoherence(t *testing.T, e *env) {
	const length = 4 * hostarch.PageSize
	content := bytes.Repeat([]byte("a"), length)
	e.writeFile("m", content)
	fd := e.mustOpen("m", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	m, ms, ar := e.mapFile(fd, length, true)
	defer m.RemoveMapping(e.ctx, ms, ar, 0, true)

	// Guest writes through the mapping, inside and outside the hole.
	copy(mappedView(t, e, m, hostarch.ReadWrite, 0, 4), "KEEP")
	copy(mappedView(t, e, m, hostarch.ReadWrite, hostarch.PageSize+10, 4), "HOLE")
	copy(mappedView(t, e, m, hostarch.ReadWrite, 3*hostarch.PageSize, 4), "TAIL")

	holeStart, holeLen := uint64(hostarch.PageSize), uint64(hostarch.PageSize)
	if err := allocate(e, fd, punch, holeStart, holeLen); err != nil {
		t.Fatalf("punch: %v", err)
	}
	// The mapping sees zeros in the hole and keeps its other pages.
	if got := mappedView(t, e, m, hostarch.ReadWrite, hostarch.PageSize+10, 4); !bytes.Equal(got, make([]byte, 4)) {
		t.Fatalf("mapped hole = %q, want zeros", got)
	}
	if got := mappedView(t, e, m, hostarch.ReadWrite, 0, 4); string(got) != "KEEP" {
		t.Fatalf("mapped page before the hole = %q, want KEEP", got)
	}
	if got := mappedView(t, e, m, hostarch.ReadWrite, 3*hostarch.PageSize, 4); string(got) != "TAIL" {
		t.Fatalf("mapped page after the hole = %q, want TAIL", got)
	}
	// A read system call and the host file agree with the mapping.
	want := bytes.Clone(content)
	copy(want, "KEEP")
	copy(want[3*hostarch.PageSize:], "TAIL")
	clear(want[holeStart : holeStart+holeLen])
	if got := e.pread(fd, 0, length); !bytes.Equal(got, want) {
		t.Fatalf("read after the punch differs from the expectation")
	}
	if got := e.hostRead("m"); got != string(want) {
		t.Fatalf("host file after the punch differs from the expectation")
	}
	// A later mapped write to the hole reaches the host again.
	copy(mappedView(t, e, m, hostarch.ReadWrite, hostarch.PageSize+10, 4), "BACK")
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	if got := e.hostRead("m")[hostarch.PageSize+10 : hostarch.PageSize+14]; got != "BACK" {
		t.Fatalf("host file after a mapped write into the hole = %q, want BACK", got)
	}

	// Growth makes the new pages reachable through the mapping.
	grow := e.mustOpen("m", linux.O_RDWR)
	defer grow.DecRef(e.ctx)
	if err := allocate(e, grow, 0, length, hostarch.PageSize); err != nil {
		t.Fatalf("grow: %v", err)
	}
	m2, ms2, ar2 := e.mapFile(grow, length+hostarch.PageSize, false)
	defer m2.RemoveMapping(e.ctx, ms2, ar2, 0, false)
	if got := mappedView(t, e, m2, hostarch.Read, length, 8); !bytes.Equal(got, make([]byte, 8)) {
		t.Fatalf("mapped page of the grown range = %q, want zeros", got)
	}
}

func TestAllocateLeavesNoEcho(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.writeFile("d/f", bytes.Repeat([]byte("z"), 4*hostarch.PageSize))
	fd := w.mustOpen("d/f", linux.O_RDWR)
	defer fd.DecRef(w.env.ctx)
	w.add("d", hostEventMask)
	w.add("d/f", hostEventMask)
	w.settle()
	hw := &w.ws.watch
	base := hw.delivered.Load()
	for _, step := range []struct {
		name string
		mode uint64
		off  uint64
		n    uint64
	}{
		{"grow", 0, 4 * hostarch.PageSize, 4 * hostarch.PageSize},
		{"keep size", keepSize, 0, 16 * hostarch.PageSize},
		{"punch", punch, 100, 5000},
	} {
		if err := allocate(w.env, fd, step.mode, step.off, step.n); err != nil {
			t.Fatalf("%s: %v", step.name, err)
		}
		w.drain()
		w.sync()
		w.expectNone("echo of " + step.name)
		if got := hw.delivered.Load(); got != base {
			t.Fatalf("%s: the watcher delivered %d notifications for a guest change", step.name, got-base)
		}
	}
}

// ---- O_TMPFILE ----

const tmpFlags = linux.O_TMPFILE | linux.O_DIRECTORY

func (e *env) openTmp(dir string, extra uint32) (*vfs.FileDescription, error) {
	return e.open(dir, tmpFlags|extra, 0o640)
}

func (e *env) mustOpenTmp(dir string, extra uint32) *vfs.FileDescription {
	e.t.Helper()
	fd, err := e.openTmp(dir, extra)
	if err != nil {
		e.t.Fatalf("open %q with O_TMPFILE: %v", dir, err)
	}
	return fd
}

// linkFD links the file that fd holds into the namespace, as linkat with
// AT_EMPTY_PATH or a /proc/self/fd path does.
func (e *env) linkFD(fd *vfs.FileDescription, newPath string) error {
	old := &vfs.PathOperation{Root: e.root, Start: fd.VirtualDentry(), Path: fspath.Path{}}
	return e.vfsObj.LinkAt(e.ctx, e.creds, old, e.pop(newPath))
}

func TestTmpfileCreateWriteReadAndVanish(t *testing.T) {
	for _, dir := range []string{".", "sub"} {
		for _, extra := range []uint32{linux.O_RDWR, linux.O_WRONLY, linux.O_RDWR | linux.O_EXCL} {
			t.Run(dir+"/"+openFlagName(extra), func(t *testing.T) {
				e := newEnv(t)
				e.mustMkdir("sub")
				before := e.hostEntries(dir)
				fd := e.mustOpenTmp(dir, extra)
				if n, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("temporary data")), vfs.WriteOptions{}); err != nil || n != 14 {
					t.Fatalf("write = (%d, %v)", n, err)
				}
				if extra&linux.O_ACCMODE != linux.O_WRONLY {
					buf := make([]byte, 32)
					n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
					if err != nil || string(buf[:n]) != "temporary data" {
						t.Fatalf("read back = (%q, %v)", buf[:n], err)
					}
				}
				st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
				if err != nil {
					t.Fatal(err)
				}
				if st.Nlink != 0 || st.Size != 14 || st.Mode&linux.S_IFMT != linux.S_IFREG || st.Mode&0o7777 != 0o640 {
					t.Fatalf("stat = (nlink %d, size %d, mode %o), want (0, 14, 100640)", st.Nlink, st.Size, st.Mode)
				}
				// The file has no name for the guest.
				if got := e.readdir(dir); len(got) > 1 || (dir == "." && len(got) != 1) {
					t.Fatalf("listing of %q = %v, want only the entries that existed before", dir, got)
				}
				if err := fd.Sync(e.ctx); err != nil {
					t.Fatalf("fsync of a temporary file: %v", err)
				}
				fd.DecRef(e.ctx)
				// The file vanishes with its last reference.
				if got := e.hostEntries(dir); !slices.Equal(got, before) {
					t.Fatalf("host entries of %q after close = %v, want %v", dir, got, before)
				}
			})
		}
	}
}

func openFlagName(f uint32) string {
	switch f {
	case linux.O_RDWR:
		return "rdwr"
	case linux.O_WRONLY:
		return "wronly"
	}
	return "rdwr-excl"
}

func TestTmpfileRules(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("f", []byte("x"))
	_, err := e.openTmp("d", linux.O_RDONLY)
	wantErrno(t, "O_TMPFILE read-only", err, linuxerr.EINVAL)
	_, err = e.openTmp("missing", linux.O_RDWR)
	wantErrno(t, "O_TMPFILE in a missing directory", err, linuxerr.ENOENT)
	_, err = e.openTmp("f", linux.O_RDWR)
	wantErrno(t, "O_TMPFILE below a file", err, linuxerr.ENOTDIR)
	_, err = e.open("d", tmpFlags|linux.O_RDWR|linux.O_CREAT, 0o600)
	wantErrno(t, "O_TMPFILE with O_CREAT", err, linuxerr.EINVAL)
	// A guest cannot see or open the internal name.
	fd := e.mustOpenTmp("d", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	for _, name := range e.hostEntries("d") {
		if _, err := e.stat("d/" + name); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat of the internal name %q = %v, want ENOENT", name, err)
		}
	}
	// Unwritable directories refuse the file.
	user := auth.NewUserCredentials(1000, 1000, nil, nil, e.creds.UserNamespace)
	_, err = e.vfsObj.OpenAt(e.ctx, user, e.fpop("d"), &vfs.OpenOptions{Flags: tmpFlags | linux.O_RDWR, Mode: 0o600})
	wantErrno(t, "O_TMPFILE in a directory the user cannot write", err, linuxerr.EACCES)
}

func TestTmpfileLinkIntoTheNamespace(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.mustMkdir("target")
	fd := e.mustOpenTmp("d", linux.O_RDWR)
	closed := false
	defer func() {
		if !closed {
			fd.DecRef(e.ctx)
		}
	}()
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("keep me")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	e.writeFile("taken", []byte("t"))
	wantErrno(t, "link onto an existing name", e.linkFD(fd, "taken"), linuxerr.EEXIST)
	wantErrno(t, "link into a missing directory", e.linkFD(fd, "nowhere/x"), linuxerr.ENOENT)

	// Link into another directory than the one of the file.
	if err := e.linkFD(fd, "target/named"); err != nil {
		t.Fatalf("link: %v", err)
	}
	if got := e.readFile("target/named"); string(got) != "keep me" {
		t.Fatalf("linked file = %q, want the written data", got)
	}
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Nlink != 1 {
		t.Fatalf("stat after the link = (nlink %d, %v), want 1", st.Nlink, err)
	}
	if got := e.mustStat("target/named"); got.Ino != st.Ino || got.Mode&0o7777 != 0o640 {
		t.Fatalf("linked name = (ino %d, mode %o), want (%d, 640)", got.Ino, got.Mode&0o7777, st.Ino)
	}
	// The description keeps working and now acts on the new name.
	e.pwriteAt(fd, 0, "K")
	if got := e.readFile("target/named"); string(got) != "Keep me" {
		t.Fatalf("linked file after a write through the description = %q", got)
	}
	if err := e.setStat("target/named", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatal(err)
	}
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MTIME, Mtime: linux.StatxTimestamp{Sec: 1_700_000_000}}}); err != nil {
		t.Fatalf("utimens through the description of a linked file: %v", err)
	}
	if got := e.mustStat("target/named").Mtime.Sec; got != 1_700_000_000 {
		t.Fatalf("mtime of the linked file = %d", got)
	}
	// A second link is an ordinary hard link.
	if err := e.linkFD(fd, "second"); err != nil {
		t.Fatalf("second link: %v", err)
	}
	if got := e.mustStat("second"); got.Nlink != 2 {
		t.Fatalf("link count after the second link = %d, want 2", got.Nlink)
	}
	if got := e.hostEntries("d"); len(got) != 0 {
		t.Fatalf("host entries of the directory of the temporary file = %v, want none", got)
	}

	closed = true
	fd.DecRef(e.ctx)
	if got := e.readFile("target/named"); string(got) != "Keep me" {
		t.Fatalf("linked file after the last close = %q", got)
	}
	if got := e.hostEntries("d"); len(got) != 0 {
		t.Fatalf("host entries after the close = %v", got)
	}
	// The record survives a reopen.
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	ws2, err := openWorkspace(e.dir, true, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws2.Close() }()
	if attr, _, err := ws2.Stat("target/named"); err != nil || attr.Mode&0o7777 != 0o600 {
		t.Fatalf("reloaded record = (%+v, %v), want mode 600", attr, err)
	}
}

func TestTmpfileWithExclNeverLinks(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR|linux.O_EXCL)
	defer fd.DecRef(e.ctx)
	wantErrno(t, "link of an O_EXCL file", e.linkFD(fd, "name"), linuxerr.ENOENT)
	if _, err := e.stat("name"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("a refused link created a name: %v", err)
	}
}

func TestTmpfileInAnUnlinkedFileCannotBeLinkedAgain(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := e.linkFD(fd, "a"); err != nil {
		t.Fatal(err)
	}
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	// The last name is gone, and the file is no temporary file any more.
	wantErrno(t, "link of an unlinked file", e.linkFD(fd, "b"), linuxerr.ENOENT)
}

func TestTmpfileMapsAndSurvivesDirectoryRename(t *testing.T) {
	forEachExtVariant(t, []string{"native", "registry"}, func(t *testing.T, e *env) {
		e.mustMkdir("d")
		fd := e.mustOpenTmp("d", linux.O_RDWR)
		defer fd.DecRef(e.ctx)
		e.pwriteAt(fd, 0, "0123456789")
		m, ms, ar := e.mapFile(fd, hostarch.PageSize, true)
		defer m.RemoveMapping(e.ctx, ms, ar, 0, true)
		if got := mappedView(t, e, m, hostarch.ReadWrite, 0, 10); string(got) != "0123456789" {
			t.Fatalf("mapped view = %q", got)
		}
		if err := e.rename("d", "d2"); err != nil {
			t.Fatalf("rename of the directory of an open temporary file: %v", err)
		}
		e.pwriteAt(fd, 0, "AB")
		if got := string(e.pread(fd, 0, 10)); got != "AB23456789" {
			t.Fatalf("read after the rename = %q", got)
		}
		if err := e.linkFD(fd, "d2/named"); err != nil {
			t.Fatalf("link after the rename: %v", err)
		}
		if got := e.readFile("d2/named"); string(got) != "AB23456789" {
			t.Fatalf("linked content = %q", got)
		}
	})
}

func TestTmpfileLeavesNoEcho(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.settle()
	hw := &w.ws.watch
	base := hw.delivered.Load()
	fd := w.mustOpenTmp("d", linux.O_RDWR)
	w.pwriteAt(fd, 0, "data")
	w.drain()
	w.sync()
	w.expectNone("echo of the temporary file")
	if err := w.linkFD(fd, "d/named"); err != nil {
		t.Fatal(err)
	}
	if got, want := eventNames(w.drain()), []string{"CREATE named"}; !slices.Equal(got, want) {
		t.Fatalf("link events = %q, want %q", got, want)
	}
	w.sync()
	w.expectNone("echo of the link")
	fd.DecRef(w.env.ctx)
	w.sync()
	w.expectNone("echo of the close")
	if got := hw.delivered.Load(); got != base {
		t.Fatalf("the watcher delivered %d notifications for guest changes", got-base)
	}
}

// ---- Link count of an unlinked file ----

func TestUnlinkedOpenFileReportsZeroLinks(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("still here"))
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	nlink := func(fd *vfs.FileDescription) uint32 {
		t.Helper()
		st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
		if err != nil {
			t.Fatal(err)
		}
		return st.Nlink
	}
	if got := nlink(fd); got != 1 {
		t.Fatalf("link count before the unlink = %d, want 1", got)
	}
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	if got := nlink(fd); got != 0 {
		t.Fatalf("link count after the unlink = %d, want 0", got)
	}
	if got := e.readAll(fd); string(got) != "still here" {
		t.Fatalf("content through the descriptor = %q", got)
	}
	// A new file of the same name is not the unlinked inode.
	e.writeFile("f", []byte("new"))
	if got := e.mustStat("f").Nlink; got != 1 {
		t.Fatalf("link count of the new file = %d, want 1", got)
	}
}

func TestUnlinkOfOneHardLinkKeepsTheCount(t *testing.T) {
	e := newEnv(t)
	e.writeFile("a", []byte("x"))
	if err := e.link("a", "b"); err != nil {
		t.Fatal(err)
	}
	fd := e.mustOpen("b", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Nlink != 1 {
		t.Fatalf("link count after one unlink = (%d, %v), want 1", st.Nlink, err)
	}
	if err := e.unlink("b"); err != nil {
		t.Fatal(err)
	}
	if st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS}); err != nil || st.Nlink != 0 {
		t.Fatalf("link count after the last unlink = (%d, %v), want 0", st.Nlink, err)
	}
}

func TestRenameOverAnOpenFileReportsZeroLinks(t *testing.T) {
	e := newEnv(t)
	e.writeFile("target", []byte("old"))
	e.writeFile("source", []byte("new"))
	fd := e.mustOpen("target", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	if err := e.rename("source", "target"); err != nil {
		t.Fatal(err)
	}
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Nlink != 0 {
		t.Fatalf("link count of the replaced file = (%d, %v), want 0", st.Nlink, err)
	}
	if got := e.mustStat("target").Nlink; got != 1 {
		t.Fatalf("link count of the new target = %d, want 1", got)
	}
}

// ---- ETXTBSY ----

func TestExecutingFileRefusesWriters(t *testing.T) {
	e := newEnv(t)
	e.writeFile("prog", []byte("#!/bin/sh\n"))
	writer := e.mustOpen("prog", linux.O_RDWR)
	defer writer.DecRef(e.ctx)
	exec := e.mustOpen("prog", linux.O_RDONLY)
	defer exec.DecRef(e.ctx)
	exec.DenyWriteAccess()

	_, err := e.open("prog", linux.O_WRONLY, 0)
	wantErrno(t, "open for writing", err, linuxerr.ETXTBSY)
	_, err = e.open("prog", linux.O_RDWR, 0)
	wantErrno(t, "open for reading and writing", err, linuxerr.ETXTBSY)
	_, err = e.open("prog", linux.O_RDONLY|linux.O_TRUNC, 0)
	wantErrno(t, "O_TRUNC", err, linuxerr.ETXTBSY)
	if fd, err := e.open("prog", linux.O_RDONLY, 0); err != nil {
		t.Fatalf("open for reading: %v", err)
	} else {
		fd.DecRef(e.ctx)
	}
	err = e.vfsObj.SetStatAt(e.ctx, e.creds, e.fpop("prog"), &vfs.SetStatOptions{
		Stat:          linux.Statx{Mask: linux.STATX_SIZE, Size: 0},
		NeedWritePerm: true,
	})
	wantErrno(t, "truncate(2)", err, linuxerr.ETXTBSY)
	// ftruncate(2) on a description opened before the exec is not refused.
	if err := writer.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 5}}); err != nil {
		t.Fatalf("ftruncate: %v", err)
	}

	// A writable shared mapping is refused. Read-only and private ones pass.
	shared := &memmap.MMapOpts{Length: hostarch.PageSize, Perms: hostarch.ReadWrite, MaxPerms: hostarch.ReadWrite}
	wantErrno(t, "writable shared mapping", writer.ConfigureMMap(e.ctx, shared), linuxerr.ETXTBSY)
	private := &memmap.MMapOpts{Length: hostarch.PageSize, Perms: hostarch.ReadWrite, MaxPerms: hostarch.ReadWrite, Private: true}
	if err := writer.ConfigureMMap(e.ctx, private); err != nil {
		t.Fatalf("private writable mapping: %v", err)
	}
	private.MappingIdentity.DecRef(e.ctx)
	readonly := &memmap.MMapOpts{Length: hostarch.PageSize, Perms: hostarch.Read, MaxPerms: hostarch.Read}
	if err := writer.ConfigureMMap(e.ctx, readonly); err != nil {
		t.Fatalf("read-only shared mapping: %v", err)
	}
	readonly.MappingIdentity.DecRef(e.ctx)

	exec.AllowWriteAccess()
	fd := e.mustOpen("prog", linux.O_WRONLY)
	fd.DecRef(e.ctx)
	ok := &memmap.MMapOpts{Length: hostarch.PageSize, Perms: hostarch.ReadWrite, MaxPerms: hostarch.ReadWrite}
	if err := writer.ConfigureMMap(e.ctx, ok); err != nil {
		t.Fatalf("writable shared mapping after the program ended: %v", err)
	}
	ok.MappingIdentity.DecRef(e.ctx)
}

func TestHardLinksShareTheExecutingCount(t *testing.T) {
	e := newEnv(t)
	e.writeFile("prog", []byte("x"))
	if err := e.link("prog", "alias"); err != nil {
		t.Fatal(err)
	}
	exec := e.mustOpen("prog", linux.O_RDONLY)
	defer exec.DecRef(e.ctx)
	exec.DenyWriteAccess()
	_, err := e.open("alias", linux.O_WRONLY, 0)
	wantErrno(t, "write open through another name", err, linuxerr.ETXTBSY)
	exec.AllowWriteAccess()
	fd, err := e.open("alias", linux.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("write open after the program ended: %v", err)
	}
	fd.DecRef(e.ctx)
}

// ---- Volume space ----

func TestStatFSReportsTheHostVolume(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("x"))
	check := func(what string, st linux.Statfs) {
		t.Helper()
		if st.Type != hostfsMagic || st.NameLength != maxFilenameLen {
			t.Fatalf("%s: type %#x name length %d, want %#x and %d", what, st.Type, st.NameLength, hostfsMagic, maxFilenameLen)
		}
		if st.BlockSize <= 0 || st.FragmentSize != st.BlockSize {
			t.Fatalf("%s: block size %d fragment size %d", what, st.BlockSize, st.FragmentSize)
		}
		if st.Blocks == 0 || st.BlocksFree > st.Blocks || st.BlocksAvailable > st.BlocksFree {
			t.Fatalf("%s: blocks %d free %d available %d are not consistent", what, st.Blocks, st.BlocksFree, st.BlocksAvailable)
		}
		if st.Flags&linux.ST_RDONLY != 0 {
			t.Fatalf("%s: a writable mount reports ST_RDONLY", what)
		}
	}
	st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("f"))
	if err != nil {
		t.Fatal(err)
	}
	check("StatFSAt", st)
	fd := e.mustOpen("f", linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	fst, err := fd.StatFS(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("regular file StatFS", fst)
	dir := e.mustOpen(".", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dir.DecRef(e.ctx)
	dst, err := dir.StatFS(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	check("directory StatFS", dst)
	if fst.Blocks != st.Blocks || fst.BlockSize != st.BlockSize || dst.Blocks != st.Blocks {
		t.Fatalf("the three calls report different volumes: %+v %+v %+v", st, fst, dst)
	}
	wantErrno(t, "StatFSAt of a missing name", func() error {
		_, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("missing"))
		return err
	}(), linuxerr.ENOENT)
}

func TestStatFSOfAReadOnlyMountReportsTheFlag(t *testing.T) {
	dir := resolvedTempDir(t)
	rw, err := openWorkspace(dir, false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	if err := rw.WriteFile("f", []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := rw.Close(); err != nil {
		t.Fatal(err)
	}
	ws, err := openWorkspace(dir, true, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.fpop("f"))
	if err != nil || st.Flags&linux.ST_RDONLY == 0 {
		t.Fatalf("StatFSAt of a read-only mount = (flags %#x, %v), want ST_RDONLY", st.Flags, err)
	}
}

// ---- Durability (section 6) ----

func TestCoalesceWindowIs250Milliseconds(t *testing.T) {
	if defaultCoalesceWindow != 250*time.Millisecond {
		t.Fatalf("defaultCoalesceWindow = %v, want 250ms", defaultCoalesceWindow)
	}
}

// metaOnDisk returns the mode that the .gvx_meta file on the host records for
// rel, and whether it records an entry.
func (e *env) metaOnDisk(rel string) (mode uint32, ok bool) {
	e.t.Helper()
	raw, err := os.ReadFile(filepath.Join(e.dir, MetaFileName))
	if errors.Is(err, os.ErrNotExist) {
		return 0, false
	}
	if err != nil {
		e.t.Fatal(err)
	}
	var store metaStoreFile
	if err := json.Unmarshal(raw, &store); err != nil {
		e.t.Fatalf("parse %s: %v", MetaFileName, err)
	}
	m, ok := store.Entries[rel]
	return m.Mode, ok
}

// newSlowFlushEnv mounts a workspace whose coalesce window never ends during
// a test, so only an explicit flush reaches the disk.
func newSlowFlushEnv(t *testing.T, opts workspaceOptions) *env {
	t.Helper()
	opts.coalesce = time.Hour
	return newEnvOpts(t, opts)
}

func TestFsyncBypassesTheCoalesceWindow(t *testing.T) {
	e := newSlowFlushEnv(t, workspaceOptions{})
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("data"))
	e.chmod("d/f", 0o600)
	if _, ok := e.metaOnDisk("d/f"); ok {
		t.Fatal("the table reached the disk before the window ended and before any sync")
	}
	fd := e.mustOpen("d/f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if mode, ok := e.metaOnDisk("d/f"); !ok || mode&0o7777 != 0o600 {
		t.Fatalf("record of d/f on disk after fsync = (%o, %v), want mode 600", mode, ok)
	}
	// fdatasync has the same effect on a later change.
	e.chmod("d/f", 0o640)
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	if mode, _ := e.metaOnDisk("d/f"); mode&0o7777 != 0o640 {
		t.Fatalf("record after the second sync = %o, want 640", mode&0o7777)
	}
}

// syncRecorder records the directories that the workspace flushes.
type syncRecorder struct {
	hostBackend
	dirs []string
}

func (s *syncRecorder) syncDir(rel string) error {
	s.dirs = append(s.dirs, rel)
	return s.hostBackend.syncDir(rel)
}

func (s *syncRecorder) take() []string {
	out := s.dirs
	s.dirs = nil
	return out
}

func TestFsyncFlushesDataFileDirectoryAndTable(t *testing.T) {
	var rec *syncRecorder
	e := newSlowFlushEnv(t, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
		rec = &syncRecorder{hostBackend: b}
		return rec
	}})
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("one"))
	e.chmod("d/f", 0o600)
	fd := e.mustOpen("d/f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	h := fd.Impl().(*regularFD).h
	hostSyncs := 0
	h.syncFn = func() error { hostSyncs++; return nil }

	// A mapped write that no read system call saw.
	m, ms, ar := e.mapFile(fd, hostarch.PageSize, true)
	defer m.RemoveMapping(e.ctx, ms, ar, 0, true)
	copy(mappedView(t, e, m, hostarch.ReadWrite, 0, 3), "MAP")

	rec.take()
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if got := e.hostRead("d/f"); got != "MAP" {
		t.Fatalf("host content after fsync = %q, want the mapped write", got)
	}
	if hostSyncs == 0 {
		t.Fatal("fsync did not flush the host file")
	}
	dirs := rec.take()
	if !slices.Contains(dirs, "d") {
		t.Fatalf("directories flushed by fsync = %v, want the parent directory d", dirs)
	}
	if !slices.Contains(dirs, ".") {
		t.Fatalf("directories flushed by fsync = %v, want the workspace directory for the table", dirs)
	}
	if mode, ok := e.metaOnDisk("d/f"); !ok || mode&0o7777 != 0o600 {
		t.Fatalf("table on disk = (%o, %v)", mode, ok)
	}
}

func TestFsyncReportsEveryFailure(t *testing.T) {
	e := newSlowFlushEnv(t, workspaceOptions{})
	e.writeFile("f", []byte("x"))
	e.chmod("f", 0o600)
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	h := fd.Impl().(*regularFD).h
	h.syncFn = func() error { return errors.New("injected disk failure") }
	wantErrno(t, "fsync with a failing host flush", fd.Sync(e.ctx), linuxerr.EIO)
	h.syncFn = nil
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("fsync after the failure: %v", err)
	}
}

// TestFsyncSurvivesACrashInTheTableWrite uses the crash model of the table
// flush: the hook stops a flush between the write of the temporary file and the
// rename. The old table stays complete, and the next sync succeeds.
func TestFsyncSurvivesACrashInTheTableWrite(t *testing.T) {
	crash := errors.New("crash before the rename")
	var armed bool
	e := newSlowFlushEnv(t, workspaceOptions{beforeMetaRename: func() error {
		if armed {
			return crash
		}
		return nil
	}})
	e.writeFile("f", []byte("x"))
	e.chmod("f", 0o600)
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatal(err)
	}
	if mode, ok := e.metaOnDisk("f"); !ok || mode&0o7777 != 0o600 {
		t.Fatalf("first table = (%o, %v)", mode, ok)
	}

	e.chmod("f", 0o644)
	armed = true
	wantErrno(t, "fsync that crashes in the table write", fd.Sync(e.ctx), linuxerr.EIO)
	if mode, _ := e.metaOnDisk("f"); mode&0o7777 != 0o600 {
		t.Fatalf("table after the crash = mode %o, want the complete old table with 600", mode&0o7777)
	}
	if _, err := os.Lstat(filepath.Join(e.dir, metaTempName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the crashed flush left %s behind: %v", metaTempName, err)
	}
	armed = false
	if err := fd.Sync(e.ctx); err != nil {
		t.Fatalf("fsync after the crash: %v", err)
	}
	if mode, _ := e.metaOnDisk("f"); mode&0o7777 != 0o644 {
		t.Fatalf("table after the retry = mode %o, want 644", mode&0o7777)
	}
}

func TestDirectoryFsyncFlushesTheTable(t *testing.T) {
	var rec *syncRecorder
	e := newSlowFlushEnv(t, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
		rec = &syncRecorder{hostBackend: b}
		return rec
	}})
	e.mustMkdir("p")
	e.mustMkdir("p/d")
	e.chmod("p/d", 0o700)
	dir := e.mustOpen("p/d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dir.DecRef(e.ctx)
	rec.take()
	if err := dir.Sync(e.ctx); err != nil {
		t.Fatalf("fsync of a directory: %v", err)
	}
	if mode, ok := e.metaOnDisk("p/d"); !ok || mode&0o7777 != 0o700 {
		t.Fatalf("table on disk = (%o, %v), want mode 700 for p/d", mode, ok)
	}
	dirs := rec.take()
	for _, want := range []string{"p/d", "p", "."} {
		if !slices.Contains(dirs, want) {
			t.Fatalf("directories flushed by fsync of p/d = %v, missing %q", dirs, want)
		}
	}
}

func TestSynchronousWritesBypassTheWindow(t *testing.T) {
	for _, flag := range []uint32{linux.O_SYNC, linux.O_DSYNC} {
		var rec *syncRecorder
		e := newSlowFlushEnv(t, workspaceOptions{wrapHost: func(b hostBackend) hostBackend {
			rec = &syncRecorder{hostBackend: b}
			return rec
		}})
		e.mustMkdir("d")
		e.writeFile("d/f", []byte("x"))
		e.chmod("d/f", 0o600)
		fd := e.mustOpen("d/f", linux.O_WRONLY|flag)
		h := fd.Impl().(*regularFD).h
		hostSyncs := 0
		h.syncFn = func() error { hostSyncs++; return nil }
		rec.take()

		e.pwriteAt(fd, 0, "sync")
		if hostSyncs != 1 {
			t.Fatalf("flag %#x: host flushes after one write = %d, want 1", flag, hostSyncs)
		}
		if mode, ok := e.metaOnDisk("d/f"); !ok || mode&0o7777 != 0o600 {
			t.Fatalf("flag %#x: table after a synchronous write = (%o, %v), want mode 600", flag, mode, ok)
		}
		if first := rec.take(); !slices.Contains(first, "d") {
			t.Fatalf("flag %#x: directories flushed by the first synchronous write = %v, want d", flag, first)
		}
		e.pwriteAt(fd, 0, "more")
		if second := rec.take(); slices.Contains(second, "d") {
			t.Fatalf("flag %#x: the second synchronous write flushed the directory entry again: %v", flag, second)
		}
		if hostSyncs != 2 {
			t.Fatalf("flag %#x: host flushes after two writes = %d, want 2", flag, hostSyncs)
		}
		// A failing flush reports no progress, as Linux does.
		h.syncFn = func() error { return errors.New("injected disk failure") }
		n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte("lost")), 0, vfs.WriteOptions{})
		if err == nil || n != 0 {
			t.Fatalf("flag %#x: write with a failing flush = (%d, %v), want (0, error)", flag, n, err)
		}
		h.syncFn = nil
		fd.DecRef(e.ctx)
	}
}

func TestFilesystemSyncFlushesTheTable(t *testing.T) {
	e := newSlowFlushEnv(t, workspaceOptions{})
	e.writeFile("f", []byte("x"))
	e.chmod("f", 0o600)
	if _, ok := e.metaOnDisk("f"); ok {
		t.Fatal("the table reached the disk before any sync")
	}
	hfs := e.root.Mount().Filesystem().Impl().(*filesystem)
	if err := hfs.Sync(e.ctx); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if mode, ok := e.metaOnDisk("f"); !ok || mode&0o7777 != 0o600 {
		t.Fatalf("table after sync = (%o, %v)", mode, ok)
	}
}

// ---- More temporary file and exchange cases ----

func TestTmpfileOpensAgainThroughItsDescriptor(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.pwriteAt(fd, 0, "reopen")
	// An open of /proc/self/fd/N resolves to the dentry of the file and opens
	// it again.
	again, err := e.vfsObj.OpenAt(e.ctx, e.creds, &vfs.PathOperation{Root: e.root, Start: fd.VirtualDentry(), Path: fspath.Path{}}, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("open again: %v", err)
	}
	defer again.DecRef(e.ctx)
	if got := e.readAll(again); string(got) != "reopen" {
		t.Fatalf("second description reads %q, want reopen", got)
	}
	// The two descriptions share the file, and the file still has no name.
	e.pwriteAt(fd, 0, "RE")
	if got := e.readAll(again); string(got) != "REopen" {
		t.Fatalf("second description after a write through the first = %q", got)
	}
	if st, err := again.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS}); err != nil || st.Nlink != 0 {
		t.Fatalf("stat of the second description = (nlink %d, %v), want 0", st.Nlink, err)
	}
}

func TestRmdirOfADirectoryWithAnOpenTmpfile(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	fd := e.mustOpenTmp("d", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.pwriteAt(fd, 0, "alive")
	// The unnamed file is no entry, so the directory is empty for the guest.
	if err := e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop("d")); err != nil {
		t.Fatalf("rmdir of a directory that holds an open temporary file: %v", err)
	}
	if got := string(e.pread(fd, 0, 5)); got != "alive" {
		t.Fatalf("temporary file after the rmdir reads %q, want alive", got)
	}
	wantErrno(t, "link into the removed directory", e.linkFD(fd, "x"), linuxerr.ENOENT)
}

func TestTmpfileKeepsItsDirectoryAliveForTheLink(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	fd := e.mustOpenTmp("a/b", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.pwriteAt(fd, 0, "x")
	// Push the cache of the directory away. A prune drops every dentry that
	// only the cache references.
	hfs := e.root.Mount().Filesystem().Impl().(*filesystem)
	hfs.mu.Lock()
	hfs.pruneAt = 1
	hfs.mu.Unlock()
	for i := range 5 {
		e.writeFile(fmt.Sprintf("noise%d", i), []byte("n"))
	}
	if err := e.rename("a", "moved"); err != nil {
		t.Fatal(err)
	}
	if err := e.linkFD(fd, "linked"); err != nil {
		t.Fatalf("link after a prune and a rename of the directory: %v", err)
	}
	if got := e.readFile("linked"); string(got) != "x" {
		t.Fatalf("linked file = %q", got)
	}
}

func TestExchangeOnAWindowsLikeVolume(t *testing.T) {
	e := newEnvOpts(t, volumeOptions(winCaps, true, true, true))
	e.writeFile("aux.c", []byte("reserved"))
	e.writeFile("plain", []byte("plain"))
	e.mustMkdir("Net::dir")
	e.writeFile("Net::dir/f", []byte("f"))
	fd := e.mustOpen("aux.c", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := e.renameFlags("aux.c", "plain", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if got := e.readFile("aux.c"); string(got) != "plain" {
		t.Fatalf("aux.c = %q, want plain", got)
	}
	if got := e.readFile("plain"); string(got) != "reserved" {
		t.Fatalf("plain = %q, want reserved", got)
	}
	if got := e.registered(fd); got != "plain" {
		t.Fatalf("registered path = %q, want plain", got)
	}
	if err := e.renameFlags("Net::dir", "plain", linux.RENAME_EXCHANGE); err != nil {
		t.Fatalf("exchange of a directory with escaped names: %v", err)
	}
	if got := e.readFile("plain/f"); string(got) != "f" {
		t.Fatalf("plain/f = %q, want f", got)
	}
	if got := e.readFile("Net::dir"); string(got) != "reserved" {
		t.Fatalf("Net::dir = %q, want reserved", got)
	}
	if got := e.readdir("."); !slices.Equal(got, []string{"Net::dir", "aux.c", "plain"}) {
		t.Fatalf("listing = %v", got)
	}
	for _, name := range e.hostEntries(".") {
		if isEphemeralName(name) {
			t.Fatalf("host holds the swap file %q after the exchange", name)
		}
	}
}

// TestExchangeFailureLeavesBothNames makes the second rename of the swap file
// path fail. Both names must keep their files.
func TestExchangeFailureLeavesBothNames(t *testing.T) {
	var failing *failNthRename
	caps := probedCaps(t)
	caps.NativeRenameSwap = false
	e := newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow, caps: &caps, wrapHost: func(b hostBackend) hostBackend {
		failing = &failNthRename{hostBackend: b}
		return failing
	}})
	e.writeFile("a", []byte("A"))
	e.writeFile("b", []byte("B"))
	for nth := 1; nth <= 3; nth++ {
		failing.arm(nth)
		if err := e.renameFlags("a", "b", linux.RENAME_EXCHANGE); err == nil {
			t.Fatalf("exchange with rename %d failing succeeded", nth)
		}
		failing.arm(0)
		if got := e.readFile("a"); string(got) != "A" {
			t.Fatalf("rename %d failing: a = %q, want A", nth, got)
		}
		if got := e.readFile("b"); string(got) != "B" {
			t.Fatalf("rename %d failing: b = %q, want B", nth, got)
		}
		for _, name := range e.hostEntries(".") {
			if isEphemeralName(name) {
				t.Fatalf("rename %d failing: the host holds %q", nth, name)
			}
		}
	}
	if err := e.renameFlags("a", "b", linux.RENAME_EXCHANGE); err != nil {
		t.Fatal(err)
	}
	if got := e.readFile("a"); string(got) != "B" {
		t.Fatalf("a after the successful exchange = %q", got)
	}
}

// failNthRename fails the nth host rename after arm, and no other.
type failNthRename struct {
	hostBackend
	failAt int
	calls  int
}

func (f *failNthRename) arm(nth int) {
	f.failAt, f.calls = nth, 0
}

func (f *failNthRename) rename(oldRel, newRel string) error {
	f.calls++
	if f.failAt != 0 && f.calls == f.failAt {
		return os.ErrPermission
	}
	return f.hostBackend.rename(oldRel, newRel)
}

// The tests below cover section 4.2: AF_UNIX sockets, FIFOs, device nodes, extended
// attributes, and the limit of the .gvx_meta table.

// idProvider supplies the unique identifiers that Unix endpoints need.
type idProvider struct{ n atomic.Uint64 }

func (p *idProvider) UniqueID() uint64 { return p.n.Add(1) }

// blockingCtx lets a goroutine block inside the VFS the way a task does. Each
// goroutine that may block needs its own value.
type blockingCtx struct {
	cookieContext
	nt gvcontext.NoTask
}

// BlockOn implements context.Context.BlockOn.
func (c *blockingCtx) BlockOn(w waiter.Waitable, mask waiter.EventMask) bool {
	return c.nt.BlockOn(w, mask)
}

func (e *env) blocking() *blockingCtx {
	return &blockingCtx{cookieContext: e.ctx.(cookieContext)}
}

func (e *env) mknod(p string, mode linux.FileMode, major, minor uint32, ep transport.BoundEndpoint) error {
	return e.vfsObj.MknodAt(e.ctx, e.creds, e.pop(p), &vfs.MknodOptions{Mode: mode, DevMajor: major, DevMinor: minor, Endpoint: ep})
}

func (e *env) mustMknod(p string, mode linux.FileMode) {
	e.t.Helper()
	if err := e.mknod(p, mode, 0, 0, nil); err != nil {
		e.t.Fatalf("mknod %q %#o: %v", p, mode, err)
	}
}

func (e *env) boundEndpoint(p string) (transport.BoundEndpoint, error) {
	return e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop(p), &vfs.BoundEndpointOptions{})
}

// impl returns the filesystem behind the mount of the test.
func (e *env) impl() *filesystem {
	return e.root.Mount().Filesystem().Impl().(*filesystem)
}

// direntTypes lists the dirent type of each entry of the directory p.
func (e *env) direntTypes(p string) map[string]uint8 {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	out := map[string]uint8{}
	err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		out[d.Name] = d.Type
		return nil
	}))
	if err != nil {
		e.t.Fatalf("readdir %q: %v", p, err)
	}
	return out
}

func (e *env) hostSize(p string) int64 {
	e.t.Helper()
	info, err := os.Lstat(e.host(p))
	if err != nil {
		e.t.Fatalf("host stat %q: %v", p, err)
	}
	if !info.Mode().IsRegular() {
		e.t.Fatalf("host file %q has mode %v, want a regular placeholder", p, info.Mode())
	}
	return info.Size()
}

// newListeningEndpoint returns a listening stream endpoint, once as the
// connecting API and once as the bound endpoint that a socket file stores.
func newListeningEndpoint(t *testing.T, ctx gvcontext.Context, ids *idProvider) (transport.Endpoint, transport.BoundEndpoint) {
	t.Helper()
	server := transport.NewConnectioned(ctx, linux.SOCK_STREAM, ids)
	if err := server.Bind(transport.Address{Addr: "/sock"}); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := server.Listen(ctx, 4); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	return server, server.(transport.BoundEndpoint)
}

func TestMknodSocketConnectsThroughBoundEndpointAt(t *testing.T) {
	e := newEnv(t)
	ids := &idProvider{}
	server, bep := newListeningEndpoint(t, e.ctx, ids)
	if err := e.mknod("sock", linux.S_IFSOCK|0o755, 0, 0, bep); err != nil {
		t.Fatalf("mknod socket: %v", err)
	}

	st := e.mustStat("sock")
	if st.Mode&linux.S_IFMT != linux.S_IFSOCK || st.Mode&0o7777 != 0o755 || st.Size != 0 {
		t.Fatalf("stat = mode %#o size %d, want a socket of mode 0755 and size 0", st.Mode, st.Size)
	}
	if got := e.hostSize("sock"); got != 0 {
		t.Fatalf("host placeholder holds %d bytes, want 0", got)
	}
	if got := e.readdir("."); len(got) != 1 || got[0] != "sock" {
		t.Fatalf("readdir = %v, want [sock]", got)
	}
	if got := e.direntTypes(".")["sock"]; got != linux.DT_SOCK {
		t.Fatalf("dirent type = %d, want DT_SOCK", got)
	}

	bound, err := e.boundEndpoint("sock")
	if err != nil {
		t.Fatalf("BoundEndpointAt: %v", err)
	}
	if bound != bep {
		t.Fatalf("BoundEndpointAt returned another endpoint than the one that mknod stored")
	}
	client := transport.NewConnectioned(e.ctx, linux.SOCK_STREAM, ids)
	if serr := client.Connect(e.ctx, bound); serr != nil {
		t.Fatalf("Connect through the socket file: %v", serr)
	}
	peer, serr := server.Accept(e.ctx, nil)
	if serr != nil {
		t.Fatalf("Accept: %v", serr)
	}
	if n, _, serr := client.SendMsg(e.ctx, [][]byte{[]byte("ping")}, transport.ControlMessages{}, nil); serr != nil || n != 4 {
		t.Fatalf("SendMsg = (%d, %v), want 4 bytes", n, serr)
	}
	buf := make([]byte, 16)
	out, _, serr := peer.RecvMsg(e.ctx, [][]byte{buf}, transport.RecvArgs{})
	if serr != nil || string(buf[:out.RecvLen]) != "ping" {
		t.Fatalf("RecvMsg = (%q, %v), want ping", buf[:out.RecvLen], serr)
	}

	_, err = e.open("sock", linux.O_RDONLY, 0)
	wantErrno(t, "open of a socket file", err, linuxerr.ENXIO)
}

func TestSocketKeepsItsEndpointAcrossRenameLinkAndPruning(t *testing.T) {
	e := newEnv(t)
	_, want := newListeningEndpoint(t, e.ctx, &idProvider{})
	if err := e.mknod("sock", linux.S_IFSOCK|0o777, 0, 0, want); err != nil {
		t.Fatal(err)
	}
	// want is the endpoint that every name of the socket must return.
	check := func(path string) {
		t.Helper()
		got, err := e.boundEndpoint(path)
		if err != nil || got != want {
			t.Fatalf("BoundEndpointAt(%q) = (%v, %v), want the stored endpoint", path, got, err)
		}
	}

	if err := e.rename("sock", "renamed"); err != nil {
		t.Fatal(err)
	}
	check("renamed")
	wantErrno(t, "BoundEndpointAt of the old name", func() error { _, err := e.boundEndpoint("sock"); return err }(), linuxerr.ENOENT)

	if err := e.link("renamed", "alias"); err != nil {
		t.Fatalf("link of a socket file: %v", err)
	}
	check("alias")
	if a, b := e.mustStat("renamed"), e.mustStat("alias"); a.Ino != b.Ino || a.Nlink != 2 {
		t.Fatalf("stat = (ino %d, nlink %d) and ino %d, want one inode with 2 links", a.Ino, a.Nlink, b.Ino)
	}

	// The cache must not drop a dentry that holds an endpoint.
	fs := e.impl()
	fs.mu.Lock()
	fs.pruneLocked(fs.root)
	fs.mu.Unlock()
	check("renamed")
	check("alias")

	// Removing one name keeps the endpoint on the other.
	if err := e.unlink("renamed"); err != nil {
		t.Fatal(err)
	}
	check("alias")
}

func TestUnlinkOfSocketRemovesPlaceholderAndRecord(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("sock", linux.S_IFSOCK|0o600)
	if err := e.unlink("sock"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if _, err := os.Lstat(e.host("sock")); !os.IsNotExist(err) {
		t.Fatalf("host placeholder after unlink: %v, want it removed", err)
	}
	e.ws.mu.RLock()
	_, ok := e.ws.meta["sock"]
	e.ws.mu.RUnlock()
	if ok {
		t.Fatalf("the .gvx_meta record of the socket survived the unlink")
	}
	_, err := e.stat("sock")
	wantErrno(t, "stat after unlink", err, linuxerr.ENOENT)
	// The name is free again.
	e.mustMknod("sock", linux.S_IFIFO|0o600)
	if st := e.mustStat("sock"); st.Mode&linux.S_IFMT != linux.S_IFIFO {
		t.Fatalf("recreated node has type %#o, want a FIFO", st.Mode&linux.S_IFMT)
	}
}

func TestSocketWithoutEndpointRefusesConnections(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("stale", linux.S_IFSOCK|0o777)
	e.mustMknod("fifo", linux.S_IFIFO|0o666)
	e.writeFile("file", []byte("x"))
	for _, p := range []string{"stale", "fifo", "file"} {
		_, err := e.boundEndpoint(p)
		wantErrno(t, "BoundEndpointAt of "+p, err, linuxerr.ECONNREFUSED)
	}
	_, err := e.boundEndpoint("missing")
	wantErrno(t, "BoundEndpointAt of a missing name", err, linuxerr.ENOENT)
}

func TestSpecialNodesPersistAcrossReopen(t *testing.T) {
	dir := resolvedTempDir(t)
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	_, bep := newListeningEndpoint(t, e.ctx, &idProvider{})
	if err := e.mknod("sock", linux.S_IFSOCK|0o751, 0, 0, bep); err != nil {
		t.Fatal(err)
	}
	e.mustMknod("fifo", linux.S_IFIFO|0o640)
	if err := e.mknod("tty", linux.S_IFCHR|0o620, 4, 7, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.mknod("disk", linux.S_IFBLK|0o660, 8, 1, nil); err != nil {
		t.Fatal(err)
	}
	e.mustMkdir("dir")
	if err := e.mknod("dir/nested", linux.S_IFIFO|0o600, 0, 0, nil); err != nil {
		t.Fatal(err)
	}
	closeEnv()

	e2, _ := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	for _, tc := range []struct {
		path         string
		typ          uint16
		perm         uint16
		major, minor uint32
	}{
		{"sock", linux.S_IFSOCK, 0o751, 0, 0},
		{"fifo", linux.S_IFIFO, 0o640, 0, 0},
		{"tty", linux.S_IFCHR, 0o620, 4, 7},
		{"disk", linux.S_IFBLK, 0o660, 8, 1},
		{"dir/nested", linux.S_IFIFO, 0o600, 0, 0},
	} {
		st := e2.mustStat(tc.path)
		if st.Mode&linux.S_IFMT != tc.typ || st.Mode&0o7777 != tc.perm || st.RdevMajor != tc.major || st.RdevMinor != tc.minor {
			t.Errorf("stat %q after reopen = type %#o perm %#o rdev %d:%d, want %#o %#o %d:%d",
				tc.path, st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor, tc.typ, tc.perm, tc.major, tc.minor)
		}
	}
	// The endpoint of the earlier mount is gone.
	_, err := e2.boundEndpoint("sock")
	wantErrno(t, "BoundEndpointAt after reopen", err, linuxerr.ECONNREFUSED)
	// A FIFO of the earlier mount opens with an empty pipe.
	fd, err := e2.open("fifo", linux.O_RDONLY|linux.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open FIFO after reopen: %v", err)
	}
	fd.DecRef(e2.ctx)
	types := e2.direntTypes(".")
	for name, want := range map[string]uint8{"sock": linux.DT_SOCK, "fifo": linux.DT_FIFO, "tty": linux.DT_CHR, "disk": linux.DT_BLK, "dir": linux.DT_DIR} {
		if types[name] != want {
			t.Errorf("dirent type of %q = %d, want %d", name, types[name], want)
		}
	}
}

func TestFIFOTransfersDataBetweenDescriptors(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)
	if st := e.mustStat("fifo"); st.Mode&linux.S_IFMT != linux.S_IFIFO || st.Size != 0 {
		t.Fatalf("stat = mode %#o size %d, want an empty FIFO", st.Mode, st.Size)
	}
	if got := e.direntTypes(".")["fifo"]; got != linux.DT_FIFO {
		t.Fatalf("dirent type = %d, want DT_FIFO", got)
	}

	// A non-blocking open for writing fails while no reader exists.
	_, err := e.open("fifo", linux.O_WRONLY|linux.O_NONBLOCK, 0)
	wantErrno(t, "O_WRONLY|O_NONBLOCK without a reader", err, linuxerr.ENXIO)

	// A non-blocking open for reading succeeds without a writer.
	reader := e.mustOpen("fifo", linux.O_RDONLY|linux.O_NONBLOCK)
	defer reader.DecRef(e.ctx)
	dst := make([]byte, 16)
	writer := e.mustOpen("fifo", linux.O_WRONLY|linux.O_NONBLOCK)
	defer writer.DecRef(e.ctx)
	_, err = reader.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	wantErrno(t, "read of an empty FIFO with a writer", err, linuxerr.ErrWouldBlock)
	if n, err := writer.Write(e.ctx, usermem.BytesIOSequence([]byte("through memory")), vfs.WriteOptions{}); err != nil || n != 14 {
		t.Fatalf("write to the FIFO = (%d, %v), want 14 bytes", n, err)
	}
	n, err := reader.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "through memory" {
		t.Fatalf("read from the FIFO = (%q, %v), want the written bytes", dst[:n], err)
	}
	if got := e.hostSize("fifo"); got != 0 {
		t.Fatalf("the host placeholder holds %d bytes, want 0: FIFO data stays in Sentry memory", got)
	}
}

func TestFIFOBlockingOpenWaitsForTheOtherEnd(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)

	type result struct {
		fd  *vfs.FileDescription
		err error
	}
	opened := make(chan result, 1)
	readerCtx := e.blocking()
	go func() {
		fd, err := e.vfsObj.OpenAt(readerCtx, e.creds, e.fpop("fifo"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
		opened <- result{fd, err}
	}()

	// The writer open succeeds once the reader exists. Both opens finish only
	// when each sees the other end.
	writer, err := e.vfsObj.OpenAt(e.blocking(), e.creds, e.fpop("fifo"), &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("blocking open for writing: %v", err)
	}
	defer writer.DecRef(e.ctx)
	r := <-opened
	if r.err != nil {
		t.Fatalf("blocking open for reading: %v", r.err)
	}
	defer r.fd.DecRef(e.ctx)

	if _, err := writer.Write(e.ctx, usermem.BytesIOSequence([]byte("hello")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 8)
	n, err := r.fd.Read(readerCtx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "hello" {
		t.Fatalf("read = (%q, %v), want hello", dst[:n], err)
	}
}

func TestFIFOReadWriteOpenNeverBlocks(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o644)
	fd := e.mustOpen("fifo", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if _, err := fd.Write(e.ctx, usermem.BytesIOSequence([]byte("loop")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, 8)
	n, err := fd.Read(e.ctx, usermem.BytesIOSequence(dst), vfs.ReadOptions{})
	if err != nil || string(dst[:n]) != "loop" {
		t.Fatalf("read = (%q, %v), want loop", dst[:n], err)
	}
}

func TestNewFIFODoesNotShareThePipeOfAnUnlinkedOne(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("a", linux.S_IFIFO|0o644)
	reader := e.mustOpen("a", linux.O_RDONLY|linux.O_NONBLOCK)
	defer reader.DecRef(e.ctx)
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	// The host may hand the inode number of a to b. Opening b for writing
	// must still find no reader, because the reader belongs to the old pipe.
	e.mustMknod("b", linux.S_IFIFO|0o644)
	_, err := e.open("b", linux.O_WRONLY|linux.O_NONBLOCK, 0)
	wantErrno(t, "O_WRONLY|O_NONBLOCK on a new FIFO", err, linuxerr.ENXIO)
}

type stubDevice struct{ err error }

func (d stubDevice) Open(gvcontext.Context, *vfs.Mount, *vfs.Dentry, vfs.OpenOptions) (*vfs.FileDescription, error) {
	return nil, d.err
}

func TestMknodDeviceNodes(t *testing.T) {
	e := newEnv(t)
	if err := e.mknod("null", linux.S_IFCHR|0o666, 1, 3, nil); err != nil {
		t.Fatalf("mknod char device: %v", err)
	}
	if err := e.mknod("sda", linux.S_IFBLK|0o660, 8, 0, nil); err != nil {
		t.Fatalf("mknod block device: %v", err)
	}
	st := e.mustStat("null")
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.Mode&0o7777 != 0o666 || st.RdevMajor != 1 || st.RdevMinor != 3 {
		t.Fatalf("stat null = type %#o perm %#o rdev %d:%d, want a 0666 character device 1:3", st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor)
	}
	st = e.mustStat("sda")
	if st.Mode&linux.S_IFMT != linux.S_IFBLK || st.RdevMajor != 8 || st.RdevMinor != 0 {
		t.Fatalf("stat sda = type %#o rdev %d:%d, want a block device 8:0", st.Mode&linux.S_IFMT, st.RdevMajor, st.RdevMinor)
	}
	if got := e.hostSize("null"); got != 0 {
		t.Fatalf("host placeholder of a device holds %d bytes", got)
	}

	// No device is registered, so open fails as it does on other filesystems.
	_, err := e.open("null", linux.O_RDONLY, 0)
	wantErrno(t, "open of an unregistered device", err, linuxerr.ENXIO)

	// A registered device receives the open.
	if err := e.vfsObj.RegisterDevice(vfs.CharDevice, 1, 3, stubDevice{err: linuxerr.EIO}, &vfs.RegisterDeviceOptions{}); err != nil {
		t.Fatal(err)
	}
	_, err = e.open("null", linux.O_RDONLY, 0)
	wantErrno(t, "open of a registered device", err, linuxerr.EIO)

	wantErrno(t, "mknod with a major above the limit", e.mknod("big", linux.S_IFCHR|0o600, rdevMajorMax+1, 0, nil), linuxerr.EINVAL)
	wantErrno(t, "mknod of a directory", e.mknod("d", linux.S_IFDIR|0o755, 0, 0, nil), linuxerr.EINVAL)
	wantErrno(t, "mknod over an existing name", e.mknod("null", linux.S_IFIFO|0o600, 0, 0, nil), linuxerr.EEXIST)
}

func TestWhiteoutRecordIsACharacterDeviceZero(t *testing.T) {
	e := newEnv(t)
	e.ws.mu.Lock()
	err := e.ws.createWhiteoutLocked("gone")
	e.ws.mu.Unlock()
	if err != nil {
		t.Fatalf("createWhiteoutLocked: %v", err)
	}
	st := e.mustStat("gone")
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.Mode&0o7777 != 0 || st.RdevMajor != 0 || st.RdevMinor != 0 {
		t.Fatalf("whiteout stat = type %#o perm %#o rdev %d:%d, want character device 0:0 with mode 0", st.Mode&linux.S_IFMT, st.Mode&0o7777, st.RdevMajor, st.RdevMinor)
	}
	if got := e.hostSize("gone"); got != 0 {
		t.Fatalf("whiteout placeholder holds %d bytes", got)
	}
	e.ws.mu.Lock()
	err = e.ws.createWhiteoutLocked("gone")
	e.ws.mu.Unlock()
	if !os.IsExist(err) {
		t.Fatalf("second whiteout = %v, want an exist error", err)
	}
}

func TestChmodAndChownKeepTheSpecialType(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.setStat("fifo", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID | linux.STATX_GID, Mode: 0o640, UID: 7, GID: 8}); err != nil {
		t.Fatalf("setstat: %v", err)
	}
	st := e.mustStat("fifo")
	if st.Mode != linux.S_IFIFO|0o640 || st.UID != 7 || st.GID != 8 {
		t.Fatalf("stat = mode %#o uid %d gid %d, want FIFO 0640 owned by 7:8", st.Mode, st.UID, st.GID)
	}
	wantErrno(t, "truncate of a FIFO", e.setStat("fifo", linux.Statx{Mask: linux.STATX_SIZE, Size: 0}), linuxerr.EINVAL)
}

func TestPlaceholderWithHostContentIsARegularFile(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("node", linux.S_IFSOCK|0o600)
	if err := os.WriteFile(e.host("node"), []byte("replaced by a host tool"), 0o600); err != nil {
		t.Fatal(err)
	}
	attr, size, err := e.ws.Stat("node")
	if err != nil {
		t.Fatal(err)
	}
	if attr.Mode&linux.S_IFMT != linux.S_IFREG || size == 0 {
		t.Fatalf("Stat = type %#o size %d, want a regular file: the host file has content", attr.Mode&linux.S_IFMT, size)
	}
}

func TestMknodRegularFileStaysAnOrdinaryFile(t *testing.T) {
	e := newEnv(t)
	e.mustMknod("plain", linux.S_IFREG|0o644)
	e.writeFile("plain", []byte("data"))
	if got := e.readFile("plain"); string(got) != "data" {
		t.Fatalf("read = %q", got)
	}
	if st := e.mustStat("plain"); st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("type = %#o, want a regular file", st.Mode&linux.S_IFMT)
	}
}

func TestMetaTableLimitRefusesNewRecords(t *testing.T) {
	e := newEnvOpts(t, workspaceOptions{coalesce: defaultCoalesceWindow, maxMeta: 5})
	hostOnly := e.host("hostfile")
	if err := os.WriteFile(hostOnly, []byte("h"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"f1", "f2"} {
		e.writeFile(name, []byte("x"))
	}
	e.mustMkdir("d1")
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("l1"), "target"); err != nil {
		t.Fatal(err)
	}
	e.mustMknod("n1", linux.S_IFIFO|0o600)
	e.ws.mu.RLock()
	count := len(e.ws.meta)
	e.ws.mu.RUnlock()
	if count != 5 {
		t.Fatalf("the table holds %d records, want 5", count)
	}

	_, err := e.open("f3", linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create at the limit", err, linuxerr.ENOSPC)
	wantErrno(t, "mkdir at the limit", e.mkdir("d2"), linuxerr.ENOSPC)
	wantErrno(t, "symlink at the limit", e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("l2"), "t"), linuxerr.ENOSPC)
	wantErrno(t, "mknod FIFO at the limit", e.mknod("n2", linux.S_IFIFO|0o600, 0, 0, nil), linuxerr.ENOSPC)
	wantErrno(t, "mknod device at the limit", e.mknod("n3", linux.S_IFCHR|0o600, 1, 1, nil), linuxerr.ENOSPC)
	wantErrno(t, "link at the limit", e.link("f1", "f1link"), linuxerr.ENOSPC)
	wantErrno(t, "chmod of a file without a record", e.setStat("hostfile", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}), linuxerr.ENOSPC)
	wantErrno(t, "chown of a file without a record", e.setStat("hostfile", linux.Statx{Mask: linux.STATX_UID, UID: 5}), linuxerr.ENOSPC)
	wantErrno(t, "setxattr on a file without a record", e.setXattr("hostfile", "trusted.k", "v", 0), linuxerr.ENOSPC)

	// A refused mutation leaves no host object behind.
	for _, name := range []string{"f3", "d2", "l2", "n2", "n3", "f1link"} {
		if _, err := os.Lstat(e.host(name)); !os.IsNotExist(err) {
			t.Errorf("host entry %q exists after a refused mutation: %v", name, err)
		}
	}

	// A record that exists needs no room, so its owner can still change it.
	if err := e.setStat("f1", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}); err != nil {
		t.Fatalf("chmod of a file with a record at the limit: %v", err)
	}
	// Removing a record makes room again.
	if err := e.unlink("n1"); err != nil {
		t.Fatal(err)
	}
	if err := e.mknod("n2", linux.S_IFIFO|0o600, 0, 0, nil); err != nil {
		t.Fatalf("mknod after an unlink made room: %v", err)
	}
}

func TestHostWatcherSuppressesEchoOfSpecialNodes(t *testing.T) {
	w := newWatchEnv(t)
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.settle()
	hw := &w.ws.watch

	// Prove first that the bridge is live, so that the checks below mean
	// something.
	hostWrite(t, w.host("d/probe"), "p")
	w.sync()
	w.expect("probe", "CREATE probe")
	w.settle()
	base := hw.delivered.Load()

	step := func(what string, op func()) {
		t.Helper()
		op()
		// The guest events arrive without a scan. The scan that follows
		// must add nothing.
		w.drain()
		w.sync()
		w.expectNone("echo of " + what)
		if got := hw.delivered.Load(); got != base {
			t.Fatalf("%s: the watcher delivered %d notifications for a guest mutation", what, got-base)
		}
	}
	step("mknod of a socket", func() {
		_, bep := newListeningEndpoint(t, w.env.ctx, &idProvider{})
		if err := w.mknod("d/sock", linux.S_IFSOCK|0o600, 0, 0, bep); err != nil {
			t.Fatal(err)
		}
	})
	step("mknod of a FIFO", func() { w.mustMknod("d/fifo", linux.S_IFIFO|0o600) })
	step("mknod of a device", func() {
		if err := w.mknod("d/dev", linux.S_IFCHR|0o600, 1, 3, nil); err != nil {
			t.Fatal(err)
		}
	})
	step("whiteout", func() {
		w.ws.mu.Lock()
		defer w.ws.mu.Unlock()
		if err := w.ws.createWhiteoutLocked("d/white"); err != nil {
			t.Fatal(err)
		}
	})
	step("rename of a FIFO", func() {
		if err := w.rename("d/fifo", "d/fifo2"); err != nil {
			t.Fatal(err)
		}
	})
	step("hard link of a socket", func() {
		if err := w.link("d/sock", "d/sock2"); err != nil {
			t.Fatal(err)
		}
	})
	step("unlink of a socket", func() {
		if err := w.unlink("d/sock"); err != nil {
			t.Fatal(err)
		}
	})
}

func TestMknodOnAReadOnlyWorkspace(t *testing.T) {
	dir := resolvedTempDir(t)
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	for name, mode := range map[string]linux.FileMode{"sock": linux.S_IFSOCK | 0o600, "fifo": linux.S_IFIFO | 0o600, "dev": linux.S_IFCHR | 0o600} {
		wantErrno(t, "mknod "+name+" on a read-only workspace", e.mknod(name, mode, 1, 1, nil), linuxerr.EROFS)
		if _, err := os.Lstat(e.host(name)); !os.IsNotExist(err) {
			t.Errorf("host entry %q exists after a refused mknod: %v", name, err)
		}
	}
}

// newMetaEnv returns a mount whose extended attributes live in .gvx_meta on
// every host. The tests of the native store are in vfs_special_linux_test.go.
func newMetaEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.ws.caps.NativeXattr = false
	return e
}

func (e *env) setXattrAs(creds *auth.Credentials, p, name, value string, flags uint32) error {
	return e.vfsObj.SetXattrAt(e.ctx, creds, e.pop(p), &vfs.SetXattrOptions{Name: name, Value: value, Flags: flags})
}

func (e *env) setXattr(p, name, value string, flags uint32) error {
	return e.setXattrAs(e.creds, p, name, value, flags)
}

func (e *env) mustSetXattr(p, name, value string) {
	e.t.Helper()
	if err := e.setXattr(p, name, value, 0); err != nil {
		e.t.Fatalf("setxattr %q %q: %v", p, name, err)
	}
}

func (e *env) getXattrAs(creds *auth.Credentials, p, name string, size uint64) (string, error) {
	return e.vfsObj.GetXattrAt(e.ctx, creds, e.pop(p), &vfs.GetXattrOptions{Name: name, Size: size})
}

func (e *env) getXattr(p, name string) (string, error) {
	return e.getXattrAs(e.creds, p, name, 0)
}

func (e *env) mustGetXattr(p, name string) string {
	e.t.Helper()
	v, err := e.getXattr(p, name)
	if err != nil {
		e.t.Fatalf("getxattr %q %q: %v", p, name, err)
	}
	return v
}

func (e *env) listXattrAs(creds *auth.Credentials, p string, size uint64) ([]string, error) {
	names, err := e.vfsObj.ListXattrAt(e.ctx, creds, e.pop(p), size)
	slices.Sort(names)
	return names, err
}

func (e *env) listXattr(p string) []string {
	e.t.Helper()
	names, err := e.listXattrAs(e.creds, p, 0)
	if err != nil {
		e.t.Fatalf("listxattr %q: %v", p, err)
	}
	return names
}

func (e *env) removeXattr(p, name string) error {
	return e.vfsObj.RemoveXattrAt(e.ctx, e.creds, e.pop(p), name)
}

// userCreds returns the credentials of an unprivileged user.
func (e *env) userCreds(uid auth.KUID) *auth.Credentials {
	return auth.NewUserCredentials(uid, auth.KGID(uid), nil, nil, e.creds.UserNamespace)
}

// openWorld makes the workspace root writable for every user.
func (e *env) openWorld() {
	e.t.Helper()
	if err := e.setStat(".", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}); err != nil {
		e.t.Fatal(err)
	}
}

func TestXattrCreateReplaceListRemove(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", []byte("data"))

	wantErrno(t, "REPLACE of a missing name", e.setXattr("f", "user.a", "1", linux.XATTR_REPLACE), linuxerr.ENODATA)
	if err := e.setXattr("f", "user.a", "1", linux.XATTR_CREATE); err != nil {
		t.Fatalf("CREATE of a new name: %v", err)
	}
	wantErrno(t, "CREATE of an existing name", e.setXattr("f", "user.a", "2", linux.XATTR_CREATE), linuxerr.EEXIST)
	if err := e.setXattr("f", "user.a", "22", linux.XATTR_REPLACE); err != nil {
		t.Fatalf("REPLACE of an existing name: %v", err)
	}
	e.mustSetXattr("f", "user.b", "")
	e.mustSetXattr("f", "trusted.t", "root")

	if got := e.mustGetXattr("f", "user.a"); got != "22" {
		t.Fatalf("getxattr user.a = %q, want 22", got)
	}
	if got := e.mustGetXattr("f", "user.b"); got != "" {
		t.Fatalf("getxattr of an empty value = %q", got)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"trusted.t", "user.a", "user.b"}) {
		t.Fatalf("listxattr = %v", got)
	}
	_, err := e.getXattrAs(e.creds, "f", "user.a", 1)
	wantErrno(t, "getxattr with a small size hint", err, linuxerr.ERANGE)
	_, err = e.listXattrAs(e.creds, "f", 3)
	wantErrno(t, "listxattr with a small size hint", err, linuxerr.ERANGE)
	if _, err := e.listXattrAs(e.creds, "f", 4096); err != nil {
		t.Fatalf("listxattr with a large size hint: %v", err)
	}

	if err := e.removeXattr("f", "user.a"); err != nil {
		t.Fatal(err)
	}
	_, err = e.getXattr("f", "user.a")
	wantErrno(t, "getxattr after remove", err, linuxerr.ENODATA)
	wantErrno(t, "remove of a missing name", e.removeXattr("f", "user.a"), linuxerr.ENODATA)
	if got := e.listXattr("f"); !slices.Equal(got, []string{"trusted.t", "user.b"}) {
		t.Fatalf("listxattr after remove = %v", got)
	}
	_, err = e.getXattr("missing", "user.a")
	wantErrno(t, "getxattr of a missing file", err, linuxerr.ENOENT)

	// The file itself is untouched.
	if got := e.readFile("f"); string(got) != "data" {
		t.Fatalf("content = %q", got)
	}
	if st := e.mustStat("f"); st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("type = %#o, want a regular file", st.Mode&linux.S_IFMT)
	}
}

func TestXattrOnAHostFileWithoutARecord(t *testing.T) {
	e := newMetaEnv(t)
	if err := os.WriteFile(e.host("plain"), []byte("host"), 0o640); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("plain", "user.k", "v")
	if got := e.mustGetXattr("plain", "user.k"); got != "v" {
		t.Fatalf("getxattr = %q", got)
	}
	st := e.mustStat("plain")
	wantMode := uint16(linux.S_IFREG | 0o640)
	if isWindowsHost() {
		// Windows keeps no permission bits, so hostfs shows its default mode.
		wantMode = st.Mode
	}
	if st.Mode != wantMode || st.Size != 4 {
		t.Fatalf("stat = mode %#o size %d, want the host mode and size to survive the new record", st.Mode, st.Size)
	}
}

func TestXattrNamespaces(t *testing.T) {
	e := newMetaEnv(t)
	e.openWorld()
	alice, bob := e.userCreds(1000), e.userCreds(2000)
	fd, err := e.vfsObj.OpenAt(e.ctx, alice, e.pop("mine"), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	fd.DecRef(e.ctx)

	// user.* belongs to the owner of a regular file.
	if err := e.setXattrAs(alice, "mine", "user.note", "hi", 0); err != nil {
		t.Fatalf("owner sets user.note: %v", err)
	}
	wantErrno(t, "write of user.* by another user", e.setXattrAs(bob, "mine", "user.note", "no", 0), linuxerr.EACCES)
	if got, err := e.getXattrAs(bob, "mine", "user.note", 0); err != nil || got != "hi" {
		t.Fatalf("read of user.* by another user with read permission = (%q, %v)", got, err)
	}

	// trusted.* needs CAP_SYS_ADMIN.
	wantErrno(t, "write of trusted.* by a user", e.setXattrAs(alice, "mine", "trusted.x", "1", 0), linuxerr.EPERM)
	_, err = e.getXattrAs(alice, "mine", "trusted.x", 0)
	wantErrno(t, "read of trusted.* by a user", err, linuxerr.ENODATA)
	if err := e.setXattrAs(e.creds, "mine", "trusted.x", "1", 0); err != nil {
		t.Fatalf("root sets trusted.x: %v", err)
	}
	if got, err := e.getXattrAs(e.creds, "mine", "trusted.x", 0); err != nil || got != "1" {
		t.Fatalf("root reads trusted.x = (%q, %v)", got, err)
	}
	_, err = e.getXattrAs(alice, "mine", "trusted.x", 0)
	wantErrno(t, "read of an existing trusted.* by a user", err, linuxerr.ENODATA)
	if names, err := e.listXattrAs(alice, "mine", 0); err != nil || !slices.Equal(names, []string{"user.note"}) {
		t.Fatalf("a user lists %v (%v), want trusted.x hidden", names, err)
	}
	if names, err := e.listXattrAs(e.creds, "mine", 0); err != nil || !slices.Equal(names, []string{"trusted.x", "user.note"}) {
		t.Fatalf("root lists %v (%v), want both names", names, err)
	}

	// security.* is read-only, except security.capability.
	wantErrno(t, "write of security.selinux", e.setXattr("mine", "security.selinux", "ctx", 0), linuxerr.EOPNOTSUPP)
	_, err = e.getXattr("mine", "security.selinux")
	wantErrno(t, "read of an unset security.selinux", err, linuxerr.ENODATA)

	// system.* and unknown namespaces are not supported.
	wantErrno(t, "write of system.posix_acl_access", e.setXattr("mine", "system.posix_acl_access", "x", 0), linuxerr.EOPNOTSUPP)
	_, err = e.getXattr("mine", "system.posix_acl_access")
	wantErrno(t, "read of system.posix_acl_access", err, linuxerr.EOPNOTSUPP)
	wantErrno(t, "write of a name without a namespace", e.setXattr("mine", "plain", "x", 0), linuxerr.EOPNOTSUPP)
}

func TestXattrOnEveryFileType(t *testing.T) {
	e := newMetaEnv(t)
	e.openWorld()
	alice := e.userCreds(1000)
	e.mustMkdir("dir")
	e.mustMknod("fifo", linux.S_IFIFO|0o666)
	e.mustMknod("sock", linux.S_IFSOCK|0o666)
	if err := e.mknod("dev", linux.S_IFCHR|0o666, 1, 3, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link"), "dir"); err != nil {
		t.Fatal(err)
	}

	// Directories carry user.* attributes.
	if err := e.setXattrAs(e.creds, "dir", "user.d", "dv", 0); err != nil {
		t.Fatalf("user.* on a directory: %v", err)
	}
	if got := e.mustGetXattr("dir", "user.d"); got != "dv" {
		t.Fatalf("directory attribute = %q", got)
	}

	// Other types carry no user.* attributes but keep trusted.* and security.capability space.
	for _, p := range []string{"fifo", "sock", "dev", "link"} {
		wantErrno(t, "user.* on "+p, e.setXattrAs(alice, p, "user.x", "1", 0), linuxerr.EPERM)
		_, err := e.getXattrAs(alice, p, "user.x", 0)
		wantErrno(t, "read of user.* on "+p, err, linuxerr.ENODATA)
		if err := e.setXattr(p, "trusted.k", "kv", 0); err != nil {
			t.Fatalf("trusted.k on %s: %v", p, err)
		}
		if got := e.mustGetXattr(p, "trusted.k"); got != "kv" {
			t.Fatalf("trusted.k on %s = %q", p, got)
		}
		if got := e.listXattr(p); !slices.Equal(got, []string{"trusted.k"}) {
			t.Fatalf("listxattr of %s = %v", p, got)
		}
	}
	// The symlink keeps its target and type.
	if st, err := e.lstat("link"); err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Fatalf("lstat link = (%#o, %v), want a symlink", st.Mode, err)
	}
	if got, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("link")); err != nil || got != "dir" {
		t.Fatalf("readlink = (%q, %v)", got, err)
	}
	for p, want := range map[string]uint32{"fifo": linux.S_IFIFO, "sock": linux.S_IFSOCK, "dev": linux.S_IFCHR} {
		if st := e.mustStat(p); uint32(st.Mode)&linux.S_IFMT != want {
			t.Fatalf("type of %s = %#o after setxattr, want %#o", p, st.Mode&linux.S_IFMT, want)
		}
	}
	if st := e.mustStat("dev"); st.RdevMajor != 1 || st.RdevMinor != 3 {
		t.Fatalf("rdev of dev = %d:%d after setxattr, want 1:3", st.RdevMajor, st.RdevMinor)
	}
}

func TestXattrSizeCapPerInode(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("a", nil)
	e.writeFile("b", nil)

	// "user.a" has 6 bytes, so 4090 bytes of value fill the cap exactly.
	e.mustSetXattr("a", "user.a", strings.Repeat("x", maxXattrBytes-len("user.a")))
	wantErrno(t, "replace above the cap", e.setXattr("a", "user.a", strings.Repeat("x", maxXattrBytes-len("user.a")+1), 0), linuxerr.ENOSPC)
	if got := e.mustGetXattr("a", "user.a"); len(got) != maxXattrBytes-len("user.a") {
		t.Fatalf("a refused replace changed the value to %d bytes", len(got))
	}
	wantErrno(t, "another name at the cap", e.setXattr("a", "user.b", "", 0), linuxerr.ENOSPC)

	// The cap counts names and values of all attributes of one inode.
	e.mustSetXattr("b", "user.one", strings.Repeat("y", 2000))
	e.mustSetXattr("b", "user.two", strings.Repeat("y", 2000))
	wantErrno(t, "third attribute above the cap", e.setXattr("b", "user.three", strings.Repeat("y", 200), 0), linuxerr.ENOSPC)
	// A smaller replace and a remove both make room.
	e.mustSetXattr("b", "user.one", "short")
	e.mustSetXattr("b", "user.three", strings.Repeat("y", 200))
	if err := e.removeXattr("b", "user.two"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("b", "user.four", strings.Repeat("y", 1500))

	// A single value above 64 KiB is too big, before any cap applies.
	wantErrno(t, "value above XATTR_SIZE_MAX", e.setXattr("b", "user.big", strings.Repeat("z", linux.XATTR_SIZE_MAX+1), 0), linuxerr.E2BIG)
}

func TestXattrMapsAreCopiedOnChange(t *testing.T) {
	cur := map[string][]byte{"user.a": []byte("1")}
	next, err := setXattrMap(cur, "user.b", []byte("2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 1 || len(next) != 2 {
		t.Fatalf("setXattrMap changed its input: cur %v next %v", cur, next)
	}
	value := []byte("3")
	next2, err := setXattrMap(next, "user.c", value, 0)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	if string(next2["user.c"]) != "3" {
		t.Fatalf("setXattrMap kept the caller buffer: %q", next2["user.c"])
	}
	gone, err := removeXattrMap(next2, "user.a")
	if err != nil || len(next2) != 3 || len(gone) != 2 {
		t.Fatalf("removeXattrMap = (%v, %v), input %v", gone, err, next2)
	}
	if last, err := removeXattrMap(map[string][]byte{"user.a": nil}, "user.a"); err != nil || last != nil {
		t.Fatalf("removal of the last name = (%v, %v), want a nil map", last, err)
	}
	if _, err := removeXattrMap(cur, "user.zz"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Fatalf("removal of a missing name = %v, want ENODATA", err)
	}
}

func TestXattrHardLinksShareAttributes(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("a", []byte("x"))
	e.mustSetXattr("a", "user.first", "1")
	if err := e.link("a", "b"); err != nil {
		t.Fatal(err)
	}
	// A new link starts with the attributes of the file.
	if got := e.mustGetXattr("b", "user.first"); got != "1" {
		t.Fatalf("attribute through the new link = %q", got)
	}
	// A change through either name shows through the other.
	e.mustSetXattr("b", "user.second", "2")
	if got := e.mustGetXattr("a", "user.second"); got != "2" {
		t.Fatalf("attribute set through b, read through a = %q", got)
	}
	e.mustSetXattr("a", "user.first", "changed")
	if got := e.mustGetXattr("b", "user.first"); got != "changed" {
		t.Fatalf("attribute replaced through a, read through b = %q", got)
	}
	if err := e.removeXattr("b", "user.second"); err != nil {
		t.Fatal(err)
	}
	_, err := e.getXattr("a", "user.second")
	wantErrno(t, "attribute removed through b, read through a", err, linuxerr.ENODATA)
	if got := e.listXattr("a"); !slices.Equal(got, e.listXattr("b")) {
		t.Fatalf("listxattr a = %v, b = %v, want equal", got, e.listXattr("b"))
	}
	// A third name joins the set, and the table holds one map for each name.
	if err := e.link("b", "c"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("c", "user.third", "3")
	for _, p := range []string{"a", "b", "c"} {
		if got := e.listXattr(p); !slices.Equal(got, []string{"user.first", "user.third"}) {
			t.Fatalf("listxattr %s = %v", p, got)
		}
	}

	// unlink, rename, and a later link keep the attributes consistent.
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("b", "renamed"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustGetXattr("renamed", "user.third"); got != "3" {
		t.Fatalf("attribute after unlink and rename = %q", got)
	}
	e.mustSetXattr("c", "user.after", "4")
	if got := e.mustGetXattr("renamed", "user.after"); got != "4" {
		t.Fatalf("attribute through the renamed link = %q", got)
	}
	e.ws.mu.RLock()
	_, goneRecord := e.ws.meta["a"]
	_, movedRecord := e.ws.meta["renamed"]
	e.ws.mu.RUnlock()
	if goneRecord || !movedRecord {
		t.Fatalf("records after unlink and rename: a=%v renamed=%v, want a gone and renamed present", goneRecord, movedRecord)
	}
}

func TestXattrHardLinkedFIFOSharesAttributes(t *testing.T) {
	e := newMetaEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.link("fifo", "fifo2"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("fifo2", "trusted.k", "v")
	if got := e.mustGetXattr("fifo", "trusted.k"); got != "v" {
		t.Fatalf("attribute through the other name = %q", got)
	}
	if st := e.mustStat("fifo2"); st.Mode&linux.S_IFMT != linux.S_IFIFO || st.Nlink != 2 {
		t.Fatalf("stat = type %#o nlink %d, want a FIFO with 2 links", st.Mode&linux.S_IFMT, st.Nlink)
	}
}

func TestXattrFollowsRenameAndUnlink(t *testing.T) {
	e := newMetaEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("x"))
	e.mustSetXattr("d/f", "user.k", "v")
	e.mustSetXattr("d", "user.dir", "dv")
	if err := e.rename("d", "moved"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustGetXattr("moved/f", "user.k"); got != "v" {
		t.Fatalf("file attribute after a directory rename = %q", got)
	}
	if got := e.mustGetXattr("moved", "user.dir"); got != "dv" {
		t.Fatalf("directory attribute after a rename = %q", got)
	}
	_, err := e.getXattr("d", "user.dir")
	wantErrno(t, "attribute at the old directory name", err, linuxerr.ENOENT)

	// A rename over a file with attributes replaces them.
	e.writeFile("target", []byte("t"))
	e.mustSetXattr("target", "user.old", "o")
	if err := e.rename("moved/f", "target"); err != nil {
		t.Fatal(err)
	}
	if got := e.listXattr("target"); !slices.Equal(got, []string{"user.k"}) {
		t.Fatalf("attributes after a rename over a file = %v, want only those of the moved file", got)
	}

	// A removed file leaves no attributes for a new file of the same name.
	if err := e.unlink("target"); err != nil {
		t.Fatal(err)
	}
	e.writeFile("target", nil)
	if got := e.listXattr("target"); len(got) != 0 {
		t.Fatalf("a new file starts with attributes %v", got)
	}
	e.ws.mu.RLock()
	rec := e.ws.meta["target"]
	e.ws.mu.RUnlock()
	if len(rec.Xattrs) != 0 {
		t.Fatalf("the record of a new file holds attributes %v", rec.Xattrs)
	}
}

func TestXattrPersistAcrossReopen(t *testing.T) {
	dir := resolvedTempDir(t)
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	e.ws.caps.NativeXattr = false
	e.writeFile("file", []byte("x"))
	e.mustMkdir("dir")
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link"), "file"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("file", "user.f", "file value")
	e.mustSetXattr("dir", "user.d", "dir value")
	e.mustSetXattr("fifo", "trusted.p", "fifo value")
	e.mustSetXattr("link", "trusted.l", "link value\x00with a NUL")
	e.mustSetXattr("file", "trusted.t", "second")
	closeEnv()

	e2, _ := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	e2.ws.caps.NativeXattr = false
	for _, tc := range []struct{ path, name, want string }{
		{"file", "user.f", "file value"},
		{"file", "trusted.t", "second"},
		{"dir", "user.d", "dir value"},
		{"fifo", "trusted.p", "fifo value"},
		{"link", "trusted.l", "link value\x00with a NUL"},
	} {
		if got, err := e2.getXattr(tc.path, tc.name); err != nil || got != tc.want {
			t.Errorf("getxattr %s %s after reopen = (%q, %v), want %q", tc.path, tc.name, got, err, tc.want)
		}
	}
	if got := e2.listXattr("file"); !slices.Equal(got, []string{"trusted.t", "user.f"}) {
		t.Errorf("listxattr after reopen = %v", got)
	}
	if st := e2.mustStat("fifo"); st.Mode&linux.S_IFMT != linux.S_IFIFO {
		t.Errorf("type of the FIFO after reopen = %#o", st.Mode&linux.S_IFMT)
	}
}

func TestXattrThroughFileDescriptors(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", []byte("data"))
	e.mustMkdir("d")

	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v1"}); err != nil {
		t.Fatalf("fsetxattr: %v", err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v1" {
		t.Fatalf("fgetxattr = (%q, %v)", got, err)
	}
	if got := e.mustGetXattr("f", "user.fd"); got != "v1" {
		t.Fatalf("path getxattr after fsetxattr = %q", got)
	}
	if names, err := fd.ListXattr(e.ctx, 0); err != nil || !slices.Equal(names, []string{"user.fd"}) {
		t.Fatalf("flistxattr = (%v, %v)", names, err)
	}

	dfd := e.mustOpen("d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dfd.DecRef(e.ctx)
	if err := dfd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.dirfd", Value: "dv"}); err != nil {
		t.Fatalf("fsetxattr on a directory: %v", err)
	}
	if got := e.mustGetXattr("d", "user.dirfd"); got != "dv" {
		t.Fatalf("directory attribute = %q", got)
	}
	if err := dfd.RemoveXattr(e.ctx, "user.dirfd"); err != nil {
		t.Fatalf("fremovexattr on a directory: %v", err)
	}

	// An unlinked file with an open descriptor keeps working attributes.
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v1" {
		t.Fatalf("fgetxattr on an unlinked file = (%q, %v)", got, err)
	}
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v2"}); err != nil {
		t.Fatalf("fsetxattr on an unlinked file: %v", err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v2" {
		t.Fatalf("fgetxattr after the change = (%q, %v)", got, err)
	}
	if err := fd.RemoveXattr(e.ctx, "user.fd"); err != nil {
		t.Fatalf("fremovexattr on an unlinked file: %v", err)
	}
	e.ws.mu.RLock()
	_, ok := e.ws.meta["f"]
	e.ws.mu.RUnlock()
	if ok {
		t.Fatalf("an xattr call on an unlinked file created a record for its old name")
	}
}

func TestXattrOnAReadOnlyWorkspace(t *testing.T) {
	dir := resolvedTempDir(t)
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
	wantErrno(t, "setxattr on a read-only workspace", e.setXattr("f", "user.k", "v", 0), linuxerr.EROFS)
	wantErrno(t, "removexattr on a read-only workspace", e.removeXattr("f", "user.k"), linuxerr.EROFS)
	_, err = e.getXattr("f", "user.k")
	wantErrno(t, "getxattr on a read-only workspace", err, linuxerr.ENODATA)
	if got := e.listXattr("f"); len(got) != 0 {
		t.Fatalf("listxattr = %v", got)
	}
}

func TestXattrMetaTableHoldsTheValues(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", nil)
	e.mustSetXattr("f", "user.k", "v")
	e.ws.mu.RLock()
	got := maps.Clone(e.ws.meta["f"].Xattrs)
	e.ws.mu.RUnlock()
	if len(got) != 1 || string(got["user.k"]) != "v" {
		t.Fatalf("the record holds %v, want user.k=v", got)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.host(MetaFileName))
	if err != nil || !strings.Contains(string(raw), `"user.k"`) {
		t.Fatalf(".gvx_meta = (%q, %v), want it to hold user.k", raw, err)
	}
}
