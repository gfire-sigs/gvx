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

//go:build !windows

package hostfs

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestPinnedHostCallsRefuseLinksAndOddNames(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("real")
	e.writeFile("real/f", []byte("x"))
	outside := t.TempDir()
	if err := os.WriteFile(outside+"/secret", []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, target := range map[string]string{"alias": "real", "escape": outside, "filelink": "real/f"} {
		if err := os.Symlink(target, e.host(name)); err != nil {
			t.Skipf("host cannot create symbolic links: %v", err)
		}
	}
	host := e.ws.host
	root := host.rootDir()

	for _, name := range []string{"alias", "escape"} {
		if _, _, err := host.openDirAt(root, name); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("openDirAt(%q) through a link = %v, want ErrPathTraversal", name, err)
		}
	}
	if f, err := host.openChildAt(root, "filelink", os.O_RDONLY, 0); err == nil {
		_ = f.Close()
		t.Errorf("openChildAt of a link succeeded, want a refusal")
	}
	if info, err := host.lstatAt(root, "filelink"); err != nil || info.kind != hostKindSymlink {
		t.Errorf("lstatAt of a link = (%v, %v), want the link itself", info.kind, err)
	}
	for _, name := range []string{"", ".", "..", "real/f", "../real"} {
		if _, _, err := host.openDirAt(root, name); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("openDirAt(%q) = %v, want ErrPathTraversal", name, err)
		}
		if _, err := host.lstatAt(root, name); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("lstatAt(%q) = %v, want ErrPathTraversal", name, err)
		}
		if f, err := host.openChildAt(root, name, os.O_RDONLY, 0); !errors.Is(err, ErrPathTraversal) {
			if err == nil {
				_ = f.Close()
			}
			t.Errorf("openChildAt(%q) = %v, want ErrPathTraversal", name, err)
		}
	}

	// The workspace never pins a link, and it never descends through one.
	for _, parent := range []string{"alias", "escape"} {
		if _, err := e.ws.lookupIn(parent, "f"); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("lookupIn below the link %q = %v, want ErrPathTraversal", parent, err)
		}
		if _, err := e.ws.lookupIn(parent, "secret"); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("lookupIn of secret below the link %q = %v, want ErrPathTraversal", parent, err)
		}
	}
	e.ws.pinMu.Lock()
	defer e.ws.pinMu.Unlock()
	for _, link := range []string{"alias", "escape"} {
		if e.ws.pins[link] != nil {
			t.Errorf("the workspace pinned the link %q", link)
		}
	}
}

func TestRetiredPinsCloseTheirDescriptors(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	e.writeFile("a/b/f", []byte("x"))
	e.mustStat("a/b/f")

	var fds []int
	e.ws.pinMu.Lock()
	for _, p := range e.ws.pins {
		fds = append(fds, int(p.h))
	}
	e.ws.pinMu.Unlock()
	if len(fds) < 2 {
		t.Fatalf("pinned descriptors = %d, want at least 2", len(fds))
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatalf("pinned descriptor %d is not open: %v", fd, err)
		}
	}
	if err := e.rename("a", "z"); err != nil {
		t.Fatal(err)
	}
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Errorf("descriptor %d after the rename: %v, want EBADF (closed)", fd, err)
		}
	}
}

// On a volume that folds case, the host opens "SUB" when it stores "sub". The
// workspace must refuse the wrong case when it opens a pin lazily, whether it
// opens the pin for the first time or after a retirement.
func TestPinOpenVerifiesTheCaseOfTheDirectory(t *testing.T) {
	e := newEnv(t)
	if !e.ws.host.caseInsensitive() && !hostFoldsCase(t, e.dir) {
		t.Skip("the host file system is case-sensitive")
	}
	e.mustMkdir("sub")
	e.writeFile("sub/file", []byte("x"))

	pinned := func(rel string) bool {
		e.ws.pinMu.Lock()
		defer e.ws.pinMu.Unlock()
		return e.ws.pins[rel] != nil
	}
	retireAll := func() {
		e.ws.mu.Lock()
		defer e.ws.mu.Unlock()
		e.ws.closeSubtreeHandlesLocked(".")
	}

	// The first lookup of a wrong-case path finds no pin to reuse.
	if _, err := e.ws.lookupPath("SUB/file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookupPath(SUB/file) = %v, want fs.ErrNotExist", err)
	}
	if pinned("SUB") {
		t.Error("the workspace pinned the directory under the wrong case")
	}
	if _, err := e.ws.lookupPath("sub/file"); err != nil {
		t.Fatalf("lookupPath(sub/file) = %v", err)
	}
	if !pinned("sub") {
		t.Fatal("the lookup of sub/file did not pin sub")
	}

	// The pin retires, as eviction or an idle sweep would retire it. The wrong
	// case must fail again, and the right case must open the pin again.
	retireAll()
	if pinned("sub") {
		t.Fatal("the pin of sub survived the retirement")
	}
	if pin, err := e.ws.acquirePin("SUB"); !errors.Is(err, fs.ErrNotExist) {
		if err == nil {
			e.ws.releasePin(pin)
		}
		t.Fatalf("acquirePin(SUB) = %v, want fs.ErrNotExist", err)
	}
	if _, err := e.ws.lookupPath("SUB/file"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lookupPath(SUB/file) after the retirement = %v, want fs.ErrNotExist", err)
	}
	if pinned("SUB") {
		t.Error("the workspace pinned the directory under the wrong case after a retirement")
	}
	if _, err := e.ws.lookupPath("sub/file"); err != nil {
		t.Fatalf("lookupPath(sub/file) after the retirement = %v", err)
	}
}

func TestHostSwapOfPinnedDirectoryIsNoticedAfterTheCacheLifetime(t *testing.T) {
	t.Run("directory", func(t *testing.T) {
		e, ch, clock := newCountEnv(t)
		e.mustMkdir("d")
		e.writeFile("d/f", []byte("old"))
		e.mustStat("d/f")

		if err := os.Rename(e.host("d"), e.host("d.old")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(e.host("d"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(e.host("d/g"), []byte("new"), 0o600); err != nil {
			t.Fatal(err)
		}

		clock.advance(cacheTTL + 1)
		ch.reset()
		if got := e.readFile("d/g"); string(got) != "new" {
			t.Fatalf("read d/g = %q, want new", got)
		}
		if ch.got("openDirAt") == 0 {
			t.Fatalf("the pin of the replaced directory was not reopened %s", ch.dump())
		}
		_, err := e.stat("d/f")
		wantErrno(t, "stat of a name in the replaced directory", err, linuxerr.ENOENT)
	})

	t.Run("link", func(t *testing.T) {
		e, _, clock := newCountEnv(t)
		e.mustMkdir("d")
		e.writeFile("d/f", []byte("inside"))
		e.mustStat("d/f")
		outside := t.TempDir()
		if err := os.WriteFile(outside+"/f", []byte("outside"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(e.host("d"), e.host("d.moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, e.host("d")); err != nil {
			t.Skipf("host cannot create symbolic links: %v", err)
		}

		clock.advance(cacheTTL + 1)
		wantErrno(t, "open through the swapped directory", func() error {
			fd, err := e.open("d/f", linux.O_RDONLY, 0)
			if err == nil {
				fd.DecRef(e.ctx)
			}
			return err
		}(), linuxerr.EACCES)
		_, err := e.stat("d/f")
		wantErrno(t, "stat through the swapped directory", err, linuxerr.EACCES)
	})
}
