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
	"fmt"
	"os"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
)

func TestHostSpecialFilesAreNeverOpened(t *testing.T) {
	e := newEnv(t)
	if err := unix.Mkfifo(e.host("pipe"), 0o600); err != nil {
		t.Skipf("host cannot create a FIFO: %v", err)
	}
	e.writeFile("plain", []byte("p"))

	// The open must return at once: a blocking open would hang this test.
	if _, err := e.ws.host.open("pipe", os.O_RDONLY, 0); err == nil {
		t.Fatalf("host.open of a FIFO succeeded")
	}
	_, err := e.open("pipe", linux.O_RDONLY, 0)
	wantErrno(t, "guest open of a host FIFO", err, linuxerr.EACCES)
	if got := e.readdir("."); len(got) != 1 || got[0] != "plain" {
		t.Fatalf("listing = %v, want only plain", got)
	}
}

func TestHostRootRefusesLinksAtEveryComponent(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("real")
	e.writeFile("real/f", []byte("x"))
	if err := os.Symlink("real", e.host("alias")); err != nil {
		t.Skipf("host cannot create symbolic links: %v", err)
	}
	for name, op := range map[string]func() error{
		"mkdir":    func() error { return e.ws.host.mkdir("alias/new") },
		"unlink":   func() error { return e.ws.host.unlink("alias/f") },
		"rename":   func() error { return e.ws.host.rename("alias/f", "real/g") },
		"link":     func() error { return e.ws.host.link("real/f", "alias/h") },
		"readlink": func() error { _, err := e.ws.host.readlink("alias/f"); return err },
		"readDir":  func() error { _, err := e.ws.host.readDir("alias"); return err },
		"chtimes":  func() error { return e.ws.host.chtimes("alias/f", nil, nil) },
	} {
		if err := op(); !errors.Is(err, ErrPathTraversal) {
			t.Errorf("%s through a host symlink = %v, want ErrPathTraversal", name, err)
		}
	}
	if raw, err := os.ReadFile(e.host("real/f")); err != nil || string(raw) != "x" {
		t.Fatalf("real/f = (%q, %v): an operation escaped through the link", raw, err)
	}
	if _, err := os.Lstat(e.host("real/new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mkdir through the link created real/new: %v", err)
	}
}

func TestPinnedMutationsRefuseNamesThatLeaveTheDirectory(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("x"))
	h := e.ws.host
	dir, _, err := h.openDirAt(h.rootDir(), "d")
	if err != nil {
		t.Fatalf("openDirAt: %v", err)
	}
	defer func() { _ = h.closeDir(dir) }()
	for name, op := range map[string]func(leaf string) error{
		"mkdirAt":   func(leaf string) error { return h.mkdirAt(dir, leaf) },
		"unlinkAt":  func(leaf string) error { return h.unlinkAt(dir, leaf) },
		"rmdirAt":   func(leaf string) error { return h.rmdirAt(dir, leaf) },
		"renameAt":  func(leaf string) error { return h.renameAt(dir, "f", dir, leaf) },
		"linkAt":    func(leaf string) error { return h.linkAt(dir, "f", dir, leaf) },
		"chtimesAt": func(leaf string) error { return h.chtimesAt(dir, leaf, nil, nil) },
	} {
		for _, leaf := range []string{"../escape", "a/b", "..", "."} {
			if err := op(leaf); !errors.Is(err, ErrPathTraversal) {
				t.Errorf("%s(%q) = %v, want ErrPathTraversal", name, leaf, err)
			}
		}
	}
	if _, err := os.Lstat(e.host("escape")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a pinned mutation created escape outside the directory: %v", err)
	}
}

func TestPinnedMutationsActOnTheLinkAndNeverOnItsTarget(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("target", []byte("t"))
	if err := os.Symlink("../target", e.host("d/link")); err != nil {
		t.Skipf("host cannot create symbolic links: %v", err)
	}
	h := e.ws.host
	dir, _, err := h.openDirAt(h.rootDir(), "d")
	if err != nil {
		t.Fatalf("openDirAt: %v", err)
	}
	defer func() { _ = h.closeDir(dir) }()

	when := time.Unix(1_000_000, 0)
	if err := h.chtimesAt(dir, "link", &when, &when); err != nil {
		t.Fatalf("chtimesAt of a link: %v", err)
	}
	if fi, err := os.Stat(e.host("target")); err != nil || fi.ModTime().Equal(when) {
		t.Fatalf("chtimesAt followed the link and changed the target: %v, %v", fi, err)
	}
	if err := h.linkAt(dir, "link", dir, "link2"); err != nil {
		t.Fatalf("linkAt of a link: %v", err)
	}
	if fi, err := os.Lstat(e.host("d/link2")); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("linkAt of a link made %v, %v, want a link to the link", fi, err)
	}
	if err := h.unlinkAt(dir, "link"); err != nil {
		t.Fatalf("unlinkAt of a link: %v", err)
	}
	if raw, err := os.ReadFile(e.host("target")); err != nil || string(raw) != "t" {
		t.Fatalf("target = (%q, %v) after unlinkAt of its link", raw, err)
	}
}

func TestListingReportsTypeAndInodeOfEveryEntry(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("sub")
	e.writeFile("file", []byte("x"))
	if err := os.Symlink("file", e.host("hostlink")); err != nil {
		t.Skipf("host cannot create symbolic links: %v", err)
	}
	if err := unix.Mkfifo(e.host("pipe"), 0o600); err != nil {
		t.Skipf("host cannot create a FIFO: %v", err)
	}
	want := map[string]hostKind{"sub": hostKindDir, "file": hostKindRegular, "hostlink": hostKindSymlink, "pipe": hostKindOther}
	for how, list := range map[string]func() ([]hostDirEntry, error){
		"by path":   func() ([]hostDirEntry, error) { return e.ws.host.readDir(".") },
		"by handle": func() ([]hostDirEntry, error) { return e.ws.host.readDirAt(e.ws.host.rootDir()) },
	} {
		entries, err := list()
		if err != nil {
			t.Fatalf("listing %s: %v", how, err)
		}
		if len(entries) != len(want) {
			t.Errorf("listing %s returned %d entries, want %d: %v", how, len(entries), len(want), entries)
		}
		for _, ent := range entries {
			kind, ok := want[ent.name]
			if !ok || ent.kind != kind {
				t.Errorf("listing %s: entry %q has kind %v, want %v (known %v)", how, ent.name, ent.kind, kind, ok)
				continue
			}
			info, err := e.ws.host.lstat(ent.name)
			if err != nil {
				t.Fatalf("lstat %q: %v", ent.name, err)
			}
			if ent.ino != info.id.ino {
				t.Errorf("listing %s: entry %q has inode %d, lstat says %d", how, ent.name, ent.ino, info.id.ino)
			}
		}
	}
}

func TestListingOfLargeDirectoryReturnsEveryName(t *testing.T) {
	e := newEnv(t)
	const n = 3000
	for i := range n {
		if err := os.WriteFile(e.host(fmt.Sprintf("a-long-entry-name-%05d", i)), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := e.ws.host.readDir(".")
	if err != nil {
		t.Fatalf("readDir: %v", err)
	}
	seen := make(map[string]bool, n)
	for _, ent := range entries {
		seen[ent.name] = true
	}
	for i := range n {
		if name := fmt.Sprintf("a-long-entry-name-%05d", i); !seen[name] {
			t.Fatalf("listing of %d entries misses %q (%d names)", n, name, len(entries))
		}
	}
}
