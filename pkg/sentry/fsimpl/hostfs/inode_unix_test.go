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
	"os"
	"testing"

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
