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
	"os"
	"path/filepath"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/xsys/unix"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

func dupFDCloexec(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
}

func openDirFDForTest(t *testing.T, dir string) int {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("os.OpenRoot(%q): %v", dir, err)
	}
	defer root.Close()
	f, err := root.Open(".")
	if err != nil {
		t.Fatalf("root.Open(.): %v", err)
	}
	// Duplicate so OpenWorkspaceFromDirFD owns an independent descriptor.
	fdCopy, err := dupFDCloexec(int(f.Fd()))
	_ = f.Close()
	if err != nil {
		t.Fatalf("dupFDCloexec: %v", err)
	}
	return fdCopy
}

func TestOpenWorkspaceFromDirFDDirectoryAndSingleFile(t *testing.T) {
	WarmWatchLimit()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "seed.txt"), []byte("hello-fd"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// 1. Directory workspace from FD.
	ws, err := OpenWorkspaceFromDirFD(openDirFDForTest(t, dir), dir, "", false)
	if err != nil {
		t.Fatalf("OpenWorkspaceFromDirFD(dir): %v", err)
	}
	defer ws.Close()

	got, err := ws.ReadFile("seed.txt")
	if err != nil || string(got) != "hello-fd" {
		t.Fatalf("ReadFile(seed.txt) = (%q, %v), want hello-fd", got, err)
	}
	if err := ws.WriteFile("guest.txt", []byte("from-guest"), 0o640); err != nil {
		t.Fatalf("WriteFile(guest.txt): %v", err)
	}
	hostData, err := os.ReadFile(filepath.Join(dir, "guest.txt"))
	if err != nil || string(hostData) != "from-guest" {
		t.Fatalf("host ReadFile(guest.txt) = (%q, %v), want from-guest", hostData, err)
	}

	// 2. Single-file workspace from parent FD + leaf name.
	if err := os.WriteFile(filepath.Join(dir, "sibling.txt"), []byte("hidden"), 0o600); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}
	sfWS, err := OpenWorkspaceFromDirFD(openDirFDForTest(t, dir), filepath.Join(dir, "seed.txt"), "seed.txt", true)
	if err != nil {
		t.Fatalf("OpenWorkspaceFromDirFD(single file): %v", err)
	}
	defer sfWS.Close()
	if !sfWS.SingleFile() {
		t.Fatal("sfWS.SingleFile() = false, want true")
	}
	sfData, err := sfWS.ReadFile(".")
	if err != nil || string(sfData) != "hello-fd" {
		t.Fatalf("sfWS.ReadFile(.) = (%q, %v), want hello-fd", sfData, err)
	}
	if _, err := sfWS.ReadFile("sibling.txt"); err == nil {
		t.Fatal("sfWS.ReadFile(sibling.txt) succeeded, want error")
	}

	// 3. Reject non-directory FD, invalid leaf names, and symlink targets.
	regFile, err := os.Open(filepath.Join(dir, "seed.txt"))
	if err != nil {
		t.Fatalf("os.Open: %v", err)
	}
	regFD, err := dupFDCloexec(int(regFile.Fd()))
	_ = regFile.Close()
	if err != nil {
		t.Fatalf("dupFDCloexec: %v", err)
	}
	if badWS, err := OpenWorkspaceFromDirFD(regFD, "reg", "", true); err == nil {
		_ = badWS.Close()
		t.Fatal("OpenWorkspaceFromDirFD accepted regular file FD")
	}
	if badWS, err := OpenWorkspaceFromDirFD(openDirFDForTest(t, dir), "bad-leaf", "../seed.txt", true); err == nil {
		_ = badWS.Close()
		t.Fatal("OpenWorkspaceFromDirFD accepted traversal leaf")
	}
	if err := os.Symlink("seed.txt", filepath.Join(dir, "link.txt")); err != nil {
		t.Fatalf("Symlink: %v", err)
	}
	if badWS, err := OpenWorkspaceFromDirFD(openDirFDForTest(t, dir), "symlink-leaf", "link.txt", true); err == nil {
		_ = badWS.Close()
		t.Fatal("OpenWorkspaceFromDirFD accepted symlink single-file leaf")
	}
}

func TestOpenWorkspaceFromDirFDHostInotify(t *testing.T) {
	WarmWatchLimit()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	ws, err := OpenWorkspaceFromDirFD(openDirFDForTest(t, dir), dir, "", false)
	if err != nil {
		t.Fatalf("OpenWorkspaceFromDirFD: %v", err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})

	we := newWatchEnvOn(t, e)
	wd := we.add("/", linux.IN_CREATE|linux.IN_MODIFY)

	if err := os.WriteFile(filepath.Join(dir, "live.txt"), []byte("from-host"), 0o644); err != nil {
		t.Fatalf("WriteFile live.txt: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range we.drain() {
			if ev.wd == wd && ev.name == "live.txt" && ev.mask&linux.IN_CREATE != 0 {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("timed out waiting for host-to-guest IN_CREATE on FD-attached hostfs workspace")
}
