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

//go:build linux

package hostfs

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

func TestHostOpenatConfinesToDirectoryAndRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skip("Android Zygote seccomp traps openat2; hostOpenat uses single-component openat there")
	}
	outer := t.TempDir()
	outsideFile := filepath.Join(outer, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(outer, "ws")
	if err := os.MkdirAll(filepath.Join(ws, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	insideFile := filepath.Join(ws, "sub", "inside.txt")
	if err := os.WriteFile(insideFile, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(ws, "sub", "link.txt")
	if err := os.Symlink(insideFile, linkPath); err != nil {
		t.Fatal(err)
	}

	wsFD, err := unix.Open(ws, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(wsFD)

	fd, err := hostOpenat(wsFD, "sub/inside.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o644)
	if err != nil {
		t.Fatalf("hostOpenat(sub/inside.txt): %v", err)
	}
	_ = unix.Close(fd)

	if fd, err := hostOpenat(wsFD, "../outside.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); !errors.Is(err, ErrPathTraversal) {
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Errorf("hostOpenat(../outside.txt) = %v, want ErrPathTraversal", err)
	}
	if fd, err := hostOpenat(wsFD, outsideFile, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); !errors.Is(err, ErrPathTraversal) {
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Errorf("hostOpenat(absolute path) = %v, want ErrPathTraversal", err)
	}
	if fd, err := hostOpenat(wsFD, "sub/link.txt", unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0); !errors.Is(err, unix.ELOOP) {
		if err == nil {
			_ = unix.Close(fd)
		}
		t.Errorf("hostOpenat(symlink) = %v, want ELOOP", err)
	}
}
