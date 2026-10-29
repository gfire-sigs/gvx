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

// Command voltree is a guest program for the volume persistence test. With
// the argument "write DIR" it writes a tree of directories, files, links, and
// attributes into DIR and syncs every object. With "verify DIR" it checks that
// the tree has the same content, permissions, link counts, and attributes. The
// two runs happen in two sandboxes that mount the same volume.
package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"

	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// entry describes one regular file of the tree.
type entry struct {
	path string
	mode fs.FileMode
	data []byte
}

// pattern returns n deterministic bytes for a seed.
func pattern(seed byte, n int) []byte {
	b := make([]byte, n)
	x := uint32(seed)*2654435761 + 1
	for i := range b {
		x = x*1664525 + 1013904223
		b[i] = byte(x >> 24)
	}
	return b
}

// files lists the regular files. The sizes cover the three storage forms of
// the volume: inline data, extents in the inode, and a file of many blocks.
func files() []entry {
	return []entry{
		{"empty", 0o600, nil},
		{"inline60", 0o644, pattern(1, 60)},
		{"small.txt", 0o640, []byte("small file\n")},
		{"a/b/mid.bin", 0o600, pattern(2, 5000)},
		{"a/b/c/big.bin", 0o600, pattern(3, 3<<20)},
		{"run.sh", 0o755, []byte("#!/bin/sh\nexit 0\n")},
	}
}

var dirs = []struct {
	path string
	mode fs.FileMode
}{
	{"a", 0o750},
	{"a/b", 0o700},
	{"a/b/c", 0o755},
}

func main() {
	if len(os.Args) != 3 || (os.Args[1] != "write" && os.Args[1] != "verify") {
		fmt.Fprintln(os.Stderr, "usage: voltree write|verify DIR")
		os.Exit(2)
	}
	var err error
	if os.Args[1] == "write" {
		err = write(os.Args[2])
	} else {
		err = verify(os.Args[2])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "voltree:", err)
		os.Exit(1)
	}
	fmt.Println(os.Args[1], "ok")
}

func write(root string) error {
	for _, d := range dirs {
		p := filepath.Join(root, d.path)
		if err := os.Mkdir(p, d.mode); err != nil {
			return err
		}
		if err := os.Chmod(p, d.mode); err != nil {
			return err
		}
	}
	for _, e := range files() {
		p := filepath.Join(root, e.path)
		f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, e.mode)
		if err != nil {
			return err
		}
		if _, err := f.Write(e.data); err != nil {
			return err
		}
		if err := f.Chmod(e.mode); err != nil {
			return err
		}
		if err := f.Sync(); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	if err := os.Link(filepath.Join(root, "small.txt"), filepath.Join(root, "a/hard.txt")); err != nil {
		return err
	}
	if err := os.Symlink("../small.txt", filepath.Join(root, "a/soft")); err != nil {
		return err
	}
	if err := unix.Setxattr(filepath.Join(root, "small.txt"), "user.note", []byte("kept"), 0); err != nil {
		return err
	}
	// Sync the directories, so that the entries are durable too.
	for _, p := range []string{"a/b/c", "a/b", "a", "."} {
		d, err := os.Open(filepath.Join(root, p))
		if err != nil {
			return err
		}
		if err := d.Sync(); err != nil {
			d.Close()
			return err
		}
		d.Close()
	}
	return nil
}

func verify(root string) error {
	for _, d := range dirs {
		info, err := os.Stat(filepath.Join(root, d.path))
		if err != nil {
			return err
		}
		if !info.IsDir() || info.Mode().Perm() != d.mode {
			return fmt.Errorf("%s: mode %v, want a directory with %v", d.path, info.Mode(), d.mode)
		}
	}
	for _, e := range files() {
		p := filepath.Join(root, e.path)
		info, err := os.Stat(p)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != e.mode {
			return fmt.Errorf("%s: mode %v, want a file with %v", e.path, info.Mode(), e.mode)
		}
		got, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, e.data) {
			return fmt.Errorf("%s: %d bytes differ from the %d bytes that sandbox one wrote", e.path, len(got), len(e.data))
		}
	}
	var st syscall.Stat_t
	if err := syscall.Stat(filepath.Join(root, "small.txt"), &st); err != nil {
		return err
	}
	if st.Nlink != 2 {
		return fmt.Errorf("small.txt has %d links, want 2", st.Nlink)
	}
	if target, err := os.Readlink(filepath.Join(root, "a/soft")); err != nil || target != "../small.txt" {
		return fmt.Errorf("symlink a/soft = %q, %v", target, err)
	}
	buf := make([]byte, 16)
	n, err := unix.Getxattr(filepath.Join(root, "small.txt"), "user.note", buf)
	if err != nil || string(buf[:n]) != "kept" {
		return fmt.Errorf("xattr user.note = %q, %v", buf[:max(n, 0)], err)
	}
	return nil
}
