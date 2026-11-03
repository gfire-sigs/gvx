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

// Command fsfeatures is a guest program for the file system feature test. With
// the arguments "ext4lite DIR" it checks the features of an ext4lite volume
// mounted at DIR: unnamed files with O_TMPFILE, the fallocate range modes, and
// the flags of preadv2 and pwritev2. With the arguments "hostfs DIR" it checks
// the fallocate modes of a hostfs mount. Every check goes through the system
// call of the guest, so it covers the whole path from the guest to the driver.
package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"z.gfire.dev/gvx/internal/xsys/unix"
)

const block = 4096

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: fsfeatures ext4lite|hostfs DIR")
		os.Exit(2)
	}
	var steps []func(dir string) error
	switch os.Args[1] {
	case "ext4lite":
		steps = []func(string) error{tmpfileLink, rangeModes, rwFlags}
	case "hostfs":
		steps = []func(string) error{hostfsModes}
	default:
		fmt.Fprintln(os.Stderr, "usage: fsfeatures ext4lite|hostfs DIR")
		os.Exit(2)
	}
	for _, step := range steps {
		if err := step(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "fsfeatures:", err)
			os.Exit(1)
		}
	}
	fmt.Println(os.Args[1], "ok")
}

// blocks returns n blocks, and every block holds bytes that no other block holds.
func blocks(seed byte, n int) []byte {
	out := make([]byte, 0, n*block)
	for i := range n {
		out = append(out, bytes.Repeat([]byte{seed + byte(i)}, block)...)
	}
	return out
}

// wantErrno fails unless err is the errno.
func wantErrno(what string, err error, want syscall.Errno) error {
	if !errors.Is(err, want) {
		return fmt.Errorf("%s = %v, want %v", what, err, want)
	}
	return nil
}

// nlink returns the link count of the open file fd.
func nlink(fd int) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return 0, err
	}
	return uint64(st.Nlink), nil
}

// tmpfileLink checks open with O_TMPFILE and the two ways to link the file.
func tmpfileLink(dir string) error {
	fd, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open with O_TMPFILE: %w", err)
	}
	defer unix.Close(fd)
	data := blocks(1, 3)
	if _, err := unix.Write(fd, data); err != nil {
		return fmt.Errorf("write to the unnamed file: %w", err)
	}
	if n, err := nlink(fd); err != nil || n != 0 {
		return fmt.Errorf("link count of the unnamed file = %d, %v, want 0", n, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Name() == "linked" || e.Name() == "second" {
			return fmt.Errorf("the directory lists %q before any link", e.Name())
		}
	}

	// The link through the magic link of /proc/self/fd gives the file its name.
	proc := fmt.Sprintf("/proc/self/fd/%d", fd)
	linked := filepath.Join(dir, "linked")
	if err := unix.Linkat(unix.AT_FDCWD, proc, unix.AT_FDCWD, linked, unix.AT_SYMLINK_FOLLOW); err != nil {
		return fmt.Errorf("linkat through %s: %w", proc, err)
	}
	if n, err := nlink(fd); err != nil || n != 1 {
		return fmt.Errorf("link count after the first link = %d, %v, want 1", n, err)
	}
	got, err := os.ReadFile(linked)
	if err != nil || !bytes.Equal(got, data) {
		return fmt.Errorf("content of %s differs from the data of the unnamed file (%d bytes, %v)", linked, len(got), err)
	}
	// A second name comes from AT_EMPTY_PATH, which needs a privileged guest.
	second := filepath.Join(dir, "second")
	if err := unix.Linkat(fd, "", unix.AT_FDCWD, second, unix.AT_EMPTY_PATH); err != nil {
		return fmt.Errorf("linkat with AT_EMPTY_PATH: %w", err)
	}
	if n, err := nlink(fd); err != nil || n != 2 {
		return fmt.Errorf("link count after the second link = %d, %v, want 2", n, err)
	}

	// A file that O_EXCL made refuses every link.
	excl, err := unix.Open(dir, unix.O_TMPFILE|unix.O_RDWR|unix.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("open with O_TMPFILE|O_EXCL: %w", err)
	}
	defer unix.Close(excl)
	err = unix.Linkat(excl, "", unix.AT_FDCWD, filepath.Join(dir, "never"), unix.AT_EMPTY_PATH)
	if e := wantErrno("linkat of an O_TMPFILE|O_EXCL file", err, unix.ENOENT); e != nil {
		return e
	}
	// A file that unlink left refuses it too.
	named := filepath.Join(dir, "doomed")
	if err := os.WriteFile(named, []byte("x"), 0o600); err != nil {
		return err
	}
	open, err := unix.Open(named, unix.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer unix.Close(open)
	if err := os.Remove(named); err != nil {
		return err
	}
	err = unix.Linkat(open, "", unix.AT_FDCWD, filepath.Join(dir, "never"), unix.AT_EMPTY_PATH)
	return wantErrno("linkat of an unlinked file", err, unix.ENOENT)
}

// check reads the whole file at fd and compares it with want.
func check(what string, fd int, want []byte) error {
	got := make([]byte, len(want)+block)
	n, err := unix.Pread(fd, got, 0)
	if err != nil {
		return fmt.Errorf("%s: read: %w", what, err)
	}
	if !bytes.Equal(got[:n], want) {
		return fmt.Errorf("%s: read %d bytes, want %d, and the bytes differ at %d", what, n, len(want), firstDiff(got[:n], want))
	}
	return nil
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// rangeModes checks the fallocate modes that the volume serves.
func rangeModes(dir string) error {
	path := filepath.Join(dir, "ranges")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	content := blocks(1, 10)
	if _, err := unix.Write(fd, content); err != nil {
		return err
	}

	if err := unix.Fallocate(fd, unix.FALLOC_FL_ZERO_RANGE|unix.FALLOC_FL_KEEP_SIZE, 2*block, 3*block); err != nil {
		return fmt.Errorf("fallocate ZERO_RANGE|KEEP_SIZE: %w", err)
	}
	clear(content[2*block : 5*block])
	if err := check("after the zero range", fd, content); err != nil {
		return err
	}

	if err := unix.Fallocate(fd, unix.FALLOC_FL_COLLAPSE_RANGE, 5*block, 2*block); err != nil {
		return fmt.Errorf("fallocate COLLAPSE_RANGE: %w", err)
	}
	content = append(content[:5*block], content[7*block:]...)
	if err := check("after the collapse", fd, content); err != nil {
		return err
	}

	if err := unix.Fallocate(fd, unix.FALLOC_FL_INSERT_RANGE, block, block); err != nil {
		return fmt.Errorf("fallocate INSERT_RANGE: %w", err)
	}
	content = append(append(content[:block:block], make([]byte, block)...), content[block:]...)
	if err := check("after the insert", fd, content); err != nil {
		return err
	}

	if err := unix.Fallocate(fd, unix.FALLOC_FL_ZERO_RANGE, int64(len(content)), 2*block); err != nil {
		return fmt.Errorf("fallocate ZERO_RANGE past the end: %w", err)
	}
	content = append(content, make([]byte, 2*block)...)
	if err := check("after the zero range past the end", fd, content); err != nil {
		return err
	}

	if err := wantErrno("COLLAPSE_RANGE with an unaligned offset", unix.Fallocate(fd, unix.FALLOC_FL_COLLAPSE_RANGE, 100, block), unix.EINVAL); err != nil {
		return err
	}
	if err := wantErrno("COLLAPSE_RANGE to the end of the file", unix.Fallocate(fd, unix.FALLOC_FL_COLLAPSE_RANGE, block, int64(len(content))), unix.EINVAL); err != nil {
		return err
	}
	if err := wantErrno("INSERT_RANGE past the end of the file", unix.Fallocate(fd, unix.FALLOC_FL_INSERT_RANGE, int64(len(content)), block), unix.EINVAL); err != nil {
		return err
	}
	if err := wantErrno("COLLAPSE_RANGE with KEEP_SIZE", unix.Fallocate(fd, unix.FALLOC_FL_COLLAPSE_RANGE|unix.FALLOC_FL_KEEP_SIZE, 0, block), unix.EOPNOTSUPP); err != nil {
		return err
	}
	if err := wantErrno("PUNCH_HOLE without KEEP_SIZE", unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE, 0, block), unix.EOPNOTSUPP); err != nil {
		return err
	}
	return check("after the rejected calls", fd, content)
}

// rwFlags checks the flags of preadv2 and pwritev2.
func rwFlags(dir string) error {
	path := filepath.Join(dir, "flags")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if _, err := unix.Write(fd, []byte("0123456789")); err != nil {
		return err
	}
	buf := make([]byte, 4)
	if n, err := unix.Preadv2(fd, [][]byte{buf}, 2, unix.RWF_NOWAIT); err != nil || string(buf[:n]) != "2345" {
		return fmt.Errorf("preadv2 with RWF_NOWAIT = %q, %v, want 2345", buf[:max(n, 0)], err)
	}
	if n, err := unix.Pwritev2(fd, [][]byte{[]byte("AB")}, 0, unix.RWF_NOWAIT); err != nil || n != 2 {
		return fmt.Errorf("pwritev2 with RWF_NOWAIT = %d, %v, want 2 bytes", n, err)
	}
	// The offset of a call with RWF_APPEND is ignored, and the position stays.
	if n, err := unix.Pwritev2(fd, [][]byte{[]byte("XY")}, 3, unix.RWF_APPEND); err != nil || n != 2 {
		return fmt.Errorf("pwritev2 with RWF_APPEND = %d, %v, want 2 bytes", n, err)
	}
	if err := check("after RWF_APPEND", fd, []byte("AB23456789XY")); err != nil {
		return err
	}
	if pos, err := unix.Seek(fd, 0, unix.SEEK_CUR); err != nil || pos != 10 {
		return fmt.Errorf("position after pwritev2 with an offset = %d, %v, want 10", pos, err)
	}
	if err := wantErrno("RWF_APPEND with RWF_NOAPPEND", func() error {
		_, err := unix.Pwritev2(fd, [][]byte{[]byte("x")}, 0, unix.RWF_APPEND|unix.RWF_NOAPPEND)
		return err
	}(), unix.EINVAL); err != nil {
		return err
	}
	if err := wantErrno("RWF_ATOMIC", func() error {
		_, err := unix.Pwritev2(fd, [][]byte{[]byte("x")}, 0, unix.RWF_ATOMIC)
		return err
	}(), unix.EOPNOTSUPP); err != nil {
		return err
	}

	// RWF_NOAPPEND overrides O_APPEND for one call.
	appendFD, err := unix.Open(path, unix.O_RDWR|unix.O_APPEND, 0)
	if err != nil {
		return err
	}
	defer unix.Close(appendFD)
	if _, err := unix.Pwritev2(appendFD, [][]byte{[]byte("zz")}, 4, unix.RWF_NOAPPEND); err != nil {
		return fmt.Errorf("pwritev2 with RWF_NOAPPEND: %w", err)
	}
	return check("after RWF_NOAPPEND", fd, []byte("AB23zz6789XY"))
}

// hostfsModes checks that the fallocate modes of hostfs reach the driver.
func hostfsModes(dir string) error {
	path := filepath.Join(dir, "punch")
	fd, err := unix.Open(path, unix.O_CREAT|unix.O_RDWR|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	content := blocks(1, 8)
	if _, err := unix.Write(fd, content); err != nil {
		return err
	}
	if err := unix.Fallocate(fd, unix.FALLOC_FL_PUNCH_HOLE|unix.FALLOC_FL_KEEP_SIZE, 2*block, 4*block); err != nil {
		return fmt.Errorf("fallocate PUNCH_HOLE|KEEP_SIZE: %w", err)
	}
	clear(content[2*block : 6*block])
	if err := check("after the punch", fd, content); err != nil {
		return err
	}
	if err := unix.Fallocate(fd, unix.FALLOC_FL_KEEP_SIZE, 0, 16*block); err != nil {
		return fmt.Errorf("fallocate KEEP_SIZE: %w", err)
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil || st.Size != int64(len(content)) {
		return fmt.Errorf("size after KEEP_SIZE = %d, %v, want %d", st.Size, err, len(content))
	}
	return wantErrno("ZERO_RANGE on hostfs", unix.Fallocate(fd, unix.FALLOC_FL_ZERO_RANGE, 0, block), unix.EOPNOTSUPP)
}
