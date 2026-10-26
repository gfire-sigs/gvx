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
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	gverrors "z.gfire.dev/gvx/pkg/errors"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// env is an ext4lite mount that the tests drive through the VFS layer, the way
// the guest kernel drives it.
type env struct {
	t      *testing.T
	ctx    gvcontext.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	root   vfs.VirtualDentry
	mntns  *vfs.MountNamespace
	vol    *Volume
	fs     *filesystem
	path   string
	done   bool
}

// cookieContext supplies the inotify cookie, the resource limits, and the
// credentials that the kernel task context normally supplies.
type cookieContext struct {
	gvcontext.Context
}

var (
	testLimits = limits.NewLimitSet()
	testCreds  = auth.NewRootCredentials(auth.NewRootUserNamespace())
)

// Value implements context.Context.Value.
func (c cookieContext) Value(key any) any {
	switch key {
	case uniqueid.CtxInotifyCookie:
		return uint32(1)
	case limits.CtxLimits:
		return testLimits
	case auth.CtxCredentials:
		return testCreds
	}
	return c.Context.Value(key)
}

// fakeClock returns a clock that advances by one second at every call. Tests
// then compare times without a dependence on the resolution of the host clock.
func fakeClock() func() time.Time {
	var tick atomic.Int64
	base := time.Unix(1_700_000_000, 0)
	return func() time.Time {
		return base.Add(time.Duration(tick.Add(1)) * time.Second)
	}
}

// newEnv formats a new volume in a temporary directory and mounts it.
func newEnv(t *testing.T) *env {
	t.Helper()
	return openEnv(t, filepath.Join(t.TempDir(), "vol.ext4"), VolumeOptions{}, vfs.MountOptions{})
}

// openEnv opens the image at path, which the call creates when it is missing,
// and mounts it.
func openEnv(t *testing.T, path string, vopts VolumeOptions, mopts vfs.MountOptions) *env {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	vol, err := OpenVolume(f, vopts)
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	vol.v.now = fakeClock()
	return mountVolume(t, vol, path, mopts)
}

func mountVolume(t *testing.T, vol *Volume, path string, mopts vfs.MountOptions) *env {
	t.Helper()
	vol.v.assertGate.Store(true)
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("vfsObj.Init: %v", err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	mopts.GetFilesystemOptions.InternalData = InternalFilesystemOptions{Volume: vol}
	mntns, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &mopts, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	root := mntns.Root(ctx)
	e := &env{
		t:      t,
		ctx:    cookieContext{vfs.WithMountNamespace(ctx, mntns)},
		creds:  creds,
		vfsObj: vfsObj,
		root:   root,
		mntns:  mntns,
		vol:    vol,
		fs:     root.Mount().Filesystem().Impl().(*filesystem),
		path:   path,
	}
	t.Cleanup(e.unmount)
	return e
}

// unmount releases the mount, which closes the volume. A second call does
// nothing.
func (e *env) unmount() {
	if e.done {
		return
	}
	e.done = true
	e.root.DecRef(e.ctx)
	e.mntns.DecRef(e.ctx)
}

// remount unmounts the volume and mounts the same image again.
func (e *env) remount() *env {
	e.t.Helper()
	e.unmount()
	return openEnv(e.t, e.path, VolumeOptions{}, vfs.MountOptions{})
}

// pop names a path without following a final symbolic link, as creation,
// deletion, and rename require.
func (e *env) pop(p string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse(p)}
}

// fpop names a path and follows a final symbolic link.
func (e *env) fpop(p string) *vfs.PathOperation {
	pop := e.pop(p)
	pop.FollowFinalSymlink = true
	return pop
}

func (e *env) mkdir(p string) error {
	return e.vfsObj.MkdirAt(e.ctx, e.creds, e.pop(p), &vfs.MkdirOptions{Mode: 0o755})
}

func (e *env) mustMkdir(p string) {
	e.t.Helper()
	if err := e.mkdir(p); err != nil {
		e.t.Fatalf("mkdir %q: %v", p, err)
	}
}

func (e *env) open(p string, flags uint32, mode linux.FileMode) (*vfs.FileDescription, error) {
	return e.vfsObj.OpenAt(e.ctx, e.creds, e.fpop(p), &vfs.OpenOptions{Flags: flags, Mode: mode})
}

func (e *env) mustOpen(p string, flags uint32) *vfs.FileDescription {
	e.t.Helper()
	fd, err := e.open(p, flags, 0o644)
	if err != nil {
		e.t.Fatalf("open %q: %v", p, err)
	}
	return fd
}

func (e *env) write(fd *vfs.FileDescription, data []byte) {
	e.t.Helper()
	if n, err := fd.Write(e.ctx, usermem.BytesIOSequence(data), vfs.WriteOptions{}); err != nil || int(n) != len(data) {
		e.t.Fatalf("write = (%d, %v), want %d bytes", n, err, len(data))
	}
}

func (e *env) pwrite(fd *vfs.FileDescription, data []byte, off int64) {
	e.t.Helper()
	if n, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(data), off, vfs.WriteOptions{}); err != nil || int(n) != len(data) {
		e.t.Fatalf("pwrite at %d = (%d, %v), want %d bytes", off, n, err, len(data))
	}
}

func (e *env) writeFile(p string, data []byte) {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_CREAT|linux.O_WRONLY|linux.O_TRUNC)
	defer fd.DecRef(e.ctx)
	e.write(fd, data)
}

func (e *env) readAll(fd *vfs.FileDescription) []byte {
	e.t.Helper()
	var out []byte
	buf := make([]byte, 4096)
	for off := int64(0); ; {
		n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
		out = append(out, buf[:n]...)
		off += n
		if errors.Is(err, io.EOF) || (err == nil && n == 0) {
			return out
		}
		if err != nil {
			e.t.Fatalf("read: %v", err)
		}
	}
}

func (e *env) readFile(p string) []byte {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY)
	defer fd.DecRef(e.ctx)
	return e.readAll(fd)
}

func (e *env) statOp(pop *vfs.PathOperation) (linux.Statx, error) {
	return e.vfsObj.StatAt(e.ctx, e.creds, pop, &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS | linux.STATX_BTIME})
}

func (e *env) stat(p string) (linux.Statx, error) { return e.statOp(e.fpop(p)) }

func (e *env) lstat(p string) (linux.Statx, error) { return e.statOp(e.pop(p)) }

func (e *env) mustStat(p string) linux.Statx {
	e.t.Helper()
	st, err := e.stat(p)
	if err != nil {
		e.t.Fatalf("stat %q: %v", p, err)
	}
	return st
}

func (e *env) unlink(p string) error {
	return e.vfsObj.UnlinkAt(e.ctx, e.creds, e.pop(p))
}

func (e *env) rmdir(p string) error {
	return e.vfsObj.RmdirAt(e.ctx, e.creds, e.pop(p))
}

func (e *env) rename(oldPath, newPath string) error {
	return e.renameFlags(oldPath, newPath, 0)
}

func (e *env) renameFlags(oldPath, newPath string, flags uint32) error {
	return e.vfsObj.RenameAt(e.ctx, e.creds, e.pop(oldPath), e.pop(newPath), &vfs.RenameOptions{Flags: flags})
}

func (e *env) link(oldPath, newPath string) error {
	return e.vfsObj.LinkAt(e.ctx, e.creds, e.pop(oldPath), e.pop(newPath))
}

func (e *env) symlink(target, p string) error {
	return e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop(p), target)
}

func (e *env) readdir(p string) []string {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	var names []string
	err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			names = append(names, d.Name)
		}
		return nil
	}))
	if err != nil {
		e.t.Fatalf("readdir %q: %v", p, err)
	}
	sort.Strings(names)
	return names
}

func (e *env) setStat(p string, stat linux.Statx) error {
	return e.vfsObj.SetStatAt(e.ctx, e.creds, e.fpop(p), &vfs.SetStatOptions{Stat: stat})
}

func wantErrno(t *testing.T, what string, err error, want *gverrors.Error) {
	t.Helper()
	if !linuxerr.Equals(want, err) {
		t.Fatalf("%s = %v, want %v", what, err, want)
	}
}

func wantBytes(t *testing.T, what string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Fatalf("%s: got %d bytes, want %d bytes, first difference at %d", what, len(got), len(want), firstDiff(got, want))
	}
}

func firstDiff(a, b []byte) int {
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

// userEnv returns credentials of an unprivileged user.
func userCreds(uid auth.KUID, gid auth.KGID) *auth.Credentials {
	return auth.NewUserCredentials(uid, gid, nil, nil, auth.NewRootUserNamespace())
}

func TestCreateReadWriteTruncateSeek(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpen("f", linux.O_CREAT|linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.write(fd, []byte("hello world"))
	if got := e.readAll(fd); string(got) != "hello world" {
		t.Fatalf("read after write = %q", got)
	}

	// pwrite does not move the offset, and a gap reads as zeros.
	e.pwrite(fd, []byte("HELLO"), 0)
	e.pwrite(fd, []byte("tail"), 20)
	want := append([]byte("HELLO world"), make([]byte, 9)...)
	want = append(want, "tail"...)
	wantBytes(t, "content", e.readAll(fd), want)

	if off, err := fd.Seek(e.ctx, 0, linux.SEEK_END); err != nil || off != 24 {
		t.Fatalf("SEEK_END = (%d, %v), want 24", off, err)
	}
	e.write(fd, []byte("+"))
	if off, err := fd.Seek(e.ctx, -2, linux.SEEK_CUR); err != nil || off != 23 {
		t.Fatalf("SEEK_CUR = (%d, %v), want 23", off, err)
	}
	buf := make([]byte, 8)
	n, err := fd.Read(e.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || string(buf[:n]) != "l+" {
		t.Fatalf("read at 23 = (%q, %v), want \"l+\"", buf[:n], err)
	}
	if _, err := fd.Read(e.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); !errors.Is(err, io.EOF) {
		t.Fatalf("read at the end = %v, want EOF", err)
	}
	if _, err := fd.Seek(e.ctx, -100, linux.SEEK_SET); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("seek to a negative offset = %v, want EINVAL", err)
	}

	// Truncate shrinks and grows. Growth reads back zeros, even where the
	// shrink removed bytes before.
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 5}}); err != nil {
		t.Fatalf("truncate to 5: %v", err)
	}
	wantBytes(t, "after shrink", e.readAll(fd), []byte("HELLO"))
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 10}}); err != nil {
		t.Fatalf("truncate to 10: %v", err)
	}
	wantBytes(t, "after growth", e.readAll(fd), append([]byte("HELLO"), make([]byte, 5)...))
	if st := e.mustStat("f"); st.Size != 10 {
		t.Fatalf("stat size = %d, want 10", st.Size)
	}
}

func TestOpenFlags(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("abc"))
	e.mustMkdir("d")
	if err := e.symlink("f", "link"); err != nil {
		t.Fatal(err)
	}

	if _, err := e.open("f", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644); !linuxerr.Equals(linuxerr.EEXIST, err) {
		t.Fatalf("O_EXCL on an existing file = %v, want EEXIST", err)
	}
	if _, err := e.open("f", linux.O_RDONLY|linux.O_DIRECTORY, 0); !linuxerr.Equals(linuxerr.ENOTDIR, err) {
		t.Fatalf("O_DIRECTORY on a file = %v, want ENOTDIR", err)
	}
	if _, err := e.open("d", linux.O_WRONLY, 0); !linuxerr.Equals(linuxerr.EISDIR, err) {
		t.Fatalf("open a directory for writing = %v, want EISDIR", err)
	}
	if _, err := e.open("link", linux.O_RDONLY|linux.O_NOFOLLOW, 0); !linuxerr.Equals(linuxerr.ELOOP, err) {
		t.Fatalf("O_NOFOLLOW on a symlink = %v, want ELOOP", err)
	}
	if _, err := e.open("missing", linux.O_RDONLY, 0); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("open a missing file = %v, want ENOENT", err)
	}

	fd := e.mustOpen("f", linux.O_WRONLY|linux.O_TRUNC)
	fd.DecRef(e.ctx)
	if st := e.mustStat("f"); st.Size != 0 {
		t.Fatalf("size after O_TRUNC = %d, want 0", st.Size)
	}

	// O_APPEND writes at the end, whatever the offset is.
	e.writeFile("log", []byte("one"))
	fd = e.mustOpen("log", linux.O_WRONLY|linux.O_APPEND)
	defer fd.DecRef(e.ctx)
	if _, err := fd.Seek(e.ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	e.write(fd, []byte("two"))
	e.pwrite(fd, []byte("three"), 0)
	wantBytes(t, "append content", e.readFile("log"), []byte("onetwothree"))
}

// TestInlineToExtent writes the largest inline content and one byte more. The
// engine moves the content to a block at that byte, and the content stays
// intact.
func TestInlineToExtent(t *testing.T) {
	if maxInline != 128 {
		t.Fatalf("maxInline = %d, the specification says 128", maxInline)
	}
	e := newEnv(t)
	inline := pattern(1, 128)
	e.writeFile("small", inline)
	if st := e.mustStat("small"); st.Blocks != 0 {
		t.Fatalf("an inline file owns %d sectors, want 0", st.Blocks)
	}
	fd := e.mustOpen("small", linux.O_RDWR)
	e.pwrite(fd, []byte{0xEE}, 128)
	want := append(bytes.Clone(inline), 0xEE)
	wantBytes(t, "content after conversion", e.readAll(fd), want)
	if st := e.mustStat("small"); st.Blocks != blockSize/512 || st.Size != uint64(len(want)) {
		t.Fatalf("after conversion: %d sectors and size %d, want %d sectors and size %d", st.Blocks, st.Size, blockSize/512, len(want))
	}
	fd.DecRef(e.ctx)

	e = e.remount()
	wantBytes(t, "content after remount", e.readFile("small"), want)
}

func TestSparseFileSeek(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpen("sparse", linux.O_CREAT|linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.pwrite(fd, pattern(2, blockSize), 0)
	e.pwrite(fd, pattern(3, blockSize), 1<<20)
	size := int64(1<<20 + blockSize)
	st := e.mustStat("sparse")
	if st.Size != uint64(size) || st.Blocks != 2*blockSize/512 {
		t.Fatalf("sparse file: size %d, %d sectors, want size %d, %d sectors", st.Size, st.Blocks, size, 2*blockSize/512)
	}
	cases := []struct {
		name   string
		off    int64
		whence int32
		want   int64
		errno  *gverrors.Error
	}{
		{"data at the start", 0, linux.SEEK_DATA, 0, nil},
		{"data in the hole", blockSize, linux.SEEK_DATA, 1 << 20, nil},
		{"hole after the first block", 0, linux.SEEK_HOLE, blockSize, nil},
		{"hole inside the hole", 100000, linux.SEEK_HOLE, 100000, nil},
		{"hole after the last block", 1 << 20, linux.SEEK_HOLE, size, nil},
		{"data at the end", size, linux.SEEK_DATA, 0, linuxerr.ENXIO},
		{"hole at the end", size, linux.SEEK_HOLE, 0, linuxerr.ENXIO},
	}
	for _, c := range cases {
		got, err := fd.Seek(e.ctx, c.off, c.whence)
		if c.errno != nil {
			if !linuxerr.Equals(c.errno, err) {
				t.Errorf("%s: Seek = (%d, %v), want %v", c.name, got, err, c.errno)
			}
			continue
		}
		if err != nil || got != c.want {
			t.Errorf("%s: Seek = (%d, %v), want %d", c.name, got, err, c.want)
		}
	}
	// The hole reads as zeros.
	buf := make([]byte, 16)
	if n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 500000, vfs.ReadOptions{}); err != nil || n != 16 || !isZero(buf) {
		t.Fatalf("read in the hole = (%d, %v, %v)", n, err, buf)
	}
}

func TestReaddirPagination(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	var want []string
	for i := range 700 {
		name := fmt.Sprintf("entry-%04d-%s", i, strings.Repeat("x", 40))
		e.writeFile("d/"+name, nil)
		want = append(want, name)
	}
	sort.Strings(want)
	if got := e.readdir("d"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("readdir returned %d names, want %d", len(got), len(want))
	}

	// A getdents call that has no room for another entry returns the error
	// of the callback, and the next call restarts at the same entry.
	fd := e.mustOpen("d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	errFull := errors.New("buffer full")
	var seen []string
	pages := 0
	for {
		room := 37
		done := false
		err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
			if room == 0 {
				return errFull
			}
			room--
			seen = append(seen, d.Name)
			return nil
		}))
		pages++
		if err == nil {
			done = true
		} else if !errors.Is(err, errFull) {
			t.Fatalf("IterDirents: %v", err)
		}
		if done {
			break
		}
	}
	if pages < 2 {
		t.Fatalf("the listing took %d pages, want several", pages)
	}
	if seen[0] != "." || seen[1] != ".." {
		t.Fatalf("the listing starts with %q and %q, want . and ..", seen[0], seen[1])
	}
	got := append([]string(nil), seen[2:]...)
	sort.Strings(got)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paged listing returned %d names, want %d without a repeat or a gap", len(got), len(want))
	}

	// Seeking to the start lists the directory again with its current entries.
	e.writeFile("d/zzz-new", nil)
	if _, err := fd.Seek(e.ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	var again []string
	if err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		again = append(again, d.Name)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	if len(again) != len(seen)+1 {
		t.Fatalf("listing after rewind has %d entries, want %d", len(again), len(seen)+1)
	}
}

func TestDirentTypes(t *testing.T) {
	e := newEnv(t)
	e.writeFile("reg", nil)
	e.mustMkdir("dir")
	if err := e.symlink("reg", "lnk"); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("fifo"), &vfs.MknodOptions{Mode: linux.S_IFIFO | 0o600}); err != nil {
		t.Fatal(err)
	}
	fd := e.mustOpen("/", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	types := map[string]uint8{}
	if err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		types[d.Name] = d.Type
		if d.Ino == 0 {
			t.Errorf("entry %q has no inode number", d.Name)
		}
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	want := map[string]uint8{".": linux.DT_DIR, "..": linux.DT_DIR, "reg": linux.DT_REG, "dir": linux.DT_DIR, "lnk": linux.DT_LNK, "fifo": linux.DT_FIFO}
	for name, typ := range want {
		if types[name] != typ {
			t.Errorf("type of %q = %d, want %d", name, types[name], typ)
		}
	}
}

func TestRename(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("b")
	e.writeFile("a/f", []byte("payload"))

	t.Run("file in a directory", func(t *testing.T) {
		if err := e.rename("a/f", "a/g"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.stat("a/f"); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Fatalf("stat of the old name = %v, want ENOENT", err)
		}
		wantBytes(t, "renamed file", e.readFile("a/g"), []byte("payload"))
	})

	t.Run("over an existing file", func(t *testing.T) {
		e.writeFile("b/victim", []byte("old"))
		before := e.mustStat("b/victim").Ino
		if err := e.rename("a/g", "b/victim"); err != nil {
			t.Fatal(err)
		}
		wantBytes(t, "replaced file", e.readFile("b/victim"), []byte("payload"))
		if got := e.mustStat("b/victim").Ino; got == before {
			t.Fatalf("the target keeps the inode %d of the replaced file", got)
		}
		if got := e.readdir("a"); len(got) != 0 {
			t.Fatalf("source directory lists %v after the move", got)
		}
	})

	t.Run("noreplace", func(t *testing.T) {
		e.writeFile("a/n", []byte("n"))
		err := e.renameFlags("a/n", "b/victim", linux.RENAME_NOREPLACE)
		wantErrno(t, "RENAME_NOREPLACE onto an existing name", err, linuxerr.EEXIST)
		if err := e.renameFlags("a/n", "b/fresh", linux.RENAME_NOREPLACE); err != nil {
			t.Fatalf("RENAME_NOREPLACE to a free name: %v", err)
		}
		wantBytes(t, "moved file", e.readFile("b/fresh"), []byte("n"))
	})

	t.Run("exchange", func(t *testing.T) {
		e.writeFile("a/x", []byte("xx"))
		e.mustMkdir("b/y")
		e.writeFile("b/y/inner", []byte("in"))
		if err := e.renameFlags("a/x", "b/y", linux.RENAME_EXCHANGE); err != nil {
			t.Fatal(err)
		}
		wantBytes(t, "file after the exchange", e.readFile("b/y"), []byte("xx"))
		wantBytes(t, "directory after the exchange", e.readFile("a/x/inner"), []byte("in"))
		// The moved directory belongs to the other parent now: its ".." and
		// the link counts of both parents changed.
		a, b := e.mustStat("a"), e.mustStat("b")
		if a.Nlink != 3 || b.Nlink != 2 {
			t.Fatalf("link counts after the exchange: a=%d b=%d, want a=3 b=2", a.Nlink, b.Nlink)
		}
		wantErrno(t, "exchange with a missing name", e.renameFlags("a/x", "a/missing", linux.RENAME_EXCHANGE), linuxerr.ENOENT)
		wantErrno(t, "NOREPLACE with EXCHANGE", e.renameFlags("a/x", "a/y2", linux.RENAME_NOREPLACE|linux.RENAME_EXCHANGE), linuxerr.EINVAL)
		wantErrno(t, "RENAME_WHITEOUT", e.renameFlags("a/x", "a/y2", linux.RENAME_WHITEOUT), linuxerr.EINVAL)
	})
}

func TestRenameDirectoryAcrossParents(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("p1")
	e.mustMkdir("p2")
	e.mustMkdir("p1/dir")
	e.mustMkdir("p1/dir/sub")
	e.writeFile("p1/dir/sub/file", []byte("deep"))
	if st := e.mustStat("p1"); st.Nlink != 3 {
		t.Fatalf("p1 nlink = %d, want 3", st.Nlink)
	}

	if err := e.rename("p1/dir", "p2/moved"); err != nil {
		t.Fatal(err)
	}
	if p1, p2 := e.mustStat("p1"), e.mustStat("p2"); p1.Nlink != 2 || p2.Nlink != 3 {
		t.Fatalf("link counts after the move: p1=%d p2=%d, want 2 and 3", p1.Nlink, p2.Nlink)
	}
	wantBytes(t, "file below the moved directory", e.readFile("p2/moved/sub/file"), []byte("deep"))
	// ".." of the moved directory names the new parent.
	if got, want := e.mustStat("p2/moved/..").Ino, e.mustStat("p2").Ino; got != want {
		t.Fatalf("\"..\" of the moved directory is inode %d, want %d", got, want)
	}

	// A directory cannot move below itself.
	wantErrno(t, "move into a subdirectory of itself", e.rename("p2/moved", "p2/moved/sub/inside"), linuxerr.EINVAL)
	// A directory replaces an empty directory but not a full one.
	e.mustMkdir("p1/empty")
	e.mustMkdir("p1/full")
	e.writeFile("p1/full/x", nil)
	if err := e.rename("p2/moved/sub", "p1/empty"); err != nil {
		t.Fatalf("directory over an empty directory: %v", err)
	}
	wantErrno(t, "directory over a full directory", e.rename("p2/moved", "p1/full"), linuxerr.ENOTEMPTY)
	wantErrno(t, "file over a directory", e.rename("p1/full/x", "p1/empty"), linuxerr.EISDIR)
	wantErrno(t, "directory over a file", e.rename("p1/empty", "p1/full/x"), linuxerr.ENOTDIR)

	// The directory structure survives a remount with correct link counts.
	e = e.remount()
	if p1, p2 := e.mustStat("p1"), e.mustStat("p2"); p1.Nlink != 4 || p2.Nlink != 3 {
		t.Fatalf("link counts after remount: p1=%d p2=%d, want 4 and 3", p1.Nlink, p2.Nlink)
	}
	wantBytes(t, "file after remount", e.readFile("p1/empty/file"), []byte("deep"))
}

func TestHardLinks(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("a", []byte("shared"))
	if err := e.link("a", "d/b"); err != nil {
		t.Fatal(err)
	}
	sa, sb := e.mustStat("a"), e.mustStat("d/b")
	if sa.Ino != sb.Ino || sa.Nlink != 2 || sb.Nlink != 2 {
		t.Fatalf("after link: inodes %d and %d, nlink %d and %d, want one inode and nlink 2", sa.Ino, sb.Ino, sa.Nlink, sb.Nlink)
	}
	// A write through one name shows through the other.
	fd := e.mustOpen("d/b", linux.O_WRONLY)
	e.pwrite(fd, []byte("SH"), 0)
	fd.DecRef(e.ctx)
	wantBytes(t, "content through the first name", e.readFile("a"), []byte("SHared"))

	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("d/b"); st.Nlink != 1 {
		t.Fatalf("nlink after unlinking one name = %d, want 1", st.Nlink)
	}
	wantBytes(t, "content after unlinking one name", e.readFile("d/b"), []byte("SHared"))

	wantErrno(t, "link to a directory", e.link("d", "dlink"), linuxerr.EPERM)
	wantErrno(t, "link over an existing name", e.link("d/b", "d"), linuxerr.EEXIST)
	wantErrno(t, "link to a missing file", e.link("missing", "m"), linuxerr.ENOENT)

	e = e.remount()
	if st := e.mustStat("d/b"); st.Nlink != 1 {
		t.Fatalf("nlink after remount = %d, want 1", st.Nlink)
	}
	wantBytes(t, "content after remount", e.readFile("d/b"), []byte("SHared"))
}

func TestSymlinks(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("dir")
	e.writeFile("dir/file", []byte("target content"))
	long := strings.Repeat("d/", 200) + "end"
	for _, c := range []struct{ target, name string }{
		{"dir/file", "short"},
		{"/dir/file", "absolute"},
		{"../dir/file", "dir/relative"},
		{long, "long"},
	} {
		if err := e.symlink(c.target, c.name); err != nil {
			t.Fatalf("symlink %q: %v", c.name, err)
		}
		got, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop(c.name))
		if err != nil || got != c.target {
			t.Fatalf("readlink %q = (%q, %v), want %q", c.name, got, err, c.target)
		}
	}
	wantBytes(t, "read through a short link", e.readFile("short"), []byte("target content"))
	wantBytes(t, "read through an absolute link", e.readFile("absolute"), []byte("target content"))
	wantBytes(t, "read through a relative link", e.readFile("dir/relative"), []byte("target content"))
	if st, err := e.lstat("long"); err != nil || st.Size != uint64(len(long)) || st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Fatalf("lstat of the long link = (%+v, %v)", st, err)
	}

	// Loops end in ELOOP, and a link to nothing ends in ENOENT.
	if err := e.symlink("loop2", "loop1"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink("loop1", "loop2"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink("self", "self"); err != nil {
		t.Fatal(err)
	}
	if err := e.symlink("nowhere", "dangling"); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"loop1", "self"} {
		if _, err := e.open(name, linux.O_RDONLY, 0); !linuxerr.Equals(linuxerr.ELOOP, err) {
			t.Fatalf("open of %q = %v, want ELOOP", name, err)
		}
	}
	if _, err := e.open("dangling", linux.O_RDONLY, 0); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("open of a dangling link = %v, want ENOENT", err)
	}
	// The creation of a file through a dangling link creates the target.
	fd := e.mustOpen("dangling", linux.O_CREAT|linux.O_WRONLY)
	fd.DecRef(e.ctx)
	if _, err := e.stat("nowhere"); err != nil {
		t.Fatalf("stat of the file that the dangling link created: %v", err)
	}
	if _, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("dir/file")); !linuxerr.Equals(linuxerr.EINVAL, err) {
		t.Fatalf("readlink of a file = %v, want EINVAL", err)
	}
	wantErrno(t, "empty target", e.symlink("", "empty"), linuxerr.ENOENT)

	e = e.remount()
	if got, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("long")); err != nil || got != long {
		t.Fatalf("readlink of the long link after remount = (%d bytes, %v), want %d bytes", len(got), err, len(long))
	}
	wantBytes(t, "read through a link after remount", e.readFile("short"), []byte("target content"))
}

func TestUnlinkOpenFile(t *testing.T) {
	e := newEnv(t)
	// statfs adds the free space of the host volume, which changes at any time.
	// The test reads the counter of the volume instead.
	free := func() uint64 {
		e.fs.v.mu.Lock()
		defer e.fs.v.mu.Unlock()
		return e.fs.v.freeBlocksTotal
	}
	data := pattern(5, 300*1024)
	e.writeFile("doomed", data)
	fd := e.mustOpen("doomed", linux.O_RDWR)
	before := free()
	if err := e.unlink("doomed"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.stat("doomed"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat after unlink = %v, want ENOENT", err)
	}
	// The name is free for a new file while the old one stays open.
	e.writeFile("doomed", []byte("new"))
	wantBytes(t, "open file after unlink", e.readAll(fd), data)
	e.pwrite(fd, []byte("late"), 0)
	st, err := fd.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
	if err != nil || st.Nlink != 0 || st.Size != uint64(len(data)) {
		t.Fatalf("fstat of the unlinked file = (nlink %d, size %d, %v), want nlink 0 and size %d", st.Nlink, st.Size, err, len(data))
	}
	if got := free(); got > before {
		t.Fatalf("free blocks grew from %d to %d while the unlinked file is open", before, got)
	}
	wantBytes(t, "new file under the old name", e.readFile("doomed"), []byte("new"))

	fd.DecRef(e.ctx)
	if got := free(); got < before+uint64(len(data))/blockSize {
		t.Fatalf("free blocks after the last close = %d, want at least %d", got, before+uint64(len(data))/blockSize)
	}
}

func TestRmdir(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", nil)
	wantErrno(t, "rmdir of a full directory", e.rmdir("d"), linuxerr.ENOTEMPTY)
	wantErrno(t, "rmdir of a file", e.rmdir("d/f"), linuxerr.ENOTDIR)
	wantErrno(t, "unlink of a directory", e.unlink("d"), linuxerr.EISDIR)
	wantErrno(t, "rmdir of \"..\"", e.rmdir("d/.."), linuxerr.ENOTEMPTY)
	wantErrno(t, "rmdir of \".\"", e.rmdir("d/."), linuxerr.EINVAL)
	if err := e.unlink("d/f"); err != nil {
		t.Fatal(err)
	}
	root := e.mustStat("/").Nlink
	if err := e.rmdir("d"); err != nil {
		t.Fatalf("rmdir of an empty directory: %v", err)
	}
	if _, err := e.stat("d"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat after rmdir = %v, want ENOENT", err)
	}
	if got := e.mustStat("/").Nlink; got != root-1 {
		t.Fatalf("root nlink = %d after rmdir, want %d", got, root-1)
	}
}

func TestOpenDirectoryAfterRmdir(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("gone")
	fd := e.mustOpen("gone", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	if err := e.rmdir("gone"); err != nil {
		t.Fatal(err)
	}
	if st, err := fd.Stat(e.ctx, vfs.StatOptions{}); err != nil || st.Nlink != 0 {
		t.Fatalf("fstat of the removed directory = (nlink %d, %v), want nlink 0", st.Nlink, err)
	}
	wantErrno(t, "mkdir below a removed directory", e.vfsObj.MkdirAt(e.ctx, e.creds, &vfs.PathOperation{Root: e.root, Start: fd.VirtualDentry(), Path: fspath.Parse("child")}, &vfs.MkdirOptions{Mode: 0o755}), linuxerr.ENOENT)
}

func TestXattr(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("x"))
	pop := e.fpop("f")
	set := func(name, value string, flags uint32) error {
		return e.vfsObj.SetXattrAt(e.ctx, e.creds, pop, &vfs.SetXattrOptions{Name: name, Value: value, Flags: flags})
	}
	get := func(name string) (string, error) {
		return e.vfsObj.GetXattrAt(e.ctx, e.creds, pop, &vfs.GetXattrOptions{Name: name, Size: 1 << 16})
	}
	if err := set("user.a", "alpha", 0); err != nil {
		t.Fatal(err)
	}
	if err := set("user.b", "beta", 0); err != nil {
		t.Fatal(err)
	}
	if err := set("trusted.t", "secret", 0); err != nil {
		t.Fatal(err)
	}
	if got, err := get("user.a"); err != nil || got != "alpha" {
		t.Fatalf("get user.a = (%q, %v)", got, err)
	}
	names, err := e.vfsObj.ListXattrAt(e.ctx, e.creds, pop, 1<<16)
	sort.Strings(names)
	if err != nil || strings.Join(names, ",") != "trusted.t,user.a,user.b" {
		t.Fatalf("list = (%v, %v)", names, err)
	}
	wantErrno(t, "list with a small buffer", func() error {
		_, err := e.vfsObj.ListXattrAt(e.ctx, e.creds, pop, 4)
		return err
	}(), linuxerr.ERANGE)
	wantErrno(t, "create over an existing attribute", set("user.a", "again", linux.XATTR_CREATE), linuxerr.EEXIST)
	wantErrno(t, "replace of a missing attribute", set("user.missing", "v", linux.XATTR_REPLACE), linuxerr.ENODATA)
	if err := set("user.a", "ALPHA", linux.XATTR_REPLACE); err != nil {
		t.Fatal(err)
	}
	if got, _ := get("user.a"); got != "ALPHA" {
		t.Fatalf("user.a after replace = %q", got)
	}
	_, err = e.vfsObj.GetXattrAt(e.ctx, e.creds, pop, &vfs.GetXattrOptions{Name: "user.a", Size: 2})
	wantErrno(t, "get into a small buffer", err, linuxerr.ERANGE)
	_, err = get("user.missing")
	wantErrno(t, "get of a missing attribute", err, linuxerr.ENODATA)
	wantErrno(t, "unsupported namespace", set("system.posix_acl_access", "x", 0), linuxerr.EOPNOTSUPP)

	// The attributes of a file share one 4 KiB block.
	wantErrno(t, "value above the block", set("user.big", strings.Repeat("v", 5000), 0), linuxerr.ENOSPC)
	if err := set("user.fits", strings.Repeat("v", 3000), 0); err != nil {
		t.Fatalf("value of 3000 bytes: %v", err)
	}
	wantErrno(t, "second value above the block", set("user.fits2", strings.Repeat("w", 3000), 0), linuxerr.ENOSPC)

	if err := e.vfsObj.RemoveXattrAt(e.ctx, e.creds, pop, "user.b"); err != nil {
		t.Fatal(err)
	}
	wantErrno(t, "remove of a missing attribute", e.vfsObj.RemoveXattrAt(e.ctx, e.creds, pop, "user.b"), linuxerr.ENODATA)

	// Attributes on a descriptor and on a directory, then a remount.
	func() {
		fd := e.mustOpen("f", linux.O_RDONLY)
		defer fd.DecRef(e.ctx)
		if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "fdv"}); err != nil {
			t.Fatal(err)
		}
	}()
	e.mustMkdir("d")
	if err := e.vfsObj.SetXattrAt(e.ctx, e.creds, e.fpop("d"), &vfs.SetXattrOptions{Name: "user.dir", Value: "dv"}); err != nil {
		t.Fatal(err)
	}
	e = e.remount()
	pop = e.fpop("f")
	for name, want := range map[string]string{"user.a": "ALPHA", "user.fits": strings.Repeat("v", 3000), "user.fd": "fdv", "trusted.t": "secret"} {
		if got, err := get(name); err != nil || got != want {
			t.Fatalf("after remount get %s = (%d bytes, %v), want %d bytes", name, len(got), err, len(want))
		}
	}
	if got, err := e.vfsObj.GetXattrAt(e.ctx, e.creds, e.fpop("d"), &vfs.GetXattrOptions{Name: "user.dir", Size: 100}); err != nil || got != "dv" {
		t.Fatalf("directory attribute after remount = (%q, %v)", got, err)
	}

}

func TestXattrPermissions(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", nil)
	user := userCreds(1000, 1000)
	pop := e.fpop("f")
	err := e.vfsObj.SetXattrAt(e.ctx, user, pop, &vfs.SetXattrOptions{Name: "user.x", Value: "v"})
	wantErrno(t, "set by a user without write permission", err, linuxerr.EACCES)
	if err := e.vfsObj.SetXattrAt(e.ctx, e.creds, pop, &vfs.SetXattrOptions{Name: "trusted.x", Value: "v"}); err != nil {
		t.Fatal(err)
	}
	names, err := e.vfsObj.ListXattrAt(e.ctx, user, pop, 0)
	if err != nil || len(names) != 0 {
		t.Fatalf("a user lists %v, %v; the trusted namespace must stay hidden", names, err)
	}
}

func TestSpecialFiles(t *testing.T) {
	e := newEnv(t)
	mk := func(name string, mode linux.FileMode, major, minor uint32, ep *fakeEndpoint) {
		t.Helper()
		opts := &vfs.MknodOptions{Mode: mode, DevMajor: major, DevMinor: minor}
		if ep != nil {
			opts.Endpoint = ep
		}
		if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop(name), opts); err != nil {
			t.Fatalf("mknod %q: %v", name, err)
		}
	}

	t.Run("fifo", func(t *testing.T) {
		mk("fifo", linux.S_IFIFO|0o666, 0, 0, nil)
		st := e.mustStat("fifo")
		if st.Mode&linux.S_IFMT != linux.S_IFIFO || st.Size != 0 {
			t.Fatalf("stat of the FIFO: mode %#o, size %d", st.Mode, st.Size)
		}
		rw := e.mustOpen("fifo", linux.O_RDWR|linux.O_NONBLOCK)
		e.write(rw, []byte("through the pipe"))
		buf := make([]byte, 64)
		n, err := rw.Read(e.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if err != nil || string(buf[:n]) != "through the pipe" {
			t.Fatalf("read from the FIFO = (%q, %v)", buf[:n], err)
		}
		// A second open shares the pipe of the inode.
		w2 := e.mustOpen("fifo", linux.O_WRONLY|linux.O_NONBLOCK)
		e.write(w2, []byte("second"))
		n, err = rw.Read(e.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		if err != nil || string(buf[:n]) != "second" {
			t.Fatalf("read of the second writer = (%q, %v)", buf[:n], err)
		}
		// A write-only open without a reader fails at once with ENXIO.
		rw.DecRef(e.ctx)
		w2.DecRef(e.ctx)
		if _, err := e.open("fifo", linux.O_WRONLY|linux.O_NONBLOCK, 0); !linuxerr.Equals(linuxerr.ENXIO, err) {
			t.Fatalf("O_WRONLY|O_NONBLOCK open without a reader = %v, want ENXIO", err)
		}
	})

	t.Run("socket", func(t *testing.T) {
		ep := &fakeEndpoint{}
		mk("sock", linux.S_IFSOCK|0o777, 0, 0, ep)
		if st := e.mustStat("sock"); st.Mode&linux.S_IFMT != linux.S_IFSOCK {
			t.Fatalf("stat of the socket file: mode %#o", st.Mode)
		}
		got, err := e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop("sock"), &vfs.BoundEndpointOptions{})
		if err != nil || got != ep {
			t.Fatalf("BoundEndpointAt = (%v, %v), want the bound endpoint", got, err)
		}
		if _, err := e.open("sock", linux.O_RDONLY, 0); !linuxerr.Equals(linuxerr.ENXIO, err) {
			t.Fatalf("open of a socket file = %v, want ENXIO", err)
		}
		if _, err := e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop("fifo"), &vfs.BoundEndpointOptions{}); !linuxerr.Equals(linuxerr.ECONNREFUSED, err) {
			t.Fatalf("BoundEndpointAt on a FIFO = %v, want ECONNREFUSED", err)
		}
		// A socket file without a bound endpoint refuses connections. That is
		// the state of a socket file from an earlier mount.
		mk("stale", linux.S_IFSOCK|0o777, 0, 0, nil)
		if _, err := e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop("stale"), &vfs.BoundEndpointOptions{}); !linuxerr.Equals(linuxerr.ECONNREFUSED, err) {
			t.Fatalf("BoundEndpointAt without an endpoint = %v, want ECONNREFUSED", err)
		}
	})

	t.Run("device nodes", func(t *testing.T) {
		mk("chr", linux.S_IFCHR|0o600, 4, 300, nil)
		mk("blk", linux.S_IFBLK|0o600, 8, 17, nil)
		chr, blk := e.mustStat("chr"), e.mustStat("blk")
		if chr.Mode&linux.S_IFMT != linux.S_IFCHR || chr.RdevMajor != 4 || chr.RdevMinor != 300 {
			t.Fatalf("character device: mode %#o rdev %d:%d, want %d:%d", chr.Mode, chr.RdevMajor, chr.RdevMinor, 4, 300)
		}
		if blk.Mode&linux.S_IFMT != linux.S_IFBLK || blk.RdevMajor != 8 || blk.RdevMinor != 17 {
			t.Fatalf("block device: mode %#o rdev %d:%d", blk.Mode, blk.RdevMajor, blk.RdevMinor)
		}
		for _, name := range []string{"chr", "blk"} {
			if _, err := e.open(name, linux.O_RDONLY, 0); !linuxerr.Equals(linuxerr.ENXIO, err) {
				t.Fatalf("open of the unregistered device %q = %v, want ENXIO", name, err)
			}
		}
		wantErrno(t, "mknod of a directory", e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("dd"), &vfs.MknodOptions{Mode: linux.S_IFDIR | 0o755}), linuxerr.EINVAL)
	})

	// The special files persist.
	e = e.remount()
	for name, typ := range map[string]uint16{"fifo": linux.S_IFIFO, "sock": linux.S_IFSOCK, "chr": linux.S_IFCHR, "blk": linux.S_IFBLK} {
		if st := e.mustStat(name); st.Mode&linux.S_IFMT != typ {
			t.Fatalf("%s after remount has mode %#o", name, st.Mode)
		}
	}
	if st := e.mustStat("chr"); st.RdevMajor != 4 || st.RdevMinor != 300 {
		t.Fatalf("device number after remount = %d:%d", st.RdevMajor, st.RdevMinor)
	}
	// The endpoint of the earlier mount is gone.
	if _, err := e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop("sock"), &vfs.BoundEndpointOptions{}); !linuxerr.Equals(linuxerr.ECONNREFUSED, err) {
		t.Fatalf("BoundEndpointAt after remount = %v, want ECONNREFUSED", err)
	}
}

func TestBoundSocketSurvivesCachePruning(t *testing.T) {
	e := newEnv(t)
	ep := &fakeEndpoint{}
	if err := e.vfsObj.MknodAt(e.ctx, e.creds, e.pop("sock"), &vfs.MknodOptions{Mode: linux.S_IFSOCK | 0o777, Endpoint: ep}); err != nil {
		t.Fatal(err)
	}
	e.fs.pruneAt = 4
	for i := range 40 {
		e.writeFile(fmt.Sprintf("f%02d", i), nil)
	}
	got, err := e.vfsObj.BoundEndpointAt(e.ctx, e.creds, e.pop("sock"), &vfs.BoundEndpointOptions{})
	if err != nil || got != ep {
		t.Fatalf("BoundEndpointAt after pruning = (%v, %v), want the bound endpoint", got, err)
	}
}

func TestFallocate(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpen("f", linux.O_CREAT|linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	e.write(fd, pattern(7, 3*blockSize))

	// Mode 0 grows the file and allocates the blocks.
	if err := fd.Allocate(e.ctx, 0, 0, 10*blockSize); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Size != 10*blockSize || st.Blocks != 10*blockSize/512 {
		t.Fatalf("after mode 0: size %d, %d sectors, want size %d and %d sectors", st.Size, st.Blocks, 10*blockSize, 10*blockSize/512)
	}
	// KEEP_SIZE allocates beyond the end and keeps the size.
	if err := fd.Allocate(e.ctx, linux.FALLOC_FL_KEEP_SIZE, 10*blockSize, 4*blockSize); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Size != 10*blockSize || st.Blocks != 14*blockSize/512 {
		t.Fatalf("after KEEP_SIZE: size %d, %d sectors, want size %d and %d sectors", st.Size, st.Blocks, 10*blockSize, 14*blockSize/512)
	}
	// PUNCH_HOLE|KEEP_SIZE frees whole blocks and zeroes partial blocks.
	punch := uint64(linux.FALLOC_FL_PUNCH_HOLE | linux.FALLOC_FL_KEEP_SIZE)
	if err := fd.Allocate(e.ctx, punch, blockSize/2, 2*blockSize); err != nil {
		t.Fatal(err)
	}
	got := e.readAll(fd)
	if len(got) != 10*blockSize {
		t.Fatalf("size after punch = %d, want %d", len(got), 10*blockSize)
	}
	want := pattern(7, 3*blockSize)
	clear(want[blockSize/2 : blockSize/2+2*blockSize])
	want = append(want, make([]byte, 7*blockSize)...)
	wantBytes(t, "content after punch", got, want)
	if pos, err := fd.Seek(e.ctx, 0, linux.SEEK_HOLE); err != nil || pos != blockSize {
		t.Fatalf("SEEK_HOLE after punch = (%d, %v), want %d", pos, err, blockSize)
	}
	// Unsupported modes.
	for _, mode := range []uint64{linux.FALLOC_FL_PUNCH_HOLE, linux.FALLOC_FL_ZERO_RANGE, linux.FALLOC_FL_COLLAPSE_RANGE, linux.FALLOC_FL_INSERT_RANGE} {
		wantErrno(t, fmt.Sprintf("fallocate mode %#x", mode), fd.Allocate(e.ctx, mode, 0, blockSize), linuxerr.EOPNOTSUPP)
	}
	wantErrno(t, "fallocate of length 0", fd.Allocate(e.ctx, 0, 0, 0), linuxerr.EINVAL)
	ro := e.mustOpen("f", linux.O_RDONLY)
	defer ro.DecRef(e.ctx)
	wantErrno(t, "fallocate on a read-only descriptor", ro.Allocate(e.ctx, 0, 0, blockSize), linuxerr.EBADF)
}

func TestChmodChownUtimes(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("x"))
	e.mustMkdir("shared")
	user := userCreds(1000, 1000)
	other := userCreds(2000, 2000)

	// The owner changes the mode, the group, and the times. Others fail.
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_UID | linux.STATX_GID, UID: 1000, GID: 1000}); err != nil {
		t.Fatal(err)
	}
	chmod := func(creds *auth.Credentials, mode uint16) error {
		return e.vfsObj.SetStatAt(e.ctx, creds, e.fpop("f"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MODE, Mode: mode}})
	}
	if err := chmod(user, 0o640); err != nil {
		t.Fatalf("chmod by the owner: %v", err)
	}
	if st := e.mustStat("f"); st.Mode&0o7777 != 0o640 || st.UID != 1000 || st.GID != 1000 || st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("stat after chmod and chown: mode %#o uid %d gid %d", st.Mode, st.UID, st.GID)
	}
	wantErrno(t, "chmod by another user", chmod(other, 0o777), linuxerr.EPERM)
	err := e.vfsObj.SetStatAt(e.ctx, user, e.fpop("f"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_UID, UID: 2000}})
	wantErrno(t, "chown to another user by a user", err, linuxerr.EPERM)

	// The permission bits decide access.
	if _, err := e.vfsObj.OpenAt(e.ctx, other, e.fpop("f"), &vfs.OpenOptions{Flags: linux.O_RDONLY}); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Fatalf("open by another user = %v, want EACCES", err)
	}
	if err := chmod(user, 0o644); err != nil {
		t.Fatal(err)
	}
	fd, err := e.vfsObj.OpenAt(e.ctx, other, e.fpop("f"), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("open by another user after chmod 644: %v", err)
	}
	fd.DecRef(e.ctx)
	if _, err := e.vfsObj.OpenAt(e.ctx, other, e.fpop("f"), &vfs.OpenOptions{Flags: linux.O_WRONLY}); !linuxerr.Equals(linuxerr.EACCES, err) {
		t.Fatalf("write open by another user = %v, want EACCES", err)
	}

	// Times: explicit values, then UTIME_NOW.
	ts := func(sec int64) linux.StatxTimestamp { return linux.StatxTimestamp{Sec: sec, Nsec: 500} }
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_ATIME | linux.STATX_MTIME, Atime: ts(1_000_000), Mtime: ts(2_000_000)}); err != nil {
		t.Fatal(err)
	}
	st := e.mustStat("f")
	if st.Atime != ts(1_000_000) || st.Mtime != ts(2_000_000) {
		t.Fatalf("times after utimes: atime %+v mtime %+v", st.Atime, st.Mtime)
	}
	if st.Ctime.Sec <= 2_000_000 {
		t.Fatalf("utimes left ctime at %d, want the current time", st.Ctime.Sec)
	}
	now := linux.StatxTimestamp{Nsec: linux.UTIME_NOW}
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_MTIME, Mtime: now}); err != nil {
		t.Fatal(err)
	}
	if got := e.mustStat("f").Mtime; got.Sec <= 2_000_000 {
		t.Fatalf("mtime after UTIME_NOW = %+v", got)
	}
	// A user without ownership may set the time to now only with write access.
	err = e.vfsObj.SetStatAt(e.ctx, other, e.fpop("f"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_MTIME, Mtime: ts(5)}})
	wantErrno(t, "explicit time by a non-owner", err, linuxerr.EPERM)

	// The root caller of this test holds CAP_FSETID, so its write keeps the
	// set-user-ID bit. The owner, without CAP_FSETID, clears it with a write.
	if err := chmod(user, 0o4755); err != nil {
		t.Fatal(err)
	}
	e.writeFile("f", []byte("rewritten"))
	if st := e.mustStat("f"); st.Mode&linux.S_ISUID == 0 {
		t.Fatalf("mode after a root write = %#o, want the set-user-ID bit kept", st.Mode)
	}
	ownerFD, err := e.vfsObj.OpenAt(e.ctx, user, e.fpop("f"), &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("owner open for writing: %v", err)
	}
	if _, err := ownerFD.PWrite(withCredentials(e.ctx, user), usermem.BytesIOSequence([]byte("owner")), 0, vfsWriteOpts); err != nil {
		t.Fatalf("owner write: %v", err)
	}
	ownerFD.DecRef(e.ctx)
	if st := e.mustStat("f"); st.Mode&linux.S_ISUID != 0 {
		t.Fatalf("mode after an owner write = %#o, want the set-user-ID bit cleared", st.Mode)
	}

	e = e.remount()
	if st := e.mustStat("f"); st.UID != 1000 || st.Mtime.Sec == 0 {
		t.Fatalf("attributes after remount: %+v", st)
	}
}

func TestPermissionsOnNamespaceChanges(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("locked")
	if err := e.setStat("locked", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o555}); err != nil {
		t.Fatal(err)
	}
	user := userCreds(1000, 1000)
	err := e.vfsObj.MkdirAt(e.ctx, user, &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse("locked/sub")}, &vfs.MkdirOptions{Mode: 0o755})
	wantErrno(t, "mkdir in a read-only directory", err, linuxerr.EACCES)
	_, err = e.vfsObj.OpenAt(e.ctx, user, &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse("locked/new"), FollowFinalSymlink: true}, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
	wantErrno(t, "create in a read-only directory", err, linuxerr.EACCES)

	// The sticky bit protects the files of other users.
	e.mustMkdir("tmp")
	if err := e.setStat("tmp", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o1777}); err != nil {
		t.Fatal(err)
	}
	e.writeFile("tmp/rootfile", nil)
	err = e.vfsObj.UnlinkAt(e.ctx, user, &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse("tmp/rootfile")})
	wantErrno(t, "unlink in a sticky directory", err, linuxerr.EPERM)
}

func TestSetgidDirectoryInheritance(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("g")
	if err := e.setStat("g", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_GID, Mode: 0o2775, GID: 4242}); err != nil {
		t.Fatal(err)
	}
	e.mustMkdir("g/sub")
	e.writeFile("g/file", nil)
	sub, file := e.mustStat("g/sub"), e.mustStat("g/file")
	if sub.GID != 4242 || sub.Mode&linux.S_ISGID == 0 {
		t.Fatalf("subdirectory: gid %d mode %#o, want gid 4242 with the set-group-ID bit", sub.GID, sub.Mode)
	}
	if file.GID != 4242 || file.Mode&linux.S_ISGID != 0 {
		t.Fatalf("file: gid %d mode %#o, want gid 4242 without the set-group-ID bit", file.GID, file.Mode)
	}
}

func TestStatfs(t *testing.T) {
	e := newEnv(t)
	statfs := func() linux.Statfs {
		t.Helper()
		st, err := e.vfsObj.StatFSAt(e.ctx, e.creds, e.pop("/"))
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	before := statfs()
	if before.Type != linux.EXT_SUPER_MAGIC || before.BlockSize != blockSize || before.FragmentSize != blockSize || before.NameLength != maxNameLen {
		t.Fatalf("statfs identity = %+v", before)
	}
	if before.Blocks == 0 || before.BlocksFree == 0 || before.BlocksFree > before.Blocks || before.BlocksAvailable != before.BlocksFree {
		t.Fatalf("statfs block numbers = %+v", before)
	}
	if before.Files == 0 || before.FilesFree == 0 || before.FilesFree > before.Files {
		t.Fatalf("statfs inode numbers = %+v", before)
	}
	// The free space of the host volume feeds the room for new groups, so
	// the exact numbers below come from the counters of the engine.
	counters := func() (blocks, inodes uint64) {
		e.fs.v.mu.Lock()
		defer e.fs.v.mu.Unlock()
		return e.fs.v.freeBlocksTotal, e.fs.v.freeInodesTotal
	}
	blocksBefore, inodesBefore := counters()
	const mib = 1 << 20
	e.writeFile("big", pattern(1, mib))
	blocksAfter, inodesAfter := counters()
	if used := blocksBefore - blocksAfter; used < mib/blockSize || used > mib/blockSize+8 {
		t.Fatalf("1 MiB of data took %d blocks, want about %d", used, mib/blockSize)
	}
	if inodesBefore-inodesAfter != 1 {
		t.Fatalf("one file took %d inodes, want 1", inodesBefore-inodesAfter)
	}
	fd := e.mustOpen("big", linux.O_RDONLY)
	viaFD, err := fd.StatFS(e.ctx)
	if err != nil || viaFD.Type != linux.EXT_SUPER_MAGIC || viaFD.Blocks == 0 {
		t.Fatalf("fstatfs = (%+v, %v)", viaFD, err)
	}
	if err := e.unlink("big"); err != nil {
		t.Fatal(err)
	}
	// The open descriptor holds the blocks until the close.
	if blocks, _ := counters(); blocks != blocksAfter {
		t.Fatalf("free blocks after unlink with an open file = %d, want %d", blocks, blocksAfter)
	}
	fd.DecRef(e.ctx)
	if blocks, inodes := counters(); blocks != blocksBefore || inodes != inodesBefore {
		t.Fatalf("after the last close: %d free blocks and %d free inodes, want %d and %d", blocks, inodes, blocksBefore, inodesBefore)
	}
}

func TestTimestampsOfWritesAndReads(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("data"))
	old := linux.StatxTimestamp{Sec: 1_000_000}
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_ATIME | linux.STATX_MTIME, Atime: old, Mtime: old}); err != nil {
		t.Fatal(err)
	}
	e.readFile("f")
	st := e.mustStat("f")
	if st.Atime.Sec <= old.Sec || st.Mtime != old {
		t.Fatalf("after a read: atime %+v mtime %+v, want a new atime and the old mtime", st.Atime, st.Mtime)
	}
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_ATIME, Atime: old}); err != nil {
		t.Fatal(err)
	}
	fd := e.mustOpen("f", linux.O_WRONLY)
	e.pwrite(fd, []byte("D"), 0)
	fd.DecRef(e.ctx)
	st = e.mustStat("f")
	if st.Mtime.Sec <= old.Sec || st.Ctime.Sec <= old.Sec || st.Atime != old {
		t.Fatalf("after a write: atime %+v mtime %+v ctime %+v, want the old atime and new mtime and ctime", st.Atime, st.Mtime, st.Ctime)
	}
	// Creating and removing a name changes the times of the directory.
	e.mustMkdir("d")
	if err := e.setStat("d", linux.Statx{Mask: linux.STATX_MTIME, Mtime: old}); err != nil {
		t.Fatal(err)
	}
	e.writeFile("d/new", nil)
	if got := e.mustStat("d").Mtime; got.Sec <= old.Sec {
		t.Fatalf("directory mtime after create = %+v", got)
	}
	if err := e.setStat("d", linux.Statx{Mask: linux.STATX_MTIME, Mtime: old}); err != nil {
		t.Fatal(err)
	}
	if err := e.unlink("d/new"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustStat("d").Mtime; got.Sec <= old.Sec {
		t.Fatalf("directory mtime after unlink = %+v", got)
	}
}

func TestNoAtimeMount(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vol.ext4")
	e := openEnv(t, path, VolumeOptions{}, vfs.MountOptions{Flags: vfs.MountFlags{NoATime: true}})
	e.writeFile("f", []byte("data"))
	old := linux.StatxTimestamp{Sec: 1_000_000}
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_ATIME, Atime: old}); err != nil {
		t.Fatal(err)
	}
	e.readFile("f")
	if got := e.mustStat("f").Atime; got != old {
		t.Fatalf("atime after a read on a noatime mount = %+v, want %+v", got, old)
	}
}

func TestReadOnlyVolume(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("d")
	e.mustMkdir("empty")
	e.writeFile("d/f", []byte("kept"))
	e.unmount()

	ro := openEnv(t, e.path, VolumeOptions{ReadOnly: true}, vfs.MountOptions{})
	wantBytes(t, "read on a read-only volume", ro.readFile("d/f"), []byte("kept"))
	if got := ro.readdir("d"); len(got) != 1 || got[0] != "f" {
		t.Fatalf("readdir = %v", got)
	}
	wantErrno(t, "mkdir", ro.mkdir("x"), linuxerr.EROFS)
	wantErrno(t, "unlink", ro.unlink("d/f"), linuxerr.EROFS)
	wantErrno(t, "rmdir", ro.rmdir("empty"), linuxerr.EROFS)
	wantErrno(t, "rename", ro.rename("d/f", "d/g"), linuxerr.EROFS)
	wantErrno(t, "link", ro.link("d/f", "d/h"), linuxerr.EROFS)
	wantErrno(t, "symlink", ro.symlink("t", "s"), linuxerr.EROFS)
	_, err := ro.open("d/f", linux.O_WRONLY, 0)
	wantErrno(t, "open for writing", err, linuxerr.EROFS)
	_, err = ro.open("new", linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create", err, linuxerr.EROFS)
	wantErrno(t, "chmod", ro.setStat("d/f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}), linuxerr.EROFS)
	wantErrno(t, "xattr", ro.vfsObj.SetXattrAt(ro.ctx, ro.creds, ro.fpop("d/f"), &vfs.SetXattrOptions{Name: "user.x", Value: "v"}), linuxerr.EROFS)
	wantErrno(t, "access for writing", ro.vfsObj.AccessAt(ro.ctx, ro.creds, vfs.MayWrite, ro.fpop("d/f")), linuxerr.EROFS)
	// Reading a file on a read-only volume must not touch the access time.
	if st := ro.mustStat("d/f"); st.Size != 4 {
		t.Fatalf("stat = %+v", st)
	}
}

func TestDentryCachePruning(t *testing.T) {
	e := newEnv(t)
	e.fs.pruneAt = 8
	e.mustMkdir("d")
	for i := range 200 {
		e.writeFile(fmt.Sprintf("d/f%03d", i), []byte(fmt.Sprintf("content %d", i)))
	}
	keep := e.mustOpen("d/f007", linux.O_RDONLY)
	defer keep.DecRef(e.ctx)
	for i := range 200 {
		if got := e.readFile(fmt.Sprintf("d/f%03d", i)); string(got) != fmt.Sprintf("content %d", i) {
			t.Fatalf("file %d reads %q", i, got)
		}
	}
	e.fs.mu.Lock()
	count := e.fs.dentryCount
	e.fs.mu.Unlock()
	if count > 100 {
		t.Fatalf("the dentry cache holds %d entries after pruning", count)
	}
	// The pruned directory entry rebuilds from the engine, and the open file
	// keeps working.
	wantBytes(t, "file that stayed open", e.readAll(keep), []byte("content 7"))
	if err := e.rename("d/f007", "d/renamed"); err != nil {
		t.Fatal(err)
	}
	wantBytes(t, "renamed file after pruning", e.readFile("d/renamed"), []byte("content 7"))
	wantBytes(t, "open file after the rename", e.readAll(keep), []byte("content 7"))
}

func TestToLinuxErr(t *testing.T) {
	for _, c := range []struct {
		name string
		in   error
		want *gverrors.Error
	}{
		{"plain linux error", linuxerr.ENOENT, linuxerr.ENOENT},
		{"corruption", corrupt("bad block %d", 3), linuxerr.EUCLEAN},
		{"wrapped linux error", fmt.Errorf("context: %w", linuxerr.ENOTEMPTY), linuxerr.ENOTEMPTY},
		{"host error", hostError(errors.New("disk on fire")), linuxerr.EIO},
		{"held space", fmt.Errorf("alloc: %w", errSpaceHeld), linuxerr.ENOSPC},
		{"unknown error", errors.New("surprise"), linuxerr.EIO},
		{"joined errors", errors.Join(errors.New("first"), linuxerr.EFBIG), linuxerr.EFBIG},
	} {
		got := toLinuxErr(c.in)
		if got != error(c.want) {
			t.Errorf("%s: toLinuxErr = %v, want %v", c.name, got, c.want)
		}
	}
	if toLinuxErr(nil) != nil {
		t.Error("toLinuxErr(nil) is not nil")
	}
}

func TestMountNeedsAVolume(t *testing.T) {
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	_, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{}, nil)
	wantErrno(t, "mount without a volume", err, linuxerr.EINVAL)
}

func TestVolumeServesOneMount(t *testing.T) {
	e := newEnv(t)
	ctx := gvcontext.Background()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatal(err)
	}
	vfsObj.MustRegisterFilesystemType(Name, FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	_, err := vfsObj.NewMountNamespace(ctx, creds, "", Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{InternalData: InternalFilesystemOptions{Volume: e.vol}},
	}, nil)
	wantErrno(t, "second mount of one volume", err, linuxerr.EBUSY)
}

func TestNameRules(t *testing.T) {
	e := newEnv(t)
	longest := strings.Repeat("n", maxNameLen)
	e.writeFile(longest, []byte("ok"))
	wantBytes(t, "file with the longest name", e.readFile(longest), []byte("ok"))
	tooLong := longest + "n"
	_, err := e.open(tooLong, linux.O_CREAT|linux.O_WRONLY, 0o644)
	wantErrno(t, "create with a name of 256 bytes", err, linuxerr.ENAMETOOLONG)
	_, err = e.stat(tooLong)
	wantErrno(t, "stat with a name of 256 bytes", err, linuxerr.ENAMETOOLONG)
	wantErrno(t, "mkdir with a name of 256 bytes", e.mkdir(tooLong), linuxerr.ENAMETOOLONG)
	wantErrno(t, "symlink with a name of 256 bytes", e.symlink("x", tooLong), linuxerr.ENAMETOOLONG)

	e.mustMkdir("d")
	wantErrno(t, "mkdir over a directory", e.mkdir("d"), linuxerr.EEXIST)
	wantErrno(t, "mkdir of \".\"", e.mkdir("d/."), linuxerr.EEXIST)
	_, err = e.open("d", linux.O_CREAT|linux.O_EXCL|linux.O_WRONLY, 0o644)
	wantErrno(t, "O_CREAT|O_EXCL over a directory", err, linuxerr.EEXIST)
	e.writeFile("file", nil)
	wantErrno(t, "mkdir below a file", e.mkdir("file/child"), linuxerr.ENOTDIR)
	_, err = e.stat("file/child")
	wantErrno(t, "stat below a file", err, linuxerr.ENOTDIR)
	_, err = e.stat("file/")
	wantErrno(t, "stat of a file with a trailing slash", err, linuxerr.ENOTDIR)
	wantErrno(t, "rename of a missing source", e.rename("missing", "other"), linuxerr.ENOENT)

	// The longest name survives a remount in a directory block that other
	// names share.
	for i := range 30 {
		e.writeFile(fmt.Sprintf("short%02d", i), nil)
	}
	e = e.remount()
	wantBytes(t, "longest name after remount", e.readFile(longest), []byte("ok"))
	if got := e.readdir("/"); len(got) != 33 {
		t.Fatalf("root lists %d names after remount, want 33", len(got))
	}
}

// TestTruncateOfExtentFile shrinks a file that owns blocks to a size inside a
// block and grows it again. The bytes between the two sizes must read as zeros.
func TestTruncateOfExtentFile(t *testing.T) {
	e := newEnv(t)
	data := pattern(8, 3*blockSize+777)
	e.writeFile("f", data)
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	for _, size := range []uint64{blockSize + 100, 3*blockSize + 5} {
		if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: size}}); err != nil {
			t.Fatal(err)
		}
	}
	got := e.readAll(fd)
	want := make([]byte, 3*blockSize+5)
	copy(want, data[:blockSize+100])
	wantBytes(t, "content after shrink and growth", got, want)
	// The shrink freed the blocks above the new end. The growth made a hole.
	if st := e.mustStat("f"); st.Blocks != 2*blockSize/512 {
		t.Fatalf("after shrink and growth the file owns %d sectors, want %d", st.Blocks, 2*blockSize/512)
	}
	// Shrinking to zero releases every block.
	if err := fd.SetStat(e.ctx, vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 0}}); err != nil {
		t.Fatal(err)
	}
	if st := e.mustStat("f"); st.Size != 0 || st.Blocks != 0 {
		t.Fatalf("after truncate to zero: size %d, %d sectors, want 0 and 0", st.Size, st.Blocks)
	}
}

// TestPathnameFollowsRenames resolves the path of a directory entry through
// the VFS. A rename of an ancestor changes the path, and an unlinked entry has
// no path.
func TestPathnameFollowsRenames(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("a")
	e.mustMkdir("a/b")
	e.writeFile("a/b/f", nil)
	vd, err := e.vfsObj.GetDentryAt(e.ctx, e.creds, e.fpop("a/b/f"), &vfs.GetDentryOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer vd.DecRef(e.ctx)
	path := func() string {
		t.Helper()
		p, err := e.vfsObj.PathnameWithDeleted(e.ctx, e.root, vd)
		if err != nil {
			t.Fatalf("PathnameWithDeleted: %v", err)
		}
		return p
	}
	if got := path(); got != "/a/b/f" {
		t.Fatalf("path = %q, want /a/b/f", got)
	}
	e.mustMkdir("z")
	if err := e.rename("a/b", "z/moved"); err != nil {
		t.Fatal(err)
	}
	if got := path(); got != "/z/moved/f" {
		t.Fatalf("path after the rename of an ancestor = %q, want /z/moved/f", got)
	}
	if err := e.unlink("z/moved/f"); err != nil {
		t.Fatal(err)
	}
	if got := path(); !strings.HasSuffix(got, "(deleted)") {
		t.Fatalf("path of the unlinked file = %q, want a deleted mark", got)
	}
	if !e.fs.IsDescendant(e.root, e.root) {
		t.Fatal("the root is not a descendant of itself")
	}
}

// TestExecutingFileRejectsWriters checks that a file that a process executes
// rejects writers, as Linux does with ETXTBSY.
func TestExecutingFileRejectsWriters(t *testing.T) {
	e := newEnv(t)
	e.writeFile("prog", []byte("#!/bin/sh\n"))
	exec := e.mustOpen("prog", linux.O_RDONLY)
	defer exec.DecRef(e.ctx)
	exec.DenyWriteAccess()
	_, err := e.open("prog", linux.O_WRONLY, 0)
	wantErrno(t, "open for writing a running program", err, linuxerr.ETXTBSY)
	_, err = e.open("prog", linux.O_RDONLY|linux.O_TRUNC, 0)
	wantErrno(t, "O_TRUNC of a running program", err, linuxerr.ETXTBSY)
	err = e.vfsObj.SetStatAt(e.ctx, e.creds, e.fpop("prog"), &vfs.SetStatOptions{
		Stat:          linux.Statx{Mask: linux.STATX_SIZE, Size: 0},
		NeedWritePerm: true,
	})
	wantErrno(t, "truncate(2) of a running program", err, linuxerr.ETXTBSY)
	exec.AllowWriteAccess()
	fd := e.mustOpen("prog", linux.O_WRONLY)
	fd.DecRef(e.ctx)
}

func TestTruncateNeedsWritePermission(t *testing.T) {
	e := newEnv(t)
	e.writeFile("f", []byte("content"))
	if err := e.setStat("f", linux.Statx{Mask: linux.STATX_MODE | linux.STATX_UID, Mode: 0o644, UID: 1000}); err != nil {
		t.Fatal(err)
	}
	other := userCreds(2000, 2000)
	err := e.vfsObj.SetStatAt(e.ctx, other, e.fpop("f"), &vfs.SetStatOptions{
		Stat:          linux.Statx{Mask: linux.STATX_SIZE, Size: 0},
		NeedWritePerm: true,
	})
	wantErrno(t, "truncate(2) without write permission", err, linuxerr.EACCES)
	wantBytes(t, "content after the failed truncate", e.readFile("f"), []byte("content"))
	owner := userCreds(1000, 1000)
	err = e.vfsObj.SetStatAt(e.ctx, owner, e.fpop("f"), &vfs.SetStatOptions{
		Stat:          linux.Statx{Mask: linux.STATX_SIZE, Size: 3},
		NeedWritePerm: true,
	})
	if err != nil {
		t.Fatalf("truncate(2) by the owner: %v", err)
	}
	wantBytes(t, "content after the truncate", e.readFile("f"), []byte("con"))
	// Truncating a directory fails.
	e.mustMkdir("d")
	wantErrno(t, "truncate of a directory", e.setStat("d", linux.Statx{Mask: linux.STATX_SIZE, Size: 0}), linuxerr.EISDIR)
}
