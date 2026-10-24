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
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// lockingCaps returns the capabilities that make a workspace quiesce the open
// handles below a renamed directory. Windows reports them itself. The other
// hosts get the capabilities of their own volume and the lock flag, so the
// tests close and reopen real descriptors there.
func lockingCaps() *WorkspaceCaps {
	var caps WorkspaceCaps
	switch runtime.GOOS {
	case "windows":
		return nil
	case "darwin":
		caps = macCaps
	default:
		caps = linuxCaps
	}
	caps.LocksOpenDirMove = true
	return &caps
}

const (
	variantNative    = "native"
	variantWinVolume = "winvolume"
)

// newQuiesceEnv mounts a workspace that tracks open handles. The native
// variant uses the volume of the test host. The winvolume variant models an
// NTFS volume, so the host names of the files differ from the guest names.
func newQuiesceEnv(t *testing.T, variant string, wrap func(hostBackend) hostBackend) *env {
	t.Helper()
	var opts workspaceOptions
	switch variant {
	case variantNative:
		opts = workspaceOptions{coalesce: defaultMetaCoalesce, caps: lockingCaps()}
		opts.wrapHost = wrap
	case variantWinVolume:
		opts = volumeOptions(winCaps, true, true, true)
		if wrap != nil {
			inner := opts.wrapHost
			opts.wrapHost = func(b hostBackend) hostBackend { return wrap(inner(b)) }
		}
	default:
		t.Fatalf("unknown variant %q", variant)
	}
	e := newEnvOpts(t, opts)
	if e.ws.handles == nil {
		t.Fatalf("the workspace has no handle registry, caps = %+v", e.ws.Caps())
	}
	return e
}

// hostPathOf returns the host path of the guest path rel.
func (e *env) hostPathOf(rel string) string {
	e.t.Helper()
	hp, err := e.ws.hostPath(rel)
	if err != nil {
		e.t.Fatalf("hostPath(%q): %v", rel, err)
	}
	return filepath.Join(e.dir, filepath.FromSlash(hp))
}

// registered returns the path under which the registry knows the handle of fd.
func (e *env) registered(fd *vfs.FileDescription) string {
	h := fd.Impl().(*regularFD).h
	return e.ws.handles.pathOf(h)
}

// pattern returns n bytes that differ from page to page.
func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('a' + (i/hostarch.PageSize+i)%26)
	}
	return b
}

func (e *env) pread(fd *vfs.FileDescription, off int64, n int) []byte {
	e.t.Helper()
	buf := make([]byte, n)
	got, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), off, vfs.ReadOptions{})
	if err != nil && !errors.Is(err, io.EOF) {
		e.t.Fatalf("PRead(%d, %d): %v", off, n, err)
	}
	return buf[:got]
}

// mappedView returns the bytes of [off, off+n) of a mapping of the file.
func mappedView(t *testing.T, e *env, m memmap.Mappable, perms hostarch.AccessType, off, n uint64) []byte {
	t.Helper()
	start := off &^ (hostarch.PageSize - 1)
	end := (off + n + hostarch.PageSize - 1) &^ (hostarch.PageSize - 1)
	ts, err := m.Translate(e.ctx, memmap.MappableRange{Start: start, End: end}, memmap.MappableRange{Start: 0, End: end}, perms)
	if err != nil {
		t.Fatalf("Translate: %v", err)
	}
	for _, tr := range ts {
		if off < tr.Source.Start || off+n > tr.Source.End {
			continue
		}
		fo := tr.Offset + off - tr.Source.Start
		bs, err := tr.File.MapInternal(memmap.FileRange{Start: fo, End: fo + n}, perms)
		if err != nil {
			t.Fatalf("MapInternal: %v", err)
		}
		if bs.NumBlocks() != 1 {
			t.Fatalf("MapInternal returned %d blocks", bs.NumBlocks())
		}
		return bs.Head().ToSlice()
	}
	t.Fatalf("no translation covers [%d, %d): %v", off, off+n, ts)
	return nil
}

// pinsUnder counts the pinned directory handles at or below rel.
func (e *env) pinsUnder(rel string) int {
	e.ws.pinMu.Lock()
	defer e.ws.pinMu.Unlock()
	n := 0
	for k := range e.ws.pins {
		if k == rel || strings.HasPrefix(k, rel+"/") {
			n++
		}
	}
	return n
}

type openCase struct {
	name  string
	flags uint32
}

var openCases = []openCase{
	{"rdonly", linux.O_RDONLY},
	{"wronly", linux.O_WRONLY},
	{"rdwr", linux.O_RDWR},
	{"rdwr-append", linux.O_RDWR | linux.O_APPEND},
	{"wronly-append", linux.O_WRONLY | linux.O_APPEND},
}

// TestRenameDirWithOpenDescendant renames a parent directory while a
// descendant file stays open for reads, writes, and mappings. The rename
// must succeed on every host, and the open file description must keep working
// at the new path.
func TestRenameDirWithOpenDescendant(t *testing.T) {
	for _, variant := range []string{variantNative, variantWinVolume} {
		for _, oc := range openCases {
			for _, depth := range []int{1, 3, 6} {
				t.Run(fmt.Sprintf("%s/%s/depth%d", variant, oc.name, depth), func(t *testing.T) {
					testRenameDirWithOpenDescendant(t, variant, oc, depth)
				})
			}
		}
	}
}

func testRenameDirWithOpenDescendant(t *testing.T, variant string, oc openCase, depth int) {
	var host *openCountHost
	e := newQuiesceEnv(t, variant, func(b hostBackend) hostBackend {
		host = &openCountHost{hostBackend: b}
		return host
	})
	// renameDir renames a directory. It requires one reopen of the file,
	// which proves that the quiesce closed the file before the rename.
	renameDir := func(from, to string) {
		t.Helper()
		before := host.opens.Load()
		if err := e.rename(from, to); err != nil {
			t.Fatalf("rename %q to %q: %v", from, to, err)
		}
		if got := host.opens.Load() - before; got != 1 {
			t.Fatalf("rename %q to %q reopened %d files, want 1", from, to, got)
		}
	}
	leaf := "data.bin"
	if variant == variantWinVolume {
		leaf = "da:ta.bin"
	}
	dirs := []string{"top"}
	for i := 1; i < depth; i++ {
		dirs = append(dirs, fmt.Sprintf("%s/l%d", dirs[i-1], i))
	}
	for _, d := range dirs {
		e.mustMkdir(d)
	}
	rel := dirs[depth-1] + "/" + leaf
	want := pattern(3 * hostarch.PageSize)
	e.writeFile(rel, want)
	// A lookup of the full path opens the pinned directory handles.
	e.mustStat(rel)
	if e.pinsUnder("top") == 0 {
		t.Fatalf("no pinned directory handle below top before the rename")
	}

	fd := e.mustOpen(rel, oc.flags)
	defer fd.DecRef(e.ctx)
	canRead := oc.flags&linux.O_ACCMODE != linux.O_WRONLY
	canWrite := oc.flags&linux.O_ACCMODE != linux.O_RDONLY
	appends := oc.flags&linux.O_APPEND != 0
	writableMap := canRead && canWrite

	var m memmap.Mappable
	var ms *recordingSpace
	var ar hostarch.AddrRange
	if canRead {
		m, ms, ar = e.mapFile(fd, uint64(len(want)), writableMap)
	}
	if writableMap {
		// A dirty mapped page that no read has flushed yet.
		copy(mappedView(t, e, m, hostarch.ReadWrite, 0, 8), "mapped!!")
		copy(want, "mapped!!")
	}

	cur := rel
	step := 0
	// verify checks the open file description at the path now.
	verify := func(now string) {
		t.Helper()
		step++
		cur = now
		if got := e.registered(fd); got != cur {
			t.Fatalf("step %d: registered path = %q, want %q", step, got, cur)
		}
		if canRead {
			if got := e.pread(fd, 0, len(want)); !bytes.Equal(got, want) {
				t.Fatalf("step %d: PRead after the rename = %.32q..., want %.32q...", step, got, want)
			}
			if got := mappedView(t, e, m, hostarch.Read, 0, 8); !bytes.Equal(got, want[:8]) {
				t.Fatalf("step %d: mapped bytes = %q, want %q", step, got, want[:8])
			}
		}
		if canWrite {
			marker := []byte(fmt.Sprintf("after-%d", step))
			off := int64(1000 + step*32)
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(marker), off, vfs.WriteOptions{}); err != nil {
				t.Fatalf("step %d: PWrite after the rename: %v", step, err)
			}
			if appends {
				want = append(want, marker...)
			} else {
				copy(want[off:], marker)
			}
			if canRead && !appends {
				if got := mappedView(t, e, m, hostarch.Read, uint64(off), uint64(len(marker))); !bytes.Equal(got, marker) {
					t.Fatalf("step %d: mapped view of the write = %q, want %q", step, got, marker)
				}
			}
		}
		if raw, err := os.ReadFile(e.hostPathOf(cur)); err != nil || !bytes.Equal(raw, want) {
			t.Fatalf("step %d: host file at %q = (%d bytes, %v), want %d bytes", step, cur, len(raw), err, len(want))
		}
		if st := e.mustStat(cur); st.Size != uint64(len(want)) {
			t.Fatalf("step %d: size = %d, want %d", step, st.Size, len(want))
		}
	}

	// Rename the top directory.
	moved := "moved"
	renameDir("top", moved)
	if _, err := e.stat("top"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Fatalf("stat of the old directory = %v, want ENOENT", err)
	}
	if _, err := os.Lstat(e.hostPathOf("top")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("host old directory: %v, want not exist", err)
	}
	if n := e.pinsUnder("top"); n != 0 {
		t.Fatalf("%d pinned directory handles remain below the old path", n)
	}
	verify(moved + strings.TrimPrefix(rel, "top"))

	if writableMap {
		// A mapped write after the reopen reaches the host at unmap.
		copy(mappedView(t, e, m, hostarch.ReadWrite, 2*hostarch.PageSize, 8), "post-map")
		copy(want[2*hostarch.PageSize:], "post-map")
	}

	// Rename a directory in the middle of the path.
	if depth >= 3 {
		renameDir(moved+"/l1", moved+"/m1")
		verify(moved + "/m1" + strings.TrimPrefix(cur, moved+"/l1"))
		renameDir(moved+"/m1", moved+"/l1")
		verify(moved + "/l1" + strings.TrimPrefix(cur, moved+"/m1"))
	}

	// Rename the top directory back.
	renameDir(moved, "top")
	verify("top" + strings.TrimPrefix(cur, moved))

	if canRead {
		m.RemoveMapping(e.ctx, ms, ar, 0, writableMap)
	}
	if raw, err := os.ReadFile(e.hostPathOf(cur)); err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("host file after unmap = (%d bytes, %v), want %d bytes", len(raw), err, len(want))
	}
	if err := fd.OnClose(e.ctx); err != nil {
		t.Fatalf("OnClose: %v", err)
	}
}

// TestRenameDirRacesWithIO runs reads and writes on open files while the
// directory above them moves back and forth. Every call must finish with a
// good result: a call that races with a quiesce waits and then uses the
// reopened file.
func TestRenameDirRacesWithIO(t *testing.T) {
	e := newQuiesceEnv(t, variantNative, nil)
	e.mustMkdir("a")
	e.mustMkdir("a/sub")
	const files = 4
	fds := make([]*vfs.FileDescription, files)
	for i := range fds {
		p := fmt.Sprintf("a/sub/f%d", i)
		e.writeFile(p, bytes.Repeat([]byte{byte('A' + i)}, 4096))
		fds[i] = e.mustOpen(p, linux.O_RDWR)
		defer fds[i].DecRef(e.ctx)
	}

	var stop atomic.Bool
	var wg sync.WaitGroup
	for i := range fds {
		fd, b := fds[i], byte('A'+i)
		wg.Add(2)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4096)
			for !stop.Load() {
				n, err := fd.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
				if err != nil && !errors.Is(err, io.EOF) {
					t.Errorf("PRead during a rename: %v", err)
					return
				}
				if n != int64(len(buf)) || !bytes.Equal(buf, bytes.Repeat([]byte{b}, len(buf))) {
					t.Errorf("PRead during a rename returned %d bytes with wrong content", n)
					return
				}
			}
		}()
		go func() {
			defer wg.Done()
			data := bytes.Repeat([]byte{b}, 64)
			for !stop.Load() {
				if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence(data), 128, vfs.WriteOptions{}); err != nil {
					t.Errorf("PWrite during a rename: %v", err)
					return
				}
			}
		}()
	}
	for i := range 100 {
		if err := e.rename("a", "b"); err != nil {
			t.Fatalf("rename a to b, round %d: %v", i, err)
		}
		if err := e.rename("b", "a"); err != nil {
			t.Fatalf("rename b to a, round %d: %v", i, err)
		}
	}
	stop.Store(true)
	wg.Wait()
}

// openCountHost counts the opens of workspace files, which are the reopens of
// a quiesce while a test renames a directory. It ignores the metadata files.
type openCountHost struct {
	hostBackend
	opens atomic.Int64
}

func (h *openCountHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	if !isReservedPath(rel) {
		h.opens.Add(1)
	}
	return h.hostBackend.open(rel, flags, perm)
}

// failRenameHost makes the host rename of a directory fail while fail is set.
// It counts the opens that happen while the rename fails, which are the
// reopens of the rollback.
type failRenameHost struct {
	hostBackend
	fail    atomic.Bool
	reopens atomic.Int64
}

func (h *failRenameHost) rename(oldRel, newRel string) error {
	if h.fail.Load() {
		return fs.ErrPermission
	}
	return h.hostBackend.rename(oldRel, newRel)
}

func (h *failRenameHost) open(rel string, flags int, perm os.FileMode) (*os.File, error) {
	if h.fail.Load() {
		h.reopens.Add(1)
	}
	return h.hostBackend.open(rel, flags, perm)
}

// TestRenameDirFailureReopensAtOldPath checks the rollback. The host rename
// fails after the quiesce closed the file, so the quiesce reopens the file at
// the old path and the file description keeps working there.
func TestRenameDirFailureReopensAtOldPath(t *testing.T) {
	for _, variant := range []string{variantNative, variantWinVolume} {
		t.Run(variant, func(t *testing.T) {
			var host *failRenameHost
			e := newQuiesceEnv(t, variant, func(b hostBackend) hostBackend {
				host = &failRenameHost{hostBackend: b}
				return host
			})
			e.mustMkdir("d")
			e.mustMkdir("d/s")
			e.writeFile("d/s/f", []byte("0123456789"))
			fd := e.mustOpen("d/s/f", linux.O_RDWR)
			defer fd.DecRef(e.ctx)

			host.fail.Store(true)
			err := e.rename("d", "e")
			host.fail.Store(false)
			wantErrno(t, "rename with a failing host", err, linuxerr.EACCES)
			if got := host.reopens.Load(); got != 1 {
				t.Fatalf("the rollback reopened %d files, want 1", got)
			}
			if got := e.registered(fd); got != "d/s/f" {
				t.Fatalf("registered path after the failed rename = %q, want d/s/f", got)
			}
			if got := e.pread(fd, 0, 10); string(got) != "0123456789" {
				t.Fatalf("PRead after the failed rename = %q", got)
			}
			if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte("XY")), 4, vfs.WriteOptions{}); err != nil {
				t.Fatalf("PWrite after the failed rename: %v", err)
			}
			if raw, err := os.ReadFile(e.hostPathOf("d/s/f")); err != nil || string(raw) != "0123XY6789" {
				t.Fatalf("host file = (%q, %v)", raw, err)
			}

			if err := e.rename("d", "e"); err != nil {
				t.Fatalf("rename after the failure: %v", err)
			}
			if got := e.pread(fd, 0, 10); string(got) != "0123XY6789" {
				t.Fatalf("PRead after the second rename = %q", got)
			}
		})
	}
}

// TestRenameDirBreaksHandleOfHostDeletedFile deletes an open file from the
// host side. The quiesce cannot reopen it, so the handle becomes broken. The
// rename itself succeeds, and the file description reports EIO.
func TestRenameDirBreaksHandleOfHostDeletedFile(t *testing.T) {
	e := newQuiesceEnv(t, variantNative, nil)
	e.mustMkdir("d")
	e.writeFile("d/gone", []byte("gone"))
	e.writeFile("d/kept", []byte("kept"))
	gone := e.mustOpen("d/gone", linux.O_RDWR)
	defer gone.DecRef(e.ctx)
	kept := e.mustOpen("d/kept", linux.O_RDWR)
	defer kept.DecRef(e.ctx)

	if err := os.Remove(e.host("d/gone")); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("d", "e"); err != nil {
		t.Fatalf("rename with a handle that cannot reopen: %v", err)
	}
	buf := make([]byte, 4)
	_, err := gone.PRead(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
	wantErrno(t, "PRead of a broken handle", err, linuxerr.EIO)
	_, err = gone.PWrite(e.ctx, usermem.BytesIOSequence(buf), 0, vfs.WriteOptions{})
	wantErrno(t, "PWrite of a broken handle", err, linuxerr.EIO)
	_, err = gone.Stat(e.ctx, vfs.StatOptions{Mask: linux.STATX_SIZE})
	wantErrno(t, "Stat of a broken handle", err, linuxerr.EIO)
	if got := e.pread(kept, 0, 4); string(got) != "kept" {
		t.Fatalf("PRead of the other file = %q", got)
	}
	// A broken handle never blocks a later rename.
	if err := e.rename("e", "f"); err != nil {
		t.Fatalf("second rename: %v", err)
	}
	if got := e.pread(kept, 0, 4); string(got) != "kept" {
		t.Fatalf("PRead of the other file after the second rename = %q", got)
	}
}

// TestRenameDirKeepsGuestUnlinkedFile unlinks an open file through the guest.
// The file has no path left, so the quiesce leaves it open and the file
// description keeps working, as POSIX requires.
func TestRenameDirKeepsGuestUnlinkedFile(t *testing.T) {
	e := newQuiesceEnv(t, variantNative, nil)
	e.mustMkdir("d")
	e.writeFile("d/u", []byte("unlinked"))
	fd := e.mustOpen("d/u", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := e.unlink("d/u"); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if err := e.rename("d", "e"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := e.pread(fd, 0, 8); string(got) != "unlinked" {
		t.Fatalf("PRead of the unlinked file = %q", got)
	}
	if _, err := fd.PWrite(e.ctx, usermem.BytesIOSequence([]byte("!")), 8, vfs.WriteOptions{}); err != nil {
		t.Fatalf("PWrite of the unlinked file: %v", err)
	}
}

// TestRenameFileMovesRegisteredPath renames an open file and then its
// directory. The handle follows both names.
func TestRenameFileMovesRegisteredPath(t *testing.T) {
	e := newQuiesceEnv(t, variantNative, nil)
	e.mustMkdir("d")
	e.writeFile("d/a", []byte("aaa"))
	e.writeFile("d/b", []byte("bbb"))
	fa := e.mustOpen("d/a", linux.O_RDWR)
	defer fa.DecRef(e.ctx)
	fb := e.mustOpen("d/b", linux.O_RDWR)
	defer fb.DecRef(e.ctx)

	// The rename replaces d/b. Its open description stays alive without a name.
	if err := e.rename("d/a", "d/b"); err != nil {
		t.Fatalf("rename of a file: %v", err)
	}
	if got := e.registered(fa); got != "d/b" {
		t.Fatalf("registered path of the renamed file = %q, want d/b", got)
	}
	if err := e.rename("d", "e"); err != nil {
		t.Fatalf("rename of the directory: %v", err)
	}
	if got := e.registered(fa); got != "e/b" {
		t.Fatalf("registered path after the directory rename = %q, want e/b", got)
	}
	if got := e.pread(fa, 0, 3); string(got) != "aaa" {
		t.Fatalf("PRead of the renamed file = %q", got)
	}
	if got := e.pread(fb, 0, 3); string(got) != "bbb" {
		t.Fatalf("PRead of the replaced file = %q", got)
	}
	if got := e.readFile("e/b"); string(got) != "aaa" {
		t.Fatalf("content at the new name = %q", got)
	}
}

// TestRenameDirTruncateUsesRegisteredHandle checks that the transient handle
// of a truncate registers too, so a truncate cannot block a rename.
func TestRenameDirTruncateUsesRegisteredHandle(t *testing.T) {
	e := newQuiesceEnv(t, variantNative, nil)
	e.mustMkdir("d")
	e.writeFile("d/t", []byte("0123456789"))
	if err := e.vfsObj.SetStatAt(e.ctx, e.creds, e.pop("d/t"), &vfs.SetStatOptions{Stat: linux.Statx{Mask: linux.STATX_SIZE, Size: 4}}); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if n := e.ws.handles.count(); n != 0 {
		t.Fatalf("%d handles stay registered after the truncate, want 0", n)
	}
	if err := e.rename("d", "e"); err != nil {
		t.Fatal(err)
	}
	if got := e.readFile("e/t"); string(got) != "0123" {
		t.Fatalf("content = %q", got)
	}
}

// fakeVolume is a handleOps backend that models a volume of files without
// the host. Each fake file is a real temporary file, so a closed file reports
// an error. A use of a closed file panics, which names the bug exactly.
type fakeVolume struct {
	t   *testing.T
	dir string
	reg *winHandleRegistry

	mu     sync.Mutex
	ids    map[string]hostID
	fileID map[*os.File]hostID
	where  map[*os.File]string
	closed map[*os.File]bool
	events []string
	nextID uint64
	// failOpen holds the paths that reopen refuses.
	failOpen map[string]error
}

func newFakeVolume(t *testing.T) *fakeVolume {
	v := &fakeVolume{
		t:        t,
		dir:      t.TempDir(),
		ids:      make(map[string]hostID),
		fileID:   make(map[*os.File]hostID),
		where:    make(map[*os.File]string),
		closed:   make(map[*os.File]bool),
		failOpen: make(map[string]error),
	}
	v.reg = newWinHandleRegistry(v)
	return v
}

func (v *fakeVolume) event(format string, args ...any) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.events = append(v.events, fmt.Sprintf(format, args...))
}

// takeEvents returns the events so far and clears them.
func (v *fakeVolume) takeEvents() []string {
	v.mu.Lock()
	defer v.mu.Unlock()
	out := v.events
	v.events = nil
	return out
}

// create adds a file to the volume and registers a handle for it. The handle
// has a mapped-page cache when owned is true, so the quiesce flushes it.
func (v *fakeVolume) create(path string, owned bool) *hostHandle {
	v.t.Helper()
	f, err := os.CreateTemp(v.dir, "f")
	if err != nil {
		v.t.Fatal(err)
	}
	v.mu.Lock()
	v.nextID++
	id := hostID{dev: 1, ino: v.nextID}
	v.ids[path] = id
	v.fileID[f] = id
	v.where[f] = path
	v.mu.Unlock()
	h := newHostHandle(f, os.O_RDWR)
	if owned {
		h.owner.Store(new(fileData))
	}
	v.reg.add(h, path)
	v.t.Cleanup(func() { _ = f.Close() })
	return h
}

// moveTree renames every path at or below old, as a host rename does.
func (v *fakeVolume) moveTree(oldRel, newRel string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	for p, id := range v.ids {
		if p == oldRel || strings.HasPrefix(p, oldRel+"/") {
			delete(v.ids, p)
			v.ids[newRel+strings.TrimPrefix(p, oldRel)] = id
		}
	}
}

// remove deletes a path, as a host process does.
func (v *fakeVolume) remove(path string) {
	v.mu.Lock()
	delete(v.ids, path)
	v.mu.Unlock()
}

// replace gives a path another file, as a host process does.
func (v *fakeVolume) replace(path string) {
	v.mu.Lock()
	v.nextID++
	v.ids[path] = hostID{dev: 1, ino: v.nextID}
	v.mu.Unlock()
}

// use panics when f is closed.
func (v *fakeVolume) use(f *os.File) {
	v.mu.Lock()
	closed, where := v.closed[f], v.where[f]
	v.mu.Unlock()
	if closed {
		panic("hostfs test: use of the closed host file of " + where)
	}
}

// open returns the number of files that the fake opened and did not close.
func (v *fakeVolume) open() int {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for f := range v.where {
		if !v.closed[f] {
			n++
		}
	}
	return n
}

func (v *fakeVolume) flush(h *hostHandle) {
	v.event("flush %s", v.reg.pathOf(h))
}

func (v *fakeVolume) identify(f *os.File) (hostID, error) {
	v.use(f)
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.fileID[f], nil
}

func (v *fakeVolume) closeFile(f *os.File) error {
	v.mu.Lock()
	if v.closed[f] {
		where := v.where[f]
		v.mu.Unlock()
		panic("hostfs test: second close of the host file of " + where)
	}
	v.closed[f] = true
	where := v.where[f]
	v.events = append(v.events, "close "+where)
	v.mu.Unlock()
	return f.Close()
}

func (v *fakeVolume) reopen(rel string, flags int) (*os.File, error) {
	v.mu.Lock()
	err := v.failOpen[rel]
	id, ok := v.ids[rel]
	v.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fs.ErrNotExist
	}
	f, err := os.CreateTemp(v.dir, "r")
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	v.fileID[f] = id
	v.where[f] = rel
	v.events = append(v.events, "reopen "+rel)
	v.mu.Unlock()
	v.t.Cleanup(func() { _ = f.Close() })
	return f, nil
}

func TestRegistryQuiesceOrderAndReopen(t *testing.T) {
	v := newFakeVolume(t)
	hs := make(map[string]*hostHandle)
	for _, p := range []string{"d/c/x", "d/b", "d/a", "other/y", "d2/z"} {
		hs[p] = v.create(p, true)
	}
	ids := make(map[string]hostID)
	for p := range hs {
		ids[p] = v.ids[p]
	}

	q := v.reg.quiesce("d")
	want := []string{
		"flush d/a", "flush d/b", "flush d/c/x",
		"close d/a", "close d/b", "close d/c/x",
	}
	if got := v.takeEvents(); !slices.Equal(got, want) {
		t.Fatalf("events of the quiesce = %q, want %q", got, want)
	}
	v.moveTree("d", "e")
	if err := q.finish(true, "e"); err != nil {
		t.Fatalf("finish: %v", err)
	}
	want = []string{"reopen e/a", "reopen e/b", "reopen e/c/x"}
	if got := v.takeEvents(); !slices.Equal(got, want) {
		t.Fatalf("events of the reopen = %q, want %q", got, want)
	}
	for old, now := range map[string]string{"d/a": "e/a", "d/b": "e/b", "d/c/x": "e/c/x"} {
		h := hs[old]
		if got := v.reg.pathOf(h); got != now {
			t.Errorf("path of %s = %q, want %q", old, got, now)
		}
		f, err := h.acquire()
		if err != nil {
			t.Fatalf("acquire %s: %v", old, err)
		}
		if id, _ := v.identify(f); id != ids[old] {
			t.Errorf("identity of %s = %v, want %v", old, id, ids[old])
		}
		h.release()
	}
	// The handles that the directory does not contain stay open and in place.
	for _, p := range []string{"other/y", "d2/z"} {
		f, err := hs[p].acquire()
		if err != nil {
			t.Fatal(err)
		}
		v.use(f)
		hs[p].release()
		if got := v.reg.pathOf(hs[p]); got != p {
			t.Errorf("path of %s = %q", p, got)
		}
	}
	if n := v.open(); n != 5 {
		t.Errorf("%d fake files stay open, want 5", n)
	}
}

func TestRegistryRollbackReopensAtOldPath(t *testing.T) {
	v := newFakeVolume(t)
	a, b := v.create("d/a", true), v.create("d/s/b", false)
	idA, idB := v.ids["d/a"], v.ids["d/s/b"]

	q := v.reg.quiesce("d")
	v.takeEvents()
	// The host rename failed: nothing moved.
	if err := q.finish(false, ""); err != nil {
		t.Fatalf("finish after a failed rename: %v", err)
	}
	if got, want := v.takeEvents(), []string{"reopen d/a", "reopen d/s/b"}; !slices.Equal(got, want) {
		t.Fatalf("events of the rollback = %q, want %q", got, want)
	}
	for _, c := range []struct {
		h    *hostHandle
		path string
		id   hostID
	}{{a, "d/a", idA}, {b, "d/s/b", idB}} {
		if got := v.reg.pathOf(c.h); got != c.path {
			t.Errorf("path = %q, want %q", got, c.path)
		}
		f, err := c.h.acquire()
		if err != nil {
			t.Fatalf("acquire %s: %v", c.path, err)
		}
		if id, _ := v.identify(f); id != c.id {
			t.Errorf("identity of %s = %v, want %v", c.path, id, c.id)
		}
		c.h.release()
	}
}

func TestRegistryBrokenHandles(t *testing.T) {
	v := newFakeVolume(t)
	gone := v.create("d/gone", false)
	swapped := v.create("d/swapped", false)
	refused := v.create("d/refused", false)
	ok := v.create("d/ok", false)

	q := v.reg.quiesce("d")
	v.remove("d/gone")
	v.replace("d/swapped")
	v.failOpen["e/refused"] = errors.New("injected open failure")
	v.moveTree("d", "e")
	err := q.finish(true, "e")
	if !errors.Is(err, errHandleBroken) || !errors.Is(err, errHandleChanged) || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("finish = %v, want errors for a missing file, a changed file, and a refused open", err)
	}
	for name, h := range map[string]*hostHandle{"gone": gone, "swapped": swapped, "refused": refused} {
		if _, err := h.acquire(); !errors.Is(err, errHandleBroken) {
			t.Errorf("acquire of the broken %s handle = %v", name, err)
		} else if !linuxerr.Equals(linuxerr.EIO, translateHostError(err)) {
			t.Errorf("guest error of the broken %s handle = %v, want EIO", name, translateHostError(err))
		}
		if _, err := h.readAt(make([]byte, 1), 0); !errors.Is(err, errHandleBroken) {
			t.Errorf("readAt of the broken %s handle = %v", name, err)
		}
		if _, err := h.writeAt([]byte{1}, 0); !errors.Is(err, errHandleBroken) {
			t.Errorf("writeAt of the broken %s handle = %v", name, err)
		}
	}
	if f, err := ok.acquire(); err != nil {
		t.Fatalf("acquire of the good handle: %v", err)
	} else {
		v.use(f)
		ok.release()
	}
	// The file that reopened with another identity was closed again.
	if n := v.open(); n != 1 {
		t.Errorf("%d fake files stay open, want only the good handle", n)
	}
	// The next quiesce skips the broken handles, and a last reference on one
	// closes without an error.
	q = v.reg.quiesce("e")
	if got := v.takeEvents(); !slices.Contains(got, "close e/ok") || slices.Contains(got, "close e/gone") {
		t.Errorf("events of the second quiesce = %q", got)
	}
	if err := q.finish(false, ""); err != nil {
		t.Fatal(err)
	}
	for _, h := range []*hostHandle{gone, swapped, refused} {
		if err := h.decRef(); err != nil {
			t.Errorf("decRef of a broken handle: %v", err)
		}
	}
}

func TestRegistryLastReferenceLeavesRegistry(t *testing.T) {
	v := newFakeVolume(t)
	h := v.create("d/a", false)
	if n := v.reg.count(); n != 1 {
		t.Fatalf("count = %d, want 1", n)
	}
	if err := h.decRef(); err != nil {
		t.Fatal(err)
	}
	if n := v.reg.count(); n != 0 {
		t.Fatalf("count after the last reference = %d, want 0", n)
	}
	q := v.reg.quiesce("d")
	if len(q.held) != 0 {
		t.Fatalf("the quiesce holds %d handles of a closed file", len(q.held))
	}
	if err := q.finish(false, ""); err != nil {
		t.Fatal(err)
	}
}

func TestRegistryDetachAndMoveFile(t *testing.T) {
	v := newFakeVolume(t)
	a, b := v.create("d/a", false), v.create("d/b", false)
	v.reg.moveFile("d/a", "d/c")
	v.moveTree("d/a", "d/c")
	if got := v.reg.pathOf(a); got != "d/c" {
		t.Fatalf("path after moveFile = %q", got)
	}
	v.reg.detach("d/b")
	if got := v.reg.quiesce("d"); len(got.held) != 1 || got.held[0].h != a {
		t.Fatalf("the quiesce holds %d handles, want only the moved file", len(got.held))
	} else if err := got.finish(false, ""); err != nil {
		t.Fatal(err)
	}
	// A detached handle stays open and usable.
	f, err := b.acquire()
	if err != nil {
		t.Fatal(err)
	}
	v.use(f)
	b.release()
}

func TestRegistryNilIsInert(t *testing.T) {
	var r *winHandleRegistry
	r.add(newHostHandle(nil, os.O_RDONLY), "x")
	r.remove(nil)
	r.detach("x")
	r.moveFile("x", "y")
	q := r.quiesce("x")
	if q != nil {
		t.Fatalf("quiesce on a nil registry = %v", q)
	}
	if err := q.finish(true, "y"); err != nil {
		t.Fatal(err)
	}
}

// TestRegistryNeverExposesClosedFile runs readers and writers against handles
// while quiesces move the handles back and forth. The fake panics when a use
// reaches a closed file. Two movers use opposite directions, and one more
// mover rolls back a subtree that overlaps the others, so the handle locks
// must follow one order.
func TestRegistryNeverExposesClosedFile(t *testing.T) {
	v := newFakeVolume(t)
	var all []*hostHandle
	for _, p := range []string{"a/p", "a/s/x", "a/s/y", "a/s/z", "x/p", "x/q/r"} {
		all = append(all, v.create(p, true))
	}

	var stop atomic.Bool
	var users sync.WaitGroup
	for _, h := range all {
		for range 2 {
			users.Add(1)
			go func() {
				defer users.Done()
				buf := make([]byte, 8)
				for !stop.Load() {
					f, err := h.acquire()
					if err == nil {
						v.use(f)
						h.release()
					}
					if _, err := h.readAt(buf, 0); err != nil && !errors.Is(err, io.EOF) {
						t.Errorf("readAt: %v", err)
						return
					}
					if _, err := h.writeAt(buf, 0); err != nil {
						t.Errorf("writeAt: %v", err)
						return
					}
				}
			}()
		}
	}

	const rounds = 200
	var movers sync.WaitGroup
	move := func(from, to string) {
		defer movers.Done()
		for range rounds {
			for _, pair := range [][2]string{{from, to}, {to, from}} {
				q := v.reg.quiesce(pair[0])
				v.moveTree(pair[0], pair[1])
				if err := q.finish(true, pair[1]); err != nil {
					t.Errorf("finish: %v", err)
					return
				}
			}
		}
	}
	movers.Add(4)
	go move("a", "b")
	go move("x", "y")
	go func() {
		defer movers.Done()
		for range rounds {
			q := v.reg.quiesce("a")
			if err := q.finish(false, ""); err != nil {
				t.Errorf("rollback of the whole tree: %v", err)
				return
			}
		}
	}()
	go func() {
		defer movers.Done()
		for range rounds {
			q := v.reg.quiesce("a/s")
			if err := q.finish(false, ""); err != nil {
				t.Errorf("rollback: %v", err)
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		movers.Wait()
		stop.Store(true)
		users.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		t.Fatal("the quiesces deadlocked")
	}
}

// count returns the number of registered handles.
func (r *winHandleRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.handles)
}
