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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// singleEnv mounts a single-file workspace on a regular file of an outer
// directory workspace, the way the guest mounts a bound file. The guest sees
// the host file at the path "mp" of the outer mount.
type singleEnv struct {
	*env
	single  *Workspace
	hostDir string
	file    string
	clock   *testClock
}

const singleName = "target.txt"

func newSingleEnv(t *testing.T, content string, readOnly bool) *singleEnv {
	t.Helper()
	outer := newEnv(t)
	hostDir := resolvedTempDir(t)
	file := filepath.Join(hostDir, singleName)
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hostDir, "sibling.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	clock := &testClock{}
	clock.advance(time.Hour)
	ws, err := openWorkspace(file, readOnly, workspaceOptions{coalesce: defaultCoalesceWindow, clock: clock.now})
	if err != nil {
		t.Fatalf("openWorkspace of a file: %v", err)
	}
	outer.writeFile("mp", nil)
	_, err = outer.vfsObj.MountAt(outer.ctx, outer.creds, "", outer.fpop("mp"), Name, &vfs.MountOptions{
		ReadOnly:             readOnly,
		GetFilesystemOptions: vfs.GetFilesystemOptions{InternalData: InternalFilesystemOptions{Workspace: ws}},
	})
	if err != nil {
		_ = ws.Close()
		t.Fatalf("mount of a file on a file: %v", err)
	}
	t.Cleanup(func() {
		_ = outer.vfsObj.UmountAt(outer.ctx, outer.creds, outer.pop("mp"), &vfs.UmountOptions{})
		_ = ws.Close()
	})
	return &singleEnv{env: outer, single: ws, hostDir: hostDir, file: file, clock: clock}
}

func (s *singleEnv) hostContent() string {
	s.t.Helper()
	raw, err := os.ReadFile(s.file)
	if err != nil {
		s.t.Fatal(err)
	}
	return string(raw)
}

// hostNames lists the names in the host directory of the file.
func (s *singleEnv) hostNames() []string {
	s.t.Helper()
	ents, err := os.ReadDir(s.hostDir)
	if err != nil {
		s.t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	slices.Sort(names)
	return names
}

func (s *singleEnv) wantHostNames(what string) {
	s.t.Helper()
	if got, want := s.hostNames(), []string{"sibling.txt", singleName}; !slices.Equal(got, want) {
		s.t.Fatalf("%s: host directory = %v, want %v (no .gvx_meta and no other file)", what, got, want)
	}
}

func TestSingleFileReadWriteTruncateAppend(t *testing.T) {
	s := newSingleEnv(t, "hello world", false)
	if got := s.readFile("mp"); string(got) != "hello world" {
		t.Fatalf("read = %q", got)
	}
	st := s.mustStat("mp")
	if st.Mode&linux.S_IFMT != linux.S_IFREG || st.Mode&0o7777 != 0o644 || st.Size != 11 || st.Nlink != 1 {
		t.Fatalf("stat = (mode %o, size %d, nlink %d), want a regular file with mode 644, size 11, 1 link", st.Mode, st.Size, st.Nlink)
	}

	fd := s.mustOpen("mp", linux.O_RDWR)
	s.pwriteAt(fd, 6, "WORLD")
	fd.DecRef(s.ctx)
	if got := s.hostContent(); got != "hello WORLD" {
		t.Fatalf("host after a write = %q", got)
	}

	fd = s.mustOpen("mp", linux.O_WRONLY|linux.O_APPEND)
	if _, err := fd.Write(s.ctx, usermem.BytesIOSequence([]byte("!!")), vfs.WriteOptions{}); err != nil {
		t.Fatal(err)
	}
	fd.DecRef(s.ctx)
	if got := s.hostContent(); got != "hello WORLD!!" {
		t.Fatalf("host after an append = %q", got)
	}

	fd = s.mustOpen("mp", linux.O_WRONLY|linux.O_TRUNC)
	s.pwriteAt(fd, 0, "new")
	fd.DecRef(s.ctx)
	if got := s.hostContent(); got != "new" {
		t.Fatalf("host after O_TRUNC = %q", got)
	}
	if err := s.setStat("mp", linux.Statx{Mask: linux.STATX_SIZE, Size: 1}); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if got := s.hostContent(); got != "n" {
		t.Fatalf("host after truncate = %q", got)
	}
	s.wantHostNames("after the writes")
}

func TestSingleFileHidesEverythingElse(t *testing.T) {
	s := newSingleEnv(t, "x", false)
	_, err := s.open("mp/sibling.txt", linux.O_RDONLY, 0)
	wantErrno(t, "open of a sibling below the file", err, linuxerr.ENOTDIR)
	_, err = s.stat("mp/" + singleName)
	wantErrno(t, "stat of the own name below the file", err, linuxerr.ENOTDIR)

	// The Workspace refuses every path but the root.
	if _, err := s.single.ReadFile("sibling.txt"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile(sibling.txt) = %v, want ErrNotExist", err)
	}
	if _, err := s.single.ReadFile(singleName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadFile(own name) = %v, want ErrNotExist", err)
	}
	if err := s.single.WriteFile("created.txt", []byte("no"), 0o644); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("WriteFile(created.txt) = %v, want ErrNotExist", err)
	}
	if err := s.single.Mkdir("dir", 0o755); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Mkdir(dir) = %v, want ErrNotExist", err)
	}
	if err := s.single.Symlink("x", "link"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Symlink = %v, want ErrNotExist", err)
	}
	if names, err := s.single.ListEntries(); err == nil && len(names) != 0 {
		t.Fatalf("ListEntries = %v, want nothing", names)
	}
	if !s.single.SingleFile() {
		t.Fatal("SingleFile() = false")
	}
	if got := s.hostContent(); got != "x" {
		t.Fatalf("host file changed: %q", got)
	}
	s.wantHostNames("after the refused calls")
}

func TestSingleFileKeepsAttributesInMemory(t *testing.T) {
	s := newSingleEnv(t, "data", false)
	s.chmod("mp", 0o600)
	if err := s.setStat("mp", linux.Statx{Mask: linux.STATX_UID | linux.STATX_GID, UID: 5, GID: 6}); err != nil {
		t.Fatal(err)
	}
	if err := s.vfsObj.SetXattrAt(s.ctx, s.creds, s.fpop("mp"), &vfs.SetXattrOptions{Name: "user.k", Value: "v"}); err != nil {
		t.Fatalf("setxattr: %v", err)
	}
	when := linux.StatxTimestamp{Sec: 1_700_000_000}
	if err := s.setStat("mp", linux.Statx{Mask: linux.STATX_MTIME, Mtime: when}); err != nil {
		t.Fatalf("utimens: %v", err)
	}
	st := s.mustStat("mp")
	if st.Mode&0o7777 != 0o600 || st.UID != 5 || st.GID != 6 || st.Mtime.Sec != when.Sec {
		t.Fatalf("stat = (mode %o, uid %d, gid %d, mtime %d)", st.Mode&0o7777, st.UID, st.GID, st.Mtime.Sec)
	}
	if got, err := s.vfsObj.GetXattrAt(s.ctx, s.creds, s.fpop("mp"), &vfs.GetXattrOptions{Name: "user.k", Size: 16}); err != nil || got != "v" {
		t.Fatalf("getxattr = (%q, %v)", got, err)
	}
	// The host file keeps its own mode. Only the times reach it.
	fi, err := os.Stat(s.file)
	if err != nil {
		t.Fatal(err)
	}
	if runtimeHasUnixModes() && fi.Mode().Perm() != 0o644 {
		t.Fatalf("host mode = %o, want the original 644", fi.Mode().Perm())
	}
	if fi.ModTime().Unix() != when.Sec {
		t.Fatalf("host mtime = %v, want the time that the guest set", fi.ModTime())
	}
	if err := s.single.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	s.wantHostNames("after the attribute changes and a sync")
	if err := s.single.Close(); err != nil {
		t.Fatal(err)
	}
	s.wantHostNames("after Close")

	// A new workspace starts with the attributes of the host file.
	ws2, err := openWorkspace(s.file, false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws2.Close() }()
	attr, _, err := ws2.Stat(".")
	if err != nil || attr.Mode&0o7777 == 0o600 || attr.UID == 5 {
		t.Fatalf("attributes after a restart = (%+v, %v), want the defaults of the host", attr, err)
	}
}

func TestSingleFileMountPointRules(t *testing.T) {
	s := newSingleEnv(t, "keep", false)
	wantErrno(t, "unlink of the mount point", s.unlink("mp"), linuxerr.EBUSY)
	wantErrno(t, "rename of the mount point", s.rename("mp", "elsewhere"), linuxerr.EBUSY)
	s.writeFile("other", []byte("o"))
	wantErrno(t, "rename onto the mount point", s.rename("other", "mp"), linuxerr.EBUSY)
	wantErrno(t, "link of the mounted file", s.link("mp", "alias"), linuxerr.EXDEV)
	wantErrno(t, "rmdir of the mount point", s.vfsObj.RmdirAt(s.ctx, s.creds, s.pop("mp")), linuxerr.ENOTDIR)
	wantErrno(t, "mkdir below the mount point", s.mkdir("mp/d"), linuxerr.ENOTDIR)
	if got := s.hostContent(); got != "keep" {
		t.Fatalf("host file = %q after the refused calls", got)
	}
	s.wantHostNames("after the refused calls")
}

func TestSingleFileReadOnly(t *testing.T) {
	s := newSingleEnv(t, "frozen", true)
	if got := s.readFile("mp"); string(got) != "frozen" {
		t.Fatalf("read = %q", got)
	}
	_, err := s.open("mp", linux.O_WRONLY, 0)
	wantErrno(t, "write open of a read-only mount", err, linuxerr.EROFS)
	wantErrno(t, "truncate of a read-only mount", s.setStat("mp", linux.Statx{Mask: linux.STATX_SIZE, Size: 0}), linuxerr.EROFS)
	wantErrno(t, "chmod of a read-only mount", s.setStat("mp", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o600}), linuxerr.EROFS)
	// The workspace refuses write access on its own too.
	if _, err := s.single.openSingle(os.O_WRONLY); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("openSingle(O_WRONLY) = %v, want ErrReadOnly", err)
	}
	if got := s.hostContent(); got != "frozen" {
		t.Fatalf("host file = %q", got)
	}
	s.wantHostNames("after a read-only session")
}

func TestSingleFileSyncAllocateAndMap(t *testing.T) {
	s := newSingleEnv(t, string(bytes.Repeat([]byte("a"), 2*hostarch.PageSize)), false)
	fd := s.mustOpen("mp", linux.O_RDWR)
	defer fd.DecRef(s.ctx)
	if err := fd.Sync(s.ctx); err != nil {
		t.Fatalf("fsync: %v", err)
	}
	if err := fd.Allocate(s.ctx, 0, 0, 4*hostarch.PageSize); err != nil {
		t.Fatalf("fallocate: %v", err)
	}
	if got := s.mustStat("mp").Size; got != 4*hostarch.PageSize {
		t.Fatalf("size after fallocate = %d", got)
	}
	if err := fd.Allocate(s.ctx, linux.FALLOC_FL_PUNCH_HOLE|linux.FALLOC_FL_KEEP_SIZE, 0, 100); err != nil {
		t.Fatalf("punch: %v", err)
	}
	if got := s.pread(fd, 0, 4); !bytes.Equal(got, make([]byte, 4)) {
		t.Fatalf("punched range reads %v", got)
	}

	m, ms, ar := s.mapFile(fd, 4*hostarch.PageSize, true)
	copy(mappedView(t, s.env, m, hostarch.ReadWrite, 200, 6), "MAPPED")
	if err := fd.Sync(s.ctx); err != nil {
		t.Fatalf("fsync with a mapping: %v", err)
	}
	m.RemoveMapping(s.ctx, ms, ar, 0, true)
	if got := s.hostContent()[200:206]; got != "MAPPED" {
		t.Fatalf("host content of the mapped write = %q", got)
	}
	s.wantHostNames("after the mapping")
}

// TestSingleFileFollowsAnAtomicHostReplace replaces the host file with a
// rename, as an editor does. A fresh open reaches the new file, and a file
// description that is open keeps the old one.
func TestSingleFileFollowsAnAtomicHostReplace(t *testing.T) {
	s := newSingleEnv(t, "old content", false)
	old := s.mustOpen("mp", linux.O_RDONLY)
	defer old.DecRef(s.ctx)
	if got := s.readAll(old); string(got) != "old content" {
		t.Fatalf("read before the replace = %q", got)
	}

	tmp := filepath.Join(s.hostDir, "editor.tmp")
	if err := os.WriteFile(tmp, []byte("replaced by an editor"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, s.file); err != nil {
		t.Fatal(err)
	}
	s.clock.advance(2 * time.Second)

	if got := s.readFile("mp"); string(got) != "replaced by an editor" {
		t.Fatalf("a fresh open reads %q, want the new file", got)
	}
	if got := s.mustStat("mp").Size; got != uint64(len("replaced by an editor")) {
		t.Fatalf("stat size = %d, want the size of the new file", got)
	}
	if got := s.readAll(old); string(got) != "old content" {
		t.Fatalf("the open description reads %q, want the old file", got)
	}
	// A write through a fresh description reaches the new file.
	fd := s.mustOpen("mp", linux.O_WRONLY)
	s.pwriteAt(fd, 0, "R")
	fd.DecRef(s.ctx)
	if got := s.hostContent(); got != "Replaced by an editor" {
		t.Fatalf("host content = %q", got)
	}
	s.wantHostNames("after the replace")
}

func TestSingleFileWatcherEvents(t *testing.T) {
	s := newSingleEnv(t, "one", false)
	s.single.watch.setPollInterval(time.Hour)
	w := newWatchEnvOn(t, s.env)
	w.add("mp", hostEventMask|linux.IN_ALL_EVENTS)
	sync := func() { s.single.watch.rescanAll() }
	sync()
	w.drain()

	hostWrite(t, s.file, "one two")
	sync()
	got := eventNames(w.drain())
	if !slices.Contains(got, "MODIFY ") {
		t.Fatalf("events after a host write = %q, want MODIFY", got)
	}

	// A guest write produces its own event and no echo from the scan.
	fd := s.mustOpen("mp", linux.O_WRONLY)
	s.pwriteAt(fd, 0, "ONE")
	fd.DecRef(s.ctx)
	w.drain()
	sync()
	if got := eventNames(w.drain()); len(got) != 0 {
		t.Fatalf("echo of a guest write = %q, want none", got)
	}

	// An atomic replace is a change that the guest must see.
	tmp := filepath.Join(s.hostDir, "editor.tmp")
	if err := os.WriteFile(tmp, []byte("a longer replacement"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, s.file); err != nil {
		t.Fatal(err)
	}
	s.clock.advance(2 * time.Second)
	sync()
	if got := eventNames(w.drain()); len(got) == 0 {
		t.Fatal("no event after an atomic host replace")
	}
}

func TestOpenWorkspaceOfAFilePinsTheParent(t *testing.T) {
	dir := resolvedTempDir(t)
	file := filepath.Join(dir, "Mixed.Case")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	ws, err := openWorkspace(file, false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ws.Close() }()
	if !ws.SingleFile() || ws.HostPath() != file {
		t.Fatalf("SingleFile = %v, HostPath = %q, want true and %q", ws.SingleFile(), ws.HostPath(), file)
	}
	if ws.single != "Mixed.Case" {
		t.Fatalf("remembered name = %q", ws.single)
	}
	// A link to the file resolves at open time.
	if runtimeHasUnixModes() {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(file, link); err != nil {
			t.Skipf("host cannot create symbolic links: %v", err)
		}
		ws2, err := openWorkspace(link, false, workspaceOptions{coalesce: defaultCoalesceWindow})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = ws2.Close() }()
		if ws2.single != "Mixed.Case" {
			t.Fatalf("name through a link = %q, want Mixed.Case", ws2.single)
		}
	}
	// A directory still opens as a directory workspace.
	dws, err := openWorkspace(dir, false, workspaceOptions{coalesce: defaultCoalesceWindow})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = dws.Close() }()
	if dws.SingleFile() {
		t.Fatal("a directory opened in single-file mode")
	}
}

// runtimeHasUnixModes reports a host whose file modes are Unix permission bits.
func runtimeHasUnixModes() bool {
	return runtime.GOOS != "windows"
}
