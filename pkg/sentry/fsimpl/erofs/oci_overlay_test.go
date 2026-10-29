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

package erofs_test

import (
	"archive/tar"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"z.gfire.dev/gvx/third_party/x_sys/unix"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/erofs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/overlay"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

// fixedClock is the realtime clock of the test sentry. tmpfs only reads Now.
type fixedClock struct{}

func (fixedClock) Now() ktime.Time                     { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedClock) NewTimer(ktime.Listener) ktime.Timer { panic("fixedClock has no timers") }

// sentry is a VFS with the filesystems that image mounts use.
type sentry struct {
	t     *testing.T
	ctx   gvcontext.Context
	vfs   *vfs.VirtualFilesystem
	creds *auth.Credentials
	root  vfs.VirtualDentry
}

func newSentry(t *testing.T) *sentry {
	t.Helper()
	memFD, err := memutil.CreateMemFD("oci-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), "oci-test"), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatal(err)
	}
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ctx := gvcontext.WithValues(gvcontext.Background(), map[any]any{
		pgalloc.CtxMemoryFile:  mf,
		ktime.CtxRealtimeClock: fixedClock{},
		auth.CtxCredentials:    creds,
		limits.CtxLimits:       ls,
	})

	v := &vfs.VirtualFilesystem{}
	if err := v.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	v.MustRegisterFilesystemType("erofs", erofs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	v.MustRegisterFilesystemType("overlay", overlay.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	v.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	return &sentry{t: t, ctx: ctx, vfs: v, creds: creds}
}

// mountErofs mounts one compiled layer read-only and returns its root.
func (s *sentry) mountErofs(path string) vfs.VirtualDentry {
	s.t.Helper()
	f, err := os.Open(path)
	if err != nil {
		s.t.Fatal(err)
	}
	defer f.Close()
	// The filesystem takes ownership of the descriptor it is given.
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		s.t.Fatal(err)
	}
	fs, rootDentry, err := erofs.FilesystemType{}.GetFilesystem(s.ctx, s.vfs, s.creds, "", vfs.GetFilesystemOptions{
		Data: "ifd=" + strconv.Itoa(fd),
	})
	if err != nil {
		s.t.Fatalf("mount EROFS layer %s: %v", path, err)
	}
	mnt := s.vfs.NewDisconnectedMount(fs, rootDentry, &vfs.MountOptions{ReadOnly: true})
	fs.DecRef(s.ctx)
	return vfs.MakeVirtualDentry(mnt, rootDentry)
}

// mountOverlay stacks layers, given bottom first, under a tmpfs upper layer.
func (s *sentry) mountOverlay(layerPaths ...string) {
	s.t.Helper()
	var lowers []vfs.VirtualDentry
	// overlay.FilesystemOptions.LowerRoots[0] is the top-most lower layer.
	for i := len(layerPaths) - 1; i >= 0; i-- {
		lowers = append(lowers, s.mountErofs(layerPaths[i]))
	}
	upperFS, upperRoot, err := tmpfs.FilesystemType{}.GetFilesystem(s.ctx, s.vfs, s.creds, "", vfs.GetFilesystemOptions{})
	if err != nil {
		s.t.Fatalf("create tmpfs upper layer: %v", err)
	}
	upperMnt := s.vfs.NewDisconnectedMount(upperFS, upperRoot, &vfs.MountOptions{})
	upperFS.DecRef(s.ctx)
	upper := vfs.MakeVirtualDentry(upperMnt, upperRoot)

	mntns, err := s.vfs.NewMountNamespace(s.ctx, s.creds, "", "overlay", &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{
			InternalData: overlay.FilesystemOptions{UpperRoot: upper, LowerRoots: lowers},
		},
	}, nil)
	if err != nil {
		s.t.Fatalf("create overlay mount namespace: %v", err)
	}
	upper.DecRef(s.ctx)
	for _, l := range lowers {
		l.DecRef(s.ctx)
	}
	s.root = mntns.Root(s.ctx)
	s.ctx = vfs.WithRoot(s.ctx, s.root)
	s.t.Cleanup(func() {
		s.root.DecRef(s.ctx)
		mntns.DecRef(s.ctx)
	})
}

func (s *sentry) pop(p string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: s.root, Start: s.root, Path: fspath.Parse(p), FollowFinalSymlink: true}
}

func (s *sentry) stat(p string) (linux.Statx, error) {
	return s.vfs.StatAt(s.ctx, s.creds, s.pop(p), &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
}

func (s *sentry) list(p string) []string {
	s.t.Helper()
	fd, err := s.vfs.OpenAt(s.ctx, s.creds, s.pop(p), &vfs.OpenOptions{Flags: linux.O_RDONLY | linux.O_DIRECTORY})
	if err != nil {
		s.t.Fatalf("open directory %s: %v", p, err)
	}
	defer fd.DecRef(s.ctx)
	var names []string
	err = fd.IterDirents(s.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if d.Name != "." && d.Name != ".." {
			names = append(names, d.Name)
		}
		return nil
	}))
	if err != nil {
		s.t.Fatalf("list %s: %v", p, err)
	}
	slices.Sort(names)
	return names
}

func (s *sentry) read(p string) string {
	s.t.Helper()
	fd, err := s.vfs.OpenAt(s.ctx, s.creds, s.pop(p), &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		s.t.Fatalf("open %s: %v", p, err)
	}
	defer fd.DecRef(s.ctx)
	var out []byte
	buf := make([]byte, 64<<10)
	for {
		n, err := fd.Read(s.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
		out = append(out, buf[:n]...)
		if errors.Is(err, io.EOF) || (err == nil && n == 0) {
			break
		}
		if err != nil {
			s.t.Fatalf("read %s: %v", p, err)
		}
	}
	return string(out)
}

func baseLayer(t *testing.T) []byte {
	return buildTar(t,
		dirEntry("dir/"), fileEntry("dir/keep", "base-keep"), fileEntry("dir/zz", "base-zz"), dirEntry("dir/sub/"), fileEntry("dir/sub/deep", "d"),
		dirEntry("dir2/"), fileEntry("dir2/a", "a"), fileEntry("dir2/b", "b"), fileEntry("dir2/c", "c"),
		fileEntry("rm-me", "gone soon"),
		dirEntry("etc/"), fileEntry("etc/passwd", "base-passwd"),
		fileEntry("Case-File", "UPPER"), fileEntry("case-file", "lower"),
		symlinkEntry("link", "etc/passwd"),
		dirEntry("dev/"), deviceEntry("dev/null", tar.TypeChar, 1, 3),
	)
}

func topLayer(t *testing.T, withOpaque bool) []byte {
	entries := []tarEntry{
		dirEntry("dir/"), fileEntry("dir/new", "top-new"),
		fileEntry(".wh.rm-me", ""),
		dirEntry("dir2/"), fileEntry("dir2/.wh.b", ""), fileEntry("dir2/d", "d"),
		dirEntry("etc/"), fileEntry("etc/passwd", "top-passwd"),
	}
	if withOpaque {
		entries = append(entries, fileEntry("dir/.wh..wh..opq", ""))
	}
	return buildTar(t, entries...)
}

func TestOverlayHonorsCompiledWhiteoutsAndOpaqueDirs(t *testing.T) {
	forEachBlockSize(t, runOverlayHonorsCompiledWhiteoutsAndOpaqueDirs)
}

func runOverlayHonorsCompiledWhiteoutsAndOpaqueDirs(t *testing.T, bs int) {
	basePath, _ := compileTar(t, bs, baseLayer(t))
	topPath, _ := compileTar(t, bs, topLayer(t, true))
	s := newSentry(t)
	s.mountOverlay(basePath, topPath)

	if got, want := s.list("/dir"), []string{"new"}; !slices.Equal(got, want) {
		t.Errorf("opaque directory lists %v, want only the top layer's %v", got, want)
	}
	for _, p := range []string{"/dir/keep", "/dir/sub", "/dir/sub/deep"} {
		if _, err := s.stat(p); !linuxerr.Equals(linuxerr.ENOENT, err) {
			t.Errorf("stat %s = %v, want ENOENT behind the opaque directory", p, err)
		}
	}
	if got := s.read("/dir/new"); got != "top-new" {
		t.Errorf("/dir/new = %q", got)
	}

	if _, err := s.stat("/rm-me"); !linuxerr.Equals(linuxerr.ENOENT, err) {
		t.Errorf("stat /rm-me = %v, want ENOENT behind the whiteout", err)
	}
	if got := s.list("/dir2"); !slices.Equal(got, []string{"a", "c", "d"}) {
		t.Errorf("/dir2 lists %v, want [a c d] with b whited out", got)
	}
	if got := s.read("/etc/passwd"); got != "top-passwd" {
		t.Errorf("/etc/passwd = %q, want the top layer's content", got)
	}

	root := s.list("/")
	for _, want := range []string{"Case-File", "case-file", "dir", "dir2", "etc", "link", "dev"} {
		if !slices.Contains(root, want) {
			t.Errorf("root lists %v, missing %q", root, want)
		}
	}
	if slices.Contains(root, "rm-me") {
		t.Errorf("root lists the whited out %q", "rm-me")
	}
	if got := s.read("/Case-File") + "/" + s.read("/case-file"); got != "UPPER/lower" {
		t.Errorf("case-sensitive names read %q, want UPPER/lower", got)
	}

	// A real device is not a whiteout, and its numbers reach stat.
	st, err := s.stat("/dev/null")
	if err != nil {
		t.Fatalf("stat /dev/null: %v", err)
	}
	if st.Mode&linux.S_IFMT != linux.S_IFCHR || st.RdevMajor != 1 || st.RdevMinor != 3 {
		t.Errorf("/dev/null = mode %o rdev %d:%d, want a 1:3 character device", st.Mode, st.RdevMajor, st.RdevMinor)
	}
	if got := s.read("/link"); got != "top-passwd" {
		t.Errorf("symlink read = %q", got)
	}

	// Writes land in the tmpfs upper layer and copy up from the EROFS layers.
	fd, err := s.vfs.OpenAt(s.ctx, s.creds, s.pop("/etc/passwd"), &vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_TRUNC})
	if err != nil {
		t.Fatalf("open /etc/passwd for writing: %v", err)
	}
	if _, err := fd.Write(s.ctx, usermem.BytesIOSequence([]byte("edited")), vfs.WriteOptions{}); err != nil {
		t.Fatalf("write: %v", err)
	}
	fd.DecRef(s.ctx)
	if got := s.read("/etc/passwd"); got != "edited" {
		t.Errorf("after write /etc/passwd = %q", got)
	}
}

func TestOverlayWithoutOpaqueMarkerMergesDirectories(t *testing.T) {
	forEachBlockSize(t, runOverlayWithoutOpaqueMarkerMergesDirectories)
}

func runOverlayWithoutOpaqueMarkerMergesDirectories(t *testing.T, bs int) {
	// The same stack without the marker must merge, which shows that the
	// opaque result above comes from the xattr and not from layer order.
	basePath, _ := compileTar(t, bs, baseLayer(t))
	topPath, _ := compileTar(t, bs, topLayer(t, false))
	s := newSentry(t)
	s.mountOverlay(basePath, topPath)
	if got, want := s.list("/dir"), []string{"keep", "new", "sub", "zz"}; !slices.Equal(got, want) {
		t.Errorf("merged directory lists %v, want %v", got, want)
	}
}

func TestOverlayOpaqueMarkerAppliesToLowerLayersOnly(t *testing.T) {
	forEachBlockSize(t, runOverlayOpaqueMarkerAppliesToLowerLayersOnly)
}

func runOverlayOpaqueMarkerAppliesToLowerLayersOnly(t *testing.T, bs int) {
	// Entries that share a layer with the marker stay visible whatever the
	// order of the tar stream, including names that sort before the marker.
	bottom := buildTar(t, dirEntry("d/"), fileEntry("d/lower", "l"))
	top := buildTar(t,
		dirEntry("d/"), fileEntry("d/!first", "1"), fileEntry("d/.wh..wh..opq", ""), fileEntry("d/zzz", "z"))
	bottomPath, _ := compileTar(t, bs, bottom)
	topPath, _ := compileTar(t, bs, top)
	s := newSentry(t)
	s.mountOverlay(bottomPath, topPath)
	if got, want := s.list("/d"), []string{"!first", "zzz"}; !slices.Equal(got, want) {
		t.Errorf("/d lists %v, want %v", got, want)
	}
}

func TestErofsServesTrustedXattrsToPrivilegedCallersOnly(t *testing.T) {
	forEachBlockSize(t, runErofsServesTrustedXattrsToPrivilegedCallersOnly)
}

func runErofsServesTrustedXattrsToPrivilegedCallersOnly(t *testing.T, bs int) {
	path, _ := compileTar(t, bs, buildTar(t,
		dirEntry("opq/"), fileEntry("opq/.wh..wh..opq", ""),
		tarEntry{hdr: tar.Header{Name: "ping", Typeflag: tar.TypeReg, Mode: 0o755, Size: 1, ModTime: epoch,
			PAXRecords: map[string]string{"SCHILY.xattr.user.note": "hello"}}, data: []byte("p")},
	))
	s := newSentry(t)
	root := s.mountErofs(path)
	defer root.DecRef(s.ctx)
	s.root = root
	pop := func(p string) *vfs.PathOperation {
		return &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(p)}
	}

	got, err := s.vfs.GetXattrAt(s.ctx, s.creds, pop("/opq"), &vfs.GetXattrOptions{Name: "trusted.overlay.opaque", Size: 1})
	if err != nil || got != "y" {
		t.Errorf("root GetXattrAt = %q, %v, want y", got, err)
	}
	if _, err := s.vfs.GetXattrAt(s.ctx, s.creds, pop("/opq"), &vfs.GetXattrOptions{Name: "trusted.overlay.opaque", Size: 0}); err != nil {
		t.Errorf("GetXattrAt with a zero size query: %v", err)
	}
	if got, err := s.vfs.GetXattrAt(s.ctx, s.creds, pop("/ping"), &vfs.GetXattrOptions{Name: "user.note"}); err != nil || got != "hello" {
		t.Errorf("user.note = %q, %v", got, err)
	}
	if _, err := s.vfs.GetXattrAt(s.ctx, s.creds, pop("/ping"), &vfs.GetXattrOptions{Name: "user.absent"}); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Errorf("missing xattr error = %v, want ENODATA", err)
	}
	names, err := s.vfs.ListXattrAt(s.ctx, s.creds, pop("/opq"), 0)
	if err != nil || !slices.Equal(names, []string{"trusted.overlay.opaque"}) {
		t.Errorf("ListXattrAt = %v, %v", names, err)
	}

	user := auth.NewUserCredentials(1000, 1000, nil, nil, s.creds.UserNamespace)
	if _, err := s.vfs.GetXattrAt(s.ctx, user, pop("/opq"), &vfs.GetXattrOptions{Name: "trusted.overlay.opaque"}); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Errorf("unprivileged trusted.* read = %v, want ENODATA", err)
	}
	names, err = s.vfs.ListXattrAt(s.ctx, user, pop("/opq"), 0)
	if err != nil || len(names) != 0 {
		t.Errorf("unprivileged ListXattrAt = %v, %v, want no names", names, err)
	}
	if err := s.vfs.SetXattrAt(s.ctx, s.creds, pop("/opq"), &vfs.SetXattrOptions{Name: "user.x", Value: "v"}); !linuxerr.Equals(linuxerr.EROFS, err) {
		t.Errorf("SetXattrAt on a read-only layer = %v, want EROFS", err)
	}
}

func TestErofsMountReadsInlineChunkedAndPlainFiles(t *testing.T) {
	forEachBlockSize(t, runErofsMountReadsInlineChunkedAndPlainFiles)
}

func runErofsMountReadsInlineChunkedAndPlainFiles(t *testing.T, bs int) {
	const sparseSize = 3<<20 + 4097
	sparse := make([]byte, sparseSize)
	copy(sparse[5*bs:], patternBytes(bs, 21))
	copy(sparse[sparseSize-300:], patternBytes(300, 22))
	plain := patternBytes(2*bs+500, 23)
	inline := patternBytes(900, 24)
	tailInline := patternBytes(bs+700, 25)

	path, _ := compileTar(t, bs, buildTar(t,
		fileEntry("sparse", string(sparse)), fileEntry("plain", string(plain)),
		fileEntry("inline", string(inline)), fileEntry("tail", string(tailInline)),
		symlinkEntry("link", "inline"),
	))
	s := newSentry(t)
	root := s.mountErofs(path)
	defer root.DecRef(s.ctx)
	s.root = root

	for name, want := range map[string][]byte{"/sparse": sparse, "/plain": plain, "/inline": inline, "/tail": tailInline, "/link": inline} {
		if got := s.read(name); got != string(want) {
			t.Errorf("%s: read %d bytes that differ from the %d bytes written", name, len(got), len(want))
		}
	}
	st, err := s.stat("/sparse")
	if err != nil || st.Size != sparseSize {
		t.Errorf("stat /sparse = size %d, %v", st.Size, err)
	}
}

// Test helpers that build layer tarballs and compile them with pkg/oci.

type tarEntry struct {
	hdr  tar.Header
	data []byte
}

var epoch = time.Unix(1_700_000_000, 0)

func dirEntry(name string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0o755, ModTime: epoch}}
}

func fileEntry(name, data string) tarEntry {
	return tarEntry{
		hdr:  tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(data)), ModTime: epoch},
		data: []byte(data),
	}
}

func symlinkEntry(name, target string) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: tar.TypeSymlink, Linkname: target, Mode: 0o777, ModTime: epoch}}
}

func deviceEntry(name string, typeflag byte, major, minor int64) tarEntry {
	return tarEntry{hdr: tar.Header{Name: name, Typeflag: typeflag, Devmajor: major, Devminor: minor, Mode: 0o600, ModTime: epoch}}
}

func buildTar(t testing.TB, entries ...tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := e.hdr
		hdr.Format = tar.FormatPAX
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("write tar header %q: %v", hdr.Name, err)
		}
		if _, err := tw.Write(e.data); err != nil {
			t.Fatalf("write tar data %q: %v", hdr.Name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	return buf.Bytes()
}

// blockSizes lists the EROFS block sizes that the tests compile layers with.
// The sentry refuses sizes that are not a multiple of its page size, so the
// build's page size decides which of them run.
var blockSizes = []int{4096, 16384, 65536}

func forEachBlockSize(t *testing.T, fn func(t *testing.T, bs int)) {
	t.Helper()
	for _, bs := range blockSizes {
		t.Run(fmt.Sprintf("block%d", bs), func(t *testing.T) {
			if bs%hostarch.PageSize != 0 {
				t.Skipf("block size %d is not a multiple of the %d-byte page size", bs, hostarch.PageSize)
			}
			fn(t, bs)
		})
	}
}

func compileTar(t testing.TB, bs int, raw []byte) (string, oci.CompileStats) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "layer.erofs")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	stats, err := oci.CompileTarToEROFSWithOptions(bytes.NewReader(raw), f, oci.CompileOptions{BlockSize: bs})
	if err != nil {
		t.Fatalf("CompileTarToEROFS: %v", err)
	}
	return p, stats
}

func patternBytes(n int, seed uint64) []byte {
	var key [32]byte
	binary.LittleEndian.PutUint64(key[:], seed)
	b := make([]byte, n)
	rand.NewChaCha8(key).Read(b)
	return b
}
