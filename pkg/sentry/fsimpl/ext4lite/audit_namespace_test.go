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
	"sort"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// credsContext carries the credentials of one caller. The VFS reads them from
// the context, as it reads them from a task.
type credsContext struct {
	gvcontext.Context
	creds *auth.Credentials
}

// Value implements context.Context.Value.
func (c credsContext) Value(key any) any {
	if key == auth.CtxCredentials {
		return c.creds
	}
	return c.Context.Value(key)
}

// withCredentials returns a context whose caller is creds.
func withCredentials(ctx gvcontext.Context, creds *auth.Credentials) gvcontext.Context {
	return credsContext{Context: ctx, creds: creds}
}

// errAuBatchFull stops a directory read after a fixed number of entries.
var errAuBatchFull = errors.New("audit: batch full")

// auTouch creates an empty regular file at p.
func auTouch(e *env, p string) {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_CREAT|linux.O_WRONLY)
	fd.DecRef(e.ctx)
}

// auDirentsN reads at most n entries of the description, dot entries included.
// The entry after the batch stays unread, so the next call returns it.
func auDirentsN(e *env, fd *vfs.FileDescription, n int) []vfs.Dirent {
	e.t.Helper()
	var out []vfs.Dirent
	err := fd.IterDirents(e.ctx, vfs.IterDirentsCallbackFunc(func(d vfs.Dirent) error {
		if len(out) == n {
			return errAuBatchFull
		}
		out = append(out, d)
		return nil
	}))
	if err != nil && !errors.Is(err, errAuBatchFull) {
		e.t.Fatalf("readdir: %v", err)
	}
	return out
}

// auListed is one entry of a directory listing with the cookie that resumes
// after it.
type auListed struct {
	name string
	next int64
}

// auListDir lists the entries of the directory p, without . and ..
func auListDir(e *env, p string) []auListed {
	e.t.Helper()
	fd := e.mustOpen(p, linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	var out []auListed
	for _, d := range auDirentsN(e, fd, 1<<20) {
		if d.Name != "." && d.Name != ".." {
			out = append(out, auListed{name: d.Name, next: d.NextOff})
		}
	}
	return out
}

// auCookieAfter returns the cookie that resumes after the entry name.
func auCookieAfter(t testing.TB, list []auListed, name string) int64 {
	t.Helper()
	for _, d := range list {
		if d.name == name {
			return d.next
		}
	}
	t.Fatalf("the listing %v has no entry %q", list, name)
	return 0
}

// auNames returns the names of a listing, in order.
func auNames(list []auListed) []string {
	out := make([]string, 0, len(list))
	for _, d := range list {
		out = append(out, d.name)
	}
	return out
}

// auSetXattr sets one attribute of p through the VFS.
func auSetXattr(e *env, p, name, value string) error {
	return e.vfsObj.SetXattrAt(e.ctx, e.creds, e.fpop(p), &vfs.SetXattrOptions{Name: name, Value: value})
}

// auGetXattr reads one attribute of p through the VFS.
func auGetXattr(e *env, p, name string) (string, error) {
	return e.vfsObj.GetXattrAt(e.ctx, e.creds, e.fpop(p), &vfs.GetXattrOptions{Name: name, Size: 1 << 16})
}

// auListXattr lists the attributes of p, sorted.
func auListXattr(e *env, p string) ([]string, error) {
	names, err := e.vfsObj.ListXattrAt(e.ctx, e.creds, e.fpop(p), 1<<16)
	sort.Strings(names)
	return names, err
}

// TestDecodeTimeClampsNanoseconds checks that a hostile extra field cannot give
// more than 999999999 nanoseconds.
func TestDecodeTimeClampsNanoseconds(t *testing.T) {
	cases := []struct {
		name  string
		lo    uint32
		extra uint32
		want  tstamp
	}{
		{name: "plain time keeps its nanoseconds and epoch bits", lo: 100, extra: 500<<2 | 1, want: tstamp{sec: 100 + 1<<32, nsec: 500}},
		{name: "largest valid nanoseconds stay", lo: 7, extra: maxNsec << 2, want: tstamp{sec: 7, nsec: maxNsec}},
		{name: "hostile extra field is clamped", lo: 7, extra: 0xFFFFFFFF, want: tstamp{sec: 7 + 3<<32, nsec: maxNsec}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeTime(tc.lo, tc.extra); got != tc.want {
				t.Errorf("decodeTime(%#x, %#x) = %+v, want %+v", tc.lo, tc.extra, got, tc.want)
			}
		})
	}
}

// TestOpenTruncClearsPrivilegeBitsWithoutFsetid checks that O_TRUNC by an owner
// without CAP_FSETID clears the set-ID bits and the file capabilities, and that
// a root caller keeps the set-ID bits.
func TestOpenTruncClearsPrivilegeBitsWithoutFsetid(t *testing.T) {
	e := newEnv(t)
	e.writeFile("/f", []byte("content"))
	if err := e.setStat("/f", linux.Statx{Mask: linux.STATX_UID | linux.STATX_GID, UID: 1000, GID: 1000}); err != nil {
		t.Fatal(err)
	}
	if err := e.setStat("/f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o6755}); err != nil {
		t.Fatal(err)
	}
	// A version 2 capability blob: the magic, then permitted and inheritable
	// sets for two words.
	capV2 := "\x01\x00\x00\x02" + "\x02\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00" + "\x00\x00\x00\x00"
	if err := auSetXattr(e, "/f", linux.XATTR_SECURITY_CAPABILITY, capV2); err != nil {
		t.Fatalf("set security.capability: %v", err)
	}

	user := userCreds(1000, 1000)
	fd, err := e.vfsObj.OpenAt(e.ctx, user, e.fpop("/f"), &vfs.OpenOptions{Flags: linux.O_WRONLY | linux.O_TRUNC})
	if err != nil {
		t.Fatalf("O_TRUNC by the owner: %v", err)
	}
	fd.DecRef(e.ctx)
	st := e.mustStat("/f")
	if st.Size != 0 {
		t.Errorf("size after O_TRUNC = %d, want 0", st.Size)
	}
	if st.Mode&(linux.S_ISUID|linux.S_ISGID) != 0 {
		t.Errorf("mode after O_TRUNC by the owner = %#o, want no set-ID bit", st.Mode)
	}
	if _, err := auGetXattr(e, "/f", linux.XATTR_SECURITY_CAPABILITY); !errors.Is(err, linuxerr.ENODATA) {
		t.Errorf("security.capability after O_TRUNC by the owner = %v, want ENODATA", err)
	}

	if err := e.setStat("/f", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o6755}); err != nil {
		t.Fatal(err)
	}
	fd, err = e.open("/f", linux.O_WRONLY|linux.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("O_TRUNC by root: %v", err)
	}
	fd.DecRef(e.ctx)
	if st := e.mustStat("/f"); st.Mode&linux.S_ISUID == 0 || st.Mode&linux.S_ISGID == 0 {
		t.Errorf("mode after O_TRUNC by root = %#o, want both set-ID bits kept", st.Mode)
	}
}

// TestDirCookieSkipsRemovedEntryOnNewDescription reads a, b, and c, unlinks a,
// and resumes at the cookie that followed b on a new description. Only c is
// left after that cookie.
func TestDirCookieSkipsRemovedEntryOnNewDescription(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("/d")
	for _, name := range []string{"a", "b", "c"} {
		auTouch(e, "/d/"+name)
	}
	listed := auListDir(e, "/d")
	if got := auNames(listed); strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("listing = %v, want a, b, c", got)
	}
	cookieAfterB := auCookieAfter(t, listed, "b")
	if err := e.unlink("/d/a"); err != nil {
		t.Fatal(err)
	}

	fd := e.mustOpen("/d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	if _, err := fd.Seek(e.ctx, cookieAfterB, linux.SEEK_SET); err != nil {
		t.Fatalf("seek to the cookie after b: %v", err)
	}
	var got []string
	for _, d := range auDirentsN(e, fd, 1<<20) {
		got = append(got, d.Name)
	}
	if strings.Join(got, ",") != "c" {
		t.Errorf("entries after the cookie of b = %v, want only c", got)
	}
}

// TestDirCookiesSurviveFlushAndRemount removes an entry, flushes, and remounts.
// The cookies of the entries that stay still resume at them, and a cookie of
// the removed entry resumes at the entry behind it.
func TestDirCookiesSurviveFlushAndRemount(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("/d")
	for _, name := range []string{"a", "b", "c", "d"} {
		auTouch(e, "/d/"+name)
	}
	listed := auListDir(e, "/d")
	cookieAfterA := auCookieAfter(t, listed, "a")
	cookieAfterB := auCookieAfter(t, listed, "b")
	if err := e.unlink("/d/b"); err != nil {
		t.Fatal(err)
	}
	if err := e.fs.syncAll(); err != nil {
		t.Fatalf("sync: %v", err)
	}
	e = e.remount()

	for _, cookie := range []int64{cookieAfterA, cookieAfterB} {
		fd := e.mustOpen("/d", linux.O_RDONLY|linux.O_DIRECTORY)
		if _, err := fd.Seek(e.ctx, cookie, linux.SEEK_SET); err != nil {
			t.Fatalf("seek to %d: %v", cookie, err)
		}
		var got []string
		for _, d := range auDirentsN(e, fd, 1<<20) {
			got = append(got, d.Name)
		}
		fd.DecRef(e.ctx)
		if strings.Join(got, ",") != "c,d" {
			t.Errorf("entries after cookie %d after remount = %v, want c, d", cookie, got)
		}
	}
}

// TestDirSeekWhence checks SEEK_SET, SEEK_CUR, and SEEK_END on a directory, and
// that a cookie inside a record resumes at the next entry.
func TestDirSeekWhence(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("/d")
	auTouch(e, "/d/a")
	auTouch(e, "/d/b")
	size := int64(e.mustStat("/d").Size)
	fd := e.mustOpen("/d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)

	if got, err := fd.Seek(e.ctx, 0, linux.SEEK_END); err != nil || got != size {
		t.Errorf("SEEK_END to 0 = (%d, %v), want the size %d", got, err, size)
	}
	if _, err := fd.Seek(e.ctx, -size-1, linux.SEEK_END); !errors.Is(err, linuxerr.EINVAL) {
		t.Errorf("SEEK_END before the start = %v, want EINVAL", err)
	}
	if _, err := fd.Seek(e.ctx, 0, linux.SEEK_DATA); !errors.Is(err, linuxerr.EINVAL) {
		t.Errorf("SEEK_DATA on a directory = %v, want EINVAL", err)
	}

	if _, err := fd.Seek(e.ctx, 0, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	first := auDirentsN(e, fd, 1)
	if len(first) != 1 || first[0].Name != "." {
		t.Fatalf("first entry = %v, want .", first)
	}
	cur, err := fd.Seek(e.ctx, 0, linux.SEEK_CUR)
	if err != nil || cur != first[0].NextOff {
		t.Errorf("SEEK_CUR after the first entry = (%d, %v), want its cookie %d", cur, err, first[0].NextOff)
	}

	// A cookie inside the record of "." resumes at the entry that follows it.
	if _, err := fd.Seek(e.ctx, 1, linux.SEEK_SET); err != nil {
		t.Fatal(err)
	}
	inside := auDirentsN(e, fd, 1)
	if len(inside) != 1 || inside[0].Name != ".." {
		t.Errorf("entries from cookie 1 = %v, want the entry ..", inside)
	}
}

// TestDirIterationNeverRepeatsOrSkipsSurvivors reads a directory in batches and
// unlinks entries between the batches. Every entry that survives all unlinks is
// returned exactly once.
func TestDirIterationNeverRepeatsOrSkipsSurvivors(t *testing.T) {
	e := newEnv(t)
	e.mustMkdir("/d")
	const total = 300
	names := make([]string, total)
	index := make(map[string]int, total)
	for i := range total {
		names[i] = fmt.Sprintf("entry-%03d-%s", i, strings.Repeat("x", 40))
		index[names[i]] = i
		auTouch(e, "/d/"+names[i])
	}

	fd := e.mustOpen("/d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer fd.DecRef(e.ctx)
	seen := make(map[string]int, total)
	removed := make(map[string]bool)
	for {
		batch := auDirentsN(e, fd, 20)
		if len(batch) == 0 {
			break
		}
		for _, d := range batch {
			if d.Name == "." || d.Name == ".." {
				continue
			}
			seen[d.Name]++
			// Remove some entries that the reader has passed.
			if index[d.Name]%3 == 0 && !removed[d.Name] {
				if err := e.unlink("/d/" + d.Name); err != nil {
					t.Fatal(err)
				}
				removed[d.Name] = true
			}
		}
		// Remove some entries that the reader has not reached yet.
		for _, name := range names {
			if seen[name] == 0 && !removed[name] && index[name]%7 == 5 {
				if err := e.unlink("/d/" + name); err != nil {
					t.Fatal(err)
				}
				removed[name] = true
			}
		}
	}

	var problems []string
	for _, name := range names {
		if removed[name] {
			continue
		}
		if seen[name] != 1 {
			problems = append(problems, fmt.Sprintf("survivor %s returned %d times, want once", name, seen[name]))
		}
	}
	for name, n := range seen {
		if n > 1 {
			problems = append(problems, fmt.Sprintf("entry %s returned %d times", name, n))
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
	if len(seen) == 0 {
		t.Fatal("the reader returned no entry")
	}
}

// TestRemoveEntryFailureLeavesDirectoryIntact frees the last block of a
// directory with a bitmap that no longer holds that block. The removal must
// fail before it changes the entry index, the blocks, or the size. Once the
// bitmap is repaired, the same removal succeeds and drops the block.
func TestRemoveEntryFailureLeavesDirectoryIntact(t *testing.T) {
	d := newAuDrv(t)
	d.mkdir("/d")
	long := strings.Repeat("n", 200)
	for i := range 40 {
		d.create(fmt.Sprintf("/d/%02d%s", i, long), 0)
	}
	v := d.e.fs.v
	st := d.e.mustStat("/d")
	n, err := v.getNode(uint32(st.Ino))
	if err != nil {
		t.Fatal(err)
	}
	defer v.putNode(n)

	n.mu.Lock()
	if err := n.loadDirLocked(); err != nil {
		n.mu.Unlock()
		t.Fatal(err)
	}
	last := n.dir.blocks[len(n.dir.blocks)-1]
	var tail []string
	for _, e := range last.entries {
		tail = append(tail, e.name)
	}
	ext := n.exts[len(n.exts)-1]
	phys := ext.pblk + uint64(ext.n) - 1
	blocksBefore := len(n.dir.blocks)
	sizeBefore := n.size
	n.mu.Unlock()
	if len(tail) != 2 {
		t.Fatalf("the last block holds %d entries, want 2", len(tail))
	}

	// The first removal leaves the last block with one entry, so it frees nothing.
	d.unlink("/d/" + tail[0])

	v.mu.Lock()
	g := v.groups[phys/blocksPerGroup]
	off := uint32(phys % blocksPerGroup)
	g.blocks.clear(off)
	v.mu.Unlock()

	err = d.e.unlink("/d/" + tail[1])
	if !errors.Is(err, linuxerr.EUCLEAN) {
		t.Errorf("unlink with the last block unallocated = %v, want EUCLEAN", err)
	}
	d.verifyLive("after the failed removal")
	n.mu.Lock()
	if got := len(n.dir.blocks); got != blocksBefore || n.size != sizeBefore {
		t.Errorf("after the failed removal: %d blocks and size %d, want %d and %d", got, n.size, blocksBefore, sizeBefore)
	}
	n.mu.Unlock()

	v.mu.Lock()
	g.blocks.set(off)
	v.mu.Unlock()
	d.unlink("/d/" + tail[1])
	d.verifyLive("after the repaired removal")
	n.mu.Lock()
	if got := len(n.dir.blocks); got != blocksBefore-1 {
		t.Errorf("after the repaired removal: %d blocks, want %d", got, blocksBefore-1)
	}
	n.mu.Unlock()
	d.syncAll()
}

// TestDirectoryAndInodeSizesOutsideTheExtentsFailWithEUCLEAN damages the size
// of a directory, a regular file, and symlinks. Each damaged inode fails with
// EUCLEAN, and none of them panics or allocates from the size.
func TestDirectoryAndInodeSizesOutsideTheExtentsFailWithEUCLEAN(t *testing.T) {
	d := newAuDrv(t)
	d.mkdir("/d")
	d.create("/f", 3*blockSize)
	d.symlink(strings.Repeat("t", 200), "/s")
	d.symlink("abc", "/t")
	d.e.unmount()
	base := d.f.snapshot()
	tree := auFsck(base, true).Tree

	type patch struct {
		off int64
		val uint32
	}
	const sizeLo, sizeHi = 0x04, 0x6C
	cases := []struct {
		name    string
		path    string
		patches []patch
	}{
		{"directory size past its extents", "/d", []patch{{sizeLo, 8192}}},
		{"directory size not a multiple of the block size", "/d", []patch{{sizeLo, 4097}}},
		{"directory size zero", "/d", []patch{{sizeLo, 0}}},
		{"directory size beyond the block cap", "/d", []patch{{sizeHi, 1}, {sizeLo, 4096}}},
		{"regular file size beyond the largest file", "/f", []patch{{sizeHi, 0x10000}}},
		{"long symlink size zero", "/s", []patch{{sizeLo, 0}}},
		{"long symlink size above the target limit", "/s", []patch{{sizeLo, 4096}}},
		{"long symlink size with high bit set", "/s", []patch{{sizeHi, 0x80000000}}},
		{"inline symlink size zero", "/t", []patch{{sizeLo, 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			img := base.clone()
			raw := auRawInode(img, tree[tc.path].ino)
			for _, p := range tc.patches {
				auLE.PutUint32(raw[p.off:], p.val)
			}
			auWriteRawInode(img, tree[tc.path].ino, raw)

			var err error
			panicked := auGuarded(func() {
				e, _, merr := auTryMount(newAuFile(img))
				if merr != nil {
					err = merr
					return
				}
				e.t = t
				t.Cleanup(e.unmount)
				_, err = e.lstat(tc.path)
			})
			if panicked != "" {
				t.Fatalf("the damaged inode panics: %s", panicked)
			}
			if !errors.Is(err, linuxerr.EUCLEAN) {
				t.Errorf("lstat %s = %v, want EUCLEAN", tc.path, err)
			}
		})
	}

	// The undamaged image mounts and every inode loads.
	e, _, err := auTryMount(newAuFile(base.clone()))
	if err != nil {
		t.Fatalf("mount of the undamaged image: %v", err)
	}
	e.t = t
	t.Cleanup(e.unmount)
	for _, p := range []string{"/d", "/f", "/s", "/t"} {
		if _, err := e.lstat(p); err != nil {
			t.Errorf("lstat %s on the undamaged image: %v", p, err)
		}
	}
}

// auRawInode returns the 256 bytes of inode ino in the image.
func auRawInode(img *auPages, ino uint32) []byte {
	raw := make([]byte, auISize)
	img.readAt(raw, auInodeOffset(ino))
	return raw
}

// auWriteRawInode stores the 256 bytes of inode ino in the image.
func auWriteRawInode(img *auPages, ino uint32, raw []byte) {
	img.writeAt(raw, auInodeOffset(ino))
}

// auInodeOffset returns the byte offset of inode ino. The inode table starts at
// block 67 of the layout that the oracle checks.
func auInodeOffset(ino uint32) int64 {
	return int64(67)*auBlock + int64(ino-1)*auISize
}

// auAttr is one attribute that an image keeps in the inode.
type auAttr struct {
	index uint8
	name  string
	value string
}

// auPutIbody writes attrs into the attribute area of a raw inode, the way Linux
// writes it: the magic number, the entries, and the values packed from the end
// of the area. Value offsets count from the first entry.
func auPutIbody(raw []byte, attrs []auAttr) {
	area := raw[ibodyOffset:]
	clear(area)
	auLE.PutUint32(area, auXattrMagic)
	off := 4
	valEnd := len(area)
	for _, a := range attrs {
		vlen := (len(a.value) + 3) &^ 3
		valEnd -= vlen
		copy(area[valEnd:], a.value)
		area[off] = byte(len(a.name))
		area[off+1] = a.index
		auLE.PutUint16(area[off+2:], uint16(valEnd-4))
		auLE.PutUint32(area[off+8:], uint32(len(a.value)))
		copy(area[off+16:], a.name)
		off += (16 + len(a.name) + 3) &^ 3
	}
}

// auMountImage mounts a copy of img through the VFS and returns the environment
// and the file that holds the image. The caller unmounts the environment.
func auMountImage(t *testing.T, img *auPages) (*env, *auFile) {
	t.Helper()
	fl := newAuFile(img)
	e, _, err := auTryMount(fl)
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	e.t = t
	t.Cleanup(e.unmount)
	return e, fl
}

// auSharedXattrImage returns an image in which /f and /g name one xattr block,
// as Linux writes it for equal attribute sets. The block holds user.a = alpha
// and its header counts two references. The block number is returned too.
func auSharedXattrImage(t *testing.T) (*auPages, uint64) {
	t.Helper()
	return auSharedXattrImageWithHole(t, false)
}

// auSharedXattrImageWithHole is auSharedXattrImage with an optional hole. When
// hole is set, a deleted file leaves free blocks below the shared block.
func auSharedXattrImageWithHole(t *testing.T, hole bool) (*auPages, uint64) {
	t.Helper()
	d := newAuDrv(t)
	if hole {
		d.create("/pad", 4*blockSize)
	}
	d.create("/f", 0)
	d.create("/g", 0)
	if err := auSetXattr(d.e, "/f", "user.a", "alpha"); err != nil {
		t.Fatal(err)
	}
	if hole {
		d.unlink("/pad")
	}
	d.e.unmount()
	base := d.f.snapshot()
	tree := auFsck(base, true).Tree
	fRaw := auRawInode(base, tree["/f"].ino)
	acl := uint64(auLE.Uint32(fRaw[0x68:])) | uint64(auLE.Uint16(fRaw[0x76:]))<<32

	// /g takes the block of /f. Each inode counts the block in i_blocks.
	gRaw := auRawInode(base, tree["/g"].ino)
	auLE.PutUint32(gRaw[0x68:], uint32(acl))
	auLE.PutUint16(gRaw[0x76:], uint16(acl>>32))
	auLE.PutUint32(gRaw[0x1C:], auLE.Uint32(gRaw[0x1C:])+8)
	auWriteRawInode(base, tree["/g"].ino, gRaw)
	base.writeAt([]byte{2, 0, 0, 0}, int64(acl)*auBlock+4)
	if res := auFsck(base, true); !res.OK() {
		t.Fatalf("the image with a shared xattr block fails the oracle:\n%s", res)
	}
	return base, acl
}

// auRefcount returns the reference count in the header of xattr block acl.
func auRefcount(img *auPages, acl uint64) uint32 {
	var hdr [8]byte
	img.readAt(hdr[:], int64(acl)*auBlock)
	return auLE.Uint32(hdr[4:])
}

// auBlockBytesWithoutRefcount returns the bytes of block blk except its
// reference count.
func auBlockBytesWithoutRefcount(img *auPages, blk uint64) []byte {
	var b [auBlock]byte
	img.readAt(b[:], int64(blk)*auBlock)
	clear(b[4:8])
	return b[:]
}

// auClaimed reports whether an inode of the image names block blk. The strict
// oracle compares the bitmap with the blocks that the inodes claim, so an
// unclaimed block is also free in the bitmap.
func auClaimed(img *auPages, blk uint64) bool {
	_, claimed := auFsck(img, true).Blocks[blk]
	return claimed
}

// auFlush flushes the volume as sync(2) does.
func auFlush(t *testing.T, e *env) {
	t.Helper()
	if err := e.fs.syncAll(); err != nil {
		t.Fatalf("sync: %v", err)
	}
}

// TestSharedXattrBlockIsCopiedBeforeItChanges changes the attributes of one of
// two inodes that name a shared xattr block. The changed inode moves to a
// private block and releases its name. The shared block keeps its content, its
// count falls to the number of names that remain, and the other inode still
// reads it. The oracle accepts the image with no problem at all.
func TestSharedXattrBlockIsCopiedBeforeItChanges(t *testing.T) {
	base, acl := auSharedXattrImage(t)
	orig := auBlockBytesWithoutRefcount(base, acl)

	e, fl := auMountImage(t, base.clone())
	for _, p := range []string{"/f", "/g"} {
		if got, err := auGetXattr(e, p, "user.a"); err != nil || got != "alpha" {
			t.Fatalf("user.a of %s = (%q, %v), want alpha", p, got, err)
		}
	}
	if err := auSetXattr(e, "/g", "user.b", "beta"); err != nil {
		t.Fatalf("set user.b on /g: %v", err)
	}
	e.unmount()
	final := fl.snapshot()

	if got := auRefcount(final, acl); got != 1 {
		t.Errorf("refcount of the shared block after the copy = %d, want 1", got)
	}
	if !bytes.Equal(orig, auBlockBytesWithoutRefcount(final, acl)) {
		t.Error("the shared xattr block changed beyond its refcount")
	}
	if res := auFsck(final, true); !res.OK() {
		t.Errorf("the image after the copy fails the oracle:\n%s", res)
	}

	e2, _ := auMountImage(t, final.clone())
	if names, err := auListXattr(e2, "/f"); err != nil || strings.Join(names, ",") != "user.a" {
		t.Errorf("attributes of /f after remount = (%v, %v), want user.a only", names, err)
	}
	if names, err := auListXattr(e2, "/g"); err != nil || strings.Join(names, ",") != "user.a,user.b" {
		t.Errorf("attributes of /g after remount = (%v, %v), want user.a and user.b", names, err)
	}
	if got, err := auGetXattr(e2, "/g", "user.b"); err != nil || got != "beta" {
		t.Errorf("user.b of /g after remount = (%q, %v), want beta", got, err)
	}
	e2.unmount()
}

// TestCompactionMovesASharedXattrBlockPrivately relocates one of two inodes that
// name a shared xattr block to a lower block. The other inode must keep the
// shared block with a count of one. The moved inode must read its attributes
// from a private block, and the oracle must accept the image.
func TestCompactionMovesASharedXattrBlockPrivately(t *testing.T) {
	base, acl := auSharedXattrImageWithHole(t, true)
	e, fl := auMountImage(t, base.clone())
	v := e.fs.v
	f := lookupNode(t, v, mustRoot(t, v), "f")
	v.gate.enterOp()
	f.mu.Lock()
	err := f.relocateLocked(acl)
	moved := f.fileACL
	f.mu.Unlock()
	v.gate.exit()
	if err != nil {
		t.Fatalf("relocate: %v", err)
	}
	if moved == 0 || moved >= acl {
		t.Fatalf("the xattr block of /f is at %d, want a block below %d", moved, acl)
	}
	auFlush(t, e)
	e.unmount()
	final := fl.snapshot()
	if got := auRefcount(final, acl); got != 1 {
		t.Errorf("refcount of the shared block = %d, want 1", got)
	}
	if res := auFsck(final, true); !res.OK() {
		t.Errorf("the image after the move fails the oracle:\n%s", res)
	}
	e2, _ := auMountImage(t, final.clone())
	for _, p := range []string{"/f", "/g"} {
		if got, err := auGetXattr(e2, p, "user.a"); err != nil || got != "alpha" {
			t.Errorf("user.a of %s after remount = (%q, %v), want alpha", p, got, err)
		}
	}
	e2.unmount()
}

// TestSharedXattrBlockIsFreedByItsLastName releases a shared xattr block from
// both sides, in both orders. The block stays allocated while one name remains,
// and the last release frees it. The oracle checks the count and the bitmap of
// the image after each step.
func TestSharedXattrBlockIsFreedByItsLastName(t *testing.T) {
	t.Run("copy then destroy", func(t *testing.T) {
		base, acl := auSharedXattrImage(t)
		e, fl := auMountImage(t, base.clone())
		if err := auSetXattr(e, "/f", "user.b", "beta"); err != nil {
			t.Fatalf("set user.b on /f: %v", err)
		}
		auFlush(t, e)
		afterCopy := fl.snapshot()
		if got := auRefcount(afterCopy, acl); got != 1 {
			t.Fatalf("refcount after the copy = %d, want 1", got)
		}
		// A flush does not mark the volume clean, so the strict check waits for
		// the unmount. The structural check still sees the counts.
		if res := auFsck(afterCopy, false); !res.OK() {
			t.Fatalf("the image after the copy fails the oracle:\n%s", res)
		}
		if got, err := auGetXattr(e, "/g", "user.a"); err != nil || got != "alpha" {
			t.Fatalf("user.a of /g after the copy = (%q, %v), want alpha", got, err)
		}
		if err := e.unlink("/g"); err != nil {
			t.Fatalf("unlink /g: %v", err)
		}
		e.unmount()
		final := fl.snapshot()
		if res := auFsck(final, true); !res.OK() {
			t.Errorf("the image after destroying the last name fails the oracle:\n%s", res)
		}
		if auClaimed(final, acl) {
			t.Errorf("block %d of the shared xattr block is still named after its last name went", acl)
		}
	})

	t.Run("destroy then copy", func(t *testing.T) {
		base, acl := auSharedXattrImage(t)
		e, fl := auMountImage(t, base.clone())
		if err := e.unlink("/g"); err != nil {
			t.Fatalf("unlink /g: %v", err)
		}
		auFlush(t, e)
		afterDestroy := fl.snapshot()
		if got := auRefcount(afterDestroy, acl); got != 1 {
			t.Fatalf("refcount after the destroy = %d, want 1", got)
		}
		if res := auFsck(afterDestroy, false); !res.OK() {
			t.Fatalf("the image after the destroy fails the oracle:\n%s", res)
		}
		if err := auSetXattr(e, "/f", "user.b", "beta"); err != nil {
			t.Fatalf("set user.b on /f: %v", err)
		}
		e.unmount()
		final := fl.snapshot()
		if res := auFsck(final, true); !res.OK() {
			t.Errorf("the image after the last copy fails the oracle:\n%s", res)
		}
		if auClaimed(final, acl) {
			t.Errorf("block %d of the shared xattr block is still named after its last name went", acl)
		}
		e2, _ := auMountImage(t, final.clone())
		if names, err := auListXattr(e2, "/f"); err != nil || strings.Join(names, ",") != "user.a,user.b" {
			t.Errorf("attributes of /f after remount = (%v, %v), want user.a and user.b", names, err)
		}
		e2.unmount()
	})
}

// TestInodeAttributesOutsideTheBlockSurvive gives a file and a directory the
// attributes that Linux keeps in the inode. The attributes are readable and
// listable. A change moves the changed attribute out of the inode, and the
// unchanged one keeps its place through a flush and a remount.
func TestInodeAttributesOutsideTheBlockSurvive(t *testing.T) {
	d := newAuDrv(t)
	d.create("/f", 3*blockSize)
	d.mkdir("/d")
	d.e.unmount()
	base := d.f.snapshot()
	tree := auFsck(base, true).Tree
	attrs := []auAttr{
		{index: 6, name: "selinux", value: "system_u:object_r:etc_t:s0\x00"},
		{index: 1, name: "tag", value: "keep"},
	}
	for _, p := range []string{"/f", "/d"} {
		raw := auRawInode(base, tree[p].ino)
		auPutIbody(raw, attrs)
		auWriteRawInode(base, tree[p].ino, raw)
	}
	if res := auFsck(base, true); !res.OK() {
		t.Fatalf("the image with in-inode attributes fails the oracle:\n%s", res)
	}

	e, fl := auMountImage(t, base.clone())
	for _, p := range []string{"/f", "/d"} {
		names, err := auListXattr(e, p)
		if err != nil || strings.Join(names, ",") != "security.selinux,user.tag" {
			t.Fatalf("attributes of %s = (%v, %v), want security.selinux and user.tag", p, names, err)
		}
		if got, err := auGetXattr(e, p, "user.tag"); err != nil || got != "keep" {
			t.Fatalf("user.tag of %s = (%q, %v), want keep", p, got, err)
		}
		if got, err := auGetXattr(e, p, "security.selinux"); err != nil || got != attrs[0].value {
			t.Fatalf("security.selinux of %s = (%q, %v), want its value", p, got, err)
		}
	}
	// A change moves the changed attribute to the block. The other stays.
	if err := auSetXattr(e, "/f", "user.tag", "changed"); err != nil {
		t.Fatalf("set user.tag on /f: %v", err)
	}
	if err := e.vfsObj.RemoveXattrAt(e.ctx, e.creds, e.fpop("/d"), "user.tag"); err != nil {
		t.Fatalf("remove user.tag from /d: %v", err)
	}
	if err := auSetXattr(e, "/d", "user.new", "fresh"); err != nil {
		t.Fatalf("set user.new on /d: %v", err)
	}
	e.unmount()
	final := fl.snapshot()

	if res := auFsck(final, true); !res.OK() {
		t.Fatalf("the flushed image fails the oracle:\n%s", res)
	}
	for _, p := range []string{"/f", "/d"} {
		raw := auRawInode(final, auFsck(final, true).Tree[p].ino)
		ents, err := parseIbodyXattrs(raw[ibodyOffset:])
		if err != nil {
			t.Fatalf("in-inode attributes of %s: %v", p, err)
		}
		var names []string
		for _, en := range ents {
			names = append(names, joinXattrName(en.index, en.name))
		}
		if strings.Join(names, ",") != "security.selinux" {
			t.Errorf("in-inode attributes of %s after the flush = %v, want security.selinux only", p, names)
		}
	}

	e2, _ := auMountImage(t, final.clone())
	if names, err := auListXattr(e2, "/f"); err != nil || strings.Join(names, ",") != "security.selinux,user.tag" {
		t.Errorf("attributes of /f after remount = (%v, %v)", names, err)
	}
	if got, err := auGetXattr(e2, "/f", "user.tag"); err != nil || got != "changed" {
		t.Errorf("user.tag of /f after remount = (%q, %v), want changed", got, err)
	}
	if got, err := auGetXattr(e2, "/d", "security.selinux"); err != nil || got != attrs[0].value {
		t.Errorf("security.selinux of /d after remount = (%q, %v)", got, err)
	}
	if names, err := auListXattr(e2, "/d"); err != nil || strings.Join(names, ",") != "security.selinux,user.new" {
		t.Errorf("attributes of /d after remount = (%v, %v), want security.selinux and user.new", names, err)
	}
}

// TestXattrBlockKeepsTheFourKiBCap checks that the attributes of the block stay
// within one block. The cap does not count the attributes in the inode.
func TestXattrBlockKeepsTheFourKiBCap(t *testing.T) {
	e := newEnv(t)
	e.writeFile("/f", []byte("x"))
	big := strings.Repeat("v", 3000)
	if err := auSetXattr(e, "/f", "user.one", big); err != nil {
		t.Fatalf("first 3000-byte attribute: %v", err)
	}
	if err := auSetXattr(e, "/f", "user.two", big); !errors.Is(err, linuxerr.ENOSPC) {
		t.Errorf("second 3000-byte attribute = %v, want ENOSPC", err)
	}
	if got, err := auGetXattr(e, "/f", "user.one"); err != nil || got != big {
		t.Errorf("first attribute after the refused one = (%d bytes, %v), want its 3000 bytes", len(got), err)
	}
}

// TestInlineInodeRefusesAttributeInTheInode checks that an inline file with an
// attribute in the inode fails with EUCLEAN. The inline limit leaves no room for
// the attribute, so the engine refuses it rather than losing it on a flush.
func TestInlineInodeRefusesAttributeInTheInode(t *testing.T) {
	d := newAuDrv(t)
	d.create("/i", 10)
	d.e.unmount()
	base := d.f.snapshot()
	ino := auFsck(base, true).Tree["/i"].ino
	raw := auRawInode(base, ino)
	auPutIbody(raw, []auAttr{{index: 1, name: "tag", value: "keep"}})
	auWriteRawInode(base, ino, raw)

	e, _ := auMountImage(t, base.clone())
	_, err := e.open("/i", linux.O_RDONLY, 0)
	if !errors.Is(err, linuxerr.EUCLEAN) {
		t.Errorf("open of the inline file = %v, want EUCLEAN", err)
	}
}

// TestReadBeyondTheFileSizeIsEOF reads at offsets past the end of a file. Some
// of the offsets would wrap to block 0 when the block number is 32 bits wide.
// Each read returns EOF and no byte of the file.
func TestReadBeyondTheFileSizeIsEOF(t *testing.T) {
	e := newEnv(t)
	e.writeFile("/f", pattern(9, 3*blockSize))
	st := e.mustStat("/f")
	v := e.fs.v
	n, err := v.getNode(uint32(st.Ino))
	if err != nil {
		t.Fatal(err)
	}
	defer v.putNode(n)
	for _, off := range []int64{int64(st.Size), int64(maxFileSize) + 1, int64(1) << 44} {
		buf := make([]byte, 16)
		got, err := n.readAt(buf, off)
		if got != 0 || !errors.Is(err, io.EOF) {
			t.Errorf("read at %d = (%d, %v), want (0, EOF)", off, got, err)
		}
	}
}
