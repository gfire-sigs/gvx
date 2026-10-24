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
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// newMetaEnv returns a mount whose extended attributes live in .gvx_meta on
// every host. The tests of the native store are in vfs_special_linux_test.go.
func newMetaEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	e.ws.caps.NativeXattr = false
	return e
}

func (e *env) setXattrAs(creds *auth.Credentials, p, name, value string, flags uint32) error {
	return e.vfsObj.SetXattrAt(e.ctx, creds, e.pop(p), &vfs.SetXattrOptions{Name: name, Value: value, Flags: flags})
}

func (e *env) setXattr(p, name, value string, flags uint32) error {
	return e.setXattrAs(e.creds, p, name, value, flags)
}

func (e *env) mustSetXattr(p, name, value string) {
	e.t.Helper()
	if err := e.setXattr(p, name, value, 0); err != nil {
		e.t.Fatalf("setxattr %q %q: %v", p, name, err)
	}
}

func (e *env) getXattrAs(creds *auth.Credentials, p, name string, size uint64) (string, error) {
	return e.vfsObj.GetXattrAt(e.ctx, creds, e.pop(p), &vfs.GetXattrOptions{Name: name, Size: size})
}

func (e *env) getXattr(p, name string) (string, error) {
	return e.getXattrAs(e.creds, p, name, 0)
}

func (e *env) mustGetXattr(p, name string) string {
	e.t.Helper()
	v, err := e.getXattr(p, name)
	if err != nil {
		e.t.Fatalf("getxattr %q %q: %v", p, name, err)
	}
	return v
}

func (e *env) listXattrAs(creds *auth.Credentials, p string, size uint64) ([]string, error) {
	names, err := e.vfsObj.ListXattrAt(e.ctx, creds, e.pop(p), size)
	slices.Sort(names)
	return names, err
}

func (e *env) listXattr(p string) []string {
	e.t.Helper()
	names, err := e.listXattrAs(e.creds, p, 0)
	if err != nil {
		e.t.Fatalf("listxattr %q: %v", p, err)
	}
	return names
}

func (e *env) removeXattr(p, name string) error {
	return e.vfsObj.RemoveXattrAt(e.ctx, e.creds, e.pop(p), name)
}

// userCreds returns the credentials of an unprivileged user.
func (e *env) userCreds(uid auth.KUID) *auth.Credentials {
	return auth.NewUserCredentials(uid, auth.KGID(uid), nil, nil, e.creds.UserNamespace)
}

// openWorld makes the workspace root writable for every user.
func (e *env) openWorld() {
	e.t.Helper()
	if err := e.setStat(".", linux.Statx{Mask: linux.STATX_MODE, Mode: 0o777}); err != nil {
		e.t.Fatal(err)
	}
}

func TestXattrCreateReplaceListRemove(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", []byte("data"))

	wantErrno(t, "REPLACE of a missing name", e.setXattr("f", "user.a", "1", linux.XATTR_REPLACE), linuxerr.ENODATA)
	if err := e.setXattr("f", "user.a", "1", linux.XATTR_CREATE); err != nil {
		t.Fatalf("CREATE of a new name: %v", err)
	}
	wantErrno(t, "CREATE of an existing name", e.setXattr("f", "user.a", "2", linux.XATTR_CREATE), linuxerr.EEXIST)
	if err := e.setXattr("f", "user.a", "22", linux.XATTR_REPLACE); err != nil {
		t.Fatalf("REPLACE of an existing name: %v", err)
	}
	e.mustSetXattr("f", "user.b", "")
	e.mustSetXattr("f", "trusted.t", "root")

	if got := e.mustGetXattr("f", "user.a"); got != "22" {
		t.Fatalf("getxattr user.a = %q, want 22", got)
	}
	if got := e.mustGetXattr("f", "user.b"); got != "" {
		t.Fatalf("getxattr of an empty value = %q", got)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"trusted.t", "user.a", "user.b"}) {
		t.Fatalf("listxattr = %v", got)
	}
	_, err := e.getXattrAs(e.creds, "f", "user.a", 1)
	wantErrno(t, "getxattr with a small size hint", err, linuxerr.ERANGE)
	_, err = e.listXattrAs(e.creds, "f", 3)
	wantErrno(t, "listxattr with a small size hint", err, linuxerr.ERANGE)
	if _, err := e.listXattrAs(e.creds, "f", 4096); err != nil {
		t.Fatalf("listxattr with a large size hint: %v", err)
	}

	if err := e.removeXattr("f", "user.a"); err != nil {
		t.Fatal(err)
	}
	_, err = e.getXattr("f", "user.a")
	wantErrno(t, "getxattr after remove", err, linuxerr.ENODATA)
	wantErrno(t, "remove of a missing name", e.removeXattr("f", "user.a"), linuxerr.ENODATA)
	if got := e.listXattr("f"); !slices.Equal(got, []string{"trusted.t", "user.b"}) {
		t.Fatalf("listxattr after remove = %v", got)
	}
	_, err = e.getXattr("missing", "user.a")
	wantErrno(t, "getxattr of a missing file", err, linuxerr.ENOENT)

	// The file itself is untouched.
	if got := e.readFile("f"); string(got) != "data" {
		t.Fatalf("content = %q", got)
	}
	if st := e.mustStat("f"); st.Mode&linux.S_IFMT != linux.S_IFREG {
		t.Fatalf("type = %#o, want a regular file", st.Mode&linux.S_IFMT)
	}
}

func TestXattrOnAHostFileWithoutARecord(t *testing.T) {
	e := newMetaEnv(t)
	if err := os.WriteFile(e.host("plain"), []byte("host"), 0o640); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("plain", "user.k", "v")
	if got := e.mustGetXattr("plain", "user.k"); got != "v" {
		t.Fatalf("getxattr = %q", got)
	}
	st := e.mustStat("plain")
	if st.Mode != linux.S_IFREG|0o640 || st.Size != 4 {
		t.Fatalf("stat = mode %#o size %d, want the host mode and size to survive the new record", st.Mode, st.Size)
	}
}

func TestXattrNamespaces(t *testing.T) {
	e := newMetaEnv(t)
	e.openWorld()
	alice, bob := e.userCreds(1000), e.userCreds(2000)
	fd, err := e.vfsObj.OpenAt(e.ctx, alice, e.pop("mine"), &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o644})
	if err != nil {
		t.Fatal(err)
	}
	fd.DecRef(e.ctx)

	// user.* belongs to the owner of a regular file.
	if err := e.setXattrAs(alice, "mine", "user.note", "hi", 0); err != nil {
		t.Fatalf("owner sets user.note: %v", err)
	}
	wantErrno(t, "write of user.* by another user", e.setXattrAs(bob, "mine", "user.note", "no", 0), linuxerr.EACCES)
	if got, err := e.getXattrAs(bob, "mine", "user.note", 0); err != nil || got != "hi" {
		t.Fatalf("read of user.* by another user with read permission = (%q, %v)", got, err)
	}

	// trusted.* needs CAP_SYS_ADMIN.
	wantErrno(t, "write of trusted.* by a user", e.setXattrAs(alice, "mine", "trusted.x", "1", 0), linuxerr.EPERM)
	_, err = e.getXattrAs(alice, "mine", "trusted.x", 0)
	wantErrno(t, "read of trusted.* by a user", err, linuxerr.ENODATA)
	if err := e.setXattrAs(e.creds, "mine", "trusted.x", "1", 0); err != nil {
		t.Fatalf("root sets trusted.x: %v", err)
	}
	if got, err := e.getXattrAs(e.creds, "mine", "trusted.x", 0); err != nil || got != "1" {
		t.Fatalf("root reads trusted.x = (%q, %v)", got, err)
	}
	_, err = e.getXattrAs(alice, "mine", "trusted.x", 0)
	wantErrno(t, "read of an existing trusted.* by a user", err, linuxerr.ENODATA)
	if names, err := e.listXattrAs(alice, "mine", 0); err != nil || !slices.Equal(names, []string{"user.note"}) {
		t.Fatalf("a user lists %v (%v), want trusted.x hidden", names, err)
	}
	if names, err := e.listXattrAs(e.creds, "mine", 0); err != nil || !slices.Equal(names, []string{"trusted.x", "user.note"}) {
		t.Fatalf("root lists %v (%v), want both names", names, err)
	}

	// security.* is read-only, except security.capability.
	wantErrno(t, "write of security.selinux", e.setXattr("mine", "security.selinux", "ctx", 0), linuxerr.EOPNOTSUPP)
	_, err = e.getXattr("mine", "security.selinux")
	wantErrno(t, "read of an unset security.selinux", err, linuxerr.ENODATA)

	// system.* and unknown namespaces are not supported.
	wantErrno(t, "write of system.posix_acl_access", e.setXattr("mine", "system.posix_acl_access", "x", 0), linuxerr.EOPNOTSUPP)
	_, err = e.getXattr("mine", "system.posix_acl_access")
	wantErrno(t, "read of system.posix_acl_access", err, linuxerr.EOPNOTSUPP)
	wantErrno(t, "write of a name without a namespace", e.setXattr("mine", "plain", "x", 0), linuxerr.EOPNOTSUPP)
}

func TestXattrOnEveryFileType(t *testing.T) {
	e := newMetaEnv(t)
	e.openWorld()
	alice := e.userCreds(1000)
	e.mustMkdir("dir")
	e.mustMknod("fifo", linux.S_IFIFO|0o666)
	e.mustMknod("sock", linux.S_IFSOCK|0o666)
	if err := e.mknod("dev", linux.S_IFCHR|0o666, 1, 3, nil); err != nil {
		t.Fatal(err)
	}
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link"), "dir"); err != nil {
		t.Fatal(err)
	}

	// Directories carry user.* attributes.
	if err := e.setXattrAs(e.creds, "dir", "user.d", "dv", 0); err != nil {
		t.Fatalf("user.* on a directory: %v", err)
	}
	if got := e.mustGetXattr("dir", "user.d"); got != "dv" {
		t.Fatalf("directory attribute = %q", got)
	}

	// Other types carry no user.* attributes but keep trusted.* and security.capability space.
	for _, p := range []string{"fifo", "sock", "dev", "link"} {
		wantErrno(t, "user.* on "+p, e.setXattrAs(alice, p, "user.x", "1", 0), linuxerr.EPERM)
		_, err := e.getXattrAs(alice, p, "user.x", 0)
		wantErrno(t, "read of user.* on "+p, err, linuxerr.ENODATA)
		if err := e.setXattr(p, "trusted.k", "kv", 0); err != nil {
			t.Fatalf("trusted.k on %s: %v", p, err)
		}
		if got := e.mustGetXattr(p, "trusted.k"); got != "kv" {
			t.Fatalf("trusted.k on %s = %q", p, got)
		}
		if got := e.listXattr(p); !slices.Equal(got, []string{"trusted.k"}) {
			t.Fatalf("listxattr of %s = %v", p, got)
		}
	}
	// The symlink keeps its target and type.
	if st, err := e.lstat("link"); err != nil || st.Mode&linux.S_IFMT != linux.S_IFLNK {
		t.Fatalf("lstat link = (%#o, %v), want a symlink", st.Mode, err)
	}
	if got, err := e.vfsObj.ReadlinkAt(e.ctx, e.creds, e.pop("link")); err != nil || got != "dir" {
		t.Fatalf("readlink = (%q, %v)", got, err)
	}
	for p, want := range map[string]uint32{"fifo": linux.S_IFIFO, "sock": linux.S_IFSOCK, "dev": linux.S_IFCHR} {
		if st := e.mustStat(p); uint32(st.Mode)&linux.S_IFMT != want {
			t.Fatalf("type of %s = %#o after setxattr, want %#o", p, st.Mode&linux.S_IFMT, want)
		}
	}
	if st := e.mustStat("dev"); st.RdevMajor != 1 || st.RdevMinor != 3 {
		t.Fatalf("rdev of dev = %d:%d after setxattr, want 1:3", st.RdevMajor, st.RdevMinor)
	}
}

func TestXattrSizeCapPerInode(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("a", nil)
	e.writeFile("b", nil)

	// "user.a" has 6 bytes, so 4090 bytes of value fill the cap exactly.
	e.mustSetXattr("a", "user.a", strings.Repeat("x", maxXattrBytes-len("user.a")))
	wantErrno(t, "replace above the cap", e.setXattr("a", "user.a", strings.Repeat("x", maxXattrBytes-len("user.a")+1), 0), linuxerr.ENOSPC)
	if got := e.mustGetXattr("a", "user.a"); len(got) != maxXattrBytes-len("user.a") {
		t.Fatalf("a refused replace changed the value to %d bytes", len(got))
	}
	wantErrno(t, "another name at the cap", e.setXattr("a", "user.b", "", 0), linuxerr.ENOSPC)

	// The cap counts names and values of all attributes of one inode.
	e.mustSetXattr("b", "user.one", strings.Repeat("y", 2000))
	e.mustSetXattr("b", "user.two", strings.Repeat("y", 2000))
	wantErrno(t, "third attribute above the cap", e.setXattr("b", "user.three", strings.Repeat("y", 200), 0), linuxerr.ENOSPC)
	// A smaller replace and a remove both make room.
	e.mustSetXattr("b", "user.one", "short")
	e.mustSetXattr("b", "user.three", strings.Repeat("y", 200))
	if err := e.removeXattr("b", "user.two"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("b", "user.four", strings.Repeat("y", 1500))

	// A single value above 64 KiB is too big, before any cap applies.
	wantErrno(t, "value above XATTR_SIZE_MAX", e.setXattr("b", "user.big", strings.Repeat("z", linux.XATTR_SIZE_MAX+1), 0), linuxerr.E2BIG)
}

func TestXattrMapsAreCopiedOnChange(t *testing.T) {
	cur := map[string][]byte{"user.a": []byte("1")}
	next, err := setXattrMap(cur, "user.b", []byte("2"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur) != 1 || len(next) != 2 {
		t.Fatalf("setXattrMap changed its input: cur %v next %v", cur, next)
	}
	value := []byte("3")
	next2, err := setXattrMap(next, "user.c", value, 0)
	if err != nil {
		t.Fatal(err)
	}
	value[0] = 'X'
	if string(next2["user.c"]) != "3" {
		t.Fatalf("setXattrMap kept the caller buffer: %q", next2["user.c"])
	}
	gone, err := removeXattrMap(next2, "user.a")
	if err != nil || len(next2) != 3 || len(gone) != 2 {
		t.Fatalf("removeXattrMap = (%v, %v), input %v", gone, err, next2)
	}
	if last, err := removeXattrMap(map[string][]byte{"user.a": nil}, "user.a"); err != nil || last != nil {
		t.Fatalf("removal of the last name = (%v, %v), want a nil map", last, err)
	}
	if _, err := removeXattrMap(cur, "user.zz"); !linuxerr.Equals(linuxerr.ENODATA, err) {
		t.Fatalf("removal of a missing name = %v, want ENODATA", err)
	}
}

func TestXattrHardLinksShareAttributes(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("a", []byte("x"))
	e.mustSetXattr("a", "user.first", "1")
	if err := e.link("a", "b"); err != nil {
		t.Fatal(err)
	}
	// A new link starts with the attributes of the file.
	if got := e.mustGetXattr("b", "user.first"); got != "1" {
		t.Fatalf("attribute through the new link = %q", got)
	}
	// A change through either name shows through the other.
	e.mustSetXattr("b", "user.second", "2")
	if got := e.mustGetXattr("a", "user.second"); got != "2" {
		t.Fatalf("attribute set through b, read through a = %q", got)
	}
	e.mustSetXattr("a", "user.first", "changed")
	if got := e.mustGetXattr("b", "user.first"); got != "changed" {
		t.Fatalf("attribute replaced through a, read through b = %q", got)
	}
	if err := e.removeXattr("b", "user.second"); err != nil {
		t.Fatal(err)
	}
	_, err := e.getXattr("a", "user.second")
	wantErrno(t, "attribute removed through b, read through a", err, linuxerr.ENODATA)
	if got := e.listXattr("a"); !slices.Equal(got, e.listXattr("b")) {
		t.Fatalf("listxattr a = %v, b = %v, want equal", got, e.listXattr("b"))
	}
	// A third name joins the set, and the table holds one map for each name.
	if err := e.link("b", "c"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("c", "user.third", "3")
	for _, p := range []string{"a", "b", "c"} {
		if got := e.listXattr(p); !slices.Equal(got, []string{"user.first", "user.third"}) {
			t.Fatalf("listxattr %s = %v", p, got)
		}
	}

	// unlink, rename, and a later link keep the attributes consistent.
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	if err := e.rename("b", "renamed"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustGetXattr("renamed", "user.third"); got != "3" {
		t.Fatalf("attribute after unlink and rename = %q", got)
	}
	e.mustSetXattr("c", "user.after", "4")
	if got := e.mustGetXattr("renamed", "user.after"); got != "4" {
		t.Fatalf("attribute through the renamed link = %q", got)
	}
	e.ws.mu.RLock()
	_, goneRecord := e.ws.meta["a"]
	_, movedRecord := e.ws.meta["renamed"]
	e.ws.mu.RUnlock()
	if goneRecord || !movedRecord {
		t.Fatalf("records after unlink and rename: a=%v renamed=%v, want a gone and renamed present", goneRecord, movedRecord)
	}
}

func TestXattrHardLinkedFIFOSharesAttributes(t *testing.T) {
	e := newMetaEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.link("fifo", "fifo2"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("fifo2", "trusted.k", "v")
	if got := e.mustGetXattr("fifo", "trusted.k"); got != "v" {
		t.Fatalf("attribute through the other name = %q", got)
	}
	if st := e.mustStat("fifo2"); st.Mode&linux.S_IFMT != linux.S_IFIFO || st.Nlink != 2 {
		t.Fatalf("stat = type %#o nlink %d, want a FIFO with 2 links", st.Mode&linux.S_IFMT, st.Nlink)
	}
}

func TestXattrFollowsRenameAndUnlink(t *testing.T) {
	e := newMetaEnv(t)
	e.mustMkdir("d")
	e.writeFile("d/f", []byte("x"))
	e.mustSetXattr("d/f", "user.k", "v")
	e.mustSetXattr("d", "user.dir", "dv")
	if err := e.rename("d", "moved"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustGetXattr("moved/f", "user.k"); got != "v" {
		t.Fatalf("file attribute after a directory rename = %q", got)
	}
	if got := e.mustGetXattr("moved", "user.dir"); got != "dv" {
		t.Fatalf("directory attribute after a rename = %q", got)
	}
	_, err := e.getXattr("d", "user.dir")
	wantErrno(t, "attribute at the old directory name", err, linuxerr.ENOENT)

	// A rename over a file with attributes replaces them.
	e.writeFile("target", []byte("t"))
	e.mustSetXattr("target", "user.old", "o")
	if err := e.rename("moved/f", "target"); err != nil {
		t.Fatal(err)
	}
	if got := e.listXattr("target"); !slices.Equal(got, []string{"user.k"}) {
		t.Fatalf("attributes after a rename over a file = %v, want only those of the moved file", got)
	}

	// A removed file leaves no attributes for a new file of the same name.
	if err := e.unlink("target"); err != nil {
		t.Fatal(err)
	}
	e.writeFile("target", nil)
	if got := e.listXattr("target"); len(got) != 0 {
		t.Fatalf("a new file starts with attributes %v", got)
	}
	e.ws.mu.RLock()
	rec := e.ws.meta["target"]
	e.ws.mu.RUnlock()
	if len(rec.Xattrs) != 0 {
		t.Fatalf("the record of a new file holds attributes %v", rec.Xattrs)
	}
}

func TestXattrPersistAcrossReopen(t *testing.T) {
	dir := resolvedTempDir(t)
	e, closeEnv := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	e.ws.caps.NativeXattr = false
	e.writeFile("file", []byte("x"))
	e.mustMkdir("dir")
	e.mustMknod("fifo", linux.S_IFIFO|0o600)
	if err := e.vfsObj.SymlinkAt(e.ctx, e.creds, e.pop("link"), "file"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("file", "user.f", "file value")
	e.mustSetXattr("dir", "user.d", "dir value")
	e.mustSetXattr("fifo", "trusted.p", "fifo value")
	e.mustSetXattr("link", "trusted.l", "link value\x00with a NUL")
	e.mustSetXattr("file", "trusted.t", "second")
	closeEnv()

	e2, _ := openEnvAt(t, dir, workspaceOptions{coalesce: defaultCoalesceWindow})
	e2.ws.caps.NativeXattr = false
	for _, tc := range []struct{ path, name, want string }{
		{"file", "user.f", "file value"},
		{"file", "trusted.t", "second"},
		{"dir", "user.d", "dir value"},
		{"fifo", "trusted.p", "fifo value"},
		{"link", "trusted.l", "link value\x00with a NUL"},
	} {
		if got, err := e2.getXattr(tc.path, tc.name); err != nil || got != tc.want {
			t.Errorf("getxattr %s %s after reopen = (%q, %v), want %q", tc.path, tc.name, got, err, tc.want)
		}
	}
	if got := e2.listXattr("file"); !slices.Equal(got, []string{"trusted.t", "user.f"}) {
		t.Errorf("listxattr after reopen = %v", got)
	}
	if st := e2.mustStat("fifo"); st.Mode&linux.S_IFMT != linux.S_IFIFO {
		t.Errorf("type of the FIFO after reopen = %#o", st.Mode&linux.S_IFMT)
	}
}

func TestXattrThroughFileDescriptors(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", []byte("data"))
	e.mustMkdir("d")

	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v1"}); err != nil {
		t.Fatalf("fsetxattr: %v", err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v1" {
		t.Fatalf("fgetxattr = (%q, %v)", got, err)
	}
	if got := e.mustGetXattr("f", "user.fd"); got != "v1" {
		t.Fatalf("path getxattr after fsetxattr = %q", got)
	}
	if names, err := fd.ListXattr(e.ctx, 0); err != nil || !slices.Equal(names, []string{"user.fd"}) {
		t.Fatalf("flistxattr = (%v, %v)", names, err)
	}

	dfd := e.mustOpen("d", linux.O_RDONLY|linux.O_DIRECTORY)
	defer dfd.DecRef(e.ctx)
	if err := dfd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.dirfd", Value: "dv"}); err != nil {
		t.Fatalf("fsetxattr on a directory: %v", err)
	}
	if got := e.mustGetXattr("d", "user.dirfd"); got != "dv" {
		t.Fatalf("directory attribute = %q", got)
	}
	if err := dfd.RemoveXattr(e.ctx, "user.dirfd"); err != nil {
		t.Fatalf("fremovexattr on a directory: %v", err)
	}

	// An unlinked file with an open descriptor keeps working attributes.
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v1" {
		t.Fatalf("fgetxattr on an unlinked file = (%q, %v)", got, err)
	}
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v2"}); err != nil {
		t.Fatalf("fsetxattr on an unlinked file: %v", err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v2" {
		t.Fatalf("fgetxattr after the change = (%q, %v)", got, err)
	}
	if err := fd.RemoveXattr(e.ctx, "user.fd"); err != nil {
		t.Fatalf("fremovexattr on an unlinked file: %v", err)
	}
	e.ws.mu.RLock()
	_, ok := e.ws.meta["f"]
	e.ws.mu.RUnlock()
	if ok {
		t.Fatalf("an xattr call on an unlinked file created a record for its old name")
	}
}

func TestXattrOnAReadOnlyWorkspace(t *testing.T) {
	dir := resolvedTempDir(t)
	if err := os.WriteFile(dir+"/f", []byte("ro"), 0o644); err != nil {
		t.Fatal(err)
	}
	ws, err := OpenWorkspace(dir, true)
	if err != nil {
		t.Fatal(err)
	}
	e := mountEnv(t, ws, dir)
	t.Cleanup(func() {
		e.root.DecRef(e.ctx)
		_ = ws.Close()
	})
	wantErrno(t, "setxattr on a read-only workspace", e.setXattr("f", "user.k", "v", 0), linuxerr.EROFS)
	wantErrno(t, "removexattr on a read-only workspace", e.removeXattr("f", "user.k"), linuxerr.EROFS)
	_, err = e.getXattr("f", "user.k")
	wantErrno(t, "getxattr on a read-only workspace", err, linuxerr.ENODATA)
	if got := e.listXattr("f"); len(got) != 0 {
		t.Fatalf("listxattr = %v", got)
	}
}

func TestXattrMetaTableHoldsTheValues(t *testing.T) {
	e := newMetaEnv(t)
	e.writeFile("f", nil)
	e.mustSetXattr("f", "user.k", "v")
	e.ws.mu.RLock()
	got := maps.Clone(e.ws.meta["f"].Xattrs)
	e.ws.mu.RUnlock()
	if len(got) != 1 || string(got["user.k"]) != "v" {
		t.Fatalf("the record holds %v, want user.k=v", got)
	}
	if err := e.ws.Sync(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(e.host(MetaFileName))
	if err != nil || !strings.Contains(string(raw), `"user.k"`) {
		t.Fatalf(".gvx_meta = (%q, %v), want it to hold user.k", raw, err)
	}
}
