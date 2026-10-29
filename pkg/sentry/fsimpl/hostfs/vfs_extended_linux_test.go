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
	"slices"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/third_party/x_sys/unix"
)

// hostVolumeOf reads the volume of dir the way the host backend does.
func hostVolumeOf(t *testing.T, dir string) hostVolume {
	t.Helper()
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		t.Fatal(err)
	}
	unit := uint64(st.Frsize)
	if unit == 0 {
		unit = uint64(st.Bsize)
	}
	return hostVolume{blockSize: unit, blocks: st.Blocks, free: st.Bfree, avail: st.Bavail, files: st.Files, filesFree: st.Ffree}
}

// TestTmpfileWithExclHoldsNoHostNameOnLinux checks the native O_TMPFILE
// path. The volume of the test may refuse O_TMPFILE. The fallback removes
// the name at once, so the host directory is empty in both cases.
func TestTmpfileWithExclHoldsNoHostNameOnLinux(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR|linux.O_EXCL)
	defer fd.DecRef(e.ctx)
	e.pwriteAt(fd, 0, "anonymous")
	if got := e.hostEntries("."); len(got) != 0 {
		t.Fatalf("host entries while an O_EXCL temporary file is open = %v, want none", got)
	}
	// The host kernel agrees that no name reaches the file.
	h := fd.Impl().(*regularFD).h
	info, err := h.fstat(e.ws.host)
	if err != nil {
		t.Fatal(err)
	}
	if info.nlink != 0 {
		t.Fatalf("host link count of an O_EXCL temporary file = %d, want 0", info.nlink)
	}
	if got := e.pread(fd, 0, 9); string(got) != "anonymous" {
		t.Fatalf("read back = %q", got)
	}
}

// TestTmpfileWithoutExclUsesAHiddenHostNameOnLinux shows the other path: a
// file that the guest may link keeps a hidden host name, because the seccomp
// rule of the host filesystem refuses linkat with AT_EMPTY_PATH.
func TestTmpfileWithoutExclUsesAHiddenHostNameOnLinux(t *testing.T) {
	e := newEnv(t)
	fd := e.mustOpenTmp(".", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	got := e.hostEntries(".")
	if len(got) != 1 || !isEphemeralName(got[0]) {
		t.Fatalf("host entries = %v, want one hidden internal name", got)
	}
}

// newNativeEnv mounts a workspace whose host supports user extended
// attributes. A host without them, such as an older tmpfs, skips the test: the
// capability probe clears NativeXattr there.
func newNativeEnv(t *testing.T) *env {
	t.Helper()
	e := newEnv(t)
	if !e.ws.caps.NativeXattr {
		t.Skip("the host file system of the test directory has no user extended attributes")
	}
	return e
}

func hostGetXattr(path, name string) (string, error) {
	buf := make([]byte, 1<<16)
	n, err := unix.Getxattr(path, name, buf)
	if err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

func (e *env) metaXattrs(rel string) map[string][]byte {
	e.ws.mu.RLock()
	defer e.ws.mu.RUnlock()
	return e.ws.meta[rel].Xattrs
}

func TestNativeXattrStoresUserAttributesOnTheHost(t *testing.T) {
	e := newNativeEnv(t)
	e.writeFile("f", []byte("data"))

	wantErrno(t, "REPLACE of a missing name", e.setXattr("f", "user.a", "1", linux.XATTR_REPLACE), linuxerr.ENODATA)
	if err := e.setXattr("f", "user.a", "1", linux.XATTR_CREATE); err != nil {
		t.Fatalf("CREATE: %v", err)
	}
	wantErrno(t, "CREATE of an existing name", e.setXattr("f", "user.a", "2", linux.XATTR_CREATE), linuxerr.EEXIST)
	e.mustSetXattr("f", "user.b", "")
	e.mustSetXattr("f", "user.a", "replaced")

	if got, err := hostGetXattr(e.host("f"), "user.a"); err != nil || got != "replaced" {
		t.Fatalf("host xattr user.a = (%q, %v), want the guest value", got, err)
	}
	if got, err := hostGetXattr(e.host("f"), "user.b"); err != nil || got != "" {
		t.Fatalf("host xattr user.b = (%q, %v), want an empty value", got, err)
	}
	if got := e.metaXattrs("f"); len(got) != 0 {
		t.Fatalf(".gvx_meta holds %v, want the host to hold user.* attributes", got)
	}
	if got := e.mustGetXattr("f", "user.a"); got != "replaced" {
		t.Fatalf("getxattr = %q", got)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"user.a", "user.b"}) {
		t.Fatalf("listxattr = %v", got)
	}
	_, err := e.getXattrAs(e.creds, "f", "user.a", 1)
	wantErrno(t, "getxattr with a small size hint", err, linuxerr.ERANGE)
	if err := e.removeXattr("f", "user.a"); err != nil {
		t.Fatal(err)
	}
	if _, err := hostGetXattr(e.host("f"), "user.a"); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("host xattr after the guest removed it: %v, want ENODATA", err)
	}
	_, err = e.getXattr("f", "user.a")
	wantErrno(t, "getxattr after remove", err, linuxerr.ENODATA)
	wantErrno(t, "remove of a missing name", e.removeXattr("f", "user.a"), linuxerr.ENODATA)
}

func TestNativeXattrOnDirectoriesAndHardLinks(t *testing.T) {
	e := newNativeEnv(t)
	e.mustMkdir("d")
	e.mustSetXattr("d", "user.dir", "dv")
	e.mustSetXattr(".", "user.root", "rv")
	if got, err := hostGetXattr(e.host("d"), "user.dir"); err != nil || got != "dv" {
		t.Fatalf("host xattr of a directory = (%q, %v)", got, err)
	}
	if got, err := hostGetXattr(e.dir, "user.root"); err != nil || got != "rv" {
		t.Fatalf("host xattr of the workspace root = (%q, %v)", got, err)
	}

	e.writeFile("a", []byte("x"))
	if err := e.link("a", "b"); err != nil {
		t.Fatal(err)
	}
	e.mustSetXattr("a", "user.shared", "s1")
	if got := e.mustGetXattr("b", "user.shared"); got != "s1" {
		t.Fatalf("attribute through the other link = %q", got)
	}
	if got, err := hostGetXattr(e.host("b"), "user.shared"); err != nil || got != "s1" {
		t.Fatalf("host xattr through the other link = (%q, %v)", got, err)
	}
	if err := e.unlink("a"); err != nil {
		t.Fatal(err)
	}
	if got := e.mustGetXattr("b", "user.shared"); got != "s1" {
		t.Fatalf("attribute after the other link went away = %q", got)
	}
	if got := e.metaXattrs("b"); len(got) != 0 {
		t.Fatalf(".gvx_meta holds %v for a natively stored attribute", got)
	}
}

func TestNativeXattrKeepsTrustedAndSecurityInTheMetaStore(t *testing.T) {
	e := newNativeEnv(t)
	e.writeFile("f", nil)
	// Root holds CAP_SYS_ADMIN in the guest. The host must never receive an
	// attribute that its kernel could honor.
	e.mustSetXattr("f", "trusted.t", "tv")
	e.mustSetXattr("f", "user.u", "uv")
	if _, err := hostGetXattr(e.host("f"), "trusted.t"); err == nil {
		t.Fatalf("trusted.t reached the host file")
	}
	if got := e.metaXattrs("f"); len(got) != 1 || string(got["trusted.t"]) != "tv" {
		t.Fatalf(".gvx_meta holds %v, want trusted.t only", got)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"trusted.t", "user.u"}) {
		t.Fatalf("listxattr = %v, want both stores", got)
	}
	if err := e.removeXattr("f", "trusted.t"); err != nil {
		t.Fatal(err)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"user.u"}) {
		t.Fatalf("listxattr after removing trusted.t = %v", got)
	}
}

func TestNativeXattrShowsHostAttributesToTheGuest(t *testing.T) {
	e := newNativeEnv(t)
	e.writeFile("f", nil)
	if err := unix.Setxattr(e.host("f"), "user.fromhost", []byte("hv"), 0); err != nil {
		t.Skipf("the test directory refuses user xattrs: %v", err)
	}
	// Host attributes outside user.* stay hidden from the guest.
	_ = unix.Setxattr(e.host("f"), "security.gvx.hidden", []byte("x"), 0)
	if got := e.mustGetXattr("f", "user.fromhost"); got != "hv" {
		t.Fatalf("getxattr of a host attribute = %q", got)
	}
	for _, name := range e.listXattr("f") {
		if name != "user.fromhost" {
			t.Fatalf("listxattr = %v, want only the host user.* attribute", e.listXattr("f"))
		}
	}
	// A name that the meta store holds wins and stays in the meta store.
	e.ws.caps.NativeXattr = false
	e.mustSetXattr("f", "user.inmeta", "mv")
	e.ws.caps.NativeXattr = true
	e.mustSetXattr("f", "user.inmeta", "mv2")
	if got := e.mustGetXattr("f", "user.inmeta"); got != "mv2" {
		t.Fatalf("getxattr = %q", got)
	}
	if _, err := hostGetXattr(e.host("f"), "user.inmeta"); err == nil {
		t.Fatalf("an attribute of the meta store moved to the host file")
	}
	if got := e.metaXattrs("f"); string(got["user.inmeta"]) != "mv2" {
		t.Fatalf(".gvx_meta holds %v, want the new value", got)
	}
	if err := e.removeXattr("f", "user.inmeta"); err != nil {
		t.Fatal(err)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"user.fromhost"}) {
		t.Fatalf("listxattr after removing the meta attribute = %v", got)
	}
}

// refusingHost opens regular files for reading on /dev/null. The kernel
// refuses user.* attributes on a character device with EPERM, as the lockdown
// filter refuses a call that the allowlist lacks.
type refusingHost struct{ hostBackend }

func (h refusingHost) openChildAt(dir hostDirHandle, name string, flags int, perm os.FileMode) (*os.File, error) {
	if flags == os.O_RDONLY {
		return os.Open("/dev/null")
	}
	return h.hostBackend.openChildAt(dir, name, flags, perm)
}

func TestNativeXattrFallsBackToTheMetaStoreWhenTheHostRefuses(t *testing.T) {
	e := newEnvOpts(t, workspaceOptions{
		coalesce: defaultCoalesceWindow,
		wrapHost: func(b hostBackend) hostBackend { return refusingHost{b} },
	})
	if !e.ws.caps.NativeXattr {
		t.Skip("the host file system of the test directory has no user extended attributes")
	}
	e.writeFile("f", []byte("data"))
	e.mustSetXattr("f", "user.k", "v")
	if got := e.mustGetXattr("f", "user.k"); got != "v" {
		t.Fatalf("getxattr = %q", got)
	}
	if got := e.metaXattrs("f"); string(got["user.k"]) != "v" {
		t.Fatalf(".gvx_meta holds %v, want the attribute that the host refused", got)
	}
	if got := e.listXattr("f"); !slices.Equal(got, []string{"user.k"}) {
		t.Fatalf("listxattr = %v", got)
	}
	if err := e.removeXattr("f", "user.k"); err != nil {
		t.Fatal(err)
	}
	_, err := e.getXattr("f", "user.k")
	wantErrno(t, "getxattr after remove", err, linuxerr.ENODATA)
	// The meta store enforces its size cap for these attributes.
	wantErrno(t, "attribute above the meta store cap", e.setXattr("f", "user.big", string(make([]byte, maxXattrBytes)), 0), linuxerr.ENOSPC)
}

func TestNativeXattrThroughFileDescriptors(t *testing.T) {
	e := newNativeEnv(t)
	e.writeFile("f", []byte("data"))
	fd := e.mustOpen("f", linux.O_RDWR)
	defer fd.DecRef(e.ctx)
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v1"}); err != nil {
		t.Fatalf("fsetxattr: %v", err)
	}
	if got, err := hostGetXattr(e.host("f"), "user.fd"); err != nil || got != "v1" {
		t.Fatalf("host xattr after fsetxattr = (%q, %v)", got, err)
	}
	// The open descriptor reaches the attributes of an unlinked file.
	if err := e.unlink("f"); err != nil {
		t.Fatal(err)
	}
	if got, err := fd.GetXattr(e.ctx, &vfs.GetXattrOptions{Name: "user.fd"}); err != nil || got != "v1" {
		t.Fatalf("fgetxattr on an unlinked file = (%q, %v)", got, err)
	}
	if err := fd.SetXattr(e.ctx, &vfs.SetXattrOptions{Name: "user.fd", Value: "v2"}); err != nil {
		t.Fatalf("fsetxattr on an unlinked file: %v", err)
	}
	if names, err := fd.ListXattr(e.ctx, 0); err != nil || !slices.Equal(names, []string{"user.fd"}) {
		t.Fatalf("flistxattr on an unlinked file = (%v, %v)", names, err)
	}
	if err := fd.RemoveXattr(e.ctx, "user.fd"); err != nil {
		t.Fatalf("fremovexattr on an unlinked file: %v", err)
	}
	if names, err := fd.ListXattr(e.ctx, 0); err != nil || len(names) != 0 {
		t.Fatalf("flistxattr after the removal = (%v, %v)", names, err)
	}
}

func TestNativeXattrSkipsSpecialNodes(t *testing.T) {
	e := newNativeEnv(t)
	e.mustMknod("fifo", linux.S_IFIFO|0o666)
	e.mustMknod("sock", linux.S_IFSOCK|0o666)
	for _, p := range []string{"fifo", "sock"} {
		wantErrno(t, "user.* on "+p, e.setXattrAs(e.userCreds(1000), p, "user.x", "1", 0), linuxerr.EPERM)
		e.mustSetXattr(p, "trusted.k", "v")
		if _, err := hostGetXattr(e.host(p), "trusted.k"); err == nil {
			t.Fatalf("an attribute of %s reached its host placeholder", p)
		}
		if got := e.metaXattrs(p); string(got["trusted.k"]) != "v" {
			t.Fatalf(".gvx_meta holds %v for %s", got, p)
		}
	}
}

func TestHostWatcherSuppressesEchoOfNativeXattrChanges(t *testing.T) {
	w := newWatchEnv(t)
	if !w.ws.caps.NativeXattr {
		t.Skip("the host file system of the test directory has no user extended attributes")
	}
	w.mustMkdir("d")
	w.add("d", hostEventMask)
	w.writeFile("d/seed", []byte("seed"))
	w.add("d/seed", hostEventMask)
	w.mustMkdir("d/sub")
	w.settle()
	hw := &w.ws.watch

	// The bridge is live: a host change reaches the guest.
	hostWrite(t, w.host("d/probe"), "p")
	w.sync()
	w.expect("probe", "CREATE probe")
	w.settle()
	base := hw.delivered.Load()

	step := func(what string, op func()) {
		t.Helper()
		op()
		w.drain()
		w.sync()
		w.expectNone("echo of " + what)
		if got := hw.delivered.Load(); got != base {
			t.Fatalf("%s: the watcher delivered %d notifications for a guest mutation", what, got-base)
		}
	}
	step("setxattr on a watched file", func() { w.mustSetXattr("d/seed", "user.guest", "g") })
	step("setxattr on a file in a watched directory", func() {
		w.writeFile("d/other", nil)
		w.drain()
		w.sync()
		w.mustSetXattr("d/other", "user.guest", "g")
	})
	step("removexattr on a watched file", func() {
		if err := w.removeXattr("d/seed", "user.guest"); err != nil {
			t.Fatal(err)
		}
	})
	step("setxattr on a watched directory", func() { w.mustSetXattr("d", "user.guest", "g") })
	step("setxattr on a subdirectory of a watched directory", func() { w.mustSetXattr("d/sub", "user.guest", "g") })
	step("fsetxattr through a descriptor", func() {
		fd := w.mustOpen("d/seed", linux.O_RDWR)
		defer fd.DecRef(w.env.ctx)
		if err := fd.SetXattr(w.env.ctx, &vfs.SetXattrOptions{Name: "user.viafd", Value: "x"}); err != nil {
			t.Fatal(err)
		}
	})
}
