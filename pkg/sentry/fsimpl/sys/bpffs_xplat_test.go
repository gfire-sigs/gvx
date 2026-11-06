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

package sys_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const bpfFSMagic = 0xcafe4a11

type fixedClock struct{}

func (fixedClock) Now() ktime.Time                     { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedClock) NewTimer(ktime.Listener) ktime.Timer { panic("fixedClock has no timers") }

// sysfsEnv is a sysfs mount namespace with the bpffs type registered, driven
// through the VFS the way the guest kernel drives it.
type sysfsEnv struct {
	t     *testing.T
	ctx   gvcontext.Context
	creds *auth.Credentials
	vfs   *vfs.VirtualFilesystem
	root  vfs.VirtualDentry
}

func newSysfsEnv(t *testing.T) *sysfsEnv {
	t.Helper()
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	ctx := gvcontext.WithValues(gvcontext.Background(), map[any]any{
		kernel.CtxKernel:          &kernel.Kernel{},
		ktime.CtxRealtimeClock:    fixedClock{},
		auth.CtxCredentials:       creds,
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
	v := &vfs.VirtualFilesystem{}
	if err := v.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	v.MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	v.MustRegisterFilesystemType(sys.BPFName, sys.BPFFilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true, AllowUserList: true})
	mntns, err := v.NewMountNamespace(ctx, creds, "", sys.Name, &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(sysfs): %v", err)
	}
	e := &sysfsEnv{t: t, ctx: vfs.WithMountNamespace(ctx, mntns), creds: creds, vfs: v, root: mntns.Root(ctx)}
	t.Cleanup(func() {
		e.root.DecRef(ctx)
		mntns.DecRef(ctx)
	})
	return e
}

func (e *sysfsEnv) pop(path string) *vfs.PathOperation {
	return &vfs.PathOperation{Root: e.root, Start: e.root, Path: fspath.Parse(path)}
}

func (e *sysfsEnv) stat(path string) (linux.Statx, error) {
	return e.vfs.StatAt(e.ctx, e.creds, e.pop(path), &vfs.StatOptions{Mask: linux.STATX_BASIC_STATS})
}

func (e *sysfsEnv) mkdir(path string) error {
	return e.vfs.MkdirAt(e.ctx, e.creds, e.pop(path), &vfs.MkdirOptions{Mode: 0755})
}

func (e *sysfsEnv) mountBPF(path string) error {
	_, err := e.vfs.MountAt(e.ctx, e.creds, "bpffs", e.pop(path), sys.BPFName, &vfs.MountOptions{})
	return err
}

func (e *sysfsEnv) statfsMagic(path string) uint64 {
	e.t.Helper()
	st, err := e.vfs.StatFSAt(e.ctx, e.creds, e.pop(path))
	if err != nil {
		e.t.Fatalf("statfs %s: %v", path, err)
	}
	return st.Type
}

func requireErrno(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Errorf("%s = %v, want %v", what, got, want)
	}
}

func TestSysfsHasBPFMountpoint(t *testing.T) {
	e := newSysfsEnv(t)
	st, err := e.stat("/fs/bpf")
	if err != nil {
		t.Fatalf("stat /fs/bpf: %v", err)
	}
	if st.Mode&linux.S_IFMT != linux.S_IFDIR || st.Mode&07777 != 0755 || st.UID != 0 || st.GID != 0 {
		t.Errorf("/fs/bpf mode=%#o uid=%d gid=%d, want a root-owned 0755 directory", st.Mode, st.UID, st.GID)
	}
	if got := e.statfsMagic("/fs/bpf"); got != linux.SYSFS_MAGIC {
		t.Errorf("statfs magic of the unmounted mountpoint = %#x, want sysfs %#x", got, linux.SYSFS_MAGIC)
	}
}

func TestSysfsBPFMountpointCannotBeCreatedAgain(t *testing.T) {
	e := newSysfsEnv(t)
	requireErrno(t, "mkdir /fs/bpf", e.mkdir("/fs/bpf"), linuxerr.EEXIST)
	requireErrno(t, "mkdir /fs/bpf/x", e.mkdir("/fs/bpf/x"), linuxerr.EPERM)
}

func TestBPFFSMountOverSysfsMountpoint(t *testing.T) {
	e := newSysfsEnv(t)
	if err := e.mountBPF("/fs/bpf"); err != nil {
		t.Fatalf("mount -t bpf bpffs /sys/fs/bpf: %v", err)
	}
	if got := e.statfsMagic("/fs/bpf"); got != bpfFSMagic {
		t.Errorf("statfs magic = %#x, want BPF_FS_MAGIC %#x", got, bpfFSMagic)
	}
	st, err := e.stat("/fs/bpf")
	if err != nil {
		t.Fatalf("stat mounted /fs/bpf: %v", err)
	}
	if st.Mode&07777 != 01777 {
		t.Errorf("bpffs root mode = %#o, want 01777 as on Linux", st.Mode&07777)
	}
}

func TestBPFFSMountOutsideTheMountpoint(t *testing.T) {
	e := newSysfsEnv(t)
	if err := e.mkdir("/fs/other"); !errors.Is(err, linuxerr.EPERM) {
		t.Skipf("sysfs accepts mkdir: %v", err)
	}
	requireErrno(t, "mount over a missing path", e.mountBPF("/fs/nothing"), linuxerr.ENOENT)
}

func TestBPFFSHoldsDirectoriesOnly(t *testing.T) {
	e := newSysfsEnv(t)
	if err := e.mountBPF("/fs/bpf"); err != nil {
		t.Fatalf("mount bpffs: %v", err)
	}
	if err := e.mkdir("/fs/bpf/a"); err != nil {
		t.Fatalf("mkdir /fs/bpf/a: %v", err)
	}
	if err := e.mkdir("/fs/bpf/a/b"); err != nil {
		t.Fatalf("mkdir /fs/bpf/a/b: %v", err)
	}
	requireErrno(t, "mkdir existing", e.mkdir("/fs/bpf/a"), linuxerr.EEXIST)

	st, err := e.stat("/fs/bpf/a")
	if err != nil || st.Mode&linux.S_IFMT != linux.S_IFDIR || st.Nlink != 3 {
		t.Errorf("stat /fs/bpf/a = (mode %#o, nlink %d, %v), want a directory with 3 links", st.Mode, st.Nlink, err)
	}

	err = e.vfs.MknodAt(e.ctx, e.creds, e.pop("/fs/bpf/file"), &vfs.MknodOptions{Mode: linux.S_IFREG | 0644})
	requireErrno(t, "mknod regular file", err, linuxerr.EPERM)

	requireErrno(t, "rmdir non-empty", e.vfs.RmdirAt(e.ctx, e.creds, e.pop("/fs/bpf/a")), linuxerr.ENOTEMPTY)
	if err := e.vfs.RmdirAt(e.ctx, e.creds, e.pop("/fs/bpf/a/b")); err != nil {
		t.Fatalf("rmdir /fs/bpf/a/b: %v", err)
	}
	if st, err := e.stat("/fs/bpf/a"); err != nil || st.Nlink != 2 {
		t.Errorf("nlink after rmdir = %d (%v), want 2", st.Nlink, err)
	}
	if err := e.vfs.RmdirAt(e.ctx, e.creds, e.pop("/fs/bpf/a")); err != nil {
		t.Fatalf("rmdir /fs/bpf/a: %v", err)
	}
	if _, err := e.stat("/fs/bpf/a"); !errors.Is(err, linuxerr.ENOENT) {
		t.Errorf("stat removed directory = %v, want ENOENT", err)
	}
}

func TestBPFFSListedInProcFilesystems(t *testing.T) {
	e := newSysfsEnv(t)
	var buf bytes.Buffer
	e.vfs.GenerateProcFilesystems(&buf)
	if !strings.Contains(buf.String(), "nodev\tbpf\n") {
		t.Errorf("/proc/filesystems = %q, want a nodev bpf line", buf.String())
	}
}
