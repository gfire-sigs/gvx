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

package virtgpu

import (
	"encoding/binary"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/dev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
)

const (
	guestMemSize = 64 << 10
	badGuestAddr = hostarch.Addr(0xfff0_0000)
)

func requireBlobHost(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "darwin" {
		t.Skip("blob views require darwin (blob_other.go stub)")
	}
}

type fixedClock struct{}

func (fixedClock) Now() ktime.Time                     { return ktime.FromNanoseconds(1_700_000_000_000_000_000) }
func (fixedClock) NewTimer(ktime.Listener) ktime.Timer { panic("fixedClock has no timers") }

type testNode struct {
	dev   *Device
	vfs   *vfs.VirtualFilesystem
	root  vfs.VirtualDentry
	ctx   context.Context
	creds *auth.Credentials
}

func newTestNode(t *testing.T, r Renderer) *testNode {
	t.Helper()
	return newTestNodeWithLimits(t, r, Limits{})
}

// isolatedContext gives each testNode its own NoTask blocker so concurrent or
// synctest tests never share the package-global context.Background cancel chan.
type isolatedContext struct {
	context.Context
	nt context.NoTask
}

func (c *isolatedContext) Block(ch <-chan struct{}) error {
	return c.nt.Block(ch)
}

func (c *isolatedContext) BlockWithTimeout(ch chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if !haveTimeout {
		return timeout, c.nt.Block(ch)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	start := time.Now()
	select {
	case <-ch:
		return max(0, timeout-time.Since(start)), nil
	case <-timer.C:
		return 0, linuxerr.ETIMEDOUT
	}
}

func newTestNodeWithLimits(t *testing.T, r Renderer, lim Limits) *testNode {
	t.Helper()

	if fr, ok := r.(*fakeRenderer); ok {
		t.Cleanup(fr.cleanup)
	}

	memFD, err := memutil.CreateMemFD("virtgpu-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memFD), "virtgpu-test"), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	k := &kernel.Kernel{}
	k.MaxFDLimit.Store(kernel.MaxFdLimit)
	v := &vfs.VirtualFilesystem{}
	ctx := context.WithValues(&isolatedContext{Context: context.Background()}, map[any]any{
		kernel.CtxKernel:          k,
		ktime.CtxRealtimeClock:    fixedClock{},
		auth.CtxCredentials:       creds,
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
		pgalloc.CtxMemoryFile:     mf,
		ctxTestVFS{}:              v,
	})

	if err := v.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	v.MustRegisterFilesystemType(tmpfs.Name, tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})
	v.MustRegisterFilesystemType(dev.Name, dev.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	d, err := Register(v, r, lim)
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	mntns, err := v.NewMountNamespace(ctx, creds, "", dev.Name, &vfs.MountOptions{}, nil)
	if err != nil {
		t.Fatalf("NewMountNamespace(dev): %v", err)
	}
	root := mntns.Root(ctx)
	ctx = vfs.WithMountNamespace(ctx, mntns)
	t.Cleanup(func() {
		root.DecRef(ctx)
		mntns.DecRef(ctx)
	})

	return &testNode{
		dev:   d,
		vfs:   v,
		root:  root,
		ctx:   ctx,
		creds: creds,
	}
}

func (n *testNode) pop(pathname string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  n.root,
		Start: n.root,
		Path:  fspath.Parse(pathname),
	}
}

func (n *testNode) open(t *testing.T) *vfs.FileDescription {
	t.Helper()
	return n.openFlags(t, linux.O_RDWR)
}

func (n *testNode) openFlags(t *testing.T, flags uint32) *vfs.FileDescription {
	t.Helper()
	fd, err := n.vfs.OpenAt(n.ctx, n.creds, n.pop("/dri/renderD128"), &vfs.OpenOptions{Flags: flags})
	if err != nil {
		t.Fatalf("OpenAt(/dri/renderD128, %#x): %v", flags, err)
	}
	return fd
}

func (n *testNode) openVenus(t *testing.T) *vfs.FileDescription {
	t.Helper()
	fd := n.open(t)
	mem := newGuestMem()
	putContextInit(t, mem, 0x1000, 0x2000, mesaVenusParams())
	if err := n.ioctl(fd, cmdVirtgpuContextInit, mem, 0x1000); err != nil {
		fd.DecRef(n.ctx)
		t.Fatalf("CONTEXT_INIT: %v", err)
	}
	return fd
}

func (n *testNode) openVirgl(t *testing.T) *vfs.FileDescription {
	t.Helper()
	fd := n.open(t)
	mem := newGuestMem()
	putContextInit(t, mem, 0x1000, 0x2000, mesaVirglParams())
	if err := n.ioctl(fd, cmdVirtgpuContextInit, mem, 0x1000); err != nil {
		fd.DecRef(n.ctx)
		t.Fatalf("CONTEXT_INIT(virgl): %v", err)
	}
	return fd
}

func (n *testNode) ioctl(fd *vfs.FileDescription, cmd uint32, mem *guestMem, addr hostarch.Addr) error {
	return n.ioctlWithCtx(n.ctx, fd, cmd, mem, addr)
}

func (n *testNode) ioctlWithCtx(ctx context.Context, fd *vfs.FileDescription, cmd uint32, mem *guestMem, addr hostarch.Addr) error {
	var args arch.SyscallArguments
	args[1] = arch.SyscallArgument{Value: uintptr(cmd)}
	args[2] = arch.SyscallArgument{Value: uintptr(addr)}
	_, err := fd.Ioctl(ctx, &mem.BytesIO, 0, args)
	return err
}

type guestMem struct {
	usermem.BytesIO
}

func newGuestMem() *guestMem {
	return &guestMem{
		BytesIO: usermem.BytesIO{Bytes: make([]byte, guestMemSize)},
	}
}

func (m *guestMem) put(t *testing.T, addr hostarch.Addr, v any) {
	t.Helper()
	n, err := binary.Encode(m.Bytes[addr:], binary.LittleEndian, v)
	if err != nil {
		t.Fatalf("encode %T at %#x: %v", v, addr, err)
	}
	if n != binary.Size(v) {
		t.Fatalf("encode %T: wrote %d bytes, want %d", v, n, binary.Size(v))
	}
}

func (m *guestMem) get(t *testing.T, addr hostarch.Addr, dst any) {
	t.Helper()
	n, err := binary.Decode(m.Bytes[addr:], binary.LittleEndian, dst)
	if err != nil {
		t.Fatalf("decode %T at %#x: %v", dst, addr, err)
	}
	if n != binary.Size(dst) {
		t.Fatalf("decode %T: read %d bytes, want %d", dst, n, binary.Size(dst))
	}
}

func (m *guestMem) writeBytes(addr hostarch.Addr, b []byte) {
	copy(m.Bytes[addr:], b)
}

func (m *guestMem) readBytes(addr hostarch.Addr, n int) []byte {
	out := make([]byte, n)
	copy(out, m.Bytes[addr:addr+hostarch.Addr(n)])
	return out
}

type ctxTestVFS struct{}

// testTaskCtx wraps a test context with signal interruption (Block), an
// independent LimitSet, and a real kernel.FDTable (fdInstaller).
type testTaskCtx struct {
	context.Context
	intr   chan struct{}
	limSet *limits.LimitSet
	fdt    *kernel.FDTable

	mu   sync.Mutex
	refs []*vfs.FileDescription
}

var _ fdInstaller = (*testTaskCtx)(nil)

func newTestTaskCtx(t *testing.T, base context.Context) *testTaskCtx {
	t.Helper()
	k := kernel.KernelFromContext(base)
	if k == nil {
		k = &kernel.Kernel{}
		k.MaxFDLimit.Store(kernel.MaxFdLimit)
	}
	tc := &testTaskCtx{
		Context: base,
		intr:    make(chan struct{}),
		limSet:  limits.NewLimitSet(),
		fdt:     k.NewFDTable(),
	}
	// Occupy standard descriptors 0, 1, and 2 so allocated sync_file FDs
	// start at 3 and RLIMIT_NOFILE=3 exhausts the table.
	if v, ok := base.Value(ctxTestVFS{}).(*vfs.VirtualFilesystem); ok && v != nil {
		placeholder, err := newSyncFile(tc, v, &fence{})
		if err != nil {
			t.Fatalf("newSyncFile(placeholder): %v", err)
		}
		for i := int32(0); i < 3; i++ {
			if prev, err := tc.fdt.NewFDAt(tc, i, placeholder, kernel.FDFlags{}); err != nil {
				placeholder.DecRef(tc)
				t.Fatalf("NewFDAt(%d): %v", i, err)
			} else if prev != nil {
				prev.DecRef(tc)
			}
		}
		placeholder.DecRef(tc)
	}
	t.Cleanup(tc.closeAll)
	return tc
}

func (c *testTaskCtx) Value(key any) any {
	if key == limits.CtxLimits {
		return c.limSet
	}
	return c.Context.Value(key)
}

func (c *testTaskCtx) FDTable() *kernel.FDTable {
	return c.fdt
}

func (c *testTaskCtx) setNoFileLimit(t *testing.T, n uint64) {
	t.Helper()
	if _, err := c.limSet.Set(limits.NumberOfFiles, limits.Limit{Cur: n, Max: n}, true); err != nil {
		t.Fatalf("Set(RLIMIT_NOFILE, %d): %v", n, err)
	}
}

func (c *testTaskCtx) Interrupt() {
	select {
	case <-c.intr:
	default:
		close(c.intr)
	}
}

func (c *testTaskCtx) Block(ch <-chan struct{}) error {
	select {
	case <-ch:
		return nil
	case <-c.intr:
		return linuxerr.ErrInterrupted
	}
}

func (c *testTaskCtx) BlockWithTimeout(ch chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if !haveTimeout {
		return timeout, c.Block(ch)
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	start := time.Now()
	select {
	case <-ch:
		return max(0, timeout-time.Since(start)), nil
	case <-c.intr:
		return max(0, timeout-time.Since(start)), linuxerr.ErrInterrupted
	case <-timer.C:
		return 0, linuxerr.ETIMEDOUT
	}
}

func (c *testTaskCtx) file(fd int32) *vfs.FileDescription {
	f, _ := c.fdt.Get(fd)
	if f != nil {
		c.mu.Lock()
		c.refs = append(c.refs, f)
		c.mu.Unlock()
	}
	return f
}

func (c *testTaskCtx) fdFlags(fd int32) kernel.FDFlags {
	f, flags := c.fdt.Get(fd)
	if f != nil {
		f.DecRef(c)
	}
	return flags
}

func (c *testTaskCtx) closeAll() {
	c.mu.Lock()
	refs := c.refs
	c.refs = nil
	c.mu.Unlock()
	for _, f := range refs {
		f.DecRef(c)
	}
	c.fdt.DecRef(c)
}
