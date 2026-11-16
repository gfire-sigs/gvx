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

package devpts_test

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"math"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/devpts"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/fsutilx"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/loader"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/usermem"
	"z.gfire.dev/gvx/pkg/waiter"
)

var initTestEnvOnce sync.Once

func ensureTestEnv() {
	initTestEnvOnce.Do(func() {
		cpuid.Initialize()
		if _, ok := kernel.LookupSyscallTable(abi.Linux, arch.Host); !ok {
			kernel.RegisterSyscallTable(&kernel.SyscallTable{
				OS:   abi.Linux,
				Arch: arch.Host,
			})
		}
	})
}

type taskWorkFunc func(*kernel.Task)

func (f taskWorkFunc) TaskWork(t *kernel.Task) {
	f(t)
}

type ptyTestPlatform struct {
	platform.NoCPUPreemptionDetection
	platform.NoCPUNumbers
	mu       sync.Mutex
	contexts []*ptyTestPlatformContext
}

func (*ptyTestPlatform) SupportsAddressSpaceIO() bool  { return false }
func (*ptyTestPlatform) HaveGlobalMemoryBarrier() bool { return false }
func (*ptyTestPlatform) GlobalMemoryBarrier() error    { return nil }
func (*ptyTestPlatform) MinUserAddress() hostarch.Addr { return hostarch.PageSize }
func (*ptyTestPlatform) MaxUserAddress() hostarch.Addr { return 0x0000_7fff_ffff_f000 }
func (*ptyTestPlatform) MapUnit() uint64               { return 0 }
func (*ptyTestPlatform) ConcurrencyCount() int         { return math.MaxInt }
func (*ptyTestPlatform) SeccompInfo() platform.SeccompInfo {
	return platform.StaticSeccompInfo{PlatformName: "test"}
}

func (p *ptyTestPlatform) NewContext(context.Context) platform.Context {
	c := &ptyTestPlatformContext{
		intrCh: make(chan struct{}, 1),
	}
	p.mu.Lock()
	p.contexts = append(p.contexts, c)
	p.mu.Unlock()
	return c
}

func (*ptyTestPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return ptyTestAddressSpace{}, nil
}

type ptyTestPlatformContext struct {
	platform.NoCPUNumbers
	intrCh chan struct{}
}

func (*ptyTestPlatformContext) Release()                     {}
func (*ptyTestPlatformContext) FullStateChanged()            {}
func (*ptyTestPlatformContext) Preempt()                     {}
func (*ptyTestPlatformContext) PrepareSleep()                {}
func (*ptyTestPlatformContext) PrepareUninterruptibleSleep() {}
func (*ptyTestPlatformContext) PrepareStop()                 {}
func (*ptyTestPlatformContext) PrepareExecve()               {}
func (*ptyTestPlatformContext) PrepareExit()                 {}
func (*ptyTestPlatformContext) PullFullState(platform.AddressSpace, *arch.Context64) error {
	return nil
}

func (c *ptyTestPlatformContext) Interrupt() {
	select {
	case c.intrCh <- struct{}{}:
	default:
	}
}

func (c *ptyTestPlatformContext) Switch(_ context.Context, _ platform.MemoryManager, _ *arch.Context64, _ int32) (*linux.SignalInfo, hostarch.AccessType, error) {
	<-c.intrCh
	return nil, hostarch.NoAccess, platform.ErrContextInterrupt
}

type ptyTestAddressSpace struct {
	platform.NoAddressSpaceIO
}

func (ptyTestAddressSpace) Release()                                                     {}
func (ptyTestAddressSpace) PreFork()                                                     {}
func (ptyTestAddressSpace) PostFork()                                                    {}
func (ptyTestAddressSpace) Unmap(hostarch.Addr, uint64)                                  {}
func (ptyTestAddressSpace) UserModifiedGS(context.Context, platform.MemoryManager) error { return nil }
func (ptyTestAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

func minimalELF64() []byte {
	machine := uint16(elf.EM_AARCH64)
	if arch.Host == arch.AMD64 {
		machine = uint16(elf.EM_X86_64)
	}
	const (
		loadAddr  = 0x400000
		totalSize = 64 + 56
	)
	var hdr elf.Header64
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)})
	hdr.Type = uint16(elf.ET_EXEC)
	hdr.Machine = machine
	hdr.Version = uint32(elf.EV_CURRENT)
	hdr.Entry = loadAddr
	hdr.Phoff = 64
	hdr.Ehsize = 64
	hdr.Phentsize = 56
	hdr.Phnum = 1

	phdr := elf.Prog64{
		Type:   uint32(elf.PT_LOAD),
		Flags:  uint32(elf.PF_R | elf.PF_X),
		Off:    0,
		Vaddr:  loadAddr,
		Paddr:  loadAddr,
		Filesz: totalSize,
		Memsz:  totalSize,
		Align:  0x10000,
	}

	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, &hdr)
	_ = binary.Write(&buf, binary.LittleEndian, &phdr)
	return buf.Bytes()
}

type taskWorker struct {
	tg      *kernel.ThreadGroup
	task    *kernel.Task
	pctx    *ptyTestPlatformContext
	scratch hostarch.Addr
}

func (w *taskWorker) run(fn func(*kernel.Task)) {
	done := make(chan struct{})
	w.task.RegisterWork(taskWorkFunc(func(task *kernel.Task) {
		fn(task)
		close(done)
	}))
	w.pctx.Interrupt()
	<-done
}

func (w *taskWorker) readReplica(fd *vfs.FileDescription, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	var n int64
	var err error
	w.run(func(task *kernel.Task) {
		n, err = fd.Read(task, dst, opts)
	})
	return n, err
}

func (w *taskWorker) readReplicaWithHook(fd *vfs.FileDescription, dst usermem.IOSequence, opts vfs.ReadOptions, onBlock func(*kernel.Task, blockCall)) (int64, error) {
	var n int64
	var err error
	w.run(func(task *kernel.Task) {
		ctx := &hookContext{
			Context: task,
			onBlock: func(call blockCall) {
				onBlock(task, call)
			},
		}
		n, err = fd.Read(ctx, dst, opts)
	})
	return n, err
}

type ptyFixture struct {
	k      *kernel.Kernel
	plat   *ptyTestPlatform
	sctx   context.Context
	creds  *auth.Credentials
	vfsObj *vfs.VirtualFilesystem
	mntns  *vfs.MountNamespace
	root   vfs.VirtualDentry
	reader *taskWorker
	peer   *taskWorker
}

func (f *ptyFixture) createWorker(t *testing.T) *taskWorker {
	t.Helper()
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatalf("NewLinuxLimitSet: %v", err)
	}
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	fdTable := f.k.NewFDTable()
	f.mntns.IncRef()
	tg, _, err := f.k.CreateProcess(kernel.CreateProcessArgs{
		Filename:             "/init",
		Argv:                 []string{"/init"},
		WorkingDirectory:     "/",
		Credentials:          f.creds,
		FDTable:              fdTable,
		MountNamespace:       f.mntns,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         f.k.RootUTSNamespace(),
		IPCNamespace:         f.k.RootIPCNamespace(),
		PIDNamespace:         f.k.RootPIDNamespace(),
		Origin:               kernel.OriginExec,
	})
	fdTable.DecRef(f.sctx)
	if err != nil {
		t.Fatalf("CreateProcess: %v", err)
	}
	f.plat.mu.Lock()
	pctx := f.plat.contexts[len(f.plat.contexts)-1]
	f.plat.mu.Unlock()
	w := &taskWorker{
		tg:   tg,
		task: tg.Leader(),
		pctx: pctx,
	}
	return w
}

func (w *taskWorker) initMemory(t *testing.T) {
	t.Helper()
	var mapErr error
	w.run(func(task *kernel.Task) {
		addr, err := task.MemoryManager().MMap(task, memmap.MMapOpts{
			Length:   3 * hostarch.PageSize,
			Private:  true,
			Perms:    hostarch.ReadWrite,
			MaxPerms: hostarch.AnyAccess,
		})
		if err != nil {
			mapErr = err
			return
		}
		w.scratch = addr
		task.Arch().SetStack(uintptr(addr + 3*hostarch.PageSize))
	})
	if mapErr != nil {
		t.Fatalf("MMap scratch and stack: %v", mapErr)
	}
}

func newPTYFixture(t *testing.T) *ptyFixture {
	t.Helper()
	ensureTestEnv()

	fd, err := memutil.CreateMemFD("devpts-test", 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), "devpts-test"), pgalloc.MemoryFileOpts{
		Accounting: usage.NewMemoryLocked(),
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)

	plat := &ptyTestPlatform{}
	k := &kernel.Kernel{Platform: plat}
	k.SetMemoryFile(mf)

	vdso, err := loader.PrepareVDSO(mf)
	if err != nil {
		t.Fatalf("PrepareVDSO: %v", err)
	}

	tk := kernel.NewTimekeeper()
	paramsRange, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		t.Fatalf("mf.Allocate: %v", err)
	}
	vdsoParams := kernel.NewVDSOParamPage(mf, paramsRange)
	tk.SetClocks(sentrytime.NewCalibratedClocks(false), vdsoParams)
	t.Cleanup(tk.Destroy)

	userNS := auth.NewRootUserNamespace()
	creds := auth.NewRootCredentials(userNS)
	if err := k.Init(kernel.InitKernelArgs{
		FeatureSet:        cpuid.HostFeatureSet(),
		Timekeeper:        tk,
		RootUserNamespace: userNS,
		ApplicationCores:  1,
		Vdso:              vdso,
		VdsoParams:        vdsoParams,
		RootUTSNamespace:  kernel.NewUTSNamespace("host", "domain", userNS),
		RootIPCNamespace:  kernel.NewIPCNamespace(userNS),
		RootPIDNamespace:  kernel.NewRootPIDNamespace(userNS),
		MaxFDLimit:        kernel.MaxFdLimit,
		Cgroup2FSInit:     cgroup2fs.NewFilesystem,
	}); err != nil {
		t.Fatalf("Kernel.Init: %v", err)
	}

	sctx := k.SupervisorContext()
	vfsObj := k.VFS()
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType(devpts.Name, &devpts.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", "tmpfs", &vfs.MountOptions{}, k)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() { mntns.DecRef(sctx) })
	root := mntns.Root(sctx)
	t.Cleanup(func() { root.DecRef(sctx) })

	initPop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/init")}
	initFD, err := vfsObj.OpenAt(sctx, creds, initPop, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0o755})
	if err != nil {
		t.Fatalf("OpenAt(/init): %v", err)
	}
	if _, err := initFD.Write(sctx, usermem.BytesIOSequence(minimalELF64()), vfs.WriteOptions{}); err != nil {
		initFD.DecRef(sctx)
		t.Fatalf("Write(/init): %v", err)
	}
	initFD.DecRef(sctx)

	for _, dir := range []string{"/dev", "/dev/pts"} {
		pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(dir)}
		if err := vfsObj.MkdirAt(sctx, creds, pop, &vfs.MkdirOptions{Mode: 0o755}); err != nil {
			t.Fatalf("MkdirAt(%s): %v", dir, err)
		}
	}
	ptsPop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/dev/pts")}
	if _, err := vfsObj.MountAt(sctx, creds, "devpts", ptsPop, devpts.Name, &vfs.MountOptions{
		GetFilesystemOptions: vfs.GetFilesystemOptions{Data: "ptmxmode=0666,mode=0620,newinstance"},
	}); err != nil {
		t.Fatalf("MountAt(/dev/pts): %v", err)
	}

	f := &ptyFixture{
		k:      k,
		plat:   plat,
		sctx:   sctx,
		creds:  creds,
		vfsObj: vfsObj,
		mntns:  mntns,
		root:   root,
	}
	f.reader = f.createWorker(t)
	f.peer = f.createWorker(t)
	if err := k.Start(); err != nil {
		t.Fatalf("Kernel.Start: %v", err)
	}
	t.Cleanup(func() {
		k.Kill(linux.WaitStatusExit(0))
		k.WaitExited()
	})
	f.reader.initMemory(t)
	f.peer.initMemory(t)
	return f
}

func (f *ptyFixture) openPair(t *testing.T, replicaFlags uint32) (*vfs.FileDescription, *vfs.FileDescription) {
	t.Helper()
	var masterFD, replicaFD *vfs.FileDescription
	var openErr error
	f.peer.run(func(task *kernel.Task) {
		ptmxPop := &vfs.PathOperation{Root: f.root, Start: f.root, Path: fspath.Parse("/dev/pts/ptmx")}
		mfd, err := f.vfsObj.OpenAt(task, f.creds, ptmxPop, &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_NOCTTY})
		if err != nil {
			openErr = err
			return
		}
		var unlock [4]byte
		if _, err := task.MemoryManager().CopyOut(task, f.peer.scratch, unlock[:], usermem.IOOpts{}); err != nil {
			mfd.DecRef(task)
			openErr = err
			return
		}
		if _, err := mfd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
			{}, {Value: linux.TIOCSPTLCK}, {Value: uintptr(f.peer.scratch)},
		}); err != nil {
			mfd.DecRef(task)
			openErr = err
			return
		}
		if _, err := mfd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
			{}, {Value: linux.TIOCGPTN}, {Value: uintptr(f.peer.scratch)},
		}); err != nil {
			mfd.DecRef(task)
			openErr = err
			return
		}
		var ptyNumBuf [4]byte
		if _, err := task.MemoryManager().CopyIn(task, f.peer.scratch, ptyNumBuf[:], usermem.IOOpts{}); err != nil {
			mfd.DecRef(task)
			openErr = err
			return
		}
		ptyNum := binary.LittleEndian.Uint32(ptyNumBuf[:])
		repPath := "/dev/pts/" + strconv.FormatUint(uint64(ptyNum), 10)
		repPop := &vfs.PathOperation{Root: f.root, Start: f.root, Path: fspath.Parse(repPath)}
		rfd, err := f.vfsObj.OpenAt(task, f.creds, repPop, &vfs.OpenOptions{Flags: linux.O_RDWR | linux.O_NOCTTY | replicaFlags})
		if err != nil {
			mfd.DecRef(task)
			openErr = err
			return
		}
		masterFD = mfd
		replicaFD = rfd
	})
	if openErr != nil {
		t.Fatalf("openPair: %v", openErr)
	}
	return masterFD, replicaFD
}

func (f *ptyFixture) setRawTermiosOn(w *taskWorker, fd *vfs.FileDescription, vmin, vtime uint8, useTermios2 bool) error {
	var ioctlErr error
	w.run(func(task *kernel.Task) {
		if useTermios2 {
			if _, err := fd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
				{}, {Value: linux.TCGETS2}, {Value: uintptr(w.scratch)},
			}); err != nil {
				ioctlErr = err
				return
			}
			var kterm linux.KernelTermios
			buf := make([]byte, kterm.SizeBytes())
			if _, err := task.MemoryManager().CopyIn(task, w.scratch, buf, usermem.IOOpts{}); err != nil {
				ioctlErr = err
				return
			}
			kterm.UnmarshalBytes(buf)
			kterm.LocalFlags &^= linux.ICANON | linux.ECHO
			kterm.ControlCharacters[linux.VMIN] = vmin
			kterm.ControlCharacters[linux.VTIME] = vtime
			kterm.MarshalBytes(buf)
			if _, err := task.MemoryManager().CopyOut(task, w.scratch, buf, usermem.IOOpts{}); err != nil {
				ioctlErr = err
				return
			}
			_, ioctlErr = fd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
				{}, {Value: linux.TCSETS2}, {Value: uintptr(w.scratch)},
			})
			return
		}
		if _, err := fd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
			{}, {Value: linux.TCGETS}, {Value: uintptr(w.scratch)},
		}); err != nil {
			ioctlErr = err
			return
		}
		var term linux.Termios
		termBuf := make([]byte, term.SizeBytes())
		if _, err := task.MemoryManager().CopyIn(task, w.scratch, termBuf, usermem.IOOpts{}); err != nil {
			ioctlErr = err
			return
		}
		term.UnmarshalBytes(termBuf)
		term.LocalFlags &^= linux.ICANON | linux.ECHO
		term.ControlCharacters[linux.VMIN] = vmin
		term.ControlCharacters[linux.VTIME] = vtime
		term.MarshalBytes(termBuf)
		if _, err := task.MemoryManager().CopyOut(task, w.scratch, termBuf, usermem.IOOpts{}); err != nil {
			ioctlErr = err
			return
		}
		_, ioctlErr = fd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
			{}, {Value: linux.TCSETS}, {Value: uintptr(w.scratch)},
		})
	})
	return ioctlErr
}

func (f *ptyFixture) setRawTermios(t *testing.T, fd *vfs.FileDescription, vmin, vtime uint8) {
	t.Helper()
	if err := f.setRawTermiosOn(f.peer, fd, vmin, vtime, false); err != nil {
		t.Fatalf("setRawTermios(VMIN=%d, VTIME=%d): %v", vmin, vtime, err)
	}
}

func (f *ptyFixture) writeMaster(fd *vfs.FileDescription, data []byte) (int64, error) {
	var n int64
	var err error
	f.peer.run(func(task *kernel.Task) {
		n, err = fd.Write(task, usermem.BytesIOSequence(data), vfs.WriteOptions{})
	})
	return n, err
}

type blockCall struct {
	haveTimeout bool
	timeout     time.Duration
}

// hookContext wraps a real Task Context and runs onBlock before blocking.
type hookContext struct {
	context.Context
	onBlock  func(blockCall)
	override func(chan struct{}, bool, time.Duration) (time.Duration, error)
}

func (h *hookContext) BlockWithTimeout(c chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if h.onBlock != nil {
		h.onBlock(blockCall{haveTimeout: haveTimeout, timeout: timeout})
	}
	if h.override != nil {
		return h.override(c, haveTimeout, timeout)
	}
	return h.Context.BlockWithTimeout(c, haveTimeout, timeout)
}

func (h *hookContext) Block(c <-chan struct{}) error {
	if h.onBlock != nil {
		h.onBlock(blockCall{haveTimeout: false})
	}
	return h.Context.Block(c)
}

func TestReplicaNonCanonicalVMINZeroVTIMEZeroDrainsWithoutBlocking(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	f.setRawTermios(t, replicaFD, 0, 0)

	buf := make([]byte, 1024)
	n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || n != 0 {
		t.Fatalf("empty read with VMIN=0 VTIME=0 = (%d, %v), want (0, nil)", n, err)
	}

	if wn, werr := f.writeMaster(masterFD, []byte("q")); werr != nil || wn != 1 {
		t.Fatalf("master write 'q' = (%d, %v), want (1, nil)", wn, werr)
	}

	n, err = f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || n != 1 || buf[0] != 'q' {
		t.Fatalf("first read after 'q' = (%d, %q, %v), want (1, \"q\", nil)", n, buf[:max(0, int(n))], err)
	}

	n, err = f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || n != 0 {
		t.Fatalf("drain read after 'q' = (%d, %v), want (0, nil)", n, err)
	}

	masterNB, nonblockReplica := f.openPair(t, linux.O_NONBLOCK)
	defer masterNB.DecRef(f.sctx)
	defer nonblockReplica.DecRef(f.sctx)
	// Configure the second terminal with VMIN=0 and VTIME=0 so O_NONBLOCK returns (0, nil).
	f.setRawTermios(t, nonblockReplica, 0, 0)
	n, err = f.reader.readReplica(nonblockReplica, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || n != 0 {
		t.Fatalf("O_NONBLOCK empty read with VMIN=0 VTIME=0 = (%d, %v), want (0, nil)", n, err)
	}
}

func TestReplicaNonCanonicalVMINZeroPositiveVTIMETimesOutAndWakesOnInput(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	f.setRawTermios(t, replicaFD, 0, 2)

	buf := make([]byte, 64)
	if n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{Flags: fsutilx.RWFNoWait}); !linuxerr.Equals(linuxerr.EAGAIN, err) || n != 0 {
		t.Fatalf("RWF_NOWAIT empty read with VMIN=0 VTIME=2 = (%d, %v), want (0, EAGAIN)", n, err)
	}

	masterNB, replicaNB := f.openPair(t, linux.O_NONBLOCK)
	defer masterNB.DecRef(f.sctx)
	defer replicaNB.DecRef(f.sctx)
	f.setRawTermios(t, replicaNB, 0, 2)
	if n, err := f.reader.readReplica(replicaNB, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || n != 0 {
		t.Fatalf("O_NONBLOCK empty read with VMIN=0 VTIME=2 = (%d, %v), want (0, ErrWouldBlock)", n, err)
	}
	if n, err := f.reader.readReplica(replicaNB, usermem.BytesIOSequence(buf), vfs.ReadOptions{Flags: fsutilx.RWFNoWait}); !linuxerr.Equals(linuxerr.EAGAIN, err) || n != 0 {
		t.Fatalf("O_NONBLOCK+RWF_NOWAIT empty read = (%d, %v), want (0, EAGAIN)", n, err)
	}
	if n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{Flags: 0x8000}); !linuxerr.Equals(linuxerr.EOPNOTSUPP, err) || n != 0 {
		t.Fatalf("unsupported ReadOptions.Flags = (%d, %v), want (0, EOPNOTSUPP)", n, err)
	}

	start := time.Now()
	n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	elapsed := time.Since(start)
	if err != nil || n != 0 {
		t.Fatalf("timed empty read with VMIN=0 VTIME=2 = (%d, %v), want (0, nil)", n, err)
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("timed read elapsed %v, want at least 150ms for VTIME=2", elapsed)
	}

	f.setRawTermios(t, replicaFD, 0, 20)
	var writeOnce sync.Once
	start = time.Now()
	n, err = f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, call blockCall) {
		if !call.haveTimeout || call.timeout != 2*time.Second {
			t.Errorf("BlockWithTimeout call = %+v, want haveTimeout=true timeout=2s", call)
		}
		writeOnce.Do(func() {
			go func() {
				_, _ = f.writeMaster(masterFD, []byte("ok"))
			}()
		})
	})
	elapsed = time.Since(start)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("woken read with VMIN=0 VTIME=20 = (%d, %q, %v), want (2, \"ok\", nil)", n, buf[:max(0, int(n))], err)
	}
	if elapsed >= 1500*time.Millisecond {
		t.Fatalf("woken read took %v, want early wakeup well below 2s timeout", elapsed)
	}
}

func TestReplicaNonCanonicalPositiveVMINAccumulatesAndInterbyteTimerExpires(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	// Case A with VMIN=3 and VTIME=0 blocks until 3 bytes arrive.
	f.setRawTermios(t, replicaFD, 3, 0)
	if _, err := f.writeMaster(masterFD, []byte("a")); err != nil {
		t.Fatalf("master write 'a': %v", err)
	}
	var sentRest sync.Once
	buf := make([]byte, 64)
	n, err := f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, call blockCall) {
		if call.haveTimeout {
			t.Errorf("Case A BlockWithTimeout haveTimeout = true, want false")
		}
		sentRest.Do(func() {
			go func() {
				_, _ = f.writeMaster(masterFD, []byte("bc"))
			}()
		})
	})
	if err != nil || string(buf[:n]) != "abc" {
		t.Fatalf("Case A read (VMIN=3, VTIME=0) = (%d, %q, %v), want (3, \"abc\", nil)", n, buf[:max(0, int(n))], err)
	}

	// Case B with VMIN=4 and VTIME=2 waits untimed for byte 1, then expires after 200ms.
	f.setRawTermios(t, replicaFD, 4, 2)
	var calls []blockCall
	var mu sync.Mutex
	var sentFirst sync.Once
	n, err = f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, call blockCall) {
		mu.Lock()
		calls = append(calls, call)
		mu.Unlock()
		sentFirst.Do(func() {
			go func() {
				_, _ = f.writeMaster(masterFD, []byte("ab"))
			}()
		})
	})
	if err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("Case B read (VMIN=4, VTIME=2) = (%d, %q, %v), want (2, \"ab\", nil)", n, buf[:max(0, int(n))], err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) < 2 || calls[0].haveTimeout || !calls[len(calls)-1].haveTimeout {
		t.Fatalf("Case B block calls = %+v, want initial untimed wait followed by 200ms interbyte timer", calls)
	}
}

func TestReplicaTimedReadPreservesSignalInterruptAndUserFault(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	// Install a caught SIGUSR1 handler on the reader thread group so SendSignal interrupts BlockWithTimeout.
	f.reader.run(func(task *kernel.Task) {
		if _, err := task.ThreadGroup().SetSigAction(linux.SIGUSR1, &linux.SigAction{
			Handler:  0x400000,
			Flags:    linux.SA_RESTORER,
			Restorer: 0x400000,
		}); err != nil {
			t.Fatalf("SetSigAction(SIGUSR1): %v", err)
		}
	})

	f.setRawTermios(t, replicaFD, 0, 20)
	buf := make([]byte, 64)
	var sigOnce sync.Once
	n, err := f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(task *kernel.Task, _ blockCall) {
		sigOnce.Do(func() {
			go func() {
				_ = task.SendSignal(kernel.SignalInfoPriv(linux.SIGUSR1))
			}()
		})
	})
	if !linuxerr.Equals(linuxerr.ErrInterrupted, err) || n != 0 {
		t.Fatalf("signal during timed read = (%d, %v), want (0, ErrInterrupted)", n, err)
	}

	// Verify the deadline boundary where BlockWithTimeout returns rem == 0 with ErrInterrupted.
	var deadlineIntN int64
	var deadlineIntErr error
	f.reader.run(func(task *kernel.Task) {
		ctx := &hookContext{
			Context: task,
			override: func(chan struct{}, bool, time.Duration) (time.Duration, error) {
				return 0, linuxerr.ErrInterrupted
			},
		}
		deadlineIntN, deadlineIntErr = replicaFD.Read(ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	})
	if !linuxerr.Equals(linuxerr.ErrInterrupted, deadlineIntErr) || deadlineIntN != 0 {
		t.Fatalf("rem=0 ErrInterrupted timed read = (%d, %v), want (0, ErrInterrupted)", deadlineIntN, deadlineIntErr)
	}

	// Verify EFAULT is preserved when post-timeout drain copies into unmapped user memory.
	f.setRawTermios(t, replicaFD, 0, 1)
	var faultN int64
	var faultErr error
	f.reader.run(func(task *kernel.Task) {
		badSeq, seqErr := task.SingleIOSequence(hostarch.Addr(0x7000_0000), 16, usermem.IOOpts{})
		if seqErr != nil {
			t.Fatalf("SingleIOSequence: %v", seqErr)
		}
		ctx := &hookContext{
			Context: task,
			override: func(chan struct{}, bool, time.Duration) (time.Duration, error) {
				_, _ = f.writeMaster(masterFD, []byte("x"))
				return 0, linuxerr.ETIMEDOUT
			},
		}
		faultN, faultErr = replicaFD.Read(ctx, badSeq, vfs.ReadOptions{})
	})
	if !linuxerr.Equals(linuxerr.EFAULT, faultErr) || faultN != 0 {
		t.Fatalf("post-timeout unmapped user buffer = (%d, %v), want (0, EFAULT)", faultN, faultErr)
	}
}

func TestReplicaConcurrentTCSETSWakesBlockedNonCanonicalReader(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	// Subcase 1: Reader blocks with VMIN=3, VTIME=0 and total=1; lowering VMIN to 1 via TCSETS returns (1, nil).
	f.setRawTermios(t, replicaFD, 3, 0)
	if _, err := f.writeMaster(masterFD, []byte("x")); err != nil {
		t.Fatalf("master write 'x': %v", err)
	}
	buf := make([]byte, 64)
	var lowerOnce sync.Once
	n, err := f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, _ blockCall) {
		lowerOnce.Do(func() {
			go func() {
				_ = f.setRawTermiosOn(f.peer, replicaFD, 1, 0, false)
			}()
		})
	})
	if err != nil || string(buf[:n]) != "x" {
		t.Fatalf("TCSETS lowering VMIN to 1 = (%d, %q, %v), want (1, \"x\", nil)", n, buf[:max(0, int(n))], err)
	}

	// Subcase 2: Reader blocks with VMIN=3, VTIME=0 and total=0; TCSETS2 to VMIN=0, VTIME=0 returns (0, nil).
	f.setRawTermios(t, replicaFD, 3, 0)
	var pollOnce sync.Once
	n, err = f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, _ blockCall) {
		pollOnce.Do(func() {
			go func() {
				_ = f.setRawTermiosOn(f.peer, replicaFD, 0, 0, true)
			}()
		})
	})
	if err != nil || n != 0 {
		t.Fatalf("TCSETS2 setting VMIN=0 VTIME=0 = (%d, %v), want (0, nil)", n, err)
	}

	// Subcase 3: Reader blocks with VMIN=3, VTIME=20 and total=1; clearing VTIME to 0 disables the timer.
	f.setRawTermios(t, replicaFD, 3, 20)
	if _, err := f.writeMaster(masterFD, []byte("a")); err != nil {
		t.Fatalf("master write 'a': %v", err)
	}
	var calls []blockCall
	var mu sync.Mutex
	step := 0
	n, err = f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, call blockCall) {
		mu.Lock()
		calls = append(calls, call)
		cur := step
		step++
		mu.Unlock()
		switch cur {
		case 0:
			go func() {
				_ = f.setRawTermiosOn(f.peer, replicaFD, 2, 0, false)
			}()
		case 1:
			go func() {
				_, _ = f.writeMaster(masterFD, []byte("b"))
			}()
		}
	})
	if err != nil || string(buf[:n]) != "ab" {
		t.Fatalf("TCSETS clearing VTIME = (%d, %q, %v), want (2, \"ab\", nil)", n, buf[:max(0, int(n))], err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) < 2 || !calls[0].haveTimeout || calls[1].haveTimeout {
		t.Fatalf("block calls across VTIME clear = %+v, want timed wait then untimed wait", calls)
	}
}

func TestReplicaCanonicalModeAndMasterCloseRemainIntact(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer replicaFD.DecRef(f.sctx)

	buf := make([]byte, 64)
	if _, err := f.writeMaster(masterFD, []byte("hi")); err != nil {
		masterFD.DecRef(f.sctx)
		t.Fatalf("master write partial line: %v", err)
	}
	if n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); !linuxerr.Equals(linuxerr.ErrWouldBlock, err) || n != 0 {
		masterFD.DecRef(f.sctx)
		t.Fatalf("canonical read before newline = (%d, %v), want (0, ErrWouldBlock)", n, err)
	}

	if _, err := f.writeMaster(masterFD, []byte("\r")); err != nil {
		masterFD.DecRef(f.sctx)
		t.Fatalf("master write newline: %v", err)
	}
	n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	if err != nil || string(buf[:n]) != "hi\n" {
		masterFD.DecRef(f.sctx)
		t.Fatalf("canonical read after newline = (%d, %q, %v), want (3, \"hi\\n\", nil)", n, buf[:max(0, int(n))], err)
	}

	// Ctrl+D (0x04) on an empty canonical line returns (0, nil) EOF.
	if _, err := f.writeMaster(masterFD, []byte{0x04}); err != nil {
		masterFD.DecRef(f.sctx)
		t.Fatalf("master write VEOF: %v", err)
	}
	if n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); err != nil || n != 0 {
		masterFD.DecRef(f.sctx)
		t.Fatalf("canonical read on VEOF = (%d, %v), want (0, nil)", n, err)
	}

	// Closing the master returns (0, nil) EOF once pending input is drained.
	masterFD.DecRef(f.sctx)
	if n, err := f.reader.readReplica(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}); err != nil || n != 0 {
		t.Fatalf("replica read after master close = (%d, %v), want (0, nil)", n, err)
	}
}

func TestMasterCloseWakesReplicaWaitersAndReportsHangup(t *testing.T) {
	f := newPTYFixture(t)

	// Subcase 1: Registered replica waiter wakes on master close, reports POLLHUP/POLLIN, and rejects writes with EIO.
	masterFD, replicaFD := f.openPair(t, 0)
	defer replicaFD.DecRef(f.sctx)

	const wantMask = waiter.ReadableEvents | waiter.WritableEvents | waiter.EventErr | waiter.EventHUp
	const readHangupMask = waiter.ReadableEvents | waiter.EventErr | waiter.EventHUp
	w, ch := waiter.NewChannelEntry(readHangupMask)
	if err := replicaFD.EventRegister(&w); err != nil {
		masterFD.DecRef(f.sctx)
		t.Fatalf("EventRegister: %v", err)
	}
	defer replicaFD.EventUnregister(&w)

	if got := replicaFD.Readiness(readHangupMask) & readHangupMask; got != 0 {
		masterFD.DecRef(f.sctx)
		t.Fatalf("initial replica Readiness = %#x, want 0", got)
	}
	masterFD.DecRef(f.sctx)
	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("master close did not wake registered replica waiter within 500ms")
	}
	if got := replicaFD.Readiness(wantMask); got != wantMask {
		t.Fatalf("post-close replica Readiness = %#x, want %#x", got, wantMask)
	}
	var writeN int64
	var writeErr error
	f.peer.run(func(task *kernel.Task) {
		writeN, writeErr = replicaFD.Write(task, usermem.BytesIOSequence([]byte("x")), vfs.WriteOptions{})
	})
	if !linuxerr.Equals(linuxerr.EIO, writeErr) || writeN != 0 {
		t.Fatalf("post-close replica Write = (%d, %v), want (0, EIO)", writeN, writeErr)
	}

	// Subcase 2: Blocked non-canonical VMIN=4 reader with 2 buffered bytes wakes on master close and returns (2, nil).
	master2, replica2 := f.openPair(t, 0)
	defer replica2.DecRef(f.sctx)
	f.setRawTermios(t, replica2, 4, 0)
	if _, err := f.writeMaster(master2, []byte("ab")); err != nil {
		master2.DecRef(f.sctx)
		t.Fatalf("writeMaster 'ab': %v", err)
	}
	buf := make([]byte, 64)
	var close2Once sync.Once
	done2 := make(chan struct{})
	var n2 int64
	var err2 error
	go func() {
		n2, err2 = f.reader.readReplicaWithHook(replica2, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, _ blockCall) {
			close2Once.Do(func() {
				go master2.DecRef(f.sctx)
			})
		})
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("master close left blocked VMIN=4 replica reader hung")
	}
	if err2 != nil || string(buf[:n2]) != "ab" {
		t.Fatalf("woken VMIN=4 read on master close = (%d, %q, %v), want (2, \"ab\", nil)", n2, buf[:max(0, int(n2))], err2)
	}

	// Subcase 3: Blocked timed VMIN=0 VTIME=20 reader wakes immediately on master close instead of waiting 2s.
	master3, replica3 := f.openPair(t, 0)
	defer replica3.DecRef(f.sctx)
	f.setRawTermios(t, replica3, 0, 20)
	var close3Once sync.Once
	start := time.Now()
	n3, err3 := f.reader.readReplicaWithHook(replica3, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, _ blockCall) {
		close3Once.Do(func() {
			go master3.DecRef(f.sctx)
		})
	})
	if elapsed := time.Since(start); elapsed >= 1500*time.Millisecond {
		t.Fatalf("master close during VTIME=20 read took %v, want immediate wakeup", elapsed)
	}
	if err3 != nil || n3 != 0 {
		t.Fatalf("woken VTIME=20 read on master close = (%d, %v), want (0, nil)", n3, err3)
	}
}

func TestMasterTCSETSWakesBlockedNonCanonicalReplicaReader(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	f.setRawTermios(t, replicaFD, 3, 0)
	if _, err := f.writeMaster(masterFD, []byte("x")); err != nil {
		t.Fatalf("writeMaster 'x': %v", err)
	}
	buf := make([]byte, 64)
	var lowerOnce sync.Once
	done := make(chan struct{})
	var n int64
	var err error
	go func() {
		n, err = f.reader.readReplicaWithHook(replicaFD, usermem.BytesIOSequence(buf), vfs.ReadOptions{}, func(_ *kernel.Task, _ blockCall) {
			lowerOnce.Do(func() {
				go func() {
					_ = f.setRawTermiosOn(f.peer, masterFD, 1, 0, false)
				}()
			})
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		_ = f.setRawTermiosOn(f.peer, replicaFD, 0, 0, true)
		<-done
		t.Fatal("master TCSETS lowering VMIN did not wake blocked replica reader")
	}
	if err != nil || string(buf[:n]) != "x" {
		t.Fatalf("master TCSETS wake read = (%d, %q, %v), want (1, \"x\", nil)", n, buf[:max(0, int(n))], err)
	}
}

func TestMasterJobControlTargetsReplicaTTY(t *testing.T) {
	f := newPTYFixture(t)
	masterFD, replicaFD := f.openPair(t, 0)
	defer masterFD.DecRef(f.sctx)
	defer replicaFD.DecRef(f.sctx)

	ioctlInt32 := func(w *taskWorker, fd *vfs.FileDescription, cmd uintptr, val *int32, copyIn bool) error {
		var ioctlErr error
		w.run(func(task *kernel.Task) {
			if copyIn {
				var raw [4]byte
				binary.LittleEndian.PutUint32(raw[:], uint32(*val))
				if _, err := task.MemoryManager().CopyOut(task, w.scratch, raw[:], usermem.IOOpts{}); err != nil {
					ioctlErr = err
					return
				}
			}
			_, ioctlErr = fd.Ioctl(task, task.MemoryManager(), 0, arch.SyscallArguments{
				{}, {Value: cmd}, {Value: uintptr(w.scratch)},
			})
			if ioctlErr == nil && !copyIn && val != nil {
				var raw [4]byte
				if _, err := task.MemoryManager().CopyIn(task, w.scratch, raw[:], usermem.IOOpts{}); err != nil {
					ioctlErr = err
					return
				}
				*val = int32(binary.LittleEndian.Uint32(raw[:]))
			}
		})
		return ioctlErr
	}

	// 1. Before any session acquires the replica as controlling TTY, master TIOCGPGRP returns 0 without error.
	gotPGID := int32(-1)
	if err := ioctlInt32(f.peer, masterFD, linux.TIOCGPGRP, &gotPGID, false); err != nil || gotPGID != 0 {
		t.Fatalf("uncontrolled master TIOCGPGRP = (%d, %v), want (0, nil)", gotPGID, err)
	}

	// 2. Acquire controlling TTY via master TIOCSCTTY on f.reader (a distinct session from f.peer).
	if err := ioctlInt32(f.reader, masterFD, linux.TIOCSCTTY, nil, false); err != nil {
		t.Fatalf("master TIOCSCTTY: %v", err)
	}
	wantPGID := int32(f.reader.task.ThreadID())
	var repPGID int32
	if err := ioctlInt32(f.reader, replicaFD, linux.TIOCGPGRP, &repPGID, false); err != nil || repPGID != wantPGID {
		t.Fatalf("replica TIOCGPGRP after master TIOCSCTTY = (%d, %v), want (%d, nil)", repPGID, err, wantPGID)
	}

	// 3. Cross-session master TIOCGPGRP from f.peer returns f.reader's foreground PGID, while cross-session TIOCSPGRP returns ENOTTY.
	if err := ioctlInt32(f.peer, masterFD, linux.TIOCGPGRP, &gotPGID, false); err != nil || gotPGID != wantPGID {
		t.Fatalf("cross-session master TIOCGPGRP = (%d, %v), want (%d, nil)", gotPGID, err, wantPGID)
	}
	if err := ioctlInt32(f.peer, masterFD, linux.TIOCSPGRP, &wantPGID, true); !linuxerr.Equals(linuxerr.ENOTTY, err) {
		t.Fatalf("cross-session master TIOCSPGRP = %v, want ENOTTY", err)
	}

	// 4. Same-session master TIOCSPGRP succeeds, and master TIOCNOTTY returns ENOTTY as on Linux.
	if err := ioctlInt32(f.reader, masterFD, linux.TIOCSPGRP, &wantPGID, true); err != nil {
		t.Fatalf("same-session master TIOCSPGRP: %v", err)
	}
	if err := ioctlInt32(f.reader, masterFD, linux.TIOCNOTTY, nil, false); !linuxerr.Equals(linuxerr.ENOTTY, err) {
		t.Fatalf("master TIOCNOTTY = %v, want ENOTTY", err)
	}
}
