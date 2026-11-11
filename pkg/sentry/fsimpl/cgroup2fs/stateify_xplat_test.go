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

package cgroup2fs

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/abi"
	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/fspath"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/arch"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/tmpfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/ktime"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/loader"
	"z.gfire.dev/gvx/pkg/sentry/memmap"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/uniqueid"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/state"
	"z.gfire.dev/gvx/pkg/usermem"
)

var initTestLoaderOnce sync.Once

func ensureTestLoaderEnv() {
	initTestLoaderOnce.Do(func() {
		cpuid.Initialize()
		if _, ok := kernel.LookupSyscallTable(abi.Linux, arch.Host); !ok {
			kernel.RegisterSyscallTable(&kernel.SyscallTable{
				OS:   abi.Linux,
				Arch: arch.Host,
			})
		}
	})
}

type testSRPlatform struct{ platform.Platform }

func (testSRPlatform) SupportsAddressSpaceIO() bool                { return false }
func (testSRPlatform) CooperativelySchedulesAddressSpace() bool    { return false }
func (testSRPlatform) MinUserAddress() hostarch.Addr               { return hostarch.PageSize }
func (testSRPlatform) MaxUserAddress() hostarch.Addr               { return 0x0000_7fff_ffff_f000 }
func (testSRPlatform) MapUnit() uint64                             { return 0 }
func (testSRPlatform) HasCPUNumbers() bool                         { return false }
func (testSRPlatform) NumCPUs() int                                { return 1 }
func (testSRPlatform) DetectPreemptMigrate() bool                  { return false }
func (testSRPlatform) CountsCgroupMemory() bool                    { return true }
func (testSRPlatform) NewContext(context.Context) platform.Context { return testSRPlatformContext{} }
func (testSRPlatform) NewAddressSpace(platform.AddressSpaceOptions) (platform.AddressSpace, error) {
	return testSRAddressSpace{}, nil
}

type testSRPlatformContext struct{ platform.Context }

type testSRAddressSpace struct{ platform.AddressSpace }

func (testSRAddressSpace) Release()                    {}
func (testSRAddressSpace) Unmap(hostarch.Addr, uint64) {}
func (testSRAddressSpace) MapFile(hostarch.Addr, memmap.File, memmap.FileRange, hostarch.AccessType, bool) error {
	return nil
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

func minimalStaticELF64() []byte {
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

func newTestKernelMemoryFile(t *testing.T, name string) *pgalloc.MemoryFile {
	t.Helper()
	fd, err := memutil.CreateMemFD(name, 0)
	if err != nil {
		t.Fatalf("CreateMemFD: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(fd), name), pgalloc.MemoryFileOpts{
		Accounting: usage.NewMemoryLocked(),
	})
	if err != nil {
		t.Fatalf("NewMemoryFile: %v", err)
	}
	t.Cleanup(mf.Destroy)
	return mf
}

func bootTestKernelWithInitTask(t *testing.T, opts MemoryEnforcerOptions) (*kernel.Kernel, *kernel.Task, vfs.VirtualDentry) {
	t.Helper()
	ensureTestLoaderEnv()

	mf := newTestKernelMemoryFile(t, "cgroup2fs-orig")
	k := &kernel.Kernel{Platform: testSRPlatform{}}
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
		Cgroup2FSInit:     NewFilesystemWithMemoryOptions(opts),
	}); err != nil {
		t.Fatalf("Kernel.Init: %v", err)
	}

	sctx := k.SupervisorContext()
	vfsObj := k.VFS()
	vfsObj.MustRegisterFilesystemType("tmpfs", tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})
	vfsObj.MustRegisterFilesystemType("cgroup2", FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{AllowUserMount: true})

	mntns, err := vfsObj.NewMountNamespace(sctx, creds, "", "tmpfs", &vfs.MountOptions{}, k)
	if err != nil {
		t.Fatalf("NewMountNamespace: %v", err)
	}
	t.Cleanup(func() {
		mntns.DecRef(sctx)
	})
	root := mntns.Root(sctx)
	t.Cleanup(func() {
		root.DecRef(sctx)
	})

	initPop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/init")}
	initFD, err := vfsObj.OpenAt(sctx, creds, initPop, &vfs.OpenOptions{Flags: linux.O_CREAT | linux.O_WRONLY, Mode: 0755})
	if err != nil {
		t.Fatalf("OpenAt(/init): %v", err)
	}
	if _, err := initFD.Write(sctx, usermem.BytesIOSequence(minimalStaticELF64()), vfs.WriteOptions{}); err != nil {
		initFD.DecRef(sctx)
		t.Fatalf("Write(/init): %v", err)
	}
	initFD.DecRef(sctx)

	cgPop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/cgroup")}
	if err := vfsObj.MkdirAt(sctx, creds, cgPop, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(/cgroup): %v", err)
	}
	if _, err := vfsObj.MountAt(sctx, creds, "", cgPop, "cgroup2", &vfs.MountOptions{}); err != nil {
		t.Fatalf("MountAt(/cgroup): %v", err)
	}

	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		t.Fatalf("NewLinuxLimitSet: %v", err)
	}
	fdTable := k.NewFDTable()
	mntns.IncRef()
	tg, _, err := k.CreateProcess(kernel.CreateProcessArgs{
		Filename:             "/init",
		Argv:                 []string{"/init"},
		WorkingDirectory:     "/",
		Credentials:          creds,
		FDTable:              fdTable,
		MountNamespace:       mntns,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         k.RootUTSNamespace(),
		IPCNamespace:         k.RootIPCNamespace(),
		PIDNamespace:         k.RootPIDNamespace(),
		Origin:               kernel.OriginExec,
	})
	fdTable.DecRef(sctx)
	if err != nil {
		t.Fatalf("CreateProcess: %v", err)
	}
	return k, tg.Leader(), root
}

func newCgroupStateCtx(k *kernel.Kernel, creds *auth.Credentials) context.Context {
	return context.WithValues(context.Background(), map[any]any{
		kernel.CtxKernel:          k,
		auth.CtxCredentials:       creds,
		ktime.CtxRealtimeClock:    fixedClock{},
		limits.CtxLimits:          limits.NewLimitSet(),
		uniqueid.CtxInotifyCookie: uint32(1),
	})
}

func readAllFD(t *testing.T, ctx context.Context, fd *vfs.FileDescription) string {
	t.Helper()
	buf := make([]byte, 8192)
	n, err := fd.PRead(ctx, usermem.BytesIOSequence(buf), 0, vfs.ReadOptions{})
	if err != nil {
		t.Fatalf("PRead: %v", err)
	}
	return string(buf[:n])
}

func writeCgroupFile(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path, data string) {
	t.Helper()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_WRONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s, O_WRONLY): %v", path, err)
	}
	defer fd.DecRef(ctx)
	if _, err := fd.Write(ctx, usermem.BytesIOSequence([]byte(data)), vfs.WriteOptions{}); err != nil {
		t.Fatalf("Write(%s, %q): %v", path, data, err)
	}
}

func openCgroupRead(t *testing.T, ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, path string) *vfs.FileDescription {
	t.Helper()
	pop := &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse(path)}
	fd, err := vfsObj.OpenAt(ctx, creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		t.Fatalf("OpenAt(%s, O_RDONLY): %v", path, err)
	}
	return fd
}

func podControllers(cg *cgroup) (*cpu, *memory) {
	cg.fs.treeMu.RLock()
	defer cg.fs.treeMu.RUnlock()
	cc, _ := cg.ctrls[kernel.Cgroup2CPU].(*cpu)
	mc, _ := cg.ctrls[kernel.Cgroup2Memory].(*memory)
	return cc, mc
}

func TestCgroup2FSTier2KernelSaveLoadRoundTrip(t *testing.T) {
	opts := MemoryEnforcerOptions{
		PollInterval:     25 * time.Millisecond,
		IdlePollInterval: 100 * time.Millisecond,
		ScanRatio:        6,
	}
	kOrig, taskOrig, root := bootTestKernelWithInitTask(t, opts)
	sctx := kOrig.SupervisorContext()
	creds := auth.CredentialsFromContext(sctx)
	vfsObj := kOrig.VFS()
	fs := kOrig.Cgroup2FS().(*filesystem)
	t.Cleanup(fs.releaseXplat)

	const wantReportedMem = uint64(512 << 20)
	kOrig.SetReportedMemory(wantReportedMem)
	kOrig.KernelLog().Printk(kernel.LogWarning, "pre-checkpoint-oom")

	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/cgroup.subtree_control", "+cpu +memory\n")
	if err := vfsObj.MkdirAt(sctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/cgroup/pod")}, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(/cgroup/pod): %v", err)
	}
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/pod/memory.max", "67108864\n")
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/pod/memory.oom.group", "1\n")
	writeCgroupFile(t, sctx, vfsObj, creds, root, "/cgroup/pod/cpu.max", "50000 100000\n")

	// Accumulate 20 ms in the root cgroup before migrating PID 1 into /pod, then
	// burn 75 ms inside /pod so baselineCharges and taskCPUMeters are both non-zero.
	taskOrig.SetCPUTimeMeasured(20 * time.Millisecond)
	writeCgroupFile(t, taskOrig.AsyncContext(), vfsObj, creds, root, "/cgroup/pod/cgroup.procs", "1\n")
	taskOrig.SetCPUTimeMeasured(95 * time.Millisecond)

	rawPodCg, err := fs.FindCgroup(sctx, "/pod")
	if err != nil {
		t.Fatalf("FindCgroup(/pod): %v", err)
	}
	_, podMem := podControllers(rawPodCg.(*cgroup))
	podMem.oom.hitMax.Add(2)
	podMem.countOOMEvent(sctx)
	podMem.countOOMKill(sctx)
	podMem.countOOMGroupKill(sctx)

	eventsFD := openCgroupRead(t, sctx, vfsObj, creds, root, "/cgroup/pod/memory.events")
	statFD := openCgroupRead(t, sctx, vfsObj, creds, root, "/cgroup/pod/memory.stat")
	cpuMaxFD := openCgroupRead(t, sctx, vfsObj, creds, root, "/cgroup/pod/cpu.max")
	cpuStatFD := openCgroupRead(t, sctx, vfsObj, creds, root, "/cgroup/pod/cpu.stat")
	fds := []*vfs.FileDescription{eventsFD, statFD, cpuMaxFD, cpuStatFD}
	if _, err := taskOrig.FDTable().NewFDs(sctx, 3, fds, kernel.FDFlags{}); err != nil {
		t.Fatalf("NewFDs: %v", err)
	}
	for _, fd := range fds {
		fd.DecRef(sctx)
	}

	preSaveCPUStat := readAllFD(t, sctx, cpuStatFD)
	if !strings.Contains(preSaveCPUStat, "usage_usec 75000\n") {
		t.Fatalf("pre-save cpu.stat =\n%s\nwant usage_usec 75000", preSaveCPUStat)
	}

	var checkpointBuf bytes.Buffer
	if err := kOrig.SaveTo(
		sctx,
		nopWriteCloser{Writer: &checkpointBuf},
		nil,
		nil,
		false,
		true,
		nil,
		vfs.PrepareSaveOptions{},
		nil,
	); err != nil {
		t.Fatalf("Kernel.SaveTo: %v", err)
	}
	if fs.memEnforcer.running.Load() {
		t.Fatal("memEnforcer remained running during SaveTo before BeforeResume")
	}
	kOrig.BeforeResume(sctx)
	if !fs.memEnforcer.running.Load() {
		t.Fatal("memEnforcer did not resume in BeforeResume")
	}

	mfRestored := newTestKernelMemoryFile(t, "cgroup2fs-restored")
	kRestored := &kernel.Kernel{Platform: testSRPlatform{}}
	kRestored.SetMemoryFile(mfRestored)
	restoreCtx := kRestored.SupervisorContext()
	clocks := sentrytime.NewCalibratedClocks(false)
	if err := kRestored.LoadFrom(
		restoreCtx,
		bytes.NewReader(checkpointBuf.Bytes()),
		nil,
		nil,
		nil,
		clocks,
		&vfs.CompleteRestoreOptions{},
		nil,
	); err != nil {
		t.Fatalf("Kernel.LoadFrom: %v", err)
	}
	t.Cleanup(func() {
		kRestored.Timekeeper().Destroy()
	})
	restoredFS := kRestored.Cgroup2FS().(*filesystem)
	t.Cleanup(restoredFS.releaseXplat)

	restoredTasks := kRestored.TaskSet().Root.Tasks()
	if len(restoredTasks) != 1 {
		t.Fatalf("restored task count = %d, want 1", len(restoredTasks))
	}
	restoredTask := restoredTasks[0]
	getRestoredFD := func(fdNum int32) *vfs.FileDescription {
		t.Helper()
		fd, _ := restoredTask.FDTable().Get(fdNum)
		if fd == nil {
			t.Fatalf("restored FD %d is nil", fdNum)
		}
		t.Cleanup(func() {
			fd.DecRef(kRestored.SupervisorContext())
		})
		return fd
	}
	restoredEventsFD := getRestoredFD(3)
	restoredStatFD := getRestoredFD(4)
	restoredCPUMaxFD := getRestoredFD(5)
	restoredCPUStatFD := getRestoredFD(6)

	loadCtx := kRestored.SupervisorContext()
	eventsText := readAllFD(t, loadCtx, restoredEventsFD)
	for _, wantLine := range []string{"max 3\n", "oom 1\n", "oom_kill 1\n", "oom_group_kill 1\n"} {
		if !strings.Contains(eventsText, wantLine) {
			t.Errorf("restored memory.events =\n%s\nmissing %q", eventsText, wantLine)
		}
	}

	statFields := parseMemoryStat(t, readAllFD(t, loadCtx, restoredStatFD))
	if _, ok := statFields["anon"]; !ok {
		t.Errorf("restored memory.stat lacks anon field: %v", statFields)
	}

	if got := readAllFD(t, loadCtx, restoredCPUMaxFD); got != "50000 100000\n" {
		t.Errorf("restored cpu.max = %q, want \"50000 100000\\n\"", got)
	}

	restoredCPUStat := readAllFD(t, loadCtx, restoredCPUStatFD)
	if !strings.Contains(restoredCPUStat, "usage_usec 75000\n") {
		t.Errorf("restored cpu.stat =\n%s\nwant usage_usec 75000", restoredCPUStat)
	}

	if got := restoredFS.memEnforcer.opts; got != opts {
		t.Errorf("restored memEnforcer.opts = %+v, want %+v", got, opts)
	}
	if !restoredFS.memEnforcer.running.Load() {
		t.Error("memEnforcer did not start in CompleteRestore with an active memory.max limit")
	}

	if gotMem, ok := kRestored.ReportedMemory(); !ok || gotMem != wantReportedMem {
		t.Errorf("restored ReportedMemory = (%d, %t), want (%d, true)", gotMem, ok, wantReportedMem)
	}
	if klog := kRestored.LookupKernelLog(); klog == nil || !strings.Contains(string(klog.ReadAll(4096, false)), "pre-checkpoint-oom") {
		t.Errorf("restored KernelLog was not reattached to kRestored")
	}

	rawRestoredPod, err := restoredFS.FindCgroup(loadCtx, "/pod")
	if err != nil {
		t.Fatalf("restored FindCgroup(/pod): %v", err)
	}
	restoredCPU, _ := podControllers(rawRestoredPod.(*cgroup))
	requireLimit(t, restoredCPU, 50*time.Millisecond, 100*time.Millisecond, true)
}

func TestCgroup2FSStateLoadDefersEnforcerUntilCompleteRestoreAndPreservesLogBufLen(t *testing.T) {
	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	kOrig := &kernel.Kernel{Platform: testSRPlatform{}}
	wantLogCap := kernel.KernelLogMinBufLen * 4
	if !kOrig.SetKernelLogBufLen(wantLogCap) {
		t.Fatal("SetKernelLogBufLen returned false")
	}
	kOrig.SetReportedMemory(256 << 20)
	ctx := newCgroupStateCtx(kOrig, creds)

	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(ctx); err != nil {
		t.Fatalf("VirtualFilesystem.Init: %v", err)
	}
	opts := MemoryEnforcerOptions{
		PollInterval:     25 * time.Millisecond,
		IdlePollInterval: 100 * time.Millisecond,
		ScanRatio:        6,
	}
	vfsfs, err := NewFilesystemWithMemoryOptions(opts)(ctx, kOrig, vfsObj)
	if err != nil {
		t.Fatalf("NewFilesystemWithMemoryOptions: %v", err)
	}
	fs := vfsfs.Impl().(*filesystem)
	fs.root.IncRef()
	mnt := vfsObj.NewDisconnectedMount(vfsfs, fs.root.VFSDentry(), &vfs.MountOptions{})
	root := vfs.MakeVirtualDentry(mnt, fs.root.VFSDentry())
	root.IncRef()
	t.Cleanup(func() {
		root.DecRef(ctx)
		mnt.DecRef(ctx)
		vfsfs.DecRef(ctx)
		vfsObj.Release(ctx)
	})

	writeCgroupFile(t, ctx, vfsObj, creds, root, "/cgroup.subtree_control", "+cpu +memory\n")
	if err := vfsObj.MkdirAt(ctx, creds, &vfs.PathOperation{Root: root, Start: root, Path: fspath.Parse("/pod")}, &vfs.MkdirOptions{Mode: 0755}); err != nil {
		t.Fatalf("MkdirAt(/pod): %v", err)
	}
	writeCgroupFile(t, ctx, vfsObj, creds, root, "/pod/memory.max", "67108864\n")
	writeCgroupFile(t, ctx, vfsObj, creds, root, "/pod/cpu.max", "50000 100000\n")

	if err := vfsObj.PrepareSave(ctx, vfs.PrepareSaveOptions{}); err != nil {
		t.Fatalf("PrepareSave: %v", err)
	}
	bundle := []any{vfsObj, vfsfs, mnt, root, creds}
	var saveBuf bytes.Buffer
	if _, err := state.Save(ctx, &saveBuf, &bundle); err != nil {
		t.Fatalf("state.Save: %v", err)
	}
	savedBytes := saveBuf.Bytes()

	// Simulate ExtractRootfsUpperLayer: load state without calling CompleteRestore,
	// verify memEnforcer stays stopped, and release VFS cleanly.
	kExtract := &kernel.Kernel{Platform: testSRPlatform{}}
	extractCtx := newCgroupStateCtx(kExtract, creds)
	var extracted []any
	if _, err := state.Load(extractCtx, bytes.NewReader(savedBytes), &extracted); err != nil {
		t.Fatalf("state.Load(extract): %v", err)
	}
	extractVFS := extracted[0].(*vfs.VirtualFilesystem)
	extractVFSFS := extracted[1].(*vfs.Filesystem)
	extractMnt := extracted[2].(*vfs.Mount)
	extractRoot := extracted[3].(vfs.VirtualDentry)
	extractFS := extractVFSFS.Impl().(*filesystem)
	if extractFS.memEnforcer.running.Load() {
		t.Fatal("memEnforcer started inside state.Load before CompleteRestore")
	}
	extractRoot.DecRef(extractCtx)
	extractMnt.DecRef(extractCtx)
	extractVFSFS.DecRef(extractCtx)
	extractVFS.Release(extractCtx)

	// Full restore: memEnforcer starts in CompleteRestore, and pre-allocation
	// SetKernelLogBufLen survives onto kRestored.
	kRestored := &kernel.Kernel{Platform: testSRPlatform{}}
	loadCtx := newCgroupStateCtx(kRestored, creds)
	var loaded []any
	if _, err := state.Load(loadCtx, bytes.NewReader(savedBytes), &loaded); err != nil {
		t.Fatalf("state.Load: %v", err)
	}
	restoredVFS := loaded[0].(*vfs.VirtualFilesystem)
	restoredVFSFS := loaded[1].(*vfs.Filesystem)
	restoredMnt := loaded[2].(*vfs.Mount)
	restoredRoot := loaded[3].(vfs.VirtualDentry)
	restoredCreds := loaded[4].(*auth.Credentials)
	restoredFS := restoredVFSFS.Impl().(*filesystem)
	t.Cleanup(func() {
		restoredRoot.DecRef(loadCtx)
		restoredMnt.DecRef(loadCtx)
		restoredVFSFS.DecRef(loadCtx)
		restoredVFS.Release(loadCtx)
	})

	if restoredFS.memEnforcer.running.Load() {
		t.Fatal("memEnforcer started before CompleteRestore")
	}
	loadCtx = newCgroupStateCtx(kRestored, restoredCreds)
	if err := restoredVFS.CompleteRestore(loadCtx, &vfs.CompleteRestoreOptions{}); err != nil {
		t.Fatalf("CompleteRestore: %v", err)
	}
	if !restoredFS.memEnforcer.running.Load() {
		t.Error("memEnforcer did not start in CompleteRestore")
	}
	if got := kRestored.KernelLogBufLen(); got != wantLogCap {
		t.Errorf("restored KernelLogBufLen = %d, want %d", got, wantLogCap)
	}
	if got := kRestored.KernelLog().BufLen(); got != wantLogCap {
		t.Errorf("allocated restored KernelLog().BufLen = %d, want %d", got, wantLogCap)
	}
	if gotMem, ok := kRestored.ReportedMemory(); !ok || gotMem != 256<<20 {
		t.Errorf("restored ReportedMemory = (%d, %t), want (%d, true)", gotMem, ok, 256<<20)
	}
}
