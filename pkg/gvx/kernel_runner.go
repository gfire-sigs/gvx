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

package gvx

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/cpuid"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/memutil"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/limits"
	"z.gfire.dev/gvx/pkg/sentry/loader"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/socket/netfilter"
	"z.gfire.dev/gvx/pkg/sentry/strace"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/usage"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
	"z.gfire.dev/gvx/pkg/sentry/watchdog"

	// Register Linux syscall tables and socket families in the Sentry kernel.
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/genetlink/wireguard"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/netfilter"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/route"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/netlink/uevent"
	_ "z.gfire.dev/gvx/pkg/sentry/socket/unix"
	_ "z.gfire.dev/gvx/pkg/sentry/syscalls/linux"
)

type logMultiplexer struct {
	mu     sync.RWMutex
	base   log.Emitter
	nextID uint64
	sinks  map[uint64]*log.Writer
}

func (m *logMultiplexer) setBase(e log.Emitter) {
	m.mu.Lock()
	m.base = e
	m.mu.Unlock()
}

func (m *logMultiplexer) attach(w io.Writer) func() {
	if w == nil {
		return nil
	}
	m.mu.Lock()
	if m.sinks == nil {
		m.sinks = make(map[uint64]*log.Writer)
	}
	m.nextID++
	id := m.nextID
	m.sinks[id] = &log.Writer{Next: w}
	m.mu.Unlock()
	return sync.OnceFunc(func() {
		m.mu.Lock()
		delete(m.sinks, id)
		m.mu.Unlock()
	})
}

func (m *logMultiplexer) Emit(depth int, level log.Level, timestamp time.Time, format string, v ...any) {
	m.mu.RLock()
	base := m.base
	var sinks []*log.Writer
	if len(m.sinks) > 0 {
		sinks = make([]*log.Writer, 0, len(m.sinks))
		for _, sink := range m.sinks {
			sinks = append(sinks, sink)
		}
	}
	m.mu.RUnlock()

	if base != nil {
		base.Emit(depth+1, level, timestamp, format, v...)
	}
	for _, sink := range sinks {
		sink.Emit(depth+1, level, timestamp, format, v...)
	}
}

var (
	runtimeGlobalsOnce sync.Once
	runtimeLogMux      logMultiplexer
)

func initRuntimeGlobals() {
	runtimeGlobalsOnce.Do(func() {
		if os.Getenv("GVX_DEBUG_LOG") != "" || os.Getenv("GVX_STRACE") != "" {
			runtimeLogMux.setBase(&log.Writer{Next: os.Stderr})
		}
		log.SetTarget(&runtimeLogMux)
		if os.Getenv("GVX_DEBUG_LOG") == "2" {
			log.SetLevel(log.Debug)
		}
		if os.Getenv("GVX_STRACE") != "" {
			strace.Initialize()
			strace.EnableAll(strace.SinkTypeLog)
		}
		cpuid.Initialize()
		_ = usage.Init()
		if usage.MemoryAccounting == nil {
			usage.MemoryAccounting = usage.NewMemoryLocked()
		}
	})
}

func attachDebugLogSink(w io.Writer) func() {
	initRuntimeGlobals()
	return runtimeLogMux.attach(w)
}

func init() {
	initRuntimeGlobals()
}

// guestFeatureSetter is a platform whose guests use fewer CPU features than
// the host. whpx on amd64 is one: its partition exposes only the vector state
// that it saves and restores.
type guestFeatureSetter interface {
	GuestFeatureSet(host cpuid.FeatureSet) cpuid.FeatureSet
}

// guestFeatureSet returns the CPU features that guests of plat can use. The
// Sentry derives /proc/cpuinfo, signal frames, and sigreturn checks from it.
func guestFeatureSet(plat platform.Platform) cpuid.FeatureSet {
	if g, ok := plat.(guestFeatureSetter); ok {
		return g.GuestFeatureSet(cpuid.HostFeatureSet())
	}
	return cpuid.HostFeatureSet()
}

// errRunConsumed reports a second Run call. The first Run consumes the kernel
// MemoryFile, and the host lockdown denies the creation of a new one.
var errRunConsumed = errors.New("gvx: Sandbox.Run already ran and consumed the kernel memory file")

// createKernelMemoryFile creates the Sentry MemoryFile on an anonymous host
// backing file. New calls it before the host lockdown because the lockdown
// denies new host file creation.
func createKernelMemoryFile() (*pgalloc.MemoryFile, error) {
	const memFileName = "gvx-kernel-memory"
	memFD, err := memutil.CreateMemFD(memFileName, 0)
	if err != nil {
		return nil, fmt.Errorf("gvx: create memory backing file: %w", err)
	}
	memFile := os.NewFile(uintptr(memFD), memFileName)
	if err := memutil.VerifyExecMapping(memFD); err != nil {
		return nil, errors.Join(fmt.Errorf("gvx: %w", err), memFile.Close())
	}
	// A sandbox counts its own memory. The global usage.MemoryAccounting sums
	// every kernel of the process, and the memory cgroup IDs of two kernels
	// overlap.
	mf, err := pgalloc.NewMemoryFile(memFile, pgalloc.MemoryFileOpts{Accounting: usage.NewMemoryLocked()})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("gvx: init pgalloc.MemoryFile: %w", err), memFile.Close())
	}
	return mf, nil
}

func createSandboxLimitSet() (*limits.LimitSet, error) {
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return nil, err
	}
	ls.SetUnchecked(limits.NumberOfFiles, limits.Limit{Cur: 65536, Max: 65536})
	ls.SetUnchecked(limits.AS, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Data, limits.Limit{Cur: limits.Infinity, Max: limits.Infinity})
	ls.SetUnchecked(limits.Stack, limits.Limit{Cur: 8 * 1024 * 1024, Max: limits.Infinity})
	ls.SetUnchecked(limits.ProcessCount, limits.Limit{Cur: 4096, Max: 4096})
	return ls, nil
}

func (s *Sandbox) setActiveKernel(k *kernel.Kernel, dog *watchdog.Watchdog) {
	s.mu.Lock()
	s.activeKernel = k
	s.activeWatchdog = dog
	s.mu.Unlock()
	if s.kernelReady != nil {
		s.kernelReadyOnce.Do(func() {
			close(s.kernelReady)
		})
	}
}

func (s *Sandbox) clearActiveKernel() {
	s.mu.Lock()
	s.activeKernel = nil
	s.activeWatchdog = nil
	s.mu.Unlock()
}

func (s *Sandbox) closeRunDone() {
	if s.runDone != nil {
		s.runDoneOnce.Do(func() {
			close(s.runDone)
		})
	}
}

func (s *Sandbox) hasRestoredKernel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.restoredKernel != nil
}

func (s *Sandbox) runWithKernel(ctx context.Context, argv []string) (int, error) {
	defer s.closeRunDone()
	initRuntimeGlobals()
	if s.detachDebugLog == nil && s.cfg.DebugLog != nil {
		if detach := attachDebugLogSink(s.cfg.DebugLog); detach != nil {
			defer detach()
		}
	}
	if len(argv) == 0 {
		return 1, fmt.Errorf("gvx: empty command vector")
	}

	s.mu.Lock()
	mf := s.memFile
	s.memFile = nil
	s.mu.Unlock()
	if mf == nil {
		return 1, errRunConsumed
	}
	defer mf.Destroy()

	hostRAM, _ := hostMemory()
	k, tk, creds, cleanupNetLog, err := s.initFreshKernel(mf, hostRAM)
	if err != nil {
		return 1, err
	}
	defer tk.Destroy()
	defer cleanupNetLog()

	sctx := k.SupervisorContext()
	mntns, err := s.buildKernelRootMountNamespace(sctx, k, creds)
	if err != nil {
		return 1, err
	}
	mntnsOwned := true
	defer func() {
		if mntnsOwned {
			mntns.DecRef(sctx)
		}
	}()

	root := mntns.Root(sctx)
	rootOwned := true
	defer func() {
		if rootOwned {
			root.DecRef(sctx)
		}
	}()
	sctxWithRoot := vfs.WithRoot(sctx, root)

	if err := s.setupKernelSubmountsAndFiles(sctxWithRoot, k.VFS(), creds, root); err != nil {
		return 1, err
	}

	tg, cleanupStdio, err := s.createInitialGuestProcess(ctx, sctx, sctxWithRoot, k, creds, mntns, root, argv)
	if cleanupStdio != nil {
		defer cleanupStdio()
	}
	if err != nil {
		return 1, err
	}
	// Drop the setup references on root and mntns so only the guest tasks own
	// the mount namespace while the sandbox runs.
	root.DecRef(sctx)
	rootOwned = false
	mntns.DecRef(sctx)
	mntnsOwned = false

	return s.executeActiveKernel(ctx, k, tg, mf, hostRAM, "gvx: start Sentry kernel")
}

// initFreshKernel initializes a new Sentry kernel, timekeeper, VDSO, network
// namespace, and VFS registry on top of mf.
func (s *Sandbox) initFreshKernel(mf *pgalloc.MemoryFile, hostRAM uint64) (*kernel.Kernel, *kernel.Timekeeper, *auth.Credentials, func(), error) {
	k := &kernel.Kernel{
		Platform:  s.plat,
		AllowSUID: s.cfg.AllowSUID,
	}
	k.SetMemoryFile(mf)
	if s.cfg.Resources.MemoryBytes > 0 {
		k.SetReportedMemory(reportedMemory(s.cfg.Resources.MemoryBytes, hostRAM))
	}

	vdso, err := loader.PrepareVDSO(mf)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("gvx: prepare VDSO: %w", err)
	}

	tk := kernel.NewTimekeeper()
	paramsRange, err := mf.Allocate(hostarch.PageSize, pgalloc.AllocOpts{Kind: usage.System})
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("gvx: allocate VDSO param page: %w", err)
	}
	vdsoParams := kernel.NewVDSOParamPage(mf, paramsRange)
	tk.SetClocks(sentrytime.NewCalibratedClocks(false), vdsoParams)

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())
	rootNetNS, cleanupNetLog := s.initKernelRootNetworkNamespace(k, creds)

	if err := s.initKernelInstance(k, tk, creds, rootNetNS, vdso, vdsoParams); err != nil {
		cleanupNetLog()
		tk.Destroy()
		return nil, nil, nil, nil, err
	}
	if err := registerKernelVFS(k.VFS(), rootNetNS); err != nil {
		cleanupNetLog()
		tk.Destroy()
		return nil, nil, nil, nil, err
	}
	return k, tk, creds, cleanupNetLog, nil
}

func (s *Sandbox) initKernelInstance(k *kernel.Kernel, tk *kernel.Timekeeper, creds *auth.Credentials, rootNetNS *inet.Namespace, vdso *loader.VDSO, vdsoParams *kernel.VDSOParamPage) error {
	maxCPUs := max(runtime.NumCPU(), 1)
	if err := k.Init(kernel.InitKernelArgs{
		FeatureSet:           guestFeatureSet(s.plat),
		Timekeeper:           tk,
		RootUserNamespace:    creds.UserNamespace,
		RootNetworkNamespace: rootNetNS,
		ApplicationCores:     uint(guestCPUs(s.cfg.Resources.CPUMillis, maxCPUs)),
		Vdso:                 vdso,
		VdsoParams:           vdsoParams,
		RootUTSNamespace:     kernel.NewUTSNamespace(s.hostname(), "localdomain", creds.UserNamespace),
		RootIPCNamespace:     kernel.NewIPCNamespace(creds.UserNamespace),
		RootPIDNamespace:     kernel.NewRootPIDNamespace(creds.UserNamespace),
		MaxFDLimit:           kernel.MaxFdLimit,
		Cgroup2FSInit: cgroup2fs.NewFilesystemWithMemoryOptions(cgroup2fs.MemoryEnforcerOptions{
			PollInterval:     s.cfg.Tuning.Duration(tuning.MemoryCgroupPollInterval),
			IdlePollInterval: s.cfg.Tuning.Duration(tuning.MemoryCgroupIdlePollInterval),
			ScanRatio:        s.cfg.Tuning.Int(tuning.MemoryCgroupScanRatio),
		}),
	}); err != nil {
		return fmt.Errorf("gvx: init Sentry kernel: %w", err)
	}
	if !k.SetKernelLogBufLen(int(s.cfg.Tuning.Size(tuning.KernelLogBufLen))) {
		return errors.New("gvx: the kernel log exists before its size is set")
	}
	k.KernelLog().WriteBootMessages()
	return nil
}

// createInitialGuestProcess resolves the target executable, user credentials,
// stdio descriptors, and limits, then creates the initial thread group in k.
func (s *Sandbox) createInitialGuestProcess(ctx context.Context, sctx, sctxWithRoot gvcontext.Context, k *kernel.Kernel, creds *auth.Credentials, mntns *vfs.MountNamespace, root vfs.VirtualDentry, argv []string) (*kernel.ThreadGroup, func(), error) {
	vfsObj := k.VFS()
	execPath, err := resolveGuestExecutable(sctxWithRoot, vfsObj, creds, root, argv[0], s.cfg.Envv)
	if err != nil {
		return nil, nil, err
	}
	readGuest := buildCachedGuestReader(sctxWithRoot, vfsObj, creds, root, execPath)

	user, procCreds, err := s.guestUser(sctxWithRoot, vfsObj, creds, root)
	if err != nil {
		return nil, nil, err
	}

	fdTable := k.NewFDTable()
	tty, cleanupStdio, err := s.setupKernelStdio(ctx, sctx, vfsObj, creds, fdTable)
	if err != nil {
		fdTable.DecRef(sctx)
		return nil, nil, err
	}

	ls, err := createSandboxLimitSet()
	if err != nil {
		fdTable.DecRef(sctx)
		return nil, cleanupStdio, err
	}

	var procTTY *kernel.TTY
	if tty != nil {
		procTTY = tty.ktty
	}

	mntns.IncRef()
	procArgs := kernel.CreateProcessArgs{
		Filename:             execPath,
		Argv:                 argv,
		Envv:                 finalizeEnv(s.cfg.Envv, guestEnvDefaults{Home: user.Home, Hostname: s.hostname(), TTY: tty != nil}),
		WorkingDirectory:     s.initialWorkingDir(),
		Credentials:          procCreds,
		FDTable:              fdTable,
		MountNamespace:       mntns,
		Umask:                0o022,
		Limits:               ls,
		MaxSymlinkTraversals: linux.MaxSymlinkTraversals,
		UTSNamespace:         k.RootUTSNamespace(),
		IPCNamespace:         k.RootIPCNamespace(),
		Origin:               kernel.OriginExec,
		ContainerID:          cmp.Or(s.cfg.Name, "gvx-default"),
		PIDNamespace:         k.RootPIDNamespace(),
		TTY:                  procTTY,
	}

	tg, _, err := k.CreateProcess(procArgs)
	// CreateProcess takes its own reference on fdTable. Drop this one now, as
	// runsc does, so the last reference drops when the guest closes the table
	// in a task context. The Release of a netlink socket needs that context,
	// and a guest init such as systemd exits with netlink sockets open.
	fdTable.DecRef(sctx)
	if err != nil {
		if hint := s.nonPIEHintForGuestFile(readGuest, execPath); hint != "" {
			err = fmt.Errorf("%w; %s", err, hint)
		}
		return nil, cleanupStdio, fmt.Errorf("gvx: create guest process %q: %w", execPath, err)
	}
	if tty != nil {
		tty.startPump()
	}
	return tg, cleanupStdio, nil
}

func (s *Sandbox) initialWorkingDir() string {
	workDir := s.cfg.WorkDir
	if (workDir == "" || workDir == "/") && s.resolvedImg != nil && s.resolvedImg.Config.WorkingDir != "" {
		workDir = s.resolvedImg.Config.WorkingDir
	}
	if workDir == "" {
		return "/"
	}
	return workDir
}

func buildCachedGuestReader(sctxWithRoot gvcontext.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry, execPath string) func(string, int) ([]byte, error) {
	var (
		cachedExecHeader []byte
		cachedExecErr    error
		cachedExecOnce   sync.Once
	)
	return func(path string, maxBytes int) ([]byte, error) {
		if path == execPath && maxBytes == elfProbeBytes {
			cachedExecOnce.Do(func() {
				cachedExecHeader, cachedExecErr = readGuestFile(sctxWithRoot, vfsObj, creds, root, path, maxBytes)
			})
			return cachedExecHeader, cachedExecErr
		}
		return readGuestFile(sctxWithRoot, vfsObj, creds, root, path, maxBytes)
	}
}

func (s *Sandbox) runRestoredKernel(ctx context.Context) (int, error) {
	defer s.closeRunDone()
	initRuntimeGlobals()
	if s.detachDebugLog == nil && s.cfg.DebugLog != nil {
		if detach := attachDebugLogSink(s.cfg.DebugLog); detach != nil {
			defer detach()
		}
	}

	s.mu.Lock()
	k := s.restoredKernel
	s.restoredKernel = nil
	collector := s.restoredStdio
	s.restoredStdio = nil
	mf := s.memFile
	s.memFile = nil
	s.mu.Unlock()
	if k == nil || mf == nil {
		return 1, errRunConsumed
	}
	defer mf.Destroy()
	if tk := k.Timekeeper(); tk != nil {
		defer tk.Destroy()
	}
	if s.netStack != nil {
		netfilter.SetStackLog(s.netStack, kernelLogFunc(k))
		defer netfilter.SetStackLog(s.netStack, nil)
	}

	tg := k.GlobalInit()
	if tg == nil {
		return 1, errors.New("gvx: restored kernel has no global init process")
	}

	cleanupStdio := s.activateRestoredStdio(ctx, tg, collector)
	defer cleanupStdio()

	hostRAM, _ := hostMemory()
	return s.executeActiveKernel(ctx, k, tg, mf, hostRAM, "gvx: start restored Sentry kernel")
}

// executeActiveKernel starts k, attaches the watchdog and memory guard, waits
// for guest exit or cancellation, and translates the exit status.
func (s *Sandbox) executeActiveKernel(ctx context.Context, k *kernel.Kernel, tg *kernel.ThreadGroup, mf *pgalloc.MemoryFile, hostRAM uint64, startErrPrefix string) (int, error) {
	if err := k.Start(); err != nil {
		return 1, fmt.Errorf("%s: %w", startErrPrefix, err)
	}
	// The watchdog logs the stacks of a task that stays in the Sentry for a
	// long time. GVX_DEBUG_LOG shows the log.
	dog := watchdog.New(k, watchdog.DefaultOpts)
	dog.Start()
	defer dog.Stop()

	s.setActiveKernel(k, dog)
	defer s.clearActiveKernel()

	doneCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		case <-doneCh:
		}
	}()

	var memoryExceeded atomic.Bool
	stopGuard := s.startKernelMemoryGuard(ctx, k, tg, mf, hostRAM, &memoryExceeded)
	defer stopGuard()

	tg.WaitExited()
	s.ckptMu.Lock()
	s.clearActiveKernel()
	k.WaitExited()
	s.ckptMu.Unlock()
	close(doneCh)
	k.Pause()

	return s.collectKernelExitStatus(ctx, k, tg, &memoryExceeded)
}

func (s *Sandbox) startKernelMemoryGuard(ctx context.Context, k *kernel.Kernel, tg *kernel.ThreadGroup, mf *pgalloc.MemoryFile, hostRAM uint64, memoryExceeded *atomic.Bool) func() {
	limit, interval := effectiveMemoryLimit(s.cfg.Resources.MemoryBytes, hostRAM, s.cfg.Tuning)
	if limit == 0 {
		return func() {}
	}
	guard := memoryGuard{
		limit: limit,
		// The accounting counts a committed page only after a scan of the
		// memory file. UpdateUsage limits its own scan rate. The accounting
		// belongs to this memory file (see createKernelMemoryFile), so it
		// does not hold the pages of the other sandboxes of the process.
		used: func() uint64 {
			_ = mf.UpdateUsage(nil)
			return mf.Accounting().Total()
		},
		flushScan:    mf.FlushCommitScan,
		idleActivity: k.IdleTaskActivityChan,
		interval:     interval,
		kill: func() {
			memoryExceeded.Store(true)
			_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		},
	}
	guardCtx, stopGuard := context.WithCancel(ctx)
	guardDone := make(chan struct{})
	go func() {
		defer close(guardDone)
		guard.run(guardCtx)
	}()
	return func() {
		stopGuard()
		<-guardDone
	}
}

func (s *Sandbox) collectKernelExitStatus(ctx context.Context, k *kernel.Kernel, tg *kernel.ThreadGroup, memoryExceeded *atomic.Bool) (int, error) {
	if s.checkpointStopped.Load() {
		return 0, nil
	}
	if ctx.Err() != nil {
		return 1, ctx.Err()
	}
	if memoryExceeded.Load() {
		return 137, ErrMemoryLimit
	}

	ws := tg.ExitStatus()
	if ws.Signaled() && ws.TerminationSignal() == linux.SIGKILL {
		if cause := k.TakeEngineFault(); cause != "" {
			return 128 + int(linux.SIGKILL), engineFaultError(cause)
		}
	}
	if ws.Signaled() {
		return 128 + int(ws.TerminationSignal()), nil
	}
	return int(ws.ExitStatus()), nil
}
