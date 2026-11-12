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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/fd"
	"z.gfire.dev/gvx/pkg/gvx/hostcerts"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/oci"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/inet"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/pgalloc"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/state/stateio"
	sentrytime "z.gfire.dev/gvx/pkg/sentry/time"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// RestoreOptions configures a Restore call.
type RestoreOptions struct {
	// Dir is the host directory containing manifest.json, state.img,
	// pages.meta, and pages.img.
	Dir string
}

// ErrCheckpointManifest reports a checkpoint manifest validation failure.
var ErrCheckpointManifest = errors.New("gvx: invalid checkpoint manifest")

type nopCloseReaderAt struct {
	*os.File
}

func (nopCloseReaderAt) Close() error {
	return nil
}

type restoreNetworkArgs struct {
	sb *Sandbox
}

func (r restoreNetworkArgs) ConfigureNetwork(st inet.Stack) error {
	nsStack, ok := st.(*netstack.Stack)
	if !ok || nsStack == nil || nsStack.Stack == nil {
		return errors.New("gvx: restored root network stack is nil")
	}
	restored := nsStack.Stack
	switch r.sb.cfg.NetworkMode {
	case NetModeNAT:
		if r.sb.natForwarder == nil {
			return errors.New("gvx: NAT forwarder is nil during restore")
		}
		if err := r.sb.natForwarder.AttachRestoredStack(restored); err != nil {
			return fmt.Errorf("gvx: attach restored NAT stack: %w", err)
		}
		if r.sb.portForwarder != nil {
			if err := r.sb.portForwarder.RebindRestore(restored); err != nil {
				return fmt.Errorf("gvx: rebind port forwarder to restored stack: %w", err)
			}
		}
	case NetModeWireGuard:
		if r.sb.wgEndpoint == nil {
			return errors.New("gvx: WireGuard endpoint is nil during restore")
		}
		if err := r.sb.wgEndpoint.AttachRestoredStack(restored); err != nil {
			return fmt.Errorf("gvx: attach restored WireGuard stack: %w", err)
		}
	case NetModeNone:
		if r.sb.netStack != nil && r.sb.netStack != restored {
			r.sb.netStack.Close()
		}
		if err := netbackend.AttachRestoredLoopbackStack(restored); err != nil {
			return fmt.Errorf("gvx: attach restored loopback stack: %w", err)
		}
	default:
		return fmt.Errorf("gvx: unsupported network mode %q during restore", r.sb.cfg.NetworkMode)
	}
	r.sb.netStack = restored
	return nil
}

func readAndParseManifest(dir string) (CheckpointManifest, error) {
	manifestPath := filepath.Join(dir, checkpointManifestFileName)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: read %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	var m CheckpointManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: decode %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	return m, nil
}

func (s *Sandbox) validateCheckpointManifest(m CheckpointManifest) error {
	if m.Version != CheckpointManifestVersion {
		return fmt.Errorf("%w: unsupported version %d (want %d)", ErrCheckpointManifest, m.Version, CheckpointManifestVersion)
	}
	if m.GOOS != runtime.GOOS {
		return fmt.Errorf("%w: host OS mismatch: bundle has %q, current host is %q", ErrCheckpointManifest, m.GOOS, runtime.GOOS)
	}
	if m.GOARCH != runtime.GOARCH {
		return fmt.Errorf("%w: host architecture mismatch: bundle has %q, current host is %q", ErrCheckpointManifest, m.GOARCH, runtime.GOARCH)
	}
	wantArch := s.cfg.Architecture
	if wantArch == "" {
		wantArch = runtime.GOARCH
	}
	if m.Arch != wantArch {
		return fmt.Errorf("%w: guest architecture mismatch: bundle has %q, config has %q", ErrCheckpointManifest, m.Arch, wantArch)
	}
	if m.Platform != s.platName {
		return fmt.Errorf("%w: platform mismatch: bundle has %q, active platform is %q", ErrCheckpointManifest, m.Platform, s.platName)
	}
	wantHoles := platformAddrHoles(s.plat)
	if !slices.Equal(m.UserAddressHoles, wantHoles) {
		return fmt.Errorf("%w: user address holes mismatch: bundle has %v, active platform has %v", ErrCheckpointManifest, m.UserAddressHoles, wantHoles)
	}
	if !slices.Equal(m.LayerDigests, s.layerDigests) {
		return fmt.Errorf("%w: OCI layer digests mismatch: bundle has %v, config resolved %v", ErrCheckpointManifest, m.LayerDigests, s.layerDigests)
	}
	wantMounts := sandboxManifestMounts(s.mounts)
	if !slices.Equal(m.Mounts, wantMounts) {
		return fmt.Errorf("%w: mounts mismatch: bundle has %v, config has %v", ErrCheckpointManifest, m.Mounts, wantMounts)
	}
	if m.NetMode != "" && m.NetMode != s.cfg.NetworkMode {
		return fmt.Errorf("%w: network mode mismatch: bundle has %q, config has %q", ErrCheckpointManifest, m.NetMode, s.cfg.NetworkMode)
	}
	return nil
}

func (s *Sandbox) hasLayerSource() bool {
	return len(s.cfg.OCILayerTars) > 0 || s.cfg.OCIImage != "" || len(s.cfg.ELFBytes) > 0 || s.cfg.BinaryPath != ""
}

func (s *Sandbox) openManifestLayers(digests []string) (err error) {
	if len(digests) == 0 {
		return nil
	}
	cache, err := NewLayerCacheWithTuning(s.cfg.OCICacheDir, s.cfg.Tuning)
	if err != nil {
		return err
	}
	layerFiles, err := cache.OpenLayerHandles(digests)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, oci.CloseLayerFiles(layerFiles))
	}()
	for i, f := range layerFiles {
		layerPath, err := cache.LayerPath(digests[i])
		if err != nil {
			return err
		}
		hh, err := fd.OpenHostPath(layerPath, os.O_RDONLY, 0)
		if err != nil {
			return fmt.Errorf("gvx: open EROFS HostHandle %q: %w", layerPath, err)
		}
		s.layerHandles = append(s.layerHandles, hh)
		s.layerDigests = append(s.layerDigests, normalizeEROFSDigest(digests[i]))
		if err := verifySameLayerFile(f, layerPath); err != nil {
			return err
		}
		info, err := f.Stat()
		if err != nil {
			return fmt.Errorf("gvx: stat EROFS layer %q: %w", layerPath, err)
		}
		s.layerBytes += uint64(info.Size())
	}
	return nil
}

// Restore loads a checkpoint bundle from opts.Dir into a new Sandbox. Restore
// opens all host handles, validates manifest.json, and applies hostlockdown
// before loading untrusted checkpoint pages and kernel state.
func Restore(ctx context.Context, cfg Config, opts RestoreOptions) (*Sandbox, error) {
	initRuntimeGlobals()
	if opts.Dir == "" {
		return nil, fmt.Errorf("%w: RestoreOptions.Dir is empty", ErrInvalidConfig)
	}
	manifest, err := readAndParseManifest(opts.Dir)
	if err != nil {
		return nil, err
	}
	if (cfg.Platform == "" || cfg.Platform == PlatformAuto) && manifest.Platform != "" {
		cfg.Platform = PlatformType(manifest.Platform)
	}
	if cfg.NetworkMode == "" && manifest.NetMode != "" {
		cfg.NetworkMode = manifest.NetMode
	}
	if cfg.Architecture == "" && manifest.Arch != "" {
		cfg.Architecture = manifest.Arch
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	applyHostMemoryDefaults()

	sb := &Sandbox{
		cfg:            cfg,
		kernelReady:    make(chan struct{}),
		runDone:        make(chan struct{}),
		detachDebugLog: attachDebugLogSink(cfg.DebugLog),
	}
	if cfg.HostCACerts {
		roots, err := hostcerts.Collect(ctx, cfg.Warnings)
		if err != nil {
			return nil, fmt.Errorf("gvx: read the host root certificates: %w", err)
		}
		sb.hostCARoots = roots
	}

	var (
		stateFile     *os.File
		pagesMetaFile *os.File
		pagesFile     *os.File
	)
	closeBundleReadFiles := func() error {
		var errs []error
		for _, ptr := range []**os.File{&stateFile, &pagesMetaFile, &pagesFile} {
			if *ptr != nil {
				if cErr := (*ptr).Close(); cErr != nil && !errors.Is(cErr, os.ErrClosed) {
					errs = append(errs, cErr)
				}
				*ptr = nil
			}
		}
		return errors.Join(errs...)
	}

	cleanup := func(cause error) (*Sandbox, error) {
		return nil, errors.Join(cause, closeBundleReadFiles(), sb.Close())
	}

	openReadOnly := func(name string) (*os.File, error) {
		p := filepath.Join(opts.Dir, name)
		f, oErr := os.Open(p)
		if oErr != nil {
			return nil, fmt.Errorf("gvx: open checkpoint file %q: %w", p, oErr)
		}
		return f, nil
	}
	if stateFile, err = openReadOnly(checkpointStateFileName); err != nil {
		return cleanup(err)
	}
	if pagesMetaFile, err = openReadOnly(checkpointPagesMetaFileName); err != nil {
		return cleanup(err)
	}
	if pagesFile, err = openReadOnly(checkpointPagesFileName); err != nil {
		return cleanup(err)
	}

	allowUnconfined := cfg.AllowUnconfinedSystrap || os.Getenv("GVX_ALLOW_NO_HYPERVISOR") == "1"
	opened, err := openPlatform(cfg.Platform, !cfg.DisableHostLockdown, allowUnconfined)
	if err != nil {
		return cleanup(err)
	}
	sb.plat = opened.plat
	sb.platName = opened.name
	sb.fallbackFrom = opened.fallbackFrom

	if sb.hasLayerSource() {
		if err := sb.initOCILayers(ctx); err != nil {
			return cleanup(err)
		}
	} else {
		if err := sb.openManifestLayers(manifest.LayerDigests); err != nil {
			return cleanup(err)
		}
	}

	if err := sb.openMountsForRestore(); err != nil {
		return cleanup(err)
	}

	if err := sb.validateCheckpointManifest(manifest); err != nil {
		return cleanup(err)
	}

	if err := sb.initNetstack(); err != nil {
		return cleanup(err)
	}

	mf, err := createKernelMemoryFile()
	if err != nil {
		return cleanup(err)
	}
	sb.memFile = mf
	sb.attachChunkMemory()

	if cfg.CheckpointDir != "" {
		cf, cErr := openCheckpointBundleFiles(cfg.CheckpointDir)
		if cErr != nil {
			return cleanup(cErr)
		}
		sb.ckptFiles = cf
	}

	if !cfg.DisableHostLockdown {
		st, lErr := hostlockdown.Apply(sb.lockdownOptions())
		if lErr != nil {
			return cleanup(fmt.Errorf("gvx: apply host lockdown: %w", lErr))
		}
		sb.lockdown = st
		installHostLockdownBridges()
		if tb, ok := sb.plat.(interface{ SetThreadInit(func() error) }); ok {
			tb.SetThreadInit(hostlockdown.BindThread)
		}
	}

	hostRAM, _ := hostMemory()
	k := &kernel.Kernel{
		Platform:  sb.plat,
		AllowSUID: sb.cfg.AllowSUID,
	}
	k.SetMemoryFile(mf)
	if sb.cfg.Resources.MemoryBytes > 0 {
		k.SetReportedMemory(reportedMemory(sb.cfg.Resources.MemoryBytes, hostRAM))
	}
	_ = k.SetKernelLogBufLen(int(sb.cfg.Tuning.Size(tuning.KernelLogBufLen)))

	loadCtx := k.SupervisorContext()
	erofsCtx, err := sb.WithRestoreEROFSFDMap(loadCtx)
	if err != nil {
		return cleanup(err)
	}
	loadCtx = erofsCtx.(gvcontext.Context)

	mfMap := make(map[checkpoint.ResourceID]*pgalloc.MemoryFile)
	loadCtx = gvcontext.WithValue(loadCtx, pgalloc.CtxMemoryFileMap, mfMap)

	containerName := cmp.Or(sb.cfg.Name, "gvx-default")
	wsMap := make(map[checkpoint.ResourceID]*hostfs.Workspace)
	volMap := make(map[string]*ext4lite.Volume)
	for _, sm := range sb.mounts {
		if sm.workspace != nil {
			id := checkpoint.ResourceID{
				ContainerName: containerName,
				Path:          sm.GuestPath,
			}
			wsMap[id] = sm.workspace
		}
		if sm.volume != nil {
			volMap[sm.GuestPath] = sm.volume
		}
	}
	if len(wsMap) > 0 {
		loadCtx = hostfs.WithRestoreWorkspacesContext(loadCtx, wsMap)
	}
	if len(volMap) > 0 {
		loadCtx = ext4lite.WithRestoreVolumeMap(loadCtx, volMap)
	}

	rawHost := false
	if sb.cfg.TTY || isHostTerminalReader(sb.cfg.Stdin) {
		rawHost = isHostTerminal(sb.cfg.Stdin) || isHostTerminal(sb.cfg.Stdout)
	}
	collector := &restoreStdioCollector{}
	loadCtx = withRestoreCollector(loadCtx, collector).(gvcontext.Context)
	loadCtx = WithRestoreStdio(loadCtx, RestoreStdio{
		Stdin:   sb.cfg.Stdin,
		Stdout:  sb.cfg.Stdout,
		Stderr:  sb.cfg.Stderr,
		RawHost: &rawHost,
	}).(gvcontext.Context)
	loadCtx = WithRestoreNetnsHook(loadCtx, nil).(gvcontext.Context)

	pagesMetaReader := stateio.NewBufioReadCloser(io.NopCloser(pagesMetaFile))
	pagesAsyncReader := stateio.NewIOReader(nopCloseReaderAt{pagesFile}, 4<<20, 1024, 4)
	asyncMFLoader := kernel.NewAsyncMFLoader(pagesMetaReader, pagesAsyncReader, mf, nil, pgalloc.AsyncPagesFileLoadOpts{})
	asyncMFLoader.KickoffPrivate(loadCtx, mfMap)

	stateReader := stateio.NewBufioReadCloser(io.NopCloser(stateFile))
	vfsOpts := &vfs.CompleteRestoreOptions{
		ValidateFileSizes:                  true,
		ValidateFileModificationTimestamps: true,
	}
	clocks := sentrytime.NewCalibratedClocks(false)
	loadErr := k.LoadFrom(
		loadCtx,
		stateReader,
		asyncMFLoader,
		nil,
		restoreNetworkArgs{sb: sb},
		clocks,
		vfsOpts,
		nil,
	)
	_ = stateReader.Close()
	waitErr := asyncMFLoader.Wait()
	closeErr := closeBundleReadFiles()
	if loadErr != nil || waitErr != nil || closeErr != nil {
		if tk := k.Timekeeper(); tk != nil {
			tk.Destroy()
		}
		return cleanup(errors.Join(loadErr, waitErr, closeErr))
	}

	k.IncCheckpointGenOnRestore()
	sb.restoredKernel = k
	sb.restoredStdio = collector
	return sb, nil
}
