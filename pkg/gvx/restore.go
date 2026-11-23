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
	// TrustLegacyCheckpoint allows importing a trusted version 1 checkpoint,
	// which may lack saved guest firewall rules. It never relaxes validation
	// of version 3 or 5 checkpoints or of rules that are present.
	TrustLegacyCheckpoint bool
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
	// eth0 holds the eth0 settings that the checkpoint recorded in NAT mode.
	// It is nil when the manifest has none.
	eth0 *netbackend.Eth0Config
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
		if err := r.sb.natForwarder.AttachRestoredStackWithConfig(restored, r.eth0); err != nil {
			return fmt.Errorf("gvx: attach restored NAT stack: %w", err)
		}
		if r.sb.portForwarder != nil {
			if err := r.sb.portForwarder.RebindRestore(restored); err != nil {
				return fmt.Errorf("gvx: rebind port forwarder to restored stack: %w", err)
			}
		}
		// The guest stack of New is dead now: the forwarder moved to the
		// restored stack. Close it, or its timers and goroutines leak.
		if r.sb.netStack != nil && r.sb.netStack != restored {
			r.sb.netStack.Close()
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

func stopRestoredKernelTimers(k *kernel.Kernel) {
	if root := k.RootNetworkNamespace(); root != nil {
		stop := func(st inet.Stack) {
			if ns, ok := st.(*netstack.Stack); ok && ns != nil && ns.Stack != nil {
				ns.Stack.StopRestoredIPTablesReaper()
			}
		}
		stop(root.Stack())
		root.ForEachChildStack(stop)
	}
	if tk := k.Timekeeper(); tk != nil {
		tk.Destroy()
	}
}

// maxManifestBytes bounds the size of manifest.json. A manifest of 1 MiB
// holds thousands of mounts, so a larger file is corrupt.
const maxManifestBytes = 1 << 20

// readManifestBytes reads manifest.json from path and fails when the file is
// larger than maxManifestBytes, before the whole file reaches memory.
func (b *bundleRoot) readManifestBytes() ([]byte, error) {
	f, err := b.openFile(checkpointManifestFileName, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("file exceeds %d bytes", maxManifestBytes)
	}
	return data, nil
}

func (b *bundleRoot) readAndParseManifest() (CheckpointManifest, error) {
	manifestPath := filepath.Join(b.path, checkpointManifestFileName)
	data, err := b.readManifestBytes()
	if err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: read %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	var decoded struct {
		CheckpointManifest
		LegacyNetPolicy json.RawMessage `json:"net_policy"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: decode %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	if len(decoded.LegacyNetPolicy) != 0 && string(decoded.LegacyNetPolicy) != "null" {
		return CheckpointManifest{}, fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "checkpoint manifest contains obsolete network policy metadata"))
	}
	return decoded.CheckpointManifest, nil
}

func (s *Sandbox) validateCheckpointManifest(m CheckpointManifest) error {
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
	hasRootVol := s.rootVolume != nil
	if m.RootVolume != hasRootVol {
		return fmt.Errorf("%w: root volume mismatch: bundle has %v, config has %v", ErrCheckpointManifest, m.RootVolume, hasRootVol)
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

// restorePlatform returns the backend of a restored sandbox. An explicit
// request of the caller wins. Without one, the bundle names the backend,
// because the saved state fits only the backend that wrote it.
//
// The bundle is untrusted input, so it cannot give the permission that
// openPlatform requires for Windows systrap. When the bundle names systrap on
// Windows, the caller must permit it.
func restorePlatform(goos string, requested PlatformType, manifestPlatform string, allowUnconfinedSystrap bool) (PlatformType, error) {
	if requested != "" && requested != PlatformAuto {
		return requested, nil
	}
	if manifestPlatform == "" {
		return requested, nil
	}
	fromBundle := PlatformType(manifestPlatform)
	if goos == "windows" && fromBundle == PlatformSystrap && !allowUnconfinedSystrap {
		return "", fmt.Errorf("gvx: the checkpoint bundle names Windows systrap, which lacks hardware or kernel syscall isolation; set Config.Platform to systrap (-platform=systrap) or set Config.AllowUnconfinedSystrap (-allow-unconfined-systrap): %w", ErrPlatformUnavailable)
	}
	return fromBundle, nil
}

// Restore loads a checkpoint bundle from opts.Dir into a new Sandbox. Restore
// opens all host handles, validates manifest.json, and applies hostlockdown
// before loading untrusted checkpoint pages and kernel state.
//
// Restore takes ownership of Config.CheckpointListener on every call. When
// Restore fails, it closes the listener.
func Restore(ctx context.Context, cfg Config, opts RestoreOptions) (_ *Sandbox, retErr error) {
	if ln := cfg.CheckpointListener; ln != nil {
		defer func() {
			if retErr != nil {
				_ = ln.Close()
			}
		}()
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("%w: RestoreOptions.Dir is empty", ErrInvalidConfig)
	}
	bundle, err := openBundleRoot(opts.Dir, cfg.NetPolicy != nil)
	if err != nil {
		return nil, fmt.Errorf("%w: open bundle %q: %w", ErrCheckpointManifest, opts.Dir, err)
	}
	defer bundle.Close()
	manifest, err := bundle.readAndParseManifest()
	if err != nil {
		return nil, err
	}
	if err := manifest.validateVersion(); err != nil {
		return nil, err
	}
	var (
		sb            *Sandbox
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
		readErr := closeBundleReadFiles()
		if sb == nil {
			return nil, errors.Join(cause, readErr)
		}
		return nil, errors.Join(cause, readErr, sb.Close())
	}
	openReadOnly := func(name string) (*os.File, error) {
		p := filepath.Join(opts.Dir, name)
		f, oErr := bundle.openFile(name, os.O_RDONLY, 0)
		if oErr != nil {
			return nil, fmt.Errorf("gvx: open checkpoint file %q: %w", p, oErr)
		}
		return f, nil
	}
	if stateFile, err = openReadOnly(checkpointStateFileName); err != nil {
		return cleanup(err)
	}
	if _, err := manifest.statePayloadOffset(stateFile); err != nil {
		return cleanup(err)
	}
	networkCheckpointMode := inet.RequireNetworkCheckpoint
	if manifest.Version == legacyCheckpointManifestVersion {
		if !opts.TrustLegacyCheckpoint {
			return cleanup(fmt.Errorf("%w: version 1 restore requires TrustLegacyCheckpoint", ErrCheckpointManifest))
		}
		networkCheckpointMode = inet.ImportLegacyNetworkCheckpoint
	}
	if manifest.Version == protectedCheckpointManifestVersion {
		if cfg.NetPolicy == nil {
			return cleanup(netPolicyError("policy_required", "a protected checkpoint requires an explicit network policy"))
		}
		if cfg.NetworkMode != "" && cfg.NetworkMode != NetModeNAT {
			return cleanup(fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "a protected checkpoint requires NAT mode")))
		}
	}

	initRuntimeGlobals()
	allowUnconfined := cfg.AllowUnconfinedSystrap || os.Getenv("GVX_ALLOW_NO_HYPERVISOR") == "1"
	if cfg.Platform, err = restorePlatform(runtime.GOOS, cfg.Platform, manifest.Platform, allowUnconfined); err != nil {
		return cleanup(err)
	}
	if cfg.NetworkMode == "" && manifest.NetMode != "" {
		cfg.NetworkMode = manifest.NetMode
	}
	if cfg.Architecture == "" && manifest.Arch != "" {
		cfg.Architecture = manifest.Arch
	}
	if err := cfg.normalizeWithMode(len(manifest.LayerDigests) > 0); err != nil {
		return cleanup(err)
	}
	if manifest.RootVolume != (cfg.RootVolume != "") {
		return cleanup(fmt.Errorf("%w: root volume mismatch: bundle has %v, config has %v", ErrCheckpointManifest, manifest.RootVolume, cfg.RootVolume != ""))
	}
	applyHostMemoryDefaults()

	sb = &Sandbox{
		cfg:            cfg,
		kernelReady:    make(chan struct{}),
		runDone:        make(chan struct{}),
		detachDebugLog: attachDebugLogSink(cfg.DebugLog),
	}
	if cfg.HostCACerts {
		roots, err := hostcerts.Collect(ctx, cfg.Warnings)
		if err != nil {
			return cleanup(fmt.Errorf("gvx: read the host root certificates: %w", err))
		}
		sb.hostCARoots = roots
	}
	if err := sb.initNetPolicy(bundle); err != nil {
		return cleanup(err)
	}
	if pagesMetaFile, err = openReadOnly(checkpointPagesMetaFileName); err != nil {
		return cleanup(err)
	}
	if pagesFile, err = openReadOnly(checkpointPagesFileName); err != nil {
		return cleanup(err)
	}
	if sb.policyStorage != nil {
		sb.policyStorage.files = append(sb.policyStorage.files, bundle.identities...)
	}

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

	hostRAM, _ := hostMemory()
	restoreLimit, _ := effectiveMemoryLimit(sb.cfg.Resources.MemoryBytes, hostRAM, sb.cfg.Tuning)
	mf, err := createKernelMemoryFile(restoreFileLimit(restoreLimit, manifest.MemoryLimitBytes), sb.platName == "systrap")
	if err != nil {
		return cleanup(err)
	}
	sb.memFile = mf
	sb.attachChunkMemory()

	if cfg.CheckpointDir != "" {
		cf, cErr := sb.openCheckpointOutput()
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

	// Recheck the retained file before decoding any saved state.
	stateOffset, err := manifest.statePayloadOffset(stateFile)
	if err != nil {
		return cleanup(err)
	}
	if stateOffset != 0 {
		if _, err := stateFile.Seek(stateOffset, io.SeekStart); err != nil {
			return cleanup(fmt.Errorf("gvx: seek checkpoint payload: %w", err))
		}
	}

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
	// Close the descriptors that no restored filesystem claims, whether
	// LoadFrom succeeds, fails, or panics.
	restoreFDMap := vfs.RestoreFilesystemFDMapFromContext(loadCtx)
	defer func() { _ = closeRestoreFDMap(restoreFDMap) }()

	mfMap := make(map[checkpoint.ResourceID]*pgalloc.MemoryFile)
	loadCtx = gvcontext.WithValue(loadCtx, pgalloc.CtxMemoryFileMap, mfMap)

	containerName := cmp.Or(sb.cfg.Name, "gvx-default")
	wsMap := make(map[checkpoint.ResourceID]*hostfs.Workspace)
	volMap := make(map[string]*ext4lite.Volume)
	if sb.rootVolume != nil {
		volMap[rootVolumeUniqueID] = sb.rootVolume
	}
	for _, sm := range sb.mounts {
		if sm.workspace != nil {
			if err := sm.workspace.ValidateRestoreBinding(); err != nil {
				return cleanup(fmt.Errorf("gvx: restore host mount %s: %w", sm.GuestPath, err))
			}
			id := checkpoint.ResourceID{
				ContainerName: containerName,
				Path:          sm.GuestPath,
			}
			wsMap[id] = sm.workspace
		}
		if sm.Kind == MountOverlay {
			if sm.volume != nil {
				volMap[overlayLowerUniqueID(sm.GuestPath)] = sm.volume
			}
			if sm.upperVolume != nil {
				volMap[overlayUpperUniqueID(sm.GuestPath)] = sm.upperVolume
			}
		} else if sm.volume != nil {
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
	loadCtx = inet.WithNetworkCheckpointRestore(loadCtx, networkCheckpointMode)

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
		restoreNetworkArgs{sb: sb, eth0: manifest.Eth0},
		clocks,
		vfsOpts,
		nil,
	)
	_ = stateReader.Close()
	waitErr := asyncMFLoader.Wait()
	closeErr := closeBundleReadFiles()
	sb.restoredKernel = k
	if loadErr != nil || waitErr != nil || closeErr != nil {
		// Close stops root and child timers before destroying their clock.
		return cleanup(errors.Join(loadErr, waitErr, closeErr))
	}

	k.IncCheckpointGenOnRestore()
	sb.restoredStdio = collector
	return sb, nil
}
