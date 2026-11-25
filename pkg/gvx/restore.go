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
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/rpcfs"
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

// maxManifestBytes bounds the size of manifest.json. A manifest of 1 MiB
// holds thousands of mounts, so a larger file is corrupt.
const maxManifestBytes = 1 << 20

// readManifestBytes reads manifest.json from path and fails when the file is
// larger than maxManifestBytes, before the whole file reaches memory.
func readManifestBytes(dir string) ([]byte, error) {
	f, err := openBundleFile(dir, checkpointManifestFileName, os.O_RDONLY, 0)
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

func readAndParseManifest(dir string) (CheckpointManifest, error) {
	manifestPath := filepath.Join(dir, checkpointManifestFileName)
	data, err := readManifestBytes(dir)
	if err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: read %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	var m CheckpointManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return CheckpointManifest{}, fmt.Errorf("%w: decode %q: %w", ErrCheckpointManifest, manifestPath, err)
	}
	return m, nil
}

func validateManifestNATPolicy(m CheckpointManifest, supplied bool) error {
	switch m.Version {
	case CheckpointManifestVersion:
		if m.NATPolicyRequired {
			return fmt.Errorf("%w: version %d cannot set nat_policy_required", ErrCheckpointManifest, m.Version)
		}
		return nil
	case checkpointManifestNATPolicyVersion:
		if m.NetMode != NetModeNAT {
			return fmt.Errorf("%w: version %d requires NAT", ErrCheckpointManifest, m.Version)
		}
		if !supplied {
			return fmt.Errorf("%w: this bundle requires a NAT policy; pass --nat-policy-file", ErrCheckpointManifest)
		}
		return nil
	case checkpointManifestVolumeLimitVersion:
		if m.NATPolicyRequired {
			if m.NetMode != NetModeNAT {
				return fmt.Errorf("%w: version %d with nat_policy_required requires NAT", ErrCheckpointManifest, m.Version)
			}
			if !supplied {
				return fmt.Errorf("%w: this bundle requires a NAT policy; pass --nat-policy-file", ErrCheckpointManifest)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: unsupported version %d", ErrCheckpointManifest, m.Version)
	}
}

func validateManifestMountsPreflight(m CheckpointManifest) error {
	seenPaths := make(map[string]struct{}, len(m.Mounts))
	cappedCount := 0
	for _, mm := range m.Mounts {
		if err := validateGuestPath(mm.GuestPath); err != nil {
			return fmt.Errorf("%w: invalid manifest mount path %q: %v", ErrCheckpointManifest, mm.GuestPath, err)
		}
		if _, dup := seenPaths[mm.GuestPath]; dup {
			return fmt.Errorf("%w: duplicate manifest mount path %q", ErrCheckpointManifest, mm.GuestPath)
		}
		seenPaths[mm.GuestPath] = struct{}{}
		if mm.Ephemeral {
			return fmt.Errorf("%w: manifest mount %q names an ephemeral volume", ErrCheckpointManifest, mm.GuestPath)
		}
		if mm.BackingReadOnly != nil && *mm.BackingReadOnly && !mm.ReadOnly {
			return fmt.Errorf("%w: manifest mount %q has a writable guest view with a read-only backing file", ErrCheckpointManifest, mm.GuestPath)
		}
		if mm.VolumeLimit != nil {
			if m.Version < checkpointManifestVolumeLimitVersion {
				return fmt.Errorf("%w: manifest version %d cannot contain volume_limit at %q", ErrCheckpointManifest, m.Version, mm.GuestPath)
			}
			if mm.Type != MountVolume || mm.Kind != "ext4lite" {
				return fmt.Errorf("%w: manifest volume_limit at %q requires type=volume and kind=ext4lite", ErrCheckpointManifest, mm.GuestPath)
			}
			if mm.VolumeLimit.MaxBytes <= 0 {
				return fmt.Errorf("%w: manifest volume_limit at %q must be positive, got %d", ErrCheckpointManifest, mm.GuestPath, mm.VolumeLimit.MaxBytes)
			}
			if err := ext4lite.ValidateMaxBytes(mm.VolumeLimit.MaxBytes); err != nil {
				return fmt.Errorf("%w: invalid manifest volume_limit at %q: %v", ErrCheckpointManifest, mm.GuestPath, err)
			}
			cappedCount++
		}
	}
	if m.Version == checkpointManifestVolumeLimitVersion && cappedCount == 0 {
		return fmt.Errorf("%w: manifest version %d requires at least one capped volume mount", ErrCheckpointManifest, m.Version)
	}
	return nil
}

func inheritRestoreMountLimits(cfg *Config, m CheckpointManifest) error {
	bundleByPath := make(map[string]ManifestMount, len(m.Mounts))
	for _, mm := range m.Mounts {
		if mm.Type != MountRPCFS {
			bundleByPath[mm.GuestPath] = mm
		}
	}
	for i := range cfg.Mounts {
		cm := &cfg.Mounts[i]
		if cm.Ephemeral {
			continue
		}
		bm, ok := bundleByPath[cm.GuestPath]
		if !ok || bm.VolumeLimit == nil {
			continue
		}
		if cm.Kind != MountVolume {
			return fmt.Errorf("%w: capped mount %q requires type=volume, config has %s", ErrCheckpointManifest, cm.GuestPath, cm.Kind)
		}
		if cm.SizeBytes == 0 {
			cm.SizeBytes = bm.VolumeLimit.MaxBytes
		} else if cm.SizeBytes != bm.VolumeLimit.MaxBytes {
			return fmt.Errorf("%w: volume limit mismatch at %q: bundle has %d bytes, config has %d bytes", ErrCheckpointManifest, cm.GuestPath, bm.VolumeLimit.MaxBytes, cm.SizeBytes)
		}
	}
	return nil
}

func prepareRestoreConfigMounts(cfg *Config, m CheckpointManifest) (map[string]bool, error) {
	for _, cm := range cfg.Mounts {
		if cm.Ephemeral {
			return nil, fmt.Errorf("%w: ephemeral ext4lite volume at %q cannot be restored", ErrInvalidConfig, cm.GuestPath)
		}
	}
	bundleByPath := make(map[string]ManifestMount, len(m.Mounts))
	for _, mm := range m.Mounts {
		if mm.Type != MountRPCFS {
			bundleByPath[mm.GuestPath] = mm
		}
	}
	restoreBackingRO := make(map[string]bool)
	inherited := false
	for i := range cfg.Mounts {
		cm := &cfg.Mounts[i]
		bm, ok := bundleByPath[cm.GuestPath]
		if !ok {
			if cm.SizeBytes > 0 {
				return nil, fmt.Errorf("%w: mounts mismatch: config has unexpected capped mount %q", ErrCheckpointManifest, cm.GuestPath)
			}
			continue
		}
		if bm.VolumeLimit != nil {
			if cm.Kind != MountVolume {
				return nil, fmt.Errorf("%w: capped mount %q requires type=volume, config has %s", ErrCheckpointManifest, cm.GuestPath, cm.Kind)
			}
			driver, err := cfg.resolveVolumeDriver(*cm)
			if err != nil {
				return nil, err
			}
			if driver != DriverExt4lite {
				return nil, fmt.Errorf("%w: capped mount %q requires driver %q, resolved %q", ErrInvalidConfig, cm.GuestPath, DriverExt4lite, driver)
			}
			savedBackingRO := bm.ReadOnly
			if bm.BackingReadOnly != nil {
				savedBackingRO = *bm.BackingReadOnly
			}
			if !savedBackingRO && cm.ReadOnly {
				return nil, fmt.Errorf("%w: capped mount %q was saved with a writable backing file and cannot be restored read-only", ErrCheckpointManifest, cm.GuestPath)
			}
			if savedBackingRO && !cm.ReadOnly {
				return nil, fmt.Errorf("%w: capped mount %q was saved with a read-only backing file and cannot be restored read-write", ErrCheckpointManifest, cm.GuestPath)
			}
			restoreBackingRO[cm.GuestPath] = savedBackingRO
			cm.ReadOnly = bm.ReadOnly
			if cm.SizeBytes == 0 {
				cm.SizeBytes = bm.VolumeLimit.MaxBytes
				inherited = true
			} else if cm.SizeBytes != bm.VolumeLimit.MaxBytes {
				return nil, fmt.Errorf("%w: volume limit mismatch at %q: bundle has %d bytes, config has %d bytes", ErrCheckpointManifest, cm.GuestPath, bm.VolumeLimit.MaxBytes, cm.SizeBytes)
			}
		} else if cm.SizeBytes > 0 {
			return nil, fmt.Errorf("%w: mount %q has no saved volume limit in checkpoint bundle, cannot set size=%d on restore", ErrCheckpointManifest, cm.GuestPath, cm.SizeBytes)
		}
	}
	if inherited {
		rootImg := ""
		if cfg.RootVolume != "" {
			rm, err := parseRootVolumeMount(cfg.RootVolume)
			if err != nil {
				return nil, err
			}
			rootImg, err = cfg.volumeImagePath(rm)
			if err != nil {
				return nil, err
			}
		}
		if err := cfg.validateVolumeConflicts(rootImg); err != nil {
			return nil, err
		}
	}
	return restoreBackingRO, nil
}

func (s *Sandbox) validateCheckpointManifest(m CheckpointManifest) error {
	if err := validateManifestNATPolicy(m, s.cfg.NetworkPolicy != nil); err != nil {
		return err
	}
	if err := validateManifestMountsPreflight(m); err != nil {
		return err
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
	hasRootVol := s.rootVolume != nil
	if m.RootVolume != hasRootVol {
		return fmt.Errorf("%w: root volume mismatch: bundle has %v, config has %v", ErrCheckpointManifest, m.RootVolume, hasRootVol)
	}
	if err := s.validateManifestMounts(m.Mounts); err != nil {
		return err
	}
	if m.NetMode != "" && m.NetMode != s.cfg.NetworkMode {
		return fmt.Errorf("%w: network mode mismatch: bundle has %q, config has %q", ErrCheckpointManifest, m.NetMode, s.cfg.NetworkMode)
	}
	return nil
}

type manifestMountKey struct {
	typ       MountKind
	guestPath string
	readOnly  bool
	kind      string
}

func manifestVolumeLimitEqual(a, b *ManifestVolumeLimit) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.MaxBytes == b.MaxBytes
}

func (s *Sandbox) validateManifestMounts(bundleMounts []ManifestMount) error {
	seenPaths := make(map[string]struct{}, len(bundleMounts))
	bundleOther := make(map[string]ManifestMount)
	bundleRPC := make(map[string]ManifestMount)
	for _, mm := range bundleMounts {
		if err := validateGuestPath(mm.GuestPath); err != nil {
			return fmt.Errorf("%w: invalid manifest mount path %q: %v", ErrCheckpointManifest, mm.GuestPath, err)
		}
		if _, dup := seenPaths[mm.GuestPath]; dup {
			return fmt.Errorf("%w: duplicate manifest mount path %q", ErrCheckpointManifest, mm.GuestPath)
		}
		seenPaths[mm.GuestPath] = struct{}{}
		if mm.Ephemeral {
			return fmt.Errorf("%w: manifest mount %q names an ephemeral volume", ErrCheckpointManifest, mm.GuestPath)
		}
		if mm.Type == MountRPCFS {
			bundleRPC[mm.GuestPath] = mm
		} else {
			bundleOther[mm.GuestPath] = mm
		}
	}

	wantOther := sandboxManifestMounts(s.mounts)
	wantByPath := make(map[string]ManifestMount, len(wantOther))
	for i, wm := range wantOther {
		wantByPath[wm.GuestPath] = wm
		bm, ok := bundleOther[wm.GuestPath]
		if !ok {
			return fmt.Errorf("%w: mounts mismatch: config has unexpected mount %q (bundle has %v)", ErrCheckpointManifest, wm.GuestPath, bundleMounts)
		}
		if (manifestMountKey{bm.Type, bm.GuestPath, bm.ReadOnly, bm.Kind}) != (manifestMountKey{wm.Type, wm.GuestPath, wm.ReadOnly, wm.Kind}) ||
			!manifestVolumeLimitEqual(bm.VolumeLimit, wm.VolumeLimit) {
			return fmt.Errorf("%w: mounts mismatch at %q: bundle has %+v, config has %+v", ErrCheckpointManifest, wm.GuestPath, bm, wm)
		}
		if bm.Dynamic {
			s.mounts[i].dynamic = true
		}
	}

	var omittedDynamicTmpfs []sandboxMount
	for _, bm := range bundleMounts {
		if bm.Type == MountRPCFS {
			continue
		}
		if _, ok := wantByPath[bm.GuestPath]; ok {
			continue
		}
		if bm.Dynamic && bm.Type == MountTmpfs {
			omittedDynamicTmpfs = append(omittedDynamicTmpfs, sandboxMount{
				Mount: Mount{
					Kind:      MountTmpfs,
					GuestPath: bm.GuestPath,
					ReadOnly:  bm.ReadOnly,
				},
				dynamic: true,
			})
			continue
		}
		return fmt.Errorf("%w: mounts mismatch: bundle requires mount %q (%s, ro=%t, label=%q)", ErrCheckpointManifest, bm.GuestPath, bm.Type, bm.ReadOnly, bm.Label)
	}

	for _, sm := range s.serveMounts {
		bm, ok := bundleRPC[sm.GuestPath]
		if !ok {
			return fmt.Errorf("%w: serve mount %q is not present in checkpoint bundle", ErrCheckpointManifest, sm.GuestPath)
		}
		if sm.SingleFile != bm.SingleFile {
			return fmt.Errorf("%w: serve mount %q single-file mismatch: bundle has %v, config has %v", ErrCheckpointManifest, sm.GuestPath, bm.SingleFile, sm.SingleFile)
		}
		if !sm.ReadOnly && bm.ReadOnly {
			return fmt.Errorf("%w: serve mount %q is read-only in checkpoint bundle and cannot be restored read-write", ErrCheckpointManifest, sm.GuestPath)
		}
	}

	if len(omittedDynamicTmpfs) > 0 {
		s.mounts = append(s.mounts, omittedDynamicTmpfs...)
		sortMountsByDepth(s.mounts)
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
	initRuntimeGlobals()
	if ln := cfg.ControlListener; ln != nil {
		defer func() {
			if retErr != nil {
				_ = ln.Close()
			}
		}()
	}
	if ln := cfg.CheckpointListener; ln != nil && ln != cfg.ControlListener {
		defer func() {
			if retErr != nil {
				_ = ln.Close()
			}
		}()
	}
	if opts.Dir == "" {
		return nil, fmt.Errorf("%w: RestoreOptions.Dir is empty", ErrInvalidConfig)
	}
	if len(cfg.Extensions) > 0 {
		if err := validateConfigExtensions(cfg, true); err != nil {
			return nil, err
		}
		return nil, ErrCheckpointExtensionUnsupported
	}
	for _, cm := range cfg.Mounts {
		if cm.Ephemeral {
			return nil, fmt.Errorf("%w: ephemeral ext4lite volume at %q cannot be restored", ErrInvalidConfig, cm.GuestPath)
		}
	}
	manifest, err := readAndParseManifest(opts.Dir)
	if err != nil {
		return nil, err
	}
	if err := validateManifestNATPolicy(manifest, cfg.NetworkPolicy != nil); err != nil {
		return nil, err
	}
	if err := validateManifestMountsPreflight(manifest); err != nil {
		return nil, err
	}
	allowUnconfined := cfg.AllowUnconfinedSystrap || os.Getenv("GVX_ALLOW_NO_HYPERVISOR") == "1"
	if cfg.Platform, err = restorePlatform(runtime.GOOS, cfg.Platform, manifest.Platform, allowUnconfined); err != nil {
		return nil, err
	}
	if cfg.NetworkMode == "" && manifest.NetMode != "" {
		cfg.NetworkMode = manifest.NetMode
	}
	if cfg.Architecture == "" && manifest.Arch != "" {
		cfg.Architecture = manifest.Arch
	}
	if err := inheritRestoreMountLimits(&cfg, manifest); err != nil {
		return nil, err
	}
	if err := cfg.normalizeWithMode(len(manifest.LayerDigests) > 0); err != nil {
		return nil, err
	}
	if manifest.RootVolume != (cfg.RootVolume != "") {
		return nil, fmt.Errorf("%w: root volume mismatch: bundle has %v, config has %v", ErrCheckpointManifest, manifest.RootVolume, cfg.RootVolume != "")
	}
	restoreBackingRO, err := prepareRestoreConfigMounts(&cfg, manifest)
	if err != nil {
		return nil, err
	}
	applyHostMemoryDefaults()

	sb := &Sandbox{
		cfg:              cfg,
		restoreBackingRO: restoreBackingRO,
		kernelReady:      make(chan struct{}),
		runDone:          make(chan struct{}),
		detachDebugLog:   attachDebugLogSink(cfg.DebugLog),
	}
	sb.initControlState()
	if cfg.HostCACerts {
		roots, err := hostcerts.Collect(ctx, cfg.Warnings)
		if err != nil {
			return nil, errors.Join(fmt.Errorf("gvx: read the host root certificates: %w", err), sb.Close())
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
		f, oErr := openBundleFile(opts.Dir, name, os.O_RDONLY, 0)
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
	if err := sb.openServeMountsForRestore(); err != nil {
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
		cf, cErr := openCheckpointBundleFiles(cfg.CheckpointDir)
		if cErr != nil {
			return cleanup(cErr)
		}
		sb.ckptFiles = cf
	}

	if !cfg.DisableHostLockdown {
		if cfg.AllowBindAttach {
			hostfs.WarmWatchLimit()
		}
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

	manifestRPCByTarget := make(map[string]ManifestMount)
	for _, mm := range manifest.Mounts {
		if mm.Type == MountRPCFS {
			manifestRPCByTarget[mm.GuestPath] = mm
		}
	}
	rpcRestoreClients := make(map[string]rpcfs.RestoreClient, len(sb.serveMounts))
	serveByTarget := make(map[string]sandboxServeMount, len(sb.serveMounts))
	for _, sm := range sb.serveMounts {
		label := cmp.Or(sm.HostPath, sm.hostPath)
		rpcRestoreClients[sm.GuestPath] = rpcfs.RestoreClient{
			Client:     sm.Client,
			Label:      label,
			ReadOnly:   sm.ReadOnly,
			SingleFile: sm.SingleFile,
		}
		serveByTarget[sm.GuestPath] = sm
	}
	loadCtx = rpcfs.WithRestoreConfig(loadCtx, &rpcfs.RestoreConfig{
		Clients: rpcRestoreClients,
		OnRestored: func(h *rpcfs.Handle) {
			target := h.Target()
			if target == "" {
				return
			}
			mm := manifestRPCByTarget[target]
			entry := &rpcMountEntry{
				target:          target,
				label:           h.Label(),
				readOnly:        h.ReadOnly() || mm.ReadOnly,
				backingReadOnly: h.BackingReadOnly(),
				singleFile:      h.SingleFile(),
				detached:        h.Detached(),
				handle:          h,
			}
			if sm, ok := serveByTarget[target]; ok {
				entry.client = sm.Client
				entry.clientReadOnly = sm.ReadOnly
				entry.backingReadOnly = h.BackingReadOnly() || sm.ReadOnly
				entry.readOnly = entry.readOnly || sm.ReadOnly
			}
			sb.rpcMountsMu.Lock()
			sb.rpcMounts[target] = entry
			sb.rpcMountsMu.Unlock()
		},
	})

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
		restoreNetworkArgs{sb: sb, eth0: manifest.Eth0},
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
