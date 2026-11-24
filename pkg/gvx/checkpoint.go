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
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/rpcfs"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/state/stateio"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// ErrCheckpointExecActive reports that active exec sessions prevent checkpointing
// unless CheckpointOptions.Force is set.
var ErrCheckpointExecActive = errors.New("gvx: active exec sessions prevent checkpoint; pass Force to detach them")

// ErrCheckpointRPCFSActive is retained for API compatibility. Active rpcfs
// mounts no longer block checkpointing.
//
// Deprecated: Checkpoint now quiesces and records active rpcfs mounts.
var ErrCheckpointRPCFSActive = errors.New("gvx: unmount active rpcfs proxy mounts before checkpointing")

// ErrCheckpointNATTunnelActive reports that a NAT tunnel still needs to drain.
var ErrCheckpointNATTunnelActive = errors.New("gvx: close active NAT control tunnels that used bandwidth limits before checkpointing")

const (
	// CheckpointManifestVersion is the version for bundles without a NAT policy.
	CheckpointManifestVersion = 1

	// A runtime that cannot require an explicit policy must reject this bundle.
	checkpointManifestNATPolicyVersion = 2

	checkpointManifestFileName  = "manifest.json"
	checkpointStateFileName     = "state.img"
	checkpointPagesMetaFileName = "pages.meta"
	checkpointPagesFileName     = "pages.img"
)

// CheckpointOptions configures a Sandbox.Checkpoint or CheckpointStream call.
type CheckpointOptions struct {
	// LeaveRunning resumes the sandbox after writing the checkpoint bundle when
	// true. When false, Checkpoint stops the sandbox after saving.
	LeaveRunning bool
	// Force detaches and kills any active control exec sessions before saving.
	Force bool
}

// AddrHoleEntry records one reserved guest virtual address range in a
// checkpoint manifest.
type AddrHoleEntry struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// ManifestMount records one configured or runtime-attached mount in a
// checkpoint manifest.
type ManifestMount struct {
	Type       MountKind `json:"type"`
	GuestPath  string    `json:"guest_path"`
	ReadOnly   bool      `json:"read_only"`
	Kind       string    `json:"kind,omitempty"`
	Dynamic    bool      `json:"dynamic,omitempty"`
	Label      string    `json:"label,omitempty"`
	SingleFile bool      `json:"single_file,omitempty"`
}

// CheckpointManifest describes the host and sandbox configuration of a saved
// checkpoint bundle in manifest.json.
type CheckpointManifest struct {
	Version          int             `json:"version"`
	GOOS             string          `json:"goos"`
	GOARCH           string          `json:"goarch"`
	Platform         string          `json:"platform"`
	Arch             string          `json:"arch"`
	UserAddressHoles []AddrHoleEntry `json:"user_address_holes,omitempty"`
	LayerDigests     []string        `json:"layer_digests,omitempty"`
	RootVolume       bool            `json:"root_volume,omitempty"`
	Mounts           []ManifestMount `json:"mounts,omitempty"`
	NetMode          NetMode         `json:"net_mode"`
	// Eth0 records the addresses, MTU, and routes that the guest set on eth0
	// in NAT mode. A restore applies them again. The field is absent in other
	// network modes and in bundles of older runtimes.
	Eth0 *netbackend.Eth0Config `json:"eth0,omitempty"`
	// MemoryLimitBytes is the memory limit that the guard of the saving
	// sandbox enforced: the configured limit, or the RAM of the host without
	// one. A restore sizes the cap of the memory file from the larger of this
	// value and its own limit. The field is absent in bundles of older
	// runtimes.
	MemoryLimitBytes uint64    `json:"memory_limit_bytes,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
}

type checkpointBundleFiles struct {
	dir       string
	manifest  *os.File
	state     *os.File
	pagesMeta *os.File
	pages     *os.File

	// afterSave runs after Kernel.SaveTo succeeds and before the manifest is
	// written. Tests set it to inject a post-save failure. Production code
	// leaves it nil.
	afterSave func() error
}

func openCheckpointBundleFiles(dir string) (*checkpointBundleFiles, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("gvx: create checkpoint directory %q: %w", dir, err)
	}
	files := &checkpointBundleFiles{dir: dir}
	openWritable := func(name string) (*os.File, error) {
		p := filepath.Join(dir, name)
		f, err := openBundleFile(dir, name, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, fmt.Errorf("gvx: pre-open checkpoint file %q: %w", p, err)
		}
		return f, nil
	}
	var err error
	if files.manifest, err = openWritable(checkpointManifestFileName); err != nil {
		_ = files.Close()
		return nil, err
	}
	if files.state, err = openWritable(checkpointStateFileName); err != nil {
		_ = files.Close()
		return nil, err
	}
	if files.pagesMeta, err = openWritable(checkpointPagesMetaFileName); err != nil {
		_ = files.Close()
		return nil, err
	}
	if files.pages, err = openWritable(checkpointPagesFileName); err != nil {
		_ = files.Close()
		return nil, err
	}
	return files, nil
}

func (f *checkpointBundleFiles) rewindAndTruncate() error {
	for _, file := range []*os.File{f.manifest, f.state, f.pagesMeta, f.pages} {
		if file == nil {
			return errors.New("gvx: checkpoint bundle file is closed")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("gvx: seek checkpoint file %q: %w", file.Name(), err)
		}
		if err := file.Truncate(0); err != nil {
			return fmt.Errorf("gvx: truncate checkpoint file %q: %w", file.Name(), err)
		}
	}
	return nil
}

func (f *checkpointBundleFiles) syncAll() error {
	for _, file := range []*os.File{f.pages, f.pagesMeta, f.state, f.manifest} {
		if file == nil {
			continue
		}
		if err := file.Sync(); err != nil {
			return fmt.Errorf("gvx: sync checkpoint file %q: %w", file.Name(), err)
		}
	}
	return nil
}

func (f *checkpointBundleFiles) Close() error {
	if f == nil {
		return nil
	}
	var errs []error
	for _, ptr := range []**os.File{&f.manifest, &f.state, &f.pagesMeta, &f.pages} {
		if *ptr != nil {
			if err := (*ptr).Close(); err != nil && !errors.Is(err, os.ErrClosed) {
				errs = append(errs, err)
			}
			*ptr = nil
		}
	}
	return errors.Join(errs...)
}

// nopCloseWriter wraps an *os.File so stateio writers flush buffered bytes on
// Close without closing the underlying pre-opened descriptor.
type nopCloseWriter struct {
	*os.File
}

func (nopCloseWriter) Close() error {
	return nil
}

func platformAddrHoles(plat platform.Platform) []AddrHoleEntry {
	hp, ok := plat.(platform.AddressHolePlatform)
	if !ok || hp == nil {
		return nil
	}
	ranges := hp.UserAddressHoles()
	if len(ranges) == 0 {
		return nil
	}
	out := make([]AddrHoleEntry, len(ranges))
	for i, r := range ranges {
		out[i] = AddrHoleEntry{
			Start: uint64(r.Start),
			End:   uint64(r.End),
		}
	}
	return out
}

func sandboxManifestMounts(mounts []sandboxMount) []ManifestMount {
	if len(mounts) == 0 {
		return nil
	}
	out := make([]ManifestMount, len(mounts))
	for i, sm := range mounts {
		kind := "tmpfs"
		var label string
		switch sm.Kind {
		case MountBind:
			kind = "hostfs"
			label = cmp.Or(sm.hostPath, sm.HostPath)
		case MountVolume:
			if sm.volume != nil {
				kind = "ext4lite"
				label = cmp.Or(sm.VolumeName, sm.ImagePath)
			} else {
				kind = "hostfs"
				label = cmp.Or(sm.VolumeName, sm.hostPath)
			}
		case MountOverlay:
			if sm.upperVolume != nil {
				kind = "overlay:ext4lite"
			} else {
				kind = "overlay:tmpfs"
			}
			label = sm.Mount.volumeLabel()
		}
		out[i] = ManifestMount{
			Type:      sm.Kind,
			GuestPath: sm.GuestPath,
			ReadOnly:  sm.ReadOnly,
			Kind:      kind,
			Dynamic:   sm.dynamic,
			Label:     label,
		}
	}
	return out
}

func (s *Sandbox) buildCheckpointManifest() CheckpointManifest {
	s.mu.Lock()
	arch := s.cfg.Architecture
	if arch == "" {
		arch = runtime.GOARCH
	}
	layerDigests := append([]string(nil), s.layerDigests...)
	hasRootVol := s.rootVolume != nil
	mounts := sandboxManifestMounts(s.mounts)
	netMode := s.cfg.NetworkMode
	plat := s.plat
	platName := s.platName
	s.mu.Unlock()
	version := CheckpointManifestVersion
	if s.natPolicy.RequiredOnRestore() {
		version = checkpointManifestNATPolicyVersion
	}

	s.rpcMountsMu.Lock()
	if len(s.rpcMounts) > 0 {
		rpcEntries := make([]ManifestMount, 0, len(s.rpcMounts))
		for _, rm := range s.rpcMounts {
			rpcEntries = append(rpcEntries, ManifestMount{
				Type:       MountRPCFS,
				GuestPath:  rm.target,
				ReadOnly:   rm.readOnly,
				Kind:       rpcfs.Name,
				Dynamic:    true,
				Label:      rm.label,
				SingleFile: rm.singleFile,
			})
		}
		slices.SortFunc(rpcEntries, func(a, b ManifestMount) int {
			return cmp.Compare(a.GuestPath, b.GuestPath)
		})
		mounts = append(mounts, rpcEntries...)
	}
	s.rpcMountsMu.Unlock()
	return CheckpointManifest{
		Version:          version,
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
		Platform:         platName,
		Arch:             arch,
		UserAddressHoles: platformAddrHoles(plat),
		LayerDigests:     layerDigests,
		RootVolume:       hasRootVol,
		Mounts:           mounts,
		NetMode:          netMode,
		CreatedAt:        time.Now().UTC(),
	}
}

// AcceptCheckpointConn accepts one connection from Config.ControlListener or
// Config.CheckpointListener.
func (s *Sandbox) AcceptCheckpointConn() (net.Conn, error) {
	s.mu.Lock()
	ln := s.controlListener()
	locked := s.lockdown.Applied
	s.mu.Unlock()
	if ln == nil {
		return nil, fmt.Errorf("%w: Config.CheckpointListener is nil", ErrInvalidConfig)
	}
	if locked {
		return hostlockdown.AcceptListener(ln)
	}
	return ln.Accept()
}

// saveQuiescer is a host network component that stops its traffic into the
// guest Netstack while the kernel saves its state.
type saveQuiescer interface {
	QuiesceForSave()
	ResumeAfterSave() error
}

// saveQuiescersLocked returns the network components of s that must stop
// during a checkpoint. s.mu must be held: Close clears these fields under it.
func (s *Sandbox) saveQuiescersLocked() []saveQuiescer {
	var out []saveQuiescer
	if s.wgEndpoint != nil {
		out = append(out, s.wgEndpoint)
	}
	if s.natForwarder != nil {
		out = append(out, s.natForwarder)
	}
	if s.portForwarder != nil {
		out = append(out, s.portForwarder)
	}
	return out
}

// guestNICCount returns the number of NICs of the guest root Netstack.
func (s *Sandbox) guestNICCount() int {
	s.mu.Lock()
	st := s.netStack
	s.mu.Unlock()
	if st == nil {
		return 0
	}
	return len(st.NICInfo())
}

// snapshotEth0 returns the eth0 settings of the guest in NAT mode, or nil in
// every other mode. The guest must be paused: a running guest can change them.
func (s *Sandbox) snapshotEth0() *netbackend.Eth0Config {
	if s.cfg.NetworkMode != NetModeNAT {
		return nil
	}
	s.mu.Lock()
	st := s.netStack
	s.mu.Unlock()
	cfg, ok := netbackend.SnapshotEth0Config(st)
	if !ok {
		return nil
	}
	return &cfg
}

// Checkpoint saves the running sandbox state into the pre-opened bundle files
// under Config.CheckpointDir. When opts.LeaveRunning is true, Checkpoint
// resumes the sandbox after writing the bundle. When opts.LeaveRunning is
// false, Checkpoint stops the guest kernel so Run returns cleanly.
func (s *Sandbox) Checkpoint(ctx context.Context, opts CheckpointOptions) (retErr error) {
	// Wait for kernel startup before acquiring s.opMu/s.ckptMu to avoid AB-BA
	// deadlocks with executeActiveKernel.
	s.mu.Lock()
	if err := s.refuseGPUCheckpointLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	files := s.ckptFiles
	readyCh := s.kernelReady
	doneCh := s.runDone
	s.mu.Unlock()

	if files == nil {
		return fmt.Errorf("%w: Config.CheckpointDir must be set before New or Restore", ErrInvalidConfig)
	}
	if readyCh == nil {
		return errors.New("gvx: sandbox is not initialized for checkpoint")
	}

	select {
	case <-readyCh:
	case <-doneCh:
		return errors.New("gvx: sandbox exited before Checkpoint started")
	case <-ctx.Done():
		return ctx.Err()
	}

	s.opMu.Lock()
	opLocked := true
	defer func() {
		if opLocked {
			s.opMu.Unlock()
		}
	}()
	s.ckptMu.Lock()
	ckptLocked := true
	defer func() {
		if ckptLocked {
			s.ckptMu.Unlock()
		}
	}()

	s.mu.Lock()
	files = s.ckptFiles
	k := s.activeKernel
	dog := s.activeWatchdog
	quiescers := s.saveQuiescersLocked()
	alreadyPaused := s.userPaused
	alreadyQuiesced := s.userPauseQuiesced
	s.mu.Unlock()
	if files == nil {
		return fmt.Errorf("%w: Config.CheckpointDir must be set before New or Restore", ErrInvalidConfig)
	}
	if k == nil {
		return errors.New("gvx: sandbox is not running")
	}
	if s.hasShapedNATControlTunnel() {
		return ErrCheckpointNATTunnelActive
	}
	rpcQuiescers := s.rpcSaveQuiescers()
	if s.activeExecCount() > 0 {
		if !opts.Force {
			return ErrCheckpointExecActive
		}
		if alreadyPaused {
			return fmt.Errorf("%w: cannot force-stop exec sessions while sandbox is paused", ErrCheckpointExecActive)
		}
		if err := s.forceStopExecSessions(ctx, k); err != nil {
			return err
		}
	}

	if err := files.rewindAndTruncate(); err != nil {
		return err
	}

	if !alreadyPaused {
		if dog != nil {
			dog.Stop()
		}
		k.Pause()
	}
	// Invariant: from here until the guest is resumed or killed, every
	// return path restores the exact prior pause/quiesce/watchdog state.
	paused := true
	kCtx := k.SupervisorContext()
	nicsBefore := s.guestNICCount()
	quiescedHere := false
	rpcQuiescedHere := false
	defer func() {
		if !paused {
			return
		}
		k.BeforeResume(kCtx)
		if retErr != nil && !opts.LeaveRunning && s.guestNICCount() < nicsBefore {
			retErr = errors.Join(retErr, errors.New("gvx: the failed checkpoint removed the guest network configuration, so the guest was stopped"))
			k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			s.mu.Lock()
			s.userPaused = false
			s.userPauseQuiesced = false
			s.mu.Unlock()
			alreadyPaused = false
		}
		if quiescedHere {
			for _, q := range quiescers {
				if err := q.ResumeAfterSave(); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("gvx: resume network backend after checkpoint: %w", err))
				}
			}
		}
		if rpcQuiescedHere {
			for _, q := range rpcQuiescers {
				if err := q.ResumeAfterSave(); err != nil {
					retErr = errors.Join(retErr, fmt.Errorf("gvx: resume rpcfs mount after checkpoint: %w", err))
				}
			}
		}
		if !alreadyPaused {
			if dog != nil {
				dog.Start()
			}
			k.Unpause()
		}
		k.OnCheckpointAttempt(retErr)
	}()
	if err := k.ReceiveTaskStatesChecked(); err != nil {
		return fmt.Errorf("gvx: capture task states for checkpoint: %w", err)
	}

	if !alreadyQuiesced {
		for _, q := range quiescers {
			q.QuiesceForSave()
		}
		quiescedHere = true
	}
	if len(rpcQuiescers) > 0 {
		for _, q := range rpcQuiescers {
			q.QuiesceForSave()
		}
		rpcQuiescedHere = true
	}
	eth0 := s.snapshotEth0()

	stateWriter := stateio.NewBufioWriteCloser(nopCloseWriter{files.state})
	pagesMetaWriter := stateio.NewBufioWriteCloser(nopCloseWriter{files.pagesMeta})
	pagesWriter := stateio.NewIOWriter(nopCloseWriter{files.pages}, 256<<10, 64, 4)

	if saveErr := k.SaveTo(
		kCtx,
		stateWriter,
		pagesMetaWriter,
		pagesWriter,
		true,
		opts.LeaveRunning,
		nil,
		vfs.PrepareSaveOptions{ValidateMetadata: true},
		nil,
	); saveErr != nil {
		return fmt.Errorf("gvx: save kernel state: %w", saveErr)
	}

	if files.afterSave != nil {
		if err := files.afterSave(); err != nil {
			return fmt.Errorf("gvx: after checkpoint save: %w", err)
		}
	}
	manifest := s.buildCheckpointManifest()
	manifest.Eth0 = eth0
	hostRAM, _ := hostMemory()
	manifest.MemoryLimitBytes, _ = effectiveMemoryLimit(s.liveMemoryBytes.Load(), hostRAM, s.cfg.Tuning)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("gvx: marshal checkpoint manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')
	if _, err := files.manifest.Write(manifestBytes); err != nil {
		return fmt.Errorf("gvx: write checkpoint manifest: %w", err)
	}
	if err := files.syncAll(); err != nil {
		return err
	}

	s.emitEvent("lifecycle", "checkpoint", map[string]string{
		"leave_running": fmt.Sprintf("%t", opts.LeaveRunning),
	})

	if opts.LeaveRunning {
		k.SetSaveSuccess(false)
		// The deferred rollback restores the pre-checkpoint running or paused state.
		return nil
	}

	paused = false
	s.detachRPCMountsForStop()
	s.checkpointStopped.Store(true)
	s.mu.Lock()
	s.userPaused = false
	s.userPauseQuiesced = false
	s.mu.Unlock()
	k.SetSaveSuccess(false)
	k.Kill(linux.WaitStatusExit(0))
	if dog != nil {
		dog.Start()
	}
	k.Unpause()
	k.OnCheckpointAttempt(nil)
	s.clearActiveKernel()
	ckptLocked = false
	s.ckptMu.Unlock()
	opLocked = false
	s.opMu.Unlock()
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type bufWriteCloser struct {
	bytes.Buffer
}

func (*bufWriteCloser) Close() error { return nil }

// CheckpointStream captures a complete checkpoint bundle in memory (manifest.json,
// state.img, pages.meta, pages.img) without opening host files under lockdown,
// then writes it as a tar archive to dst.
func (s *Sandbox) CheckpointStream(ctx context.Context, opts CheckpointOptions, dst io.Writer) error {
	return s.checkpointStreamRun(ctx, opts, func(manifestBytes, stateBytes, pagesMetaBytes, pagesBytes []byte) error {
		return writeCheckpointTar(dst, manifestBytes, stateBytes, pagesMetaBytes, pagesBytes)
	})
}

func writeCheckpointTar(dst io.Writer, manifestBytes, stateBytes, pagesMetaBytes, pagesBytes []byte) error {
	tw := tar.NewWriter(dst)
	now := time.Now().UTC()
	entries := []struct {
		name string
		data []byte
	}{
		{checkpointManifestFileName, manifestBytes},
		{checkpointStateFileName, stateBytes},
		{checkpointPagesMetaFileName, pagesMetaBytes},
		{checkpointPagesFileName, pagesBytes},
	}
	for _, entry := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name:    entry.name,
			Mode:    0o600,
			Size:    int64(len(entry.data)),
			ModTime: now,
		}); err != nil {
			return fmt.Errorf("gvx: write tar header %s: %w", entry.name, err)
		}
		if _, err := tw.Write(entry.data); err != nil {
			return fmt.Errorf("gvx: write tar body %s: %w", entry.name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("gvx: close checkpoint tar stream: %w", err)
	}
	return nil
}

// checkpointStreamRun captures the in-memory checkpoint bundle and invokes
// streamFn. When opts.LeaveRunning is true, the guest resumes before streamFn
// transfers bytes. When opts.LeaveRunning is false, the guest remains paused
// until streamFn completes so Sandbox.Run does not exit and close the control
// server mid-transfer.
func (s *Sandbox) checkpointStreamRun(
	ctx context.Context,
	opts CheckpointOptions,
	streamFn func(manifestBytes, stateBytes, pagesMetaBytes, pagesBytes []byte) error,
) (retErr error) {
	// Wait for kernel startup before acquiring s.opMu/s.ckptMu to avoid AB-BA
	// deadlocks with executeActiveKernel.
	s.mu.Lock()
	if err := s.refuseGPUCheckpointLocked(); err != nil {
		s.mu.Unlock()
		return err
	}
	readyCh := s.kernelReady
	doneCh := s.runDone
	s.mu.Unlock()
	if readyCh == nil {
		return errors.New("gvx: sandbox is not initialized for checkpoint")
	}

	select {
	case <-readyCh:
	case <-doneCh:
		return errors.New("gvx: sandbox exited before Checkpoint started")
	case <-ctx.Done():
		return ctx.Err()
	}

	s.opMu.Lock()
	opLocked := true
	defer func() {
		if opLocked {
			s.opMu.Unlock()
		}
	}()
	s.ckptMu.Lock()
	ckptLocked := true
	defer func() {
		if ckptLocked {
			s.ckptMu.Unlock()
		}
	}()

	s.mu.Lock()
	k := s.activeKernel
	dog := s.activeWatchdog
	quiescers := s.saveQuiescersLocked()
	alreadyPaused := s.userPaused
	alreadyQuiesced := s.userPauseQuiesced
	s.mu.Unlock()
	if k == nil {
		return errors.New("gvx: sandbox is not running")
	}
	if s.hasShapedNATControlTunnel() {
		return ErrCheckpointNATTunnelActive
	}
	rpcQuiescers := s.rpcSaveQuiescers()
	if s.activeExecCount() > 0 {
		if !opts.Force {
			return ErrCheckpointExecActive
		}
		if alreadyPaused {
			return fmt.Errorf("%w: cannot force-stop exec sessions while sandbox is paused", ErrCheckpointExecActive)
		}
		if err := s.forceStopExecSessions(ctx, k); err != nil {
			return err
		}
	}

	if !alreadyPaused {
		if dog != nil {
			dog.Stop()
		}
		k.Pause()
	}
	paused := true
	kCtx := k.SupervisorContext()
	nicsBefore := s.guestNICCount()
	quiescedHere := false
	rpcQuiescedHere := false
	resumeOrRestore := func(err error) error {
		if !paused {
			return err
		}
		paused = false
		k.BeforeResume(kCtx)
		if err != nil && !opts.LeaveRunning && s.guestNICCount() < nicsBefore {
			err = errors.Join(err, errors.New("gvx: the failed checkpoint removed the guest network configuration, so the guest was stopped"))
			k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
			s.mu.Lock()
			s.userPaused = false
			s.userPauseQuiesced = false
			s.mu.Unlock()
			alreadyPaused = false
		}
		if quiescedHere {
			for _, q := range quiescers {
				if rErr := q.ResumeAfterSave(); rErr != nil {
					err = errors.Join(err, fmt.Errorf("gvx: resume network backend after checkpoint: %w", rErr))
				}
			}
		}
		if rpcQuiescedHere {
			for _, q := range rpcQuiescers {
				if rErr := q.ResumeAfterSave(); rErr != nil {
					err = errors.Join(err, fmt.Errorf("gvx: resume rpcfs mount after checkpoint: %w", rErr))
				}
			}
		}
		if !alreadyPaused {
			if dog != nil {
				dog.Start()
			}
			k.Unpause()
		}
		k.OnCheckpointAttempt(err)
		return err
	}
	defer func() {
		if paused {
			retErr = resumeOrRestore(retErr)
		}
	}()

	if err := k.ReceiveTaskStatesChecked(); err != nil {
		return fmt.Errorf("gvx: capture task states for checkpoint: %w", err)
	}
	if !alreadyQuiesced {
		for _, q := range quiescers {
			q.QuiesceForSave()
		}
		quiescedHere = true
	}
	if len(rpcQuiescers) > 0 {
		for _, q := range rpcQuiescers {
			q.QuiesceForSave()
		}
		rpcQuiescedHere = true
	}
	eth0 := s.snapshotEth0()

	var stateBuf, pagesMetaBuf, pagesBuf bufWriteCloser
	stateWriter := stateio.NewBufioWriteCloser(&stateBuf)
	pagesMetaWriter := stateio.NewBufioWriteCloser(&pagesMetaBuf)
	pagesWriter := stateio.NewIOWriter(&pagesBuf, 256<<10, 64, 4)

	if saveErr := k.SaveTo(
		kCtx,
		stateWriter,
		pagesMetaWriter,
		pagesWriter,
		true,
		opts.LeaveRunning,
		nil,
		vfs.PrepareSaveOptions{ValidateMetadata: true},
		nil,
	); saveErr != nil {
		return fmt.Errorf("gvx: save kernel state: %w", saveErr)
	}

	manifest := s.buildCheckpointManifest()
	manifest.Eth0 = eth0
	hostRAM, _ := hostMemory()
	s.mu.Lock()
	curTune := s.cfg.Tuning
	s.mu.Unlock()
	manifest.MemoryLimitBytes, _ = effectiveMemoryLimit(s.liveMemoryBytes.Load(), hostRAM, curTune)
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return fmt.Errorf("gvx: marshal checkpoint manifest: %w", err)
	}
	manifestBytes = append(manifestBytes, '\n')

	s.emitEvent("lifecycle", "checkpoint", map[string]string{
		"leave_running": fmt.Sprintf("%t", opts.LeaveRunning),
		"stream":        "true",
	})

	if opts.LeaveRunning {
		k.SetSaveSuccess(false)
		if err := resumeOrRestore(nil); err != nil {
			return err
		}
		ckptLocked = false
		s.ckptMu.Unlock()
		opLocked = false
		s.opMu.Unlock()
		return streamFn(manifestBytes, stateBuf.Bytes(), pagesMetaBuf.Bytes(), pagesBuf.Bytes())
	}

	// Keep the sandbox paused until the caller finishes streaming the bundle so
	// Run() cannot exit and close the control server mid-transfer.
	streamErr := streamFn(manifestBytes, stateBuf.Bytes(), pagesMetaBuf.Bytes(), pagesBuf.Bytes())

	paused = false
	s.detachRPCMountsForStop()
	s.checkpointStopped.Store(true)
	s.mu.Lock()
	s.userPaused = false
	s.userPauseQuiesced = false
	s.mu.Unlock()
	k.SetSaveSuccess(false)
	k.Kill(linux.WaitStatusExit(0))
	if dog != nil {
		dog.Start()
	}
	k.Unpause()
	k.OnCheckpointAttempt(nil)
	s.clearActiveKernel()
	ckptLocked = false
	s.ckptMu.Unlock()
	opLocked = false
	s.opMu.Unlock()

	if streamErr != nil {
		return streamErr
	}
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
