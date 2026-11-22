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
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/platform"
	"z.gfire.dev/gvx/pkg/sentry/state/stateio"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const (
	legacyCheckpointManifestVersion          = 1
	legacyProtectedCheckpointManifestVersion = 2

	// CheckpointManifestVersion identifies unprotected bundles with guest
	// iptables state. Older readers must not resume without those rules.
	CheckpointManifestVersion          = 3
	protectedCheckpointManifestVersion = 4

	// Protected state starts with the signature, version, hex store ID, and big-endian generation.
	checkpointPolicyStateMagic      = "GVXNPST"
	checkpointPolicyStateVersion    = 1
	checkpointPolicyStateIDOffset   = len(checkpointPolicyStateMagic) + 1
	checkpointPolicyStateGeneration = checkpointPolicyStateIDOffset + 2*policyStoreIDBytes
	checkpointPolicyStateHeaderSize = checkpointPolicyStateGeneration + 8

	checkpointManifestFileName  = "manifest.json"
	checkpointStateFileName     = "state.img"
	checkpointPagesMetaFileName = "pages.meta"
	checkpointPagesFileName     = "pages.img"
)

// CheckpointOptions configures a Sandbox.Checkpoint call.
type CheckpointOptions struct {
	// LeaveRunning resumes the sandbox after writing the checkpoint bundle when
	// true. When false, Checkpoint stops the sandbox after saving.
	LeaveRunning bool
}

// AddrHoleEntry records one reserved guest virtual address range in a
// checkpoint manifest.
type AddrHoleEntry struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

// ManifestMount records one configured mount in a checkpoint manifest.
type ManifestMount struct {
	Type      MountKind `json:"type"`
	GuestPath string    `json:"guest_path"`
	ReadOnly  bool      `json:"read_only"`
	Kind      string    `json:"kind,omitempty"`
}

// CheckpointNetPolicy binds a protected bundle to host-selected policy state.
type CheckpointNetPolicy struct {
	StoreID       string `json:"store_id"`
	MinGeneration uint64 `json:"min_generation"`
}

func (b *CheckpointNetPolicy) stateHeader() [checkpointPolicyStateHeaderSize]byte {
	var h [checkpointPolicyStateHeaderSize]byte
	copy(h[:], checkpointPolicyStateMagic)
	h[len(checkpointPolicyStateMagic)] = checkpointPolicyStateVersion
	copy(h[checkpointPolicyStateIDOffset:checkpointPolicyStateGeneration], b.StoreID)
	binary.BigEndian.PutUint64(h[checkpointPolicyStateGeneration:], b.MinGeneration)
	return h
}

func (m CheckpointManifest) statePayloadOffset(f *os.File) (int64, error) {
	var h [checkpointPolicyStateHeaderSize]byte
	n, err := f.ReadAt(h[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, fmt.Errorf("%w: read checkpoint state header: %w", ErrCheckpointManifest, err)
	}
	if m.NetPolicy == nil {
		signatureBytes := min(n, len(checkpointPolicyStateMagic))
		if signatureBytes > 0 && string(h[:signatureBytes]) == checkpointPolicyStateMagic[:signatureBytes] {
			return 0, fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "protected checkpoint state requires a protected manifest"))
		}
		return 0, nil
	}
	if n != len(h) || h != m.NetPolicy.stateHeader() {
		return 0, fmt.Errorf("%w: %w", ErrCheckpointManifest, netPolicyError("state_mismatch", "checkpoint state header does not match the network policy binding"))
	}
	return int64(len(h)), nil
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
	// NetPolicy records the store binding of a protected NAT sandbox.
	NetPolicy *CheckpointNetPolicy `json:"net_policy,omitempty"`
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
		switch sm.Kind {
		case MountBind:
			kind = "hostfs"
		case MountVolume:
			if sm.volume != nil {
				kind = "ext4lite"
			} else {
				kind = "hostfs"
			}
		case MountOverlay:
			if sm.upperVolume != nil {
				kind = "overlay:ext4lite"
			} else {
				kind = "overlay:tmpfs"
			}
		}
		out[i] = ManifestMount{
			Type:      sm.Kind,
			GuestPath: sm.GuestPath,
			ReadOnly:  sm.ReadOnly,
			Kind:      kind,
		}
	}
	return out
}

func (s *Sandbox) buildCheckpointManifest() CheckpointManifest {
	arch := s.cfg.Architecture
	if arch == "" {
		arch = runtime.GOARCH
	}
	return CheckpointManifest{
		Version:          CheckpointManifestVersion,
		GOOS:             runtime.GOOS,
		GOARCH:           runtime.GOARCH,
		Platform:         s.platName,
		Arch:             arch,
		UserAddressHoles: platformAddrHoles(s.plat),
		LayerDigests:     append([]string(nil), s.layerDigests...),
		RootVolume:       s.rootVolume != nil,
		Mounts:           sandboxManifestMounts(s.mounts),
		NetMode:          s.cfg.NetworkMode,
		CreatedAt:        time.Now().UTC(),
	}
}

// AcceptCheckpointConn accepts one connection from Config.CheckpointListener.
func (s *Sandbox) AcceptCheckpointConn() (net.Conn, error) {
	s.mu.Lock()
	ln := s.cfg.CheckpointListener
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
	s.ckptMu.Lock()
	ckptLocked := true
	defer func() {
		if ckptLocked {
			s.ckptMu.Unlock()
		}
	}()

	s.mu.Lock()
	files := s.ckptFiles
	readyCh := s.kernelReady
	doneCh := s.runDone
	policyBinding, policyErr := s.checkpointNetPolicyLocked()
	s.mu.Unlock()
	if policyErr != nil {
		return policyErr
	}

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

	s.mu.Lock()
	k := s.activeKernel
	dog := s.activeWatchdog
	quiescers := s.saveQuiescersLocked()
	s.mu.Unlock()
	if k == nil {
		return errors.New("gvx: sandbox is not running")
	}

	if err := files.rewindAndTruncate(); err != nil {
		return err
	}
	if policyBinding != nil {
		header := policyBinding.stateHeader()
		if _, err := files.state.Write(header[:]); err != nil {
			return fmt.Errorf("gvx: write protected checkpoint state header: %w", err)
		}
	}

	if dog != nil {
		dog.Stop()
	}
	k.Pause()
	// Invariant: from here until the guest is resumed or killed, every
	// return path undoes the pause, the watchdog stop, and the WireGuard
	// quiesce. A bundle write or sync failure must not leave the kernel
	// paused, because Run and Close would then block forever.
	paused := true
	kCtx := k.SupervisorContext()
	nicsBefore := s.guestNICCount()
	defer func() {
		if !paused {
			return
		}
		k.BeforeResume(kCtx)
		// Kernel.SaveTo with resume=false removes the NICs of the guest
		// Netstack and ends its connections, because the saved guest is not
		// meant to continue. A failure after that point leaves a guest
		// without a network, so the guest stops instead of resuming. A
		// failure before it leaves the guest intact, and it resumes.
		if retErr != nil && !opts.LeaveRunning && s.guestNICCount() < nicsBefore {
			retErr = errors.Join(retErr, errors.New("gvx: the failed checkpoint removed the guest network configuration, so the guest was stopped"))
			k.Kill(linux.WaitStatusTerminationSignal(linux.SIGKILL))
		}
		for _, q := range quiescers {
			if err := q.ResumeAfterSave(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("gvx: resume network backend after checkpoint: %w", err))
			}
		}
		if dog != nil {
			dog.Start()
		}
		k.Unpause()
		k.OnCheckpointAttempt(retErr)
	}()
	if err := k.ReceiveTaskStatesChecked(); err != nil {
		return fmt.Errorf("gvx: capture task states for checkpoint: %w", err)
	}

	for _, q := range quiescers {
		q.QuiesceForSave()
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
	if policyBinding != nil {
		manifest.Version = protectedCheckpointManifestVersion
		manifest.NetPolicy = policyBinding
	}
	manifest.Eth0 = eth0
	hostRAM, _ := hostMemory()
	manifest.MemoryLimitBytes, _ = effectiveMemoryLimit(s.cfg.Resources.MemoryBytes, hostRAM, s.cfg.Tuning)
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

	if opts.LeaveRunning {
		k.SetSaveSuccess(false)
		// The deferred rollback resumes the guest and reports success.
		return nil
	}

	paused = false
	s.checkpointStopped.Store(true)
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
	select {
	case <-doneCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
