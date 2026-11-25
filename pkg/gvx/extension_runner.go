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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/gvx/shm"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/sys"
	"z.gfire.dev/gvx/pkg/sentry/socket/netstack"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

const defaultExtensionStopTimeout = 30 * time.Second

type boundExtEntry struct {
	name  string
	bound BoundExtension
}

// Process-wide lockdown grants recorded the first time hostlockdown.Apply
// succeeds in this process. Subsequent Sandboxes in the same process verify
// their extension requirements against these recorded grants.
var (
	extLockdownMu        sync.Mutex
	extLockdownRecvMsgFD map[int]struct{}
)

func recordProcessExtensionLockdown(recvMsgFDs []int) {
	extLockdownMu.Lock()
	defer extLockdownMu.Unlock()
	if extLockdownRecvMsgFD != nil {
		return
	}
	m := make(map[int]struct{}, len(recvMsgFDs))
	for _, fd := range recvMsgFDs {
		if fd >= 0 {
			m[fd] = struct{}{}
		}
	}
	extLockdownRecvMsgFD = m
}

func extensionLockdownGrantSatisfied(req ExtensionLockdown) bool {
	if len(req.RecvMsgFDs) == 0 {
		return true
	}
	extLockdownMu.Lock()
	defer extLockdownMu.Unlock()
	if extLockdownRecvMsgFD == nil {
		return false
	}
	for _, fd := range req.RecvMsgFDs {
		if _, ok := extLockdownRecvMsgFD[fd]; !ok {
			return false
		}
	}
	return true
}

func hostMappingAlignForPlatform(platName string) uint64 {
	if platName == "hvf" {
		return 16384
	}
	align := uint64(hostarch.PageSize)
	if osPage := os.Getpagesize(); osPage > 0 && uint64(osPage) > align {
		align = uint64(osPage)
	}
	return align
}

func validateConfigExtensions(cfg Config, isRestore bool) error {
	if len(cfg.Extensions) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(cfg.Extensions))
	env := ValidationEnv{
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
		Platform:      cfg.Platform,
		NetworkMode:   cfg.NetworkMode,
		HasCheckpoint: cfg.CheckpointDir != "",
		IsRestore:     isRestore,
	}
	for i, ext := range cfg.Extensions {
		if ext == nil {
			return fmt.Errorf("%w: extension[%d] is nil", ErrInvalidConfig, i)
		}
		name := strings.TrimSpace(ext.Name())
		if name == "" {
			return fmt.Errorf("%w: extension[%d] has an empty name", ErrInvalidConfig, i)
		}
		if _, dup := seen[name]; dup {
			return fmt.Errorf("%w: duplicate extension %q", ErrInvalidConfig, name)
		}
		seen[name] = struct{}{}
		if err := ext.Validate(env); err != nil {
			return fmt.Errorf("gvx: validate extension %q: %w", name, err)
		}
	}
	return nil
}

func (s *Sandbox) openExtensions(ctx context.Context) error {
	if len(s.cfg.Extensions) == 0 {
		return nil
	}
	hostRAM, _ := hostMemory()
	align := hostMappingAlignForPlatform(s.platName)
	s.shmImporter = shm.NewImporter(shm.Options{
		PlatformName:     s.platName,
		HostMappingAlign: align,
		QuotaBytes:       shm.DefaultQuotaBytes(hostRAM),
	})

	alreadyLocked := hostlockdown.IsLockedDown()
	var (
		allTopos   []sys.TopologyAddition
		recvMsgFDs []int
	)
	for _, ext := range s.cfg.Extensions {
		extName := strings.TrimSpace(ext.Name())
		env := PreLockdownEnv{
			PlatformName:     s.platName,
			HostMappingAlign: align,
			HostRAMBytes:     hostRAM,
			SharedMemory:     s.shmImporter,
			SpawnHelper: func(hctx context.Context, spec HelperSpec) (*HelperProcess, error) {
				if spec.Name == "" {
					spec.Name = extName
				}
				hp, err := spawnHelperProcess(hctx, spec)
				if err != nil {
					return nil, err
				}
				s.mu.Lock()
				s.extHelpers = append(s.extHelpers, hp)
				s.mu.Unlock()
				return hp, nil
			},
			Logf: func(format string, args ...any) {
				log.Infof("ext[%s]: "+format, append([]any{extName}, args...)...)
			},
		}

		bound, err := ext.OpenPreLockdown(ctx, env)
		if err != nil {
			return fmt.Errorf("gvx: open extension %q: %w", extName, err)
		}
		if bound == nil {
			return fmt.Errorf("gvx: extension %q returned nil BoundExtension", extName)
		}
		s.mu.Lock()
		s.boundExts = append(s.boundExts, boundExtEntry{name: extName, bound: bound})
		s.mu.Unlock()

		reqs := bound.LockdownRequirements()
		for _, fd := range reqs.RecvMsgFDs {
			if fd < 0 {
				return fmt.Errorf("%w: extension %q requested negative RecvMsgFD %d", ErrInvalidConfig, extName, fd)
			}
		}

		if alreadyLocked {
			if bound.NeedsHelperSpawn() {
				return fmt.Errorf("gvx: extension %q requires helper spawn: %w", extName, ErrLockdownActive)
			}
			if !extensionLockdownGrantSatisfied(reqs) {
				return fmt.Errorf("gvx: extension %q requires lockdown grants not present in active lockdown: %w", extName, ErrLockdownActive)
			}
		}

		for _, fd := range reqs.RecvMsgFDs {
			if !slices.Contains(recvMsgFDs, fd) {
				recvMsgFDs = append(recvMsgFDs, fd)
			}
		}
		if bound.CheckpointPolicy() != CheckpointSupported {
			s.extCheckpointBlocked = true
		}
		allTopos = append(allTopos, bound.SysfsTopologies()...)
	}

	if len(allTopos) > 0 {
		if err := sys.ValidateTopologyAdditions(allTopos); err != nil {
			return fmt.Errorf("gvx: validate extension sysfs topologies: %w", err)
		}
		s.extSysfsTopologies = allTopos
	}
	s.extRecvMsgFDs = recvMsgFDs
	if s.shmImporter.HasImported() {
		s.extCheckpointBlocked = true
	}
	return nil
}

func (s *Sandbox) checkExtensionCheckpointGuard() error {
	s.mu.Lock()
	blocked := s.extCheckpointBlocked
	imp := s.shmImporter
	s.mu.Unlock()
	if blocked || (imp != nil && imp.HasImported()) {
		return ErrCheckpointExtensionUnsupported
	}
	return nil
}

func (s *Sandbox) attachKernelExtensions(ctx context.Context, vfsObj *vfs.VirtualFilesystem) error {
	s.mu.Lock()
	exts := slices.Clone(s.boundExts)
	imp := s.shmImporter
	s.mu.Unlock()
	if len(exts) == 0 {
		return nil
	}
	for _, entry := range exts {
		extName := entry.name
		kenv := &KernelEnv{
			VFS:          vfsObj,
			SharedMemory: imp,
			Logf: func(format string, args ...any) {
				log.Infof("ext[%s]: "+format, append([]any{extName}, args...)...)
			},
		}
		if err := entry.bound.AttachKernel(ctx, kenv); err != nil {
			return fmt.Errorf("gvx: attach extension %q to kernel: %w", extName, err)
		}
	}
	return nil
}

func (s *Sandbox) inspectExtensions() map[string]json.RawMessage {
	s.mu.Lock()
	exts := slices.Clone(s.boundExts)
	s.mu.Unlock()
	if len(exts) == 0 {
		return nil
	}
	var out map[string]json.RawMessage
	for _, entry := range exts {
		raw, err := entry.bound.Inspect()
		if err != nil || len(raw) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]json.RawMessage, len(exts))
		}
		out[entry.name] = slices.Clone(raw)
	}
	return out
}

func (s *Sandbox) statsExtensions() map[string]json.RawMessage {
	s.mu.Lock()
	exts := slices.Clone(s.boundExts)
	s.mu.Unlock()
	if len(exts) == 0 {
		return nil
	}
	var out map[string]json.RawMessage
	for _, entry := range exts {
		raw, err := entry.bound.Stats()
		if err != nil || len(raw) == 0 {
			continue
		}
		if out == nil {
			out = make(map[string]json.RawMessage, len(exts))
		}
		out[entry.name] = slices.Clone(raw)
	}
	return out
}

func (s *Sandbox) abortExtensions() {
	s.mu.Lock()
	exts := slices.Clone(s.boundExts)
	s.mu.Unlock()
	for i := len(exts) - 1; i >= 0; i-- {
		exts[i].bound.AbortPending()
	}
}

func (s *Sandbox) closeBoundExtensions(guestUnmapped bool) error {
	s.mu.Lock()
	exts := slices.Clone(s.boundExts)
	s.mu.Unlock()
	var errs []error
	for i := len(exts) - 1; i >= 0; i-- {
		if err := exts[i].bound.Close(guestUnmapped); err != nil {
			errs = append(errs, fmt.Errorf("gvx: close extension %q: %w", exts[i].name, err))
		}
	}
	return errors.Join(errs...)
}

func (s *Sandbox) closeExtensionHelpers() error {
	s.mu.Lock()
	helpers := s.extHelpers
	s.extHelpers = nil
	s.mu.Unlock()
	var errs []error
	for i := len(helpers) - 1; i >= 0; i-- {
		if err := helpers[i].Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (s *Sandbox) stopKernelForExtensionClose(stopTimeout time.Duration) error {
	s.mu.Lock()
	runStarted := s.runStarted
	readyCh := s.kernelReady
	doneCh := s.runDone
	s.mu.Unlock()
	if !runStarted || doneCh == nil {
		return nil
	}

	if stopTimeout <= 0 {
		stopTimeout = defaultExtensionStopTimeout
	}
	timer := time.NewTimer(stopTimeout)
	defer timer.Stop()

	// If Run has started but not yet published runningKernel, wait for either
	// kernel startup or Run completion before signaling guest tasks.
	select {
	case <-doneCh:
		return nil
	case <-readyCh:
	case <-timer.C:
		return fmt.Errorf("gvx: timed out waiting %s for sandbox startup to finish before close", stopTimeout)
	}

	s.mu.Lock()
	k := s.runningKernel
	if k == nil {
		k = s.activeKernel
	}
	dog := s.activeWatchdog
	s.mu.Unlock()

	if k != nil {
		s.unpauseForShutdown(k, dog)
		s.abortExtensions()
		s.closeRPCMounts()
		s.closeUnixForwards()
		for _, tg := range k.TaskSet().Root.ThreadGroups() {
			_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		}
		s.killActiveExecSessions(k)
	} else {
		s.abortExtensions()
	}

	select {
	case <-doneCh:
		return nil
	case <-timer.C:
		return fmt.Errorf("gvx: guest kernel did not exit within %s during extension teardown", stopTimeout)
	}
}

func (s *Sandbox) closeControlEndpoints() []error {
	s.mu.Lock()
	srv := s.controlSrv
	s.controlSrv = nil
	ctrlLn := s.cfg.ControlListener
	ckptLn := s.cfg.CheckpointListener
	if ckptLn == ctrlLn {
		ckptLn = nil
	}
	s.cfg.ControlListener = nil
	s.cfg.CheckpointListener = nil
	s.mu.Unlock()

	var errs []error
	if srv != nil {
		_ = srv.Close()
	}
	if ctrlLn != nil {
		if err := ctrlLn.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	if ckptLn != nil {
		if err := ckptLn.Close(); err != nil && !errors.Is(err, os.ErrClosed) && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, err)
		}
	}
	return errs
}

// closeWithExtensions executes the three-outcome teardown protocol for
// Sandboxes with one or more bound extensions. The caller sets s.closing=true
// and releases s.mu before calling closeWithExtensions.
func (s *Sandbox) closeWithExtensions(done chan struct{}, stopTimeout time.Duration) error {
	// Phase 1: wake paused kernel, abort pending extension work, kill guest tasks.
	stopErr := s.stopKernelForExtensionClose(stopTimeout)
	if stopErr != nil {
		// Outcome 2: kernel did not stop within timeout. Close extensions with
		// guestUnmapped=false, close control endpoints, retain platform, memory,
		// and mounts, and keep Sandbox open for a retryable second Close().
		extErr := s.closeBoundExtensions(false)
		ctrlErrs := s.closeControlEndpoints()
		allErr := errors.Join(append([]error{stopErr, extErr}, ctrlErrs...)...)
		s.mu.Lock()
		s.closing = false
		s.closeErr = allErr
		s.mu.Unlock()
		close(done)
		return allErr
	}

	s.abortExtensions()
	s.closeRPCMounts()
	s.closeUnixForwards()
	errs := s.closeControlEndpoints()

	s.mu.Lock()
	if s.restoredKernel != nil {
		if tk := s.restoredKernel.Timekeeper(); tk != nil {
			tk.Destroy()
		}
		s.restoredKernel = nil
	}
	if s.netStack != nil {
		netstack.RemoveRegisteredLinks(s.netStack)
	}
	if s.ckptFiles != nil {
		if err := s.ckptFiles.Close(); err != nil {
			errs = append(errs, err)
		}
		s.ckptFiles = nil
	}
	s.closeServeMounts()

	if s.natPolicy != nil {
		s.natPolicy.Close()
	}
	if s.bandwidth != nil {
		s.mu.Unlock()
		s.bandwidth.Close()
		s.mu.Lock()
	}
	if s.portForwarder != nil {
		if err := s.portForwarder.Close(); err != nil {
			errs = append(errs, err)
		}
		s.portForwarder = nil
	}
	if s.natForwarder != nil {
		if err := s.natForwarder.Close(); err != nil {
			errs = append(errs, err)
		}
		s.natForwarder = nil
	}
	if s.wgEndpoint != nil {
		if err := s.wgEndpoint.Close(); err != nil {
			errs = append(errs, err)
		}
		s.wgEndpoint = nil
		s.netStack = nil
	}
	if s.netStack != nil {
		s.netStack.Close()
		s.netStack = nil
	}

	if s.plat != nil {
		if closer, ok := s.plat.(io.Closer); ok {
			plat := closer
			s.mu.Unlock()
			platErr := plat.Close()
			if platErr != nil {
				// Outcome 3: Platform.Close failed. Call Close(false) in reverse
				// open order, retain backing memory and mounts, and return joined errors.
				extErr := s.closeBoundExtensions(false)
				s.mu.Lock()
				s.closed = true
				s.closing = false
				s.closeErr = errors.Join(append(errs, platErr, extErr)...)
				err := s.closeErr
				s.mu.Unlock()
				close(done)
				return err
			}
			s.mu.Lock()
		}
		s.plat = nil
	}

	// Outcome 1: kernel and platform stopped cleanly. Drop importer claims first,
	// then call Close(true) on extensions in reverse open order, then reap any
	// leftover helper processes before releasing mounts and memory.
	imp := s.shmImporter
	s.mu.Unlock()

	if imp != nil {
		imp.ReleaseAll()
	}
	if extErr := s.closeBoundExtensions(true); extErr != nil {
		errs = append(errs, extErr)
	}
	if helperErr := s.closeExtensionHelpers(); helperErr != nil {
		errs = append(errs, helperErr)
	}

	s.mu.Lock()
	if err := s.closeMounts(); err != nil {
		errs = append(errs, err)
	}
	for _, hh := range s.layerHandles {
		if err := hh.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.layerHandles = nil
	s.layerDigests = nil
	if s.resolvedImg != nil {
		if err := s.resolvedImg.Close(); err != nil {
			errs = append(errs, err)
		}
		s.resolvedImg = nil
	}
	if s.memFile != nil {
		s.memFile.Destroy()
		s.memFile = nil
	}
	if s.runMemFile != nil {
		s.runMemFile.Destroy()
		s.runMemFile = nil
	}
	if s.detachDebugLog != nil {
		s.detachDebugLog()
		s.detachDebugLog = nil
	}
	s.closed = true
	s.closing = false
	s.closeErr = errors.Join(errs...)
	err := s.closeErr
	s.mu.Unlock()
	close(done)
	return err
}
