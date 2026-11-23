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
	"os"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/checkpoint"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/hostfs"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/rpcfs"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type rpcMountEntry struct {
	target            string
	label             string
	readOnly          bool
	backingReadOnly   bool
	singleFile        bool
	detached          bool
	checkpointClosing atomic.Bool
	handle            *rpcfs.Handle
	stream            *control.Stream
	cancel            context.CancelFunc
	client            rpcfs.Client
}

func (s *Sandbox) rpcSaveQuiescers() []saveQuiescer {
	s.rpcMountsMu.Lock()
	defer s.rpcMountsMu.Unlock()
	if len(s.rpcMounts) == 0 {
		return nil
	}
	out := make([]saveQuiescer, 0, len(s.rpcMounts))
	for _, e := range s.rpcMounts {
		if e.handle != nil {
			out = append(out, e.handle)
		}
	}
	return out
}

// detachRPCMountsForStop marks every active rpcfs mount as closing for a
// stopping checkpoint, notifies serving clients with an rpcfs.detached event,
// detaches the clients without unmounting the VFS mount, and cancels their
// serve streams.
func (s *Sandbox) detachRPCMountsForStop() {
	s.rpcMountsMu.Lock()
	entries := make([]*rpcMountEntry, 0, len(s.rpcMounts))
	for _, e := range s.rpcMounts {
		e.checkpointClosing.Store(true)
		entries = append(entries, e)
	}
	s.rpcMountsMu.Unlock()

	for _, e := range entries {
		if e.stream != nil {
			notifyCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = e.stream.SendEvent(notifyCtx, "rpcfs.detached", map[string]string{
				"target": e.target,
				"reason": "checkpoint",
			})
			cancel()
			e.stream.CloseEvents()
		}
		if e.handle != nil {
			e.handle.DetachClient()
		}
		if e.cancel != nil {
			e.cancel()
		}
	}
}

func (s *Sandbox) closeRPCMounts() {
	s.rpcMountsMu.Lock()
	entries := make([]*rpcMountEntry, 0, len(s.rpcMounts))
	for k, e := range s.rpcMounts {
		e.checkpointClosing.Store(true)
		entries = append(entries, e)
		delete(s.rpcMounts, k)
	}
	s.rpcMountsMu.Unlock()
	for _, e := range entries {
		if e.handle != nil {
			e.handle.DetachClient()
		}
		if e.cancel != nil {
			e.cancel()
		}
		if e.client != nil {
			_ = e.client.Close()
		}
	}
}

func (s *Sandbox) listMountInfos() []control.MountInfo {
	s.mu.Lock()
	mounts := append([]sandboxMount(nil), s.mounts...)
	roRoot := s.cfg.ReadOnlyRoot
	hasImage := len(s.layerDigests) > 0
	s.mu.Unlock()

	rootType := "tmpfs"
	if hasImage {
		rootType = "overlay"
	}
	out := []control.MountInfo{{
		Target:   "/",
		Type:     rootType,
		Source:   "rootfs",
		ReadOnly: roRoot,
		Mutable:  true,
	}}
	for _, sm := range mounts {
		info := control.MountInfo{
			Target:   sm.GuestPath,
			ReadOnly: sm.ReadOnly,
		}
		switch sm.Kind {
		case MountTmpfs:
			info.Type = "tmpfs"
			info.Source = "tmpfs"
			info.Mutable = true
		case MountOverlay:
			info.Type = "overlay"
			info.Source = sm.Mount.volumeLabel()
			info.Mutable = !sm.backingReadOnly
		case MountVolume:
			if sm.volume != nil {
				info.Type = "ext4lite"
				info.Source = cmp.Or(sm.VolumeName, sm.ImagePath, "volume")
				info.Mutable = !sm.backingReadOnly
			} else {
				info.Type = "hostfs"
				info.Source = cmp.Or(sm.VolumeName, sm.hostPath)
				info.Mutable = !sm.backingReadOnly && sm.workspace != nil && !sm.workspace.ReadOnly()
			}
		default:
			info.Type = "hostfs"
			info.Source = cmp.Or(sm.hostPath, sm.HostPath)
			info.Mutable = !sm.backingReadOnly && sm.workspace != nil && !sm.workspace.ReadOnly()
		}
		out = append(out, info)
	}

	s.rpcMountsMu.Lock()
	for _, rm := range s.rpcMounts {
		out = append(out, control.MountInfo{
			Target:   rm.target,
			Type:     rpcfs.Name,
			Source:   cmp.Or(rm.label, "client-proxy"),
			ReadOnly: rm.readOnly,
			Mutable:  !rm.backingReadOnly,
		})
	}
	s.rpcMountsMu.Unlock()
	return out
}

func (s *Sandbox) handleMountList(_ context.Context, stream *control.Stream) error {
	return stream.Reply(control.MountListResponse{Mounts: s.listMountInfos()})
}

func (s *Sandbox) mountTargetExistsLocked(target string) bool {
	for _, m := range s.mounts {
		if m.GuestPath == target {
			return true
		}
	}
	return false
}

func (s *Sandbox) handleMountAdd(ctx context.Context, stream *control.Stream, raw json.RawMessage, fds []int) error {
	defer func() {
		closeUnusedFDs(fds)
	}()

	var req control.MountAddRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	target := strings.TrimSpace(req.Target)
	if err := validateGuestPath(target); err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	kind := strings.ToLower(strings.TrimSpace(req.Type))
	if kind == "" {
		kind = "tmpfs"
	}

	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}
	s.opMu.RLock()
	defer s.opMu.RUnlock()
	s.mountOpMu.Lock()
	defer s.mountOpMu.Unlock()

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	s.mu.Lock()
	locked := s.lockdown.Applied
	mf := s.runMemFile
	if s.mountTargetExistsLocked(target) {
		s.mu.Unlock()
		return control.NewErrorf(control.CodeAlreadyExists, "mount target %q already exists", target)
	}
	s.mu.Unlock()

	s.rpcMountsMu.Lock()
	_, rpcExists := s.rpcMounts[target]
	s.rpcMountsMu.Unlock()
	if rpcExists {
		return control.NewErrorf(control.CodeAlreadyExists, "mount target %q already exists", target)
	}

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()
	caps := s.ControlCapabilities()

	switch kind {
	case "tmpfs":
		if !slices.Contains(caps, control.CapMountTmpfs) {
			return control.NewError(control.CodeForbiddenByPolicy, "tmpfs mounts are disabled by policy")
		}
		if req.TmpfsSizeBytes < 0 {
			return control.NewError(control.CodeInvalidArgument, "tmpfs_size_bytes must be non-negative")
		}
		if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, target, 0o1777); err != nil {
			return control.NewErrorf(control.CodeInternal, "prepare mount point %q: %v", target, err)
		}
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
		if _, err := vfsObj.MountAt(sctxWithRoot, creds, "", &pop, "tmpfs", &vfs.MountOptions{
			ReadOnly: req.ReadOnly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				Data:          tmpfsMountData(req.TmpfsSizeBytes),
			},
		}); err != nil {
			return control.NewErrorf(control.CodeInternal, "mount tmpfs at %q: %v", target, err)
		}
		s.mu.Lock()
		s.mounts = append(s.mounts, sandboxMount{
			Mount: Mount{
				Kind:           MountTmpfs,
				GuestPath:      target,
				ReadOnly:       req.ReadOnly,
				TmpfsSizeBytes: req.TmpfsSizeBytes,
			},
			dynamic: true,
		})
		sortMountsByDepth(s.mounts)
		s.mu.Unlock()
		s.emitEvent("mount", "add", map[string]string{"type": "tmpfs", "target": target})
		return stream.Reply(control.MountInfo{
			Target: target, Type: "tmpfs", Source: "tmpfs", ReadOnly: req.ReadOnly, Mutable: true,
		})

	case "volume":
		if !slices.Contains(caps, control.CapMountVolumeAttach) {
			if (runtime.GOOS == "linux" || runtime.GOOS == "android") && locked && !s.cfg.AllowVolumeAttach {
				return control.NewError(control.CodeLockdownDenied, "live ext4lite volume attachment on Linux/Android requires --allow-volume-attach")
			}
			return control.NewError(control.CodeForbiddenByPolicy, "volume attachment is disabled by policy")
		}
		if len(fds) != 1 {
			return control.NewError(control.CodeInvalidArgument, "volume attach requires exactly one SCM_RIGHTS file descriptor")
		}
		fd := fds[0]
		fds = nil // ownership transferred to f below
		f := os.NewFile(uintptr(fd), cmp.Or(req.Source, "attached-volume.ext4"))
		info, statErr := f.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			_ = f.Close()
			return control.NewError(control.CodeInvalidArgument, "attached volume file descriptor must refer to a regular file")
		}
		vol, volErr := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{ReadOnly: req.ReadOnly})
		if volErr != nil {
			if errors.Is(volErr, ext4lite.ErrVolumeInUse) {
				return control.NewError(control.CodeBusy, "volume image is already in use by another sandbox")
			}
			return control.NewErrorf(control.CodeInternal, "open attached ext4lite volume: %v", volErr)
		}
		if sharedChunkMemory && mf != nil {
			vol.SetChunkMemory(&memoryFileChunks{MemoryFile: mf})
		}
		if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, target, 0o755); err != nil {
			_ = vol.Close()
			return control.NewErrorf(control.CodeInternal, "prepare mount point %q: %v", target, err)
		}
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
		if _, err := vfsObj.MountAt(sctxWithRoot, creds, "", &pop, ext4lite.Name, &vfs.MountOptions{
			ReadOnly: req.ReadOnly,
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				InternalData: ext4lite.InternalFilesystemOptions{
					Volume:   vol,
					UniqueID: target,
				},
			},
		}); err != nil {
			_ = vol.Close()
			return control.NewErrorf(control.CodeInternal, "mount ext4lite volume at %q: %v", target, err)
		}
		s.mu.Lock()
		s.volumes = append(s.volumes, vol)
		s.mounts = append(s.mounts, sandboxMount{
			Mount: Mount{
				Kind:      MountVolume,
				Driver:    DriverExt4lite,
				ImagePath: req.Source,
				GuestPath: target,
				ReadOnly:  req.ReadOnly,
			},
			backingReadOnly: req.ReadOnly,
			dynamic:         true,
			volume:          vol,
		})
		sortMountsByDepth(s.mounts)
		s.mu.Unlock()
		s.emitEvent("mount", "add", map[string]string{"type": "ext4lite", "target": target})
		return stream.Reply(control.MountInfo{
			Target: target, Type: "ext4lite", Source: cmp.Or(req.Source, "volume"), ReadOnly: req.ReadOnly, Mutable: !req.ReadOnly,
		})

	case "bind":
		if len(fds) > 0 {
			if !slices.Contains(caps, control.CapMountBindAttach) {
				if runtime.GOOS == "windows" {
					return control.NewError(control.CodeUnsupported, "live hostfs bind attachment via SCM_RIGHTS is POSIX-only; use rungv mount serve or -lockdown=false")
				}
				if locked && !s.cfg.AllowBindAttach {
					return control.NewError(control.CodeLockdownDenied, "live hostfs bind attachment under host lockdown requires --allow-bind-attach; or use rungv mount serve")
				}
				return control.NewError(control.CodeForbiddenByPolicy, "bind attachment is disabled by policy")
			}
			if len(fds) != 1 {
				return control.NewError(control.CodeInvalidArgument, "bind attach requires exactly one SCM_RIGHTS directory file descriptor")
			}

			var (
				extHandle int64 = -1
				hasExt    bool
			)
			if runtime.GOOS == "darwin" && locked {
				if req.SandboxToken == "" {
					return control.NewError(control.CodeInvalidArgument, "bind attach under macOS Seatbelt lockdown requires sandbox_token")
				}
				h, extErr := hostlockdown.ConsumeFileExtension(req.SandboxToken)
				if extErr != nil {
					return control.NewErrorf(control.CodeLockdownDenied, "consume sandbox file extension: %v", extErr)
				}
				extHandle, hasExt = h, true
			}
			releaseExt := func() {
				if hasExt {
					_ = hostlockdown.ReleaseFileExtension(extHandle)
					hasExt = false
				}
			}

			dirFD := fds[0]
			fds = nil // ownership transferred to OpenWorkspaceFromDirFD below
			label := cmp.Or(strings.TrimSpace(req.Source), target)
			ws, wsErr := hostfs.OpenWorkspaceFromDirFD(dirFD, label, req.SingleFileName, req.ReadOnly)
			if wsErr != nil {
				releaseExt()
				return control.NewErrorf(control.CodeInvalidArgument, "open attached hostfs bind %q: %v", label, wsErr)
			}
			if sharedChunkMemory && mf != nil {
				ws.SetChunkMemory(&memoryFileChunks{MemoryFile: mf})
			}
			isFile := ws.SingleFile()
			if isFile {
				if err := vfsEnsureEmptyFile(sctxWithRoot, vfsObj, creds, root, target, 0o644); err != nil {
					_ = ws.Close()
					releaseExt()
					return control.NewErrorf(control.CodeInternal, "create guest file %q: %v", target, err)
				}
			} else if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, target, 0o755); err != nil {
				_ = ws.Close()
				releaseExt()
				return control.NewErrorf(control.CodeInternal, "create guest dir %q: %v", target, err)
			}
			pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
			if _, err := vfsObj.MountAt(sctxWithRoot, creds, "", &pop, hostfs.Name, &vfs.MountOptions{
				ReadOnly: ws.ReadOnly(),
				GetFilesystemOptions: vfs.GetFilesystemOptions{
					InternalMount: true,
					InternalData: hostfs.InternalFilesystemOptions{
						Workspace: ws,
						UniqueID: checkpoint.ResourceID{
							ContainerName: cmp.Or(s.cfg.Name, "gvx-default"),
							Path:          target,
						},
					},
				},
			}); err != nil {
				_ = ws.Close()
				releaseExt()
				return control.NewErrorf(control.CodeInternal, "mount hostfs at %q: %v", target, err)
			}
			m := Mount{Kind: MountBind, HostPath: label, GuestPath: target, ReadOnly: req.ReadOnly}
			s.mu.Lock()
			s.workspaces = append(s.workspaces, ws)
			if hasExt {
				s.sandboxExtHandles = append(s.sandboxExtHandles, extHandle)
			}
			s.mounts = append(s.mounts, sandboxMount{
				Mount:            m,
				hostPath:         label,
				hostFile:         isFile,
				backingReadOnly:  ws.ReadOnly(),
				dynamic:          true,
				workspace:        ws,
				hasSandboxExt:    hasExt,
				sandboxExtHandle: extHandle,
			})
			sortMountsByDepth(s.mounts)
			s.mu.Unlock()
			s.emitEvent("mount", "add", map[string]string{"type": "hostfs", "target": target})
			return stream.Reply(control.MountInfo{
				Target: target, Type: "hostfs", Source: label, ReadOnly: req.ReadOnly, Mutable: !req.ReadOnly,
			})
		}

		if locked {
			if !s.cfg.AllowBindAttach {
				return control.NewError(control.CodeLockdownDenied, "dynamic host bind mounts are denied under host lockdown; start with --allow-bind-attach, use rungv mount serve, or start with -lockdown=false")
			}
			if runtime.GOOS == "windows" {
				return control.NewError(control.CodeUnsupported, "live hostfs bind attach under lockdown is POSIX-only; use rungv mount serve or start with -lockdown=false")
			}
			return control.NewError(control.CodeInvalidArgument, "bind attach under host lockdown requires one SCM_RIGHTS directory file descriptor over a Unix control socket")
		}
		if !slices.Contains(caps, control.CapMountBind) {
			return control.NewError(control.CodeForbiddenByPolicy, "bind mounts are disabled by policy")
		}
		src := strings.TrimSpace(req.Source)
		if src == "" {
			return control.NewError(control.CodeInvalidArgument, "bind mount requires source host path")
		}
		m := Mount{Kind: MountBind, HostPath: src, GuestPath: target, ReadOnly: req.ReadOnly}
		if err := m.validate(); err != nil {
			return control.NewError(control.CodeInvalidArgument, err.Error())
		}
		hostPath, isFile, err := s.prepareHostPath(m)
		if err != nil {
			return control.NewError(control.CodeInvalidArgument, err.Error())
		}
		ws, err := hostfs.OpenWorkspace(hostPath, req.ReadOnly)
		if err != nil {
			return control.NewErrorf(control.CodeInternal, "open bind mount %q: %v", hostPath, err)
		}
		if sharedChunkMemory && mf != nil {
			ws.SetChunkMemory(&memoryFileChunks{MemoryFile: mf})
		}
		if isFile {
			if err := vfsEnsureEmptyFile(sctxWithRoot, vfsObj, creds, root, target, 0o644); err != nil {
				_ = ws.Close()
				return control.NewErrorf(control.CodeInternal, "create guest file %q: %v", target, err)
			}
		} else if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, target, 0o755); err != nil {
			_ = ws.Close()
			return control.NewErrorf(control.CodeInternal, "create guest dir %q: %v", target, err)
		}
		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
		if _, err := vfsObj.MountAt(sctxWithRoot, creds, "", &pop, hostfs.Name, &vfs.MountOptions{
			ReadOnly: ws.ReadOnly(),
			GetFilesystemOptions: vfs.GetFilesystemOptions{
				InternalMount: true,
				InternalData: hostfs.InternalFilesystemOptions{
					Workspace: ws,
					UniqueID: checkpoint.ResourceID{
						ContainerName: cmp.Or(s.cfg.Name, "gvx-default"),
						Path:          target,
					},
				},
			},
		}); err != nil {
			_ = ws.Close()
			return control.NewErrorf(control.CodeInternal, "mount hostfs at %q: %v", target, err)
		}
		s.mu.Lock()
		s.workspaces = append(s.workspaces, ws)
		s.mounts = append(s.mounts, sandboxMount{
			Mount:           m,
			hostPath:        hostPath,
			hostFile:        isFile,
			backingReadOnly: ws.ReadOnly(),
			dynamic:         true,
			workspace:       ws,
		})
		sortMountsByDepth(s.mounts)
		s.mu.Unlock()
		s.emitEvent("mount", "add", map[string]string{"type": "hostfs", "target": target})
		return stream.Reply(control.MountInfo{
			Target: target, Type: "hostfs", Source: hostPath, ReadOnly: req.ReadOnly, Mutable: !req.ReadOnly,
		})

	default:
		return control.NewErrorf(control.CodeInvalidArgument, "unsupported dynamic mount type %q (want tmpfs, volume, or bind)", kind)
	}
}

func (s *Sandbox) handleMountRemount(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.MountRemountRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	target := path.Clean("/" + strings.TrimPrefix(strings.TrimSpace(req.Target), "/"))
	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}
	s.opMu.RLock()
	defer s.opMu.RUnlock()
	s.mountOpMu.Lock()
	defer s.mountOpMu.Unlock()

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	var (
		matched control.MountInfo
		found   bool
	)
	for _, info := range s.listMountInfos() {
		if info.Target == target {
			matched = info
			found = true
			break
		}
	}
	if !found {
		return control.NewErrorf(control.CodeNotFound, "mount target %q is not a managed mount point", target)
	}
	// Refuse remount rw when the host backing store was opened read-only.
	if !req.ReadOnly && !matched.Mutable {
		return control.NewErrorf(control.CodeLockdownDenied, "mount %q was opened read-only on the host and cannot be remounted read-write", target)
	}

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target), FollowFinalSymlink: false}
	vd, err := vfsObj.GetDentryAt(sctxWithRoot, creds, &pop, &vfs.GetDentryOptions{})
	if err != nil {
		return control.NewErrorf(control.CodeNotFound, "mount target %q not found: %v", target, err)
	}
	defer vd.DecRef(sctxWithRoot)

	if vd.Dentry() != vd.Mount().Root() {
		return control.NewErrorf(control.CodeInvalidArgument, "path %q is not a mount root", target)
	}

	if err := vfsObj.SetMountReadOnly(vd.Mount(), req.ReadOnly); err != nil {
		return control.NewErrorf(control.CodeBusy, "remount %q (ro=%t): %v", target, req.ReadOnly, err)
	}

	s.mu.Lock()
	if target == "/" {
		s.cfg.ReadOnlyRoot = req.ReadOnly
	} else {
		for i := range s.mounts {
			if s.mounts[i].GuestPath == target {
				s.mounts[i].ReadOnly = req.ReadOnly
			}
		}
	}
	s.mu.Unlock()
	s.rpcMountsMu.Lock()
	if rm, ok := s.rpcMounts[target]; ok {
		rm.readOnly = req.ReadOnly
	}
	s.rpcMountsMu.Unlock()
	s.emitEvent("mount", "remount", map[string]string{
		"target":    target,
		"read_only": strconv.FormatBool(req.ReadOnly),
	})
	return stream.Reply(map[string]any{"target": target, "read_only": req.ReadOnly})
}

func (s *Sandbox) handleMountRemove(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.MountRemoveRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	target := strings.TrimSpace(req.Target)
	if err := validateGuestPath(target); err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}
	s.opMu.RLock()
	defer s.opMu.RUnlock()
	s.mountOpMu.Lock()
	defer s.mountOpMu.Unlock()

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	var flags uint32
	if req.Detach {
		flags = linux.MNT_DETACH
	}
	pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
	if err := vfsObj.UmountAt(sctxWithRoot, creds, &pop, &vfs.UmountOptions{Flags: flags}); err != nil {
		if linuxerr.Equals(linuxerr.EBUSY, err) {
			return control.NewErrorf(control.CodeBusy, "mount %q is busy (pass --detach for lazy unmount)", target)
		}
		return control.NewErrorf(control.CodeNotFound, "unmount %q: %v", target, err)
	}

	var closeVol *ext4lite.Volume
	var closeWS *hostfs.Workspace
	var releaseExtHandle int64
	var hasReleaseExt bool
	s.mu.Lock()
	kept := s.mounts[:0]
	for _, m := range s.mounts {
		if m.GuestPath == target {
			if m.dynamic && !req.Detach {
				if m.volume != nil {
					closeVol = m.volume
					s.volumes = slices.DeleteFunc(s.volumes, func(v *ext4lite.Volume) bool { return v == closeVol })
				}
				if m.workspace != nil {
					closeWS = m.workspace
					s.workspaces = slices.DeleteFunc(s.workspaces, func(w *hostfs.Workspace) bool { return w == closeWS })
				}
				if m.hasSandboxExt {
					releaseExtHandle = m.sandboxExtHandle
					hasReleaseExt = true
					if idx := slices.Index(s.sandboxExtHandles, releaseExtHandle); idx >= 0 {
						s.sandboxExtHandles = slices.Delete(s.sandboxExtHandles, idx, idx+1)
					}
				}
			}
			continue
		}
		kept = append(kept, m)
	}
	s.mounts = kept
	s.mu.Unlock()
	if closeVol != nil {
		_ = closeVol.Close()
	}
	if closeWS != nil {
		_ = closeWS.Close()
	}
	if hasReleaseExt {
		_ = hostlockdown.ReleaseFileExtension(releaseExtHandle)
	}

	s.rpcMountsMu.Lock()
	rm := s.rpcMounts[target]
	delete(s.rpcMounts, target)
	s.rpcMountsMu.Unlock()
	if rm != nil {
		if rm.handle != nil {
			rm.handle.DetachClient()
		}
		if rm.cancel != nil {
			rm.cancel()
		}
		if rm.client != nil {
			_ = rm.client.Close()
		}
	}

	s.emitEvent("mount", "remove", map[string]string{"target": target})
	return stream.Reply(map[string]string{"removed": target})
}

// streamRPCFSClient bridges rpcfs.Client calls over a bidirectional control.Stream.
type streamRPCFSClient struct {
	ctx    context.Context
	cancel context.CancelFunc
	stream *control.Stream

	nextID        atomic.Uint64
	mu            sync.Mutex
	pending       map[uint64]chan control.RPCFSResponse
	notifyHandler func(rpcfs.NotifyEvent)
	closed        bool
}

func newStreamRPCFSClient(parent context.Context, stream *control.Stream) *streamRPCFSClient {
	ctx, cancel := context.WithCancel(parent)
	c := &streamRPCFSClient{
		ctx:     ctx,
		cancel:  cancel,
		stream:  stream,
		pending: make(map[uint64]chan control.RPCFSResponse),
	}
	go c.recvLoop()
	return c
}

func (c *streamRPCFSClient) MaxChunkBytes() int64 {
	maxFrame := c.stream.MaxFrameBytes()
	if maxFrame <= 0 {
		maxFrame = control.DefaultMaxFrameBytes
	}
	overhead := min(4096, maxFrame/4)
	chunk := int64(((maxFrame - overhead) * 3) / 4)
	if chunk < 512 {
		return 512
	}
	if chunk > 1<<20 {
		return 1 << 20
	}
	return chunk
}

func (c *streamRPCFSClient) SetNotifyHandler(fn func(rpcfs.NotifyEvent)) {
	c.mu.Lock()
	c.notifyHandler = fn
	c.mu.Unlock()
}

func (c *streamRPCFSClient) recvLoop() {
	defer func() {
		_ = c.Close()
	}()
	for {
		ev, err := c.stream.RecvEvent(c.ctx)
		if err != nil {
			return
		}
		switch ev.Type {
		case "rpcfs.resp":
			var resp control.RPCFSResponse
			if json.Unmarshal(ev.Data, &resp) != nil {
				continue
			}
			c.mu.Lock()
			ch := c.pending[resp.ID]
			delete(c.pending, resp.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- resp
			}
		case "rpcfs.notify":
			var nev control.RPCFSNotifyEvent
			if json.Unmarshal(ev.Data, &nev) != nil {
				continue
			}
			c.mu.Lock()
			handler := c.notifyHandler
			c.mu.Unlock()
			if handler != nil {
				handler(rpcfs.NotifyEvent{
					Path:   nev.Path,
					Name:   nev.Name,
					Mask:   nev.Mask,
					Cookie: nev.Cookie,
				})
			}
		}
	}
}

func (c *streamRPCFSClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	c.notifyHandler = nil
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.mu.Unlock()
	c.cancel()
	return nil
}

func errnoToLinuxErr(errno int) error {
	switch errno {
	case 0:
		return nil
	case control.LinuxENOENT:
		return linuxerr.ENOENT
	case control.LinuxEEXIST:
		return linuxerr.EEXIST
	case control.LinuxEACCES:
		return linuxerr.EACCES
	case control.LinuxEPERM:
		return linuxerr.EPERM
	case control.LinuxEBUSY:
		return linuxerr.EBUSY
	case control.LinuxEXDEV:
		return linuxerr.EXDEV
	case control.LinuxENOTDIR:
		return linuxerr.ENOTDIR
	case control.LinuxEISDIR:
		return linuxerr.EISDIR
	case control.LinuxENAMETOOLONG:
		return linuxerr.ENAMETOOLONG
	case control.LinuxENOTEMPTY:
		return linuxerr.ENOTEMPTY
	case control.LinuxELOOP:
		return linuxerr.ELOOP
	case control.LinuxEINVAL:
		return linuxerr.EINVAL
	case control.LinuxEROFS:
		return linuxerr.EROFS
	case control.LinuxENOSPC:
		return linuxerr.ENOSPC
	case control.LinuxEOPNOTSUPP:
		return linuxerr.EOPNOTSUPP
	default:
		return linuxerr.EIO
	}
}

func toRPCFSEntry(e control.RPCFSEntry) rpcfs.Entry {
	return rpcfs.Entry{
		Name:       e.Name,
		Ino:        e.Ino,
		Mode:       e.Mode,
		Size:       e.Size,
		Nlink:      e.Nlink,
		UID:        e.UID,
		GID:        e.GID,
		AtimeNS:    e.AtimeNS,
		MtimeNS:    e.MtimeNS,
		CtimeNS:    e.CtimeNS,
		LinkTarget: e.LinkTarget,
	}
}

func (c *streamRPCFSClient) roundTrip(ctx context.Context, req control.RPCFSRequest) (control.RPCFSResponse, error) {
	id := c.nextID.Add(1)
	req.ID = id
	ch := make(chan control.RPCFSResponse, 1)
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return control.RPCFSResponse{}, linuxerr.EIO
	}
	c.pending[id] = ch
	c.mu.Unlock()

	if err := c.stream.SendEvent(c.ctx, "rpcfs.req", req); err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return control.RPCFSResponse{}, linuxerr.EIO
	}

	select {
	case resp, ok := <-ch:
		if !ok {
			return control.RPCFSResponse{}, linuxerr.EIO
		}
		if resp.Errno != 0 {
			return resp, errnoToLinuxErr(resp.Errno)
		}
		if resp.Error != "" {
			return resp, linuxerr.EIO
		}
		return resp, nil
	case <-c.ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return control.RPCFSResponse{}, linuxerr.EIO
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return control.RPCFSResponse{}, linuxerr.EINTR
	}
}

func (c *streamRPCFSClient) Stat(ctx context.Context, rel string) (rpcfs.Entry, error) {
	resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "stat", Path: rel})
	if err != nil {
		return rpcfs.Entry{}, err
	}
	if resp.Entry == nil {
		return rpcfs.Entry{}, linuxerr.EIO
	}
	return toRPCFSEntry(*resp.Entry), nil
}

const (
	maxRPCFSReaddirPages   = 4096
	maxRPCFSReaddirEntries = 1 << 20
)

func (c *streamRPCFSClient) Readdir(ctx context.Context, rel string) ([]rpcfs.Entry, error) {
	var (
		out    []rpcfs.Entry
		offset int64
	)
	for range maxRPCFSReaddirPages {
		resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "readdir", Path: rel, Offset: offset})
		if err != nil {
			return nil, err
		}
		if len(out)+len(resp.Entries) > maxRPCFSReaddirEntries {
			return nil, linuxerr.EIO
		}
		for _, e := range resp.Entries {
			out = append(out, toRPCFSEntry(e))
		}
		if !resp.HasMore {
			return out, nil
		}
		if len(resp.Entries) == 0 || resp.NextOffset <= offset {
			return nil, linuxerr.EIO
		}
		offset = resp.NextOffset
	}
	return nil, linuxerr.EIO
}

func (c *streamRPCFSClient) Read(ctx context.Context, rel string, offset, length int64) ([]byte, error) {
	resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "read", Path: rel, Offset: offset, Length: length})
	if err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func (c *streamRPCFSClient) Write(ctx context.Context, rel string, offset int64, data []byte) (int64, error) {
	resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "write", Path: rel, Offset: offset, Data: data})
	if err != nil {
		return 0, err
	}
	return resp.Written, nil
}

func (c *streamRPCFSClient) Create(ctx context.Context, rel string, mode, flags uint32) (rpcfs.Entry, error) {
	resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "create", Path: rel, Mode: mode, Flags: flags})
	if err != nil {
		return rpcfs.Entry{}, err
	}
	if resp.Entry == nil {
		return rpcfs.Entry{}, linuxerr.EIO
	}
	return toRPCFSEntry(*resp.Entry), nil
}

func (c *streamRPCFSClient) Mkdir(ctx context.Context, rel string, mode uint32) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "mkdir", Path: rel, Mode: mode})
	return err
}

func (c *streamRPCFSClient) Unlink(ctx context.Context, rel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "unlink", Path: rel})
	return err
}

func (c *streamRPCFSClient) Rmdir(ctx context.Context, rel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "rmdir", Path: rel})
	return err
}

func (c *streamRPCFSClient) Rename(ctx context.Context, oldRel, newRel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "rename", Path: oldRel, NewPath: newRel})
	return err
}

func (c *streamRPCFSClient) Truncate(ctx context.Context, rel string, size int64) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "truncate", Path: rel, Size: size})
	return err
}

func (c *streamRPCFSClient) Chmod(ctx context.Context, rel string, mode uint32) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "chmod", Path: rel, Mode: mode})
	return err
}

func (c *streamRPCFSClient) Utimens(ctx context.Context, rel string, atimeNS, mtimeNS int64, setAtime, setMtime bool) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{
		Op: "utimens", Path: rel, AtimeNS: atimeNS, MtimeNS: mtimeNS, SetAtime: setAtime, SetMtime: setMtime,
	})
	return err
}

func (c *streamRPCFSClient) Readlink(ctx context.Context, rel string) (string, error) {
	resp, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "readlink", Path: rel})
	if err != nil {
		return "", err
	}
	if resp.Entry != nil {
		return resp.Entry.LinkTarget, nil
	}
	return "", linuxerr.EIO
}

func (c *streamRPCFSClient) Symlink(ctx context.Context, target, linkRel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "symlink", Path: linkRel, Target: target})
	return err
}

func (c *streamRPCFSClient) Watch(ctx context.Context, rel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "watch", Path: rel})
	return err
}

func (c *streamRPCFSClient) Unwatch(ctx context.Context, rel string) error {
	_, err := c.roundTrip(ctx, control.RPCFSRequest{Op: "unwatch", Path: rel})
	return err
}

func (s *Sandbox) handleMountServe(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.MountServeRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	target := strings.TrimSpace(req.Target)
	if err := validateGuestPath(target); err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}

	if _, _, err := s.activeKernelChecked(ctx); err != nil {
		return err
	}

	s.opMu.RLock()
	opLocked := true
	unlockOp := func() {
		if opLocked {
			opLocked = false
			s.opMu.RUnlock()
		}
	}
	defer unlockOp()

	s.mountOpMu.Lock()
	mountLocked := true
	unlockMount := func() {
		if mountLocked {
			mountLocked = false
			s.mountOpMu.Unlock()
		}
	}
	defer unlockMount()

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	s.mu.Lock()
	dupStatic := s.mountTargetExistsLocked(target)
	doneCh := s.runDone
	s.mu.Unlock()
	if dupStatic {
		return control.NewErrorf(control.CodeAlreadyExists, "mount target %q already exists", target)
	}
	s.rpcMountsMu.Lock()
	existing := s.rpcMounts[target]
	if existing != nil && !existing.detached {
		s.rpcMountsMu.Unlock()
		return control.NewErrorf(control.CodeAlreadyExists, "mount target %q already exists", target)
	}
	s.rpcMountsMu.Unlock()

	serveCtx, serveCancel := context.WithCancel(ctx)
	defer serveCancel()
	rpcClient := newStreamRPCFSClient(serveCtx, stream)
	defer rpcClient.Close()

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	defer root.DecRef(sctx)
	defer mntns.DecRef(sctx)
	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	creds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	var entry *rpcMountEntry
	if existing != nil {
		// Reconnect to a restored detached rpcfs mount in place so existing
		// guest file descriptors become valid again.
		if existing.singleFile != req.SingleFile {
			return control.NewErrorf(control.CodeInvalidArgument, "restored rpcfs mount %q single_file=%t does not match client single_file=%t", target, existing.singleFile, req.SingleFile)
		}
		if !req.ReadOnly && existing.backingReadOnly {
			return control.NewErrorf(control.CodeLockdownDenied, "restored rpcfs mount %q is read-only and cannot be served read-write", target)
		}
		if err := existing.handle.AttachClient(rpcClient, req.ReadOnly, req.Label); err != nil {
			return control.NewErrorf(control.CodeInternal, "reattach rpcfs at %q: %v", target, err)
		}
		prevLabel := existing.label
		prevReadOnly := existing.readOnly
		s.rpcMountsMu.Lock()
		existing.detached = false
		existing.readOnly = existing.backingReadOnly || req.ReadOnly
		if req.Label != "" {
			existing.label = req.Label
		}
		existing.stream = stream
		existing.cancel = serveCancel
		existing.client = rpcClient
		existing.checkpointClosing.Store(false)
		s.rpcMountsMu.Unlock()
		entry = existing

		if err := stream.SendResponse(control.MountServeResponse{Target: target}); err != nil {
			existing.handle.DetachClient()
			s.rpcMountsMu.Lock()
			if s.rpcMounts[target] == existing {
				existing.detached = true
				existing.label = prevLabel
				existing.readOnly = prevReadOnly
				existing.stream = nil
				existing.cancel = nil
				existing.client = nil
			}
			s.rpcMountsMu.Unlock()
			return err
		}
	} else {
		if req.SingleFile {
			if err := vfsEnsureEmptyFile(sctxWithRoot, vfsObj, creds, root, target, 0o644); err != nil {
				return control.NewErrorf(control.CodeInternal, "create rpcfs mount file %q: %v", target, err)
			}
		} else {
			if err := vfsEnsureDirAll(sctxWithRoot, vfsObj, creds, root, target, 0o755); err != nil {
				return control.NewErrorf(control.CodeInternal, "create rpcfs mount point %q: %v", target, err)
			}
		}
		fs, rootD, err := rpcfs.NewFilesystemWithOptions(sctxWithRoot, vfsObj, rpcClient, rpcfs.Options{
			Target:     target,
			Label:      req.Label,
			ReadOnly:   req.ReadOnly,
			SingleFile: req.SingleFile,
		})
		if err != nil {
			return control.NewErrorf(control.CodeInternal, "init rpcfs at %q: %v", target, err)
		}
		handle, _ := rpcfs.HandleOf(fs)
		mnt := vfsObj.NewDisconnectedMount(fs, rootD, &vfs.MountOptions{ReadOnly: req.ReadOnly})
		fs.DecRef(sctxWithRoot)
		rootD.DecRef(sctxWithRoot)

		pop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
		if err := vfsObj.ConnectMountAt(sctxWithRoot, creds, mnt, &pop); err != nil {
			mnt.DecRef(sctxWithRoot)
			return control.NewErrorf(control.CodeInternal, "connect rpcfs mount at %q: %v", target, err)
		}
		mnt.DecRef(sctxWithRoot)

		entry = &rpcMountEntry{
			target:          target,
			label:           req.Label,
			readOnly:        req.ReadOnly,
			backingReadOnly: req.ReadOnly,
			singleFile:      req.SingleFile,
			handle:          handle,
			stream:          stream,
			cancel:          serveCancel,
			client:          rpcClient,
		}
		s.rpcMountsMu.Lock()
		s.rpcMounts[target] = entry
		s.rpcMountsMu.Unlock()

		if err := stream.SendResponse(control.MountServeResponse{Target: target}); err != nil {
			s.rpcMountsMu.Lock()
			if s.rpcMounts[target] == entry {
				delete(s.rpcMounts, target)
			}
			s.rpcMountsMu.Unlock()
			umPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
			_ = vfsObj.UmountAt(sctxWithRoot, creds, &umPop, &vfs.UmountOptions{Flags: linux.MNT_DETACH})
			return err
		}
	}
	unlockMount()
	unlockOp()

	s.emitEvent("mount", "serve", map[string]string{
		"target":    target,
		"label":     req.Label,
		"read_only": strconv.FormatBool(req.ReadOnly),
	})

	// Hold the mount active until the client disconnects, sandbox exits,
	// checkpoint stops the sandbox, or mount.remove cancels serveCtx.
	var sandboxExited bool
	select {
	case <-serveCtx.Done():
	case <-doneCh:
		sandboxExited = true
	}

	if sandboxExited || entry.checkpointClosing.Load() {
		if sandboxExited {
			s.rpcMountsMu.Lock()
			if s.rpcMounts[target] == entry {
				delete(s.rpcMounts, target)
			}
			s.rpcMountsMu.Unlock()
		}
		return nil
	}

	// Lock order: opMu -> mountOpMu -> mu -> rpcMountsMu. Keep entry in
	// s.rpcMounts until UmountAt finishes so concurrent Checkpoint/mount.add
	// cannot observe a half-unmounted rpcfs or clobber a replacement mount.
	s.opMu.RLock()
	s.mountOpMu.Lock()
	if entry.checkpointClosing.Load() {
		s.mountOpMu.Unlock()
		s.opMu.RUnlock()
		return nil
	}
	s.mu.Lock()
	active := s.activeKernel == k
	s.mu.Unlock()
	s.rpcMountsMu.Lock()
	stillMounted := s.rpcMounts[target] == entry
	s.rpcMountsMu.Unlock()

	if stillMounted && active {
		umPop := vfs.PathOperation{Root: root, Start: root, Path: makeFPath(target)}
		_ = vfsObj.UmountAt(sctxWithRoot, creds, &umPop, &vfs.UmountOptions{Flags: linux.MNT_DETACH})
	}
	if entry.handle != nil {
		entry.handle.DetachClient()
	}
	s.rpcMountsMu.Lock()
	if s.rpcMounts[target] == entry {
		delete(s.rpcMounts, target)
	}
	s.rpcMountsMu.Unlock()
	s.mountOpMu.Unlock()
	s.opMu.RUnlock()

	if stillMounted && active {
		s.emitEvent("mount", "remove", map[string]string{"target": target, "reason": "client_disconnected"})
	}
	return nil
}
