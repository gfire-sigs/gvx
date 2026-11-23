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
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/hostlockdown"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

// eventHub fans out sandbox lifecycle events to active sandbox.events subscribers.
type eventHub struct {
	mu     sync.Mutex
	nextID uint64
	subs   map[uint64]chan control.SandboxEvent
}

func newEventHub() *eventHub {
	return &eventHub{subs: make(map[uint64]chan control.SandboxEvent)}
}

func (h *eventHub) publish(ev control.SandboxEvent) {
	if h == nil {
		return
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	h.mu.Lock()
	for _, ch := range h.subs {
		select {
		case ch <- ev:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *eventHub) subscribe() (<-chan control.SandboxEvent, func()) {
	ch := make(chan control.SandboxEvent, 128)
	h.mu.Lock()
	h.nextID++
	id := h.nextID
	h.subs[id] = ch
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.subs, id)
		h.mu.Unlock()
	}
}

func (s *Sandbox) emitEvent(typ, action string, attrs map[string]string) {
	if s.events == nil {
		return
	}
	s.events.publish(control.SandboxEvent{
		Timestamp:  time.Now().UTC(),
		Type:       typ,
		Action:     action,
		Attributes: attrs,
	})
}

func closeUnusedFDs(fds []int) {
	for _, fd := range fds {
		if fd >= 0 {
			_ = os.NewFile(uintptr(fd), "unused-scm-fd").Close()
		}
	}
}

type lockedControlListener struct {
	net.Listener
	locked bool
}

func (l lockedControlListener) Accept() (net.Conn, error) {
	if l.locked {
		return hostlockdown.AcceptListener(l.Listener)
	}
	return l.Listener.Accept()
}

// ControlCapabilities returns the active control protocol capability list after
// applying lockdown availability, Config.ControlPolicy, and Config.ControlDisable.
func (s *Sandbox) ControlCapabilities() []string {
	s.mu.Lock()
	locked := s.lockdown.Applied
	hasCkptDir := s.ckptFiles != nil
	hasNATPolicy := s.natPolicy != nil
	cfg := s.cfg
	s.mu.Unlock()

	avail := []string{
		control.CapPing,
		control.CapInspect,
		control.CapStats,
		control.CapEvents,
		control.CapPause,
		control.CapStop,
		control.CapCheckpointStream,
		control.CapExec,
		control.CapExecTTY,
		control.CapFSExport,
		control.CapFSImport,
		control.CapResourceMemory,
		control.CapResourceCPU,
		control.CapResourcePids,
		control.CapResourceTuning,
		control.CapNetDial,
		control.CapUnixForward,
		control.CapMountList,
		control.CapMountTmpfs,
		control.CapMountRemount,
		control.CapMountRemove,
		control.CapMountServe,
		control.CapProcList,
		control.CapProcSignal,
		control.CapKernelLog,
		control.CapKernelLogClear,
		control.CapDebug,
	}
	if hasCkptDir {
		avail = append(avail, control.CapCheckpointLocal)
	}
	if hasNATPolicy {
		avail = append(avail, control.CapNATPolicyRead, control.CapNATPolicyWrite)
	}
	if cfg.NetworkMode == NetModeNAT {
		avail = append(avail, control.CapResourceNetwork, control.CapPortList, control.CapPortRemove)
		if !locked || cfg.AutoPublishPorts || cfg.DynamicPorts || hasLoopbackBindAddr(cfg.DynamicPortAddrs) {
			avail = append(avail, control.CapPortDynamicLoopback)
		}
		if hasNonLoopbackBindAddr(cfg.DynamicPortAddrs) {
			avail = append(avail, control.CapPortDynamicAny)
		}
		if !locked {
			avail = append(avail, control.CapPortAnyBind)
		}
	}
	if !locked {
		avail = append(avail, control.CapMountBind)
	}
	if supportsBindAttach(runtime.GOOS, locked, cfg.AllowBindAttach) {
		avail = append(avail, control.CapMountBindAttach)
	}
	if supportsVolumeAttach(runtime.GOOS, locked, cfg.AllowVolumeAttach) {
		avail = append(avail, control.CapMountVolumeAttach)
	}
	return control.FilterCapabilities(avail, cfg.ControlPolicy, cfg.ControlDisable)
}

func supportsBindAttach(goos string, locked, allowBindAttach bool) bool {
	if goos != "darwin" && goos != "linux" && goos != "android" {
		return false
	}
	return !locked || allowBindAttach
}

func supportsVolumeAttach(goos string, locked, allowVolumeAttach bool) bool {
	if goos == "darwin" {
		return true
	}
	return (goos == "linux" || goos == "android") && (!locked || allowVolumeAttach)
}

// ServeControl serves gvx-ctrl/2 (and legacy v1 JSON checkpoint) requests on
// Config.ControlListener (or Config.CheckpointListener) until ctx is canceled
// or Sandbox.Close runs.
func (s *Sandbox) ServeControl(ctx context.Context) error {
	s.mu.Lock()
	ln := s.controlListener()
	locked := s.lockdown.Applied
	cfg := s.cfg
	hasBandwidth := s.bandwidth != nil
	s.mu.Unlock()
	if ln == nil {
		return fmt.Errorf("%w: Config.ControlListener is nil", ErrInvalidConfig)
	}
	caps := s.ControlCapabilities()
	var features []string
	if hasBandwidth {
		features = append(features, control.FeatureNetQoS)
	}
	srv := control.NewServer(lockedControlListener{Listener: ln, locked: locked}, control.ServerConfig{
		SandboxID:        cmp.Or(cfg.Name, "gvx-default"),
		Token:            cfg.ControlToken,
		Capabilities:     caps,
		AllowFDs:         slices.Contains(caps, control.CapMountVolumeAttach) || slices.Contains(caps, control.CapMountBindAttach),
		MaxConnections:   cfg.Tuning.Int(tuning.ControlMaxConnections),
		MaxFrameBytes:    int(cfg.Tuning.Size(tuning.ControlMaxFrameBytes)),
		HandshakeTimeout: cfg.Tuning.Duration(tuning.ControlHandshakeTimeout),
		Handler:          s,
		Features:         features,
	})
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.controlSrv = srv
	s.mu.Unlock()
	return srv.Serve(ctx)
}

// ShutdownControl gracefully stops ServeControl, sends GOAWAY to active v2
// connections, and waits until in-flight RPCs finish or ctx expires.
func (s *Sandbox) ShutdownControl(ctx context.Context) error {
	s.mu.Lock()
	srv := s.controlSrv
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// HandleLegacyCheckpoint implements control.Handler for backward-compatible v1
// JSON checkpoint requests.
func (s *Sandbox) HandleLegacyCheckpoint(ctx context.Context, req control.LegacyCheckpointRequest) error {
	if err := s.validateCheckpointDir(req.Dir); err != nil {
		return err
	}
	return s.Checkpoint(ctx, CheckpointOptions{LeaveRunning: req.LeaveRunning})
}

// HandleStream implements control.Handler and dispatches one v2 RPC stream.
func (s *Sandbox) HandleStream(ctx context.Context, stream *control.Stream, req control.RequestEnvelope, fds []int) error {
	if req.Method != control.MethodMountAdd {
		closeUnusedFDs(fds)
		fds = nil
	}
	switch req.Method {
	case control.MethodPing:
		return s.handlePing(ctx, stream)
	case control.MethodInspect:
		return s.handleInspect(ctx, stream)
	case control.MethodStats:
		return s.handleStats(ctx, stream, req.Params)
	case control.MethodEvents:
		return s.handleEvents(ctx, stream, req.Params)
	case control.MethodPause:
		return s.handlePause(ctx, stream, req.Params)
	case control.MethodUnpause:
		return s.handleUnpause(ctx, stream)
	case control.MethodStop:
		return s.handleStop(ctx, stream, req.Params)
	case control.MethodCheckpoint:
		return s.handleCheckpoint(ctx, stream, req.Params)
	case control.MethodCheckpointStream:
		return s.handleCheckpointStream(ctx, stream, req.Params)
	case control.MethodExecStart:
		return s.handleExecStart(ctx, stream, req.Params)
	case control.MethodFSStat:
		return s.handleFSStat(ctx, stream, req.Params)
	case control.MethodFSExport:
		return s.handleFSExport(ctx, stream, req.Params)
	case control.MethodFSImport:
		return s.handleFSImport(ctx, stream, req.Params)
	case control.MethodResourceUpdate:
		return s.handleResourceUpdate(ctx, stream, req.Params)
	case control.MethodPortList:
		return s.handlePortList(ctx, stream)
	case control.MethodPortAdd:
		return s.handlePortAdd(ctx, stream, req.Params)
	case control.MethodPortRemove:
		return s.handlePortRemove(ctx, stream, req.Params)
	case control.MethodNetDial:
		return s.handleNetDial(ctx, stream, req.Params)
	case control.MethodNATPolicyGet:
		return s.handleNATPolicyGet(ctx, stream)
	case control.MethodNATPolicySet:
		return s.handleNATPolicySet(ctx, stream, req.Params)
	case control.MethodUnixForward:
		return s.handleUnixForward(ctx, stream, req.Params)
	case control.MethodUnixAccept:
		return s.handleUnixAccept(ctx, stream, req.Params)
	case control.MethodMountList:
		return s.handleMountList(ctx, stream)
	case control.MethodMountAdd:
		return s.handleMountAdd(ctx, stream, req.Params, fds)
	case control.MethodMountRemount:
		return s.handleMountRemount(ctx, stream, req.Params)
	case control.MethodMountRemove:
		return s.handleMountRemove(ctx, stream, req.Params)
	case control.MethodMountServe:
		return s.handleMountServe(ctx, stream, req.Params)
	case control.MethodProcList:
		return s.handleProcList(ctx, stream)
	case control.MethodProcSignal:
		return s.handleProcSignal(ctx, stream, req.Params)
	case control.MethodKernelLog:
		return s.handleKernelLog(ctx, stream, req.Params)
	case control.MethodDebugLogLevel:
		return s.handleDebugLogLevel(ctx, stream, req.Params)
	default:
		return control.NewErrorf(control.CodeUnsupported, "unknown control method %q", req.Method)
	}
}

func decodeParams(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return control.NewErrorf(control.CodeInvalidArgument, "decode params: %v", err)
	}
	return nil
}

func (s *Sandbox) activeKernelChecked(ctx context.Context) (*kernel.Kernel, *kernel.ThreadGroup, error) {
	s.mu.Lock()
	readyCh := s.kernelReady
	doneCh := s.runDone
	s.mu.Unlock()
	if readyCh == nil {
		return nil, nil, control.NewError(control.CodeSandboxExiting, "sandbox is not initialized")
	}
	select {
	case <-readyCh:
	case <-doneCh:
		return nil, nil, control.NewError(control.CodeSandboxExiting, "sandbox has exited")
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
	return s.activeKernelNow()
}

// activeKernelNow returns the currently active kernel without waiting on
// kernelReady. Callers holding s.opMu must use this after waiting on
// kernelReady beforehand to avoid AB-BA deadlocks with executeActiveKernel.
func (s *Sandbox) activeKernelNow() (*kernel.Kernel, *kernel.ThreadGroup, error) {
	s.mu.Lock()
	k := s.activeKernel
	s.mu.Unlock()
	if k == nil {
		return nil, nil, control.NewError(control.CodeSandboxExiting, "sandbox is not running")
	}
	tg := k.GlobalInit()
	if tg == nil {
		return nil, nil, control.NewError(control.CodeSandboxExiting, "sandbox init process has exited")
	}
	return k, tg, nil
}

// guestRoot acquires references to the guest root VirtualDentry and
// MountNamespace of PID 1. The caller must DecRef both returned objects.
func (s *Sandbox) guestRoot(sctx gvcontext.Context, k *kernel.Kernel) (vfs.VirtualDentry, *vfs.MountNamespace, error) {
	tg := k.GlobalInit()
	if tg == nil {
		return vfs.VirtualDentry{}, nil, control.NewError(control.CodeSandboxExiting, "sandbox init process has exited")
	}
	leader := tg.Leader()
	if leader == nil {
		return vfs.VirtualDentry{}, nil, control.NewError(control.CodeSandboxExiting, "sandbox init leader is unavailable")
	}
	mntns := leader.GetMountNamespace()
	if mntns == nil {
		return vfs.VirtualDentry{}, nil, control.NewError(control.CodeSandboxExiting, "sandbox mount namespace is unavailable")
	}
	root := mntns.Root(sctx)
	return root, mntns, nil
}

// withGuestVFS binds both root and mntns onto sctx so VFS mount operations
// never re-acquire kernel.extMu via supervisorContext.Value while holding
// vfs.mountMu.
func withGuestVFS(sctx gvcontext.Context, root vfs.VirtualDentry, mntns *vfs.MountNamespace) gvcontext.Context {
	return vfs.WithMountNamespace(vfs.WithRoot(sctx, root), mntns)
}

func (s *Sandbox) sandboxStateString() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return "exited"
	}
	if s.activeKernel == nil {
		select {
		case <-s.runDone:
			return "exited"
		default:
			return "starting"
		}
	}
	if s.userPaused {
		return "paused"
	}
	return "running"
}

func mapControlErr(err error) error {
	if err == nil {
		return nil
	}
	var pe *control.ProtoError
	if errors.As(err, &pe) {
		return pe
	}
	switch {
	case errors.Is(err, ErrCheckpointExecActive):
		return control.NewError(control.CodeExecActive, err.Error())
	case errors.Is(err, ErrCheckpointRPCFSActive), errors.Is(err, ErrCheckpointNATTunnelActive):
		return control.NewError(control.CodeBusy, err.Error())
	case errors.Is(err, ErrInvalidConfig):
		return control.NewError(control.CodeInvalidArgument, err.Error())
	default:
		msg := err.Error()
		if strings.Contains(msg, "not found") || strings.Contains(msg, "no such") {
			return control.NewError(control.CodeNotFound, msg)
		}
		return control.NewError(control.CodeInternal, msg)
	}
}
