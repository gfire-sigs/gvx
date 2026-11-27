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
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	gvcontext "z.gfire.dev/gvx/pkg/context"
	"z.gfire.dev/gvx/pkg/errors/linuxerr"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/vfs"
)

type execSession struct {
	pid    int32
	tg     *kernel.ThreadGroup
	tty    *ttyState
	cancel context.CancelFunc
	done   chan struct{}
}

func (s *Sandbox) activeExecCount() int {
	s.execMu.Lock()
	defer s.execMu.Unlock()
	return len(s.execSessions) + s.execReserved
}

// forceStopExecSessions sends SIGKILL to every active exec session and waits
// until each session finishes exiting and tearing down its temporary stdio
// devices before returning.
func (s *Sandbox) forceStopExecSessions(ctx context.Context, k *kernel.Kernel) error {
	s.execMu.Lock()
	sessions := make([]*execSession, 0, len(s.execSessions))
	for _, sess := range s.execSessions {
		sessions = append(sessions, sess)
	}
	s.execMu.Unlock()
	for _, sess := range sessions {
		if sess.cancel != nil {
			sess.cancel()
		}
		if sess.tg != nil && k != nil {
			_ = k.SendExternalSignalThreadGroup(sess.tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, sess := range sessions {
		if sess.done == nil {
			continue
		}
		select {
		case <-sess.done:
		case <-waitCtx.Done():
			return waitCtx.Err()
		}
	}
	return nil
}

func (s *Sandbox) resolveExecCredentials(
	sctx gvcontext.Context,
	vfsObj *vfs.VirtualFilesystem,
	rootCreds *auth.Credentials,
	rootDentry vfs.VirtualDentry,
	userSpec string,
	privileged *bool,
) (execUser, *auth.Credentials, error) {
	spec := strings.TrimSpace(userSpec)
	if spec == "" {
		spec = s.cfg.User
		if spec == "" && s.resolvedImg != nil {
			spec = s.resolvedImg.Config.User
		}
	}
	passwd, err := readGuestFile(sctx, vfsObj, rootCreds, rootDentry, "/etc/passwd", maxGuestIdentityFile)
	if err != nil {
		return execUser{}, nil, err
	}
	group, err := readGuestFile(sctx, vfsObj, rootCreds, rootDentry, "/etc/group", maxGuestIdentityFile)
	if err != nil {
		return execUser{}, nil, err
	}
	user, err := resolveExecUser(spec, passwd, group)
	if err != nil {
		return execUser{}, nil, control.NewErrorf(control.CodeInvalidArgument, "resolve user %q: %v", spec, err)
	}
	extra := make([]auth.KGID, len(user.ExtraGIDs))
	for i, g := range user.ExtraGIDs {
		extra[i] = auth.KGID(g)
	}
	dropCaps := privileged != nil && !*privileged
	if user.UID == 0 && user.GID == 0 && len(extra) == 0 && !dropCaps {
		return user, rootCreds, nil
	}
	var caps *auth.TaskCapabilities
	if dropCaps {
		// Pass a non-nil zero TaskCapabilities so NewUserCredentials drops all
		// permitted, effective, and bounding capabilities even for UID 0.
		caps = &auth.TaskCapabilities{}
	} else if user.UID == 0 {
		all := auth.AllCapabilities
		caps = &auth.TaskCapabilities{
			PermittedCaps:   all,
			InheritableCaps: all,
			EffectiveCaps:   all,
			BoundingCaps:    all,
		}
	}
	return user, auth.NewUserCredentials(auth.KUID(user.UID), auth.KGID(user.GID), extra, caps, rootCreds.UserNamespace), nil
}

func mergeExecEnv(base, overrides []string) []string {
	out := append([]string(nil), base...)
	index := make(map[string]int, len(out))
	for i, kv := range out {
		if k, _, ok := strings.Cut(kv, "="); ok {
			index[k] = i
		}
	}
	for _, kv := range overrides {
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			continue
		}
		if pos, exists := index[k]; exists {
			out[pos] = kv
		} else {
			index[k] = len(out)
			out = append(out, kv)
		}
	}
	return out
}

type streamOutWriter struct {
	ctx      context.Context
	stream   *control.Stream
	ch       control.Channel
	mu       sync.Mutex
	disabled bool
}

func (w *streamOutWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	disabled := w.disabled
	w.mu.Unlock()
	if disabled {
		return len(p), nil
	}
	if err := w.stream.WriteData(w.ctx, w.ch, p, false); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *streamOutWriter) detach() {
	w.mu.Lock()
	w.disabled = true
	w.mu.Unlock()
}

func (s *Sandbox) handleExecStart(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.ExecStartRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if len(req.Argv) == 0 || strings.TrimSpace(req.Argv[0]) == "" {
		return control.NewError(control.CodeInvalidArgument, "exec argv must not be empty")
	}
	if req.TTY && !slices.Contains(s.ControlCapabilities(), control.CapExecTTY) {
		return control.NewError(control.CodeForbiddenByPolicy, "exec TTY allocation is disabled by policy")
	}

	// Wait for kernel startup before acquiring s.opMu so early exec RPCs never
	// deadlock with executeActiveKernel holding s.opMu.Lock() during startup.
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

	k, _, err := s.activeKernelNow()
	if err != nil {
		return err
	}

	s.mu.Lock()
	paused := s.userPaused
	maxSessions := s.cfg.Tuning.Int(tuning.ControlMaxExecSessions)
	s.mu.Unlock()
	if paused {
		return control.NewError(control.CodeAlreadyPaused, "cannot exec while sandbox is paused")
	}

	if maxSessions <= 0 {
		maxSessions = 32
	}
	s.execMu.Lock()
	if len(s.execSessions)+s.execReserved >= maxSessions {
		s.execMu.Unlock()
		return control.NewErrorf(control.CodeLimitExceeded, "active exec session limit (%d) reached", maxSessions)
	}
	s.execReserved++
	s.execMu.Unlock()
	reserved := true
	releaseReserved := func() {
		if reserved {
			reserved = false
			s.execMu.Lock()
			s.execReserved--
			s.execMu.Unlock()
		}
	}
	defer releaseReserved()

	sctx := k.SupervisorContext()
	root, mntns, err := s.guestRoot(sctx, k)
	if err != nil {
		return err
	}
	releaseVFS := sync.OnceFunc(func() {
		root.DecRef(sctx)
		mntns.DecRef(sctx)
	})
	defer releaseVFS()

	sctxWithRoot := withGuestVFS(sctx, root, mntns)
	rootCreds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	// Build merged environment (sandbox env + exec -e overrides).
	mergedEnv := mergeExecEnv(s.cfg.Envv, req.Env)
	workDir := strings.TrimSpace(req.WorkDir)
	if workDir == "" {
		workDir = s.initialWorkingDir()
	}
	if !strings.HasPrefix(workDir, "/") {
		return control.NewErrorf(control.CodeInvalidArgument, "working directory %q must be absolute", workDir)
	}

	execPath, err := resolveGuestExecutable(sctxWithRoot, vfsObj, rootCreds, root, req.Argv[0], workDir, mergedEnv)
	if err != nil {
		return control.NewError(control.CodeNotFound, err.Error())
	}

	user, procCreds, err := s.resolveExecCredentials(sctxWithRoot, vfsObj, rootCreds, root, req.User, req.Privileged)
	if err != nil {
		return err
	}

	ls, err := createSandboxLimitSet()
	if err != nil {
		return control.NewErrorf(control.CodeInternal, "create limits: %v", err)
	}

	// Docker-style stdin: closed (/dev/null EOF) unless req.Stdin is true.
	var (
		inReader   io.Reader
		outWriter  io.Writer = io.Discard
		errWriter  io.Writer = io.Discard
		streamOut  *streamOutWriter
		streamErr  *streamOutWriter
		tty        *ttyState
		pump       *stdinPump
		cleanups   []func()
		runCleanup = func() {
			for i := len(cleanups) - 1; i >= 0; i-- {
				cleanups[i]()
			}
		}
	)

	execCtx, execCancel := context.WithCancel(context.Background())
	if !req.Detach {
		streamOut = &streamOutWriter{ctx: ctx, stream: stream, ch: control.ChannelStdout}
		outWriter = streamOut
		if req.TTY {
			errWriter = streamOut
		} else {
			streamErr = &streamOutWriter{ctx: ctx, stream: stream, ch: control.ChannelStderr}
			errWriter = streamErr
		}
		if req.Stdin {
			inReader = stream.ChannelReader(ctx, control.ChannelStdin)
		}
		if req.TTY {
			rows, cols := req.Rows, req.Cols
			if rows == 0 {
				rows = 24
			}
			if cols == 0 {
				cols = 80
			}
			tty = newTTYState(inReader, outWriter, true, rows, cols)
			removeTTY := s.addStdioQuiescer(tty)
			cleanups = append(cleanups, removeTTY, tty.stop)
		} else if inReader != nil {
			pump = newStdinPump(inReader)
			removePump := s.addStdioQuiescer(pump)
			cleanups = append(cleanups, removePump, pump.stop)
		}
	}

	baseMinor := s.nextStdioMinor.Add(3) - 3
	stdioFDs, unregisterDevs, err := openStdioFDsAtMinor(sctx, vfsObj, rootCreds, baseMinor, inReader, outWriter, errWriter, tty, pump)
	if err != nil {
		execCancel()
		runCleanup()
		return control.NewErrorf(control.CodeInternal, "open exec stdio: %v", err)
	}
	cleanups = append(cleanups, unregisterDevs)

	fdTable := k.NewFDTable()
	_, fdErr := fdTable.NewFDs(sctx, 0, stdioFDs[:], kernel.FDFlags{})
	for _, fd := range stdioFDs {
		fd.DecRef(sctx)
	}
	if fdErr != nil {
		fdTable.DecRef(sctx)
		execCancel()
		runCleanup()
		return control.NewErrorf(control.CodeInternal, "bind exec stdio: %v", fdErr)
	}

	var procTTY *kernel.TTY
	if tty != nil {
		procTTY = tty.ktty
	}

	mntns.IncRef()
	procArgs := kernel.CreateProcessArgs{
		Filename:             execPath,
		Argv:                 req.Argv,
		Envv:                 finalizeEnv(mergedEnv, guestEnvDefaults{Home: user.Home, Hostname: s.hostname(), TTY: req.TTY}),
		WorkingDirectory:     workDir,
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

	tg, tid, err := k.CreateProcess(procArgs)
	fdTable.DecRef(sctx)
	releaseVFS()
	if err != nil {
		execCancel()
		runCleanup()
		if linuxerr.Equals(linuxerr.EAGAIN, err) {
			return control.NewErrorf(control.CodeLimitExceeded, "create exec process %q: %v", execPath, err)
		}
		return control.NewErrorf(control.CodeInternal, "create exec process %q: %v", execPath, err)
	}
	k.StartProcess(tg)
	if tty != nil {
		tty.startPump()
	}

	pid := int32(tid)
	sessDone := make(chan struct{})
	sess := &execSession{pid: pid, tg: tg, tty: tty, cancel: execCancel, done: sessDone}
	s.execMu.Lock()
	if reserved {
		reserved = false
		s.execReserved--
	}
	s.execSessions[pid] = sess
	s.execMu.Unlock()
	unlockOp()

	finishSession := sync.OnceFunc(func() {
		execCancel()
		runCleanup()
		s.execMu.Lock()
		delete(s.execSessions, pid)
		s.execMu.Unlock()
		close(sessDone)
	})

	s.emitEvent("exec", "start", map[string]string{
		"pid":  strconv.Itoa(int(pid)),
		"argv": strings.Join(req.Argv, " "),
	})

	if req.Detach {
		// Reap detached exec resources asynchronously on exit.
		go func() {
			tg.WaitExited()
			ws := tg.ExitStatus()
			finishSession()
			s.emitEvent("exec", "exit", map[string]string{
				"pid":       strconv.Itoa(int(pid)),
				"exit_code": strconv.Itoa(int(ws.ExitStatus())),
			})
		}()
		return stream.Reply(control.ExecStartResponse{PID: pid})
	}

	if err := stream.SendResponse(control.ExecStartResponse{PID: pid}); err != nil {
		// Client disappeared right after start; let process finish and clean up.
		if streamOut != nil {
			streamOut.detach()
		}
		if streamErr != nil {
			streamErr.detach()
		}
		go func() {
			tg.WaitExited()
			finishSession()
		}()
		return err
	}

	// Listen for client-sent exec.resize and exec.signal events while attached.
	evDone := make(chan struct{})
	go func() {
		defer close(evDone)
		for {
			ev, evErr := stream.RecvEvent(execCtx)
			if evErr != nil {
				return
			}
			switch ev.Type {
			case "exec.resize":
				if tty != nil {
					var r control.ExecResizeEvent
					if json.Unmarshal(ev.Data, &r) == nil && r.Rows > 0 && r.Cols > 0 {
						tty.deliverWinsize(linux.Winsize{Row: r.Rows, Col: r.Cols})
					}
				}
			case "exec.signal":
				var sigEv control.ExecSignalEvent
				if json.Unmarshal(ev.Data, &sigEv) == nil {
					if sig, parseErr := parseLinuxSignal(sigEv.Signal); parseErr == nil {
						sentForeground := false
						if tty != nil && sig != linux.SIGKILL && tty.ktty != nil {
							if cttyTG := tty.ktty.ThreadGroup(); cttyTG != nil {
								if fg, _ := cttyTG.ForegroundProcessGroup(tty.ktty); fg != nil {
									tty.signalForeground(sig)
									sentForeground = true
								}
							}
						}
						if !sentForeground {
							_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(sig)})
						}
					}
				}
			}
		}
	}()

	exitedCh := make(chan struct{})
	go func() {
		defer close(exitedCh)
		tg.WaitExited()
	}()

	select {
	case <-exitedCh:
		// Process exited cleanly. Read exit status before closing sessDone so
		// checkpoint/save never races with kernel task reads.
		execCancel()
		<-evDone
		ws := tg.ExitStatus()
		finishSession()

		_ = stream.CloseChannel(control.ChannelStdout)
		if !req.TTY {
			_ = stream.CloseChannel(control.ChannelStderr)
		}
		exitEv := control.ExecExitEvent{}
		if ws.Signaled() {
			exitEv.Signal = int32(ws.TerminationSignal())
			exitEv.ExitCode = 128 + int(ws.TerminationSignal())
		} else {
			exitEv.ExitCode = int(ws.ExitStatus())
		}
		s.emitEvent("exec", "exit", map[string]string{
			"pid":       strconv.Itoa(int(pid)),
			"exit_code": strconv.Itoa(exitEv.ExitCode),
		})
		_ = stream.SendFinalEvent(ctx, "exec.exit", exitEv)
		return nil

	case <-ctx.Done():
		// Client disconnected or detached. Detach stream writers so guest I/O
		// continues without blocking, and reap the process in the background.
		execCancel()
		if streamOut != nil {
			streamOut.detach()
		}
		if streamErr != nil {
			streamErr.detach()
		}
		if tty != nil {
			tty.stop()
		}
		if pump != nil {
			pump.stop()
		}
		go func() {
			<-exitedCh
			ws := tg.ExitStatus()
			finishSession()
			s.emitEvent("exec", "exit", map[string]string{
				"pid":       strconv.Itoa(int(pid)),
				"exit_code": strconv.Itoa(int(ws.ExitStatus())),
			})
		}()
		return nil
	}
}
