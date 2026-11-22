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
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
)

// Pause pauses all guest vCPUs/tasks and optionally quiesces host network traffic.
func (s *Sandbox) Pause(ctx context.Context, quiesceNet bool) error {
	s.ckptMu.Lock()
	defer s.ckptMu.Unlock()

	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if s.userPaused {
		s.mu.Unlock()
		return control.NewError(control.CodeAlreadyPaused, "sandbox is already paused")
	}
	dog := s.activeWatchdog
	quiescers := s.saveQuiescersLocked()
	s.mu.Unlock()

	if dog != nil {
		dog.Stop()
	}
	k.Pause()
	if quiesceNet {
		for _, q := range quiescers {
			q.QuiesceForSave()
		}
	}

	s.mu.Lock()
	s.userPaused = true
	s.userPauseQuiesced = quiesceNet
	s.mu.Unlock()

	s.emitEvent("lifecycle", "pause", map[string]string{
		"quiesce_net": strconv.FormatBool(quiesceNet),
	})
	return nil
}

// Unpause resumes a sandbox previously paused with Pause.
func (s *Sandbox) Unpause(ctx context.Context) error {
	s.ckptMu.Lock()
	defer s.ckptMu.Unlock()

	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if !s.userPaused {
		s.mu.Unlock()
		return control.NewError(control.CodeNotPaused, "sandbox is not paused")
	}
	dog := s.activeWatchdog
	wasQuiesced := s.userPauseQuiesced
	quiescers := s.saveQuiescersLocked()
	s.userPaused = false
	s.userPauseQuiesced = false
	s.mu.Unlock()

	if wasQuiesced {
		for _, q := range quiescers {
			_ = q.ResumeAfterSave()
		}
	}
	if dog != nil {
		dog.Start()
	}
	k.Unpause()

	s.emitEvent("lifecycle", "unpause", nil)
	return nil
}

func (s *Sandbox) handlePause(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.PauseRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	quiesce := true
	if req.QuiesceNet != nil {
		quiesce = *req.QuiesceNet
	}
	if err := s.Pause(ctx, quiesce); err != nil {
		return mapControlErr(err)
	}
	return stream.Reply(map[string]string{"state": "paused"})
}

func (s *Sandbox) handleUnpause(ctx context.Context, stream *control.Stream) error {
	if err := s.Unpause(ctx); err != nil {
		return mapControlErr(err)
	}
	return stream.Reply(map[string]string{"state": "running"})
}

func (s *Sandbox) handleStop(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.StopRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	sigName := req.Signal
	if sigName == "" {
		sigName = "SIGTERM"
	}
	sig, err := parseLinuxSignal(sigName)
	if err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	timeout := 10 * time.Second
	if req.TimeoutMS > 0 {
		timeout = time.Duration(req.TimeoutMS) * time.Millisecond
	}

	k, tg, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	s.mu.Lock()
	dog := s.activeWatchdog
	doneCh := s.runDone
	s.mu.Unlock()

	// Unpause first so PID 1 can receive and handle the stop signal.
	s.unpauseForShutdown(k, dog)

	if err := k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(sig)}); err != nil {
		return control.NewErrorf(control.CodeInternal, "deliver %s: %v", sigName, err)
	}
	s.emitEvent("lifecycle", "stop", map[string]string{"signal": sigName})

	if sig == linux.SIGKILL {
		return stream.Reply(control.StopResponse{Signaled: sigName, Killed: true})
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-doneCh:
		return stream.Reply(control.StopResponse{Signaled: sigName, Killed: false})
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		_ = k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(linux.SIGKILL)})
		return stream.Reply(control.StopResponse{Signaled: sigName, Killed: true})
	}
}

func (s *Sandbox) handleCheckpoint(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.CheckpointRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if err := s.validateCheckpointDir(req.Dir); err != nil {
		return err
	}
	if err := s.Checkpoint(ctx, CheckpointOptions{
		LeaveRunning: req.LeaveRunning,
		Force:        req.Force,
	}); err != nil {
		return mapControlErr(err)
	}
	return stream.Reply(map[string]bool{"ok": true})
}

func (s *Sandbox) handleCheckpointStream(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.CheckpointStreamRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	manifestBytes, stateBytes, pagesMetaBytes, pagesBytes, doneCh, err := s.captureCheckpointStreamBuffers(ctx, CheckpointOptions{
		LeaveRunning: req.LeaveRunning,
		Force:        req.Force,
	})
	if err != nil {
		return mapControlErr(err)
	}
	if err := stream.SendResponse(control.CheckpointStreamResponse{
		Files: []string{
			checkpointManifestFileName,
			checkpointStateFileName,
			checkpointPagesMetaFileName,
			checkpointPagesFileName,
		},
	}); err != nil {
		return err
	}
	w := stream.ChannelWriter(ctx, control.ChannelGeneric, req.Compress)
	if err := writeCheckpointTar(w, manifestBytes, stateBytes, pagesMetaBytes, pagesBytes); err != nil {
		_ = w.Close()
		return mapControlErr(err)
	}
	if err := w.Close(); err != nil {
		return err
	}
	if !req.LeaveRunning {
		select {
		case <-doneCh:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Sandbox) handleResourceUpdate(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.ResourceUpdateRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	caps := s.ControlCapabilities()
	hasCap := func(c string) bool { return slices.Contains(caps, c) }

	// Validate all requested fields before mutating any state.
	if req.MemoryBytes != nil {
		if !hasCap(control.CapResourceMemory) {
			return control.NewError(control.CodeForbiddenByPolicy, "memory updates are disabled by policy")
		}
		m := *req.MemoryBytes
		if m < 0 || (m > 0 && m < MinMemoryLimit) {
			return control.NewErrorf(control.CodeInvalidArgument, "memory limit %d is invalid (want 0 or >= %d)", m, MinMemoryLimit)
		}
		if m > 0 && !req.ForceMemory {
			s.mu.Lock()
			mf := s.runMemFile
			s.mu.Unlock()
			if mf != nil {
				mf.FlushCommitScan()
				_ = mf.UpdateUsage(nil)
				used := mf.Accounting().Total()
				if uint64(m) < used {
					return control.NewErrorf(control.CodeInvalidArgument, "requested memory limit %d bytes is below current usage %d bytes (pass --force-memory to allow immediate OOM)", m, used)
				}
			}
		}
	}
	if req.CPUMillis != nil || req.CPUQuotaUSec != nil || req.CPUPeriodUSec != nil {
		if !hasCap(control.CapResourceCPU) {
			return control.NewError(control.CodeForbiddenByPolicy, "CPU updates are disabled by policy")
		}
		if req.CPUMillis != nil && (req.CPUQuotaUSec != nil || req.CPUPeriodUSec != nil) {
			return control.NewError(control.CodeInvalidArgument, "specify either --cpus or --cpu-quota/--cpu-period, not both")
		}
		if req.CPUMillis != nil {
			q := *req.CPUMillis
			if q < 0 || q > int64(runtime.NumCPU())*1000 {
				return control.NewErrorf(control.CodeInvalidArgument, "CPU quota %d exceeds host range [0, %d]", q, runtime.NumCPU()*1000)
			}
		} else {
			period := int64(100000)
			if req.CPUPeriodUSec != nil {
				period = *req.CPUPeriodUSec
			}
			if period < 1000 || period > 1000000 {
				return control.NewErrorf(control.CodeInvalidArgument, "cpu period %d us out of range [1000, 1000000]", period)
			}
			if req.CPUQuotaUSec != nil && *req.CPUQuotaUSec != 0 && *req.CPUQuotaUSec < 1000 {
				return control.NewErrorf(control.CodeInvalidArgument, "cpu quota %d us must be 0 (unlimited) or >= 1000", *req.CPUQuotaUSec)
			}
		}
	}
	if req.PidsLimit != nil {
		if !hasCap(control.CapResourcePids) {
			return control.NewError(control.CodeForbiddenByPolicy, "pids limit updates are disabled by policy")
		}
		if *req.PidsLimit < 0 {
			return control.NewError(control.CodeInvalidArgument, "pids limit must be non-negative")
		}
	}
	if req.IsolateLAN != nil {
		if !hasCap(control.CapResourceNetwork) {
			return control.NewError(control.CodeForbiddenByPolicy, "network policy updates are disabled by policy")
		}
		if s.natForwarder == nil {
			return control.NewError(control.CodeUnsupported, "--isolate-lan requires -net=nat")
		}
	}

	var parsedTuning tuning.Values
	if len(req.Tuning) > 0 {
		if !hasCap(control.CapResourceTuning) {
			return control.NewError(control.CodeForbiddenByPolicy, "tuning updates are disabled by policy")
		}
		s.mu.Lock()
		parsedTuning = s.cfg.Tuning
		s.mu.Unlock()
		for kName, rawVal := range req.Tuning {
			if !tuning.IsMutable(kName) {
				return control.NewErrorf(control.CodeInvalidArgument, "tunable %q cannot be changed at runtime", kName)
			}
			var setErr error
			parsedTuning, setErr = parsedTuning.Set(kName, rawVal)
			if setErr != nil {
				return control.NewErrorf(control.CodeInvalidArgument, "tunable %s=%s: %v", kName, rawVal, setErr)
			}
		}
	}

	// Apply validated updates.
	attrs := map[string]string{}
	if req.MemoryBytes != nil {
		m := *req.MemoryBytes
		hostRAM, _ := hostMemory()
		s.mu.Lock()
		s.cfg.Resources.MemoryBytes = m
		curTune := s.cfg.Tuning
		s.mu.Unlock()
		s.liveMemoryBytes.Store(m)
		limit, interval := effectiveMemoryLimit(m, hostRAM, curTune)
		s.liveMemoryLimit.Store(limit)
		s.liveMemoryIntNS.Store(int64(interval))
		if m > 0 {
			k.SetReportedMemory(reportedMemory(m, hostRAM))
		} else {
			k.SetReportedMemory(0)
		}
		select {
		case s.liveMemoryWake <- struct{}{}:
		default:
		}
		attrs["memory_bytes"] = strconv.FormatInt(m, 10)
	}

	if req.CPUMillis != nil {
		q := *req.CPUMillis
		s.mu.Lock()
		s.cfg.Resources.CPUMillis = q
		s.mu.Unlock()
		if q == 0 {
			k.SetSandboxCPULimit(-1, 100*time.Millisecond)
		} else {
			quota := max(time.Duration(q)*100*time.Microsecond, time.Millisecond)
			k.SetSandboxCPULimit(quota, 100*time.Millisecond)
		}
		attrs["cpu_millis"] = strconv.FormatInt(q, 10)
	} else if req.CPUQuotaUSec != nil || req.CPUPeriodUSec != nil {
		curQuota, curPeriod, limited := k.SandboxCPULimit()
		period := curPeriod
		if period <= 0 {
			period = 100 * time.Millisecond
		}
		if req.CPUPeriodUSec != nil {
			period = time.Duration(*req.CPUPeriodUSec) * time.Microsecond
		}
		quota := curQuota
		if !limited {
			quota = -1
		}
		if req.CPUQuotaUSec != nil {
			if *req.CPUQuotaUSec <= 0 {
				quota = -1
			} else {
				quota = time.Duration(*req.CPUQuotaUSec) * time.Microsecond
			}
		}
		k.SetSandboxCPULimit(quota, period)
		var millis int64
		if quota > 0 && period > 0 {
			millis = int64(quota) * 1000 / int64(period)
		}
		s.mu.Lock()
		s.cfg.Resources.CPUMillis = millis
		s.mu.Unlock()
		attrs["cpu_quota_us"] = strconv.FormatInt(quota.Microseconds(), 10)
		attrs["cpu_period_us"] = strconv.FormatInt(period.Microseconds(), 10)
	}

	if req.PidsLimit != nil {
		if err := cgroup2fs.SetRootPidsMax(k, *req.PidsLimit); err != nil {
			return control.NewErrorf(control.CodeInvalidArgument, "set pids limit: %v", err)
		}
		s.mu.Lock()
		s.cfg.Resources.PidsLimit = *req.PidsLimit
		s.mu.Unlock()
		attrs["pids_limit"] = strconv.FormatInt(*req.PidsLimit, 10)
	}

	if req.IsolateLAN != nil && s.natForwarder != nil {
		s.natForwarder.SetIsolateLAN(*req.IsolateLAN)
		s.mu.Lock()
		s.cfg.IsolateLAN = *req.IsolateLAN
		s.mu.Unlock()
		attrs["isolate_lan"] = strconv.FormatBool(*req.IsolateLAN)
	}

	if len(req.Tuning) > 0 {
		s.mu.Lock()
		s.cfg.Tuning = parsedTuning
		s.mu.Unlock()
		if s.natForwarder != nil {
			s.natForwarder.SetDialTimeout(parsedTuning.Duration(tuning.NATDialTimeout))
			s.natForwarder.SetUDPIdleTimeout(parsedTuning.Duration(tuning.UDPIdleTimeout))
			s.natForwarder.SetDNSTimeouts(
				parsedTuning.Duration(tuning.DNSTimeout),
				parsedTuning.Duration(tuning.DNSUpstreamTimeout),
			)
		}
		if s.portForwarder != nil {
			s.portForwarder.SetUDPIdleTimeout(parsedTuning.Duration(tuning.UDPIdleTimeout))
			s.portForwarder.SetGuestDialWindow(parsedTuning.Duration(tuning.ForwardGuestDialWindow))
			s.portForwarder.SetDynamicPollInterval(parsedTuning.Duration(tuning.ForwardDynamicPollInterval))
		}
		hostRAM, _ := hostMemory()
		_, interval := effectiveMemoryLimit(s.liveMemoryBytes.Load(), hostRAM, parsedTuning)
		s.liveMemoryIntNS.Store(int64(interval))
		select {
		case s.liveMemoryWake <- struct{}{}:
		default:
		}
		attrs["tuning_keys"] = strconv.Itoa(len(req.Tuning))
	}

	s.emitEvent("resource", "update", attrs)
	return stream.Reply(s.snapshotResources(k))
}

func (s *Sandbox) snapshotResources(k *kernel.Kernel) control.ResourceSnapshot {
	s.mu.Lock()
	res := s.cfg.Resources
	isolateLAN := s.cfg.IsolateLAN
	curTune := s.cfg.Tuning
	s.mu.Unlock()
	if s.natForwarder != nil {
		isolateLAN = s.natForwarder.IsolateLAN()
	}
	var quotaUS, periodUS int64
	if k != nil {
		q, p, limited := k.SandboxCPULimit()
		if limited {
			quotaUS = q.Microseconds()
			periodUS = p.Microseconds()
		}
		if _, pMax := cgroup2fs.RootPidsLimit(k); pMax > 0 {
			res.PidsLimit = pMax
		}
	}
	guestCPU := 0
	if k != nil {
		guestCPU = int(k.ApplicationCores())
	} else {
		guestCPU = guestCPUs(res.CPUMillis, runtime.NumCPU())
	}
	overrides := make(map[string]string)
	for _, entry := range tuning.Entries() {
		if entry.Mutable {
			if v, ok := curTune.Get(entry.Name); ok {
				overrides[entry.Name] = entry.Format(v)
			}
		}
	}
	return control.ResourceSnapshot{
		MemoryBytes:   s.liveMemoryBytes.Load(),
		CPUMillis:     res.CPUMillis,
		CPUQuotaUSec:  quotaUS,
		CPUPeriodUSec: periodUS,
		GuestCPUs:     guestCPU,
		PidsLimit:     res.PidsLimit,
		IsolateLAN:    isolateLAN,
		Tuning:        overrides,
	}
}

var signalNameMap = map[string]linux.Signal{
	"HUP":    linux.SIGHUP,
	"INT":    linux.SIGINT,
	"QUIT":   linux.SIGQUIT,
	"ILL":    linux.SIGILL,
	"TRAP":   linux.SIGTRAP,
	"ABRT":   linux.SIGABRT,
	"BUS":    linux.SIGBUS,
	"FPE":    linux.SIGFPE,
	"KILL":   linux.SIGKILL,
	"USR1":   linux.SIGUSR1,
	"SEGV":   linux.SIGSEGV,
	"USR2":   linux.SIGUSR2,
	"PIPE":   linux.SIGPIPE,
	"ALRM":   linux.SIGALRM,
	"TERM":   linux.SIGTERM,
	"CHLD":   linux.SIGCHLD,
	"CONT":   linux.SIGCONT,
	"STOP":   linux.SIGSTOP,
	"TSTP":   linux.SIGTSTP,
	"TTIN":   linux.SIGTTIN,
	"TTOU":   linux.SIGTTOU,
	"URG":    linux.SIGURG,
	"XCPU":   linux.SIGXCPU,
	"XFSZ":   linux.SIGXFSZ,
	"VTALRM": linux.SIGVTALRM,
	"PROF":   linux.SIGPROF,
	"WINCH":  linux.SIGWINCH,
	"IO":     linux.SIGIO,
	"SYS":    linux.SIGSYS,
}

func parseLinuxSignal(raw string) (linux.Signal, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, errors.New("signal name is empty")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 || n > 64 {
			return 0, fmt.Errorf("signal number %d out of range [1, 64]", n)
		}
		return linux.Signal(n), nil
	}
	upper := strings.TrimPrefix(strings.ToUpper(s), "SIG")
	if sig, ok := signalNameMap[upper]; ok {
		return sig, nil
	}
	return 0, fmt.Errorf("unknown POSIX signal %q", raw)
}
