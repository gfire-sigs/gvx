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
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/abi/linux"
	"z.gfire.dev/gvx/pkg/gvx/control"
	"z.gfire.dev/gvx/pkg/log"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/sentry/blockdev"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/cgroup2fs"
	"z.gfire.dev/gvx/pkg/sentry/kernel"
	"z.gfire.dev/gvx/pkg/sentry/kernel/auth"
	"z.gfire.dev/gvx/pkg/sentry/mm"
	"z.gfire.dev/gvx/pkg/waiter"
)

func (s *Sandbox) handlePing(_ context.Context, stream *control.Stream) error {
	s.mu.Lock()
	started := s.startedAt
	name := cmp.Or(s.cfg.Name, "gvx-default")
	s.mu.Unlock()
	return stream.Reply(control.PingResponse{
		Version:      control.ProtocolVersion,
		SandboxID:    name,
		State:        s.sandboxStateString(),
		UptimeNanos:  time.Since(started).Nanoseconds(),
		Capabilities: s.ControlCapabilities(),
	})
}

func (s *Sandbox) handleInspect(_ context.Context, stream *control.Stream) error {
	s.mu.Lock()
	k := s.activeKernel
	mf := s.runMemFile
	st := s.netStack
	cfg := s.cfg
	started := s.startedAt
	posture := s.SecurityPosture()
	s.mu.Unlock()

	var memUsed uint64
	if mf != nil {
		mf.FlushCommitScan()
		_ = mf.UpdateUsage(nil)
		memUsed = mf.Accounting().Total()
	}

	var eth0IP string
	var eth0MTU uint32
	if st != nil {
		if info, ok := st.NICInfo()[netbackend.Eth0NICID]; ok {
			eth0MTU = info.MTU
			for _, pa := range info.ProtocolAddresses {
				if pa.AddressWithPrefix.Address.Len() == 4 {
					eth0IP = pa.AddressWithPrefix.Address.String()
					break
				}
			}
		}
	}

	pidCount := 0
	if k != nil {
		pidCount = len(k.TaskSet().Root.ThreadGroups())
	}

	arch := cfg.Architecture
	if arch == "" {
		arch = runtime.GOARCH
	}

	return stream.Reply(control.InspectResponse{
		ID:                 cmp.Or(cfg.Name, "gvx-default"),
		Name:               cfg.Name,
		State:              s.sandboxStateString(),
		Platform:           posture.Platform,
		Architecture:       arch,
		SyscallIsolation:   string(posture.SyscallIsolation),
		LockdownApplied:    posture.Lockdown.Applied,
		NetworkMode:        string(cfg.NetworkMode),
		Eth0IP:             eth0IP,
		Eth0MTU:            eth0MTU,
		Resources:          s.snapshotResources(k),
		MemoryUsedBytes:    memUsed,
		Ports:              s.listPortRuleInfos(),
		Mounts:             s.listMountInfos(),
		ActiveExecSessions: s.activeExecCount(),
		PIDCount:           pidCount,
		Capabilities:       s.ControlCapabilities(),
		StartedAt:          started.UTC(),
		UptimeNanos:        time.Since(started).Nanoseconds(),
	})
}

func (s *Sandbox) sampleStats(k *kernel.Kernel) control.StatsSample {
	s.mu.Lock()
	mf := s.runMemFile
	st := s.netStack
	s.mu.Unlock()

	sample := control.StatsSample{
		Timestamp: time.Now().UTC(),
	}
	if k != nil {
		cpuStats := k.CPUStats()
		bwStats := k.SandboxCPUBandwidthStats()
		sample.CPU = control.CPUStatsSample{
			UserNanos:      cpuStats.UserTime.Nanoseconds(),
			SystemNanos:    cpuStats.SysTime.Nanoseconds(),
			Periods:        bwStats.Periods,
			Throttled:      bwStats.Throttled,
			ThrottledNanos: bwStats.ThrottledTime.Nanoseconds(),
		}
		curPids, maxPids := cgroup2fs.RootPidsLimit(k)
		if curPids > 0 {
			sample.PIDs = int(curPids)
		} else {
			sample.PIDs = len(k.TaskSet().Root.ThreadGroups())
		}
		sample.PIDsLimit = maxPids

		if reg := blockdev.Of(k.VFS()); reg != nil {
			for _, dev := range reg.Devices() {
				if dev.Stats == nil {
					continue
				}
				snap := dev.Stats.Snapshot()
				sample.BlockIO = append(sample.BlockIO, control.BlockStatsSample{
					Disk:         dev.Name,
					ReadOps:      snap.ReadsCompleted,
					WriteOps:     snap.WritesCompleted,
					ReadSectors:  snap.SectorsRead,
					WriteSectors: snap.SectorsWritten,
				})
			}
		}
	}

	if mf != nil {
		mf.FlushCommitScan()
		_ = mf.UpdateUsage(nil)
		memStats, total := mf.Accounting().Copy()
		sample.Memory = control.MemoryStatsSample{
			TotalBytes: total,
			AnonBytes:  memStats.Anonymous,
			FileBytes:  memStats.PageCache + memStats.Mapped,
			TmpfsBytes: memStats.Tmpfs,
			LimitBytes: s.liveMemoryLimit.Load(),
		}
	}

	if st != nil {
		nics := st.NICInfo()
		nicIDs := make([]int, 0, len(nics))
		for id := range nics {
			nicIDs = append(nicIDs, int(id))
		}
		slices.Sort(nicIDs)
		for _, id := range nicIDs {
			for nicID, info := range nics {
				if int(nicID) != id {
					continue
				}
				sample.Network = append(sample.Network, control.NetStatsSample{
					Interface: info.Name,
					RxBytes:   info.Stats.Rx.Bytes.Value(),
					TxBytes:   info.Stats.Tx.Bytes.Value(),
					RxPackets: info.Stats.Rx.Packets.Value(),
					TxPackets: info.Stats.Tx.Packets.Value(),
				})
			}
		}
	}
	return sample
}

func (s *Sandbox) handleStats(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.StatsRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	if !req.Stream {
		return stream.Reply(s.sampleStats(k))
	}
	interval := time.Second
	if req.IntervalMS > 0 {
		interval = max(time.Duration(req.IntervalMS)*time.Millisecond, 100*time.Millisecond)
	}
	if err := stream.SendResponse(s.sampleStats(k)); err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = stream.CloseEvents()
			return nil
		case <-s.runDone:
			_ = stream.CloseEvents()
			return nil
		case <-ticker.C:
			if err := stream.SendEvent(ctx, "stats", s.sampleStats(k)); err != nil {
				return nil
			}
		}
	}
}

func (s *Sandbox) handleProcList(ctx context.Context, stream *control.Stream) error {
	k, _, err := s.activeKernelChecked(ctx)
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
	rootCreds := auth.NewRootCredentials(k.RootUserNamespace())
	vfsObj := k.VFS()

	pidns := k.TaskSet().Root
	tgs := pidns.ThreadGroups()
	procs := make([]control.ProcessInfo, 0, len(tgs))
	for _, tg := range tgs {
		pid := pidns.IDOfThreadGroup(tg)
		if pid <= 0 {
			continue
		}
		leader := tg.Leader()
		if leader == nil {
			continue
		}
		var ppid int32
		if parent := leader.Parent(); parent != nil {
			ppid = int32(pidns.IDOfThreadGroup(parent.ThreadGroup()))
		}
		var pgid, sid int32
		if pg := tg.ProcessGroup(); pg != nil {
			pgid = int32(pidns.IDOfProcessGroup(pg))
			if sess := pg.Session(); sess != nil {
				sid = int32(pidns.IDOfSession(sess))
			}
		}
		creds := leader.Credentials()
		var uid, gid uint32
		if creds != nil {
			uid = uint32(creds.EffectiveKUID)
			gid = uint32(creds.EffectiveKGID)
		}
		var tmm *mm.MemoryManager
		leader.WithMuLocked(func(t *kernel.Task) {
			tmm = t.MemoryManager()
		})
		var rss uint64
		if tmm != nil {
			rss = tmm.ResidentSetSize()
		}
		cpuStats := tg.CPUStats()
		var cmdline []string
		if rawCmd, rErr := readGuestFile(sctxWithRoot, vfsObj, rootCreds, root, fmt.Sprintf("/proc/%d/cmdline", pid), 4096); rErr == nil && len(rawCmd) > 0 {
			for _, part := range bytes.Split(bytes.TrimRight(rawCmd, "\x00"), []byte{0}) {
				cmdline = append(cmdline, string(part))
			}
		}
		procs = append(procs, control.ProcessInfo{
			PID:      int32(pid),
			PPID:     ppid,
			PGID:     pgid,
			SID:      sid,
			UID:      uid,
			GID:      gid,
			State:    leader.StateStatus(),
			Threads:  tg.Count(),
			CPUNanos: (cpuStats.UserTime + cpuStats.SysTime).Nanoseconds(),
			RSSBytes: rss,
			Comm:     leader.Name(),
			Cmdline:  cmdline,
		})
	}
	slices.SortFunc(procs, func(a, b control.ProcessInfo) int { return cmp.Compare(a.PID, b.PID) })
	return stream.Reply(control.ProcListResponse{Processes: procs})
}

func (s *Sandbox) handleProcSignal(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.ProcSignalRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	sigName := req.Signal
	if sigName == "" {
		sigName = "SIGKILL"
	}
	sig, err := parseLinuxSignal(sigName)
	if err != nil {
		return control.NewError(control.CodeInvalidArgument, err.Error())
	}
	k, initTG, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}

	if req.All {
		if sig == linux.SIGKILL {
			s.mu.Lock()
			dog := s.activeWatchdog
			s.mu.Unlock()
			s.unpauseForShutdown(k, dog)
		}
		pidns := k.TaskSet().Root
		count := 0
		for _, tg := range pidns.ThreadGroups() {
			if err := k.SendExternalSignalThreadGroup(tg, &linux.SignalInfo{Signo: int32(sig)}); err == nil {
				count++
			}
		}
		s.emitEvent("proc", "signal", map[string]string{"signal": sigName, "all": "true", "count": strconv.Itoa(count)})
		return stream.Reply(map[string]any{"signal": sigName, "signaled": count})
	}

	targetTG := initTG
	targetPID := req.PID
	if targetPID == 0 {
		targetPID = 1
	}
	if targetPID != 1 {
		t := k.TaskSet().Root.TaskWithID(kernel.ThreadID(targetPID))
		if t == nil {
			return control.NewErrorf(control.CodeNotFound, "guest PID %d not found", targetPID)
		}
		targetTG = t.ThreadGroup()
	} else if sig == linux.SIGKILL {
		s.mu.Lock()
		dog := s.activeWatchdog
		s.mu.Unlock()
		s.unpauseForShutdown(k, dog)
	}

	if err := k.SendExternalSignalThreadGroup(targetTG, &linux.SignalInfo{Signo: int32(sig)}); err != nil {
		return control.NewErrorf(control.CodeInternal, "send %s to pid %d: %v", sigName, targetPID, err)
	}
	s.emitEvent("proc", "signal", map[string]string{"signal": sigName, "pid": strconv.Itoa(int(targetPID))})
	return stream.Reply(map[string]any{"signal": sigName, "pid": targetPID})
}

func toControlLogRecord(r kernel.KernelLogRecord) control.KernelLogRecord {
	return control.KernelLogRecord{
		Seq:   r.Seq,
		Level: int(r.Level),
		USec:  r.Time.Microseconds(),
		Text:  r.Text,
	}
}

func (s *Sandbox) handleKernelLog(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.KernelLogRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	if req.Clear && !slices.Contains(s.ControlCapabilities(), control.CapKernelLogClear) {
		return control.NewError(control.CodeForbiddenByPolicy, "clearing the kernel log is disabled by sandbox policy")
	}
	k, _, err := s.activeKernelChecked(ctx)
	if err != nil {
		return err
	}
	kl := k.KernelLog()
	first := max(kl.FirstSeq(), kl.ClearSeq())
	next := kl.NextSeq()
	var records []control.KernelLogRecord
	for seq := first; seq < next; seq++ {
		rec, ok := kl.Lookup(seq)
		if !ok || rec.Seq >= next {
			break
		}
		if rec.Seq > seq {
			seq = rec.Seq
		}
		if req.MaxLevel > 0 && int(rec.Level) > req.MaxLevel-1 {
			continue
		}
		records = append(records, toControlLogRecord(rec))
	}
	if req.Tail > 0 && len(records) > req.Tail {
		records = records[len(records)-req.Tail:]
	}
	if req.Clear {
		kl.Clear()
	}
	if !req.Follow {
		return stream.Reply(control.KernelLogResponse{Records: records})
	}

	if err := stream.SendResponse(control.KernelLogResponse{Records: records}); err != nil {
		return err
	}
	cursor := next
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.ReadableEvents)
	if err := kl.EventRegister(&waitEntry); err != nil {
		return err
	}
	defer kl.EventUnregister(&waitEntry)

	for {
		curNext := kl.NextSeq()
		if curFirst := max(kl.FirstSeq(), kl.ClearSeq()); cursor < curFirst {
			cursor = curFirst
		}
		for cursor < curNext {
			rec, ok := kl.Lookup(cursor)
			if !ok || rec.Seq >= curNext {
				cursor = curNext
				break
			}
			cursor = rec.Seq + 1
			if req.MaxLevel > 0 && int(rec.Level) > req.MaxLevel-1 {
				continue
			}
			if err := stream.SendEvent(ctx, "log", toControlLogRecord(rec)); err != nil {
				return nil
			}
		}
		select {
		case <-notifyCh:
		case <-ctx.Done():
			_ = stream.CloseEvents()
			return nil
		case <-s.runDone:
			_ = stream.CloseEvents()
			return nil
		}
	}
}

func matchesEventFilters(ev control.SandboxEvent, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	// Group filters by key: values for the same key are OR'd, and distinct keys
	// are AND'd, matching Docker event filter semantics.
	groups := make(map[string][]string, len(filters))
	for _, raw := range filters {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		k, v, ok := strings.Cut(trimmed, "=")
		if !ok {
			groups["type"] = append(groups["type"], trimmed)
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if key == "" {
			continue
		}
		groups[key] = append(groups[key], strings.TrimSpace(v))
	}
	for key, vals := range groups {
		var actual string
		var exists bool
		switch key {
		case "type":
			actual, exists = ev.Type, true
		case "action":
			actual, exists = ev.Action, true
		default:
			actual, exists = ev.Attributes[key]
		}
		if !exists || !slices.Contains(vals, actual) {
			return false
		}
	}
	return true
}

func (s *Sandbox) handleEvents(ctx context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.EventsRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	ch, unsub := s.events.subscribe()
	defer unsub()
	if err := stream.SendResponse(map[string]bool{"subscribed": true}); err != nil {
		return err
	}
	for {
		select {
		case ev := <-ch:
			if !matchesEventFilters(ev, req.Filters) {
				continue
			}
			if err := stream.SendEvent(ctx, "event", ev); err != nil {
				return nil
			}
		case <-ctx.Done():
			_ = stream.CloseEvents()
			return nil
		case <-s.runDone:
			_ = stream.CloseEvents()
			return nil
		}
	}
}

func (s *Sandbox) handleDebugLogLevel(_ context.Context, stream *control.Stream, raw json.RawMessage) error {
	var req control.DebugLogLevelRequest
	if err := decodeParams(raw, &req); err != nil {
		return err
	}
	var level log.Level
	switch strings.ToLower(strings.TrimSpace(req.Level)) {
	case "warning", "warn":
		level = log.Warning
	case "info":
		level = log.Info
	case "debug":
		level = log.Debug
	default:
		return control.NewErrorf(control.CodeInvalidArgument, "unsupported log level %q (want warning, info, or debug)", req.Level)
	}
	log.SetLevel(level)
	s.emitEvent("debug", "log_level", map[string]string{"level": strings.ToLower(strings.TrimSpace(req.Level))})
	return stream.Reply(map[string]string{"level": strings.ToLower(strings.TrimSpace(req.Level))})
}
