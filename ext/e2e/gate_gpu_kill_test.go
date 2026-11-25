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

//go:build darwin || windows || linux

package e2e

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// rendererComm is the process name of the renderer (16 bytes, the
	// limit of p_comm on macOS).
	rendererComm = "gvx-gpu-renderer"

	// killProbeRounds keeps the compute probe in its submit-and-wait loop
	// far longer than the test waits (about 0.6 ms each round on hvf).
	killProbeRounds = "100000000"

	// killVirglRounds keeps glesprobe in its alternating clear-and-readback
	// loop far longer than the test waits.
	killVirglRounds = "2000000"

	// killExitTimeout bounds the time from the kill of the renderer to the
	// exit of rungv. A longer time is a hang.
	killExitTimeout = 2 * time.Minute
)

// processPIDs returns the process IDs that pgrep prints for args, or nil
// when no process matches.
func processPIDs(t *testing.T, args ...string) []int {
	t.Helper()
	out, err := exec.Command("pgrep", args...).Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return nil // no match
	}
	if err != nil {
		t.Fatalf("pgrep %v: %v", args, err)
	}
	var pids []int
	for _, f := range strings.Fields(string(out)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			t.Fatalf("pgrep %v printed %q", args, f)
		}
		pids = append(pids, pid)
	}
	slices.Sort(pids)
	return pids
}

// parsePSProcLine parses one line of "LC_ALL=C ps -p <pid> -o ppid=,lstart=".
func parsePSProcLine(line string, loc *time.Location) (int, time.Time, error) {
	fields := strings.Fields(line)
	if len(fields) != 6 {
		return 0, time.Time{}, fmt.Errorf("unexpected ps output %q", line)
	}
	ppid, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("parse ppid in %q: %w", line, err)
	}
	started, err := time.ParseInLocation(time.ANSIC, strings.Join(fields[1:], " "), loc)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("parse lstart in %q: %w", line, err)
	}
	return ppid, started, nil
}

// psProcInfo returns the parent PID and start time of pid.
// It reports ok=false when pid already exited.
func psProcInfo(t *testing.T, pid int) (int, time.Time, bool) {
	t.Helper()
	cmd := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "ppid=,lstart=")
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	out, err := cmd.Output()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return 0, time.Time{}, false
	}
	if err != nil {
		t.Fatalf("ps -p %d: %v", pid, err)
	}
	line := strings.TrimSpace(string(out))
	if line == "" {
		return 0, time.Time{}, false
	}
	ppid, started, err := parsePSProcLine(line, time.Local)
	if err != nil {
		t.Fatalf("ps -p %d: %v", pid, err)
	}
	return ppid, started, true
}

// orphanRendererPIDs returns live renderer PIDs reparented to PID 1 since
// start, excluding ignore. It also returns non-orphan renderer PIDs owned by
// other processes for diagnostics.
func orphanRendererPIDs(t *testing.T, since time.Time, ignore []int) (orphans, nonOrphans []int) {
	t.Helper()
	for _, pid := range processPIDs(t, "-x", rendererComm) {
		ppid, started, ok := psProcInfo(t, pid)
		if !ok {
			continue
		}
		if ppid != 1 {
			nonOrphans = append(nonOrphans, pid)
			continue
		}
		if !since.IsZero() && started.Before(since) {
			continue
		}
		if slices.Contains(ignore, pid) {
			continue
		}
		orphans = append(orphans, pid)
	}
	return orphans, nonOrphans
}

// killRecord is the result.json of TestE2EGPURendererKill.
type killRecord struct {
	Gate               string            `json:"gate"`
	Mode               string            `json:"mode"`
	Pass               bool              `json:"pass"`
	Host               gpuHostRecord     `json:"host"`
	RendererPID        int               `json:"renderer_pid"`
	ExitCode           int               `json:"rungv_exit_code"`
	KillToExitMS       int64             `json:"kill_to_exit_ms"`
	ProbeOutcome       string            `json:"probe_outcome"` // "vulkan-error", "gl-error", or "signal"
	ProbeError         string            `json:"probe_error"`
	Probe              map[string]string `json:"probe"`
	RestartedRenderers []int             `json:"restarted_renderers"`
	NewRenderers       []int             `json:"renderers_left"`
	CleanupNote        string            `json:"cleanup_check"`
	KD1                kd1Counts         `json:"kd1"`
	RefusedIoctls      []refusedIoctl    `json:"refused_ioctls"`
	Failures           []string          `json:"failures"`
}

// TestE2EGPURendererKill kills the renderer while the guest probe runs its
// submit-and-wait loop in venus mode or its alternating clear-and-readback
// loop in virgl mode. The guest must report a probe error or exit by signal.
// The sandbox must exit with that code within killExitTimeout. The Sentry must
// log the lost renderer, and no renderer process may remain. The renderer
// never restarts.
func TestE2EGPURendererKill(t *testing.T) {
	requireGPUGate(t)
	for _, mode := range []string{"venus", "virgl"} {
		t.Run(mode, func(t *testing.T) {
			if !gpuModeEnabled(mode) {
				t.Skipf("%s not in %s", mode, gpuModesEnv)
			}
			runRendererKill(t, gpuArtifactDir(t, filepath.Join("g1-kill", mode)), mode)
		})
	}
}

// runRendererKill executes one renderer-kill scenario for mode ("venus" or
// "virgl") and writes its record to art/result.json.
func runRendererKill(t *testing.T, art, mode string) {
	t.Helper()
	start := time.Now()
	gateName := "G1-kill"
	if mode == "virgl" {
		gateName = "G3-kill"
	}
	rec := &killRecord{Gate: gateName, Mode: mode, Host: newGPUHostRecord(start)}
	defer func() {
		rec.Host.DurationSec = int(time.Since(start).Seconds())
		rec.Pass = !t.Failed()
		writeJSON(t, filepath.Join(art, "result.json"), rec)
	}()
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format, args...)
		rec.Failures = append(rec.Failures, fmt.Sprintf(format, args...))
	}

	var (
		env          []string
		argv         []string
		readyLine    string
		execProbeTag string
		probePrefix  string
		errorOutcome string
	)
	switch mode {
	case "venus":
		env = []string{
			"GVX_G1_SNAPSHOT=" + g1Snapshot,
			"GVX_G1_ICD=" + venusICD,
			"GVX_G1_DEVICE=Venus",
			"GVX_G1_EXEC_PROBE=1",
			"GVX_VK_ROUNDS=" + killProbeRounds,
		}
		argv = []string{"bash", "/workspace/gpu/g1.sh"}
		readyLine = "GVX-VK rounds_begin="
		execProbeTag = "GVX-G1 exec_probe=1"
		probePrefix = "GVX-VK "
		errorOutcome = "vulkan-error"
	case "virgl":
		env = []string{
			"GVX_G3_SNAPSHOT=" + g1Snapshot,
			"GVX_G3_EXEC_PROBE=1",
			"GVX_GL_ROUNDS=" + killVirglRounds,
		}
		argv = []string{"bash", "/workspace/gpu/g3.sh"}
		readyLine = "GVX-GL rounds_begin="
		execProbeTag = "GVX-G3 exec_probe=1"
		probePrefix = "GVX-GL "
		errorOutcome = "gl-error"
	default:
		t.Fatalf("unknown GPU kill mode %q", mode)
	}

	beforeOrphans, _ := orphanRendererPIDs(t, time.Time{}, nil)
	out := filepath.Join(art, "out")
	if err := os.MkdirAll(out, 0o777); err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	args := rungvArgs(t, gpuRun{
		mode: mode, image: g1Image, net: "nat", workspace: g1Workspace(t), out: out,
		env: env, argv: argv,
	})
	logPath := filepath.Join(art, "sentry.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create %s: %v", logPath, err)
	}
	defer logFile.Close()
	stdout := newOutputLog()
	cmd := exec.Command(toolPath(t, rungvPkg), args...)
	cmd.Env = append(os.Environ(), "GVX_DEBUG_LOG=2")
	cmd.Stdout = stdout
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start rungv: %v", err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	defer func() {
		select {
		case <-done:
		default:
			_ = cmd.Process.Kill()
			<-done
		}
		if err := os.WriteFile(filepath.Join(art, "stdout.txt"), []byte(stdout.String()), 0o644); err != nil {
			t.Errorf("write stdout.txt: %v", err)
		}
	}()

	// The loop starts after apt, the build, the info tool, and the pre-kill
	// probe checks.
	stdout.waitFor(t, 0, readyLine, g1Timeout, done)
	children := processPIDs(t, "-P", strconv.Itoa(cmd.Process.Pid), "-x", rendererComm)
	if len(children) != 1 {
		t.Fatalf("renderer children of rungv %d = %v, want exactly one", cmd.Process.Pid, children)
	}
	rec.RendererPID = children[0]
	seenChildren := []int{rec.RendererPID}
	proc, err := os.FindProcess(rec.RendererPID)
	if err != nil {
		t.Fatalf("find renderer %d: %v", rec.RendererPID, err)
	}
	if err := proc.Kill(); err != nil {
		t.Fatalf("kill renderer %d: %v", rec.RendererPID, err)
	}
	killed := time.Now()

	deadline := time.NewTimer(killExitTimeout)
	defer deadline.Stop()
	sample := time.NewTicker(50 * time.Millisecond)
	defer sample.Stop()
waitExit:
	for {
		select {
		case <-done:
			break waitExit
		case <-sample.C:
			for _, pid := range processPIDs(t, "-P", strconv.Itoa(cmd.Process.Pid), "-x", rendererComm) {
				if !slices.Contains(seenChildren, pid) {
					seenChildren = append(seenChildren, pid)
					rec.RestartedRenderers = append(rec.RestartedRenderers, pid)
				}
			}
		case <-deadline.C:
			fail("rungv did not exit within %s after the renderer kill (the guest or the Sentry hangs); stdout tail:\n%s", killExitTimeout, tail(stdout.String(), 20))
			return
		}
	}
	rec.KillToExitMS = time.Since(killed).Milliseconds()
	var exitErr *exec.ExitError
	switch {
	case waitErr == nil:
		rec.ExitCode = 0
	case errors.As(waitErr, &exitErr):
		rec.ExitCode = exitErr.ExitCode()
	default:
		t.Fatalf("wait for rungv: %v", waitErr)
	}

	text := stdout.String()
	rec.Probe = keyValues(text, probePrefix)
	rec.ProbeError = rec.Probe["error"]
	scan := scanGPULog(t, logPath)
	rec.KD1, rec.RefusedIoctls = scan.KD1, scan.Refused

	// The probe exits 1 when a call or pixel check fails (printing
	// "<probePrefix>error=..."). It exits 128+signal when the guest driver
	// aborts (SIGABRT gives 134). Because the probe replaced the script via
	// exec, the sandbox returns its exit code.
	if !strings.Contains(text, execProbeTag) {
		fail("guest script did not exec the probe (%s missing); stdout tail:\n%s", execProbeTag, tail(text, 20))
	}
	switch mode {
	case "venus":
		if want := g1ProbeWords + " mismatches=0 first_bad=-1"; rec.Probe["checked"] != want {
			fail("pre-kill probe checked = %q, want %q", rec.Probe["checked"], want)
		}
		if rec.Probe["result"] == "PASS" {
			fail("probe reported PASS after the renderer kill")
		}
	case "virgl":
		if rec.Probe["result"] != "PASS" {
			fail("pre-kill probe result = %q, want PASS", rec.Probe["result"])
		}
		if _, finished := rec.Probe["rounds_end"]; finished {
			fail("probe reported rounds_end=%s after the renderer kill", rec.Probe["rounds_end"])
		}
	}
	switch {
	case rec.ProbeError != "" && rec.ExitCode == 1:
		rec.ProbeOutcome = errorOutcome
	case rec.ProbeError == "" && rec.ExitCode > 128 && rec.ExitCode <= 192:
		rec.ProbeOutcome = "signal"
	default:
		fail("rungv exit code %d with probe error %q: want 1 with a probe error, or 129..192 without one", rec.ExitCode, rec.ProbeError)
	}
	if rec.KD1.RendererLost < 1 {
		fail("the Sentry log has no \"virtgpu: renderer lost\" line for the kill (renderer_lost = 0)")
	}

	// Verify that every renderer child of rungv exited and none restarted.
	// Check for new PID-1 orphans so concurrent tests from other processes do
	// not cause false failures.
	afterAll := processPIDs(t, "-x", rendererComm)
	var aliveChildren []int
	for _, pid := range seenChildren {
		if slices.Contains(afterAll, pid) {
			aliveChildren = append(aliveChildren, pid)
		}
	}
	orphans, otherRenderers := orphanRendererPIDs(t, start.Truncate(time.Second), beforeOrphans)
	for _, pid := range append(slices.Clone(aliveChildren), orphans...) {
		if !slices.Contains(rec.NewRenderers, pid) {
			rec.NewRenderers = append(rec.NewRenderers, pid)
		}
	}
	slices.Sort(rec.NewRenderers)
	rec.CleanupNote = fmt.Sprintf("children_seen=%v children_alive=%v restarted_children=%v orphans_after_exit=%v ignored_other_renderers=%v",
		seenChildren, aliveChildren, rec.RestartedRenderers, orphans, otherRenderers)
	if len(rec.RestartedRenderers) != 0 {
		fail("rungv spawned new renderer children after kill: %v (%s)", rec.RestartedRenderers, rec.CleanupNote)
	}
	if len(aliveChildren) != 0 {
		fail("recorded renderer children still alive after exit: %v (%s)", aliveChildren, rec.CleanupNote)
	}
	if len(orphans) != 0 {
		fail("orphaned renderer processes left after exit: %v (%s)", orphans, rec.CleanupNote)
	}
	t.Logf("renderer %d killed; rungv exit %d after %d ms; outcome %s; probe error %q; %s",
		rec.RendererPID, rec.ExitCode, rec.KillToExitMS, rec.ProbeOutcome, rec.ProbeError, rec.CleanupNote)
}

// tail returns the last n lines of s.
func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	return strings.Join(lines[max(0, len(lines)-n):], "\n")
}

// TestParsePSProcLine checks parsing of macOS ps "ppid=,lstart=" output.
func TestParsePSProcLine(t *testing.T) {
	loc := time.UTC
	ppid, started, err := parsePSProcLine("    1 Fri Nov 20 16:21:44 2026", loc)
	if err != nil {
		t.Fatalf("parsePSProcLine() error = %v", err)
	}
	want := time.Date(2026, time.November, 20, 16, 21, 44, 0, loc)
	if ppid != 1 || !started.Equal(want) {
		t.Fatalf("parsePSProcLine() = (%d, %v), want (1, %v)", ppid, started, want)
	}
	ppid, started, err = parsePSProcLine("73481 Thu Nov  5 09:05:01 2026", loc)
	if err != nil {
		t.Fatalf("parsePSProcLine(single-digit day) error = %v", err)
	}
	wantDay := time.Date(2026, time.November, 5, 9, 5, 1, 0, loc)
	if ppid != 73481 || !started.Equal(wantDay) {
		t.Fatalf("parsePSProcLine(single-digit day) = (%d, %v), want (73481, %v)", ppid, started, wantDay)
	}
	if _, _, err := parsePSProcLine("bad", loc); err == nil {
		t.Fatal("parsePSProcLine(bad) error = nil, want error")
	}
}
