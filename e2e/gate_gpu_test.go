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
	"bufio"
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The GPU gates G1, G2, and G3 of the macOS GPU work prove the virtual render
// node (-gpu=venus and -gpu=virgl) with unmodified guest Mesa and Chromium.
// They run only on request, on darwin/arm64 with hvf, with a built
// gvx-gpu-renderer bundle.
const (
	// gpuGateEnv turns the GPU gates on when it is "1".
	gpuGateEnv = "GVX_E2E_GPU"

	// gpuModesEnv lists the GPU modes that the gates run, separated by commas:
	// venus, virgl. Unset means both.
	gpuModesEnv = "GVX_E2E_GPU_MODES"

	// gpuArtifactEnv names a host directory. Each gate writes its record to
	// a subdirectory (g1, g2, g3) for the review of a person or an agent. When
	// it is unset, the record goes to a temporary directory of the test.
	gpuArtifactEnv = "GVX_E2E_ARTIFACT_DIR"

	// gpuRendererEnv is the renderer path that gvx.New reads. The rungv
	// child process inherits it.
	gpuRendererEnv = "GVX_GPU_RENDERER"

	// gpuOutGuestPath is the guest mount point of the writable output
	// directory of a gate run.
	gpuOutGuestPath = "/out"
)

// gpuAssets holds the guest scripts, the compute probe, and the WebGL scene
// of the GPU gates.
//
//go:embed testdata/gpu
var gpuAssets embed.FS

// requireGPUGate skips the calling test unless the user asked for the GPU
// gates and the host can run them. With the opt-in set, a missing renderer
// is a failure, not a skip.
func requireGPUGate(t *testing.T) {
	t.Helper()
	if os.Getenv(gpuGateEnv) != "1" {
		t.Skipf("the GPU gates need a built gvx-gpu-renderer bundle; set %s=1", gpuGateEnv)
	}
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skipf("-gpu=venus needs darwin/arm64, not %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	requireAutoPlatform(t)
	requireRegistry(t)
	path := os.Getenv(gpuRendererEnv)
	if path == "" {
		t.Fatalf("%s=1 needs %s: run scripts/gpu/build-renderer.sh and export %s=$PWD/build/gpu/gvx-gpu-renderer/bin/gvx-gpu-renderer", gpuGateEnv, gpuRendererEnv, gpuRendererEnv)
	}
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() {
		t.Fatalf("%s=%s is not a regular file: %v", gpuRendererEnv, path, err)
	}
}

// gpuArtifactDir returns an empty directory for the record of gate. It
// removes an earlier record of the same gate first.
func gpuArtifactDir(t *testing.T, gate string) string {
	t.Helper()
	base := os.Getenv(gpuArtifactEnv)
	if base == "" {
		return t.TempDir()
	}
	dir := filepath.Join(base, gate)
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("remove the old record %s: %v", dir, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create the record directory %s: %v", dir, err)
	}
	t.Logf("gate record: %s", dir)
	return dir
}

// copyEmbedded copies the embedded directory src of fsys into dst.
func copyEmbedded(t *testing.T, fsys embed.FS, src, dst string) {
	t.Helper()
	sub, err := fs.Sub(fsys, src)
	if err != nil {
		t.Fatalf("open the embedded %s: %v", src, err)
	}
	if err := os.CopyFS(dst, sub); err != nil {
		t.Fatalf("copy the embedded %s to %s: %v", src, dst, err)
	}
}

// gpuModeEnabled reports whether mode is in GVX_E2E_GPU_MODES (default: all).
func gpuModeEnabled(mode string) bool {
	raw := strings.TrimSpace(os.Getenv(gpuModesEnv))
	if raw == "" {
		return true
	}
	for _, part := range strings.Split(raw, ",") {
		if strings.EqualFold(strings.TrimSpace(part), mode) {
			return true
		}
	}
	return false
}

// gpuRun describes one rungv run of a GPU gate.
type gpuRun struct {
	gpu       bool              // -gpu=venus when true and mode is empty, -gpu=off otherwise (kept for G1)
	mode      string            // -gpu value when not empty: "venus", "virgl", or "off"
	image     string            // OCI image reference
	net       string            // -net value
	workspace string            // host directory at /workspace
	out       string            // host directory at /out (writable)
	readOnly  map[string]string // host directory: guest path, mounted read-only
	env       []string          // guest environment (KEY=VALUE)
	argv      []string          // guest command
	timeout   time.Duration
}

// gpuRunResult is the outcome of one gpuRun.
type gpuRunResult struct {
	code   int    // exit code of rungv (the guest exit code when it ran)
	stdout string // guest standard output
	log    string // path of the rungv standard error: Sentry log, renderer lines, guest standard error
}

// runGPUGuest runs r through the rungv command with the host lockdown on and
// GVX_DEBUG_LOG=2, so that the Sentry log holds the refused ioctls of the
// render node. The lockdown confines the whole host process, so the gate
// cannot run the sandbox inside the test process. It writes stdout.txt and
// sentry.log to r.out/.. (the run directory).
func runGPUGuest(t *testing.T, runDir string, r gpuRun) gpuRunResult {
	t.Helper()
	bin := toolPath(t, rungvPkg)
	args := rungvArgs(t, r)

	logPath := filepath.Join(runDir, "sentry.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("create %s: %v", logPath, err)
	}
	defer logFile.Close()
	var stdout bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), r.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(), "GVX_DEBUG_LOG=2")
	cmd.Stdout = &stdout
	cmd.Stderr = logFile
	t.Logf("run: %s %s", bin, strings.Join(args, " "))
	start := time.Now()
	err = cmd.Run()
	t.Logf("rungv ran %s", time.Since(start).Round(time.Millisecond))
	if werr := os.WriteFile(filepath.Join(runDir, "stdout.txt"), stdout.Bytes(), 0o644); werr != nil {
		t.Errorf("write stdout.txt: %v", werr)
	}
	res := gpuRunResult{stdout: stdout.String(), log: logPath}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		res.code = exitErr.ExitCode()
	default:
		t.Fatalf("run rungv: %v (log: %s)", err, logPath)
	}
	if ctx.Err() != nil {
		t.Fatalf("rungv did not finish in %s (log: %s); stdout:\n%s", r.timeout, logPath, res.stdout)
	}
	return res
}

// rungvArgs returns the rungv command line of r. The host lockdown stays at
// its default (on).
func rungvArgs(t *testing.T, r gpuRun) []string {
	t.Helper()
	mode := r.mode
	if mode == "" {
		mode = "off"
		if r.gpu {
			mode = "venus"
		}
	}
	args := []string{"run", "-gpu=" + mode, "-net=" + r.net, "-cache-dir", sharedCacheDir(t),
		"-workspace", r.workspace, "-v", r.out + ":" + gpuOutGuestPath}
	hosts := make([]string, 0, len(r.readOnly))
	for host := range r.readOnly {
		hosts = append(hosts, host)
	}
	slices.Sort(hosts)
	for _, host := range hosts {
		args = append(args, "-v", host+":"+r.readOnly[host]+":ro")
	}
	for _, kv := range r.env {
		args = append(args, "-e", kv)
	}
	args = append(args, "-image", r.image, "--")
	return append(args, r.argv...)
}

// rungvError returns the last "rungv run:" line of the log at path: the
// error of a sandbox that did not start. It returns "" when there is none.
func rungvError(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	last := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "rungv run:") {
			last = line
		}
	}
	return last
}

// newGPURunDir returns art/name with an empty out subdirectory.
func newGPURunDir(t *testing.T, art, name string) (runDir, out string) {
	t.Helper()
	runDir = filepath.Join(art, name)
	out = filepath.Join(runDir, "out")
	if err := os.MkdirAll(out, 0o777); err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	return runDir, out
}

// refusedIoctl is one request number that the render node refused.
type refusedIoctl struct {
	Name  string `json:"name"`
	Nr    string `json:"nr"`
	Cmd   string `json:"cmd"`
	Error string `json:"error"`
	Files int    `json:"files"` // number of DRM files that saw it (one log line each)
}

// refusedIoctlRE matches the line of virtgpu (renderFD.logRefused).
var refusedIoctlRE = regexp.MustCompile(`virtgpu: refused ioctl (\S+) \(nr (0x[0-9a-f]+), cmd (0x[0-9a-f]+)\): (.*)$`)

// gpuLogLineRE selects the log lines of the GPU path for the short log.
var gpuLogLineRE = regexp.MustCompile(`virtgpu|gpurender|gvx-gpu-renderer|ErrGPU|renderD128`)

// kd1Counts are the counts of the accepted renderer defect KD-1 (the first
// BLOB_CREATE of a new context fails with StatusIO during concurrent context
// churn, and the context then dies) in one rungv log. Every field is written,
// so a record holds an explicit 0.
type kd1Counts struct {
	// BlobCreateStatusIO counts BLOB_CREATE replies with StatusIO: the line
	// "virtgpu: BLOB_CREATE ctx <n> failed: ...: EIO" of the device, or the
	// line "gpurender: BLOB_CREATE ctx <n> refused: EIO" of the client.
	BlobCreateStatusIO int `json:"blob_create_status_io"`
	// SendMessageEINVAL counts the renderer stderr line
	// "server: failed to send message: Invalid argument".
	SendMessageEINVAL int `json:"renderer_server_failed_to_send_message"`
	// SocketDisconnected counts the renderer stderr line
	// "proxy: socket disconnected".
	SocketDisconnected int `json:"renderer_proxy_socket_disconnected"`
	// ProxyBlobReplyFailed counts the renderer stderr line "proxy: failed to
	// get reply of blob": the renderer side of a failed BLOB_CREATE. It
	// corroborates BlobCreateStatusIO and needs no device log line.
	ProxyBlobReplyFailed int `json:"renderer_proxy_failed_to_get_reply_of_blob"`
	// ContextLost counts the line "virtgpu: context <n> lost" of the device:
	// one line for each context that became lost (wp10.md section 3.4).
	ContextLost int `json:"context_lost"`
	// RendererLost counts the line "virtgpu: renderer lost" (the whole
	// renderer, not KD-1; recorded beside it) without the line of the normal
	// teardown ("... client closed").
	RendererLost int `json:"renderer_lost"`
	// StderrLinesDropped sums the "gpurender: dropped <n> renderer stderr
	// lines" lines of the client rate limit (50 lines a second).
	StderrLinesDropped int `json:"renderer_stderr_lines_dropped"`
	// Complete is false when StderrLinesDropped is not 0: the two renderer
	// counts are then lower bounds.
	Complete bool `json:"complete"`
}

// ReportRequired reports whether the parent session must receive the counts:
// a BLOB_CREATE StatusIO reply or a KD-1 renderer line was seen, or the
// renderer counts are incomplete.
func (k kd1Counts) ReportRequired() bool {
	return k.BlobCreateStatusIO > 0 || k.SendMessageEINVAL > 0 || k.SocketDisconnected > 0 || k.ProxyBlobReplyFailed > 0 || !k.Complete
}

func (k kd1Counts) String() string {
	return fmt.Sprintf("blob_create_status_io=%d server_failed_to_send_message=%d proxy_socket_disconnected=%d proxy_failed_to_get_reply_of_blob=%d context_lost=%d renderer_lost=%d stderr_lines_dropped=%d complete=%v",
		k.BlobCreateStatusIO, k.SendMessageEINVAL, k.SocketDisconnected, k.ProxyBlobReplyFailed, k.ContextLost, k.RendererLost, k.StderrLinesDropped, k.Complete)
}

var (
	kd1BlobCreateIORE    = regexp.MustCompile(`virtgpu: BLOB_CREATE ctx \d+ failed: .*: EIO$|gpurender: BLOB_CREATE ctx \d+ refused: EIO$`)
	kd1ContextLostRE     = regexp.MustCompile(`virtgpu: context \d+ lost`)
	kd1StderrDroppedRE   = regexp.MustCompile(`gpurender: dropped (\d+) renderer stderr lines`)
	kd1SendMessageLine   = "server: failed to send message: Invalid argument"
	kd1SocketDisconnLine = "proxy: socket disconnected"
	kd1BlobReplyLine     = "proxy: failed to get reply of blob"
	rendererLostLine     = "virtgpu: renderer lost"
)

// gpuLogScan is the result of scanGPULog.
type gpuLogScan struct {
	Refused []refusedIoctl
	KD1     kd1Counts
}

// scanGPULog reads the rungv log at path. It returns the refused ioctls in
// order of first appearance and the KD-1 counts, and writes the lines of the
// GPU path to sentry-gpu.log next to it.
func scanGPULog(t *testing.T, path string) gpuLogScan {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	var short bytes.Buffer
	scan := gpuLogScan{Refused: []refusedIoctl{}}
	index := map[string]int{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if gpuLogLineRE.MatchString(line) {
			short.WriteString(line)
			short.WriteByte('\n')
		}
		countKD1(&scan.KD1, line)
		m := refusedIoctlRE.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key := m[1] + " " + m[2]
		if i, ok := index[key]; ok {
			scan.Refused[i].Files++
			continue
		}
		index[key] = len(scan.Refused)
		scan.Refused = append(scan.Refused, refusedIoctl{Name: m[1], Nr: m[2], Cmd: m[3], Error: m[4], Files: 1})
	}
	if err := sc.Err(); err != nil {
		t.Errorf("read %s: %v", path, err)
	}
	scan.KD1.Complete = scan.KD1.StderrLinesDropped == 0
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), "sentry-gpu.log"), short.Bytes(), 0o644); err != nil {
		t.Errorf("write sentry-gpu.log: %v", err)
	}
	return scan
}

// countKD1 adds the KD-1 lines of one log line to k.
func countKD1(k *kd1Counts, line string) {
	switch {
	case kd1BlobCreateIORE.MatchString(line):
		k.BlobCreateStatusIO++
	case strings.Contains(line, kd1SendMessageLine):
		k.SendMessageEINVAL++
	case strings.Contains(line, kd1SocketDisconnLine):
		k.SocketDisconnected++
	case strings.Contains(line, kd1BlobReplyLine):
		k.ProxyBlobReplyFailed++
	case kd1ContextLostRE.MatchString(line):
		k.ContextLost++
	case strings.Contains(line, rendererLostLine) && !strings.Contains(line, "client closed"):
		k.RendererLost++
	}
	if m := kd1StderrDroppedRE.FindStringSubmatch(line); m != nil {
		n, _ := strconv.Atoi(m[1])
		k.StderrLinesDropped += n
	}
}

// recordKD1 logs the KD-1 counts of each run and returns them for the gate
// record. A count that the parent session must see produces a log line that
// says so; KD-1 is an accepted defect, so it does not fail the gate.
func recordKD1(t *testing.T, runs map[string]kd1Counts) map[string]kd1Counts {
	t.Helper()
	for name, k := range runs {
		t.Logf("KD-1 %s: %s", name, k)
		if k.ReportRequired() {
			t.Logf("KD-1 %s: report these counts to the parent session (known-defects.md, KD-1)", name)
		}
	}
	return runs
}

// writeJSON writes v as indented JSON to path.
func writeJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("encode %s: %v", path, err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// gpuHostRecord describes the host and the build of a gate run.
type gpuHostRecord struct {
	GOOS        string `json:"goos"`
	GOARCH      string `json:"goarch"`
	CPU         string `json:"cpu"`
	OSVersion   string `json:"os_version"`
	GVXCommit   string `json:"gvx_commit"`
	Renderer    string `json:"renderer"`
	BuildInfo   string `json:"renderer_buildinfo"`
	Lockdown    bool   `json:"host_lockdown"`
	DebugLog    int    `json:"gvx_debug_log"`
	StartedUTC  string `json:"started_utc"`
	DurationSec int    `json:"duration_sec"`
}

// commandText returns the trimmed output of a host command, or "" when it
// fails. The record is best effort; the assertions do not read it.
func commandText(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func newGPUHostRecord(start time.Time) gpuHostRecord {
	renderer := os.Getenv(gpuRendererEnv)
	buildInfo, _ := os.ReadFile(filepath.Join(filepath.Dir(filepath.Dir(renderer)), "BUILDINFO"))
	commit := commandText("git", "rev-parse", "HEAD")
	if commandText("git", "status", "--porcelain", "--untracked-files=no") != "" {
		commit += "+dirty"
	}
	return gpuHostRecord{
		GOOS:       runtime.GOOS,
		GOARCH:     runtime.GOARCH,
		CPU:        commandText("sysctl", "-n", "machdep.cpu.brand_string"),
		OSVersion:  commandText("sw_vers", "-productVersion"),
		GVXCommit:  commit,
		Renderer:   renderer,
		BuildInfo:  strings.TrimSpace(string(buildInfo)),
		Lockdown:   true,
		DebugLog:   2,
		StartedUTC: start.UTC().Format(time.RFC3339),
	}
}

// keyValues collects the "<prefix>key=value" lines of text. The first value
// of a key wins.
func keyValues(text, prefix string) map[string]string {
	kv := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		rest, ok := strings.CutPrefix(line, prefix)
		if !ok {
			continue
		}
		key, value, _ := strings.Cut(rest, "=")
		if _, seen := kv[key]; !seen {
			kv[key] = value
		}
	}
	return kv
}

// G1 constants.
const (
	// g1Image is Debian trixie (arm64 and amd64 index). The gate installs
	// Mesa from a Debian snapshot, so the packages stay the same over time.
	g1Image = "debian:trixie-20261104-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2"

	// g1Snapshot is the snapshot.debian.org time stamp of the packages:
	// mesa-vulkan-drivers 25.0.7-2+deb13u1, vulkan-tools 1.4.304.0,
	// glslang-tools 15.1.0, gcc 14.2.0.
	g1Snapshot = "20261115T000000Z"

	// g1Timeout bounds one G1 run. The package download is about 109 MB.
	g1Timeout = 15 * time.Minute

	// venusICD and lavapipeICD are the Vulkan driver files of Mesa.
	venusICD    = "/usr/share/vulkan/icd.d/virtio_icd.json"
	lavapipeICD = "/usr/share/vulkan/icd.d/lvp_icd.json"

	// venusDeviceName is the prefix of the device name of Mesa venus. Mesa
	// appends the name of the host device in parentheses.
	venusDeviceName = "Virtio-GPU Venus"

	// renderNodeStat is the stat output of /dev/dri/renderD128: a character
	// device 226:128 (hexadecimal e2:80) with mode 0666.
	renderNodeStat = "character special file e2:80 666"

	// virtioGPUSysfsDevice is the realpath of /sys/dev/char/226:128/device.
	virtioGPUSysfsDevice = "/sys/devices/pci0000:00/0000:00:01.0/virtio0"

	// g1ProbeWords is the GVX_VK_WORDS default of vkcompute.c.
	g1ProbeWords = "1048576"
)

// g1Record is the result.json of gate G1.
type g1Record struct {
	Gate          string               `json:"gate"`
	Pass          bool                 `json:"pass"`
	Host          gpuHostRecord        `json:"host"`
	Image         string               `json:"image"`
	Snapshot      string               `json:"debian_snapshot"`
	Control       map[string]string    `json:"control_lavapipe"`
	Venus         map[string]string    `json:"venus"`
	VulkanCheck   map[string]string    `json:"venus_vulkan_probe"`
	RefusedIoctls []refusedIoctl       `json:"refused_ioctls"`
	KD1           map[string]kd1Counts `json:"kd1"`
	KD1Report     bool                 `json:"kd1_report_required"`
	Failures      []string             `json:"failures"`
	Files         map[string]string    `json:"files"`
}

// g1Workspace returns a workspace with the G1 assets in its gpu directory.
func g1Workspace(t *testing.T) string {
	t.Helper()
	ws := t.TempDir()
	copyEmbedded(t, gpuAssets, "testdata/gpu", filepath.Join(ws, "gpu"))
	return ws
}

// runG1 runs g1.sh once and returns its GVX-G1 and GVX-VK values.
func runG1(t *testing.T, art, name string, gpu bool, icd, device string) (g1, vk map[string]string, res gpuRunResult) {
	t.Helper()
	runDir, out := newGPURunDir(t, art, name)
	res = runGPUGuest(t, runDir, gpuRun{
		gpu:       gpu,
		image:     g1Image,
		net:       "nat",
		workspace: g1Workspace(t),
		out:       out,
		env:       []string{"GVX_G1_SNAPSHOT=" + g1Snapshot, "GVX_G1_ICD=" + icd, "GVX_G1_DEVICE=" + device},
		argv:      []string{"bash", "/workspace/gpu/g1.sh"},
		timeout:   g1Timeout,
	})
	g1 = keyValues(res.stdout, "GVX-G1 ")
	vk = keyValues(res.stdout, "GVX-VK ")
	for k, v := range vk {
		g1["vk_"+k] = v
	}
	g1["rungv_exit"] = strconv.Itoa(res.code)
	return g1, vk, res
}

// TestE2EGateGPUVulkan is gate G1: unmodified Mesa venus in a Debian guest
// finds the virtual render node, lists the host GPU, and runs a compute
// shader whose result the guest reads through a mapped blob. The control run
// uses lavapipe (Mesa on the CPU) with the GPU off, so a failure of the venus
// run points at the GPU path and not at the probe or the packages.
func TestE2EGateGPUVulkan(t *testing.T) {
	requireGPUGate(t)
	if !gpuModeEnabled("venus") {
		t.Skipf("venus not in %s", gpuModesEnv)
	}
	art := gpuArtifactDir(t, "g1")
	start := time.Now()
	rec := g1Record{Gate: "G1", Image: g1Image, Snapshot: g1Snapshot, Host: newGPUHostRecord(start),
		Files: map[string]string{
			"control":        "control/stdout.txt, control/out/",
			"venus_stdout":   "venus/stdout.txt",
			"venus_log":      "venus/sentry.log",
			"venus_gpu_log":  "venus/sentry-gpu.log",
			"vulkaninfo":     "venus/out/vulkaninfo.txt",
			"refused_ioctls": "refused-ioctls.json",
			"kd1":            "kd1.json",
			"result":         "result.json",
		}}
	rec.KD1 = map[string]kd1Counts{}
	defer func() {
		rec.Host.DurationSec = int(time.Since(start).Seconds())
		rec.Pass = !t.Failed()
		recordKD1(t, rec.KD1)
		for _, k := range rec.KD1 {
			rec.KD1Report = rec.KD1Report || k.ReportRequired()
		}
		writeJSON(t, filepath.Join(art, "kd1.json"), rec.KD1)
		writeJSON(t, filepath.Join(art, "result.json"), rec)
	}()
	fail := func(t *testing.T, format string, args ...any) {
		t.Helper()
		t.Errorf(format, args...)
		rec.Failures = append(rec.Failures, t.Name()+": "+fmt.Sprintf(format, args...))
	}

	t.Run("control-lavapipe", func(t *testing.T) {
		g1, _, res := runG1(t, art, "control", false, lavapipeICD, "llvmpipe")
		rec.Control = g1
		rec.KD1["control"] = scanGPULog(t, res.log).KD1
		if !strings.Contains(res.stdout, "GVX-G1 step=apt") {
			fail(t, "control guest did not start (rungv exit %d): %s", res.code, rungvError(res.log))
			t.FailNow()
		}
		want := map[string]string{"probe_exit": "0", "vk_result": "PASS", "vk_checked": g1ProbeWords + " mismatches=0 first_bad=-1", "vk_driver_name": "llvmpipe"}
		for k, v := range want {
			if g1[k] != v {
				fail(t, "control %s = %q, want %q (the probe or the packages are broken; the GPU path is not involved)", k, g1[k], v)
			}
		}
		if g1["sysfs_device"] != "" {
			fail(t, "control sysfs_device = %q, want empty: the GPU is off", g1["sysfs_device"])
		}
	})

	var venus map[string]string
	t.Run("venus", func(t *testing.T) {
		g1, _, res := runG1(t, art, "venus", true, venusICD, "Venus")
		rec.Venus = g1
		scan := scanGPULog(t, res.log)
		rec.RefusedIoctls = scan.Refused
		rec.KD1["venus"] = scan.KD1
		writeJSON(t, filepath.Join(art, "refused-ioctls.json"), scan.Refused)
		for _, r := range scan.Refused {
			t.Logf("refused ioctl: %s nr %s cmd %s: %s (files %d)", r.Name, r.Nr, r.Cmd, r.Error, r.Files)
		}
		if !strings.Contains(res.stdout, "GVX-G1 step=apt") {
			fail(t, "venus guest did not start (rungv exit %d): %s", res.code, rungvError(res.log))
			t.FailNow()
		}
		if !strings.Contains(res.stdout, "GVX-G1 done") {
			fail(t, "g1.sh did not finish (rungv exit %d); stdout:\n%s", res.code, res.stdout)
		}
		venus = g1
	})
	if venus == nil {
		return
	}

	// Step 1 needs the render node, the sysfs tree, the capset, a context,
	// blobs, and EXECBUFFER for the venus ring.
	t.Run("step1-vulkaninfo", func(t *testing.T) {
		if venus["render_node"] != renderNodeStat {
			fail(t, "render_node = %q, want %q", venus["render_node"], renderNodeStat)
		}
		if venus["sysfs_device"] != virtioGPUSysfsDevice {
			fail(t, "sysfs_device = %q, want %q", venus["sysfs_device"], virtioGPUSysfsDevice)
		}
		if got := strings.TrimSpace(venus["pci_id"]); got != "0x1af4 0x1050" {
			fail(t, "pci_id = %q, want %q", got, "0x1af4 0x1050")
		}
		if venus["vulkaninfo_exit"] != "0" {
			fail(t, "vulkaninfo exit = %q, want 0 (see venus/out/vulkaninfo.txt)", venus["vulkaninfo_exit"])
		}
		name := venus["vulkaninfo_deviceName"]
		if !strings.HasPrefix(name, venusDeviceName) || !strings.Contains(name, "Apple") {
			fail(t, "vulkaninfo deviceName = %q, want %q with the Apple GPU name", name, venusDeviceName+" (Apple ...)")
		}
		if venus["vulkaninfo_driverName"] != "venus" {
			fail(t, "vulkaninfo driverName = %q, want venus", venus["vulkaninfo_driverName"])
		}
	})

	// Step 2 adds host-visible memory (MAP and mmap of blobs), a compute
	// dispatch, fences, and the sync_file export when the driver offers it.
	t.Run("step2-compute", func(t *testing.T) {
		rec.VulkanCheck = map[string]string{
			"device_name": venus["vk_device_name"], "driver_name": venus["vk_driver_name"],
			"checked": venus["vk_checked"], "first_dispatch_ms": venus["vk_first_dispatch_ms"],
			"rounds": venus["vk_rounds"], "syncfd": venus["vk_syncfd"], "result": venus["vk_result"],
		}
		if !strings.HasPrefix(venus["vk_device_name"], venusDeviceName) {
			fail(t, "probe device_name = %q, want %q", venus["vk_device_name"], venusDeviceName+" (...)")
		}
		if venus["vk_driver_name"] != "venus" {
			fail(t, "probe driver_name = %q, want venus", venus["vk_driver_name"])
		}
		if want := g1ProbeWords + " mismatches=0 first_bad=-1"; venus["vk_checked"] != want {
			fail(t, "probe checked = %q, want %q", venus["vk_checked"], want)
		}
		if venus["vk_syncfd"] == "FAIL" {
			fail(t, "probe syncfd = FAIL: the sync_file of EXECBUFFER FENCE_FD_OUT did not become readable")
		}
		if venus["vk_result"] != "PASS" || venus["probe_exit"] != "0" {
			fail(t, "probe result = %q, exit %q; want PASS, 0", venus["vk_result"], venus["probe_exit"])
		}
	})
}

// refusedLogFixture holds Sentry log lines in the format of
// renderFD.logRefused (pkg/sentry/devices/virtgpu/ioctl.go) with the task
// prefix of a guest ioctl, plus lines of other subsystems.
const refusedLogFixture = `I1120 05:48:26.100000    4242 kernel_runner.go:310] EXEC: []string{"bash", "/workspace/gpu/g1.sh"}
D1120 05:48:30.200000    4242 task_log.go:73] [  12:  12] virtgpu: refused ioctl DRM_IOCTL_SYNCOBJ_CREATE (nr 0xbf, cmd 0xc00864bf): operation not supported
D1120 05:48:30.300000    4242 task_log.go:73] [  12:  12] Transitioning from exit state TaskExitNone to TaskExitInitiated
D1120 05:48:31.200000    4242 task_log.go:73] [  14:  14] virtgpu: refused ioctl DRM_IOCTL_SYNCOBJ_CREATE (nr 0xbf, cmd 0xc00864bf): operation not supported
D1120 05:48:31.400000    4242 task_log.go:73] [  14:  15] virtgpu: refused ioctl unknown (nr 0x99, cmd 0xc0106499): invalid argument
I1120 05:48:31.500000    4242 gpu.go:80] gvx-gpu-renderer: context 1 created
`

// TestScanGPULogCollectsRefusedIoctls parses refusal lines: one entry for
// each request number in order of first appearance, with the number of DRM
// files that logged it, and a short log with only the GPU lines.
func TestScanGPULogCollectsRefusedIoctls(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sentry.log")
	if err := os.WriteFile(path, []byte(refusedLogFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	scan := scanGPULog(t, path)
	got := scan.Refused
	want := []refusedIoctl{
		{Name: "DRM_IOCTL_SYNCOBJ_CREATE", Nr: "0xbf", Cmd: "0xc00864bf", Error: "operation not supported", Files: 2},
		{Name: "unknown", Nr: "0x99", Cmd: "0xc0106499", Error: "invalid argument", Files: 1},
	}
	if !slices.Equal(got, want) {
		t.Errorf("scanGPULog() = %+v, want %+v", got, want)
	}
	short, err := os.ReadFile(filepath.Join(dir, "sentry-gpu.log"))
	if err != nil {
		t.Fatalf("read sentry-gpu.log: %v", err)
	}
	if n := strings.Count(string(short), "\n"); n != 4 {
		t.Errorf("sentry-gpu.log lines = %d, want 4 (three refusals and one renderer line):\n%s", n, short)
	}
}

// kd1LogFixture holds the KD-1 lines in their log formats: the renderer
// stderr lines (forwarded by pkg/gvx as "gvx-gpu-renderer: <line>"), the
// device lines of wp10.md section 3.4, and one rate-limit summary of the
// client.
const kd1LogFixture = `I1120 06:10:01.000000    4242 gpu.go:145] gvx-gpu-renderer: virgl: server: failed to send message: Invalid argument
I1120 06:10:01.000100    4242 gpu.go:145] gvx-gpu-renderer: virgl: server: failed to dispatch context op 2
I1120 06:10:01.000200    4242 gpu.go:145] gvx-gpu-renderer: virgl: proxy: socket disconnected
I1120 06:10:01.000300    4242 gpu.go:145] gvx-gpu-renderer: virgl: proxy: failed to get reply of blob 0
D1120 06:10:01.000400    4242 gem.go:230] virtgpu: BLOB_CREATE ctx 7 failed: gpuproto: renderer refused BLOB_CREATE: EIO
D1120 06:10:01.000500    4242 gem.go:230] virtgpu: BLOB_CREATE ctx 8 failed: gpuproto: renderer refused BLOB_CREATE: EINVAL
I1120 06:10:01.000600    4242 events.go:50] virtgpu: context 7 lost
I1120 06:10:02.000000    4242 gpu.go:145] gvx-gpu-renderer: gpurender: dropped 12 renderer stderr lines
W1120 06:10:09.000000    4242 events.go:67] virtgpu: renderer lost: gpuproto: GPU renderer lost: gpurender: client closed
`

// TestScanGPULogCountsKD1 counts each KD-1 line once, ignores a BLOB_CREATE
// failure with another errno and the renderer-lost line of the normal
// teardown, and marks the renderer counts incomplete when the client dropped
// stderr lines.
func TestScanGPULogCountsKD1(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentry.log")
	if err := os.WriteFile(path, []byte(kd1LogFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanGPULog(t, path).KD1
	want := kd1Counts{BlobCreateStatusIO: 1, SendMessageEINVAL: 1, SocketDisconnected: 1, ProxyBlobReplyFailed: 1, ContextLost: 1, StderrLinesDropped: 12, Complete: false}
	if got != want {
		t.Errorf("scanGPULog().KD1 = %+v, want %+v", got, want)
	}
	if !got.ReportRequired() {
		t.Errorf("ReportRequired() = false, want true for %+v", got)
	}
}

// TestScanGPULogKD1ZeroIsExplicit checks that a log without KD-1 lines gives
// complete zero counts that need no report, and that the JSON record holds
// each count as 0.
func TestScanGPULogKD1ZeroIsExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentry.log")
	if err := os.WriteFile(path, []byte(refusedLogFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	got := scanGPULog(t, path).KD1
	if got != (kd1Counts{Complete: true}) || got.ReportRequired() {
		t.Errorf("scanGPULog().KD1 = %+v (report %v), want zero counts, complete, no report", got, got.ReportRequired())
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"blob_create_status_io", "renderer_server_failed_to_send_message", "renderer_proxy_socket_disconnected", "context_lost"} {
		if !strings.Contains(string(data), `"`+key+`":0`) {
			t.Errorf("KD-1 JSON %s lacks an explicit %q: 0", data, key)
		}
	}
}

// TestGPUModeEnabled verifies GVX_E2E_GPU_MODES parsing with unset, single,
// comma-separated, and padded values.
func TestGPUModeEnabled(t *testing.T) {
	cases := []struct {
		env  string
		mode string
		want bool
	}{
		{"", "venus", true},
		{"", "virgl", true},
		{"venus", "venus", true},
		{"venus", "virgl", false},
		{"virgl", "venus", false},
		{"virgl", "virgl", true},
		{"venus, virgl", "virgl", true},
		{" VIRGL ", "virgl", true},
		{"none", "venus", false},
	}
	for _, c := range cases {
		t.Setenv(gpuModesEnv, c.env)
		if got := gpuModeEnabled(c.mode); got != c.want {
			t.Errorf("gpuModeEnabled(%q) with %s=%q = %v, want %v", c.mode, gpuModesEnv, c.env, got, c.want)
		}
	}
}
