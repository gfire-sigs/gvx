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
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// guardCase is the outcome of one case of vkguard.c.
type guardCase struct {
	Name   string `json:"name"`
	Stage  string `json:"stage"`  // "call" when the case sent its invalid create info
	Result string `json:"result"` // result of vkguard; empty when the process gave none
	Detail string `json:"detail"`
	Exit   string `json:"exit"` // exit code of the process; empty when the case did not run
}

// guardRecord is the result.json of the venus guard gate.
type guardRecord struct {
	Gate              string               `json:"gate"`
	Pass              bool                 `json:"pass"`
	Host              gpuHostRecord        `json:"host"`
	Image             string               `json:"image"`
	Snapshot          string               `json:"debian_snapshot"`
	DeviceName        string               `json:"device_name"`
	Cases             []guardCase          `json:"cases"`
	RendererLostLines []string             `json:"renderer_lost_lines"`
	RefusedByHost     []string             `json:"refused_by_host"`
	KD1               map[string]kd1Counts `json:"kd1"`
	KD1Report         bool                 `json:"kd1_report_required"`
	Failures          []string             `json:"failures"`
	Files             map[string]string    `json:"files"`
}

// guardKind is one group of vkguard cases that send invalid create info.
type guardKind struct {
	// casePrefix is the start of the case names of the kind.
	casePrefix string
	// logPrefix is the start of the warning that the renderer writes when it
	// refuses the create info (vkr_validate.c of the pinned patch 0003).
	logPrefix string
	// reply is true when the guest driver waits for the result of the
	// command, so that the guest sees the refusal as an error code.
	reply bool
}

// guardKinds lists the kinds. A longer casePrefix comes first.
var guardKinds = []guardKind{
	{casePrefix: "buffer-view-", logPrefix: "vkr: buffer view: "},
	{casePrefix: "view-", logPrefix: "vkr: image view: "},
	{casePrefix: "image-", logPrefix: "vkr: image: ", reply: true},
}

// guardKindOf returns the kind of the case name, or nil for a valid case.
func guardKindOf(name string) *guardKind {
	for i := range guardKinds {
		if strings.HasPrefix(name, guardKinds[i].casePrefix) {
			return &guardKinds[i]
		}
	}
	return nil
}

// parseGuardCases returns the cases of the vkguard.sh output in order.
func parseGuardCases(stdout string) []guardCase {
	var cases []guardCase
	index := map[string]int{}
	for _, line := range strings.Split(stdout, "\n") {
		rest, ok := strings.CutPrefix(line, "GVX-GUARD case=")
		if !ok {
			continue
		}
		// The detail is the rest of the line and can have spaces.
		rest, detail, hasDetail := strings.Cut(rest, " detail=")
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		i, seen := index[fields[0]]
		if !seen {
			i = len(cases)
			index[fields[0]] = i
			cases = append(cases, guardCase{Name: fields[0]})
		}
		for _, f := range fields[1:] {
			key, value, _ := strings.Cut(f, "=")
			switch key {
			case "stage":
				cases[i].Stage = value
			case "result":
				cases[i].Result = value
			case "exit":
				cases[i].Exit = value
			}
		}
		if hasDetail {
			cases[i].Detail = detail
		}
	}
	return cases
}

// guardHostRefusals returns the warnings of the create info tests of the
// renderer in the rungv log at path, each from its "vkr: " prefix.
func guardHostRefusals(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var lines []string
	for _, line := range strings.Split(string(data), "\n") {
		for _, kind := range guardKinds {
			if i := strings.Index(line, kind.logPrefix); i >= 0 {
				lines = append(lines, line[i:])
				break
			}
		}
	}
	return lines
}

// guardCaseFailure returns why the outcome of c is not correct, or "".
func guardCaseFailure(c guardCase) string {
	kind := guardKindOf(c.Name)
	if kind == nil {
		if c.Result != "ok" || c.Exit != "0" {
			return fmt.Sprintf("result=%q exit=%q (%s), want ok and 0: the host must make these valid objects", c.Result, c.Exit, c.Detail)
		}
		return ""
	}
	// Without the stage, the process stopped in the setup of the case and
	// did not send the invalid create info.
	if c.Stage != "call" {
		return fmt.Sprintf("stage=%q result=%q exit=%q (%s): the case did not send its create info", c.Stage, c.Result, c.Exit, c.Detail)
	}
	if kind.reply {
		if c.Result != "refused" || c.Exit != "0" {
			return fmt.Sprintf("result=%q exit=%q (%s), want refused and 0", c.Result, c.Exit, c.Detail)
		}
		return ""
	}
	// The guest driver sends the create command of a view without a reply.
	// The use of the refused view stops the context. The guest then gets an
	// error from the next command with a reply (lost), or the guest driver
	// stops the process with abort (exit code 134).
	switch {
	case c.Result == "refused" && c.Exit == "0":
	case c.Result == "lost" && c.Exit == "0":
	case c.Result == "" && c.Exit == "134":
	default:
		return fmt.Sprintf("result=%q exit=%q (%s), want refused, lost, or exit 134 without a result", c.Result, c.Exit, c.Detail)
	}
	return ""
}

// TestE2EGateGPUVenusGuard proves that create info from the guest does not
// stop the renderer. vkguard.c sends, each in a new venus context, valid
// objects that a host driver defect made fatal (the 3D image of the WebGL
// conformance page conformance2/textures/misc/tex-storage-and-subimage-3d.html)
// and invalid create info of images, image views, and buffer views. The host
// must make the valid objects, refuse each invalid create info, and keep the
// renderer: the last case makes ordinary objects in a new context.
func TestE2EGateGPUVenusGuard(t *testing.T) {
	requireGPUGate(t)
	if !gpuModeEnabled("venus") {
		t.Skipf("venus not in %s", gpuModesEnv)
	}
	art := gpuArtifactDir(t, "venus-guard")
	start := time.Now()
	rec := guardRecord{Gate: "venus-guard", Image: g1Image, Snapshot: g1Snapshot, Host: newGPUHostRecord(start),
		KD1: map[string]kd1Counts{},
		Files: map[string]string{
			"stdout":  "venus/stdout.txt",
			"log":     "venus/sentry.log",
			"gpu_log": "venus/sentry-gpu.log",
			"kd1":     "kd1.json",
			"result":  "result.json",
		}}
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
	fail := func(format string, args ...any) {
		t.Helper()
		t.Errorf(format, args...)
		rec.Failures = append(rec.Failures, fmt.Sprintf(format, args...))
	}

	runDir, out := newGPURunDir(t, art, "venus")
	res := runGPUGuest(t, runDir, gpuRun{
		gpu:       true,
		image:     g1Image,
		net:       "nat",
		workspace: g1Workspace(t),
		out:       out,
		env:       []string{"GVX_G1_SNAPSHOT=" + g1Snapshot, "GVX_G1_ICD=" + venusICD},
		argv:      []string{"bash", "/workspace/gpu/vkguard.sh"},
		timeout:   g1Timeout + 60*time.Minute,
	})
	scan := scanGPULog(t, res.log)
	rec.KD1["venus"] = scan.KD1
	rec.RendererLostLines = scan.RendererLostLines
	rec.RefusedByHost = guardHostRefusals(t, res.log)
	rec.Cases = parseGuardCases(res.stdout)
	rec.DeviceName = keyValues(res.stdout, "GVX-GUARD ")["device_name"]

	if !strings.Contains(res.stdout, "GVX-GUARD step=cases") || !strings.Contains(res.stdout, "GVX-GUARD done") {
		fail("vkguard.sh did not run its cases (rungv exit %d): %s; stdout:\n%s", res.code, rungvError(res.log), res.stdout)
		return
	}
	if !strings.HasPrefix(rec.DeviceName, venusDeviceName) {
		fail("device_name = %q, want %q (...)", rec.DeviceName, venusDeviceName)
	}

	// The main claim: no case stopped the renderer.
	for _, line := range scan.RendererLostLines {
		fail("the renderer stopped: %s", line)
	}

	wantRefusals := map[string]int{}
	valid := 0
	for _, c := range rec.Cases {
		t.Logf("case %s: stage=%q result=%q detail=%q exit=%q", c.Name, c.Stage, c.Result, c.Detail, c.Exit)
		if msg := guardCaseFailure(c); msg != "" {
			fail("case %s: %s", c.Name, msg)
		}
		if kind := guardKindOf(c.Name); kind != nil {
			wantRefusals[kind.logPrefix]++
		} else {
			valid++
		}
	}
	if valid == 0 || rec.Cases[len(rec.Cases)-1].Name != "alive" {
		fail("vkguard gave %d valid cases, and the last case is not \"alive\"", valid)
	}

	// Each invalid create info gives one warning of its kind in the renderer
	// log. An exact count proves that the host test refused each case, and
	// that a refusal in the guest did not hide a missing host test.
	gotRefusals := map[string]int{}
	for _, line := range rec.RefusedByHost {
		for _, kind := range guardKinds {
			if strings.HasPrefix(line, kind.logPrefix) {
				gotRefusals[kind.logPrefix]++
			}
		}
	}
	for _, kind := range guardKinds {
		want, got := wantRefusals[kind.logPrefix], gotRefusals[kind.logPrefix]
		if want == 0 {
			fail("vkguard ran no %q case", kind.casePrefix)
		}
		if got != want {
			fail("the renderer log has %d %q lines, want %d (one for each %q case):\n%s",
				got, kind.logPrefix, want, kind.casePrefix, strings.Join(rec.RefusedByHost, "\n"))
		}
	}
}

func TestParseGuardCases(t *testing.T) {
	const stdout = `GVX-GUARD step=cases
GVX-GUARD device_name=Virtio-GPU Venus (Apple M1 Ultra)
GVX-GUARD case=valid-3d-1x1x8 result=ok detail=3D view:0
GVX-GUARD case=valid-3d-1x1x8 exit=0
GVX-GUARD case=image-levels stage=call
GVX-GUARD case=image-levels result=refused detail=vkCreateImage:-1000011001
GVX-GUARD case=image-levels exit=0
GVX-GUARD case=view-levels stage=call
GVX-GUARD case=view-levels exit=134
GVX-GUARD case=buffer-view-range exit=139
GVX-GUARD done
`
	got := parseGuardCases(stdout)
	want := []guardCase{
		{Name: "valid-3d-1x1x8", Result: "ok", Detail: "3D view:0", Exit: "0"},
		{Name: "image-levels", Stage: "call", Result: "refused", Detail: "vkCreateImage:-1000011001", Exit: "0"},
		{Name: "view-levels", Stage: "call", Exit: "134"},
		{Name: "buffer-view-range", Exit: "139"},
	}
	if len(got) != len(want) {
		t.Fatalf("parseGuardCases gave %d cases, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("case %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// The first three outcomes are correct. The last case stopped in its
	// setup, so it did not send its create info.
	for i, wantFailure := range []bool{false, false, false, true} {
		if msg := guardCaseFailure(got[i]); (msg != "") != wantFailure {
			t.Errorf("guardCaseFailure(%s) = %q, want a failure: %v", got[i].Name, msg, wantFailure)
		}
	}
	for _, c := range []guardCase{
		{Name: "view-levels", Stage: "call", Result: "accepted", Exit: "0"},
		{Name: "view-levels", Stage: "call", Exit: "139"},
		{Name: "view-levels", Stage: "call", Exit: "124"},
		{Name: "image-levels", Stage: "call", Exit: "134"},
		{Name: "alive", Result: "fail", Exit: "0"},
	} {
		if guardCaseFailure(c) == "" {
			t.Errorf("guardCaseFailure(%+v) = \"\", want a failure", c)
		}
	}
	if kind := guardKindOf("buffer-view-range"); kind == nil || kind.logPrefix != "vkr: buffer view: " {
		t.Errorf("guardKindOf(buffer-view-range) = %+v, want the buffer view kind", kind)
	}
	if kind := guardKindOf("valid-3d-1x1x8"); kind != nil {
		t.Errorf("guardKindOf(valid-3d-1x1x8) = %+v, want nil", kind)
	}
}
