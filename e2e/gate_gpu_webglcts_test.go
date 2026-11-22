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
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
)

const (
	// webglCTSEnv turns TestE2EGateGPUWebGLCTS on and selects its scope:
	// "subset" (also "1"), "full", or "full-deqp".
	webglCTSEnv = "GVX_E2E_WEBGL_CTS"

	// webglCTSPagesEnv overrides webgl-cts-subset.txt with comma-separated
	// selectors in subset syntax for diagnosis runs.
	webglCTSPagesEnv = "GVX_E2E_WEBGL_CTS_PAGES"

	webglCTSGuestPath     = "/opt/webgl-cts"
	webglCTSProbeGuestDir = "/opt/gvx-gpu-probe"
	webglCTSProbeGuestBin = "/opt/gvx-gpu-probe/gvx-gpu-probe"
	webglCTSVersion1      = "1.0.4"
	webglCTSVersion2      = "2.0.1"

	// maxCTSSandboxResumes bounds resume runs after the initial sandbox run in
	// one mode (1 initial run plus 4 resumes = 5 sandbox runs total).
	maxCTSSandboxResumes = 4

	// The gate appends webglCTSChromiumFlags to the flags of every mode. They
	// match Chromium's conformance runner (GenerateBrowserArgs in
	// content/test/gpu/gpu_tests/webgl_conformance_integration_test_base.py)
	// without --test-type=gpu, which only hides an info bar.
	webglCTSChromiumFlags = "--autoplay-policy=no-user-gesture-required " +
		"--disable-domain-blocking-for-3d-apis --disable-gpu-process-crash-limit " +
		"--enable-webgl-draft-extensions --disable-gpu-watchdog " +
		"--enable-blink-features=SharedArrayBuffer --disable-features=CanvasNoise " +
		"--js-flags=--expose-gc"
)

// ctsRecord is result.json of TestE2EGateGPUWebGLCTS.
type ctsRecord struct {
	Gate         string                     `json:"gate"`
	Pass         bool                       `json:"pass"`
	Scope        string                     `json:"scope"`
	Diagnosis    string                     `json:"diagnosis_pages,omitempty"`
	Host         gpuHostRecord              `json:"host"`
	Image        string                     `json:"image"`
	CTSCommit    string                     `json:"cts_commit"`
	CTSDigest    string                     `json:"cts_sha256"`
	Versions     map[string]string          `json:"versions"`
	SubsetSHA256 string                     `json:"subset_sha256"`
	ExpectSHA256 string                     `json:"expectations_sha256"`
	Pages        int                        `json:"pages"`
	Modes        map[string]*ctsModeSummary `json:"modes"`
	Regressions  int                        `json:"unexpected_regressions"`
	Degradations int                        `json:"unexpected_degradations"`
	Stale        []string                   `json:"stale_expectations"`
	KD1          map[string]kd1Counts       `json:"kd1"`
	KD1Report    bool                       `json:"kd1_report_required"`
	Failures     []string                   `json:"failures"`
	Files        map[string]string          `json:"files"`
}

// ctsModeSummary is the summary of one mode in result.json.
type ctsModeSummary struct {
	ChromiumFlags  string            `json:"chromium_flags"`
	Renderer       string            `json:"renderer"`
	Guest          map[string]string `json:"guest"`
	Counts         map[string]int    `json:"counts"`
	Flaky          int               `json:"flaky"`
	Runs           int               `json:"sandbox_runs"`
	Launches       int               `json:"browser_launches"`
	RendererLosses int               `json:"renderer_losses"`
	WallSec        int               `json:"wall_sec"`
	RefusedIoctls  []refusedIoctl    `json:"refused_ioctls"`
}

// ctsModeResult is <mode>/results.json: one entry for each page.
type ctsModeResult struct {
	Mode  string                    `json:"mode"`
	Pages map[string]*ctsRecordPage `json:"pages"`
}

// ctsRecordPage is one page outcome in <mode>/results.json.
type ctsRecordPage struct {
	Status         ctsStatus `json:"status"`
	Reason         string    `json:"reason,omitempty"`
	Passed         int       `json:"passed"`
	Failed         int       `json:"failed"`
	Skipped        int       `json:"skipped"`
	Millis         int       `json:"ms"`
	Attempts       int       `json:"attempts"`
	Flaky          bool      `json:"flaky,omitempty"`
	ContextLost    int       `json:"context_lost,omitempty"`
	Renderers      []string  `json:"renderers,omitempty"`
	SoftwareRender bool      `json:"software_renderer,omitempty"`
	Messages       []string  `json:"messages,omitempty"`
	HostEvents     []string  `json:"host_events,omitempty"`
}

type ctsPageEntry struct {
	ID    string `json:"id"`
	WebGL int    `json:"webgl"`
	Path  string `json:"page"`
	Slow  bool   `json:"slow,omitempty"`
}

// TestE2EGateGPUWebGLCTS runs the WebGL 1 and WebGL 2 conformance suites on
// SwiftShader, venus, and virgl. It fails when a GPU mode regresses or
// degrades relative to SwiftShader without a matching expectation.
func TestE2EGateGPUWebGLCTS(t *testing.T) {
	requireGPUGate(t)
	rawScope := strings.TrimSpace(os.Getenv(webglCTSEnv))
	if rawScope == "" {
		t.Skipf("WebGL CTS gate is off; set %s=subset, full, or full-deqp", webglCTSEnv)
	}
	var scope string
	switch rawScope {
	case "1", "subset":
		scope = "subset"
	case "full":
		scope = "full"
	case "full-deqp":
		scope = "full-deqp"
	default:
		t.Fatalf("unknown %s=%q; want subset, full, or full-deqp", webglCTSEnv, rawScope)
	}

	art := gpuArtifactDir(t, "webgl-cts")
	cts := acceptprog.FetchWebGLCTS(t)
	pwcore := acceptprog.FetchPlaywrightCore(t)

	subsetBytes, err := gpuAssets.ReadFile("testdata/gpu/webgl-cts-subset.txt")
	if err != nil {
		t.Fatalf("read webgl-cts-subset.txt: %v", err)
	}
	expectBytes, err := gpuAssets.ReadFile("testdata/gpu/webgl-cts-expectations.txt")
	if err != nil {
		t.Fatalf("read webgl-cts-expectations.txt: %v", err)
	}

	start := time.Now()
	rec := &ctsRecord{
		Gate:      "WEBGL-CTS",
		Scope:     scope,
		Diagnosis: strings.TrimSpace(os.Getenv(webglCTSPagesEnv)),
		Host:      newGPUHostRecord(start),
		Image:     browserImage,
		CTSCommit: acceptprog.WebGLCTSCommit,
		CTSDigest: acceptprog.WebGLCTSSHA256,
		Versions: map[string]string{
			"webgl1": webglCTSVersion1,
			"webgl2": webglCTSVersion2,
		},
		SubsetSHA256: sha256Hex(subsetBytes),
		ExpectSHA256: sha256Hex(expectBytes),
		Modes:        map[string]*ctsModeSummary{},
		Stale:        []string{},
		KD1:          map[string]kd1Counts{},
		Failures:     []string{},
		Files: map[string]string{
			"result":      "result.json",
			"qa":          "QA.md",
			"pages":       "pages.json",
			"regressions": "regressions.json",
			"candidates":  "expectations-candidates.txt",
			"kd1":         "kd1.json",
			"per_mode":    "<mode>/{results.json,refused-ioctls.json,gpu-info.json,run<n>/}",
		},
	}

	modeResults := map[string]*ctsModeResult{}
	allDeltas := []ctsDelta{}
	swFailures := []ctsDelta{}
	unplacedEvents := map[string][]string{}

	defer func() {
		rec.Host.DurationSec = int(time.Since(start).Seconds())
		rec.Pass = !t.Failed()
		recordKD1(t, rec.KD1)
		for _, k := range rec.KD1 {
			rec.KD1Report = rec.KD1Report || k.ReportRequired()
		}
		for mode, mr := range modeResults {
			modeDir := filepath.Join(art, mode)
			if err := os.MkdirAll(modeDir, 0o755); err != nil {
				t.Errorf("create %s: %v", modeDir, err)
				continue
			}
			writeJSONSoft(t, filepath.Join(modeDir, "results.json"), mr)
		}
		writeJSONSoft(t, filepath.Join(art, "kd1.json"), rec.KD1)
		writeJSONSoft(t, filepath.Join(art, "regressions.json"), allDeltas)

		candDeltas := make([]ctsDelta, 0, len(swFailures)+len(allDeltas))
		candDeltas = append(candDeltas, swFailures...)
		candDeltas = append(candDeltas, allDeltas...)
		var candBuf bytes.Buffer
		if err := writeCTSCandidates(&candBuf, candDeltas); err != nil {
			t.Errorf("format expectations-candidates.txt: %v", err)
		} else if err := os.WriteFile(filepath.Join(art, "expectations-candidates.txt"), candBuf.Bytes(), 0o644); err != nil {
			t.Errorf("write expectations-candidates.txt: %v", err)
		}

		writeJSONSoft(t, filepath.Join(art, "result.json"), rec)

		var qaBuf bytes.Buffer
		if err := writeCTSQA(&qaBuf, rec, modeResults, allDeltas, swFailures, unplacedEvents); err != nil {
			t.Errorf("format QA.md: %v", err)
		} else if err := os.WriteFile(filepath.Join(art, "QA.md"), qaBuf.Bytes(), 0o644); err != nil {
			t.Errorf("write QA.md: %v", err)
		}
	}()

	fail := func(format string, args ...any) {
		t.Helper()
		msg := fmt.Sprintf(format, args...)
		t.Error(msg)
		rec.Failures = append(rec.Failures, msg)
	}

	venusEnabled := gpuModeEnabled("venus")
	virglEnabled := gpuModeEnabled("virgl")
	if venusEnabled {
		if err := verifyVenusMesaPatches(os.Getenv(gpuRendererEnv), filepath.Join("..", "gpurenderer", "patches", "mesa")); err != nil {
			fail("venus: %v", err)
			venusEnabled = false
			if !virglEnabled {
				t.FailNow()
			}
		}
	}

	exps, err := parseCTSExpectations(bytes.NewReader(expectBytes))
	if err != nil {
		fail("parse webgl-cts-expectations.txt: %v", err)
		t.FailNow()
	}

	ctsFS := os.DirFS(cts)
	w1, err := expandCTSList(ctsFS, "00_test_list.txt", webglCTSVersion1, 1)
	if err != nil {
		fail("expand WebGL 1 test list: %v", err)
		t.FailNow()
	}
	w2, err := expandCTSList(ctsFS, "00_test_list.txt", webglCTSVersion2, 2)
	if err != nil {
		fail("expand WebGL 2 test list: %v", err)
		t.FailNow()
	}
	allPages := append(append([]ctsPage(nil), w1...), w2...)

	var selected []ctsPage
	switch {
	case rec.Diagnosis != "":
		lines := strings.ReplaceAll(rec.Diagnosis, ",", "\n")
		sel, selErr := parseCTSSubset(strings.NewReader(lines))
		if selErr != nil {
			fail("parse %s: %v", webglCTSPagesEnv, selErr)
			t.FailNow()
		}
		selected, err = selectCTSPages(allPages, sel)
		if err != nil {
			fail("select %s pages: %v", webglCTSPagesEnv, err)
			t.FailNow()
		}
	case scope == "subset":
		sel, selErr := parseCTSSubset(bytes.NewReader(subsetBytes))
		if selErr != nil {
			fail("parse webgl-cts-subset.txt: %v", selErr)
			t.FailNow()
		}
		selected, err = selectCTSPages(allPages, sel)
		if err != nil {
			fail("select subset pages: %v", err)
			t.FailNow()
		}
	case scope == "full":
		selected = append(selected, w1...)
		for _, p := range w2 {
			if !strings.HasPrefix(p.Path, "deqp/functional/") {
				selected = append(selected, p)
			}
		}
	case scope == "full-deqp":
		selected = allPages
	}

	rec.Pages = len(selected)
	pageEntries := make([]ctsPageEntry, len(selected))
	for i, p := range selected {
		pageEntries[i] = ctsPageEntry{ID: p.ID(), WebGL: p.WebGL, Path: p.Path, Slow: p.Slow}
	}
	writeJSONSoft(t, filepath.Join(art, "pages.json"), pageEntries)

	venusFlags := cmp.Or(os.Getenv(gpuChromiumFlagsEnv), gpuChromiumFlags) + " " + webglCTSChromiumFlags
	virglFlags := cmp.Or(os.Getenv(gpuChromiumVirglFlagsEnv), gpuChromiumVirglFlags) + " " + webglCTSChromiumFlags
	swFlags := referenceChromiumFlags + " " + webglCTSChromiumFlags

	baseRO := map[string]string{
		pwcore: playwrightCoreGuestPath,
		cts:    webglCTSGuestPath,
	}

	var probeDir string
	if venusEnabled || virglEnabled {
		probeDir = ctsDeviceProbeDir(t, hostArch())
	}

	type modeSpec struct {
		name     string
		gpuMode  string
		flags    string
		probeBin string
		readOnly map[string]string
	}
	modes := []modeSpec{
		{name: "swiftshader", gpuMode: "off", flags: swFlags, readOnly: baseRO},
	}
	if venusEnabled {
		debs := acceptprog.FetchGPUGuestDebs(t, hostArch())
		ro := map[string]string{
			pwcore:   playwrightCoreGuestPath,
			cts:      webglCTSGuestPath,
			debs:     gpuDebsGuestPath,
			probeDir: webglCTSProbeGuestDir,
		}
		modes = append(modes, modeSpec{name: "venus", gpuMode: "venus", flags: venusFlags, probeBin: webglCTSProbeGuestBin, readOnly: ro})
	}
	if virglEnabled {
		ro := map[string]string{
			pwcore:   playwrightCoreGuestPath,
			cts:      webglCTSGuestPath,
			probeDir: webglCTSProbeGuestDir,
		}
		modes = append(modes, modeSpec{name: "virgl", gpuMode: "virgl", flags: virglFlags, probeBin: webglCTSProbeGuestBin, readOnly: ro})
	}

	ranModes := map[string]bool{}
	for _, m := range modes {
		summary, mr, kd1, unplaced, clean := runCTSMode(t, art, m.name, m.gpuMode, m.flags, m.probeBin, m.readOnly, selected, fail)
		rec.Modes[m.name] = summary
		rec.KD1[m.name] = kd1
		modeResults[m.name] = mr
		unplacedEvents[m.name] = unplaced
		ranModes[m.name] = true

		if summary.Counts["not-run"] > 0 {
			fail("%s has %d not-run pages after resumes", m.name, summary.Counts["not-run"])
		}
		if summary.Counts["error"] > 0 {
			fail("%s has %d driver error pages", m.name, summary.Counts["error"])
		}
		renderers := collectCTSRenderers(mr.Pages)
		rendererOK := validateModeRenderers(m.name, renderers, fail)
		if m.name == "swiftshader" {
			if !clean || summary.Counts["not-run"] > 0 || summary.Counts["error"] > 0 || !rendererOK {
				t.FailNow()
			}
		} else if summary.RendererLosses > 0 {
			fail("%s lost the GPU renderer %d times", m.name, summary.RendererLosses)
		}
	}

	swResult := modeResults["swiftshader"]
	usedExp := make([]bool, len(exps))
	enforceSubset := scope == "subset" && rec.Diagnosis == ""

	for _, p := range selected {
		id := p.ID()
		r := swResult.Pages[id]
		if r == nil || r.Status == ctsPass {
			continue
		}
		d := ctsDelta{
			ID:        id,
			Mode:      "swiftshader",
			Reference: r.Status,
			Status:    r.Status,
			Reason:    r.Reason,
			Failed:    r.Failed,
			Messages:  r.Messages,
			Flaky:     r.Flaky,
			Kind:      "swiftshader-fail",
		}
		if idx := matchCTSExpectationIndex(exps, d); idx >= 0 {
			d.Expected = exps[idx].Reason
			usedExp[idx] = true
		} else if enforceSubset {
			fail("subset page %s does not pass on SwiftShader (status %s)", id, r.Status)
		}
		swFailures = append(swFailures, d)
	}

	for _, mode := range []string{"venus", "virgl"} {
		gpuResult, ok := modeResults[mode]
		if !ok {
			continue
		}
		deltas := diffCTSModes(mode, swResult.Pages, gpuResult.Pages)
		for i := range deltas {
			d := &deltas[i]
			if d.Kind != "regression" && d.Kind != "degradation" {
				continue
			}
			if idx := matchCTSExpectationIndex(exps, *d); idx >= 0 {
				d.Expected = exps[idx].Reason
				usedExp[idx] = true
				continue
			}
			if d.Kind == "regression" {
				rec.Regressions++
			} else if d.Kind == "degradation" {
				rec.Degradations++
			}
			if enforceSubset {
				fail("%s %s %s: swiftshader=%s, %s=%s (no expectation)", d.Mode, d.Kind, d.ID, d.Reference, d.Mode, d.Status)
			}
		}
		allDeltas = append(allDeltas, deltas...)
	}

	if rec.Diagnosis == "" {
		rec.Stale = findStaleCTSExpectations(exps, usedExp, ranModes, selected)
	}
}

func runCTSMode(t *testing.T, art, mode, gpuMode, flags, probeBin string, readOnly map[string]string, pages []ctsPage, fail func(format string, args ...any)) (*ctsModeSummary, *ctsModeResult, kd1Counts, []string, bool) {
	t.Helper()
	modeStart := time.Now()
	modeDir := filepath.Join(art, mode)
	if err := os.MkdirAll(modeDir, 0o755); err != nil {
		t.Fatalf("create %s: %v", modeDir, err)
	}

	summary := &ctsModeSummary{
		ChromiumFlags: flags,
		Guest:         map[string]string{},
		Counts: map[string]int{
			"pass":    0,
			"fail":    0,
			"timeout": 0,
			"crash":   0,
			"error":   0,
			"not-run": 0,
		},
		RefusedIoctls: []refusedIoctl{},
	}
	modeKD1 := kd1Counts{Complete: true}
	var runs []ctsRunRecord

	remaining := pages
	gpuInfoCopied := false
	lastClean := false
	lastStatus := "no sandbox run executed"

	maxRuns := 1 + maxCTSSandboxResumes
	for runIdx := 1; runIdx <= maxRuns && len(remaining) > 0; runIdx++ {
		ws := g2Workspace(t)
		listPath := filepath.Join(ws, "gpu", "webgl-cts-pages.txt")
		var listBuf bytes.Buffer
		if err := writeCTSRunList(&listBuf, remaining); err != nil {
			t.Fatalf("format webgl-cts-pages.txt: %v", err)
		}
		if err := os.WriteFile(listPath, listBuf.Bytes(), 0o644); err != nil {
			t.Fatalf("write %s: %v", listPath, err)
		}

		runDir, out := newGPURunDir(t, modeDir, fmt.Sprintf("run%d", runIdx))
		timeout := min(10*time.Minute+time.Duration(len(remaining))*8*time.Second, 4*time.Hour)
		runStart := time.Now()
		runEnv := []string{
			"GVX_CTS_MODE=" + mode,
			"GVX_CTS_ARGS=" + flags,
			"GVX_CTS_OUT=" + gpuOutGuestPath,
			"GVX_CTS_LIST=/workspace/gpu/webgl-cts-pages.txt",
		}
		if probeBin != "" {
			runEnv = append(runEnv, "GVX_CTS_PROBE="+probeBin)
		}
		res := runGPUGuest(t, runDir, gpuRun{
			mode:        gpuMode,
			image:       browserImage,
			net:         "none",
			workspace:   ws,
			out:         out,
			readOnly:    readOnly,
			env:         runEnv,
			argv:        []string{"bash", "/workspace/gpu/webgl-cts.sh"},
			timeout:     timeout,
			softTimeout: true,
		})
		summary.Runs++

		scan := scanGPULog(t, res.log)
		summary.RefusedIoctls = mergeRefusedIoctls(summary.RefusedIoctls, scan.Refused)
		modeKD1 = addKD1Counts(modeKD1, scan.KD1)

		runRec := ctsRunRecord{
			logPath:       res.log,
			year:          runStart.Year(),
			rendererLost:  scan.KD1.RendererLost > 0,
			lossEventLine: firstRendererLostLine(scan.RendererLostLines),
		}
		jl := filepath.Join(out, "results.jsonl")
		if _, err := os.Stat(jl); err == nil {
			runRec.jsonlPath = jl
		}
		runs = append(runs, runRec)

		if !gpuInfoCopied {
			if err := copyFile(filepath.Join(out, "gpu-info.json"), filepath.Join(modeDir, "gpu-info.json")); err == nil {
				gpuInfoCopied = true
			}
		}

		for k, v := range keyValues(res.stdout, "GVX-CTS ") {
			if _, seen := summary.Guest[k]; !seen {
				summary.Guest[k] = v
			}
		}
		for _, line := range strings.Split(res.stdout, "\n") {
			if strings.HasPrefix(line, "GVX-CTS launch=") {
				summary.Launches++
			}
		}

		abortReason := parseCTSAbortReason(res.stdout)
		runClean := ctsRunFinishedCleanly(res)
		lastStatus = fmt.Sprintf("exit=%d timedOut=%v done=%v abort=%q error=%v rendererLost=%v",
			res.code, res.timedOut,
			strings.Contains(res.stdout, "GVX-CTS done"),
			abortReason,
			strings.Contains(res.stdout, "GVX-CTS error="),
			runRec.rendererLost)
		if runClean && !runRec.rendererLost {
			lastClean = true
			break
		}

		mergedSoFar, readErr := readCTSRunRecords(runs)
		if readErr != nil {
			fail("%s run%d read results.jsonl: %v", mode, runIdx, readErr)
			lastClean = false
			break
		}
		remaining = ctsRemainingPages(pages, mergedSoFar.Pages, true)
		if runRec.rendererLost || abortReason == "renderer-lost" {
			lossPage := ""
			if len(mergedSoFar.LossPages) > 0 {
				lossPage = mergedSoFar.LossPages[len(mergedSoFar.LossPages)-1]
			}
			t.Logf("%s run%d lost GPU renderer (lossPage=%q, abort=%q, invalidated=%d); %d pages remain",
				mode, runIdx, lossPage, abortReason, mergedSoFar.Invalidated, len(remaining))
			if len(remaining) == 0 {
				lastClean = true
				break
			}
			lastClean = false
			continue
		}
		lastClean = false
		t.Logf("%s run%d did not finish cleanly (%s); %d pages remain", mode, runIdx, lastStatus, len(remaining))
	}

	if !lastClean {
		fail("%s did not finish cleanly after %d run(s) (%s)", mode, summary.Runs, lastStatus)
	}

	mergedOut, err := readCTSRunRecords(runs)
	if err != nil {
		fail("%s read merged results: %v", mode, err)
	}
	merged := map[string]*ctsRecordPage{}
	windows := map[string][][2]int64{}
	var placedEvents map[string]bool
	summary.RendererLosses = modeKD1.RendererLost
	if mergedOut != nil {
		merged = mergedOut.Pages
		windows = mergedOut.Windows
		placedEvents = mergedOut.PlacedEvents
		summary.RendererLosses = max(modeKD1.RendererLost, len(mergedOut.LossPages))
		if mergedOut.Truncated > 0 {
			t.Logf("%s ignored %d truncated trailing JSONL line(s)", mode, mergedOut.Truncated)
		}
		if mergedOut.Invalidated > 0 {
			t.Logf("%s dropped %d invalid JSONL record(s)", mode, mergedOut.Invalidated)
		}
		for _, runNum := range mergedOut.UnattributedLosses {
			fail("%s run%d reported a Sentry renderer loss with no renderer_lost probe record and no in-flight page", mode, runNum)
		}
	}

	for _, p := range pages {
		id := p.ID()
		if _, ok := merged[id]; !ok {
			merged[id] = &ctsRecordPage{Status: ctsNotRun, Reason: "not-run"}
		}
	}

	var unplaced []string
	for _, lr := range runs {
		data, readErr := os.ReadFile(lr.logPath)
		if readErr != nil {
			continue
		}
		unplaced = append(unplaced, placeHostEventsSkip(string(data), lr.year, time.Local, merged, windows, placedEvents)...)
	}

	markCTSSoftwareRenderers(mode, merged)

	for _, p := range pages {
		rec := merged[p.ID()]
		summary.Counts[string(rec.Status)]++
		if rec.Flaky {
			summary.Flaky++
		}
	}
	summary.Renderer = pickCTSModeRenderer(mode, collectCTSRenderers(merged))
	summary.WallSec = int(time.Since(modeStart).Seconds())

	mr := &ctsModeResult{Mode: mode, Pages: merged}
	writeJSONSoft(t, filepath.Join(modeDir, "refused-ioctls.json"), summary.RefusedIoctls)
	writeJSONSoft(t, filepath.Join(modeDir, "results.json"), mr)
	return summary, mr, modeKD1, unplaced, lastClean
}

type ctsRunRecord struct {
	jsonlPath     string
	logPath       string
	year          int
	rendererLost  bool
	lossEventLine string
}

func readCTSRunRecords(runs []ctsRunRecord) (*ctsMergeOutput, error) {
	if len(runs) == 0 {
		return &ctsMergeOutput{
			Pages:        map[string]*ctsRecordPage{},
			Windows:      map[string][][2]int64{},
			PlacedEvents: map[string]bool{},
		}, nil
	}
	inputs := make([]ctsRunInput, len(runs))
	var files []*os.File
	defer func() {
		for _, f := range files {
			_ = f.Close()
		}
	}()
	for i, r := range runs {
		var reader io.Reader
		if r.jsonlPath != "" {
			f, err := os.Open(r.jsonlPath)
			if err != nil {
				return nil, err
			}
			files = append(files, f)
			reader = f
		}
		inputs[i] = ctsRunInput{
			Results:       reader,
			RendererLost:  r.rendererLost,
			LossEventLine: r.lossEventLine,
		}
	}
	return mergeCTSRuns(inputs)
}

var ctsProbeDirs = map[string]string{}

// ctsDeviceProbeDir compiles the static Linux virtgpu device probe for arch
// once per test run and returns the host directory containing gvx-gpu-probe.
func ctsDeviceProbeDir(t *testing.T, arch string) string {
	t.Helper()
	toolsMu.Lock()
	defer toolsMu.Unlock()
	if dir, ok := ctsProbeDirs[arch]; ok {
		return dir
	}
	if toolsDir == "" {
		dir, err := os.MkdirTemp("", "gvx-e2e-tools-*")
		if err != nil {
			t.Fatalf("create tool dir: %v", err)
		}
		toolsDir = dir
	}
	dir := filepath.Join(toolsDir, "gpuprobe-"+arch)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create probe dir %s: %v", dir, err)
	}
	out := filepath.Join(dir, "gvx-gpu-probe")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./testdata/gpuprobe/main.go")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS=linux", "GOARCH="+arch)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build gpuprobe (%s) failed: %v\n%s", arch, err, combined)
	}
	ctsProbeDirs[arch] = dir
	return dir
}

func mergeRefusedIoctls(dst, add []refusedIoctl) []refusedIoctl {
	index := make(map[string]int, len(dst))
	for i, r := range dst {
		index[r.Name+" "+r.Nr] = i
	}
	for _, r := range add {
		key := r.Name + " " + r.Nr
		if i, ok := index[key]; ok {
			dst[i].Files += r.Files
			continue
		}
		index[key] = len(dst)
		dst = append(dst, r)
	}
	return dst
}

func addKD1Counts(a, b kd1Counts) kd1Counts {
	return kd1Counts{
		BlobCreateStatusIO:   a.BlobCreateStatusIO + b.BlobCreateStatusIO,
		SendMessageEINVAL:    a.SendMessageEINVAL + b.SendMessageEINVAL,
		SocketDisconnected:   a.SocketDisconnected + b.SocketDisconnected,
		ProxyBlobReplyFailed: a.ProxyBlobReplyFailed + b.ProxyBlobReplyFailed,
		ContextLost:          a.ContextLost + b.ContextLost,
		RendererLost:         a.RendererLost + b.RendererLost,
		StderrLinesDropped:   a.StderrLinesDropped + b.StderrLinesDropped,
		Complete:             a.Complete && b.Complete,
	}
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// writeJSONSoft writes v as indented JSON to path and records errors with
// t.Errorf rather than t.Fatalf so deferred artifact writes continue.
func writeJSONSoft(t *testing.T, path string, v any) {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Errorf("encode %s: %v", path, err)
		return
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		t.Errorf("write %s: %v", path, err)
	}
}
