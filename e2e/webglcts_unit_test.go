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
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"z.gfire.dev/gvx/internal/acceptprog"
)

func TestExpandCTSListInheritsVersions(t *testing.T) {
	fsys := fstest.MapFS{
		"00_test_list.txt": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"c1/basic.html",
			"--min-version 2.0.0 c2/00_test_list.txt",
		}, "\n"))},
		"c2/00_test_list.txt": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"plain.html",
			"--max-version 1.9.9 old-only.html",
		}, "\n"))},
	}

	w1, err := expandCTSList(fsys, "00_test_list.txt", "1.0.4", 1)
	if err != nil {
		t.Fatalf("expandCTSList(1.0.4) = %v, want nil", err)
	}
	want1 := []ctsPage{{WebGL: 1, Path: "c1/basic.html"}}
	if !slices.Equal(w1, want1) {
		t.Fatalf("expandCTSList(1.0.4) = %+v, want %+v", w1, want1)
	}

	w2, err := expandCTSList(fsys, "00_test_list.txt", "2.0.1", 2)
	if err != nil {
		t.Fatalf("expandCTSList(2.0.1) = %v, want nil", err)
	}
	want2 := []ctsPage{
		{WebGL: 2, Path: "c1/basic.html"},
		{WebGL: 2, Path: "c2/plain.html"},
	}
	if !slices.Equal(w2, want2) {
		t.Fatalf("expandCTSList(2.0.1) = %+v, want %+v", w2, want2)
	}
}

func TestExpandCTSListSlowAndComments(t *testing.T) {
	fsys := fstest.MapFS{
		"00_test_list.txt": &fstest.MapFile{Data: []byte(strings.Join([]string{
			"# hash comment",
			"; semicolon comment",
			"// slash comment",
			"ab",
			"1234",
			"--slow slowdir/00_test_list.txt",
			"fast.html",
		}, "\n"))},
		"slowdir/00_test_list.txt": &fstest.MapFile{Data: []byte("page1.html\npage2.html\n")},
	}
	got, err := expandCTSList(fsys, "00_test_list.txt", "1.0.4", 1)
	if err != nil {
		t.Fatalf("expandCTSList() = %v, want nil", err)
	}
	want := []ctsPage{
		{WebGL: 1, Path: "slowdir/page1.html", Slow: true},
		{WebGL: 1, Path: "slowdir/page2.html", Slow: true},
		{WebGL: 1, Path: "fast.html", Slow: false},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("expandCTSList() = %+v, want %+v", got, want)
	}
}

func TestExpandCTSListRejectsBadInput(t *testing.T) {
	deepFS := fstest.MapFS{}
	for i := 0; i <= 9; i++ {
		name := fmt.Sprintf("l%d.txt", i)
		next := fmt.Sprintf("l%d.txt\n", i+1)
		if i == 9 {
			next = "leaf.html\n"
		}
		deepFS[name] = &fstest.MapFile{Data: []byte(next)}
	}

	cases := []struct {
		name string
		fsys fstest.MapFS
		root string
	}{
		{
			name: "unknown_option",
			fsys: fstest.MapFS{"00_test_list.txt": {Data: []byte("--bogus page.html\n")}},
			root: "00_test_list.txt",
		},
		{
			name: "missing_nested_file",
			fsys: fstest.MapFS{"00_test_list.txt": {Data: []byte("missing/00_test_list.txt\n")}},
			root: "00_test_list.txt",
		},
		{
			name: "dotdot_escape",
			fsys: fstest.MapFS{"00_test_list.txt": {Data: []byte("../escape.html\n")}},
			root: "00_test_list.txt",
		},
		{
			name: "depth_9",
			fsys: deepFS,
			root: "l0.txt",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := expandCTSList(tc.fsys, tc.root, "2.0.1", 2); err == nil {
				t.Fatalf("expandCTSList(%s) = nil error, want error", tc.name)
			}
		})
	}
}

func TestCTSVersionAtLeast(t *testing.T) {
	cases := []struct {
		have, want string
		expect     bool
	}{
		{"1.2.3", "1.1", true},
		{"1.1.1", "1.1", true},
		{"1.0.9", "1.1", false},
		{"1.1", "1.1.1", false},
		{"2.0.1", "2.0.1", true},
	}
	for _, tc := range cases {
		if got := ctsVersionAtLeast(tc.have, tc.want); got != tc.expect {
			t.Errorf("ctsVersionAtLeast(%q, %q) = %v, want %v", tc.have, tc.want, got, tc.expect)
		}
	}
}

func TestSelectCTSPagesDirectoryGlobExclude(t *testing.T) {
	pages := []ctsPage{
		{WebGL: 1, Path: "conformance/rendering/a.html"},
		{WebGL: 1, Path: "conformance/rendering/b.html"},
		{WebGL: 1, Path: "conformance/extensions/oes-a.html"},
		{WebGL: 1, Path: "conformance/extensions/ext-b.html"},
		{WebGL: 2, Path: "conformance2/sync/s.html"},
	}

	sel, err := parseCTSSubset(strings.NewReader(strings.Join([]string{
		"# comment",
		"1 conformance/rendering/",
		"1 conformance/extensions/oes-*.html",
		"! 1 conformance/rendering/b.html",
		"2 conformance2/sync/",
	}, "\n")))
	if err != nil {
		t.Fatalf("parseCTSSubset() = %v", err)
	}
	got, err := selectCTSPages(pages, sel)
	if err != nil {
		t.Fatalf("selectCTSPages() = %v", err)
	}
	want := []ctsPage{
		{WebGL: 1, Path: "conformance/rendering/a.html"},
		{WebGL: 1, Path: "conformance/extensions/oes-a.html"},
		{WebGL: 2, Path: "conformance2/sync/s.html"},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("selectCTSPages() = %+v, want %+v", got, want)
	}

	unmatched, err := parseCTSSubset(strings.NewReader("1 conformance/no-such-dir/\n"))
	if err != nil {
		t.Fatalf("parseCTSSubset(unmatched) = %v", err)
	}
	if _, err := selectCTSPages(pages, unmatched); err == nil {
		t.Fatal("selectCTSPages(unmatched) = nil error, want error")
	}
}

func TestReadCTSResultsMergesAttempts(t *testing.T) {
	run1 := strings.Join([]string{
		`{"i":0,"attempt":1,"webgl":1,"page":"a.html","status":"fail","passed":1,"failed":2,"ms":500,"start_unix_ms":1000,"device_alive":true}`,
		`{"i":1,"attempt":1,"webgl":1,"page":"b.html","status":"pass","passed":5,"failed":0,"ms":200,"start_unix_ms":2000,"device_alive":true}`,
		`{"i":0,"attempt":2,"webgl":1,"page":"a.html","status":"pass","passed":3,"failed":0,"ms":450,"start_unix_ms":3000,"device_alive":true}`,
		`{"i":2,"attempt":1,"webgl":1,"page":"c.html","status":"pa`,
	}, "\n")

	pages, windows, truncated, err := readCTSResults(strings.NewReader(run1))
	if err != nil {
		t.Fatalf("readCTSResults() = %v", err)
	}
	if truncated != 1 {
		t.Fatalf("truncated = %d, want 1", truncated)
	}
	a := pages["1/a.html"]
	if a == nil || a.Status != ctsPass || !a.Flaky || a.Attempts != 2 || a.Passed != 3 || a.Failed != 0 {
		t.Fatalf("1/a.html = %+v, want pass, flaky, attempts=2", a)
	}
	b := pages["1/b.html"]
	if b == nil || b.Status != ctsPass || b.Flaky || b.Attempts != 1 {
		t.Fatalf("1/b.html = %+v, want pass, not flaky, attempts=1", b)
	}
	if len(windows["1/a.html"]) != 2 {
		t.Fatalf("windows[1/a.html] = %v, want 2 windows", windows["1/a.html"])
	}

	// An interior line with an unknown status fails decoding.
	badStatus := strings.Join([]string{
		`{"i":0,"attempt":1,"webgl":1,"page":"a.html","status":"bogus","ms":10,"device_alive":true}`,
		`{"i":1,"attempt":1,"webgl":1,"page":"b.html","status":"pass","ms":10,"device_alive":true}`,
	}, "\n")
	if _, _, _, err := readCTSResults(strings.NewReader(badStatus)); err == nil {
		t.Fatal("readCTSResults(badStatus) = nil error, want error")
	}

	// A delayed-gpu-process-crash correction overwrites attempt 1 without inflating Attempts.
	delayed := strings.Join([]string{
		`{"i":0,"attempt":1,"webgl":1,"page":"a.html","status":"pass","passed":2,"failed":0,"ms":100,"device_alive":true}`,
		`{"i":0,"attempt":1,"webgl":1,"page":"a.html","status":"crash","reason":"delayed-gpu-process-crash","passed":2,"failed":0,"ms":100,"device_alive":true}`,
	}, "\n")
	dPages, _, _, err := readCTSResults(strings.NewReader(delayed))
	if err != nil {
		t.Fatalf("readCTSResults(delayed) = %v", err)
	}
	if got := dPages["1/a.html"]; got == nil || got.Status != ctsCrash || got.Attempts != 1 {
		t.Fatalf("delayed crash 1/a.html = %+v, want crash with Attempts=1", got)
	}
}

func TestDiffCTSModesKinds(t *testing.T) {
	ref := map[string]*ctsRecordPage{
		"1/pass-pass.html":     {Status: ctsPass},
		"1/reg-fail.html":      {Status: ctsPass},
		"1/reg-soft.html":      {Status: ctsPass},
		"1/reg-fail-soft.html": {Status: ctsPass},
		"2/deg-fail-to.html":   {Status: ctsFail},
		"2/deg-to-crash.html":  {Status: ctsTimeout},
		"2/deg-crash-err.html": {Status: ctsCrash},
		"2/deg-err-nr.html":    {Status: ctsError},
		"2/to-to-fail.html":    {Status: ctsTimeout},
		"2/imp-pass.html":      {Status: ctsFail},
		"2/both-fail.html":     {Status: ctsFail},
	}
	gpu := map[string]*ctsRecordPage{
		"1/pass-pass.html":     {Status: ctsPass},
		"1/reg-fail.html":      {Status: ctsFail, Failed: 2},
		"1/reg-soft.html":      {Status: ctsPass, SoftwareRender: true},
		"1/reg-fail-soft.html": {Status: ctsFail, Failed: 1, SoftwareRender: true},
		"2/deg-fail-to.html":   {Status: ctsTimeout, Reason: "idle"},
		"2/deg-to-crash.html":  {Status: ctsCrash, Reason: "gpu-process-crash"},
		"2/deg-crash-err.html": {Status: ctsError, Reason: "driver"},
		"2/deg-err-nr.html":    {Status: ctsNotRun, Reason: "not-run"},
		"2/to-to-fail.html":    {Status: ctsFail, Failed: 1},
		"2/imp-pass.html":      {Status: ctsPass},
		"2/both-fail.html":     {Status: ctsFail, Failed: 1},
	}
	got := diffCTSModes("virgl", ref, gpu)
	if len(got) != 8 {
		t.Fatalf("diffCTSModes() returned %d deltas (%+v), want 8", len(got), got)
	}
	byID := map[string]ctsDelta{}
	for _, d := range got {
		byID[d.ID] = d
	}
	if d := byID["1/reg-fail.html"]; d.Kind != "regression" || d.Status != ctsFail {
		t.Errorf("1/reg-fail.html = %+v, want regression/fail", d)
	}
	if d := byID["1/reg-soft.html"]; d.Kind != "regression" || d.Status != ctsSoftware || !d.SoftwareRender {
		t.Errorf("1/reg-soft.html = %+v, want regression/software", d)
	}
	if d := byID["1/reg-fail-soft.html"]; d.Kind != "regression" || d.Status != ctsFail || !d.SoftwareRender {
		t.Errorf("1/reg-fail-soft.html = %+v, want regression/fail+software", d)
	}
	for _, tc := range []struct {
		id     string
		status ctsStatus
	}{
		{"2/deg-fail-to.html", ctsTimeout},
		{"2/deg-to-crash.html", ctsCrash},
		{"2/deg-crash-err.html", ctsError},
		{"2/deg-err-nr.html", ctsNotRun},
	} {
		if d := byID[tc.id]; d.Kind != "degradation" || d.Status != tc.status {
			t.Errorf("%s = %+v, want degradation/%s", tc.id, d, tc.status)
		}
	}
	if _, exists := byID["2/to-to-fail.html"]; exists {
		t.Errorf("2/to-to-fail.html unexpectedly produced a delta: %+v", byID["2/to-to-fail.html"])
	}
	if d := byID["2/imp-pass.html"]; d.Kind != "improvement" || d.Status != ctsPass {
		t.Errorf("2/imp-pass.html = %+v, want improvement/pass", d)
	}
}

func TestParseCTSExpectations(t *testing.T) {
	valid := strings.Join([]string{
		"# header comment",
		"* 2 conformance2/sync/sync-webgl-specific.html timeout # host sync limit",
		"virgl * conformance/extensions/ fail,crash # driver limit",
		"swiftshader 1 conformance/foo-*.html any # known upstream",
		"venus 2 conformance2/soft.html software # software fallback test",
	}, "\n")
	exps, err := parseCTSExpectations(strings.NewReader(valid))
	if err != nil {
		t.Fatalf("parseCTSExpectations(valid) = %v", err)
	}
	if len(exps) != 4 {
		t.Fatalf("len(exps) = %d, want 4", len(exps))
	}
	if exps[0].Mode != "*" || exps[0].WebGL != 2 || exps[0].Reason != "host sync limit" {
		t.Errorf("exps[0] = %+v", exps[0])
	}
	if exps[1].WebGL != 0 || !slices.Equal(exps[1].Statuses, []ctsStatus{ctsFail, ctsCrash}) {
		t.Errorf("exps[1] = %+v", exps[1])
	}

	invalid := []struct {
		name string
		line string
	}{
		{"missing_reason", "virgl 1 a.html fail"},
		{"empty_reason", "virgl 1 a.html fail #   "},
		{"unknown_mode", "opengl 1 a.html fail # reason"},
		{"unknown_webgl", "virgl 3 a.html fail # reason"},
		{"unknown_status", "virgl 1 a.html bogus # reason"},
		{"missing_pattern", "virgl 1 fail # reason"},
		{"bad_glob", "virgl 1 [unclosed fail # reason"},
	}
	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseCTSExpectations(strings.NewReader(tc.line + "\n")); err == nil {
				t.Fatalf("parseCTSExpectations(%q) = nil error, want error", tc.line)
			}
		})
	}
}

func TestMatchCTSExpectation(t *testing.T) {
	exps, err := parseCTSExpectations(strings.NewReader(strings.Join([]string{
		"virgl * conformance/extensions/khr-*.html fail,timeout # first match",
		"* * conformance/extensions/ any # catch-all gpu",
		"swiftshader 1 conformance/extensions/sw.html fail # explicit swiftshader",
		"venus 2 conformance2/soft.html software # software only",
		"venus 2 conformance2/fail-soft.html fail,software # fail and software",
		"venus 2 conformance2/any-soft.html any,software # any and software",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}

	d1 := ctsDelta{ID: "1/conformance/extensions/khr-parallel.html", Mode: "virgl", Status: ctsFail}
	if got := matchCTSExpectation(exps, d1); got == nil || got.Reason != "first match" {
		t.Fatalf("match(d1) = %+v, want first match", got)
	}

	d2 := ctsDelta{ID: "2/conformance/extensions/oes.html", Mode: "venus", Status: ctsCrash}
	if got := matchCTSExpectation(exps, d2); got == nil || got.Reason != "catch-all gpu" {
		t.Fatalf("match(d2) = %+v, want catch-all gpu", got)
	}

	// Mode "*" never matches swiftshader; an explicit swiftshader line does.
	dSWWildcard := ctsDelta{ID: "1/conformance/extensions/oes.html", Mode: "swiftshader", Status: ctsFail}
	if got := matchCTSExpectation(exps, dSWWildcard); got != nil {
		t.Fatalf("match(dSWWildcard) = %+v, want nil", got)
	}
	dSWExplicit := ctsDelta{ID: "1/conformance/extensions/sw.html", Mode: "swiftshader", Status: ctsFail}
	if got := matchCTSExpectation(exps, dSWExplicit); got == nil || got.Reason != "explicit swiftshader" {
		t.Fatalf("match(dSWExplicit) = %+v, want explicit swiftshader", got)
	}

	// Software renderer fallback requires an explicit software expectation; "any" alone does not hide it.
	dSoftAny := ctsDelta{ID: "1/conformance/extensions/khr-parallel.html", Mode: "venus", Status: ctsSoftware, SoftwareRender: true}
	if got := matchCTSExpectation(exps, dSoftAny); got != nil {
		t.Fatalf("match(dSoftAny) = %+v, want nil", got)
	}
	dSoftExplicit := ctsDelta{ID: "2/conformance2/soft.html", Mode: "venus", Status: ctsSoftware, SoftwareRender: true}
	if got := matchCTSExpectation(exps, dSoftExplicit); got == nil || got.Reason != "software only" {
		t.Fatalf("match(dSoftExplicit) = %+v, want software only", got)
	}

	// A software-only expectation must not hide a fail/crash/timeout on that page.
	dFailSoftUnmatched := ctsDelta{ID: "2/conformance2/soft.html", Mode: "venus", Status: ctsFail, SoftwareRender: true}
	if got := matchCTSExpectation(exps, dFailSoftUnmatched); got != nil {
		t.Fatalf("match(dFailSoftUnmatched) = %+v, want nil", got)
	}
	dFailSoftMatched := ctsDelta{ID: "2/conformance2/fail-soft.html", Mode: "venus", Status: ctsFail, SoftwareRender: true}
	if got := matchCTSExpectation(exps, dFailSoftMatched); got == nil || got.Reason != "fail and software" {
		t.Fatalf("match(dFailSoftMatched) = %+v, want fail and software", got)
	}
	dCrashAnySoft := ctsDelta{ID: "2/conformance2/any-soft.html", Mode: "venus", Status: ctsCrash, SoftwareRender: true}
	if got := matchCTSExpectation(exps, dCrashAnySoft); got == nil || got.Reason != "any and software" {
		t.Fatalf("match(dCrashAnySoft) = %+v, want any and software", got)
	}
}

func TestPlaceCTSHostEvents(t *testing.T) {
	loc := time.UTC
	t1 := time.Date(2026, 11, 22, 3, 46, 20, 0, loc).UnixMilli()
	t2 := time.Date(2026, 11, 22, 3, 46, 30, 0, loc).UnixMilli()
	pages := map[string]*ctsRecordPage{
		"1/a.html": {Status: ctsPass},
		"2/b.html": {Status: ctsCrash},
	}
	windows := map[string][][2]int64{
		"1/a.html": {{t1, t1 + 2000}},
		"2/b.html": {{t2, t2 + 2000}},
	}
	logText := strings.Join([]string{
		"I1122 03:46:21.500000    100 events.go:50] virtgpu: context 3 lost",
		"I1122 03:46:25.000000    100 events.go:50] virtgpu: context 4 lost",
		"W1122 03:46:31.100000    100 events.go:67] virtgpu: renderer lost: broken pipe",
		"W1122 03:46:31.200000    100 events.go:67] virtgpu: renderer lost: gpurender: client closed",
	}, "\n")

	unplaced := placeHostEvents(logText, 2026, loc, pages, windows)
	if len(pages["1/a.html"].HostEvents) != 1 || !strings.Contains(pages["1/a.html"].HostEvents[0], "context 3 lost") {
		t.Errorf("1/a.html HostEvents = %v, want context 3 lost", pages["1/a.html"].HostEvents)
	}
	if len(pages["2/b.html"].HostEvents) != 1 || !strings.Contains(pages["2/b.html"].HostEvents[0], "renderer lost: broken pipe") {
		t.Errorf("2/b.html HostEvents = %v, want renderer lost", pages["2/b.html"].HostEvents)
	}
	if len(unplaced) != 1 || !strings.Contains(unplaced[0], "context 4 lost") {
		t.Errorf("unplaced = %v, want [context 4 lost]", unplaced)
	}
}

func TestWriteCTSCandidatesProducesValidExpectations(t *testing.T) {
	deltas := []ctsDelta{
		{ID: "2/conformance2/rendering/a.html", Mode: "virgl", Status: ctsFail, Kind: "regression", Messages: []string{"line1\nline2"}},
		{ID: "1/conformance/b.html", Mode: "venus", Status: ctsSoftware, SoftwareRender: true, Kind: "regression"},
		{ID: "2/conformance2/d.html", Mode: "venus", Status: ctsFail, SoftwareRender: true, Kind: "regression"},
		{ID: "1/conformance/c.html", Mode: "virgl", Status: ctsFail, Kind: "regression", Expected: "already listed"},
	}
	var buf bytes.Buffer
	if err := writeCTSCandidates(&buf, deltas); err != nil {
		t.Fatalf("writeCTSCandidates() = %v", err)
	}
	exps, err := parseCTSExpectations(&buf)
	if err != nil {
		t.Fatalf("parseCTSExpectations(candidates) = %v", err)
	}
	if len(exps) != 3 {
		t.Fatalf("len(exps) = %d, want 3", len(exps))
	}
	if exps[0].Reason != "TODO" || !slices.Equal(exps[1].Statuses, []ctsStatus{ctsSoftware}) || !slices.Equal(exps[2].Statuses, []ctsStatus{ctsFail, ctsSoftware}) {
		t.Errorf("unexpected parsed candidates: %+v", exps)
	}
	if got := matchCTSExpectation(exps, deltas[2]); got == nil {
		t.Errorf("generated candidate did not match fail+software delta %+v", deltas[2])
	}
}

func TestValidateCTSModeRenderers(t *testing.T) {
	venusStr := "ANGLE (Apple, Vulkan 1.4.307 (Virtio-GPU Venus (Apple M1 Ultra) (0x00000064)), venus)"
	virglStr := "ANGLE (Mesa, virgl (Apple M1 Ultra), OpenGL ES 3.0)"
	swStr := "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver)"

	for _, tc := range []struct {
		name      string
		mode      string
		renderers []string
		wantOK    bool
	}{
		{"venus_empty", "venus", nil, false},
		{"virgl_empty", "virgl", nil, false},
		{"swiftshader_empty", "swiftshader", nil, false},
		{"venus_valid", "venus", []string{venusStr}, true},
		{"venus_only_software", "venus", []string{swStr}, false},
		{"venus_mixed_with_software_fallback", "venus", []string{swStr, venusStr}, true},
		{"venus_wrong_gpu_backend", "venus", []string{venusStr, virglStr}, false},
		{"virgl_valid", "virgl", []string{virglStr}, true},
		{"virgl_only_software", "virgl", []string{swStr}, false},
		{"virgl_mixed_with_software_fallback", "virgl", []string{swStr, virglStr}, true},
		{"virgl_wrong_gpu_backend", "virgl", []string{virglStr, venusStr}, false},
		{"swiftshader_valid", "swiftshader", []string{swStr}, true},
		{"swiftshader_with_gpu", "swiftshader", []string{swStr, venusStr}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var msgs []string
			ok := validateModeRenderers(tc.mode, tc.renderers, func(format string, args ...any) {
				msgs = append(msgs, fmt.Sprintf(format, args...))
			})
			if ok != tc.wantOK {
				t.Errorf("validateModeRenderers(%s) = %v (msgs %v), want %v", tc.mode, ok, msgs, tc.wantOK)
			}
		})
	}

	// Verify Go-side software-renderer marking and non-software summary selection.
	pages := map[string]*ctsRecordPage{
		"1/a.html": {Status: ctsPass, Renderers: []string{swStr}},
		"1/b.html": {Status: ctsPass, Renderers: []string{venusStr}},
	}
	markCTSSoftwareRenderers("venus", pages)
	if !pages["1/a.html"].SoftwareRender || pages["1/b.html"].SoftwareRender {
		t.Errorf("markCTSSoftwareRenderers = (a:%v, b:%v), want (true, false)", pages["1/a.html"].SoftwareRender, pages["1/b.html"].SoftwareRender)
	}
	if got := pickCTSModeRenderer("venus", collectCTSRenderers(pages)); got != venusStr {
		t.Errorf("pickCTSModeRenderer(venus) = %q, want %q", got, venusStr)
	}
}

func TestCTSResumeQueuesUnseenAndUnretriedPages(t *testing.T) {
	pages := []ctsPage{
		{WebGL: 1, Path: "pass.html"},
		{WebGL: 1, Path: "fail-once.html", Slow: true},
		{WebGL: 1, Path: "fail-twice.html"},
		{WebGL: 2, Path: "unseen.html"},
	}
	seen := map[string]*ctsRecordPage{
		"1/pass.html":       {Status: ctsPass, Attempts: 1},
		"1/fail-once.html":  {Status: ctsFail, Attempts: 1},
		"1/fail-twice.html": {Status: ctsFail, Attempts: 2},
	}

	got := ctsRemainingPages(pages, seen, true)
	want := []ctsPage{
		{WebGL: 1, Path: "fail-once.html", Slow: true, Retry: true},
		{WebGL: 2, Path: "unseen.html", Retry: false},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ctsRemainingPages() = %+v, want %+v", got, want)
	}

	var buf bytes.Buffer
	if err := writeCTSRunList(&buf, got); err != nil {
		t.Fatal(err)
	}
	wantList := "1 fail-once.html slow retry\n2 unseen.html\n"
	if buf.String() != wantList {
		t.Fatalf("writeCTSRunList() = %q, want %q", buf.String(), wantList)
	}

	if ctsRunFinishedCleanly(gpuRunResult{code: 0, stdout: "GVX-CTS done\nGVX-CTS abort=crash-run\n"}) {
		t.Error("ctsRunFinishedCleanly accepted abort line")
	}
	if ctsRunFinishedCleanly(gpuRunResult{code: 1, stdout: "GVX-CTS done\n"}) {
		t.Error("ctsRunFinishedCleanly accepted non-zero exit code")
	}
	if !ctsRunFinishedCleanly(gpuRunResult{code: 0, stdout: "GVX-CTS done\n"}) {
		t.Error("ctsRunFinishedCleanly rejected clean run")
	}
}

func TestFindStaleCTSExpectations(t *testing.T) {
	exps, err := parseCTSExpectations(strings.NewReader(strings.Join([]string{
		"venus 1 conformance/a.html fail # matched in run",
		"venus 1 conformance/b.html fail # selected and unmatched",
		"venus 2 conformance2/outside.html fail # not in selected pages",
		"virgl 1 conformance/b.html fail # mode did not run",
		"* 1 conformance/b.html fail # wildcard gpu matched selected",
	}, "\n")))
	if err != nil {
		t.Fatal(err)
	}
	used := []bool{true, false, false, false, false}
	ranModes := map[string]bool{"swiftshader": true, "venus": true}
	selected := []ctsPage{
		{WebGL: 1, Path: "conformance/a.html"},
		{WebGL: 1, Path: "conformance/b.html"},
	}

	got := findStaleCTSExpectations(exps, used, ranModes, selected)
	if len(got) != 2 {
		t.Fatalf("findStaleCTSExpectations() = %v, want 2 entries", got)
	}
	if !strings.HasPrefix(got[0], "line 2:") || !strings.HasPrefix(got[1], "line 5:") {
		t.Errorf("findStaleCTSExpectations() = %v, want lines 2 and 5", got)
	}
}

func TestExpandCTSListPinnedCounts(t *testing.T) {
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		t.Skip("WebGL CTS fetch is off (GVX_E2E_OFFLINE=1)")
	}
	cts := acceptprog.FetchWebGLCTS(t)
	fsys := os.DirFS(cts)

	w1, err := expandCTSList(fsys, "00_test_list.txt", webglCTSVersion1, 1)
	if err != nil {
		t.Fatalf("expandCTSList(1.0.4) = %v", err)
	}
	if len(w1) != 971 {
		t.Errorf("WebGL 1 page count = %d, want 971", len(w1))
	}

	w2, err := expandCTSList(fsys, "00_test_list.txt", webglCTSVersion2, 2)
	if err != nil {
		t.Fatalf("expandCTSList(2.0.1) = %v", err)
	}
	if len(w2) != 2865 {
		t.Errorf("WebGL 2 page count = %d, want 2865", len(w2))
	}

	subsetBytes, err := gpuAssets.ReadFile("testdata/gpu/webgl-cts-subset.txt")
	if err != nil {
		t.Fatalf("read webgl-cts-subset.txt: %v", err)
	}
	sel, err := parseCTSSubset(bytes.NewReader(subsetBytes))
	if err != nil {
		t.Fatalf("parseCTSSubset() = %v", err)
	}
	all := append(append([]ctsPage(nil), w1...), w2...)
	selected, err := selectCTSPages(all, sel)
	if err != nil {
		t.Fatalf("selectCTSPages() = %v", err)
	}
	t.Logf("pinned CTS counts: webgl1=%d webgl2=%d subset=%d", len(w1), len(w2), len(selected))
	if len(selected) != 1009 {
		t.Errorf("subset page count = %d, want 1009", len(selected))
	}
}

func TestMergeCTSRunsDeviceAliveAndProtectsRetry(t *testing.T) {
	lossLine := "virtgpu: renderer lost: gpuproto: GPU renderer lost: renderer exited: killed by signal abort trap"
	run1 := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"pass.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"pass.html","status":"pass","passed":5,"failed":0,"ms":500,"start_unix_ms":1000,"renderers":["Virtio-GPU Venus"],"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"pre-crash.html","start_unix_ms":2000}`,
		`{"i":1,"attempt":1,"webgl":2,"page":"pre-crash.html","status":"crash","reason":"gpu-process-crash","passed":1,"failed":0,"ms":800,"start_unix_ms":2000,"renderers":["Virtio-GPU Venus"],"device_alive":true}`,
		`{"i":2,"attempt":1,"webgl":2,"page":"legacy-missing-field.html","status":"pass","passed":2,"failed":0,"ms":100,"start_unix_ms":3000}`,
		`{"i":3,"attempt":1,"webgl":2,"page":"probe-err.html","status":"pass","passed":2,"failed":0,"ms":100,"start_unix_ms":3500,"device_alive":false}`,
		`{"kind":"start","i":1,"attempt":2,"webgl":2,"page":"pre-crash.html","start_unix_ms":4000}`,
		`{"i":1,"attempt":2,"webgl":2,"page":"pre-crash.html","status":"fail","passed":0,"failed":3,"ms":400,"start_unix_ms":4000,"device_alive":false}`,
		`{"kind":"start","i":4,"attempt":1,"webgl":2,"page":"killer.html","start_unix_ms":5000}`,
		`{"i":4,"attempt":1,"webgl":2,"page":"killer.html","status":"crash","reason":"gpu-process-crash","passed":10,"failed":4,"ms":4000,"start_unix_ms":5000,"renderers":["Virtio-GPU Venus"],"device_alive":false,"renderer_lost":true}`,
	}, "\n")

	out1, err := mergeCTSRuns([]ctsRunInput{{
		Results:       strings.NewReader(run1),
		RendererLost:  true,
		LossEventLine: lossLine,
	}})
	if err != nil {
		t.Fatalf("mergeCTSRuns(run1) = %v", err)
	}
	if out1.Invalidated != 4 {
		t.Fatalf("Invalidated = %d, want 4 (legacy, probe-err, invalid retry, killer raw)", out1.Invalidated)
	}
	if len(out1.UnattributedLosses) != 0 {
		t.Fatalf("UnattributedLosses = %v, want empty", out1.UnattributedLosses)
	}
	if !slices.Equal(out1.LossPages, []string{"2/killer.html"}) {
		t.Fatalf("LossPages = %v, want [2/killer.html]", out1.LossPages)
	}
	if got := out1.Pages["2/pass.html"]; got == nil || got.Status != ctsPass || got.Attempts != 1 {
		t.Errorf("2/pass.html = %+v, want pass with 1 attempt", got)
	}
	// An invalid retry must preserve the valid attempt 1 record.
	if got := out1.Pages["2/pre-crash.html"]; got == nil || got.Status != ctsCrash || got.Reason != "gpu-process-crash" || got.Attempts != 1 {
		t.Errorf("2/pre-crash.html = %+v, want attempt-1 gpu-process-crash preserved", got)
	}
	if got := out1.Pages["2/killer.html"]; got == nil || got.Status != ctsCrash || got.Reason != "renderer-lost" || got.Attempts != 1 || len(got.HostEvents) != 1 || got.HostEvents[0] != lossLine {
		t.Errorf("2/killer.html = %+v, want crash/renderer-lost with loss host event", got)
	}
	for _, dropped := range []string{"2/legacy-missing-field.html", "2/probe-err.html"} {
		if _, ok := out1.Pages[dropped]; ok {
			t.Errorf("%s stayed in merged map, want dropped", dropped)
		}
	}
	if !out1.PlacedEvents[lossLine] {
		t.Errorf("PlacedEvents missing lossLine %q", lossLine)
	}

	// Merge run2 on a fresh sandbox and verify flaky retry and valid passes.
	run2 := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"legacy-missing-field.html","start_unix_ms":20000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"legacy-missing-field.html","status":"pass","passed":2,"failed":0,"ms":300,"start_unix_ms":20000,"renderers":["Virtio-GPU Venus"],"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"probe-err.html","start_unix_ms":20500}`,
		`{"i":1,"attempt":1,"webgl":2,"page":"probe-err.html","status":"pass","passed":8,"failed":0,"ms":300,"start_unix_ms":20500,"renderers":["Virtio-GPU Venus"],"device_alive":true}`,
		`{"kind":"start","i":2,"attempt":2,"webgl":2,"page":"pre-crash.html","start_unix_ms":21000}`,
		`{"i":2,"attempt":2,"webgl":2,"page":"pre-crash.html","status":"pass","passed":5,"failed":0,"ms":300,"start_unix_ms":21000,"renderers":["Virtio-GPU Venus"],"device_alive":true}`,
	}, "\n")
	out2, err := mergeCTSRuns([]ctsRunInput{
		{Results: strings.NewReader(run1), RendererLost: true, LossEventLine: lossLine},
		{Results: strings.NewReader(run2)},
	})
	if err != nil {
		t.Fatalf("mergeCTSRuns(run1+run2) = %v", err)
	}
	for _, id := range []string{"2/pass.html", "2/legacy-missing-field.html", "2/probe-err.html"} {
		if got := out2.Pages[id]; got == nil || got.Status != ctsPass || got.SoftwareRender {
			t.Errorf("%s = %+v, want valid hardware pass", id, got)
		}
	}
	if got := out2.Pages["2/pre-crash.html"]; got == nil || got.Status != ctsPass || !got.Flaky || got.Attempts != 2 {
		t.Errorf("2/pre-crash.html = %+v, want pass, flaky, attempts=2", got)
	}
	if got := out2.Pages["2/killer.html"]; got == nil || got.Status != ctsCrash || got.Reason != "renderer-lost" {
		t.Errorf("2/killer.html = %+v, want crash/renderer-lost preserved after run2", got)
	}
}

func TestMergeCTSRunsInFlightStart(t *testing.T) {
	pages := []ctsPage{
		{WebGL: 2, Path: "ok.html"},
		{WebGL: 2, Path: "hung.html"},
		{WebGL: 2, Path: "next.html"},
	}

	// An unmatched start line during a host renderer loss becomes crash/renderer-lost.
	lossLine := "virtgpu: renderer lost: killed by signal segmentation fault"
	withLoss := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"ok.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"ok.html","status":"pass","passed":3,"failed":0,"ms":200,"start_unix_ms":1000,"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"hung.html","start_unix_ms":2000}`,
		`{"i":1,"attempt":1,"webgl":2,"page":"hung.html","status":"cr`,
	}, "\n")
	outLoss, err := mergeCTSRuns([]ctsRunInput{{
		Results:       strings.NewReader(withLoss),
		RendererLost:  true,
		LossEventLine: lossLine,
	}})
	if err != nil {
		t.Fatalf("mergeCTSRuns(withLoss) = %v", err)
	}
	if outLoss.Truncated != 1 {
		t.Errorf("Truncated = %d, want 1", outLoss.Truncated)
	}
	if len(outLoss.UnattributedLosses) != 0 {
		t.Errorf("UnattributedLosses = %v, want empty", outLoss.UnattributedLosses)
	}
	if got := outLoss.Pages["2/hung.html"]; got == nil || got.Status != ctsCrash || got.Reason != "renderer-lost" || len(got.HostEvents) != 1 || got.HostEvents[0] != lossLine {
		t.Fatalf("2/hung.html = %+v, want crash/renderer-lost with loss host event", got)
	}
	remLoss := ctsRemainingPages(pages, outLoss.Pages, true)
	wantRemLoss := []ctsPage{{WebGL: 2, Path: "next.html", Retry: false}}
	if !slices.Equal(remLoss, wantRemLoss) {
		t.Errorf("ctsRemainingPages(withLoss) = %+v, want %+v", remLoss, wantRemLoss)
	}

	// Without a host renderer loss, an unmatched start line becomes timeout with one retry.
	withoutLoss := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"ok.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"ok.html","status":"pass","passed":3,"failed":0,"ms":200,"start_unix_ms":1000,"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"hung.html","start_unix_ms":2000}`,
	}, "\n")
	outTimeout, err := mergeCTSRuns([]ctsRunInput{{Results: strings.NewReader(withoutLoss)}})
	if err != nil {
		t.Fatalf("mergeCTSRuns(withoutLoss) = %v", err)
	}
	if got := outTimeout.Pages["2/hung.html"]; got == nil || got.Status != ctsTimeout || got.Reason != "in-flight" || got.Attempts != 1 {
		t.Fatalf("2/hung.html = %+v, want timeout/in-flight attempts=1", got)
	}
	remTimeout := ctsRemainingPages(pages, outTimeout.Pages, true)
	wantRemTimeout := []ctsPage{
		{WebGL: 2, Path: "hung.html", Retry: true},
		{WebGL: 2, Path: "next.html", Retry: false},
	}
	if !slices.Equal(remTimeout, wantRemTimeout) {
		t.Errorf("ctsRemainingPages(withoutLoss) = %+v, want %+v", remTimeout, wantRemTimeout)
	}

	// A second in-flight timeout exhausts retries.
	retryHang := `{"kind":"start","i":0,"attempt":2,"webgl":2,"page":"hung.html","start_unix_ms":5000}` + "\n"
	outSecond, err := mergeCTSRuns([]ctsRunInput{
		{Results: strings.NewReader(withoutLoss)},
		{Results: strings.NewReader(retryHang)},
	})
	if err != nil {
		t.Fatalf("mergeCTSRuns(retryHang) = %v", err)
	}
	if got := outSecond.Pages["2/hung.html"]; got == nil || got.Status != ctsTimeout || got.Attempts != 2 {
		t.Fatalf("2/hung.html after retry hang = %+v, want timeout attempts=2", got)
	}
	remSecond := ctsRemainingPages(pages, outSecond.Pages, true)
	if !slices.Equal(remSecond, []ctsPage{{WebGL: 2, Path: "next.html", Retry: false}}) {
		t.Errorf("ctsRemainingPages(retryHang) = %+v, want only next.html", remSecond)
	}
}

func TestMergeCTSRunsFailClosedUnattributedLoss(t *testing.T) {
	// Sentry reports renderer loss, but no record has renderer_lost and no start
	// line stays open. The merger keeps device_alive=true records and flags the run.
	run1 := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"alive.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"alive.html","status":"pass","passed":4,"failed":0,"ms":300,"start_unix_ms":1000,"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"dead.html","start_unix_ms":2000}`,
		`{"i":1,"attempt":1,"webgl":2,"page":"dead.html","status":"fail","passed":0,"failed":1,"ms":200,"start_unix_ms":2000,"device_alive":false}`,
	}, "\n")
	out, err := mergeCTSRuns([]ctsRunInput{{
		Results:       strings.NewReader(run1),
		RendererLost:  true,
		LossEventLine: "virtgpu: renderer lost: broken pipe",
	}})
	if err != nil {
		t.Fatalf("mergeCTSRuns() = %v", err)
	}
	if !slices.Equal(out.UnattributedLosses, []int{1}) {
		t.Fatalf("UnattributedLosses = %v, want [1]", out.UnattributedLosses)
	}
	if got := out.Pages["2/alive.html"]; got == nil || got.Status != ctsPass {
		t.Errorf("2/alive.html = %+v, want valid pass preserved", got)
	}
	if _, ok := out.Pages["2/dead.html"]; ok {
		t.Errorf("2/dead.html stayed in merged map, want dropped")
	}
}

func TestCTSResumeAfterRendererLoss(t *testing.T) {
	pages := []ctsPage{
		{WebGL: 2, Path: "pass.html"},
		{WebGL: 2, Path: "pre-fail.html", Slow: true},
		{WebGL: 2, Path: "killer.html"},
		{WebGL: 2, Path: "unrun.html"},
	}
	run1 := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"pass.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"pass.html","status":"pass","passed":3,"failed":0,"ms":400,"start_unix_ms":1000,"device_alive":true}`,
		`{"kind":"start","i":1,"attempt":1,"webgl":2,"page":"pre-fail.html","start_unix_ms":2000}`,
		`{"i":1,"attempt":1,"webgl":2,"page":"pre-fail.html","status":"fail","passed":1,"failed":1,"ms":400,"start_unix_ms":2000,"device_alive":true}`,
		`{"kind":"start","i":2,"attempt":1,"webgl":2,"page":"killer.html","start_unix_ms":3000}`,
		`{"i":2,"attempt":1,"webgl":2,"page":"killer.html","status":"crash","reason":"gpu-process-crash","passed":2,"failed":1,"ms":1500,"start_unix_ms":3000,"device_alive":false,"renderer_lost":true}`,
	}, "\n")
	out, err := mergeCTSRuns([]ctsRunInput{{
		Results:       strings.NewReader(run1),
		RendererLost:  true,
		LossEventLine: "virtgpu: renderer lost: abort",
	}})
	if err != nil {
		t.Fatalf("mergeCTSRuns() = %v", err)
	}
	got := ctsRemainingPages(pages, out.Pages, true)
	want := []ctsPage{
		{WebGL: 2, Path: "pre-fail.html", Slow: true, Retry: true},
		{WebGL: 2, Path: "unrun.html", Retry: false},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("ctsRemainingPages() = %+v, want %+v", got, want)
	}
}

func TestParseCTSAbortReason(t *testing.T) {
	cases := []struct {
		name   string
		stdout string
		want   string
	}{
		{"none", "GVX-CTS mode=venus\nGVX-CTS done\n", ""},
		{"crash_run", "GVX-CTS mode=venus\nGVX-CTS abort=crash-run\n", "crash-run"},
		{"renderer_lost", "GVX-CTS mode=venus\nGVX-CTS abort=renderer-lost\n", "renderer-lost"},
		{"device_dead_at_start", "GVX-CTS mode=venus\nGVX-CTS abort=device-dead-at-start\n", "device-dead-at-start"},
		{"probe_error", "GVX-CTS mode=venus\nGVX-CTS abort=probe-error\n", "probe-error"},
		{"launch_failed", "GVX-CTS error=\"launch failed\"\nGVX-CTS abort=launch-failed\n", "launch-failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseCTSAbortReason(tc.stdout); got != tc.want {
				t.Errorf("parseCTSAbortReason() = %q, want %q", got, tc.want)
			}
		})
	}
	for _, reason := range []string{"renderer-lost", "device-dead-at-start", "probe-error"} {
		if ctsRunFinishedCleanly(gpuRunResult{code: 0, stdout: "GVX-CTS done\nGVX-CTS abort=" + reason + "\n"}) {
			t.Errorf("ctsRunFinishedCleanly accepted abort=%s", reason)
		}
		if ctsRunFinishedCleanly(gpuRunResult{code: 1, stdout: "GVX-CTS abort=" + reason + "\n"}) {
			t.Errorf("ctsRunFinishedCleanly accepted non-zero exit with abort=%s", reason)
		}
	}
}

func TestCTSPlaceHostEventsSkipsProbeAttributedLoss(t *testing.T) {
	lossLine := "virtgpu: renderer lost: gpuproto: GPU renderer lost: killed by signal abort trap"
	logText := strings.Join([]string{
		"I1122 03:46:21.500000    100 events.go:50] virtgpu: context 3 lost",
		lossLine,
		"virtgpu: renderer lost: gpuproto: GPU renderer lost: gpurender: client closed",
	}, "\n")

	t1 := time.Date(2026, 11, 22, 3, 46, 20, 0, time.UTC).UnixMilli()
	pages := map[string]*ctsRecordPage{
		"2/a.html": {Status: ctsPass},
		"2/b.html": {Status: ctsCrash, Reason: "renderer-lost", HostEvents: []string{lossLine}},
	}
	windows := map[string][][2]int64{
		"2/a.html": {{t1, t1 + 2000}},
	}
	unplaced := placeHostEventsSkip(logText, 2026, time.UTC, pages, windows, map[string]bool{lossLine: true})
	if len(unplaced) != 0 {
		t.Errorf("unplaced = %v, want empty", unplaced)
	}
	if len(pages["2/a.html"].HostEvents) != 1 || !strings.Contains(pages["2/a.html"].HostEvents[0], "context 3 lost") {
		t.Errorf("2/a.html HostEvents = %v, want context 3 lost", pages["2/a.html"].HostEvents)
	}
}

func TestMergeCTSRunsDelayedLossCorrectionKeepsAttempts(t *testing.T) {
	// Page P passes its post-page probe, then the renderer dies before page Q.
	// The pre-Q probe emits a delayed-gpu-process-crash correction with
	// renderer_lost=true for P without writing Q's start line.
	run1 := strings.Join([]string{
		`{"kind":"start","i":0,"attempt":1,"webgl":2,"page":"p.html","start_unix_ms":1000}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"p.html","status":"pass","passed":5,"failed":0,"ms":400,"start_unix_ms":1000,"device_alive":true}`,
		`{"i":0,"attempt":1,"webgl":2,"page":"p.html","status":"crash","reason":"delayed-gpu-process-crash","passed":5,"failed":0,"ms":400,"start_unix_ms":1000,"device_alive":false,"renderer_lost":true}`,
	}, "\n")
	out, err := mergeCTSRuns([]ctsRunInput{{Results: strings.NewReader(run1)}})
	if err != nil {
		t.Fatalf("mergeCTSRuns() = %v", err)
	}
	if !slices.Equal(out.LossPages, []string{"2/p.html"}) {
		t.Fatalf("LossPages = %v, want [2/p.html]", out.LossPages)
	}
	got := out.Pages["2/p.html"]
	if got == nil || got.Status != ctsCrash || got.Reason != "renderer-lost" || got.Attempts != 1 {
		t.Fatalf("2/p.html = %+v, want crash/renderer-lost with Attempts=1", got)
	}
	pages := []ctsPage{{WebGL: 2, Path: "p.html"}, {WebGL: 2, Path: "q.html"}}
	rem := ctsRemainingPages(pages, out.Pages, true)
	if !slices.Equal(rem, []ctsPage{{WebGL: 2, Path: "q.html", Retry: false}}) {
		t.Fatalf("ctsRemainingPages() = %+v, want only q.html", rem)
	}
}

func TestCTSDeviceProbeBuildsForLinuxArches(t *testing.T) {
	for _, arch := range []string{"arm64", "amd64"} {
		t.Run(arch, func(t *testing.T) {
			dir := ctsDeviceProbeDir(t, arch)
			binPath := dir + "/gvx-gpu-probe"
			data, err := os.ReadFile(binPath)
			if err != nil {
				t.Fatalf("read %s: %v", binPath, err)
			}
			if len(data) < 4 || string(data[:4]) != "\x7fELF" {
				t.Fatalf("%s is not an ELF binary (len=%d)", binPath, len(data))
			}
		})
	}
}

// TestCTSEmbeddedRuleFilesParse parses the subset and expectations files
// that the gate embeds. A syntax error then fails the default unit tests
// and not only a GPU run.
func TestCTSEmbeddedRuleFilesParse(t *testing.T) {
	subset, err := gpuAssets.ReadFile("testdata/gpu/webgl-cts-subset.txt")
	if err != nil {
		t.Fatalf("read subset: %v", err)
	}
	if _, err := parseCTSSubset(bytes.NewReader(subset)); err != nil {
		t.Fatalf("parse subset: %v", err)
	}
	expect, err := gpuAssets.ReadFile("testdata/gpu/webgl-cts-expectations.txt")
	if err != nil {
		t.Fatalf("read expectations: %v", err)
	}
	exps, err := parseCTSExpectations(bytes.NewReader(expect))
	if err != nil {
		t.Fatalf("parse expectations: %v", err)
	}
	if len(exps) == 0 {
		t.Fatalf("expectations file has no rule")
	}
}
