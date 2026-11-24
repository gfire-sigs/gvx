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
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx/exttest"
)

// G2 constants.
const (
	// gpuChromiumFlags are the Chromium flags of the GPU pass (decisions D8):
	// ANGLE on Vulkan, no GPU blocklist, and no Vulkan surface in headless
	// mode. GVX_E2E_GPU_CHROMIUM_FLAGS replaces them for the fallback steps
	// of decisions D1.
	gpuChromiumFlags    = "--use-angle=vulkan --ignore-gpu-blocklist --disable-vulkan-surface"
	gpuChromiumFlagsEnv = "GVX_E2E_GPU_CHROMIUM_FLAGS"

	// gpuChromiumVirglFlags are the Chromium flags of the virgl pass: ANGLE on
	// the system OpenGL ES (Mesa virgl) through EGL, no GPU blocklist.
	gpuChromiumVirglFlags    = "--use-gl=angle --use-angle=gl-egl --ignore-gpu-blocklist"
	gpuChromiumVirglFlagsEnv = "GVX_E2E_GPU_CHROMIUM_VIRGL_FLAGS"
	g2VirglBrowsers          = "headless-shell"

	// referenceChromiumFlags select SwiftShader for the reference pass.
	referenceChromiumFlags = "--use-angle=swiftshader --enable-unsafe-swiftshader"

	// g2Browsers are the browsers of gpu-webgl.js: the headless shell (the
	// Playwright default) and the full Chromium in its headless mode.
	g2Browsers = "headless-shell chromium"

	// g2NavTimeouts is the GVX_G2_NAV_TIMEOUTS value of gpu-webgl.js: the
	// timeout in ms of the launch and of every navigation and wait for each
	// browser. Gate rule (parent decision after the KD-2 fix): both browsers
	// pass with the Playwright default of 30 s, so a regression of known
	// defect KD-2 (slow shader compiles in the renderer) fails the gate. The
	// fixed bundle measured a first page of 1.9 s (headless shell) and 5.5 s
	// (Chromium). Both passes use the same values.
	g2NavTimeouts = "headless-shell=30000 chromium=30000"

	// g2NavTimeoutOverrideEnv names a host variable that, when set, the test
	// passes to the guest under the same name. It replaces the timeout of
	// every browser (ms). It is for diagnosis only; result.json and QA.md
	// mark a run that used it.
	g2NavTimeoutOverrideEnv = "GVX_G2_NAV_TIMEOUT_MS"

	// gpuDebsGuestPath is the guest mount point of FetchGPUGuestDebs.
	gpuDebsGuestPath = "/opt/gpu-debs"

	// g2Timeout bounds one G2 run: two browsers with five pages each. The
	// first page of a fresh GPU process took about 55 s on the KosmicKrisp
	// spike bundle (pipeline compilation in the host driver).
	g2Timeout = 30 * time.Minute

	// sceneChannelTolerance is the largest difference of one color channel
	// between the GPU and the reference scene that counts as equal.
	sceneChannelTolerance = 16

	// sceneMaxMismatch is the largest fraction of scene pixels that may
	// differ from the reference by more than sceneChannelTolerance. Edge
	// pixels of the triangles can differ between conforming rasterizers.
	sceneMaxMismatch = 0.01
)

var (
	softwareRendererRE = regexp.MustCompile(`(?i)swiftshader|llvmpipe|lavapipe|softpipe`)
	vulkanRendererRE   = regexp.MustCompile(`(?i)vulkan`)
	venusRendererRE    = regexp.MustCompile(`(?i)venus|virtio`)
	loadMillisRE       = regexp.MustCompile(`ms=(\d+)`)
)

// g2QAChecklist is the checklist of the vision review of scene-gpu.png
// (decisions D11, adapted to webgl-scene.html).
var g2QAChecklist = []string{
	"scene-gpu.png is 800x600 and has a uniform dark blue background (about RGB 26,51,77).",
	"Three solid triangles, apex up, side by side in the lower half: red on the left, green in the middle, blue on the right, of equal size.",
	"A checker quad in the upper middle with four sharp cells: top row black then white, bottom row white then black. No blur at the cell edges.",
	"A light grey rectangle near the bottom right corner (white at 50 % alpha over the background, about RGB 140,153,166).",
	"No black frame, no missing shape, no noise, no tearing, no garbage pixels.",
	"scene-gpu.png looks the same as scene-swiftshader.png; scene-diff.png is dark except for at most a few edge pixels (magenta marks a difference). A one-pixel magenta row on the middle line of the checker is expected: that row samples exactly on a texel boundary, where the NEAREST choice is implementation-defined.",
	"probe-gpu.png is 256x256: left half pure red, right half pure blue.",
}

// sceneResult is window.__gvxScene of webgl-scene.html.
type sceneResult struct {
	WebGLVersion     int    `json:"webglVersion"`
	UnmaskedVendor   string `json:"unmaskedVendor"`
	UnmaskedRenderer string `json:"unmaskedRenderer"`
	PixelChecks      []struct {
		Name string `json:"name"`
		X    int    `json:"x"`
		Y    int    `json:"y"`
		Want []int  `json:"want"`
		Got  []int  `json:"got"`
		OK   bool   `json:"ok"`
	} `json:"pixelChecks"`
	Errors []string `json:"errors"`
	Pass   bool     `json:"pass"`
}

// g2Browser is the record of one browser in result.json.
type g2Browser struct {
	Name                   string            `json:"name"`
	Pass                   bool              `json:"pass"`
	Probe                  map[string]string `json:"probe"`
	Scene                  *sceneResult      `json:"scene"`
	ReferenceScene         *sceneResult      `json:"reference_scene"`
	SceneMismatchFraction  float64           `json:"scene_mismatch_fraction"`
	SceneMaxChannelDiff    int               `json:"scene_max_channel_diff"`
	FrameMillis            int               `json:"load_ms_gpu"`
	ReferenceFrameMillis   int               `json:"load_ms_swiftshader"`
	SpeedupOverSwiftShader float64           `json:"speedup_over_swiftshader"`
	// NavTimeoutMillis is the timeout that gpu-webgl.js used for this
	// browser; FirstPageMillis is the time of its first page on the GPU (the
	// cold start of KD-2). Both are recorded, not asserted beyond the timeout.
	NavTimeoutMillis int `json:"nav_timeout_ms"`
	FirstPageMillis  int `json:"first_page_ms_gpu"`
	// Timings and ReferenceTimings are the timings.json of gpu-webgl.js
	// (nav_timeout_ms, launch_ms, first_page_ms, scene_page_ms,
	// second_page_ms, load_page_ms). They are recorded, not asserted.
	Timings          map[string]int    `json:"timings_ms_gpu"`
	ReferenceTimings map[string]int    `json:"timings_ms_swiftshader"`
	DisplayType      string            `json:"display_type"`
	FeatureStatus    map[string]string `json:"feature_status"`
	Failures         []string          `json:"failures"`
}

// g2ModeRecord is the record of an additional GPU mode pass in g2Record.
type g2ModeRecord struct {
	ChromiumFlags string            `json:"chromium_flags"`
	Guest         map[string]string `json:"guest"`
	Browsers      []*g2Browser      `json:"browsers"`
	RefusedIoctls []refusedIoctl    `json:"refused_ioctls"`
	Failures      []string          `json:"failures"`
}

// g2Record is the result.json of gate G2.
type g2Record struct {
	Gate           string               `json:"gate"`
	Pass           bool                 `json:"pass"`
	Host           gpuHostRecord        `json:"host"`
	Image          string               `json:"image"`
	ChromiumFlags  string               `json:"chromium_flags"`
	NavTimeouts    string               `json:"nav_timeouts"`
	NavOverride    string               `json:"nav_timeout_override_ms"`
	ReferenceFlags string               `json:"reference_flags"`
	Guest          map[string]string    `json:"guest"`
	Browsers       []*g2Browser         `json:"browsers"`
	Virgl          *g2ModeRecord        `json:"virgl,omitempty"`
	RefusedIoctls  []refusedIoctl       `json:"refused_ioctls"`
	KD1            map[string]kd1Counts `json:"kd1"`
	KD1Report      bool                 `json:"kd1_report_required"`
	Failures       []string             `json:"failures"`
	QAChecklist    []string             `json:"qa_checklist"`
	Files          map[string]string    `json:"files"`
}

// g2Workspace returns the Phase 0 browser workspace with the GPU assets in
// its gpu directory.
func g2Workspace(t *testing.T) string {
	t.Helper()
	ws := browserWorkspace(t)
	copyEmbedded(t, gpuAssets, "testdata/gpu", filepath.Join(ws, "gpu"))
	return ws
}

// TestE2EGateGPUChromium is gate G2: Chromium renders WebGL through ANGLE on
// Vulkan, Mesa venus, and the host GPU. A reference pass with SwiftShader
// runs first in a sandbox without the GPU. For each browser the GPU pass must
// name a venus Vulkan renderer (not a software one), pass the pixel checks
// of both pages, and match the reference scene.
func TestE2EGateGPUChromium(t *testing.T) {
	requireGPUGate(t)
	runVenus := gpuModeEnabled("venus")
	runVirgl := gpuModeEnabled("virgl")
	if !runVenus && !runVirgl {
		t.Skipf("neither venus nor virgl in %s", gpuModesEnv)
	}
	art := gpuArtifactDir(t, "g2")
	pwcore := exttest.FetchPlaywrightCore(t)
	flags := cmp.Or(os.Getenv(gpuChromiumFlagsEnv), gpuChromiumFlags)
	virglFlags := cmp.Or(os.Getenv(gpuChromiumVirglFlagsEnv), gpuChromiumVirglFlags)
	navEnv := []string{"GVX_G2_NAV_TIMEOUTS=" + g2NavTimeouts}
	navOverride := os.Getenv(g2NavTimeoutOverrideEnv)
	if navOverride != "" {
		navEnv = append(navEnv, g2NavTimeoutOverrideEnv+"="+navOverride)
		t.Logf("%s=%s replaces the navigation timeout of every browser (diagnosis run)", g2NavTimeoutOverrideEnv, navOverride)
	}
	start := time.Now()
	rec := &g2Record{
		Gate: "G2", Image: browserImage, Host: newGPUHostRecord(start),
		ChromiumFlags: flags, ReferenceFlags: referenceChromiumFlags, QAChecklist: g2QAChecklist,
		NavTimeouts: g2NavTimeouts, NavOverride: navOverride,
		Files: map[string]string{
			"result":         "result.json",
			"qa":             "QA.md",
			"refused_ioctls": "refused-ioctls.json",
			"kd1":            "kd1.json",
			"per_browser":    "<browser>/{scene-gpu.png,scene-swiftshader.png,scene-diff.png,probe-gpu.png,probe-swiftshader.png,scene-gpu.json,scene-swiftshader.json,gpu-info-gpu.json,gpu-info-swiftshader.json}",
			"gpu_run":        "gpu/{stdout.txt,sentry.log,sentry-gpu.log,out/}",
			"reference_run":  "swiftshader/{stdout.txt,sentry.log,out/}",
		},
	}
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
		writeG2QA(t, art, rec)
	}()
	note := func(t *testing.T, list *[]string, format string, args ...any) {
		t.Helper()
		msg := fmt.Sprintf(format, args...)
		t.Error(msg)
		*list = append(*list, msg)
	}
	readOnly := map[string]string{pwcore: playwrightCoreGuestPath}

	refBrowsers := g2Browsers
	if !runVenus {
		refBrowsers = g2VirglBrowsers
	}
	refDir, refOut := newGPURunDir(t, art, "swiftshader")
	ref := runGPUGuest(t, refDir, gpuRun{
		image: browserImage, net: "none", workspace: g2Workspace(t), out: refOut, readOnly: readOnly,
		env: append([]string{"GVX_G2_MODE=swiftshader", "GVX_G2_ARGS=" + referenceChromiumFlags,
			"GVX_G2_OUT=" + gpuOutGuestPath, "GVX_G2_CHANNELS=" + refBrowsers}, navEnv...),
		argv:    []string{"bash", "/workspace/gpu/g2.sh"},
		timeout: g2Timeout,
	})
	// The reference run has no renderer, so its KD-1 counts are 0 unless
	// the harness mixed up the runs.
	rec.KD1["swiftshader"] = scanGPULog(t, ref.log).KD1
	if ref.code != 0 || !strings.Contains(ref.stdout, "GVX-G2 done") {
		note(t, &rec.Failures, "reference pass failed (rungv exit %d): %s; the harness or the image is broken, not the GPU path; stdout:\n%s", ref.code, rungvError(ref.log), ref.stdout)
		t.FailNow()
	}

	if runVenus {
		debs := exttest.FetchGPUGuestDebs(t, hostArch())
		gpuReadOnly := map[string]string{pwcore: playwrightCoreGuestPath, debs: gpuDebsGuestPath}
		gpuDir, gpuOut := newGPURunDir(t, art, "gpu")
		res := runGPUGuest(t, gpuDir, gpuRun{
			gpu: true, image: browserImage, net: "none", workspace: g2Workspace(t), out: gpuOut, readOnly: gpuReadOnly,
			env: append([]string{"GVX_G2_MODE=gpu", "GVX_G2_ARGS=" + flags,
				"GVX_G2_OUT=" + gpuOutGuestPath, "GVX_G2_CHANNELS=" + g2Browsers}, navEnv...),
			argv:    []string{"bash", "/workspace/gpu/g2.sh"},
			timeout: g2Timeout,
		})
		scan := scanGPULog(t, res.log)
		rec.RefusedIoctls = scan.Refused
		rec.KD1["gpu"] = scan.KD1
		writeJSON(t, filepath.Join(art, "refused-ioctls.json"), rec.RefusedIoctls)
		for _, r := range rec.RefusedIoctls {
			t.Logf("refused ioctl: %s nr %s cmd %s: %s (files %d)", r.Name, r.Nr, r.Cmd, r.Error, r.Files)
		}
		if !strings.Contains(res.stdout, "GVX-G2 mode=gpu") {
			note(t, &rec.Failures, "GPU guest did not start (rungv exit %d): %s", res.code, rungvError(res.log))
		} else {
			rec.Guest = keyValues(res.stdout, "GVX-G2 ")

			t.Run("vulkan", func(t *testing.T) {
				g := rec.Guest
				if g["vulkaninfo_exit"] != "0" {
					note(t, &rec.Failures, "vulkaninfo exit = %q, want 0 (see gpu/out/vulkaninfo.txt)", g["vulkaninfo_exit"])
				}
				if name := g["vulkaninfo_deviceName"]; !strings.HasPrefix(name, venusDeviceName) {
					note(t, &rec.Failures, "vulkaninfo deviceName = %q, want %q", name, venusDeviceName+" (...)")
				}
				mesa, gallium := g["package_mesa-vulkan-drivers"], g["package_mesa-libgallium"]
				if mesa == "" || mesa != gallium {
					note(t, &rec.Failures, "mesa-vulkan-drivers %q and mesa-libgallium %q differ: FetchGPUGuestDebs does not match the image", mesa, gallium)
				}
			})

			for _, name := range strings.Fields(g2Browsers) {
				b := &g2Browser{Name: name}
				rec.Browsers = append(rec.Browsers, b)
				t.Run(name, func(t *testing.T) {
					evalG2Browser(t, art, refOut, gpuOut, res.stdout, b, requireGPURenderer, "", func(format string, args ...any) {
						t.Helper()
						note(t, &b.Failures, format, args...)
					})
					b.Pass = !t.Failed()
				})
			}
		}
	}

	if runVirgl {
		rec.Files["virgl_run"] = "virgl/{stdout.txt,sentry.log,sentry-gpu.log,refused-ioctls.json,out/}"
		rec.Files["virgl_browser"] = "virgl/<browser>/{scene-gpu.png,scene-swiftshader.png,scene-diff.png,probe-gpu.png,probe-swiftshader.png,scene-gpu.json,scene-swiftshader.json,gpu-info-gpu.json,gpu-info-swiftshader.json}"
		rec.Virgl = &g2ModeRecord{ChromiumFlags: virglFlags}
		virglDir, virglOut := newGPURunDir(t, art, "virgl")
		virglRes := runGPUGuest(t, virglDir, gpuRun{
			mode: "virgl", image: browserImage, net: "none", workspace: g2Workspace(t), out: virglOut, readOnly: readOnly,
			env: append([]string{"GVX_G2_MODE=virgl", "GVX_G2_ARGS=" + virglFlags,
				"GVX_G2_OUT=" + gpuOutGuestPath, "GVX_G2_CHANNELS=" + g2VirglBrowsers}, navEnv...),
			argv:    []string{"bash", "/workspace/gpu/g2.sh"},
			timeout: g2Timeout,
		})
		scan := scanGPULog(t, virglRes.log)
		rec.Virgl.RefusedIoctls = scan.Refused
		rec.KD1["virgl"] = scan.KD1
		writeJSON(t, filepath.Join(virglDir, "refused-ioctls.json"), rec.Virgl.RefusedIoctls)
		for _, r := range rec.Virgl.RefusedIoctls {
			t.Logf("virgl refused ioctl: %s nr %s cmd %s: %s (files %d)", r.Name, r.Nr, r.Cmd, r.Error, r.Files)
		}
		if !strings.Contains(virglRes.stdout, "GVX-G2 mode=virgl") {
			note(t, &rec.Virgl.Failures, "virgl guest did not start (rungv exit %d): %s", virglRes.code, rungvError(virglRes.log))
			return
		}
		rec.Virgl.Guest = keyValues(virglRes.stdout, "GVX-G2 ")
		if rec.Virgl.Guest["render_node"] != renderNodeStat {
			note(t, &rec.Virgl.Failures, "virgl render_node = %q, want %q", rec.Virgl.Guest["render_node"], renderNodeStat)
		}
		for _, name := range strings.Fields(g2VirglBrowsers) {
			b := &g2Browser{Name: name}
			rec.Virgl.Browsers = append(rec.Virgl.Browsers, b)
			t.Run("virgl/"+name, func(t *testing.T) {
				evalG2Browser(t, art, refOut, virglOut, virglRes.stdout, b, requireGLRenderer, "virgl", func(format string, args ...any) {
					t.Helper()
					note(t, &b.Failures, format, args...)
				})
				b.Pass = !t.Failed()
			})
		}
	}
}

// evalG2Browser checks the files of one browser and fills b. check validates
// the renderer string on the probe and scene pages. artSub names an optional
// subdirectory under art (empty for venus, "virgl" for virgl). fail reports
// one failed check.
func evalG2Browser(t *testing.T, art, refOut, gpuOut, stdout string, b *g2Browser, check func(renderer, page string, fail func(string, ...any)), artSub string, fail func(format string, args ...any)) {
	t.Helper()
	dir := filepath.Join(art, artSub, b.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("create %s: %v", dir, err)
	}
	gpuDir := filepath.Join(gpuOut, b.Name)
	refDir := filepath.Join(refOut, b.Name)
	for _, c := range [][2]string{
		{filepath.Join(gpuDir, "probe.png"), "probe-gpu.png"},
		{filepath.Join(refDir, "probe.png"), "probe-swiftshader.png"},
		{filepath.Join(gpuDir, "scene.png"), "scene-gpu.png"},
		{filepath.Join(refDir, "scene.png"), "scene-swiftshader.png"},
		{filepath.Join(gpuDir, "scene.json"), "scene-gpu.json"},
		{filepath.Join(refDir, "scene.json"), "scene-swiftshader.json"},
		{filepath.Join(gpuDir, "gpu-info.json"), "gpu-info-gpu.json"},
		{filepath.Join(refDir, "gpu-info.json"), "gpu-info-swiftshader.json"},
	} {
		if err := copyFile(c[0], filepath.Join(dir, c[1])); err != nil {
			t.Logf("copy %s: %v", c[1], err)
		}
	}

	// Read the timings first: a browser that timed out still has the steps
	// it finished.
	b.Timings = readTimings(filepath.Join(gpuDir, "timings.json"))
	b.ReferenceTimings = readTimings(filepath.Join(refDir, "timings.json"))
	b.NavTimeoutMillis, b.FirstPageMillis = b.Timings["nav_timeout_ms"], b.Timings["first_page_ms"]
	t.Logf("%s: navigation timeout %d ms; timings on the GPU %v, on SwiftShader %v (recorded only)", b.Name, b.NavTimeoutMillis, b.Timings, b.ReferenceTimings)

	probeText, err := os.ReadFile(filepath.Join(gpuDir, "probe.txt"))
	if err != nil {
		fail("browser %s did not finish the probe page: %v; driver line: %s", b.Name, err, g2ErrorLine(stdout, b.Name))
		return
	}
	b.Probe = parseWebGLProbe(string(probeText))
	check(b.Probe["renderer"], "probe", fail)
	for key, want := range map[string]string{"context": "webgl", "left": "255,0,0,255", "right": "0,0,255,255", "error": "0"} {
		if b.Probe[key] != want {
			fail("probe %s = %q, want %q", key, b.Probe[key], want)
		}
	}
	requireProbeScreenshot(t, filepath.Join(dir, "probe-gpu.png"))

	b.Scene = readScene(t, filepath.Join(gpuDir, "scene.json"))
	b.ReferenceScene = readScene(t, filepath.Join(refDir, "scene.json"))
	if b.ReferenceScene == nil || !b.ReferenceScene.Pass || !softwareRendererRE.MatchString(b.ReferenceScene.UnmaskedRenderer) {
		fail("reference scene did not pass on SwiftShader: the scene page or the harness is broken")
	}
	if b.Scene == nil {
		fail("browser %s did not finish the scene page; driver line: %s", b.Name, g2ErrorLine(stdout, b.Name))
		return
	}
	check(b.Scene.UnmaskedRenderer, "scene", fail)
	if !b.Scene.Pass {
		fail("scene pass = false: errors %v, pixel checks %+v", b.Scene.Errors, b.Scene.PixelChecks)
	}
	if b.ReferenceScene != nil && b.Scene.WebGLVersion != b.ReferenceScene.WebGLVersion {
		t.Logf("scene WebGL version %d differs from the reference %d (recorded, not a failure)", b.Scene.WebGLVersion, b.ReferenceScene.WebGLVersion)
	}
	frac, maxDiff, err := diffScenes(filepath.Join(dir, "scene-gpu.png"), filepath.Join(dir, "scene-swiftshader.png"), filepath.Join(dir, "scene-diff.png"))
	if err != nil {
		fail("compare the scene with the reference: %v", err)
	} else {
		b.SceneMismatchFraction, b.SceneMaxChannelDiff = frac, maxDiff
		if frac > sceneMaxMismatch {
			fail("scene differs from the SwiftShader reference in %.4f of the pixels (max channel difference %d), want at most %.2f", frac, maxDiff, sceneMaxMismatch)
		}
	}

	b.FrameMillis = loadMillis(filepath.Join(gpuDir, "load.txt"))
	b.ReferenceFrameMillis = loadMillis(filepath.Join(refDir, "load.txt"))
	if b.FrameMillis > 0 && b.ReferenceFrameMillis > 0 {
		b.SpeedupOverSwiftShader = float64(b.ReferenceFrameMillis) / float64(b.FrameMillis)
	}
	t.Logf("%s: load page %d ms on the GPU, %d ms on SwiftShader (speedup %.2f, recorded only)", b.Name, b.FrameMillis, b.ReferenceFrameMillis, b.SpeedupOverSwiftShader)
	b.DisplayType, b.FeatureStatus = readGPUInfo(filepath.Join(gpuDir, "gpu-info.json"))
}

// readTimings returns the timings.json of gpu-webgl.js, or nil.
func readTimings(path string) map[string]int {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var m map[string]int
	if json.Unmarshal(data, &m) != nil {
		return nil
	}
	return m
}

// requireGPURenderer reports a renderer string that is not ANGLE on a venus
// Vulkan device or that names a software renderer.
func requireGPURenderer(renderer, page string, fail func(format string, args ...any)) {
	if !vulkanRendererRE.MatchString(renderer) || !venusRendererRE.MatchString(renderer) || softwareRendererRE.MatchString(renderer) {
		fail("%s renderer = %q, want a Vulkan renderer on venus or virtio, and no software renderer", page, renderer)
	}
}

// requireGLRenderer reports a renderer string that is not ANGLE on Mesa virgl
// or that names a software renderer.
func requireGLRenderer(renderer, page string, fail func(format string, args ...any)) {
	if !strings.Contains(strings.ToLower(renderer), "virgl") || softwareRendererRE.MatchString(renderer) {
		fail("%s renderer = %q, want ANGLE on Mesa virgl, and no software renderer", page, renderer)
	}
}

// g2ErrorLine returns the error line of gpu-webgl.js for browser, if any.
func g2ErrorLine(stdout, browser string) string {
	prefix := "GVX-G2 browser=" + browser + " error="
	for _, line := range strings.Split(stdout, "\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return "(none)"
}

func readScene(t *testing.T, path string) *sceneResult {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var s sceneResult
	if err := json.Unmarshal(data, &s); err != nil {
		t.Errorf("decode %s: %v", path, err)
		return nil
	}
	return &s
}

// loadMillis returns the ms value of a load.txt file, or 0.
func loadMillis(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	m := loadMillisRE.FindSubmatch(data)
	if m == nil {
		return 0
	}
	n, _ := strconv.Atoi(string(m[1]))
	return n
}

// readGPUInfo returns the display type and the feature status of the
// SystemInfo.getInfo GPU record at path. It returns zero values when the
// file is missing or holds an error.
func readGPUInfo(path string) (string, map[string]string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", nil
	}
	var info struct {
		AuxAttributes struct {
			DisplayType string `json:"displayType"`
		} `json:"auxAttributes"`
		FeatureStatus map[string]string `json:"featureStatus"`
	}
	if json.Unmarshal(data, &info) != nil {
		return "", nil
	}
	return info.AuxAttributes.DisplayType, info.FeatureStatus
}

// diffScenes compares two PNG files of the same size. It returns the
// fraction of pixels whose largest channel difference is above
// sceneChannelTolerance and the largest channel difference. It writes a diff
// image to out: magenta for a differing pixel, the dimmed first image for
// the others.
func diffScenes(aPath, bPath, out string) (float64, int, error) {
	decode := func(path string) (image.Image, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return png.Decode(bytes.NewReader(data))
	}
	a, err := decode(aPath)
	if err != nil {
		return 0, 0, err
	}
	b, err := decode(bPath)
	if err != nil {
		return 0, 0, err
	}
	if a.Bounds() != b.Bounds() {
		return 0, 0, fmt.Errorf("bounds %v and %v differ", a.Bounds(), b.Bounds())
	}
	r := a.Bounds()
	diff := image.NewNRGBA(r)
	var differ, maxDiff int
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			ca := color.NRGBAModel.Convert(a.At(x, y)).(color.NRGBA)
			cb := color.NRGBAModel.Convert(b.At(x, y)).(color.NRGBA)
			d := max(absDiff(ca.R, cb.R), absDiff(ca.G, cb.G), absDiff(ca.B, cb.B))
			maxDiff = max(maxDiff, d)
			if d > sceneChannelTolerance {
				differ++
				diff.SetNRGBA(x, y, color.NRGBA{R: 255, B: 255, A: 255})
				continue
			}
			diff.SetNRGBA(x, y, color.NRGBA{R: ca.R / 4, G: ca.G / 4, B: ca.B / 4, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, diff); err != nil {
		return 0, 0, err
	}
	if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil {
		return 0, 0, err
	}
	return float64(differ) / float64(r.Dx()*r.Dy()), maxDiff, nil
}

func absDiff(a, b uint8) int {
	if a > b {
		return int(a - b)
	}
	return int(b - a)
}

// writeG2QA writes QA.md: the brief of the vision review.
func writeG2QA(t *testing.T, art string, rec *g2Record) {
	t.Helper()
	var sb strings.Builder
	fmt.Fprintf(&sb, "# Gate G2 Vision Review\n\nAutomatic verdict: pass=%v. Chromium flags: `%s`. Reference flags: `%s`. Navigation timeouts: `%s`.\n\n", rec.Pass, rec.ChromiumFlags, rec.ReferenceFlags, rec.NavTimeouts)
	if rec.NavOverride != "" {
		fmt.Fprintf(&sb, "**Diagnosis run:** %s=%s replaced the navigation timeout of every browser. This run is not a gate record.\n\n", g2NavTimeoutOverrideEnv, rec.NavOverride)
	}
	sb.WriteString("Review each browser directory. Compare scene-gpu.png with scene-swiftshader.png and read scene-diff.png. Answer each item with PASS or FAIL and one sentence.\n\n")
	for _, b := range rec.Browsers {
		renderer := ""
		if b.Scene != nil {
			renderer = b.Scene.UnmaskedRenderer
		}
		fmt.Fprintf(&sb, "## %s\n\nAutomatic checks: pass=%v. Renderer: `%s`. Mismatch fraction: %.4f.\n\n", b.Name, b.Pass, renderer, b.SceneMismatchFraction)
		fmt.Fprintf(&sb, "First page on the GPU: %d ms with a navigation timeout of %d ms (known defect KD-2: cold-start pipeline compilation). Second page: %d ms.\n\n",
			b.FirstPageMillis, b.NavTimeoutMillis, b.Timings["second_page_ms"])
		for i, item := range rec.QAChecklist {
			fmt.Fprintf(&sb, "%d. %s\n", i+1, item)
		}
		sb.WriteString("\n")
	}
	if rec.Virgl != nil {
		fmt.Fprintf(&sb, "## virgl pass\n\nChromium flags: `%s`.\n\n", rec.Virgl.ChromiumFlags)
		for _, b := range rec.Virgl.Browsers {
			renderer := ""
			if b.Scene != nil {
				renderer = b.Scene.UnmaskedRenderer
			}
			fmt.Fprintf(&sb, "### virgl/%s\n\nAutomatic checks: pass=%v. Renderer: `%s`. Mismatch fraction: %.4f.\n\n", b.Name, b.Pass, renderer, b.SceneMismatchFraction)
			fmt.Fprintf(&sb, "First page on the GPU: %d ms with a navigation timeout of %d ms. Second page: %d ms.\n\n",
				b.FirstPageMillis, b.NavTimeoutMillis, b.Timings["second_page_ms"])
			for i, item := range rec.QAChecklist {
				fmt.Fprintf(&sb, "%d. %s\n", i+1, item)
			}
			sb.WriteString("\n")
		}
	}
	sb.WriteString("## Known defect KD-1\n\nCounts from the captured Sentry debug log (an explicit 0 means none). A non-zero BLOB_CREATE or renderer count, or complete=false, goes to the parent session.\n\n")
	for _, name := range []string{"gpu", "virgl", "swiftshader"} {
		if k, ok := rec.KD1[name]; ok {
			fmt.Fprintf(&sb, "- %s: %s\n", name, k)
		}
	}
	fmt.Fprintf(&sb, "\nReport required: %v.\n", rec.KD1Report)
	if err := os.WriteFile(filepath.Join(art, "QA.md"), []byte(sb.String()), 0o644); err != nil {
		t.Errorf("write QA.md: %v", err)
	}
}

// TestRequireGPURendererRejectsSoftware checks the renderer rule with the
// SwiftShader string of Chromium 159 (Phase 0) and the lavapipe string of
// ANGLE on Mesa: both must fail. A venus string must pass.
func TestRequireGPURendererRejectsSoftware(t *testing.T) {
	for _, c := range []struct {
		renderer string
		pass     bool
	}{
		{"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver)", false},
		{"ANGLE (Mesa, Vulkan 1.4.318 (llvmpipe (LLVM 20.1.2, 128 bits) (0x00000000)), llvmpipe-25.2.8)", false},
		// The renderer string of Chromium 159 on venus with the KosmicKrisp
		// spike bundle (decisions D12).
		{"ANGLE (Apple, Vulkan 1.4.307 (Virtio-GPU Venus (Apple M1 Ultra) (0x00000064)), venus)", true},
		{"", false},
	} {
		var failed bool
		requireGPURenderer(c.renderer, "probe", func(string, ...any) { failed = true })
		if failed == c.pass {
			t.Errorf("requireGPURenderer(%q) failed = %v, want pass %v", c.renderer, failed, c.pass)
		}
	}
}

// TestRequireGLRendererRejectsSoftware verifies that requireGLRenderer accepts
// ANGLE on Mesa virgl and rejects llvmpipe, SwiftShader, and empty strings.
func TestRequireGLRendererRejectsSoftware(t *testing.T) {
	for _, c := range []struct {
		renderer string
		pass     bool
	}{
		{"ANGLE (Mesa, virgl (Apple M1 Ultra), OpenGL ES 3.2 Mesa 25.2.8)", true},
		{"ANGLE (Mesa, llvmpipe (LLVM 20.1.2, 128 bits), OpenGL 4.5)", false},
		{"ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver)", false},
		{"", false},
	} {
		var failed bool
		requireGLRenderer(c.renderer, "probe", func(string, ...any) { failed = true })
		if failed == c.pass {
			t.Errorf("requireGLRenderer(%q) failed = %v, want pass %v", c.renderer, failed, c.pass)
		}
	}
}

// TestDiffScenesCountsChangedPixels compares two 10x10 images that differ in
// one pixel by more than the tolerance and in one pixel by less.
func TestDiffScenesCountsChangedPixels(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, img image.Image) string {
		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	a := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	b := image.NewNRGBA(image.Rect(0, 0, 10, 10))
	for i := range a.Pix {
		a.Pix[i], b.Pix[i] = 100, 100
	}
	b.SetNRGBA(3, 4, color.NRGBA{R: 100 + sceneChannelTolerance + 1, G: 100, B: 100, A: 100})
	b.SetNRGBA(5, 5, color.NRGBA{R: 100, G: 100 + sceneChannelTolerance, B: 100, A: 100})
	frac, maxDiff, err := diffScenes(write("a.png", a), write("b.png", b), filepath.Join(dir, "diff.png"))
	if err != nil {
		t.Fatalf("diffScenes() error = %v", err)
	}
	if frac != 0.01 || maxDiff != sceneChannelTolerance+1 {
		t.Errorf("diffScenes() = (%v, %d), want (0.01, %d)", frac, maxDiff, sceneChannelTolerance+1)
	}
}
