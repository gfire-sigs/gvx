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
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	g3Timeout = 15 * time.Minute

	// g3VirglRendererPrefix is the start of GL_RENDERER of Mesa virgl:
	// "virgl (<host renderer>)" (Mesa virgl_screen.c fixup_renderer).
	g3VirglRendererPrefix = "virgl ("
)

var g3ProbeChecks = []string{
	"check_fbo",
	"check_fill",
	"check_scissor",
	"check_texture",
	"check_readback",
	"check_glerror",
}

// g3Record is the result.json of gate G3.
type g3Record struct {
	Gate          string               `json:"gate"` // "G3"
	Pass          bool                 `json:"pass"`
	Host          gpuHostRecord        `json:"host"`
	Image         string               `json:"image"`
	Snapshot      string               `json:"debian_snapshot"`
	Control       map[string]string    `json:"control_llvmpipe"`
	Virgl         map[string]string    `json:"virgl"`
	EGLInfo       map[string]string    `json:"virgl_eglinfo_surfaceless"`
	RefusedIoctls []refusedIoctl       `json:"refused_ioctls"`
	KD1           map[string]kd1Counts `json:"kd1"`
	KD1Report     bool                 `json:"kd1_report_required"`
	Failures      []string             `json:"failures"`
	Files         map[string]string    `json:"files"`
}

// parseEGLInfo returns the "key: value" lines of the "Surfaceless platform:"
// section of eglinfo -B output, up to the next line that ends with
// "platform:". Keys keep their eglinfo text, such as
// "OpenGL ES profile renderer".
func parseEGLInfo(text string) map[string]string {
	out := map[string]string{}
	inSection := false
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if !inSection {
			if line == "Surfaceless platform:" {
				inSection = true
			}
			continue
		}
		if strings.HasSuffix(line, "platform:") {
			break
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if key == "" {
			continue
		}
		if _, seen := out[key]; !seen {
			out[key] = val
		}
	}
	return out
}

// runG3 runs g3.sh once and returns its GVX-G3 and GVX-GL values.
func runG3(t *testing.T, art, name, mode, expect string) (g3, gl map[string]string, outDir string, res gpuRunResult) {
	t.Helper()
	runDir, out := newGPURunDir(t, art, name)
	res = runGPUGuest(t, runDir, gpuRun{
		mode:      mode,
		image:     g1Image,
		net:       "nat",
		workspace: g1Workspace(t),
		out:       out,
		env:       []string{"GVX_G3_SNAPSHOT=" + g1Snapshot, "GVX_GL_EXPECT=" + expect},
		argv:      []string{"bash", "/workspace/gpu/g3.sh"},
		timeout:   g3Timeout,
	})
	g3 = keyValues(res.stdout, "GVX-G3 ")
	gl = keyValues(res.stdout, "GVX-GL ")
	for k, v := range gl {
		g3["gl_"+k] = v
	}
	g3["rungv_exit"] = strconv.Itoa(res.code)
	return g3, gl, out, res
}

// TestE2EGateGPUOpenGL is gate G3: unmodified Mesa virgl in a Debian trixie
// guest finds the virtual render node, reports the host GPU through eglinfo
// and GL_RENDERER, and passes surfaceless GLES 3.0 framebuffer, shader,
// scissor, texture, and readback checks. The control run uses llvmpipe with
// -gpu=off so a failure of the virgl run isolates the GPU path.
func TestE2EGateGPUOpenGL(t *testing.T) {
	requireGPUGate(t)
	if !gpuModeEnabled("virgl") {
		t.Skipf("virgl not in %s", gpuModesEnv)
	}
	art := gpuArtifactDir(t, "g3")
	start := time.Now()
	rec := g3Record{
		Gate:     "G3",
		Image:    g1Image,
		Snapshot: g1Snapshot,
		Host:     newGPUHostRecord(start),
		KD1:      map[string]kd1Counts{},
		Files: map[string]string{
			"control":        "control/stdout.txt, control/out/",
			"virgl_stdout":   "virgl/stdout.txt",
			"virgl_log":      "virgl/sentry.log",
			"virgl_gpu_log":  "virgl/sentry-gpu.log",
			"eglinfo":        "virgl/out/eglinfo.txt",
			"refused_ioctls": "refused-ioctls.json",
			"kd1":            "kd1.json",
			"result":         "result.json",
		},
	}
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

	var control map[string]string
	t.Run("control-llvmpipe", func(t *testing.T) {
		g3, gl, _, res := runG3(t, art, "control", "off", "llvmpipe")
		rec.Control = g3
		control = g3
		rec.KD1["control"] = scanGPULog(t, res.log).KD1
		if !strings.Contains(res.stdout, "GVX-G3 step=apt") {
			fail(t, "control guest did not start (rungv exit %d): %s", res.code, rungvError(res.log))
			t.FailNow()
		}
		const diag = " (the probe or the packages are broken; the GPU path is not involved)"
		if g3["probe_exit"] != "0" {
			fail(t, "control probe_exit = %q, want 0%s", g3["probe_exit"], diag)
		}
		if gl["result"] != "PASS" {
			fail(t, "control result = %q, want PASS%s", gl["result"], diag)
		}
		for _, ck := range g3ProbeChecks {
			if gl[ck] != "PASS" {
				fail(t, "control %s = %q, want PASS%s", ck, gl[ck], diag)
			}
		}
		if !strings.Contains(gl["gl_renderer"], "llvmpipe") {
			fail(t, "control gl_renderer = %q, want substring llvmpipe%s", gl["gl_renderer"], diag)
		}
		if g3["sysfs_device"] != "" {
			fail(t, "control sysfs_device = %q, want empty: the GPU is off", g3["sysfs_device"])
		}
	})

	var virgl, virglGL map[string]string
	var virglOut string
	t.Run("virgl", func(t *testing.T) {
		g3, gl, out, res := runG3(t, art, "virgl", "virgl", "virgl")
		rec.Virgl = g3
		scan := scanGPULog(t, res.log)
		rec.RefusedIoctls = scan.Refused
		rec.KD1["virgl"] = scan.KD1
		writeJSON(t, filepath.Join(art, "refused-ioctls.json"), scan.Refused)
		for _, r := range scan.Refused {
			t.Logf("refused ioctl: %s nr %s cmd %s: %s (files %d)", r.Name, r.Nr, r.Cmd, r.Error, r.Files)
		}
		if !strings.Contains(res.stdout, "GVX-G3 step=apt") {
			fail(t, "virgl guest did not start (rungv exit %d): %s", res.code, rungvError(res.log))
			t.FailNow()
		}
		if !strings.Contains(res.stdout, "GVX-G3 done") {
			fail(t, "g3.sh did not finish (rungv exit %d); stdout:\n%s", res.code, res.stdout)
		}
		virgl, virglGL, virglOut = g3, gl, out
	})
	if virgl == nil {
		return
	}

	t.Run("verify-virgl", func(t *testing.T) {
		if virgl["render_node"] != renderNodeStat {
			fail(t, "render_node = %q, want %q", virgl["render_node"], renderNodeStat)
		}
		if virgl["probe_exit"] != "0" {
			fail(t, "probe_exit = %q, want 0", virgl["probe_exit"])
		}
		if virglGL["result"] != "PASS" {
			fail(t, "probe result = %q, want PASS", virglGL["result"])
		}
		for _, ck := range g3ProbeChecks {
			if virglGL[ck] != "PASS" {
				fail(t, "probe %s = %q, want PASS", ck, virglGL[ck])
			}
		}
		renderer := virglGL["gl_renderer"]
		lower := strings.ToLower(renderer)
		if !strings.HasPrefix(renderer, g3VirglRendererPrefix) || !strings.Contains(renderer, "Apple") ||
			strings.Contains(lower, "llvmpipe") || strings.Contains(lower, "softpipe") {
			fail(t, "gl_renderer = %q, want prefix %q containing Apple without llvmpipe or softpipe", renderer, g3VirglRendererPrefix)
		}
		if !strings.HasPrefix(virglGL["gl_version"], "OpenGL ES 3.") {
			fail(t, "gl_version = %q, want prefix %q", virglGL["gl_version"], "OpenGL ES 3.")
		}
		if virgl["eglinfo_exit"] != "0" {
			fail(t, "eglinfo_exit = %q, want 0 (see virgl/out/eglinfo.txt)", virgl["eglinfo_exit"])
		}
		eglData, err := os.ReadFile(filepath.Join(virglOut, "eglinfo.txt"))
		if err != nil {
			fail(t, "read virgl/out/eglinfo.txt: %v", err)
		} else {
			rec.EGLInfo = parseEGLInfo(string(eglData))
			eglRenderer := rec.EGLInfo["OpenGL ES profile renderer"]
			if !strings.Contains(eglRenderer, "virgl") {
				fail(t, "eglinfo Surfaceless OpenGL ES profile renderer = %q, want substring virgl", eglRenderer)
			}
		}
		for k, want := range control {
			if !strings.HasPrefix(k, "package_") {
				continue
			}
			if got := virgl[k]; got != want {
				fail(t, "virgl %s = %q, control = %q (package versions differ)", k, got, want)
			}
		}
		for k, got := range virgl {
			if !strings.HasPrefix(k, "package_") {
				continue
			}
			if _, ok := control[k]; !ok {
				fail(t, "virgl %s = %q missing from control run", k, got)
			}
		}
	})
}

// eglinfoFixture holds representative eglinfo -B output across GBM,
// Surfaceless, and Device platforms.
const eglinfoFixture = `GBM platform:
EGL API version: 1.5
EGL vendor string: Mesa Project
OpenGL ES profile renderer: gbm-should-not-appear

Surfaceless platform:
EGL API version: 1.5
EGL vendor string: Mesa Project
EGL version string: 1.5
EGL client APIs: OpenGL OpenGL_ES
OpenGL core profile vendor: Mesa
OpenGL core profile renderer: virgl (Apple M1 Ultra)
OpenGL ES profile vendor: Mesa
OpenGL ES profile renderer: virgl (Apple M1 Ultra)
OpenGL ES profile version: OpenGL ES 3.2 Mesa 25.0.7-2+deb13u1

Device platform:
Device #0:
OpenGL ES profile renderer: device-should-not-appear
`

// TestParseEGLInfoSurfaceless verifies that parseEGLInfo extracts only keys
// from the Surfaceless platform section and ignores GBM and Device sections.
func TestParseEGLInfoSurfaceless(t *testing.T) {
	got := parseEGLInfo(eglinfoFixture)
	want := map[string]string{
		"EGL API version":              "1.5",
		"EGL vendor string":            "Mesa Project",
		"EGL version string":           "1.5",
		"EGL client APIs":              "OpenGL OpenGL_ES",
		"OpenGL core profile vendor":   "Mesa",
		"OpenGL core profile renderer": "virgl (Apple M1 Ultra)",
		"OpenGL ES profile vendor":     "Mesa",
		"OpenGL ES profile renderer":   "virgl (Apple M1 Ultra)",
		"OpenGL ES profile version":    "OpenGL ES 3.2 Mesa 25.0.7-2+deb13u1",
	}
	if len(got) != len(want) {
		t.Fatalf("parseEGLInfo() returned %d keys (%v), want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("parseEGLInfo()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

// TestParseEGLInfoMissingSection verifies that parseEGLInfo returns an empty
// map when the Surfaceless platform section is absent.
func TestParseEGLInfoMissingSection(t *testing.T) {
	got := parseEGLInfo("GBM platform:\nEGL API version: 1.5\n")
	if len(got) != 0 {
		t.Fatalf("parseEGLInfo(missing section) = %v, want empty map", got)
	}
}
