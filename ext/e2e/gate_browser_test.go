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
	"embed"
	"image"
	"image/color"
	"image/png"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/exttest"
)

// The browser gates are Phase 0 of docs/moonshots.md (section 9.1). They run
// Chromium, Playwright, and Electron with software rendering. The image is
// about 1 GB for each architecture, so the gates run only on request.
const (
	// browserGateEnv turns the browser gates on when it is "1".
	browserGateEnv = "GVX_E2E_BROWSER"

	// browserImage is the Playwright image for Ubuntu 24.04. It holds the
	// Chromium 159 browser, the Chromium headless shell, Node.js, and the
	// libraries that Electron needs, for linux/amd64 and linux/arm64. The
	// digest pins the image index.
	browserImage = "mcr.microsoft.com/playwright:v1.65.1-noble@sha256:1507cbfc550a63a6b7396791ca4f00df17beb56342d2447b3f106c306f525579"

	// browserGuestTimeout bounds one guest run. The first run of a test
	// process pulls and compiles the image (20 s on a 1 Gbit/s link).
	browserGuestTimeout = 10 * time.Minute

	// browserUser is the user of the image that is not root. Chromium refuses
	// to start its sandbox as root.
	browserUser = "pwuser"

	// playwrightCoreGuestPath and electronGuestPath are the read-only guest
	// mount points of the host trees that acceptprog downloads.
	playwrightCoreGuestPath = "/opt/playwright-core"
	electronGuestPath       = "/opt/electron"

	// chromiumHelloValue is the text that hello.html computes in JavaScript.
	chromiumHelloValue = "gvx-chromium-42"
)

// browserAssets holds the pages and scripts that the gates copy into the
// guest workspace. webgl-probe.html is the WebGL probe that later phases
// reuse to prove the GPU path.
//
//go:embed testdata/browser
var browserAssets embed.FS

// chromiumScript starts the Chromium browser of the image with args. The
// path of the browser holds the Playwright build number and the
// architecture, so a shell glob finds it.
func chromiumScript(args string) []string {
	return []string{"sh", "-c", `chrome=$(ls /ms-playwright/chromium-*/chrome-linux*/chrome | head -n 1); exec "$chrome" ` + args}
}

// requireBrowserOptIn skips the calling test unless the user asked for the
// browser gates. Calling it before requireBackend keeps opted-out runs from
// failing on hosts without a hypervisor.
func requireBrowserOptIn(t *testing.T) {
	t.Helper()
	if os.Getenv(browserGateEnv) != "1" {
		t.Skipf("the browser gates pull a 1 GB image; set %s=1", browserGateEnv)
	}
}

// browserWorkspace returns a new host workspace that holds the browser
// assets and an empty out directory for files that the guest writes.
func browserWorkspace(t *testing.T) string {
	t.Helper()
	assets, err := fs.Sub(browserAssets, "testdata/browser")
	if err != nil {
		t.Fatalf("open the embedded browser assets: %v", err)
	}
	dir := t.TempDir()
	if err := os.CopyFS(dir, assets); err != nil {
		t.Fatalf("copy the browser assets to %s: %v", dir, err)
	}
	if err := os.Mkdir(filepath.Join(dir, "out"), 0o755); err != nil {
		t.Fatalf("create the guest output directory: %v", err)
	}
	return dir
}

// browserSpec returns the common guest settings of a browser gate.
func browserSpec(b gateBackend, workspace string, argv ...string) guestSpec {
	return guestSpec{
		plat:      b.plat,
		image:     browserImage,
		argv:      argv,
		workspace: workspace,
		timeout:   browserGuestTimeout,
	}
}

// readOnlyBind returns a read-only bind mount of a host directory.
func readOnlyBind(hostPath, guestPath string) gvx.Mount {
	return gvx.Mount{Kind: gvx.MountBind, HostPath: hostPath, GuestPath: guestPath, ReadOnly: true}
}

// webGLProbe is the parsed output of webgl-probe.html.
type webGLProbe map[string]string

// webGLProbeLineRE matches one result line of webgl-probe.html. The text can
// be the page text (Playwright, Electron) or the serialized DOM (Chromium
// --dump-dom), where a tag can follow the last value, so a value ends before
// "<". The lowercase key skips the source text of the page script, which the
// serialized DOM also holds.
var webGLProbeLineRE = regexp.MustCompile(`(?m)GVX-WEBGL ([a-z]+)(?:=([^<\n]*))?`)

// parseWebGLProbe collects the "GVX-WEBGL key=value" lines of text. The
// first value of a key wins.
func parseWebGLProbe(text string) webGLProbe {
	p := webGLProbe{}
	for _, m := range webGLProbeLineRE.FindAllStringSubmatch(text, -1) {
		if _, ok := p[m[1]]; !ok {
			p[m[1]] = strings.TrimSpace(m[2])
		}
	}
	return p
}

// dumpDOMProbeOutput is the --dump-dom output of webgl-probe.html from
// Chromium 159 on hvf, cut to the result lines and the first script line.
const dumpDOMProbeOutput = `<body><canvas id="c" width="256" height="256"></canvas><pre id="out">GVX-WEBGL context=webgl
GVX-WEBGL vendor=Google Inc. (Google)
GVX-WEBGL renderer=ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver)
GVX-WEBGL version=WebGL 1.0 (OpenGL ES 2.0 Chromium)
GVX-WEBGL left=255,0,0,255
GVX-WEBGL right=0,0,255,255
GVX-WEBGL error=0
GVX-WEBGL done</pre>
<script>
  function emit(s) { lines.push('GVX-WEBGL ' + s); out.textContent = lines.join('\n'); }
`

// TestParseWebGLProbeReadsDumpDOM parses the serialized DOM of the probe. The
// closing tag after the last line must not become part of the key, and the
// script source must not add keys.
func TestParseWebGLProbeReadsDumpDOM(t *testing.T) {
	got := parseWebGLProbe(dumpDOMProbeOutput)
	want := webGLProbe{
		"context":  "webgl",
		"vendor":   "Google Inc. (Google)",
		"renderer": "ANGLE (Google, Vulkan 1.3.0 (SwiftShader Device (LLVM 10.0.0) (0x0000C0DE)), SwiftShader driver)",
		"version":  "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
		"left":     "255,0,0,255",
		"right":    "0,0,255,255",
		"error":    "0",
		"done":     "",
	}
	if len(got) != len(want) {
		t.Errorf("parseWebGLProbe() keys = %d (%v), want %d", len(got), got, len(want))
	}
	for key, value := range want {
		if v, ok := got[key]; !ok || v != value {
			t.Errorf("parseWebGLProbe()[%q] = %q (present %v), want %q", key, v, ok, value)
		}
	}
}

// requireSwiftShaderProbe fails the test unless the probe ran on SwiftShader
// and read back red on the left half and blue on the right half.
func requireSwiftShaderProbe(t *testing.T, text string) {
	t.Helper()
	p := parseWebGLProbe(text)
	if _, ok := p["done"]; !ok {
		t.Fatalf("WebGL probe did not finish; output:\n%s", text)
	}
	want := map[string]string{"context": "webgl", "left": "255,0,0,255", "right": "0,0,255,255", "error": "0"}
	for key, value := range want {
		if p[key] != value {
			t.Errorf("WebGL probe %s = %q, want %q", key, p[key], value)
		}
	}
	if !strings.Contains(p["renderer"], "SwiftShader") {
		t.Errorf("WebGL probe renderer = %q, want a SwiftShader renderer", p["renderer"])
	}
}

// TestE2EGateBrowserChromiumDumpDOM runs headless Chromium on a static page
// and reads the value that the page script writes into the DOM. It covers the
// multi-process start of Chromium without its sandbox and without a GPU.
func TestE2EGateBrowserChromiumDumpDOM(t *testing.T) {
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, browserSpec(b, browserWorkspace(t),
				chromiumScript("--headless=new --no-sandbox --disable-gpu --dump-dom file:///workspace/hello.html")...))
			requireContains(t, "Chromium DOM", out, `<p id="v">`+chromiumHelloValue+`</p>`)
		})
	}
}

// sandboxProcess is one "GVX-SB" line of chromium-sandbox-probe.sh.
type sandboxProcess struct {
	typ, seccomp, userNS, pidNS string
}

var sandboxLineRE = regexp.MustCompile(`(?m)^GVX-SB type=(\S+) seccomp=(\S+) userns=(\S+) pidns=(\S+)$`)

// TestE2EGateBrowserChromiumSandbox runs Chromium with its own sandbox as a
// user that is not root. Each renderer must run in seccomp filter mode in a
// user namespace and a PID namespace that differ from the browser process.
func TestE2EGateBrowserChromiumSandbox(t *testing.T) {
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			spec := browserSpec(b, browserWorkspace(t), "bash", "/workspace/chromium-sandbox-probe.sh")
			spec.user = browserUser
			out := mustRunGuest(t, spec)
			requireContains(t, "sandbox probe", out, "GVX-SB ready=1\n", "GVX-SB done\n")
			var browser *sandboxProcess
			var renderers []sandboxProcess
			for _, m := range sandboxLineRE.FindAllStringSubmatch(out, -1) {
				p := sandboxProcess{typ: m[1], seccomp: m[2], userNS: m[3], pidNS: m[4]}
				switch p.typ {
				case "browser":
					browser = &p
				case "renderer":
					renderers = append(renderers, p)
				}
			}
			if browser == nil || len(renderers) == 0 {
				t.Fatalf("sandbox probe found browser=%v renderers=%d, want one browser and at least one renderer; output:\n%s", browser != nil, len(renderers), out)
			}
			for _, r := range renderers {
				if r.seccomp != "2" {
					t.Errorf("renderer seccomp mode = %s, want 2 (filter)", r.seccomp)
				}
				if r.userNS == browser.userNS {
					t.Errorf("renderer user namespace = %s, want one that differs from the browser", r.userNS)
				}
				if r.pidNS == browser.pidNS {
					t.Errorf("renderer PID namespace = %s, want one that differs from the browser", r.pidNS)
				}
			}
		})
	}
}

// TestE2EGateBrowserWebGLSwiftShader runs the WebGL probe in headless
// Chromium with SwiftShader, the CPU implementation of Vulkan. Chromium
// creates no WebGL context without a GPU unless --enable-unsafe-swiftshader
// is set.
func TestE2EGateBrowserWebGLSwiftShader(t *testing.T) {
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, browserSpec(b, browserWorkspace(t),
				chromiumScript("--headless=new --no-sandbox --enable-unsafe-swiftshader --dump-dom file:///workspace/webgl-probe.html")...))
			requireSwiftShaderProbe(t, out)
		})
	}
}

// TestE2EGateBrowserPlaywright drives the Chromium headless shell through
// playwright-core. The guest writes a screenshot of the WebGL probe canvas
// and a PDF of a page; the host decodes both files.
func TestE2EGateBrowserPlaywright(t *testing.T) {
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			pwcore := exttest.FetchPlaywrightCore(t)
			ws := browserWorkspace(t)
			spec := browserSpec(b, ws, "node", "/workspace/playwright-gate.js")
			spec.mounts = []gvx.Mount{readOnlyBind(pwcore, playwrightCoreGuestPath)}
			out := mustRunGuest(t, spec)
			requireContains(t, "Playwright output", out,
				"GVX-PW version=159.", "GVX-PW text="+chromiumHelloValue+"\n", "GVX-PW done\n")
			requireSwiftShaderProbe(t, out)
			requireProbeScreenshot(t, filepath.Join(ws, "out", "probe.png"))
			requireOnePagePDF(t, filepath.Join(ws, "out", "hello.pdf"))
		})
	}
}

// requireProbeScreenshot fails the test unless the PNG file is a 256x256
// image with red pixels left of x=128 and blue pixels from x=128.
func requireProbeScreenshot(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the probe screenshot: %v", err)
	}
	img, err := png.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("decode the probe screenshot %s: %v", path, err)
	}
	if got, want := img.Bounds(), image.Rect(0, 0, 256, 256); got != want {
		t.Fatalf("probe screenshot bounds = %v, want %v", got, want)
	}
	red := color.NRGBA{R: 255, A: 255}
	blue := color.NRGBA{B: 255, A: 255}
	for _, c := range []struct {
		x, y int
		want color.NRGBA
	}{
		{1, 1, red}, {64, 128, red}, {127, 254, red},
		{128, 1, blue}, {192, 128, blue}, {254, 254, blue},
	} {
		if got := color.NRGBAModel.Convert(img.At(c.x, c.y)).(color.NRGBA); got != c.want {
			t.Errorf("probe screenshot pixel (%d,%d) = %v, want %v", c.x, c.y, got, c.want)
		}
	}
}

// pdfPageRE matches a page object and skips /Pages and /PageLabel entries.
var pdfPageRE = regexp.MustCompile(`/Type\s*/Page\b`)

// pdfMediaBoxRE matches the media box of a page.
var pdfMediaBoxRE = regexp.MustCompile(`/MediaBox\s*\[\s*0\s+0\s+([0-9.]+)\s+([0-9.]+)\s*\]`)

// requireOnePagePDF fails the test unless the file is a complete PDF with
// one A4 page. Chromium prints A4 as 595.92 x 842.88 points.
func requireOnePagePDF(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read the PDF: %v", err)
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("PDF %s starts with %q, want %%PDF-", path, data[:min(len(data), 8)])
	}
	if !bytes.Contains(data[max(0, len(data)-32):], []byte("%%EOF")) {
		t.Errorf("PDF %s has no %%%%EOF marker in its last 32 bytes", path)
	}
	if n := len(pdfPageRE.FindAll(data, -1)); n != 1 {
		t.Errorf("PDF %s page objects = %d, want 1", path, n)
	}
	m := pdfMediaBoxRE.FindSubmatch(data)
	if m == nil {
		t.Fatalf("PDF %s has no media box", path)
	}
	w, errW := strconv.ParseFloat(string(m[1]), 64)
	h, errH := strconv.ParseFloat(string(m[2]), 64)
	if errW != nil || errH != nil || w < 594 || w > 597 || h < 841 || h > 844 {
		t.Errorf("PDF %s media box = %s x %s points, want A4 (about 595 x 842)", path, m[1], m[2])
	}
}

// TestE2EGateBrowserElectron starts an Electron application with the
// headless Ozone platform. The application reads a value from a page, runs
// the WebGL probe on SwiftShader, and exits with code 0. On hosts where
// hostfs files lack POSIX execute bits (Windows NTFS), the guest copies the
// read-only tree into /tmp/electron and restores mode 0755 on the binaries.
func TestE2EGateBrowserElectron(t *testing.T) {
	requireBrowserOptIn(t)
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			electron := exttest.FetchElectron(t, hostArch())
			script := "set -e\n" +
				"dir=" + electronGuestPath + "\n" +
				"if [ ! -x \"$dir/electron\" ]; then\n" +
				"  cp -R \"$dir\" /tmp/electron\n" +
				"  chmod 755 /tmp/electron/electron /tmp/electron/chrome_crashpad_handler /tmp/electron/chrome-sandbox 2>/dev/null || true\n" +
				"  dir=/tmp/electron\n" +
				"fi\n" +
				"exec \"$dir/electron\" --no-sandbox --ozone-platform=headless --enable-unsafe-swiftshader /workspace/electron-app"
			spec := browserSpec(b, browserWorkspace(t), "sh", "-c", script)
			spec.mounts = []gvx.Mount{readOnlyBind(electron, electronGuestPath)}
			out := mustRunGuest(t, spec)
			requireContains(t, "Electron output", out,
				"GVX-EL electron="+exttest.ElectronVersion+" ",
				"GVX-EL text="+chromiumHelloValue+"\n", "GVX-EL done\n")
			requireSwiftShaderProbe(t, out)
		})
	}
}
