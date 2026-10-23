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
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/oci"
)

// M3 gate of SPEC section 4: unmodified alpine:3.20, nginx:alpine,
// python:3.12-alpine, and node:22-alpine run on the hardware backend and on
// systrap when the engine is available.

func TestE2EGateM3Alpine(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			// The script reads the release files, runs a pipeline of
			// dynamically linked musl tools, and uses the apk database.
			script := `. /etc/os-release && echo "id=$ID version=$VERSION_ID" &&
cat /etc/alpine-release && uname -m &&
echo alpine | tr a-z A-Z | sed 's/ALP/alp/' &&
apk info -e busybox >/dev/null && echo "apk-has-busybox" &&
ls /bin | wc -l | awk '{ if ($1 > 50) print "bin-ok" }'`
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "alpine:3.20",
				argv:  []string{"/bin/sh", "-c", script},
			})
			requireContains(t, "alpine output", out,
				"id=alpine version=3.20.", "3.20.", "alpINE\n", "apk-has-busybox\n", "bin-ok\n")
			wantMachine := map[string]string{"arm64": "aarch64", "amd64": "x86_64"}[hostArch()]
			requireContains(t, "uname -m", out, wantMachine+"\n")
		})
	}
}

// nginxReady is the error-log notice that the nginx master prints after it
// binds port 80 and forks its workers.
const nginxReady = "start worker process"

func TestE2EGateM3NginxPortForward(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			stdout, stderr := newOutputLog(), newOutputLog()
			spec := guestSpec{
				plat:     b.plat,
				image:    "nginx:alpine",
				net:      gvx.NetModeNAT,
				forwards: []gvx.PortForward{{HostPort: 0, GuestPort: 80, Protocol: "tcp", BindAddress: "127.0.0.1"}},
			}
			sb, err := gvx.New(ctx, spec.config(sharedCacheDir(t), stdout, stderr))
			if err != nil {
				t.Fatalf("gvx.New(%s, nginx:alpine) failed: %v", b.name, err)
			}
			defer func() {
				if err := sb.Close(); err != nil {
					t.Errorf("Close failed: %v", err)
				}
			}()
			hostPort := sb.BoundPort(0)
			if hostPort == 0 {
				t.Fatalf("BoundPort(0) = 0, want the ephemeral host port")
			}

			// nginx never exits on its own. Stopping it ends Run with the
			// context error. The deferred stop also covers failing paths, and
			// it runs before the sandbox closes.
			var res guestResult
			finished := make(chan struct{})
			runCtx, stopGuest := context.WithCancel(ctx)
			defer func() {
				stopGuest()
				<-finished
			}()
			go func() {
				defer close(finished)
				res.code, res.err = sb.Run(runCtx)
			}()

			// The error log reports readiness after nginx opened port 80.
			stderr.waitFor(t, 0, nginxReady, 2*time.Minute, finished)

			base := "http://127.0.0.1:" + strconv.Itoa(hostPort)
			body, status := httpGet(t, ctx, base+"/")
			if status != http.StatusOK || !strings.Contains(body, "Welcome to nginx!") {
				t.Errorf("GET / = (%d, %q), want 200 and the default page", status, body)
			}
			body, status = httpGet(t, ctx, base+"/gvx-missing.html")
			if status != http.StatusNotFound || !strings.Contains(body, "404 Not Found") {
				t.Errorf("GET /gvx-missing.html = (%d, %q), want nginx 404 page", status, body)
			}
			// The guest access log proves the requests crossed the Netstack.
			stdout.waitFor(t, 0, `"GET / HTTP/1.1" 200`, time.Minute, finished)

			stopGuest()
			<-finished
			if !errors.Is(res.err, context.Canceled) {
				t.Errorf("Run after stop = (%d, %v), want context.Canceled", res.code, res.err)
			}
		})
	}
}

// httpGet fetches url from the host and returns the body and status code.
func httpGet(t *testing.T, ctx context.Context, url string) (string, int) {
	t.Helper()
	reqCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", url, err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close body of %s: %v", url, err)
		}
	}()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body of %s: %v", url, err)
	}
	return string(body), resp.StatusCode
}

// pythonLoopbackScript hashes, encodes JSON, parses a URL, and runs an HTTP
// server and client on the guest loopback interface.
const pythonLoopbackScript = `
import hashlib, json, sys, threading, urllib.parse, urllib.request, http.server

data = b"gvx"
print("sha256=" + hashlib.sha256(data).hexdigest())
print("sha1=" + hashlib.sha1(data).hexdigest())
print("md5=" + hashlib.md5(data).hexdigest())
print("json=" + json.dumps(json.loads('{"b": [1, 2, {"c": null}], "a": "x"}'), sort_keys=True))
u = urllib.parse.urlparse("http://example.test:8080/p/q?x=1&y=2#frag")
print("url=%s|%s|%s|%s" % (u.hostname, u.port, u.path, sorted(urllib.parse.parse_qs(u.query).items())))

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "agent": self.headers.get("User-Agent", "")[:12]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
reply = urllib.request.urlopen("http://127.0.0.1:%d/loop?n=7" % server.server_port, timeout=30).read()
print("loopback=" + reply.decode())
server.shutdown()
server.server_close()
print("python=" + sys.version.split()[0])
`

func TestE2EGateM3PythonAlpine(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "python:3.12-alpine",
				argv:  []string{"python3", "-c", pythonLoopbackScript},
			})
			data := []byte("gvx")
			s256, s1, m5 := sha256.Sum256(data), sha1.Sum(data), md5.Sum(data)
			requireContains(t, "python output", out,
				"sha256="+hex.EncodeToString(s256[:])+"\n",
				"sha1="+hex.EncodeToString(s1[:])+"\n",
				"md5="+hex.EncodeToString(m5[:])+"\n",
				`json={"a": "x", "b": [1, 2, {"c": null}]}`+"\n",
				"url=example.test|8080|/p/q|[('x', ['1']), ('y', ['2'])]\n",
				`loopback={"path": "/loop?n=7", "agent": "Python-urlli"}`+"\n",
				"python=3.12.")
		})
	}
}

// nodeScript hashes, compresses, and talks to its own HTTP server on loopback.
const nodeScript = `
const crypto = require("crypto"), zlib = require("zlib"), http = require("http"), fs = require("fs");
console.log("sha256=" + crypto.createHash("sha256").update("gvx").digest("hex"));
console.log("sha1=" + crypto.createHash("sha1").update("gvx").digest("hex"));
console.log("md5=" + crypto.createHash("md5").update("gvx").digest("hex"));
const packed = zlib.gzipSync(Buffer.from("gvx-".repeat(1000)));
console.log("gunzip=" + zlib.gunzipSync(packed).length + " packed-smaller=" + (packed.length < 200));
fs.writeFileSync("/tmp/gvx-node.txt", "node-fs-ok");
console.log("fs=" + fs.readFileSync("/tmp/gvx-node.txt", "utf8"));
console.log("jit=" + [1, 2, 3, 4].map((x) => new Function("a", "return a * a")(x)).reduce((a, b) => a + b));
const server = http.createServer((req, res) => {
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify({ url: req.url, method: req.method }));
});
server.listen(0, "127.0.0.1", () => {
  http.get({ host: "127.0.0.1", port: server.address().port, path: "/loop?n=7" }, (res) => {
    let body = "";
    res.on("data", (chunk) => { body += chunk; });
    res.on("end", () => {
      console.log("loopback=" + body);
      console.log("node=" + process.version + " arch=" + process.arch);
      server.close();
    });
  });
});
`

func TestE2EGateM3NodeAlpine(t *testing.T) {
	for _, b := range gateBackends() {
		t.Run(b.name, func(t *testing.T) {
			requireBackend(t, b)
			requireRegistry(t)
			out := mustRunGuest(t, guestSpec{
				plat:  b.plat,
				image: "node:22-alpine",
				argv:  []string{"node", "-e", nodeScript},
			})
			data := []byte("gvx")
			s256, s1, m5 := sha256.Sum256(data), sha1.Sum(data), md5.Sum(data)
			requireContains(t, "node output", out,
				"sha256="+hex.EncodeToString(s256[:])+"\n",
				"sha1="+hex.EncodeToString(s1[:])+"\n",
				"md5="+hex.EncodeToString(m5[:])+"\n",
				"gunzip=4000 packed-smaller=true\n",
				"fs=node-fs-ok\n",
				"jit=30\n",
				`loopback={"url":"/loop?n=7","method":"GET"}`+"\n",
				"node=v22.")
			wantArch := map[string]string{"arm64": "arm64", "amd64": "x64"}[hostArch()]
			requireContains(t, "node arch", out, "arch="+wantArch)
		})
	}
}

// TestE2EGateM3ArchitectureSelection verifies the manifest choice per
// architecture. A pull for the other architecture caches a different
// manifest, and a run for it fails on the hardware backends, because the
// guest architecture must equal the host architecture there.
func TestE2EGateM3ArchitectureSelection(t *testing.T) {
	requireRegistry(t)
	rungv := toolPath(t, rungvPkg)
	cacheDir := t.TempDir()
	foreign := otherArch()
	host := hostArch()

	for _, arch := range []string{foreign, host} {
		stdout, stderr, code := runTool(t, rungv, "pull", "-arch="+arch, "-cache-dir="+cacheDir, "alpine:3.20")
		if code != 0 || !strings.Contains(stdout, "Digest: sha256:") {
			t.Fatalf("rungv pull -arch=%s alpine:3.20 = (code %d, stdout %q, stderr %q)", arch, code, stdout, stderr)
		}
	}

	cache, err := gvx.NewLayerCache(cacheDir)
	if err != nil {
		t.Fatalf("open layer cache: %v", err)
	}
	repo := oci.NormalizeRegistryRepo(oci.DefaultRegistryBaseURL, "alpine")
	layerDigests := map[string]string{}
	for _, arch := range []string{foreign, host} {
		img, err := cache.LoadCachedImage(oci.DefaultRegistryBaseURL, repo, "3.20", arch)
		if err != nil {
			t.Fatalf("LoadCachedImage(%s) after pull: %v", arch, err)
		}
		layerDigests[arch] = strings.Join(img.LayerDigests, ",")
		if img.Architecture != arch || len(img.LayerPaths) == 0 {
			t.Errorf("cached %s image = (arch %q, %d layers), want the requested architecture and layers", arch, img.Architecture, len(img.LayerPaths))
		}
		for _, p := range img.LayerPaths {
			if _, err := os.Stat(p); err != nil {
				t.Errorf("cached %s layer %s: %v", arch, filepath.Base(p), err)
			}
		}
		if err := img.Close(); err != nil {
			t.Errorf("close cached %s image: %v", arch, err)
		}
	}
	// The index digest is shared. The layer blobs differ per architecture.
	if layerDigests[foreign] == "" || layerDigests[foreign] == layerDigests[host] {
		t.Errorf("layer digests = %v, want distinct non-empty layer sets per architecture", layerDigests)
	}
	if cachedConfigArch(t, cacheDir, foreign) != foreign || cachedConfigArch(t, cacheDir, host) != host {
		t.Errorf("cached image configs do not carry the requested architectures")
	}

	// A foreign architecture is a usage error on the hardware backend,
	// whether the user names the backend or leaves the choice to auto.
	for _, plat := range []string{string(autoPlatform()), "auto"} {
		_, stderr, code := runTool(t, rungv, "run", "-lockdown=false", "-platform="+plat, "-net=none",
			"-arch="+foreign, "-cache-dir="+cacheDir, "-image=alpine:3.20", "--", "/bin/true")
		wantErr, wantTail := "guest architecture "+foreign+" needs -platform=systrap", "run only the host architecture"
		if runtime.GOOS == "linux" {
			wantErr, wantTail = "guest architecture "+foreign+" cannot run on a", "only the host architecture"
		}
		if code != 2 || !strings.Contains(stderr, wantErr) || !strings.Contains(stderr, wantTail) {
			t.Errorf("rungv run -platform=%s -arch=%s = (code %d, stderr %q), want usage error %q", plat, foreign, code, stderr, wantErr)
		}
	}
	_, err = gvx.New(context.Background(), gvx.Config{
		Platform:            autoPlatform(),
		Architecture:        foreign,
		NetworkMode:         gvx.NetModeNone,
		OCIImage:            "alpine:3.20",
		OCICacheDir:         cacheDir,
		DisableHostLockdown: true,
	})
	if !errors.Is(err, gvx.ErrInvalidConfig) {
		t.Errorf("gvx.New with a foreign architecture on %s = %v, want ErrInvalidConfig", autoPlatform(), err)
	}

	// The host architecture runs from the same cache.
	_, _, code := runTool(t, rungv, "run", "-lockdown=false", "-platform="+string(autoPlatform()), "-net=none",
		"-cache-dir="+cacheDir, "-image=alpine:3.20", "--", "/bin/true")
	if code != 0 {
		t.Errorf("rungv run of the host architecture exit code = %d, want 0", code)
	}
}

// cachedConfigArch reads the architecture field of the verbatim image config
// that the pull stored for arch.
func cachedConfigArch(t *testing.T, cacheDir, arch string) string {
	t.Helper()
	records, err := filepath.Glob(filepath.Join(cacheDir, "image-*.json"))
	if err != nil {
		t.Fatalf("glob image records: %v", err)
	}
	for _, p := range records {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("read image record %s: %v", p, err)
		}
		var rec struct {
			Architecture string `json:"architecture"`
			Config       []byte `json:"config"`
		}
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatalf("decode image record %s: %v", p, err)
		}
		if rec.Architecture != arch {
			continue
		}
		var cfg struct {
			Architecture string `json:"architecture"`
		}
		if err := json.Unmarshal(rec.Config, &cfg); err != nil {
			t.Fatalf("decode image config of %s: %v", p, err)
		}
		return cfg.Architecture
	}
	t.Fatalf("no cached image record for architecture %s in %s", arch, cacheDir)
	return ""
}
