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

package oci

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testRepo = "app"

// testImage is a single-architecture image in registry form.
type testImage struct {
	arch      string
	rawLayers [][]byte
	blobs     [][]byte
	config    []byte
	manifest  []byte
}

func newTestImage(t testing.TB, arch string, env string, rawLayers ...[]byte) *testImage {
	t.Helper()
	img := &testImage{arch: arch, rawLayers: rawLayers}
	var diffIDs []string
	var layerDescs []Descriptor
	for _, raw := range rawLayers {
		blob := gzipBytes(t, raw)
		img.blobs = append(img.blobs, blob)
		diffIDs = append(diffIDs, sha256Digest(raw))
		layerDescs = append(layerDescs, Descriptor{
			MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: sha256Digest(blob), Size: int64(len(blob)),
		})
	}
	cfg := map[string]any{
		"architecture": arch, "os": "linux",
		"config": map[string]any{"Env": []string{env}, "Cmd": []string{"/bin/true"}, "WorkingDir": "/w"},
		"rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs},
	}
	var err error
	if img.config, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	img.manifest, err = json.Marshal(ImageManifest{
		SchemaVersion: 2, MediaType: mediaTypeOCIManifest,
		Config: Descriptor{MediaType: mediaTypeOCIConfig, Digest: sha256Digest(img.config), Size: int64(len(img.config))},
		Layers: layerDescs,
	})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func (i *testImage) digest() string { return sha256Digest(i.manifest) }

// fakeRegistry is an in-process OCI distribution registry.
type fakeRegistry struct {
	srv *httptest.Server

	mu        sync.Mutex
	manifests map[string][]byte
	blobs     map[string][]byte
	tags      map[string]string
	requests  map[string]int

	// noDigestHeader makes HEAD answers omit Docker-Content-Digest.
	noDigestHeader bool
	// headStatus overrides the status of HEAD requests when nonzero.
	headStatus int
	// tamperBlob serves other bytes than the registered ones.
	tamperBlob map[string][]byte
	// requireToken demands "Authorization: Bearer <token>" and answers other
	// requests with a challenge that names realm.
	requireToken string
	realm        string
	// basicUser and basicPass demand HTTP basic credentials when set.
	basicUser, basicPass string
	// onBlob replaces the blob handler when set.
	onBlob func(w http.ResponseWriter, r *http.Request, digest string) bool
	// onManifest replaces the manifest handler when set.
	onManifest func(w http.ResponseWriter, r *http.Request, ref string) bool
}

func newFakeRegistry(t *testing.T) *fakeRegistry {
	t.Helper()
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	r := &fakeRegistry{
		manifests: map[string][]byte{}, blobs: map[string][]byte{}, tags: map[string]string{},
		requests: map[string]int{}, tamperBlob: map[string][]byte{},
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakeRegistry) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests[key]
}

func (r *fakeRegistry) total() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.requests {
		n += c
	}
	return n
}

func (r *fakeRegistry) addImage(img *testImage) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, blob := range img.blobs {
		r.blobs[sha256Digest(blob)] = blob
	}
	r.blobs[sha256Digest(img.config)] = img.config
	r.manifests[img.digest()] = img.manifest
	return img.digest()
}

func (r *fakeRegistry) addManifest(body []byte) string {
	r.mu.Lock()
	defer r.mu.Unlock()
	d := sha256Digest(body)
	r.manifests[d] = body
	return d
}

func (r *fakeRegistry) tag(tag, digest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tags[tag] = digest
}

func (r *fakeRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if r.basicUser != "" {
		if user, pass, ok := req.BasicAuth(); !ok || user != r.basicUser || pass != r.basicPass {
			w.Header().Set("Www-Authenticate", `Basic realm="reg"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
	}
	if r.requireToken != "" && req.Header.Get("Authorization") != "Bearer "+r.requireToken {
		w.Header().Set("Www-Authenticate", fmt.Sprintf(`Bearer realm=%q,service="reg",scope="repository:%s:pull,push"`, r.realm, testRepo))
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	prefix := "/v2/" + testRepo + "/"
	rest, ok := strings.CutPrefix(req.URL.Path, prefix)
	if !ok {
		http.NotFound(w, req)
		return
	}
	kind, ref, _ := strings.Cut(rest, "/")
	switch kind {
	case "manifests":
		r.serveManifest(w, req, ref)
	case "blobs":
		r.serveBlob(w, req, ref)
	default:
		http.NotFound(w, req)
	}
}

func (r *fakeRegistry) serveManifest(w http.ResponseWriter, req *http.Request, ref string) {
	r.mu.Lock()
	r.requests[req.Method+" manifest"]++
	if strings.HasPrefix(ref, "sha256:") {
		r.requests[req.Method+" manifest-by-digest"]++
	} else {
		r.requests[req.Method+" manifest-by-tag"]++
	}
	hook := r.onManifest
	digest := ref
	if d, ok := r.tags[ref]; ok {
		digest = d
	}
	body, found := r.manifests[digest]
	r.mu.Unlock()
	if hook != nil && hook(w, req, ref) {
		return
	}
	if req.Method == http.MethodHead && r.headStatus != 0 {
		w.WriteHeader(r.headStatus)
		return
	}
	if !found {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Type", mediaTypeOCIManifest)
	if !r.noDigestHeader || req.Method == http.MethodGet {
		w.Header().Set("Docker-Content-Digest", digest)
	}
	if req.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		return
	}
	_, _ = w.Write(body)
}

func (r *fakeRegistry) serveBlob(w http.ResponseWriter, req *http.Request, digest string) {
	r.mu.Lock()
	r.requests[req.Method+" blob"]++
	body, found := r.blobs[digest]
	if t, ok := r.tamperBlob[digest]; ok {
		body = t
	}
	hook := r.onBlob
	r.mu.Unlock()
	if hook != nil && hook(w, req, digest) {
		return
	}
	if !found {
		http.NotFound(w, req)
		return
	}
	_, _ = w.Write(body)
}

func pullArgs(r *fakeRegistry) (string, string) { return r.srv.URL, testRepo }

func twoLayerImage(t testing.TB, arch, env string) *testImage {
	return newTestImage(t, arch, env,
		buildTar(t, dirEntry("etc/"), fileEntry("etc/os-release", "base-"+arch)),
		buildTar(t, dirEntry("etc/"), fileEntry("etc/.wh.hostname", ""), fileEntry("app", "app-"+arch)),
	)
}

func newCache(t testing.TB) *LayerCache {
	t.Helper()
	c, err := newCacheAt(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func mustPull(t *testing.T, reg *fakeRegistry, cache *LayerCache, ref, arch string) *ResolvedImage {
	t.Helper()
	base, repo := pullArgs(reg)
	img, err := PullRegistryImage(context.Background(), nil, base, repo, ref, arch, cache)
	if err != nil {
		t.Fatalf("PullRegistryImage(%s, %s): %v", ref, arch, err)
	}
	t.Cleanup(func() { _ = img.Close() })
	return img
}

func TestPullSelectsTheManifestForEachArchitecture(t *testing.T) {
	reg := newFakeRegistry(t)
	amd, arm := twoLayerImage(t, "amd64", "A=amd"), twoLayerImage(t, "arm64", "A=arm")
	index, err := json.Marshal(ImageIndex{SchemaVersion: 2, MediaType: mediaTypeOCIIndex, Manifests: []Descriptor{
		{MediaType: mediaTypeOCIManifest, Digest: sha256Digest([]byte("attestation")), Size: 11, Platform: &PlatformSpec{OS: "unknown", Architecture: "unknown"}},
		{MediaType: mediaTypeOCIManifest, Digest: amd.digest(), Size: int64(len(amd.manifest)), Platform: &PlatformSpec{OS: "linux", Architecture: "amd64"}},
		{MediaType: mediaTypeOCIManifest, Digest: arm.digest(), Size: int64(len(arm.manifest)), Platform: &PlatformSpec{OS: "linux", Architecture: "arm64", Variant: "v8"}},
		{MediaType: mediaTypeOCIManifest, Digest: sha256Digest([]byte("windows")), Size: 7, Platform: &PlatformSpec{OS: "windows", Architecture: "amd64"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	reg.addImage(amd)
	reg.addImage(arm)
	reg.tag("latest", reg.addManifest(index))

	cache := newCache(t)
	for arch, want := range map[string]string{"amd64": "base-amd64", "arm64": "base-arm64", "x86_64": "base-amd64", "aarch64": "base-arm64"} {
		img := mustPull(t, reg, cache, "latest", arch)
		if len(img.LayerFiles) != 2 || len(img.LayerPaths) != 2 || len(img.LayerDigests) != 2 {
			t.Fatalf("%s: image has %d handles, %d paths, %d digests", arch, len(img.LayerFiles), len(img.LayerPaths), len(img.LayerDigests))
		}
		if got := string(readImage(t, img.LayerPaths[0])["/etc/os-release"].content); got != want {
			t.Errorf("%s: base layer holds %q, want %q", arch, got, want)
		}
		if wh := readImage(t, img.LayerPaths[1])["/etc/hostname"]; wh == nil || wh.mode != 0o020000 {
			t.Errorf("%s: whiteout of /etc/hostname = %+v", arch, wh)
		}
		if img.Config.WorkingDir != "/w" || len(img.Config.Env) != 1 || img.Config.Cmd[0] != "/bin/true" {
			t.Errorf("%s: config = %+v", arch, img.Config)
		}
		if img.Architecture != normalizeArch(arch) {
			t.Errorf("%s: Architecture = %q", arch, img.Architecture)
		}
	}
	if reg.count("GET manifest-by-digest") == 0 {
		t.Error("the sub-manifest was not fetched by digest")
	}

	base, repo := pullArgs(reg)
	_, err = PullRegistryImage(context.Background(), nil, base, repo, "latest", "riscv64", cache)
	if err == nil || !strings.Contains(err.Error(), "no linux/riscv64 manifest") {
		t.Errorf("unknown architecture: err = %v", err)
	}
}

func TestPullRejectsImagesForAnotherArchitecture(t *testing.T) {
	reg := newFakeRegistry(t)
	arm := twoLayerImage(t, "arm64", "A=arm")
	reg.tag("latest", reg.addImage(arm))
	base, repo := pullArgs(reg)
	_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
	if err == nil || !strings.Contains(err.Error(), "architecture") {
		t.Errorf("err = %v, want an architecture mismatch", err)
	}
}

func TestPullVerifiesEveryDigest(t *testing.T) {
	good := twoLayerImage(t, "amd64", "A=1")
	evilLayer := buildTar(t, fileEntry("evil", "x"))

	cases := map[string]func(reg *fakeRegistry){
		"layer bytes": func(reg *fakeRegistry) {
			reg.tamperBlob[sha256Digest(good.blobs[1])] = gzipBytes(t, evilLayer)
		},
		"config bytes": func(reg *fakeRegistry) {
			reg.tamperBlob[sha256Digest(good.config)] = []byte(strings.Replace(string(good.config), "A=1", "A=2", 1))
		},
		"manifest bytes": func(reg *fakeRegistry) {
			other := twoLayerImage(t, "amd64", "A=other")
			reg.manifests[good.digest()] = other.manifest
		},
		"layer size": func(reg *fakeRegistry) {
			var m ImageManifest
			if err := json.Unmarshal(good.manifest, &m); err != nil {
				t.Fatal(err)
			}
			m.Layers[1].Size++
			body, _ := json.Marshal(m)
			reg.manifests[good.digest()] = body
			reg.tags["latest"] = sha256Digest(body)
			reg.manifests[sha256Digest(body)] = body
		},
	}
	for name, tamper := range cases {
		t.Run(name, func(t *testing.T) {
			reg := newFakeRegistry(t)
			reg.tag("latest", reg.addImage(good))
			tamper(reg)
			cache := newCache(t)
			base, repo := pullArgs(reg)
			_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", cache)
			if !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("err = %v, want ErrDigestMismatch", err)
			}
			assertNoTempFiles(t, cache.Dir())
		})
	}
}

func TestPullRejectsATamperedLayerWithoutCachingIt(t *testing.T) {
	good := twoLayerImage(t, "amd64", "A=1")
	reg := newFakeRegistry(t)
	reg.tag("latest", reg.addImage(good))
	// A valid tar that is not the layer the manifest names.
	reg.tamperBlob[sha256Digest(good.blobs[1])] = gzipBytes(t, buildTar(t, fileEntry("evil", "x")))

	cache := newCache(t)
	base, repo := pullArgs(reg)
	if _, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", cache); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("err = %v, want ErrDigestMismatch", err)
	}
	hexStr, _ := parseDigest(sha256Digest(good.blobs[1]))
	if _, ok := cache.HasLayer(hexStr); ok {
		t.Error("the tampered layer is in the cache")
	}
	assertNoTempFiles(t, cache.Dir())
}

func assertNoTempFiles(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 0 {
		t.Errorf("temporary files left in the cache: %v", matches)
	}
}

func TestPullRevalidatesTagsAndCachesByDigest(t *testing.T) {
	reg := newFakeRegistry(t)
	v1 := twoLayerImage(t, "amd64", "V=1")
	reg.tag("latest", reg.addImage(v1))
	cache := newCache(t)

	first := mustPull(t, reg, cache, "latest", "amd64")
	if first.ManifestDigest != v1.digest() {
		t.Errorf("ManifestDigest = %q, want %q", first.ManifestDigest, v1.digest())
	}

	// An unchanged tag costs one HEAD request and no downloads.
	getsBefore := reg.count("GET manifest") + reg.count("GET blob")
	mustPull(t, reg, cache, "latest", "amd64")
	if reg.count("HEAD manifest-by-tag") != 2 {
		t.Errorf("HEAD by tag = %d, want 1 per pull", reg.count("HEAD manifest-by-tag"))
	}
	if got := reg.count("GET manifest") + reg.count("GET blob"); got != getsBefore {
		t.Errorf("an unchanged tag caused %d more GET requests", got-getsBefore)
	}

	// Moving the tag is observed and the new image replaces the old one.
	v2 := newTestImage(t, "amd64", "V=2", v1.rawLayers[0], buildTar(t, fileEntry("app", "v2")))
	reg.tag("latest", reg.addImage(v2))
	moved := mustPull(t, reg, cache, "latest", "amd64")
	if moved.ManifestDigest != v2.digest() || moved.Config.Env[0] != "V=2" {
		t.Errorf("after the tag moved: digest %q env %v", moved.ManifestDigest, moved.Config.Env)
	}
	if string(readImage(t, moved.LayerPaths[1])["/app"].content) != "v2" {
		t.Error("the moved tag still serves the old layer")
	}
	if moved.LayerDigests[0] != first.LayerDigests[0] {
		t.Error("the shared base layer was not reused")
	}
}

func TestPullByDigestNeedsNoNetworkOnceCached(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.addImage(img)
	cache := newCache(t)
	mustPull(t, reg, cache, img.digest(), "amd64")
	before := reg.total()

	// A fresh cache object models a new process over the same directory.
	again, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	reg.srv.Close()
	base, repo := pullArgs(reg)
	got, err := PullRegistryImage(context.Background(), nil, base, repo, img.digest(), "amd64", again)
	if err != nil {
		t.Fatalf("cached digest pull with the registry down: %v", err)
	}
	defer got.Close()
	if reg.total() != before {
		t.Error("a cached digest pull sent requests")
	}
	if got.Config.WorkingDir != "/w" || len(got.LayerFiles) != 2 {
		t.Errorf("cached image = %+v", got)
	}
}

func TestLoadCachedImageServesTagsOffline(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.tag("v1", reg.addImage(img))
	cache := newCache(t)
	mustPull(t, reg, cache, "v1", "amd64")
	base, repo := pullArgs(reg)
	reg.srv.Close()

	fresh, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	got, err := fresh.LoadCachedImage(base, repo, "v1", "amd64")
	if err != nil {
		t.Fatalf("LoadCachedImage: %v", err)
	}
	defer got.Close()
	if got.ManifestDigest != img.digest() || len(got.LayerFiles) != 2 {
		t.Errorf("cached image = %+v", got)
	}
	if _, err := fresh.LoadCachedImage(base, repo, "never-pulled", "amd64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("unknown tag: err = %v, want ErrNotCached", err)
	}
	if _, err := fresh.LoadCachedImage(base, repo, "v1", "arm64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("other architecture: err = %v, want ErrNotCached", err)
	}
	if _, err := PullRegistryImage(context.Background(), nil, base, repo, "v1", "amd64", fresh); err == nil {
		t.Error("a tag pull with the registry down succeeded, want a network error")
	}
}

func TestLoadCachedImageRejectsEditedRecordsAndDamagedLayers(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.tag("v1", reg.addImage(img))
	cache := newCache(t)
	first := mustPull(t, reg, cache, "v1", "amd64")
	base, repo := pullArgs(reg)

	t.Run("edited config", func(t *testing.T) {
		recPath := cache.imageRecordPath(base, repo, img.digest(), "amd64")
		raw, err := os.ReadFile(recPath)
		if err != nil {
			t.Fatal(err)
		}
		var rec imageRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			t.Fatal(err)
		}
		rec.Config = []byte(strings.Replace(string(rec.Config), "A=1", "A=evil", 1))
		edited, _ := json.Marshal(rec)
		if err := os.WriteFile(recPath, edited, 0o644); err != nil {
			t.Fatal(err)
		}
		defer os.WriteFile(recPath, raw, 0o644)
		fresh, _ := newCacheAt(cache.Dir())
		if _, err := fresh.LoadCachedImage(base, repo, "v1", "amd64"); err == nil {
			t.Error("an edited image record was accepted")
		}
	})

	t.Run("damaged layer", func(t *testing.T) {
		p := first.LayerPaths[1]
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		damaged := append([]byte(nil), raw...)
		damaged[len(damaged)-1] ^= 0xFF
		if err := os.WriteFile(p, damaged, 0o644); err != nil {
			t.Fatal(err)
		}
		fresh, _ := newCacheAt(cache.Dir())
		if _, err := fresh.LoadCachedImage(base, repo, "v1", "amd64"); !errors.Is(err, ErrNotCached) {
			t.Errorf("damaged layer: err = %v, want ErrNotCached", err)
		}
		if _, err := fresh.OpenLayerHandles(first.LayerDigests); !errors.Is(err, ErrCacheCorrupt) {
			t.Errorf("OpenLayerHandles on a damaged layer: err = %v, want ErrCacheCorrupt", err)
		}

		// A pull recompiles the damaged layer from the registry.
		again, err := PullRegistryImage(context.Background(), nil, base, repo, "v1", "amd64", fresh)
		if err != nil {
			t.Fatalf("pull over a damaged cache: %v", err)
		}
		defer again.Close()
		if got, err := os.ReadFile(p); err != nil || string(got) != string(raw) {
			t.Errorf("the damaged layer was not rebuilt (err %v)", err)
		}
	})

	t.Run("missing integrity record", func(t *testing.T) {
		hexStr := first.LayerDigests[0]
		sum := filepath.Join(cache.Dir(), hexStr+cache.sumSuffix())
		if err := os.Remove(sum); err != nil {
			t.Fatal(err)
		}
		fresh, _ := newCacheAt(cache.Dir())
		if _, ok := fresh.HasLayer(hexStr); ok {
			t.Error("a layer without an integrity record was trusted")
		}
	})
}

func TestImportCachedImageCopiesLayersWithIntegrityRecords(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.tag("v1", reg.addImage(img))
	src := newCache(t)
	mustPull(t, reg, src, "v1", "amd64")
	base, repo := pullArgs(reg)

	dst := newCache(t)
	got, err := dst.ImportCachedImage(src, base, repo, "v1", "amd64")
	if err != nil {
		t.Fatalf("ImportCachedImage: %v", err)
	}
	defer got.Close()
	if filepath.Dir(got.LayerPaths[0]) != dst.Dir() {
		t.Errorf("imported layer path %q is outside the destination cache", got.LayerPaths[0])
	}
	reg.srv.Close()
	fresh, _ := newCacheAt(dst.Dir())
	again, err := fresh.LoadCachedImage(base, repo, "v1", "amd64")
	if err != nil {
		t.Fatalf("destination cache cannot serve the imported image: %v", err)
	}
	again.Close()
	if _, err := newCache(t).ImportCachedImage(src, base, repo, "other", "amd64"); !errors.Is(err, ErrNotCached) {
		t.Errorf("import of an uncached tag: err = %v, want ErrNotCached", err)
	}
	assertNoTempFiles(t, dst.Dir())
}

func TestPullHandlesRegistryFailures(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")
	t.Run("unknown tag is 404", func(t *testing.T) {
		reg := newFakeRegistry(t)
		base, repo := pullArgs(reg)
		_, err := PullRegistryImage(context.Background(), nil, base, repo, "nope", "amd64", newCache(t))
		var se *StatusError
		if !errors.As(err, &se) || se.StatusCode != http.StatusNotFound {
			t.Errorf("err = %v, want a 404 StatusError", err)
		}
	})
	t.Run("server error is 500", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.onManifest = func(w http.ResponseWriter, r *http.Request, ref string) bool {
			w.WriteHeader(http.StatusInternalServerError)
			return true
		}
		base, repo := pullArgs(reg)
		_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
		var se *StatusError
		if !errors.As(err, &se) || se.StatusCode != http.StatusInternalServerError {
			t.Errorf("err = %v, want a 500 StatusError", err)
		}
	})
	t.Run("missing layer blob is 404", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("latest", reg.addImage(img))
		delete(reg.blobs, sha256Digest(img.blobs[0]))
		base, repo := pullArgs(reg)
		_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
		var se *StatusError
		if !errors.As(err, &se) || se.StatusCode != http.StatusNotFound {
			t.Errorf("err = %v, want a 404 StatusError", err)
		}
	})
	t.Run("deadline stops a hanging registry", func(t *testing.T) {
		reg := newFakeRegistry(t)
		release := make(chan struct{})
		reg.onManifest = func(w http.ResponseWriter, r *http.Request, ref string) bool {
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return true
		}
		t.Cleanup(func() { close(release) })
		base, repo := pullArgs(reg)
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, err := PullRegistryImage(ctx, nil, base, repo, "latest", "amd64", newCache(t))
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("err = %v, want context.DeadlineExceeded", err)
		}
	})
	t.Run("HEAD not allowed falls back to GET", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.headStatus = http.StatusMethodNotAllowed
		reg.tag("latest", reg.addImage(img))
		got := mustPull(t, reg, newCache(t), "latest", "amd64")
		if got.ManifestDigest != img.digest() {
			t.Errorf("digest = %q", got.ManifestDigest)
		}
	})
	t.Run("HEAD without a digest header falls back to GET", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.noDigestHeader = true
		reg.tag("latest", reg.addImage(img))
		got := mustPull(t, reg, newCache(t), "latest", "amd64")
		if got.ManifestDigest != img.digest() {
			t.Errorf("digest = %q", got.ManifestDigest)
		}
	})
	t.Run("schema 1 manifests are refused", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("latest", reg.addManifest([]byte(`{"schemaVersion":1,"name":"app","fsLayers":[]}`)))
		base, repo := pullArgs(reg)
		_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
		if err == nil || !strings.Contains(err.Error(), "schema 1") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("foreign layers are refused", func(t *testing.T) {
		reg := newFakeRegistry(t)
		var m ImageManifest
		if err := json.Unmarshal(img.manifest, &m); err != nil {
			t.Fatal(err)
		}
		m.Layers[0].URLs = []string{"https://elsewhere.example/blob"}
		body, _ := json.Marshal(m)
		reg.addImage(img)
		reg.tag("latest", reg.addManifest(body))
		base, repo := pullArgs(reg)
		_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
		if err == nil || !strings.Contains(err.Error(), "foreign") {
			t.Errorf("err = %v", err)
		}
	})
}

func TestRegistryClientFailsWhenTheBodyStalls(t *testing.T) {
	reg := newFakeRegistry(t)
	release := make(chan struct{})
	reg.onBlob = func(w http.ResponseWriter, r *http.Request, digest string) bool {
		_, _ = w.Write([]byte("first bytes"))
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
		}
		return true
	}
	t.Cleanup(func() { close(release) })
	rc, err := newRegistryClient(nil, reg.srv.URL, testRepo, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	defer rc.close()
	rc.idle = 100 * time.Millisecond
	body, err := rc.openBlob(context.Background(), sha256Digest([]byte("x")))
	if err != nil {
		t.Fatal(err)
	}
	defer body.Close()
	buf := make([]byte, 64)
	n, err := body.Read(buf)
	if err != nil || string(buf[:n]) != "first bytes" {
		t.Fatalf("first read = %q, %v", buf[:n], err)
	}
	if _, err := body.Read(buf); err == nil || !strings.Contains(err.Error(), "stalled") {
		t.Errorf("second read err = %v, want a stall error", err)
	}
}

func TestPullFollowsBlobRedirectsWithoutLeakingCredentials(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")
	reg := newFakeRegistry(t)
	reg.tag("latest", reg.addImage(img))

	var mu sync.Mutex
	var cdnAuth []string
	cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cdnAuth = append(cdnAuth, r.Header.Get("Authorization"))
		mu.Unlock()
		_, _ = w.Write(reg.blobs[strings.TrimPrefix(r.URL.Path, "/")])
	}))
	t.Cleanup(cdn.Close)

	// Registry and CDN are the same host on different ports. Go would keep
	// the Authorization header across that redirect.
	reg.requireToken = "secret"
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"token":"secret"}`)
	}))
	t.Cleanup(tokenSrv.Close)
	reg.realm = tokenSrv.URL + "/token"
	reg.onBlob = func(w http.ResponseWriter, r *http.Request, digest string) bool {
		http.Redirect(w, r, cdn.URL+"/"+digest, http.StatusTemporaryRedirect)
		return true
	}

	got := mustPull(t, reg, newCache(t), "latest", "amd64")
	if len(got.LayerFiles) != 2 {
		t.Fatalf("pulled %d layers", len(got.LayerFiles))
	}
	mu.Lock()
	defer mu.Unlock()
	if len(cdnAuth) != 3 {
		t.Fatalf("the CDN served %d blobs, want 2 layers and the config", len(cdnAuth))
	}
	for _, a := range cdnAuth {
		if a != "" {
			t.Errorf("the redirect target received Authorization %q", a)
		}
	}
}

func TestPullRefusesHTTPSToHTTPRedirects(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the plain http server was contacted")
	}))
	t.Cleanup(plain.Close)
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/x", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(secure.Close)
	t.Setenv("DOCKER_CONFIG", t.TempDir())

	_, err := PullRegistryImage(context.Background(), secure.Client(), secure.URL, testRepo, "latest", "amd64", newCache(t))
	if err == nil || !strings.Contains(err.Error(), "downgrades https") {
		t.Errorf("err = %v, want a refused downgrade", err)
	}
}

func TestPullRejectsOversizedRegistryBodies(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")
	reg := newFakeRegistry(t)
	reg.tag("latest", reg.addImage(img))
	cache := newCache(t)
	lim := DefaultLimits()
	lim.MaxJSONBytes = 100
	if err := cache.SetLimits(lim); err != nil {
		t.Fatal(err)
	}
	base, repo := pullArgs(reg)
	if _, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", cache); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("err = %v, want ErrLimitExceeded", err)
	}
}

func TestPullRejectsDecompressionBombLayers(t *testing.T) {
	bombTar := buildTar(t, fileEntry("zeros", string(make([]byte, 32<<20))))
	img := newTestImage(t, "amd64", "A=1", bombTar)
	reg := newFakeRegistry(t)
	reg.tag("latest", reg.addImage(img))
	cache := newCache(t)
	lim := DefaultLimits()
	lim.MaxImageBytes = 2 << 20
	if err := cache.SetLimits(lim); err != nil {
		t.Fatal(err)
	}
	base, repo := pullArgs(reg)
	if _, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", cache); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("err = %v, want ErrLimitExceeded", err)
	}
	assertNoTempFiles(t, cache.Dir())
	if matches, _ := filepath.Glob(filepath.Join(cache.Dir(), "*.erofs")); len(matches) != 0 {
		t.Errorf("a bomb layer was cached: %v", matches)
	}
}

// tokenServer answers token requests and records what it received.
type tokenServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []tokenRequest
}

type tokenRequest struct {
	method string
	auth   string
	query  url.Values
	form   url.Values
}

func newTokenServer(t *testing.T, token string) *tokenServer {
	ts := &tokenServer{}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		ts.mu.Lock()
		ts.requests = append(ts.requests, tokenRequest{method: r.Method, auth: r.Header.Get("Authorization"), query: r.URL.Query(), form: r.PostForm})
		ts.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"access_token":%q}`, token)
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func writeDockerConfig(t *testing.T, key, user, pass, identity string) {
	t.Helper()
	dir := t.TempDir()
	entry := map[string]string{}
	switch {
	case identity != "":
		entry["identitytoken"] = identity
	default:
		entry["auth"] = base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
	}
	raw, err := json.Marshal(map[string]any{"auths": map[string]any{key: entry}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_CONFIG", dir)
}

func TestPullSendsCredentialsOnlyToTheRegistryHost(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")

	t.Run("realm on the registry host receives them", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("latest", reg.addImage(img))
		reg.requireToken = "tok"
		// The token endpoint is served by the registry itself.
		mux := http.NewServeMux()
		var got tokenRequest
		var mu sync.Mutex
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			got = tokenRequest{auth: r.Header.Get("Authorization"), query: r.URL.Query()}
			mu.Unlock()
			_, _ = fmt.Fprint(w, `{"token":"tok"}`)
		})
		mux.HandleFunc("/", reg.serve)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		reg.realm = srv.URL + "/token"
		writeDockerConfig(t, srv.URL, "alice", "s3cret", "")

		if _, err := PullRegistryImage(context.Background(), nil, srv.URL, testRepo, "latest", "amd64", newCache(t)); err != nil {
			t.Fatalf("pull: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:s3cret"))
		if got.auth != wantAuth {
			t.Errorf("token request Authorization = %q, want %q", got.auth, wantAuth)
		}
		if got.query.Get("service") != "reg" || got.query.Get("scope") != "repository:app:pull,push" {
			t.Errorf("token query = %v, want service and the full comma separated scope", got.query)
		}
	})

	t.Run("realm on another host gets an anonymous request", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("latest", reg.addImage(img))
		reg.requireToken = "tok"
		ts := newTokenServer(t, "tok")
		// 127.0.0.1 and localhost are different hosts that reach the same server.
		reg.realm = strings.Replace(ts.srv.URL, "127.0.0.1", "localhost", 1) + "/token"
		writeDockerConfig(t, reg.srv.URL, "alice", "s3cret", "")

		base, repo := pullArgs(reg)
		if _, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t)); err != nil {
			t.Fatalf("pull: %v", err)
		}
		ts.mu.Lock()
		defer ts.mu.Unlock()
		if len(ts.requests) == 0 {
			t.Fatal("the token endpoint was never asked")
		}
		for _, r := range ts.requests {
			if r.auth != "" {
				t.Errorf("a foreign realm received Authorization %q", r.auth)
			}
		}
	})

	t.Run("identity token uses the refresh grant", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("latest", reg.addImage(img))
		reg.requireToken = "tok"
		mux := http.NewServeMux()
		var got tokenRequest
		var mu sync.Mutex
		mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			mu.Lock()
			got = tokenRequest{method: r.Method, auth: r.Header.Get("Authorization"), form: r.PostForm}
			mu.Unlock()
			_, _ = fmt.Fprint(w, `{"token":"tok"}`)
		})
		mux.HandleFunc("/", reg.serve)
		srv := httptest.NewServer(mux)
		t.Cleanup(srv.Close)
		reg.realm = srv.URL + "/token"
		writeDockerConfig(t, srv.URL, "", "", "refresh-me")
		if _, err := PullRegistryImage(context.Background(), nil, srv.URL, testRepo, "latest", "amd64", newCache(t)); err != nil {
			t.Fatalf("pull: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if got.method != http.MethodPost || got.form.Get("grant_type") != "refresh_token" || got.form.Get("refresh_token") != "refresh-me" || got.auth != "" {
			t.Errorf("token request = %+v", got)
		}
	})

	t.Run("basic challenge needs credentials", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.basicUser, reg.basicPass = "bob", "pw"
		reg.tag("latest", reg.addImage(img))
		base, repo := pullArgs(reg)
		if _, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t)); err == nil || !strings.Contains(err.Error(), "no credentials") {
			t.Errorf("without credentials: err = %v", err)
		}
		writeDockerConfig(t, reg.srv.URL, "bob", "pw", "")
		mustPull(t, reg, newCache(t), "latest", "amd64")
	})
}

func TestRealmCredentialPolicy(t *testing.T) {
	mustURL := func(s string) *url.URL {
		u, err := url.Parse(s)
		if err != nil {
			t.Fatal(err)
		}
		return u
	}
	for _, tc := range []struct {
		registry, realm string
		want            bool
	}{
		{"https://ghcr.io", "https://ghcr.io/token", true},
		{"https://ghcr.io:443", "https://ghcr.io/token", true},
		{"https://GHCR.io", "https://ghcr.io/token", true},
		{"http://localhost:5000", "http://localhost:5000/token", true},
		{"https://ghcr.io", "https://evil.example/token", false},
		{"https://ghcr.io", "https://ghcr.io.evil.example/token", false},
		{"https://ghcr.io", "http://ghcr.io/token", false},
		{"http://localhost:5000", "http://localhost:5001/token", false},
		{"https://registry-1.docker.io", "https://auth.docker.io/token", true},
		{"https://registry-1.docker.io", "https://evil.example/token", false},
		{"https://ghcr.io", "https://auth.docker.io/token", false},
	} {
		if got := realmMayReceiveCredentials(mustURL(tc.registry), mustURL(tc.realm)); got != tc.want {
			t.Errorf("realmMayReceiveCredentials(%s, %s) = %v, want %v", tc.registry, tc.realm, got, tc.want)
		}
	}
}

func TestDockerConfigHostMatching(t *testing.T) {
	for _, tc := range []struct {
		key, target string
		want        bool
	}{
		{"https://index.docker.io/v1/", "https://registry-1.docker.io", true},
		{"registry-1.docker.io", "https://registry-1.docker.io", true},
		{"ghcr.io", "https://ghcr.io", true},
		{"https://ghcr.io/", "https://ghcr.io", true},
		{"localhost:5000", "http://localhost:5000", true},
		{"ghcr.io", "https://evil.ghcr.io.example", false},
		{"ghcr.io", "https://registry-1.docker.io", false},
		{"https://index.docker.io/v1/", "https://ghcr.io", false},
		{"docker.io.evil.example", "https://registry-1.docker.io", false},
	} {
		writeDockerConfig(t, tc.key, "u", "p", "")
		if _, ok, err := (CredentialStore{}).Lookup(context.Background(), tc.target); err != nil || ok != tc.want {
			t.Errorf("config key %q for %s: found = %v, err = %v, want found = %v", tc.key, tc.target, ok, err, tc.want)
		}
	}
}

func TestParseChallengeKeepsCommasInsideQuotes(t *testing.T) {
	ch := parseChallenge(`Bearer realm="https://auth.example/token",service="registry.example",scope="repository:a/b:pull,push",error=invalid_token`)
	if ch.scheme != "bearer" || ch.params["realm"] != "https://auth.example/token" ||
		ch.params["service"] != "registry.example" || ch.params["scope"] != "repository:a/b:pull,push" || ch.params["error"] != "invalid_token" {
		t.Errorf("challenge = %+v", ch)
	}
}

func TestDefaultCacheDirPlatforms(t *testing.T) {
	win, err := defaultCacheDirFor("windows", func(k string) string {
		return map[string]string{"LOCALAPPDATA": `C:\Users\u\AppData\Local`}[k]
	}, nil)
	if err != nil || win != filepath.Join(`C:\Users\u\AppData\Local`, "gvx", "cache", "layers") {
		t.Errorf("windows dir = %q, %v", win, err)
	}
	if _, err := defaultCacheDirFor("windows", func(string) string { return "" }, func() (string, error) {
		return os.TempDir(), nil
	}); err == nil {
		t.Error("windows without LOCALAPPDATA fell back instead of failing")
	}
	mac, err := defaultCacheDirFor("darwin", nil, func() (string, error) { return "/Users/u/Library/Caches", nil })
	if err != nil || mac != filepath.Join("/Users/u/Library/Caches", "gvx", "layers") {
		t.Errorf("macOS dir = %q, %v", mac, err)
	}
	if _, err := defaultCacheDirFor("darwin", nil, func() (string, error) { return "", errors.New("no home") }); err == nil {
		t.Error("a missing user cache dir fell back instead of failing")
	}
}
