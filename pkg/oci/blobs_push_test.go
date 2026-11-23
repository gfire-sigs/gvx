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
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type fakePushRegistry struct {
	t      *testing.T
	srv    *httptest.Server
	authFn func(w http.ResponseWriter, r *http.Request) bool

	// externalUploadSrv, when set, receives monolithic PUTs via Location
	// redirect to a separate host so tests verify Authorization is stripped.
	externalUploadSrv *httptest.Server

	mu            sync.Mutex
	blobs         map[string]map[string][]byte // repo -> digest -> bytes
	manifests     map[string]map[string][]byte // repo -> ref(tag or digest) -> bytes
	manifestTypes map[string]map[string]string // repo -> ref -> mediaType
	uploads       map[string]string            // uuid -> repo
	blobPuts      int
	blobMounts    int
	headHits      int
	headMisses    int
	manifestPuts  int
	nextUploadID  int
}

func newFakePushRegistry(t *testing.T) *fakePushRegistry {
	t.Helper()
	r := &fakePushRegistry{
		t:             t,
		blobs:         make(map[string]map[string][]byte),
		manifests:     make(map[string]map[string][]byte),
		manifestTypes: make(map[string]map[string]string),
		uploads:       make(map[string]string),
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *fakePushRegistry) host() string {
	return strings.TrimPrefix(r.srv.URL, "http://")
}

func (r *fakePushRegistry) ref(repo, tag string) Reference {
	ref, err := ParseReference(r.host() + "/" + repo + ":" + tag)
	if err != nil {
		r.t.Fatalf("ParseReference: %v", err)
	}
	return ref
}

func (r *fakePushRegistry) seedImage(repo, tag string, img *testImage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.blobs[repo] == nil {
		r.blobs[repo] = make(map[string][]byte)
	}
	if r.manifests[repo] == nil {
		r.manifests[repo] = make(map[string][]byte)
		r.manifestTypes[repo] = make(map[string]string)
	}
	r.blobs[repo][sha256Digest(img.config)] = slices.Clone(img.config)
	for _, b := range img.blobs {
		r.blobs[repo][sha256Digest(b)] = slices.Clone(b)
	}
	r.manifests[repo][tag] = slices.Clone(img.manifest)
	r.manifests[repo][img.digest()] = slices.Clone(img.manifest)
	r.manifestTypes[repo][tag] = ocispec.MediaTypeImageManifest
	r.manifestTypes[repo][img.digest()] = ocispec.MediaTypeImageManifest
}

func (r *fakePushRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if r.authFn != nil && !r.authFn(w, req) {
		return
	}
	if req.URL.Path == "/v2/" {
		w.WriteHeader(http.StatusOK)
		return
	}
	rest, ok := strings.CutPrefix(req.URL.Path, "/v2/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	switch {
	case strings.Contains(rest, "/blobs/uploads/"):
		repo, tail, _ := strings.Cut(rest, "/blobs/uploads/")
		r.handleUpload(w, req, repo, tail)
	case strings.Contains(rest, "/blobs/"):
		repo, dgst, _ := strings.Cut(rest, "/blobs/")
		r.handleBlob(w, req, repo, dgst)
	case strings.Contains(rest, "/manifests/"):
		repo, ref, _ := strings.Cut(rest, "/manifests/")
		r.handleManifest(w, req, repo, ref)
	default:
		http.NotFound(w, req)
	}
}

func (r *fakePushRegistry) handleBlob(w http.ResponseWriter, req *http.Request, repo, dgst string) {
	r.mu.Lock()
	data, ok := r.blobs[repo][dgst]
	if req.Method == http.MethodHead {
		if ok {
			r.headHits++
		} else {
			r.headMisses++
		}
	}
	r.mu.Unlock()

	if !ok {
		http.NotFound(w, req)
		return
	}
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
	w.Header().Set("Docker-Content-Digest", dgst)
	w.WriteHeader(http.StatusOK)
	if req.Method == http.MethodGet {
		_, _ = w.Write(data)
	}
}

func (r *fakePushRegistry) handleUpload(w http.ResponseWriter, req *http.Request, repo, uploadID string) {
	switch req.Method {
	case http.MethodPost:
		mountDigest := req.URL.Query().Get("mount")
		fromRepo := req.URL.Query().Get("from")
		r.mu.Lock()
		if mountDigest != "" && fromRepo != "" {
			if srcBlob, ok := r.blobs[fromRepo][mountDigest]; ok {
				if r.blobs[repo] == nil {
					r.blobs[repo] = make(map[string][]byte)
				}
				r.blobs[repo][mountDigest] = slices.Clone(srcBlob)
				r.blobMounts++
				r.mu.Unlock()
				w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, mountDigest))
				w.Header().Set("Docker-Content-Digest", mountDigest)
				w.WriteHeader(http.StatusCreated)
				return
			}
		}
		r.nextUploadID++
		id := fmt.Sprintf("u-%d", r.nextUploadID)
		r.uploads[id] = repo
		extSrv := r.externalUploadSrv
		r.mu.Unlock()

		loc := fmt.Sprintf("/v2/%s/blobs/uploads/%s?_state=abc", repo, id)
		if extSrv != nil {
			loc = fmt.Sprintf("%s/upload/%s?repo=%s", extSrv.URL, id, url.QueryEscape(repo))
		}
		w.Header().Set("Location", loc)
		w.WriteHeader(http.StatusAccepted)

	case http.MethodPut:
		dgst := req.URL.Query().Get("digest")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if got := sha256Digest(body); got != dgst {
			http.Error(w, fmt.Sprintf("digest mismatch: got %s want %s", got, dgst), http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		if r.uploads[uploadID] != repo {
			r.mu.Unlock()
			http.Error(w, "unknown upload session", http.StatusNotFound)
			return
		}
		delete(r.uploads, uploadID)
		if r.blobs[repo] == nil {
			r.blobs[repo] = make(map[string][]byte)
		}
		r.blobs[repo][dgst] = body
		r.blobPuts++
		r.mu.Unlock()
		w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/%s", repo, dgst))
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (r *fakePushRegistry) handleManifest(w http.ResponseWriter, req *http.Request, repo, ref string) {
	switch req.Method {
	case http.MethodGet, http.MethodHead:
		r.mu.Lock()
		body, ok := r.manifests[repo][ref]
		mt := r.manifestTypes[repo][ref]
		r.mu.Unlock()
		if !ok {
			http.NotFound(w, req)
			return
		}
		if mt == "" {
			mt = ocispec.MediaTypeImageManifest
		}
		w.Header().Set("Content-Type", mt)
		w.Header().Set("Docker-Content-Digest", sha256Digest(body))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	case http.MethodPut:
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		dgst := sha256Digest(body)
		r.mu.Lock()
		if r.manifests[repo] == nil {
			r.manifests[repo] = make(map[string][]byte)
			r.manifestTypes[repo] = make(map[string]string)
		}
		r.manifests[repo][ref] = body
		r.manifests[repo][dgst] = body
		r.manifestTypes[repo][ref] = req.Header.Get("Content-Type")
		r.manifestTypes[repo][dgst] = req.Header.Get("Content-Type")
		r.manifestPuts++
		r.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func newKeepBlobsCache(t *testing.T) *LayerCache {
	t.Helper()
	c, err := NewLayerCacheWithOptions(t.TempDir(), CacheOptions{BlockSize: testBlockSize, KeepBlobs: true})
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions: %v", err)
	}
	return c
}

func TestPullKeepBlobsSavesOfflineWithOriginalDigest(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newKeepBlobsCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")

	for _, b := range img.blobs {
		if _, ok := cache.HasBlob(sha256Digest(b)); !ok {
			t.Fatalf("expected kept blob for %s", sha256Digest(b))
		}
	}

	// Shut down the registry completely to prove save needs no network.
	reg.srv.Close()

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, reg.ref("v1")); err != nil {
		t.Fatalf("offline SaveImages failed: %v", err)
	}

	_, files := untar(t, archive.Bytes())
	var idx ocispec.Index
	if err := json.Unmarshal(files["index.json"], &idx); err != nil {
		t.Fatalf("unmarshal index.json: %v", err)
	}
	if len(idx.Manifests) != 1 {
		t.Fatalf("index.json manifests = %d, want 1", len(idx.Manifests))
	}
	if got := idx.Manifests[0].Digest.String(); got != img.digest() {
		t.Fatalf("index.json manifest digest = %s, want %s", got, img.digest())
	}

	dst := newCache(t)
	loaded, err := LoadArchive(bytes.NewReader(archive.Bytes()), dst, storeArch)
	if err != nil {
		t.Fatalf("LoadArchive of offline saved archive: %v", err)
	}
	if len(loaded) != 1 || loaded[0].Digest != img.digest() || loaded[0].ID != sha256Digest(img.config) {
		t.Fatalf("loaded = %+v, want digest %s and ID %s", loaded, img.digest(), sha256Digest(img.config))
	}
}

func TestPullKeepBlobsBackfillsAlreadyCachedLayers(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")

	if _, ok := cache.HasBlob(sha256Digest(img.blobs[0])); ok {
		t.Fatal("blob should not be kept when KeepBlobs is false")
	}

	cache.SetKeepBlobs(true)
	pullTagged(t, reg, cache, img, "v1")
	reg.srv.Close()

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, reg.ref("v1")); err != nil {
		t.Fatalf("offline SaveImages after KeepBlobs backfill failed: %v", err)
	}
}

func TestLoadKeepBlobsSavesOfflineAndReloadsSameID(t *testing.T) {
	t.Run("oci layout", func(t *testing.T) {
		img := twoLayerImage(t, storeArch, "A=1")
		cache := newKeepBlobsCache(t)
		members := annotatedLayout(t, img, map[string]string{
			ocispec.AnnotationRefName: "local/app:v1",
		})
		loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch)
		if err != nil {
			t.Fatalf("LoadArchive: %v", err)
		}

		var saved bytes.Buffer
		if err := saveByName(t, cache, &saved, "local/app:v1"); err != nil {
			t.Fatalf("SaveImages of kept OCI archive: %v", err)
		}
		reloaded, err := LoadArchive(bytes.NewReader(saved.Bytes()), newCache(t), storeArch)
		if err != nil {
			t.Fatalf("reload saved archive: %v", err)
		}
		if len(reloaded) != 1 || reloaded[0].ID != loaded[0].ID || reloaded[0].Digest != img.digest() {
			t.Fatalf("reloaded = %+v, want ID %s digest %s", reloaded, loaded[0].ID, img.digest())
		}
	})

	t.Run("docker save uncompressed", func(t *testing.T) {
		img := twoLayerImage(t, storeArch, "A=1")
		cache := newKeepBlobsCache(t)
		loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, dockerSaveMembers(t, img))), cache, storeArch)
		if err != nil {
			t.Fatalf("LoadArchive docker save: %v", err)
		}

		var saved bytes.Buffer
		if err := saveByName(t, cache, &saved, "app:latest"); err != nil {
			t.Fatalf("SaveImages of kept docker save archive: %v", err)
		}
		reloaded, err := LoadArchive(bytes.NewReader(saved.Bytes()), newCache(t), storeArch)
		if err != nil {
			t.Fatalf("reload saved archive: %v", err)
		}
		if len(reloaded) != 1 || reloaded[0].ID != loaded[0].ID {
			t.Fatalf("reloaded = %+v, want ID %s", reloaded, loaded[0].ID)
		}
	})

	t.Run("docker save gzip compressed layer", func(t *testing.T) {
		img := twoLayerImage(t, storeArch, "A=1")
		members := dockerSaveMembers(t, img)
		// Replace layer 0 with a gzip-compressed tar member.
		var gzBuf bytes.Buffer
		gw := gzip.NewWriter(&gzBuf)
		if _, err := gw.Write(img.rawLayers[0]); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		members = replaceMember(members, "layer0/layer.tar", gzBuf.Bytes())

		cache := newKeepBlobsCache(t)
		loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch)
		if err != nil {
			t.Fatalf("LoadArchive compressed docker save: %v", err)
		}
		var saved bytes.Buffer
		if err := saveByName(t, cache, &saved, "app:latest"); err != nil {
			t.Fatalf("SaveImages of compressed docker save: %v", err)
		}
		reloaded, err := LoadArchive(bytes.NewReader(saved.Bytes()), newCache(t), storeArch)
		if err != nil {
			t.Fatalf("reload saved archive: %v", err)
		}
		if len(reloaded) != 1 || reloaded[0].ID != loaded[0].ID {
			t.Fatalf("reloaded = %+v, want ID %s", reloaded, loaded[0].ID)
		}
	})
}

func TestCorruptedKeptBlobFailsSaveAndPushWithDigestMismatch(t *testing.T) {
	img := twoLayerImage(t, storeArch, "A=1")
	cache := newKeepBlobsCache(t)
	members := annotatedLayout(t, img, map[string]string{ocispec.AnnotationRefName: "local/corrupt:v1"})
	if _, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch); err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	blobPath, err := cache.BlobPath(sha256Digest(img.blobs[0]))
	if err != nil {
		t.Fatalf("BlobPath: %v", err)
	}
	data, err := os.ReadFile(blobPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	data[0] ^= 0xff
	if err := os.WriteFile(blobPath, data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Clear cached verification entry to simulate a new process or mutated file.
	cache.mu.Lock()
	delete(cache.verifiedBlobs, strings.TrimPrefix(sha256Digest(img.blobs[0]), "sha256:"))
	cache.mu.Unlock()

	var buf bytes.Buffer
	if err := saveByName(t, cache, &buf, "local/corrupt:v1"); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("SaveImages error = %v, want ErrDigestMismatch", err)
	}
	if buf.Len() != 0 {
		t.Fatalf("SaveImages wrote %d bytes on corrupted blob", buf.Len())
	}

	dstReg := newFakePushRegistry(t)
	sel, err := cache.Select("local/corrupt:v1", storeArch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.PushImage(t.Context(), sel.Images[0], dstReg.ref("corrupt/app", "v1"), PushOptions{}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("PushImage error = %v, want ErrDigestMismatch", err)
	}
}

func TestPushImageFullFlowDeduplicatesSecondPush(t *testing.T) {
	srcReg := newFakeRegistry(t)
	cache := newKeepBlobsCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, srcReg, cache, img, "v1")
	// Disconnect source registry to prove kept blobs are used offline.
	srcReg.srv.Close()

	dstReg := newFakePushRegistry(t)
	sel, err := cache.Select(srcReg.ref("v1"), storeArch)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	target := dstReg.ref("dest/app", "v1")
	var events []PushEvent
	res1, err := cache.PushImage(t.Context(), sel.Images[0], target, PushOptions{
		Progress: func(ev PushEvent) { events = append(events, ev) },
	})
	if err != nil {
		t.Fatalf("first PushImage: %v", err)
	}
	if res1.Digest != img.digest() {
		t.Fatalf("pushed manifest digest = %s, want %s", res1.Digest, img.digest())
	}
	if res1.PushedBlobs != len(img.blobs)+1 || res1.SkippedBlobs != 0 {
		t.Fatalf("first push result = %+v, want %d pushed blobs and 0 skipped", res1, len(img.blobs)+1)
	}
	if len(events) != len(img.blobs)+2 {
		t.Fatalf("events count = %d, want %d", len(events), len(img.blobs)+2)
	}

	// Second push must skip every blob via HEAD and perform 0 blob PUTs.
	dstReg.mu.Lock()
	putsBefore := dstReg.blobPuts
	dstReg.mu.Unlock()

	res2, err := cache.PushImage(t.Context(), sel.Images[0], target, PushOptions{})
	if err != nil {
		t.Fatalf("second PushImage: %v", err)
	}
	if res2.Digest != img.digest() {
		t.Fatalf("second push manifest digest = %s, want %s", res2.Digest, img.digest())
	}
	if res2.PushedBlobs != 0 || res2.SkippedBlobs != len(img.blobs)+1 {
		t.Fatalf("second push result = %+v, want 0 pushed and %d skipped", res2, len(img.blobs)+1)
	}
	dstReg.mu.Lock()
	putsAfter := dstReg.blobPuts
	dstReg.mu.Unlock()
	if putsAfter != putsBefore {
		t.Fatalf("second push performed %d blob PUTs, want 0", putsAfter-putsBefore)
	}

	// Pulling back from dstReg into a fresh cache produces the exact same manifest digest and ID.
	fresh := newCache(t)
	pulled, err := PullRegistryImage(t.Context(), nil, dstReg.srv.URL, "dest/app", "v1", storeArch, fresh)
	if err != nil {
		t.Fatalf("pull back pushed image: %v", err)
	}
	_ = pulled.Close()
	if pulled.ManifestDigest != img.digest() {
		t.Fatalf("re-pulled manifest digest = %s, want %s", pulled.ManifestDigest, img.digest())
	}
}

func TestPushImageCrossRepoMount(t *testing.T) {
	reg := newFakePushRegistry(t)
	img := twoLayerImage(t, storeArch, "A=1")
	reg.seedImage("org/src", "v1", img)

	cache := newKeepBlobsCache(t)
	pulled, err := PullRegistryImage(t.Context(), nil, reg.srv.URL, "org/src", "v1", storeArch, cache)
	if err != nil {
		t.Fatalf("PullRegistryImage: %v", err)
	}
	_ = pulled.Close()

	sel, err := cache.Select(reg.host()+"/org/src:v1", storeArch)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	res, err := cache.PushImage(t.Context(), sel.Images[0], reg.ref("org/dst", "v2"), PushOptions{})
	if err != nil {
		t.Fatalf("PushImage cross-repo mount: %v", err)
	}
	if res.Digest != img.digest() {
		t.Fatalf("manifest digest = %s, want %s", res.Digest, img.digest())
	}
	if res.MountedBlobs != len(img.blobs)+1 || res.PushedBlobs != 0 {
		t.Fatalf("cross-repo mount result = %+v, want %d mounted and 0 pushed", res, len(img.blobs)+1)
	}
	reg.mu.Lock()
	mounts, puts := reg.blobMounts, reg.blobPuts
	reg.mu.Unlock()
	if mounts != len(img.blobs)+1 || puts != 0 {
		t.Fatalf("registry mounts=%d puts=%d, want mounts=%d puts=0", mounts, puts, len(img.blobs)+1)
	}
}

func TestPushImageAuthBearerScopeUpgradeAndExternalLocationStripsAuth(t *testing.T) {
	var seenScopes []string
	var seenUA []string
	var mu sync.Mutex
	tokenHandler := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		u, p, ok := req.BasicAuth()
		if !ok || u != "alice" || p != "secret" {
			http.Error(w, "bad creds", http.StatusUnauthorized)
			return
		}
		scopes := req.URL.Query()["scope"]
		mu.Lock()
		seenScopes = append(seenScopes, strings.Join(scopes, " "))
		seenUA = append(seenUA, req.Header.Get("User-Agent"))
		mu.Unlock()
		tok := "pull-token"
		for _, sc := range scopes {
			if strings.Contains(sc, "push") {
				tok = "push-token"
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"token": tok})
	})

	var reg *fakePushRegistry
	var extAuths []string
	var extMu sync.Mutex
	extSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if auth := req.Header.Get("Authorization"); auth != "" {
			extMu.Lock()
			extAuths = append(extAuths, auth)
			extMu.Unlock()
		}
		repo := req.URL.Query().Get("repo")
		dgst := req.URL.Query().Get("digest")
		body, err := io.ReadAll(req.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		reg.mu.Lock()
		if reg.blobs[repo] == nil {
			reg.blobs[repo] = make(map[string][]byte)
		}
		reg.blobs[repo][dgst] = body
		reg.blobPuts++
		reg.mu.Unlock()
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusCreated)
	}))
	defer extSrv.Close()

	reg = newFakePushRegistry(t)
	reg.externalUploadSrv = extSrv
	reg.authFn = func(w http.ResponseWriter, req *http.Request) bool {
		if req.URL.Path == "/token" {
			tokenHandler.ServeHTTP(w, req)
			return false
		}
		mu.Lock()
		seenUA = append(seenUA, req.Header.Get("User-Agent"))
		mu.Unlock()
		needPush := req.Method == http.MethodPost || req.Method == http.MethodPut
		auth := req.Header.Get("Authorization")
		if needPush {
			if auth != "Bearer push-token" {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg",scope="repository:team/app:pull,push"`, reg.srv.URL))
				w.WriteHeader(http.StatusUnauthorized)
				return false
			}
			return true
		}
		if auth != "Bearer pull-token" && auth != "Bearer push-token" {
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s/token",service="reg",scope="repository:team/app:pull"`, reg.srv.URL))
			w.WriteHeader(http.StatusUnauthorized)
			return false
		}
		return true
	}

	img := twoLayerImage(t, storeArch, "A=1")
	cache := newKeepBlobsCache(t)
	members := annotatedLayout(t, img, map[string]string{ocispec.AnnotationRefName: "local/auth:v1"})
	if _, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch); err != nil {
		t.Fatal(err)
	}
	sel, err := cache.Select("local/auth:v1", storeArch)
	if err != nil {
		t.Fatal(err)
	}

	res, err := cache.PushImage(t.Context(), sel.Images[0], reg.ref("team/app", "v1"), PushOptions{
		Credentials: &Credentials{Username: "alice", Password: "secret"},
	})
	if err != nil {
		t.Fatalf("PushImage with bearer scope upgrade: %v", err)
	}
	if res.Digest != img.digest() {
		t.Fatalf("manifest digest = %s, want %s", res.Digest, img.digest())
	}
	extMu.Lock()
	gotExtAuths := slices.Clone(extAuths)
	extMu.Unlock()
	if len(gotExtAuths) != 0 {
		t.Fatalf("external upload host received Authorization headers %v, want none", gotExtAuths)
	}
	mu.Lock()
	gotScopes := slices.Clone(seenScopes)
	gotUAs := slices.Clone(seenUA)
	mu.Unlock()
	if len(gotScopes) < 2 || !strings.Contains(gotScopes[0], ":pull") || !strings.Contains(gotScopes[1], "pull,push") {
		t.Fatalf("bearer scopes = %v, want pull then pull,push upgrade", gotScopes)
	}
	wantUA := fmt.Sprintf("gvx-oci/v1.0 (%s/%s; +https://z.gfire.dev/gvx)", runtime.GOOS, runtime.GOARCH)
	for _, ua := range gotUAs {
		if ua != wantUA {
			t.Fatalf("User-Agent = %q, want %q", ua, wantUA)
		}
	}
}

func TestDoRequestIgnores401ChallengeFromExternalRedirectHost(t *testing.T) {
	extSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("WWW-Authenticate", `Basic realm="evil-s3"`)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer extSrv.Close()

	var regHits int
	regSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		regHits++
		http.Redirect(w, req, extSrv.URL+"/signed-blob", http.StatusFound)
	}))
	defer regSrv.Close()

	rc, err := newRegistryClient(nil, regSrv.URL, "org/app", DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.close()
	rc.fixed = &Credentials{Username: "alice", Password: "secret"}
	rc.authz = "Bearer original-token"

	resp, err := rc.doRequest(t.Context(), http.MethodGet, regSrv.URL+"/v2/org/app/blobs/sha256:0000", nil, nil)
	if err != nil {
		t.Fatalf("doRequest returned unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if rc.authz != "Bearer original-token" {
		t.Fatalf("rc.authz was mutated by external redirect 401: %q", rc.authz)
	}
	if regHits != 1 {
		t.Fatalf("registry hit count = %d, want 1 (must not retry after external host 401)", regHits)
	}
}

func TestOnceRequestZeroByteBodySendsContentLengthZero(t *testing.T) {
	var gotContentLength int64 = -1
	var gotTransferEncoding []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotContentLength = req.ContentLength
		gotTransferEncoding = req.TransferEncoding
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	rc, err := newRegistryClient(nil, srv.URL, "org/app", DefaultLimits(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.close()

	resp, err := rc.onceRequest(t.Context(), http.MethodPut, srv.URL+"/upload", nil, &requestBody{
		contentLength: 0,
		contentType:   "application/octet-stream",
		open:          func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("")), nil },
	})
	if err != nil {
		t.Fatalf("onceRequest 0-byte PUT: %v", err)
	}
	_ = resp.Body.Close()
	if gotContentLength != 0 || len(gotTransferEncoding) != 0 {
		t.Fatalf("0-byte PUT Content-Length=%d Transfer-Encoding=%v, want Content-Length=0 and no chunked encoding", gotContentLength, gotTransferEncoding)
	}
}

func TestAppendDigestQueryPreservesOpaqueOrderAndEncoding(t *testing.T) {
	raw := "https://s3.example.test/upload/1?X-Amz-Signature=deadbeef&z=first%20val&a=second"
	d := digest.FromString("hello")
	got, err := appendDigestQuery(raw, d)
	if err != nil {
		t.Fatalf("appendDigestQuery: %v", err)
	}
	wantPrefix := raw + "&digest="
	if !strings.HasPrefix(got, wantPrefix) {
		t.Fatalf("appendDigestQuery = %q, want prefix %q (must preserve existing query verbatim)", got, wantPrefix)
	}
}

func TestPushImageCrossRepoMountForbiddenFallsBackToPlainUpload(t *testing.T) {
	reg := newFakePushRegistry(t)
	img := twoLayerImage(t, storeArch, "A=1")
	reg.seedImage("org/src", "v1", img)

	cache := newKeepBlobsCache(t)
	pulled, err := PullRegistryImage(t.Context(), nil, reg.srv.URL, "org/src", "v1", storeArch, cache)
	if err != nil {
		t.Fatalf("PullRegistryImage: %v", err)
	}
	_ = pulled.Close()

	// Deny cross-repo mount attempts with 403 Forbidden; plain uploads remain allowed.
	reg.authFn = func(w http.ResponseWriter, req *http.Request) bool {
		if req.Method == http.MethodPost && req.URL.Query().Get("mount") != "" {
			w.WriteHeader(http.StatusForbidden)
			return false
		}
		return true
	}

	sel, err := cache.Select(reg.host()+"/org/src:v1", storeArch)
	if err != nil {
		t.Fatal(err)
	}
	res, err := cache.PushImage(t.Context(), sel.Images[0], reg.ref("org/dst", "v1"), PushOptions{})
	if err != nil {
		t.Fatalf("PushImage after 403 mount fallback: %v", err)
	}
	if res.Digest != img.digest() || res.PushedBlobs != len(img.blobs)+1 || res.MountedBlobs != 0 {
		t.Fatalf("PushResult = %+v, want %d pushed and 0 mounted", res, len(img.blobs)+1)
	}
}

func TestPushImageUnkeptFallbackAndArchiveError(t *testing.T) {
	t.Run("unkept pulled image falls back to source registry", func(t *testing.T) {
		srcReg := newFakeRegistry(t)
		cache := newCache(t) // KeepBlobs == false
		img := twoLayerImage(t, storeArch, "A=1")
		pullTagged(t, srcReg, cache, img, "v1")

		dstReg := newFakePushRegistry(t)
		sel, err := cache.Select(srcReg.ref("v1"), storeArch)
		if err != nil {
			t.Fatal(err)
		}
		res, err := cache.PushImage(t.Context(), sel.Images[0], dstReg.ref("mirror/app", "v1"), PushOptions{})
		if err != nil {
			t.Fatalf("PushImage fallback from source registry failed: %v", err)
		}
		if res.Digest != img.digest() || res.PushedBlobs != len(img.blobs)+1 {
			t.Fatalf("PushResult = %+v, want digest %s and %d pushed blobs", res, img.digest(), len(img.blobs)+1)
		}
	})

	t.Run("unkept archive image fails before upload with ErrNoRegistrySource", func(t *testing.T) {
		cache := newCache(t) // KeepBlobs == false
		img := twoLayerImage(t, storeArch, "A=1")
		if _, err := LoadArchive(bytes.NewReader(writeArchive(t, dockerSaveMembers(t, img))), cache, storeArch); err != nil {
			t.Fatal(err)
		}
		sel, err := cache.Select("app:latest", storeArch)
		if err != nil {
			t.Fatal(err)
		}
		dstReg := newFakePushRegistry(t)
		_, err = cache.PushImage(t.Context(), sel.Images[0], dstReg.ref("mirror/app", "v1"), PushOptions{})
		if !errors.Is(err, ErrNoRegistrySource) {
			t.Fatalf("PushImage error = %v, want ErrNoRegistrySource", err)
		}
		dstReg.mu.Lock()
		totalReqs := dstReg.headHits + dstReg.headMisses + dstReg.blobPuts + dstReg.manifestPuts
		dstReg.mu.Unlock()
		if totalReqs != 0 {
			t.Fatalf("PushImage sent %d registry requests before failing", totalReqs)
		}
	})
}

func TestRemoveAndPruneFreeUnreferencedBlobsAndDiskUsageCountsBlobs(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newKeepBlobsCache(t)
	base := layerOf(t, "base", "shared-base-content")
	imgA := newTestImage(t, storeArch, "A=1", base, layerOf(t, "a", "unique-a-content"))
	imgB := newTestImage(t, storeArch, "B=1", base, layerOf(t, "b", "unique-b-content"))
	pullTagged(t, reg, cache, imgA, "a")
	pullTagged(t, reg, cache, imgB, "b")

	baseDigest := sha256Digest(imgA.blobs[0])
	aDigest := sha256Digest(imgA.blobs[1])
	bDigest := sha256Digest(imgB.blobs[1])

	usageBefore, err := cache.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}
	blobSum := int64(len(imgA.blobs[0]) + len(imgA.blobs[1]) + len(imgB.blobs[1]))
	if usageBefore.TotalBytes < blobSum {
		t.Fatalf("DiskUsage.TotalBytes = %d, want at least blob sum %d", usageBefore.TotalBytes, blobSum)
	}

	// Removing image A deletes A's unique blob but keeps the shared base blob.
	selA, err := cache.Select(reg.ref("a"), storeArch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Remove(selA.Images[0]); err != nil {
		t.Fatalf("Remove(A): %v", err)
	}
	if _, ok := cache.HasBlob(aDigest); ok {
		t.Fatalf("unique blob %s was not removed after Remove(A)", aDigest)
	}
	if _, ok := cache.HasBlob(baseDigest); !ok {
		t.Fatalf("shared base blob %s was deleted while image B still uses it", baseDigest)
	}

	// Write an orphaned blob directly into blobs/sha256/ and verify DiskUsage + PruneImages.
	orphanBytes := []byte("orphaned-blob-payload-for-prune-test")
	orphanHex := strings.TrimPrefix(sha256Digest(orphanBytes), "sha256:")
	orphanPath := filepath.Join(cache.blobsDir(), orphanHex)
	if err := os.WriteFile(orphanPath, orphanBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	usageWithOrphan, err := cache.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage with orphan: %v", err)
	}
	if usageWithOrphan.ReclaimableBytes < int64(len(orphanBytes)) {
		t.Fatalf("ReclaimableBytes = %d, want >= %d", usageWithOrphan.ReclaimableBytes, len(orphanBytes))
	}

	// Removing image B frees both B's unique blob and the shared base blob.
	selB, err := cache.Select(reg.ref("b"), storeArch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Remove(selB.Images[0]); err != nil {
		t.Fatalf("Remove(B): %v", err)
	}
	if _, ok := cache.HasBlob(bDigest); ok {
		t.Fatalf("blob %s was not removed after Remove(B)", bDigest)
	}
	if _, ok := cache.HasBlob(baseDigest); ok {
		t.Fatalf("shared base blob %s was not removed after removing the last referencing image", baseDigest)
	}

	pruneReport, err := cache.PruneImages(PruneOptions{Arch: storeArch})
	if err != nil {
		t.Fatalf("PruneImages: %v", err)
	}
	if _, statErr := os.Stat(orphanPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("orphaned blob still exists after PruneImages: stat=%v", statErr)
	}
	if pruneReport.SpaceReclaimed < int64(len(orphanBytes)) {
		t.Fatalf("SpaceReclaimed = %d, want >= %d", pruneReport.SpaceReclaimed, len(orphanBytes))
	}
}

func TestRemovePreservesBlobReferencedByOtherEROFSFormat(t *testing.T) {
	dir := t.TempDir()
	cache4k, err := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: 4096, KeepBlobs: true})
	if err != nil {
		t.Fatal(err)
	}
	cache16k, err := NewLayerCacheWithOptions(dir, CacheOptions{BlockSize: 16384, KeepBlobs: true})
	if err != nil {
		t.Fatal(err)
	}

	reg := newFakeRegistry(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache4k, img, "v1")
	pullTagged(t, reg, cache16k, img, "v1")

	sel4k, err := cache4k.Select(reg.ref("v1"), storeArch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache4k.Remove(sel4k.Images[0]); err != nil {
		t.Fatalf("Remove(4k): %v", err)
	}
	if _, ok := cache16k.HasBlob(sha256Digest(img.blobs[0])); !ok {
		t.Fatal("blob referenced by 16k format image record was deleted by 4k Remove")
	}
	if _, err := cache4k.PruneImages(PruneOptions{Arch: storeArch, All: true}); err != nil {
		t.Fatalf("PruneImages(4k): %v", err)
	}
	if _, ok := cache16k.HasBlob(sha256Digest(img.blobs[0])); !ok {
		t.Fatal("blob referenced by 16k format image record was swept by 4k PruneImages")
	}

	sel16k, err := cache16k.Select(reg.ref("v1"), storeArch)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache16k.Remove(sel16k.Images[0]); err != nil {
		t.Fatalf("Remove(16k): %v", err)
	}
	if _, ok := cache16k.HasBlob(sha256Digest(img.blobs[0])); ok {
		t.Fatal("blob remained after removing records in all formats")
	}
}

func TestParseAuthConfig(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	cases := []struct {
		name    string
		input   string
		want    Credentials
		wantErr bool
	}{
		{
			name:  "raw json username password",
			input: `{"username":"alice","password":"pw"}`,
			want:  Credentials{Username: "alice", Password: "pw"},
		},
		{
			name:  "raw json auth field",
			input: `{"auth":"` + b64("bob:s3cr3t") + `"}`,
			want:  Credentials{Username: "bob", Password: "s3cr3t"},
		},
		{
			name:  "base64 wrapped docker X-Registry-Auth",
			input: b64(`{"username":"carol","password":"tok","identitytoken":"id-1"}`),
			want:  Credentials{Username: "carol", Password: "tok", IdentityToken: "id-1"},
		},
		{
			name:  "raw url base64 identitytoken only",
			input: base64.RawURLEncoding.EncodeToString([]byte(`{"identitytoken":"refresh-xyz"}`)),
			want:  Credentials{IdentityToken: "refresh-xyz"},
		},
		{
			name:    "empty",
			input:   "  \n",
			wantErr: true,
		},
		{
			name:    "empty json object",
			input:   "{}",
			wantErr: true,
		},
		{
			name:    "malformed auth field without colon",
			input:   `{"auth":"` + b64("nocolon") + `"}`,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseAuthConfig([]byte(tc.input))
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseAuthConfig(%q) = %+v, want error", tc.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseAuthConfig(%q) error = %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ParseAuthConfig(%q) = %+v, want %+v", tc.input, got, tc.want)
			}
		})
	}
}
