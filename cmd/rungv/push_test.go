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

package main

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const ociManifestMediaType = "application/vnd.oci.image.manifest.v1+json"

type ociIndexDoc struct {
	Manifests []struct {
		Digest string `json:"digest"`
	} `json:"manifests"`
}

type cliPushRegistry struct {
	srv      *httptest.Server
	host     string
	wantUser string
	wantPass string

	mu           sync.Mutex
	blobs        map[string]map[string][]byte
	manifests    map[string]map[string][]byte
	uploads      map[string]string
	blobPuts     int
	manifestPuts int
	nextID       int
}

func startCLIPushRegistry(t *testing.T, wantUser, wantPass string) *cliPushRegistry {
	t.Helper()
	r := &cliPushRegistry{
		wantUser:  wantUser,
		wantPass:  wantPass,
		blobs:     make(map[string]map[string][]byte),
		manifests: make(map[string]map[string][]byte),
		uploads:   make(map[string]string),
	}
	r.srv = httptest.NewServer(http.HandlerFunc(r.serve))
	t.Cleanup(r.srv.Close)
	r.host = strings.TrimPrefix(r.srv.URL, "http://")
	return r
}

func (r *cliPushRegistry) serve(w http.ResponseWriter, req *http.Request) {
	if r.wantUser != "" || r.wantPass != "" {
		u, p, ok := req.BasicAuth()
		if !ok || u != r.wantUser || p != r.wantPass {
			w.Header().Set("WWW-Authenticate", `Basic realm="rungv-test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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
		repo, _, _ := strings.Cut(rest, "/blobs/uploads/")
		switch req.Method {
		case http.MethodPost:
			r.mu.Lock()
			r.nextID++
			id := fmt.Sprintf("u-%d", r.nextID)
			r.uploads[id] = repo
			r.mu.Unlock()
			w.Header().Set("Location", fmt.Sprintf("/v2/%s/blobs/uploads/%s", repo, id))
			w.WriteHeader(http.StatusAccepted)
		case http.MethodPut:
			dgst := req.URL.Query().Get("digest")
			body, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			sum := sha256.Sum256(body)
			if got := "sha256:" + hex.EncodeToString(sum[:]); got != dgst {
				http.Error(w, "digest mismatch", http.StatusBadRequest)
				return
			}
			r.mu.Lock()
			if r.blobs[repo] == nil {
				r.blobs[repo] = make(map[string][]byte)
			}
			r.blobs[repo][dgst] = body
			r.blobPuts++
			r.mu.Unlock()
			w.Header().Set("Docker-Content-Digest", dgst)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case strings.Contains(rest, "/blobs/"):
		repo, dgst, _ := strings.Cut(rest, "/blobs/")
		r.mu.Lock()
		data, exists := r.blobs[repo][dgst]
		r.mu.Unlock()
		if !exists {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(data)))
		w.Header().Set("Docker-Content-Digest", dgst)
		w.WriteHeader(http.StatusOK)
		if req.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case strings.Contains(rest, "/manifests/"):
		repo, ref, _ := strings.Cut(rest, "/manifests/")
		switch req.Method {
		case http.MethodPut:
			body, err := io.ReadAll(req.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			sum := sha256.Sum256(body)
			dgst := "sha256:" + hex.EncodeToString(sum[:])
			r.mu.Lock()
			if r.manifests[repo] == nil {
				r.manifests[repo] = make(map[string][]byte)
			}
			r.manifests[repo][ref] = body
			r.manifests[repo][dgst] = body
			r.manifestPuts++
			r.mu.Unlock()
			w.Header().Set("Docker-Content-Digest", dgst)
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet, http.MethodHead:
			r.mu.Lock()
			body, exists := r.manifests[repo][ref]
			r.mu.Unlock()
			if !exists {
				http.NotFound(w, req)
				return
			}
			sum := sha256.Sum256(body)
			w.Header().Set("Content-Type", ociManifestMediaType)
			w.Header().Set("Docker-Content-Digest", "sha256:"+hex.EncodeToString(sum[:]))
			w.WriteHeader(http.StatusOK)
			if req.Method == http.MethodGet {
				_, _ = w.Write(body)
			}
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	default:
		http.NotFound(w, req)
	}
}

func readArchiveIndexDigest(t *testing.T, archivePath string) string {
	t.Helper()
	f, err := os.Open(archivePath)
	if err != nil {
		t.Fatalf("open archive: %v", err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			t.Fatalf("index.json not found in %s", archivePath)
		}
		if err != nil {
			t.Fatalf("read archive %s: %v", archivePath, err)
		}
		if hdr.Name == "index.json" {
			raw, err := io.ReadAll(tr)
			if err != nil {
				t.Fatal(err)
			}
			var idx ociIndexDoc
			if err := json.Unmarshal(raw, &idx); err != nil {
				t.Fatal(err)
			}
			if len(idx.Manifests) == 0 {
				t.Fatal("index.json lists no manifests")
			}
			return idx.Manifests[0].Digest
		}
	}
}

func fetchRegistryPlatformDigest(t *testing.T, baseURL, repo, tag string) string {
	t.Helper()
	resp, err := http.Get(baseURL + "/v2/" + repo + "/manifests/" + tag)
	if err != nil {
		t.Fatalf("GET index manifest: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET index manifest status = %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var idx ociIndexDoc
	if err := json.Unmarshal(raw, &idx); err != nil {
		t.Fatal(err)
	}
	if len(idx.Manifests) == 0 {
		t.Fatal("registry index has no platform manifests")
	}
	return idx.Manifests[0].Digest
}

func TestCLIPullKeepBlobsOfflineSaveAndLoadRoundTrip(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	platformDigest := fetchRegistryPlatformDigest(t, reg.URL, "gvx/app", "v1")
	env := newCLIEnv(t)

	pullOut := env.run("pull", "-keep-blobs", reg.ref("v1")).mustSucceed(t, "pull -keep-blobs")
	if !digestLine.MatchString(pullOut.stdout) {
		t.Fatalf("pull output missing Digest line:\n%s", pullOut.stdout)
	}

	// Disconnect the registry completely.
	reg.Close()

	savedA := filepath.Join(t.TempDir(), "a.tar")
	env.run("save", "-o", savedA, reg.ref("v1")).mustSucceed(t, "offline save")
	if got := readArchiveIndexDigest(t, savedA); got != platformDigest {
		t.Fatalf("saved archive manifest digest = %s, want platform manifest digest %s", got, platformDigest)
	}

	// Load savedA with -keep-blobs into a second cache, save again, and reload into a third cache.
	env2 := newCLIEnv(t)
	env2.run("load", "-keep-blobs", "-i", savedA).mustSucceed(t, "load -keep-blobs")
	ids2 := env2.imageIDs()
	if len(ids2) != 1 {
		t.Fatalf("env2 image IDs = %v, want 1", ids2)
	}
	savedB := filepath.Join(t.TempDir(), "b.tar")
	env2.run("save", "-o", savedB, reg.ref("v1")).mustSucceed(t, "save loaded image")

	env3 := newCLIEnv(t)
	env3.run("load", "-i", savedB).mustSucceed(t, "reload b.tar")
	ids3 := env3.imageIDs()
	if len(ids3) != 1 || ids3[0] != ids2[0] {
		t.Fatalf("reloaded IDs = %v, want [%s]", ids3, ids2[0])
	}
}

func TestCLIGVXKeepBlobsEnvAndExplicitOverride(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	t.Setenv("GVX_KEEP_BLOBS", "1")
	env := newCLIEnv(t)
	env.run("pull", reg.ref("v1")).mustSucceed(t, "pull with GVX_KEEP_BLOBS=1")
	reg.Close()

	saved := filepath.Join(t.TempDir(), "env.tar")
	env.run("save", "-o", saved, reg.ref("v1")).mustSucceed(t, "offline save via GVX_KEEP_BLOBS=1")

	// Explicit -keep-blobs=false overrides GVX_KEEP_BLOBS=1.
	envNoKeep := newCLIEnv(t)
	envNoKeep.run("load", "-keep-blobs=false", "-i", saved).mustSucceed(t, "load -keep-blobs=false")
	res := envNoKeep.run("save", "-o", filepath.Join(t.TempDir(), "fail.tar"), reg.ref("v1"))
	if res.code == 0 {
		t.Fatal("save succeeded despite -keep-blobs=false on loaded archive")
	}
}

func TestCLITagPushAndDeduplicateSecondPush(t *testing.T) {
	srcReg := startRegistry(t, twoFiles()...)
	platformDigest := fetchRegistryPlatformDigest(t, srcReg.URL, "gvx/app", "v1")
	env := newCLIEnv(t)
	env.run("pull", "-keep-blobs", srcReg.ref("v1")).mustSucceed(t, "pull -keep-blobs")
	srcReg.Close()

	dstReg := startCLIPushRegistry(t, "", "")
	dstRef := dstReg.host + "/pushed/app:v1"
	env.run("tag", srcReg.ref("v1"), dstRef).mustSucceed(t, "tag")

	push1 := env.run("push", dstRef).mustSucceed(t, "first push")
	if !strings.Contains(push1.stdout, "digest: "+platformDigest) {
		t.Fatalf("first push output lacks platform digest %s:\n%s", platformDigest, push1.stdout)
	}
	dstReg.mu.Lock()
	putsAfterFirst := dstReg.blobPuts
	dstReg.mu.Unlock()
	if putsAfterFirst == 0 {
		t.Fatal("first push uploaded 0 blobs")
	}

	// Second push via `image push -q` uploads zero blobs and prints the exact digest.
	push2 := runCLIArgs(t, nil, "image", "push", "-cache-dir", env.cacheDir, "-q", dstRef).mustSucceed(t, "second push")
	if strings.TrimSpace(push2.stdout) != platformDigest {
		t.Fatalf("second push -q output = %q, want %q", push2.stdout, platformDigest)
	}
	dstReg.mu.Lock()
	putsAfterSecond := dstReg.blobPuts
	dstReg.mu.Unlock()
	if putsAfterSecond != putsAfterFirst {
		t.Fatalf("second push uploaded %d blobs, want 0", putsAfterSecond-putsAfterFirst)
	}

	// Two-argument form `rungv push IMAGE TARGET` works directly without prior tag.
	dstRef2 := dstReg.host + "/pushed/other:v2"
	push3 := env.run("push", "-q", srcReg.ref("v1"), dstRef2).mustSucceed(t, "two-arg push")
	if strings.TrimSpace(push3.stdout) != platformDigest {
		t.Fatalf("two-arg push digest = %q, want %q", push3.stdout, platformDigest)
	}
}

func TestCLIPushAuthModes(t *testing.T) {
	srcReg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.run("pull", "-keep-blobs", srcReg.ref("v1")).mustSucceed(t, "pull")
	srcReg.Close()

	dstReg := startCLIPushRegistry(t, "alice", "s3cr3t")
	dstRef := dstReg.host + "/secure/app:v1"

	// Without credentials, push fails.
	noAuth := env.run("push", srcReg.ref("v1"), dstRef)
	if noAuth.code == 0 {
		t.Fatal("push succeeded without credentials")
	}

	// --password-stdin with -u succeeds.
	env.runWithStdin(strings.NewReader("s3cr3t\n"), "push", "-u", "alice", "--password-stdin", srcReg.ref("v1"), dstRef).mustSucceed(t, "push --password-stdin")

	// --auth-stdin with raw JSON succeeds.
	env.runWithStdin(strings.NewReader(`{"username":"alice","password":"s3cr3t"}`), "push", "--auth-stdin", srcReg.ref("v1"), dstReg.host+"/secure/app:v2").mustSucceed(t, "push --auth-stdin raw json")

	// --auth-stdin with base64 X-Registry-Auth payload succeeds.
	xAuth := base64.StdEncoding.EncodeToString([]byte(`{"auth":"` + base64.StdEncoding.EncodeToString([]byte("alice:s3cr3t")) + `"}`))
	env.runWithStdin(strings.NewReader(xAuth), "push", "--auth-stdin", srcReg.ref("v1"), dstReg.host+"/secure/app:v3").mustSucceed(t, "push --auth-stdin base64")
}

func TestCLIRmiAndPruneFreeKeptBlobs(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	env := newCLIEnv(t)
	env.run("pull", "-keep-blobs", reg.ref("v1")).mustSucceed(t, "pull -keep-blobs")

	blobsDir := filepath.Join(env.cacheDir, "blobs", "sha256")
	entriesBefore, err := os.ReadDir(blobsDir)
	if err != nil || len(entriesBefore) == 0 {
		t.Fatalf("expected kept blobs in %s, err=%v count=%d", blobsDir, err, len(entriesBefore))
	}

	env.run("rmi", reg.ref("v1")).mustSucceed(t, "rmi")
	runCLIArgs(t, nil, "image", "prune", "-cache-dir", env.cacheDir, "-f").mustSucceed(t, "image prune")

	entriesAfter, err := os.ReadDir(blobsDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ReadDir(%s): %v", blobsDir, err)
	}
	if len(entriesAfter) != 0 {
		t.Fatalf("expected 0 kept blobs after rmi + prune, found %d", len(entriesAfter))
	}
}

func TestCLIPushUsageErrors(t *testing.T) {
	env := newCLIEnv(t)
	if res := env.run("push"); res.code != 2 {
		t.Errorf("push with no args code = %d, want 2", res.code)
	}
	if res := env.run("push", "--password-stdin", "alpine:3.20"); res.code != 2 {
		t.Errorf("push --password-stdin without -u code = %d, want 2", res.code)
	}
	if res := env.run("push", "-u", "alice", "--password-stdin", "--auth-stdin", "alpine:3.20"); res.code != 2 {
		t.Errorf("mutually exclusive auth flags code = %d, want 2", res.code)
	}
	if res := env.run("push", "--auth-fd", "1", "alpine:3.20"); res.code != 2 {
		t.Errorf("--auth-fd 1 code = %d, want 2", res.code)
	}
}
