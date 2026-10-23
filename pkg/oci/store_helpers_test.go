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
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// storeArch is the architecture of every image in the store tests.
const storeArch = "amd64"

// newImageWithCreated builds an amd64 image whose config has a creation time.
func newImageWithCreated(t testing.TB, env, created string, rawLayers ...[]byte) *testImage {
	t.Helper()
	img := newTestImage(t, storeArch, env, rawLayers...)
	var cfg map[string]any
	if err := json.Unmarshal(img.config, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg["created"] = created
	var err error
	if img.config, err = json.Marshal(cfg); err != nil {
		t.Fatal(err)
	}
	var manifest ImageManifest
	if err := json.Unmarshal(img.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Config = Descriptor{MediaType: mediaTypeOCIConfig, Digest: sha256Digest(img.config), Size: int64(len(img.config))}
	if img.manifest, err = json.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	return img
}

// layerOf returns a layer tar with one file.
func layerOf(t testing.TB, name, content string) []byte {
	t.Helper()
	return buildTar(t, fileEntry(name, content))
}

// host returns the registry name that the store shows for the fake registry.
func (r *fakeRegistry) host() string { return strings.TrimPrefix(r.srv.URL, "http://") }

// ref returns the reference of repo testRepo with tag.
func (r *fakeRegistry) ref(tag string) string { return r.host() + "/" + testRepo + ":" + tag }

// pullTagged adds img to the registry under every tag and pulls each tag.
func pullTagged(t *testing.T, reg *fakeRegistry, cache *LayerCache, img *testImage, tags ...string) {
	t.Helper()
	digest := reg.addImage(img)
	for _, tag := range tags {
		reg.tag(tag, digest)
		mustPull(t, reg, cache, tag, storeArch)
	}
}

func listImages(t *testing.T, cache *LayerCache) []Image {
	t.Helper()
	images, err := cache.ListImages(storeArch)
	if err != nil {
		t.Fatalf("ListImages: %v", err)
	}
	return images
}

// layerFiles returns the names of the layer image and integrity files of a layer.
func layerFiles(t *testing.T, cache *LayerCache, digest string) []string {
	t.Helper()
	hexStr, err := parseDigest(digest)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, name := range []string{hexStr + cache.layerSuffix(), hexStr + cache.sumSuffix()} {
		if _, err := os.Stat(filepath.Join(cache.Dir(), name)); err == nil {
			found = append(found, name)
		}
	}
	return found
}

func blobDigests(img *testImage) []string {
	var out []string
	for _, b := range img.blobs {
		out = append(out, sha256Digest(b))
	}
	return out
}
