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

package gvx

import (
	"context"
	"runtime"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/testimage"
)

// referenceRegistry serves gvx/ref:v1 and returns the registry host that a
// reference names, such as "127.0.0.1:41234".
func referenceRegistry(t *testing.T) (*testimage.Registry, string) {
	t.Helper()
	layer, err := testimage.Tar(testimage.File{Name: "marker", Data: []byte("ref\n")})
	if err != nil {
		t.Fatalf("testimage.Tar failed: %v", err)
	}
	reg := testimage.NewRegistryServer(t, "gvx/ref", "v1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{layer}, Cmd: []string{"/marker"}})
	return reg, strings.TrimPrefix(reg.URL, "http://")
}

// newReferenceResolver returns a function that resolves images into a new
// cache and reports the manifest digest and the layer digests.
func newReferenceResolver(t *testing.T) func(baseURL, image string) (digest string, layers []string, err error) {
	t.Helper()
	c, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}
	return func(baseURL, image string) (string, []string, error) {
		img, err := ResolveImage(context.Background(), c, baseURL, image, runtime.GOARCH)
		if err != nil {
			return "", nil, err
		}
		defer img.Close()
		return img.ManifestDigest, slices.Clone(img.LayerDigests), nil
	}
}

func TestResolveImageReadsTheRegistryFromTheReference(t *testing.T) {
	_, host := referenceRegistry(t)
	resolve := newReferenceResolver(t)

	digest, layers, err := resolve("", host+"/gvx/ref:v1")
	if err != nil {
		t.Fatalf("ResolveImage by reference failed: %v", err)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(layers) != 1 {
		t.Fatalf("ResolveImage = digest %q layers %v, want a digest and one layer", digest, layers)
	}

	t.Run("digest reference", func(t *testing.T) {
		resolveFresh := newReferenceResolver(t)
		got, gotLayers, err := resolveFresh("", host+"/gvx/ref@"+digest)
		if err != nil {
			t.Fatalf("ResolveImage by digest failed: %v", err)
		}
		if got != digest || !slices.Equal(gotLayers, layers) {
			t.Errorf("by digest = %q %v, want %q %v", got, gotLayers, digest, layers)
		}
	})
	t.Run("digest wins over the tag", func(t *testing.T) {
		resolveFresh := newReferenceResolver(t)
		got, _, err := resolveFresh("", host+"/gvx/ref:missing@"+digest)
		if err != nil || got != digest {
			t.Errorf("tag and digest = %q, %v, want the digest %q", got, err, digest)
		}
	})
}

func TestResolveImageOverrideDropsTheRegistryHostOfTheReference(t *testing.T) {
	reg, _ := referenceRegistry(t)
	resolve := newReferenceResolver(t)
	for _, image := range []string{"gvx/ref:v1", "ghcr.io/gvx/ref:v1"} {
		if _, _, err := resolve(reg.URL+"/", image); err != nil {
			t.Errorf("ResolveImage(%q) with an override failed: %v", image, err)
		}
	}
}

func TestResolveImageRejectsAReferenceThatIsNoFile(t *testing.T) {
	resolve := newReferenceResolver(t)
	for _, image := range []string{"Upper/Case:v1", "name::tag", "name@sha256:abc", ""} {
		_, _, err := resolve("", image)
		if err == nil || !strings.Contains(err.Error(), "invalid image reference") {
			t.Errorf("ResolveImage(%q) error = %v, want an invalid reference error", image, err)
		}
	}
}

func TestResolveImageServesAReferenceFromTheCacheWhenTheRegistryIsDown(t *testing.T) {
	reg, host := referenceRegistry(t)
	resolve := newReferenceResolver(t)
	want, layers, err := resolve("", host+"/gvx/ref:v1")
	if err != nil {
		t.Fatalf("online ResolveImage failed: %v", err)
	}

	reg.Close()
	got, gotLayers, err := resolve("", host+"/gvx/ref:v1")
	if err != nil {
		t.Fatalf("offline ResolveImage failed: %v", err)
	}
	if got != want || !slices.Equal(gotLayers, layers) {
		t.Errorf("offline = %q %v, want %q %v", got, gotLayers, want, layers)
	}
}
