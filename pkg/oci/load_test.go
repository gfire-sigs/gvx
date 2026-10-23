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
	"encoding/json"
	"slices"
	"testing"
)

// annotatedLayout returns the members of an OCI layout for img whose index
// entry carries the annotations.
func annotatedLayout(t *testing.T, img *testImage, annotations map[string]string) []archiveMemberSpec {
	t.Helper()
	members := ociLayoutMembers(t, img)
	index := ImageIndex{SchemaVersion: 2, MediaType: mediaTypeOCIIndex, Manifests: []Descriptor{{
		MediaType: mediaTypeOCIManifest, Digest: img.digest(), Size: int64(len(img.manifest)),
		Platform: &PlatformSpec{OS: "linux", Architecture: img.arch}, Annotations: annotations,
	}}}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	return replaceMember(members, "index.json", raw)
}

func familiarNames(img LoadedImage) []string {
	var names []string
	for _, n := range img.Names {
		names = append(names, n.Familiar())
	}
	slices.Sort(names)
	return names
}

func TestLoadArchiveRegistersTheNamesOfAnOCILayout(t *testing.T) {
	img := twoLayerImage(t, storeArch, "A=1")
	cache := newCache(t)
	members := annotatedLayout(t, img, map[string]string{
		annotationImageName: "docker.io/library/myapp:v2",
		annotationRefName:   "ghcr.io/org/myapp:v2",
	})

	loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch)
	if err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != sha256Digest(img.config) || loaded[0].Digest != img.digest() {
		t.Fatalf("LoadArchive = %+v, want the image %s", loaded, sha256Digest(img.config))
	}
	if want := []string{"ghcr.io/org/myapp:v2", "myapp:v2"}; !slices.Equal(familiarNames(loaded[0]), want) {
		t.Errorf("names = %v, want %v", familiarNames(loaded[0]), want)
	}
	images := listImages(t, cache)
	if len(images) != 2 {
		t.Fatalf("ListImages returned %d images, want one record per repository", len(images))
	}
	for _, i := range images {
		if !i.FromArchive() || i.ID != loaded[0].ID {
			t.Errorf("image %s = %+v, want an archive image with the loaded ID", i.Name(), i)
		}
	}
	if _, err := cache.Select("ghcr.io/org/myapp:v2", storeArch); err != nil {
		t.Errorf("Select of a loaded name: %v", err)
	}
}

func TestLoadArchiveGivesNoNameToABareTagAnnotation(t *testing.T) {
	img := twoLayerImage(t, storeArch, "A=1")
	cache := newCache(t)
	members := annotatedLayout(t, img, map[string]string{annotationRefName: "latest"})

	loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch)
	if err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	if len(loaded) != 1 || len(loaded[0].Names) != 0 {
		t.Fatalf("LoadArchive = %+v, want one image without names", loaded)
	}
	images := listImages(t, cache)
	if len(images) != 1 || images[0].Referenced() || images[0].Named() {
		t.Errorf("ListImages = %+v, want one unnamed dangling image", images)
	}
	if _, err := cache.Select(loaded[0].ID, storeArch); err != nil {
		t.Errorf("Select by ID: %v", err)
	}
}

func TestLoadArchiveRegistersRepoTagsOfADockerSaveArchive(t *testing.T) {
	img := twoLayerImage(t, storeArch, "A=1")
	cache := newCache(t)
	loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, dockerSaveMembers(t, img))), cache, storeArch)
	if err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != sha256Digest(img.config) {
		t.Fatalf("LoadArchive = %+v, want the image %s", loaded, sha256Digest(img.config))
	}
	if want := []string{"app:latest"}; !slices.Equal(familiarNames(loaded[0]), want) {
		t.Errorf("names = %v, want %v", familiarNames(loaded[0]), want)
	}
	images := listImages(t, cache)
	if len(images) != 1 || !slices.Equal(images[0].Tags, []string{"latest"}) || !images[0].FromArchive() {
		t.Fatalf("ListImages = %+v, want one archive image tagged latest", images)
	}
	// The layers carry the diff IDs as cache keys, and the record loads offline.
	if !slices.Equal(trimDigests(images[0].LayerDigests), trimDigests(images[0].DiffIDs)) {
		t.Errorf("layer keys = %v, want the diff IDs %v", images[0].LayerDigests, images[0].DiffIDs)
	}
	cached, err := cache.LoadCachedImage("", "library/app", "latest", storeArch)
	if err != nil {
		t.Fatalf("LoadCachedImage of the loaded tag: %v", err)
	}
	_ = cached.Close()
}

func TestLoadArchiveKeepsTheRegistrySourceOfAnExistingRecord(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")

	// An archive with the same manifest, named like the pulled image.
	members := annotatedLayout(t, img, map[string]string{annotationImageName: reg.ref("v1")})
	if _, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, storeArch); err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	images := listImages(t, cache)
	if len(images) != 1 || images[0].FromArchive() {
		t.Errorf("ListImages = %+v, want the registry record kept", images)
	}
}

func TestLoadArchiveSkipsImagesOfOtherArchitectures(t *testing.T) {
	amd, arm := twoLayerImage(t, "amd64", "A=amd"), twoLayerImage(t, "arm64", "A=arm")
	members := ociLayoutMembers(t, amd, arm)
	cache := newCache(t)

	loaded, err := LoadArchive(bytes.NewReader(writeArchive(t, members)), cache, "arm64")
	if err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != sha256Digest(arm.config) {
		t.Errorf("LoadArchive = %+v, want only the arm64 image", loaded)
	}
	if _, err := LoadArchive(bytes.NewReader(writeArchive(t, ociLayoutMembers(t, amd))), newCache(t), "arm64"); err == nil {
		t.Error("LoadArchive loaded an amd64-only archive for arm64")
	}
}

func TestLoadArchiveVerifiesDigestsAndFormats(t *testing.T) {
	img := twoLayerImage(t, storeArch, "A=1")
	t.Run("tampered layer", func(t *testing.T) {
		members := annotatedLayout(t, img, nil)
		tampered := replaceMember(members, "blobs/sha256/"+blobHexOf(img.blobs[0]), []byte("not the layer"))
		if _, err := LoadArchive(bytes.NewReader(writeArchive(t, tampered)), newCache(t), storeArch); err == nil {
			t.Error("LoadArchive accepted a layer that does not match its digest")
		}
	})
	t.Run("rootfs tarball", func(t *testing.T) {
		rootfs := buildTar(t, fileEntry("bin/sh", "#!"))
		if _, err := LoadArchive(bytes.NewReader(rootfs), newCache(t), storeArch); err == nil {
			t.Error("LoadArchive accepted a root filesystem tarball, which has no image name or config")
		}
	})
}

func blobHexOf(b []byte) string {
	return sha256Digest(b)[len("sha256:"):]
}
