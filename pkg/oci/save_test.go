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
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
)

// untar returns the members of a tar archive in order.
func untar(t *testing.T, raw []byte) (names []string, files map[string][]byte) {
	t.Helper()
	files = map[string][]byte{}
	tr := tar.NewReader(bytes.NewReader(raw))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, files
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read member %s: %v", hdr.Name, err)
		}
		names = append(names, hdr.Name)
		files[hdr.Name] = data
	}
}

// saveByName saves the images that the references name.
func saveByName(t *testing.T, cache *LayerCache, w io.Writer, queries ...string) error {
	t.Helper()
	var targets []SaveTarget
	for _, q := range queries {
		sel, err := cache.Select(q, storeArch)
		if err != nil {
			t.Fatalf("Select(%q): %v", q, err)
		}
		target := SaveTarget{Image: sel.Images[0]}
		if sel.Ref != nil && sel.Ref.Tag != "" {
			name := *sel.Ref
			name.Digest = ""
			target.Names = []Reference{name}
		}
		targets = append(targets, target)
	}
	return cache.SaveImages(t.Context(), w, nil, targets)
}

func TestSaveImagesRoundTripsThroughLoadArchive(t *testing.T) {
	reg := newFakeRegistry(t)
	src := newCache(t)
	img := newImageWithCreated(t, "A=1", "2024-01-02T03:04:05Z", layerOf(t, "base", "b"), layerOf(t, "app", "a"))
	pullTagged(t, reg, src, img, "v1", "latest")
	before := listImages(t, src)[0]

	var archive bytes.Buffer
	if err := saveByName(t, src, &archive, reg.ref("v1"), reg.ref("latest")); err != nil {
		t.Fatalf("SaveImages: %v", err)
	}

	dst := newCache(t)
	loaded, err := LoadArchive(bytes.NewReader(archive.Bytes()), dst, storeArch)
	if err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	if len(loaded) != 1 || loaded[0].ID != before.ID || loaded[0].Digest != before.Digest {
		t.Fatalf("LoadArchive = %+v, want the one saved image %s", loaded, before.ID)
	}
	var names []string
	for _, n := range loaded[0].Names {
		names = append(names, n.Familiar())
	}
	slices.Sort(names)
	if want := []string{reg.ref("latest"), reg.ref("v1")}; !slices.Equal(names, want) {
		t.Errorf("loaded names = %v, want %v", names, want)
	}

	after := listImages(t, dst)
	if len(after) != 1 {
		t.Fatalf("the destination lists %d images, want 1", len(after))
	}
	got := after[0]
	if got.ID != before.ID || !slices.Equal(got.Tags, before.Tags) || !slices.Equal(got.LayerDigests, before.LayerDigests) ||
		!got.Created.Equal(before.Created) || got.Config.Env[0] != "A=1" {
		t.Errorf("loaded image = %+v, want the saved image %+v", got, before)
	}
	if !got.FromArchive() || len(got.RepoDigests()) != 0 {
		t.Errorf("a loaded image has source %q and repo digests %v, want an archive source without digests", got.Source, got.RepoDigests())
	}
	cached, err := dst.LoadCachedImage(reg.srv.URL, testRepo, "v1", storeArch)
	if err != nil {
		t.Fatalf("the loaded tag does not load: %v", err)
	}
	_ = cached.Close()
}

func TestSaveImagesWritesAnOCILayoutAndADockerManifest(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	base := layerOf(t, "base", "shared")
	imgA := newTestImage(t, storeArch, "A=1", base, layerOf(t, "a", "one"))
	imgB := newTestImage(t, storeArch, "B=1", base, layerOf(t, "b", "two"))
	pullTagged(t, reg, cache, imgA, "a")
	pullTagged(t, reg, cache, imgB, "b")

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, reg.ref("a"), reg.ref("b")); err != nil {
		t.Fatalf("SaveImages: %v", err)
	}
	names, files := untar(t, archive.Bytes())

	seen := map[string]bool{}
	for _, n := range names {
		if seen[n] {
			t.Errorf("archive member %s appears twice", n)
		}
		seen[n] = true
	}
	shared := "blobs/sha256/" + strings.TrimPrefix(sha256Digest(imgA.blobs[0]), "sha256:")
	if !seen[shared] {
		t.Errorf("the shared layer %s is missing from the archive", shared)
	}
	for _, want := range []string{"oci-layout", "index.json", "manifest.json",
		"blobs/sha256/" + strings.TrimPrefix(imgA.digest(), "sha256:"),
		"blobs/sha256/" + strings.TrimPrefix(sha256Digest(imgB.config), "sha256:")} {
		if !seen[want] {
			t.Errorf("archive member %s is missing", want)
		}
	}
	// Blob contents are the original registry bytes.
	for _, b := range append(slices.Clone(imgA.blobs), imgB.blobs...) {
		member := "blobs/sha256/" + strings.TrimPrefix(sha256Digest(b), "sha256:")
		if !bytes.Equal(files[member], b) {
			t.Errorf("member %s differs from the registry blob", member)
		}
	}

	var manifest []dockerSaveEntry
	if err := json.Unmarshal(files["manifest.json"], &manifest); err != nil {
		t.Fatalf("manifest.json: %v", err)
	}
	if len(manifest) != 2 {
		t.Fatalf("manifest.json has %d entries, want 2", len(manifest))
	}
	for i, entry := range manifest {
		if !seen[entry.Config] || len(entry.Layers) != 2 || len(entry.RepoTags) != 1 {
			t.Errorf("manifest entry %d = %+v, want a config member, two layers, and one tag", i, entry)
		}
		for _, l := range entry.Layers {
			if !seen[l] {
				t.Errorf("manifest entry %d names the missing member %s", i, l)
			}
		}
	}
	if manifest[0].RepoTags[0] != reg.ref("a") || manifest[1].RepoTags[0] != reg.ref("b") {
		t.Errorf("RepoTags = %v and %v", manifest[0].RepoTags, manifest[1].RepoTags)
	}

	var index ImageIndex
	if err := json.Unmarshal(files["index.json"], &index); err != nil {
		t.Fatalf("index.json: %v", err)
	}
	if len(index.Manifests) != 2 || index.Manifests[0].Annotations[annotationRefName] != reg.ref("a") {
		t.Errorf("index.json = %+v, want two named manifests", index)
	}
}

func TestSaveImagesOutputLoadsWithLoadArchiveTar(t *testing.T) {
	reg := newFakeRegistry(t)
	src := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, src, img, "v1")
	var archive bytes.Buffer
	if err := saveByName(t, src, &archive, reg.ref("v1")); err != nil {
		t.Fatalf("SaveImages: %v", err)
	}

	got, err := LoadArchiveTar(bytes.NewReader(archive.Bytes()), newCache(t), storeArch)
	if err != nil {
		t.Fatalf("LoadArchiveTar: %v", err)
	}
	defer got.Close()
	if want := trimDigests(blobDigests(img)); !slices.Equal(got.LayerDigests, want) {
		t.Errorf("layer digests = %v, want %v", got.LayerDigests, want)
	}
}

func TestSaveImagesFailsBeforeWritingForAnImageWithoutRegistrySource(t *testing.T) {
	src := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	if _, err := LoadArchive(bytes.NewReader(writeArchive(t, dockerSaveMembers(t, img))), src, storeArch); err != nil {
		t.Fatalf("LoadArchive: %v", err)
	}
	var out bytes.Buffer
	err := saveByName(t, src, &out, "app:latest")
	if !errors.Is(err, ErrNoRegistrySource) {
		t.Fatalf("SaveImages error = %v, want ErrNoRegistrySource", err)
	}
	if out.Len() != 0 {
		t.Errorf("SaveImages wrote %d bytes before it failed", out.Len())
	}
}

func TestSaveImagesRejectsABlobThatDiffersFromItsDescriptor(t *testing.T) {
	for name, damage := range map[string]func(blob []byte) []byte{
		"same size, other content": func(b []byte) []byte {
			c := slices.Clone(b)
			c[len(c)-1] ^= 0xff
			return c
		},
		"shorter":    func(b []byte) []byte { return b[:len(b)-1] },
		"longer":     func(b []byte) []byte { return append(slices.Clone(b), 0) },
		"empty body": func([]byte) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			reg := newFakeRegistry(t)
			cache := newCache(t)
			img := twoLayerImage(t, storeArch, "A=1")
			pullTagged(t, reg, cache, img, "v1")
			reg.mu.Lock()
			reg.tamperBlob[sha256Digest(img.blobs[1])] = damage(img.blobs[1])
			reg.mu.Unlock()

			err := saveByName(t, cache, io.Discard, reg.ref("v1"))
			if !errors.Is(err, ErrDigestMismatch) {
				t.Errorf("SaveImages error = %v, want ErrDigestMismatch", err)
			}
		})
	}
}

func TestSaveImagesFetchesBlobsFromTheOriginOfACopiedTag(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")
	target, err := ParseReference("mine/copy:dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Tag(listImages(t, cache)[0], target); err != nil {
		t.Fatal(err)
	}

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, "mine/copy:dev"); err != nil {
		t.Fatalf("SaveImages of the copy: %v", err)
	}
	loaded, err := LoadArchive(bytes.NewReader(archive.Bytes()), newCache(t), storeArch)
	if err != nil || len(loaded) != 1 || len(loaded[0].Names) != 1 || loaded[0].Names[0].Familiar() != "mine/copy:dev" {
		t.Fatalf("LoadArchive = %+v, %v, want the image named mine/copy:dev", loaded, err)
	}
}

func TestSaveImagesByIDWritesAnImageWithoutAName(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	id := listImages(t, cache)[0].ID

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, id); err != nil {
		t.Fatalf("SaveImages: %v", err)
	}
	loaded, err := LoadArchive(bytes.NewReader(archive.Bytes()), newCache(t), storeArch)
	if err != nil || len(loaded) != 1 || len(loaded[0].Names) != 0 || loaded[0].ID != id {
		t.Fatalf("LoadArchive = %+v, %v, want one unnamed image %s", loaded, err, id)
	}
}

func TestSaveImagesRejectsAnEmptyTargetList(t *testing.T) {
	if err := newCache(t).SaveImages(t.Context(), io.Discard, nil, nil); err == nil {
		t.Error("SaveImages accepted no images")
	}
}
