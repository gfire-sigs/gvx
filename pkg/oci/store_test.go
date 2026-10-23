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
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestListImagesReportsNamesTagsSizeAndConfig(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	base := layerOf(t, "base", "b")
	img := newImageWithCreated(t, "A=1", "2024-05-06T07:08:09.5Z", base, layerOf(t, "app", "a"))
	pullTagged(t, reg, cache, img, "v1", "latest")

	images := listImages(t, cache)
	if len(images) != 1 {
		t.Fatalf("ListImages returned %d images, want 1", len(images))
	}
	got := images[0]
	if want := []string{"latest", "v1"}; !slices.Equal(got.Tags, want) {
		t.Errorf("Tags = %v, want %v", got.Tags, want)
	}
	if want := reg.host() + "/" + testRepo; got.Name() != want {
		t.Errorf("Name() = %q, want %q", got.Name(), want)
	}
	if got.ID != sha256Digest(img.config) || got.Digest != img.digest() {
		t.Errorf("ID = %s, Digest = %s, want config digest %s and manifest digest %s", got.ID, got.Digest, sha256Digest(img.config), img.digest())
	}
	if want := time.Date(2024, 5, 6, 7, 8, 9, 500_000_000, time.UTC); !got.Created.Equal(want) {
		t.Errorf("Created = %v, want %v", got.Created, want)
	}
	if !slices.Equal(got.LayerDigests, blobDigests(img)) {
		t.Errorf("LayerDigests = %v, want %v", got.LayerDigests, blobDigests(img))
	}
	var wantSize int64
	for _, d := range got.LayerDigests {
		p, err := cache.LayerPath(d)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		wantSize += info.Size()
	}
	if got.Size != wantSize || wantSize == 0 {
		t.Errorf("Size = %d, want the sum %d of the layer file sizes", got.Size, wantSize)
	}
	if got.Config.Env[0] != "A=1" || got.OS != "linux" || got.Architecture != storeArch {
		t.Errorf("config = %+v os %q arch %q", got.Config, got.OS, got.Architecture)
	}
	if want := []string{reg.host() + "/" + testRepo + "@" + img.digest()}; !slices.Equal(got.RepoDigests(), want) {
		t.Errorf("RepoDigests = %v, want %v", got.RepoDigests(), want)
	}
	if want := []string{reg.ref("latest"), reg.ref("v1")}; !slices.Equal(got.RepoTags(), want) {
		t.Errorf("RepoTags = %v, want %v", got.RepoTags(), want)
	}
}

func TestListImagesShowsDigestPullsAsPinned(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	digest := reg.addImage(img)
	mustPull(t, reg, cache, digest, storeArch)

	images := listImages(t, cache)
	if len(images) != 1 || !images[0].Pinned || len(images[0].Tags) != 0 || !images[0].Referenced() {
		t.Fatalf("ListImages = %+v, want one pinned image without tags", images)
	}
}

func TestListImagesFlagsTheOldImageOfAMovedTagAsDangling(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	first := twoLayerImage(t, storeArch, "A=1")
	second := twoLayerImage(t, storeArch, "A=2")
	pullTagged(t, reg, cache, first, "v1")
	pullTagged(t, reg, cache, second, "v1")

	byDigest := map[string]Image{}
	for _, img := range listImages(t, cache) {
		byDigest[img.Digest] = img
	}
	if len(byDigest) != 2 {
		t.Fatalf("ListImages returned %d images, want 2", len(byDigest))
	}
	if got := byDigest[second.digest()]; !slices.Equal(got.Tags, []string{"v1"}) {
		t.Errorf("the new image has tags %v, want [v1]", got.Tags)
	}
	if old := byDigest[first.digest()]; old.Referenced() {
		t.Errorf("the old image of the moved tag is still referenced: %+v", old)
	}
}

func TestListImagesKeepsTagRecordsFromBeforeNamesExisted(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")

	// Rewrite the tag record in the old form, which holds only the digest.
	p := cache.tagRecordPath(reg.srv.URL, testRepo, "v1", storeArch)
	if err := os.WriteFile(p, []byte(`{"digest":"`+img.digest()+`"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	images := listImages(t, cache)
	if len(images) != 1 || len(images[0].Tags) != 0 || !images[0].Referenced() {
		t.Fatalf("ListImages = %+v, want one image without listed tags that stays referenced", images)
	}
	cached, err := cache.LoadCachedImage(reg.srv.URL, testRepo, "v1", storeArch)
	if err != nil {
		t.Fatalf("the old tag record no longer loads: %v", err)
	}
	_ = cached.Close()

	// The next pull writes the names, so the cache upgrades by itself.
	mustPull(t, reg, cache, "v1", storeArch)
	if images := listImages(t, cache); len(images) != 1 || !slices.Equal(images[0].Tags, []string{"v1"}) {
		t.Errorf("after a pull ListImages = %+v, want the tag v1", images)
	}
}

func TestListImagesIgnoresOtherArchitecturesAndOtherLayerFormats(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")

	if images, err := cache.ListImages("arm64"); err != nil || len(images) != 0 {
		t.Errorf("ListImages(arm64) = %v, %v, want none", images, err)
	}
	other, err := NewLayerCacheWithOptions(cache.Dir(), CacheOptions{BlockSize: cache.BlockSize() * 2})
	if err != nil {
		t.Skipf("no second block size: %v", err)
	}
	if images, err := other.ListImages(storeArch); err != nil || len(images) != 0 {
		t.Errorf("a cache with another block size lists %v, %v, want none", images, err)
	}
}

func TestTagAddsATagInTheSameRepository(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	img := listImages(t, cache)[0]

	target, err := ParseReference(reg.ref("stable"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Tag(img, target); err != nil {
		t.Fatalf("Tag: %v", err)
	}
	images := listImages(t, cache)
	if len(images) != 1 || !slices.Equal(images[0].Tags, []string{"stable", "v1"}) {
		t.Errorf("ListImages = %+v, want one image with tags stable and v1", images)
	}
}

func TestTagCopiesTheRecordToAnotherRepositoryAndRegistry(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	img := listImages(t, cache)[0]

	for _, name := range []string{"localhost:5000/team/app:prod", "ghcr.io/org/copy:1", "mine:dev"} {
		target, err := ParseReference(name)
		if err != nil {
			t.Fatal(err)
		}
		if err := cache.Tag(img, target); err != nil {
			t.Fatalf("Tag(%s): %v", name, err)
		}
	}

	images := listImages(t, cache)
	if len(images) != 4 {
		t.Fatalf("ListImages returned %d images, want the original and three copies", len(images))
	}
	names := map[string][]string{}
	for _, i := range images {
		if i.ID != img.ID || i.Digest != img.Digest {
			t.Errorf("copy %s has ID %s digest %s, want %s and %s", i.Name(), i.ID, i.Digest, img.ID, img.Digest)
		}
		names[i.Name()] = i.RepoTags()
	}
	want := map[string][]string{
		reg.host() + "/" + testRepo: {reg.ref("v1")},
		"localhost:5000/team/app":   {"localhost:5000/team/app:prod"},
		"ghcr.io/org/copy":          {"ghcr.io/org/copy:1"},
		"mine":                      {"mine:dev"},
	}
	if !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}

	// A copy loads offline under its own key and shares the layer files.
	copied, err := cache.LoadCachedImage("http://localhost:5000", "team/app", "prod", storeArch)
	if err != nil {
		t.Fatalf("LoadCachedImage of the copy: %v", err)
	}
	defer copied.Close()
	if !slices.Equal(copied.LayerDigests, trimDigests(img.LayerDigests)) {
		t.Errorf("copy layers = %v, want %v", copied.LayerDigests, img.LayerDigests)
	}
}

func trimDigests(digests []string) []string {
	out := make([]string, len(digests))
	for i, d := range digests {
		out[i] = strings.TrimPrefix(d, "sha256:")
	}
	return out
}

func TestTagRejectsADigestTarget(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	img := listImages(t, cache)[0]
	target, err := ParseReference("other@" + img.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Tag(img, target); err == nil {
		t.Error("Tag accepted a digest as the target")
	}
}

func TestSelectFindsImagesByNameDigestAndIDPrefix(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")
	id := sha256Digest(img.config)
	idHex := strings.TrimPrefix(id, "sha256:")

	for _, tc := range []struct {
		name  string
		query string
		byRef bool
	}{
		{"name and tag", reg.ref("v1"), true},
		{"name and digest", reg.host() + "/" + testRepo + "@" + img.digest(), true},
		{"full ID", id, false},
		{"bare ID", idHex, false},
		{"twelve digit prefix", idHex[:12], false},
		{"four digit prefix", idHex[:4], false},
		{"manifest digest", img.digest(), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sel, err := cache.Select(tc.query, storeArch)
			if err != nil {
				t.Fatalf("Select(%q): %v", tc.query, err)
			}
			if len(sel.Images) != 1 || sel.Images[0].ID != id {
				t.Fatalf("Select(%q) = %+v, want the image %s", tc.query, sel.Images, id)
			}
			if (sel.Ref != nil) != tc.byRef {
				t.Errorf("Select(%q) Ref = %v, want a reference: %v", tc.query, sel.Ref, tc.byRef)
			}
		})
	}
}

func TestSelectRejectsUnknownNamesAndShortPrefixes(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1")
	idHex := strings.TrimPrefix(sha256Digest(img.config), "sha256:")

	for _, query := range []string{reg.ref("missing"), "nothing:1", idHex[:3], "ffff" + idHex[4:], "UPPER/case", ""} {
		if _, err := cache.Select(query, storeArch); !errors.Is(err, ErrNotCached) {
			t.Errorf("Select(%q) error = %v, want ErrNotCached", query, err)
		}
	}
}

func TestSelectByIDPrefixReportsAmbiguity(t *testing.T) {
	images := []Image{
		{ID: "sha256:abcd1111" + strings.Repeat("0", 56)},
		{ID: "sha256:abcd2222" + strings.Repeat("0", 56)},
	}
	if _, err := selectByID(images, "abcd"); !errors.Is(err, ErrAmbiguousImage) {
		t.Errorf("selectByID(abcd) error = %v, want ErrAmbiguousImage", err)
	}
	if sel, err := selectByID(images, "abcd1"); err != nil || len(sel.Images) != 1 {
		t.Errorf("selectByID(abcd1) = %+v, %v, want one image", sel, err)
	}
}

func TestSelectByIDReturnsEveryRepositoryOfTheImage(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	img := listImages(t, cache)[0]
	target, err := ParseReference("mine:dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Tag(img, target); err != nil {
		t.Fatal(err)
	}
	sel, err := cache.Select(img.ID, storeArch)
	if err != nil || len(sel.Images) != 2 {
		t.Fatalf("Select(ID) = %+v, %v, want both repositories", sel.Images, err)
	}
}

func TestUntagKeepsTheImageWhileAnotherTagNamesIt(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1", "latest")
	stored := listImages(t, cache)[0]

	report, err := cache.Untag(stored, "v1")
	if err != nil {
		t.Fatalf("Untag: %v", err)
	}
	if want := []string{reg.ref("v1")}; !slices.Equal(report.Untagged, want) || len(report.Deleted) != 0 {
		t.Errorf("report = %+v, want only %v untagged", report, want)
	}
	images := listImages(t, cache)
	if len(images) != 1 || !slices.Equal(images[0].Tags, []string{"latest"}) {
		t.Errorf("ListImages = %+v, want one image with the tag latest", images)
	}
	for _, d := range stored.LayerDigests {
		if len(layerFiles(t, cache, d)) != 2 {
			t.Errorf("layer %s lost its files", d)
		}
	}
}

func TestUntagOfTheLastTagDeletesTheImageButKeepsSharedLayers(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	base := layerOf(t, "base", "shared")
	imgA := newTestImage(t, storeArch, "A=1", base, layerOf(t, "a", "only-a"))
	imgB := newTestImage(t, storeArch, "B=1", base, layerOf(t, "b", "only-b"))
	pullTagged(t, reg, cache, imgA, "a")
	pullTagged(t, reg, cache, imgB, "b")
	var stored Image
	for _, i := range listImages(t, cache) {
		if i.ID == sha256Digest(imgA.config) {
			stored = i
		}
	}

	report, err := cache.Untag(stored, "a")
	if err != nil {
		t.Fatalf("Untag: %v", err)
	}
	wantUntagged := []string{reg.ref("a"), reg.host() + "/" + testRepo + "@" + imgA.digest()}
	if !slices.Equal(report.Untagged, wantUntagged) || !slices.Equal(report.Deleted, []string{stored.ID}) {
		t.Errorf("report = %+v, want untagged %v and deleted [%s]", report, wantUntagged, stored.ID)
	}

	sharedDigest, uniqueDigest := stored.LayerDigests[0], stored.LayerDigests[1]
	if got := layerFiles(t, cache, sharedDigest); len(got) != 2 {
		t.Errorf("the shared layer lost files: %v", got)
	}
	if got := layerFiles(t, cache, uniqueDigest); len(got) != 0 {
		t.Errorf("the unshared layer kept files: %v", got)
	}
	left := listImages(t, cache)
	if len(left) != 1 || left[0].ID != sha256Digest(imgB.config) {
		t.Fatalf("ListImages = %+v, want only image B", left)
	}
	loaded, err := cache.LoadCachedImage(reg.srv.URL, testRepo, "b", storeArch)
	if err != nil {
		t.Fatalf("image B no longer loads: %v", err)
	}
	_ = loaded.Close()
	if _, err := cache.LoadCachedImage(reg.srv.URL, testRepo, "a", storeArch); !errors.Is(err, ErrNotCached) {
		t.Errorf("LoadCachedImage of the removed image = %v, want ErrNotCached", err)
	}
}

func TestRemoveDeletesEveryNameAndAllUnsharedLayers(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	pullTagged(t, reg, cache, img, "v1", "latest")
	mustPull(t, reg, cache, img.digest(), storeArch)
	stored := listImages(t, cache)[0]
	if !stored.Pinned {
		t.Fatal("the digest pull did not pin the image")
	}

	report, err := cache.Remove(stored)
	if err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if !slices.Equal(report.Deleted, []string{stored.ID}) {
		t.Errorf("Deleted = %v, want [%s]", report.Deleted, stored.ID)
	}
	for _, want := range []string{reg.ref("latest"), reg.ref("v1"), reg.host() + "/" + testRepo + "@" + img.digest()} {
		if !slices.Contains(report.Untagged, want) {
			t.Errorf("Untagged = %v, want it to hold %s", report.Untagged, want)
		}
	}
	if images := listImages(t, cache); len(images) != 0 {
		t.Errorf("ListImages = %+v, want none", images)
	}
	entries, err := os.ReadDir(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		t.Errorf("the cache directory still holds %s", e.Name())
	}
}

func TestUntagOfOneRepositoryCopyKeepsTheImageOfTheOther(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	img := listImages(t, cache)[0]
	target, err := ParseReference("mine:dev")
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Tag(img, target); err != nil {
		t.Fatal(err)
	}
	var copied Image
	for _, i := range listImages(t, cache) {
		if i.Name() == "mine" {
			copied = i
		}
	}

	report, err := cache.Untag(copied, "dev")
	if err != nil {
		t.Fatalf("Untag: %v", err)
	}
	if len(report.Deleted) != 0 {
		t.Errorf("Deleted = %v, want none because the original repository still has the image", report.Deleted)
	}
	for _, d := range img.LayerDigests {
		if len(layerFiles(t, cache, d)) != 2 {
			t.Errorf("layer %s lost its files", d)
		}
	}
	loaded, err := cache.LoadCachedImage(reg.srv.URL, testRepo, "v1", storeArch)
	if err != nil {
		t.Fatalf("the original no longer loads: %v", err)
	}
	_ = loaded.Close()
}

func TestUntagOfAnUnknownTagFails(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")
	if _, err := cache.Untag(listImages(t, cache)[0], "nope"); !errors.Is(err, ErrNotCached) {
		t.Errorf("Untag error = %v, want ErrNotCached", err)
	}
}

func TestCachedDigestFollowsTagsAndRecords(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	img := twoLayerImage(t, storeArch, "A=1")
	if _, ok := cache.CachedDigest(reg.srv.URL, testRepo, "v1", storeArch); ok {
		t.Fatal("CachedDigest found an image in an empty cache")
	}
	pullTagged(t, reg, cache, img, "v1")
	if got, ok := cache.CachedDigest(reg.srv.URL, testRepo, "v1", storeArch); !ok || got != img.digest() {
		t.Errorf("CachedDigest(tag) = %q, %v, want %s", got, ok, img.digest())
	}
	if got, ok := cache.CachedDigest(reg.srv.URL, testRepo, img.digest(), storeArch); !ok || got != img.digest() {
		t.Errorf("CachedDigest(digest) = %q, %v, want %s", got, ok, img.digest())
	}
}

func TestTagRecordsKeepTheirOldKeysAndGainNames(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)
	pullTagged(t, reg, cache, twoLayerImage(t, storeArch, "A=1"), "v1")

	p := cache.tagRecordPath(reg.srv.URL, testRepo, "v1", storeArch)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("the tag record is not at its old path %s: %v", filepath.Base(p), err)
	}
	var rec tagRecord
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Repository != testRepo || rec.Tag != "v1" || rec.Architecture != storeArch || rec.BaseURL != reg.srv.URL || !isDigestRef(rec.Digest) {
		t.Errorf("tag record = %+v, want names and a digest", rec)
	}
}
