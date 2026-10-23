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
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// The image store lists, finds, tags, and removes the images that pulls and
// loads recorded in a LayerCache. It adds no new on-disk state: it reads the
// image records and the tag records.
//
// A concurrent pull, tag, or removal of the same image can race. The store
// takes no cross-process lock.

var (
	// ErrAmbiguousImage reports an image ID prefix that matches several images.
	ErrAmbiguousImage = errors.New("oci: the image ID prefix matches several images")
	// ErrNoRegistrySource reports an image whose original layer blobs are
	// not in any registry, because it came from an archive.
	ErrNoRegistrySource = errors.New("oci: the image has no registry source for its original layers")
)

// minIDPrefix is the shortest image ID prefix that selects an image.
const minIDPrefix = 4

// Image is one cached image under one repository. The same image under
// another repository or registry is another Image with the same ID.
type Image struct {
	// BaseURL and Repository name the repository of the image. An image that an
	// archive carried without a name has neither.
	BaseURL    string
	Repository string
	// Architecture is the Linux architecture of the cache entry.
	Architecture string
	// Digest is the manifest digest. An archive in the "docker save" format has
	// no manifest, so its images get the digest of a manifest that the loader
	// wrote.
	Digest string
	// ID is the digest of the image config.
	ID string
	// Tags lists the tags that name the image, sorted. A tag recorded before
	// the cache kept names is not listed.
	Tags []string
	// Pinned reports a reference by digest, as in "name@sha256:...".
	Pinned bool
	// OS is the operating system of the config.
	OS string
	// Created is the creation time of the config. It is zero when the config
	// has none.
	Created time.Time
	// Size is the sum of the sizes of the layer images in the cache.
	Size int64
	// LayerDigests lists the layer blob digests, from the lowest layer up, as
	// "sha256:<hex>". They are the cache keys of the layer images.
	LayerDigests []string
	// DiffIDs lists the digests of the uncompressed layers.
	DiffIDs []string
	// Config is the runtime config of the image.
	Config RuntimeConfig
	// Source is "archive" for an image that came from an archive, or empty for
	// an image that a registry pull recorded.
	Source string

	record imageRecord
	// legacyTagged reports a tag record without names that points to the image.
	legacyTagged bool
}

// FromArchive reports whether the image came from an archive.
func (i Image) FromArchive() bool { return i.Source == sourceArchive }

// Named reports whether the image has a repository.
func (i Image) Named() bool { return i.Repository != "" }

// Registry returns the registry name of the image, "docker.io" for Docker Hub.
func (i Image) Registry() string { return registryOfBaseURL(i.BaseURL) }

// Reference returns the reference of the image under a tag. A digest as tag
// returns the reference by digest.
func (i Image) Reference(tag string) Reference {
	ref := referenceOf(i.BaseURL, i.Repository)
	if isDigestRef(tag) {
		ref.Digest = tag
	} else {
		ref.Tag = tag
	}
	return ref
}

// Name returns the repository name as users write it, such as "alpine" or
// "ghcr.io/org/img". It is empty for an unnamed image.
func (i Image) Name() string {
	if !i.Named() {
		return ""
	}
	return referenceOf(i.BaseURL, i.Repository).FamiliarName()
}

// RepoTags returns the familiar "name:tag" form of every tag.
func (i Image) RepoTags() []string {
	tags := make([]string, 0, len(i.Tags))
	for _, tag := range i.Tags {
		tags = append(tags, i.Reference(tag).Familiar())
	}
	return tags
}

// RepoDigests returns "name@digest" for an image that came from a registry.
func (i Image) RepoDigests() []string {
	if !i.Named() || i.FromArchive() {
		return nil
	}
	return []string{i.Reference(i.Digest).Familiar()}
}

// Referenced reports whether a tag or a digest names the image. An image that
// nothing names, such as the earlier image of a moved tag, is dangling.
func (i Image) Referenced() bool {
	return len(i.Tags) > 0 || i.Pinned || i.legacyTagged
}

// blobSource returns the repository that holds the original layer blobs.
func (i Image) blobSource() (baseURL, repository string, err error) {
	if i.FromArchive() {
		return "", "", fmt.Errorf("%w: it came from an archive", ErrNoRegistrySource)
	}
	if i.record.OriginRepository != "" {
		return i.record.OriginBaseURL, i.record.OriginRepository, nil
	}
	if !i.Named() {
		return "", "", fmt.Errorf("%w: it has no repository", ErrNoRegistrySource)
	}
	return i.BaseURL, i.Repository, nil
}

// imageKey identifies the image record of one repository.
func imageKey(baseURL, repository, digest string) string {
	return strings.ToLower(baseURL) + "\x00" + repository + "\x00" + digest
}

func (i Image) key() string { return imageKey(i.BaseURL, i.Repository, i.Digest) }

// storedTag is a tag record with the path of its file.
type storedTag struct {
	path string
	rec  tagRecord
}

// readTagRecords reads every tag record of the cache directory. A record that
// does not parse is skipped. A named record whose names do not hash to its
// file name belongs to another layer format or was edited, and is skipped too.
func (c *LayerCache) readTagRecords() ([]storedTag, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("oci: list cache directory: %w", err)
	}
	var tags []storedTag
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, tagPrefix) || !strings.HasSuffix(name, cacheJSONSuffix) {
			continue
		}
		path := filepath.Join(c.dir, name)
		raw, err := readFileShared(path)
		if err != nil {
			continue
		}
		var rec tagRecord
		if err := json.Unmarshal(raw, &rec); err != nil || !isDigestRef(rec.Digest) {
			continue
		}
		if rec.named() && c.tagRecordPath(rec.BaseURL, rec.Repository, rec.Tag, rec.Architecture) != path {
			continue
		}
		tags = append(tags, storedTag{path: path, rec: rec})
	}
	return tags, nil
}

// ListImages returns the cached images for the Linux architecture arch, newest
// first. It reads records and file sizes, and it does not hash layers. A
// record that fails its verification is left out. An empty arch selects the
// host architecture.
func (c *LayerCache) ListImages(arch string) ([]Image, error) {
	_, _, _, arch = normalizePullArgs("", "", "", arch)
	tags, err := c.readTagRecords()
	if err != nil {
		return nil, err
	}
	names := make(map[string][]string)
	pinned := make(map[string]bool)
	legacy := make(map[string]bool)
	for _, t := range tags {
		if !t.rec.named() {
			legacy[t.rec.Digest] = true
			continue
		}
		if t.rec.Architecture != arch {
			continue
		}
		key := imageKey(t.rec.BaseURL, t.rec.Repository, t.rec.Digest)
		if t.rec.Tag == t.rec.Digest {
			pinned[key] = true
		} else {
			names[key] = append(names[key], t.rec.Tag)
		}
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("oci: list cache directory: %w", err)
	}
	var images []Image
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, imagePrefix) || !strings.HasSuffix(name, cacheJSONSuffix) {
			continue
		}
		raw, err := readFileShared(filepath.Join(c.dir, name))
		if err != nil {
			continue
		}
		rec, dec, err := c.decodeRecord(raw, "", arch)
		if err != nil {
			continue
		}
		img := c.newImage(rec, dec)
		img.Tags = names[img.key()]
		slices.Sort(img.Tags)
		img.Pinned = pinned[img.key()]
		img.legacyTagged = legacy[img.Digest]
		images = append(images, img)
	}
	slices.SortFunc(images, func(a, b Image) int {
		return cmp.Or(
			b.Created.Compare(a.Created),
			cmp.Compare(a.Name(), b.Name()),
			cmp.Compare(a.ID, b.ID),
			cmp.Compare(a.Digest, b.Digest),
		)
	})
	return images, nil
}

// newImage builds an Image from a verified record.
func (c *LayerCache) newImage(rec imageRecord, dec *decodedRecord) Image {
	img := Image{
		BaseURL: rec.BaseURL, Repository: rec.Repository, Architecture: rec.Architecture,
		Digest: rec.Digest, ID: dec.manifest.Config.Digest,
		Config: dec.cfg, Source: rec.Source, record: rec,
	}
	var cfg imageConfigFile
	if err := json.Unmarshal(dec.config, &cfg); err == nil {
		img.OS = cfg.OS
		img.DiffIDs = cfg.RootFS.DiffIDs
		if t, err := time.Parse(time.RFC3339Nano, cfg.Created); err == nil {
			img.Created = t
		}
	}
	for _, hexStr := range dec.layerHex {
		img.LayerDigests = append(img.LayerDigests, "sha256:"+hexStr)
		if info, err := os.Stat(filepath.Join(c.dir, hexStr+c.layerSuffix())); err == nil {
			img.Size += info.Size()
		}
	}
	return img
}

// Selection is the result of Select.
type Selection struct {
	// Images holds the selected records. A name selects one record. An image ID
	// or a manifest digest selects every record with that ID or digest.
	Images []Image
	// Ref is set when the query named a tag or a digest of a repository.
	Ref *Reference
}

// Select finds the images that query names. A query is one of these: a
// reference such as "alpine:3.20" or "name@sha256:...", an image ID, an ID
// prefix of at least four hex digits, or a manifest digest. A name wins over
// an ID prefix. The error wraps ErrNotCached when nothing matches. It wraps
// ErrAmbiguousImage when a prefix matches several IDs.
func (c *LayerCache) Select(query, arch string) (Selection, error) {
	_, _, _, arch = normalizePullArgs("", "", "", arch)
	images, err := c.ListImages(arch)
	if err != nil {
		return Selection{}, err
	}
	if ref, err := ParseReference(query); err == nil {
		img, found, err := c.imageByReference(images, ref, arch)
		if err != nil {
			return Selection{}, err
		}
		if found {
			return Selection{Images: []Image{img}, Ref: &ref}, nil
		}
	}
	return selectByID(images, query)
}

func (c *LayerCache) imageByReference(images []Image, ref Reference, arch string) (Image, bool, error) {
	digest := ref.Digest
	if digest == "" {
		raw, err := readFileShared(c.tagRecordPath(ref.BaseURL(), ref.Repository, ref.Tag, arch))
		if errors.Is(err, os.ErrNotExist) {
			return Image{}, false, nil
		}
		if err != nil {
			return Image{}, false, fmt.Errorf("oci: read tag record: %w", err)
		}
		var tr tagRecord
		if err := json.Unmarshal(raw, &tr); err != nil || !isDigestRef(tr.Digest) {
			return Image{}, false, nil
		}
		digest = tr.Digest
	}
	want := imageKey(ref.BaseURL(), ref.Repository, digest)
	for _, img := range images {
		if img.key() == want {
			return img, true, nil
		}
	}
	return Image{}, false, nil
}

func selectByID(images []Image, query string) (Selection, error) {
	q := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(query)), "sha256:")
	if len(q) < minIDPrefix || len(q) > 64 || normalizeDigestHex(q) != q {
		return Selection{}, fmt.Errorf("%w: %s", ErrNotCached, query)
	}
	var matches []Image
	ids := make(map[string]bool)
	for _, img := range images {
		if strings.HasPrefix(strings.TrimPrefix(img.ID, "sha256:"), q) {
			matches = append(matches, img)
			ids[img.ID] = true
		}
	}
	if len(q) == 64 && len(matches) == 0 {
		for _, img := range images {
			if img.Digest == "sha256:"+q {
				matches = append(matches, img)
			}
		}
	}
	switch {
	case len(matches) == 0:
		return Selection{}, fmt.Errorf("%w: %s", ErrNotCached, query)
	case len(ids) > 1:
		return Selection{}, fmt.Errorf("%w: %s", ErrAmbiguousImage, query)
	}
	return Selection{Images: matches}, nil
}

// Tag gives img another name. The target must carry a tag and no digest. A
// target in the repository of img adds a tag record. A target in another
// repository or registry also copies the image record under the target key.
// The layer images stay shared. The copy remembers the repository that holds
// the original blobs, so that SaveImages still works.
func (c *LayerCache) Tag(img Image, target Reference) error {
	if target.Tag == "" || target.Digest != "" {
		return fmt.Errorf("oci: tag target %s must have a tag and no digest", target.Familiar())
	}
	baseURL := target.BaseURL()
	if imageKey(baseURL, target.Repository, img.Digest) != img.key() {
		if err := c.copyRecord(img, baseURL, target.Repository); err != nil {
			return err
		}
	}
	return c.storeTag(baseURL, target.Repository, target.Tag, img.Architecture, img.Digest)
}

// copyRecord writes the record of img under another repository. An existing
// record there stays, because it holds the same content.
func (c *LayerCache) copyRecord(img Image, baseURL, repository string) error {
	p := c.imageRecordPath(baseURL, repository, img.Digest, img.Architecture)
	if raw, err := readFileShared(p); err == nil {
		if _, _, err := c.decodeRecord(raw, img.Digest, img.Architecture); err == nil {
			return nil
		}
	}
	rec := img.record
	if rec.Source != sourceArchive && rec.OriginRepository == "" && img.Named() {
		rec.OriginBaseURL, rec.OriginRepository = img.BaseURL, img.Repository
	}
	rec.BaseURL, rec.Repository = baseURL, repository
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("oci: encode image record: %w", err)
	}
	return writeFileAtomic(filepath.Dir(p), filepath.Base(p), raw)
}

// RemoveReport lists what a removal changed.
type RemoveReport struct {
	// Untagged lists the references that no longer exist, in familiar form.
	Untagged []string
	// Deleted lists the IDs of the images that no longer exist in the cache.
	Deleted []string
}

// Untag removes one tag of img. A digest passed as tag removes the reference by
// digest. When nothing else names the image, Untag deletes the image record
// and the layer images that no other image uses.
func (c *LayerCache) Untag(img Image, tag string) (RemoveReport, error) {
	var report RemoveReport
	if err := c.removeTagRecord(img, tag, &report); err != nil {
		return report, err
	}
	referenced, err := c.stillReferenced(img)
	if err != nil || referenced {
		return report, err
	}
	return report, c.dropRecord(img, &report)
}

// Remove deletes every name of img, its image record, and the layer images that
// no other image uses.
func (c *LayerCache) Remove(img Image) (RemoveReport, error) {
	var report RemoveReport
	for _, tag := range img.Tags {
		if err := c.removeTagRecord(img, tag, &report); err != nil {
			return report, err
		}
	}
	if img.Pinned {
		if err := c.removeTagRecord(img, img.Digest, &report); err != nil {
			return report, err
		}
	}
	return report, c.dropRecord(img, &report)
}

func (c *LayerCache) removeTagRecord(img Image, tag string, report *RemoveReport) error {
	err := os.Remove(c.tagRecordPath(img.BaseURL, img.Repository, tag, img.Architecture))
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrNotCached, img.Reference(tag).Familiar())
	}
	if err != nil {
		return fmt.Errorf("oci: remove tag record: %w", err)
	}
	if img.Named() {
		report.Untagged = append(report.Untagged, img.Reference(tag).Familiar())
	}
	return nil
}

// stillReferenced reports whether a tag record other than the removed ones
// still names the image record.
func (c *LayerCache) stillReferenced(img Image) (bool, error) {
	tags, err := c.readTagRecords()
	if err != nil {
		return false, err
	}
	for _, t := range tags {
		if !t.rec.named() {
			if t.rec.Digest == img.Digest {
				return true, nil
			}
			continue
		}
		if t.rec.Architecture == img.Architecture && imageKey(t.rec.BaseURL, t.rec.Repository, t.rec.Digest) == img.key() {
			return true, nil
		}
	}
	return false, nil
}

// dropRecord deletes the image record of img and the layer images that no
// remaining record uses. When no record with the same ID remains, the image
// is gone, so the report also lists its reference by digest and its ID.
func (c *LayerCache) dropRecord(img Image, report *RemoveReport) error {
	if err := os.Remove(c.imageRecordPath(img.BaseURL, img.Repository, img.Digest, img.Architecture)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("oci: remove image record: %w", err)
	}
	remaining, err := c.ListImages(img.Architecture)
	if err != nil {
		return err
	}
	if !slices.ContainsFunc(remaining, func(other Image) bool { return other.ID == img.ID }) {
		if img.Named() && !img.FromArchive() {
			if digestRef := img.Reference(img.Digest).Familiar(); !slices.Contains(report.Untagged, digestRef) {
				report.Untagged = append(report.Untagged, digestRef)
			}
		}
		report.Deleted = append(report.Deleted, img.ID)
	}
	return c.removeUnusedLayers(img.LayerDigests)
}

// usedLayers returns the cache keys of the layers that any image record uses.
func (c *LayerCache) usedLayers() (map[string]bool, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return nil, fmt.Errorf("oci: list cache directory: %w", err)
	}
	used := make(map[string]bool)
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, imagePrefix) || !strings.HasSuffix(name, cacheJSONSuffix) {
			continue
		}
		raw, err := readFileShared(filepath.Join(c.dir, name))
		if err != nil {
			continue
		}
		if _, dec, err := c.decodeRecord(raw, "", ""); err == nil {
			for _, hexStr := range dec.layerHex {
				used[hexStr] = true
			}
		}
	}
	return used, nil
}

// removeUnusedLayers deletes the layer images and the integrity records of the
// candidates that no image record uses.
func (c *LayerCache) removeUnusedLayers(candidates []string) error {
	used, err := c.usedLayers()
	if err != nil {
		return err
	}
	var errs []error
	for _, digest := range candidates {
		hexStr := normalizeDigestHex(digest)
		if hexStr == "" || used[hexStr] {
			continue
		}
		c.mu.Lock()
		delete(c.verified, hexStr)
		c.mu.Unlock()
		for _, p := range []string{filepath.Join(c.dir, hexStr+c.layerSuffix()), c.sumPath(hexStr)} {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("oci: remove unused layer file: %w", err))
			}
		}
	}
	return errors.Join(errs...)
}

// CachedDigest returns the manifest digest that the cache holds for a tag or a
// digest of a repository, and whether the image record verifies. It reads
// two small files and needs no network and no layer hashing.
func (c *LayerCache) CachedDigest(baseURL, repository, reference, arch string) (string, bool) {
	baseURL, repository, reference, arch = normalizePullArgs(baseURL, repository, reference, arch)
	digest := reference
	if !isDigestRef(reference) {
		raw, err := readFileShared(c.tagRecordPath(baseURL, repository, reference, arch))
		if err != nil {
			return "", false
		}
		var tr tagRecord
		if err := json.Unmarshal(raw, &tr); err != nil || !isDigestRef(tr.Digest) {
			return "", false
		}
		digest = tr.Digest
	}
	raw, err := readFileShared(c.imageRecordPath(baseURL, repository, digest, arch))
	if err != nil {
		return "", false
	}
	if _, _, err := c.decodeRecord(raw, digest, arch); err != nil {
		return "", false
	}
	return digest, true
}
