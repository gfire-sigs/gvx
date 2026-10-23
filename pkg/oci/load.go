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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// annotationRefName is the OCI annotation that names an image in index.json.
	annotationRefName = "org.opencontainers.image.ref.name"
	// annotationImageName is the containerd annotation with the full image name.
	annotationImageName = "io.containerd.image.name"
	// mediaTypeOCILayerTar is the media type of an uncompressed layer.
	mediaTypeOCILayerTar = "application/vnd.oci.image.layer.v1.tar"
)

// LoadedImage is one image that LoadArchive registered in the cache.
type LoadedImage struct {
	// ID is the digest of the image config.
	ID string
	// Digest is the manifest digest. The loader writes the manifest of an image
	// from a "docker save" archive, so that digest names no registry content.
	Digest string
	// Names lists the tags that the archive gave the image. It is empty for an
	// image without a name.
	Names []Reference
}

func blobDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LoadArchive compiles every image of an image archive for targetArch into the
// cache and registers the image records and the tags of the archive. The
// archive is an OCI image layout or a `docker save` archive, optionally gzip or
// zstd compressed. Tags come from the `RepoTags` of manifest.json and from the
// "io.containerd.image.name" and "org.opencontainers.image.ref.name"
// annotations of index.json. An annotation without ":", "/", or "@" is a bare
// tag without a name and gives no tag. An image from another architecture is
// skipped. LoadArchive verifies digests as LoadArchiveTar does. The loaded
// images have no registry source for their original layers.
func LoadArchive(r io.Reader, cache *LayerCache, targetArch string) ([]LoadedImage, error) {
	if cache == nil {
		var err error
		cache, err = NewLayerCache("")
		if err != nil {
			return nil, err
		}
	}
	_, _, _, targetArch = normalizePullArgs("", "", "", targetArch)

	a, cleanup, err := cache.openArchive(r)
	if err != nil {
		return nil, err
	}
	images, loadErr := a.register(targetArch)
	if cleanupErr := cleanup(); cleanupErr != nil {
		loadErr = errors.Join(loadErr, cleanupErr)
	}
	if loadErr != nil {
		return nil, loadErr
	}
	return images, nil
}

func (a *archive) register(arch string) ([]LoadedImage, error) {
	if err := a.index(); err != nil {
		return nil, err
	}
	if _, ok := a.members["index.json"]; ok {
		raw, err := a.readJSON("index.json")
		if err != nil {
			return nil, err
		}
		var idx ImageIndex
		if err := json.Unmarshal(raw, &idx); err == nil && len(idx.Manifests) > 0 {
			return a.registerOCILayout(idx, arch)
		}
		if _, ok := a.members["oci-layout"]; ok {
			return nil, errors.New("oci: archive has an oci-layout marker but index.json lists no manifests")
		}
	}
	if _, ok := a.members["manifest.json"]; ok {
		return a.registerDockerSave(arch)
	}
	return nil, errors.New("oci: the archive is neither an OCI image layout nor a docker save archive")
}

func (a *archive) registerOCILayout(idx ImageIndex, arch string) ([]LoadedImage, error) {
	configNames := a.dockerSaveNames()
	var out []LoadedImage
	byDigest := make(map[string]int)
	var firstErr error
	for _, desc := range idx.Manifests {
		if !isManifestMediaType(desc.MediaType) {
			continue
		}
		member, err := blobMemberName(desc.Digest)
		if err != nil {
			return nil, err
		}
		body, err := a.readJSON(member)
		if err != nil {
			return nil, err
		}
		if err := verifyBody(desc, body); err != nil {
			return nil, fmt.Errorf("oci: manifest %s: %w", desc.Digest, err)
		}
		res, err := resolveManifestChain(body, arch, func(d Descriptor) ([]byte, error) {
			name, err := blobMemberName(d.Digest)
			if err != nil {
				return nil, err
			}
			return a.readJSON(name)
		})
		if err != nil {
			// A multi-architecture archive can hold other platforms.
			firstErr = cmpFirst(firstErr, err)
			continue
		}
		cfgMember, err := blobMemberName(res.Manifest.Config.Digest)
		if err != nil {
			return nil, err
		}
		cfgBytes, err := a.readJSON(cfgMember)
		if err != nil {
			return nil, err
		}
		if err := verifyBody(res.Manifest.Config, cfgBytes); err != nil {
			return nil, fmt.Errorf("oci: config %s: %w", res.Manifest.Config.Digest, err)
		}
		if _, err := parseImageConfig(cfgBytes, arch, len(res.Manifest.Layers)); err != nil {
			firstErr = cmpFirst(firstErr, err)
			continue
		}
		if _, err := a.compileOCILayers(res.Manifest.Layers); err != nil {
			return nil, err
		}

		raw := archiveNames(desc.Annotations)
		raw = append(raw, configNames[res.Manifest.Config.Digest]...)
		names := parseArchiveNames(raw)
		if err := a.cache.registerLoaded(imageRecord{
			Digest: desc.Digest, Architecture: arch, Manifests: res.Chain, Config: cfgBytes,
		}, names); err != nil {
			return nil, err
		}
		if i, ok := byDigest[desc.Digest]; ok {
			out[i].Names = mergeNames(out[i].Names, names)
			continue
		}
		byDigest[desc.Digest] = len(out)
		out = append(out, LoadedImage{ID: res.Manifest.Config.Digest, Digest: desc.Digest, Names: names})
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("oci: index.json lists no image manifest")
	}
	return out, nil
}

func (a *archive) registerDockerSave(arch string) ([]LoadedImage, error) {
	entries, err := a.dockerSaveEntries()
	if err != nil {
		return nil, err
	}
	var out []LoadedImage
	var firstErr error
	for _, e := range entries {
		names, err := parseRepoTags(e.RepoTags)
		if err != nil {
			return nil, err
		}
		img, skip, err := a.compileDockerSaveEntry(e, arch)
		if skip {
			firstErr = cmpFirst(firstErr, err)
			continue
		}
		if err != nil {
			return nil, err
		}

		// The format has no manifest. The record holds a manifest that points at
		// the layers by their diff IDs, which are the cache keys.
		manifest := ImageManifest{
			SchemaVersion: 2,
			MediaType:     mediaTypeOCIManifest,
			Config:        Descriptor{MediaType: mediaTypeOCIConfig, Digest: blobDigest(img.cfgBytes), Size: int64(len(img.cfgBytes))},
		}
		for i, diffID := range img.diffIDs {
			manifest.Layers = append(manifest.Layers, Descriptor{MediaType: mediaTypeOCILayerTar, Digest: diffID, Size: img.layerSizes[i]})
		}
		body, err := json.Marshal(manifest)
		if err != nil {
			return nil, fmt.Errorf("oci: encode manifest of a docker save image: %w", err)
		}
		digest := blobDigest(body)
		if err := a.cache.registerLoaded(imageRecord{
			Digest: digest, Architecture: arch, Manifests: [][]byte{body}, Config: img.cfgBytes,
		}, names); err != nil {
			return nil, err
		}
		out = append(out, LoadedImage{ID: manifest.Config.Digest, Digest: digest, Names: names})
	}
	if len(out) == 0 {
		if firstErr != nil {
			return nil, firstErr
		}
		return nil, errors.New("oci: manifest.json lists no images")
	}
	return out, nil
}

func cmpFirst(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

func isManifestMediaType(mt string) bool {
	switch mt {
	case "", mediaTypeOCIManifest, mediaTypeDockerManifest, mediaTypeOCIIndex, mediaTypeDockerList:
		return true
	}
	return false
}

// archiveNames returns the names that the annotations of an index.json entry give.
func archiveNames(annotations map[string]string) []string {
	var names []string
	if n := annotations[annotationImageName]; n != "" {
		names = append(names, n)
	}
	if n := annotations[annotationRefName]; strings.ContainsAny(n, ":/@") {
		names = append(names, n)
	}
	return names
}

// parseArchiveNames parses names and keeps those with a tag. A name that does
// not parse, or has only a digest, is left out.
func parseArchiveNames(raw []string) []Reference {
	var refs []Reference
	for _, s := range raw {
		ref, err := ParseReference(s)
		if err != nil || ref.Tag == "" {
			continue
		}
		ref.Digest = ""
		refs = mergeNames(refs, []Reference{ref})
	}
	return refs
}

// parseRepoTags parses the RepoTags of a manifest.json entry. A tag that does
// not parse is an error.
func parseRepoTags(tags []string) ([]Reference, error) {
	var refs []Reference
	for _, s := range tags {
		ref, err := ParseReference(s)
		if err != nil {
			return nil, fmt.Errorf("oci: invalid RepoTags entry in manifest.json: %w", err)
		}
		if ref.Tag == "" {
			continue
		}
		ref.Digest = ""
		refs = mergeNames(refs, []Reference{ref})
	}
	return refs, nil
}

func mergeNames(have, more []Reference) []Reference {
	for _, m := range more {
		dup := false
		for _, h := range have {
			if h == m {
				dup = true
				break
			}
		}
		if !dup {
			have = append(have, m)
		}
	}
	return have
}

// dockerSaveNames maps the config digest of every manifest.json entry to its
// RepoTags. An archive without a usable manifest.json has no names this way.
func (a *archive) dockerSaveNames() map[string][]string {
	names := make(map[string][]string)
	if _, ok := a.members["manifest.json"]; !ok {
		return names
	}
	entries, err := a.dockerSaveEntries()
	if err != nil {
		return names
	}
	for _, e := range entries {
		cfgName, err := cleanTarPath(e.Config)
		if err != nil {
			continue
		}
		cfgBytes, err := a.readJSON(cfgName)
		if err != nil {
			continue
		}
		id := blobDigest(cfgBytes)
		names[id] = append(names[id], e.RepoTags...)
	}
	return names
}

// registerLoaded records an image from an archive under every repository of
// names, and records each tag. An image without a name gets a record without a
// repository, which lists as an untagged image. An existing record stays, so
// that a registry-sourced record keeps its source.
func (c *LayerCache) registerLoaded(rec imageRecord, names []Reference) error {
	rec.Source = sourceArchive
	type repoKey struct{ baseURL, repository string }
	var order []repoKey
	tags := make(map[repoKey][]string)
	for _, n := range names {
		k := repoKey{n.BaseURL(), n.Repository}
		if _, ok := tags[k]; !ok {
			order = append(order, k)
		}
		tags[k] = append(tags[k], n.Tag)
	}
	if len(order) == 0 {
		order = append(order, repoKey{})
	}
	for _, k := range order {
		rec.BaseURL, rec.Repository = k.baseURL, k.repository
		if err := c.storeImageIfAbsent(rec); err != nil {
			return err
		}
		for _, tag := range tags[k] {
			if err := c.storeTag(k.baseURL, k.repository, tag, rec.Architecture, rec.Digest); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *LayerCache) storeImageIfAbsent(rec imageRecord) error {
	p := c.imageRecordPath(rec.BaseURL, rec.Repository, rec.Digest, rec.Architecture)
	if raw, err := readFileShared(p); err == nil {
		if _, _, err := c.decodeRecord(raw, rec.Digest, rec.Architecture); err == nil {
			return nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("oci: read image record %s: %w", filepath.Base(p), err)
	}
	return c.storeImage(rec)
}
