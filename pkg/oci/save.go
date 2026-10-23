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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"time"
)

// SaveTarget selects one image for SaveImages and gives it names.
type SaveTarget struct {
	Image Image
	// Names are the tags that the archive records for the image, in the
	// "RepoTags" of manifest.json and in the annotations of index.json. An
	// empty list saves an image without a name.
	Names []Reference
}

// preparedSave is a target with its verified record and blob source.
type preparedSave struct {
	img     Image
	dec     *decodedRecord
	names   []Reference
	baseURL string
	repo    string
}

// saveBlobPath returns the archive member of a blob.
func saveBlobPath(digest string) string {
	return "blobs/sha256/" + normalizeDigestHex(digest)
}

// SaveImages writes one tar archive of the images to w. The archive is an OCI
// image layout and also holds a Docker manifest.json with RepoTags, so
// `docker load` and LoadArchive read it. Blobs that images share appear once.
//
// The cache holds compiled EROFS layers, not the original blobs. SaveImages
// therefore fetches each original layer blob from the registry that the image
// came from. It verifies size and digest while it copies the blob into the
// archive. An image without a registry source, such as an image that
// LoadArchive loaded, makes SaveImages fail with ErrNoRegistrySource before it
// writes anything. A failure after the first byte leaves a partial stream in
// w, so the caller must discard its output on error. A nil client selects a
// default HTTP client. An image that is a manifest list saves its manifest for
// the architecture of the image, not the whole list.
func (c *LayerCache) SaveImages(ctx context.Context, w io.Writer, client *http.Client, targets []SaveTarget) error {
	prepared, err := c.prepareSave(targets)
	if err != nil {
		return err
	}

	clients := make(map[string]*registryClient)
	defer func() {
		for _, rc := range clients {
			rc.close()
		}
	}()
	clientFor := func(p preparedSave) (*registryClient, error) {
		key := p.baseURL + "\x00" + p.repo
		if rc, ok := clients[key]; ok {
			return rc, nil
		}
		rc, err := newRegistryClient(client, p.baseURL, p.repo, c.limits)
		if err != nil {
			return nil, err
		}
		clients[key] = rc
		return rc, nil
	}

	tw := tar.NewWriter(w)
	written := make(map[string]bool)
	writeBlob := func(digest string, data []byte) error {
		if written[digest] {
			return nil
		}
		written[digest] = true
		return writeTarFile(tw, saveBlobPath(digest), data)
	}
	if err := writeTarFile(tw, "oci-layout", []byte(`{"imageLayoutVersion":"1.0.0"}`)); err != nil {
		return err
	}

	index := ImageIndex{SchemaVersion: 2, MediaType: mediaTypeOCIIndex}
	var manifestJSON []dockerSaveEntry
	for _, p := range prepared {
		manifestDigest := blobDigest(p.dec.manifestBody)
		if err := writeBlob(manifestDigest, p.dec.manifestBody); err != nil {
			return err
		}
		if err := writeBlob(p.dec.manifest.Config.Digest, p.dec.config); err != nil {
			return err
		}
		entry := dockerSaveEntry{Config: saveBlobPath(p.dec.manifest.Config.Digest)}
		for _, l := range p.dec.manifest.Layers {
			if !written[l.Digest] {
				rc, err := clientFor(p)
				if err != nil {
					return err
				}
				written[l.Digest] = true
				if err := copyRegistryBlob(ctx, tw, rc, l); err != nil {
					return err
				}
			}
			entry.Layers = append(entry.Layers, saveBlobPath(l.Digest))
		}

		mediaType := p.dec.manifest.MediaType
		if mediaType == "" {
			mediaType = mediaTypeOCIManifest
		}
		desc := Descriptor{
			MediaType: mediaType, Digest: manifestDigest, Size: int64(len(p.dec.manifestBody)),
			Platform: &PlatformSpec{OS: "linux", Architecture: p.img.Architecture},
		}
		if len(p.names) == 0 {
			index.Manifests = append(index.Manifests, desc)
		}
		for _, n := range p.names {
			named := desc
			named.Annotations = map[string]string{annotationRefName: n.Familiar(), annotationImageName: n.String()}
			index.Manifests = append(index.Manifests, named)
			entry.RepoTags = append(entry.RepoTags, n.Familiar())
		}
		manifestJSON = append(manifestJSON, entry)
	}

	indexRaw, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("oci: encode index.json: %w", err)
	}
	manifestRaw, err := json.Marshal(manifestJSON)
	if err != nil {
		return fmt.Errorf("oci: encode manifest.json: %w", err)
	}
	if err := writeTarFile(tw, "index.json", indexRaw); err != nil {
		return err
	}
	if err := writeTarFile(tw, "manifest.json", manifestRaw); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("oci: finish archive: %w", err)
	}
	return nil
}

// prepareSave verifies the records and finds the blob source of every image.
// Targets with the same image record merge their names.
func (c *LayerCache) prepareSave(targets []SaveTarget) ([]preparedSave, error) {
	if len(targets) == 0 {
		return nil, errors.New("oci: no image to save")
	}
	var out []preparedSave
	for _, t := range targets {
		if i := slices.IndexFunc(out, func(p preparedSave) bool {
			return p.img.key() == t.Image.key() && p.img.Architecture == t.Image.Architecture
		}); i >= 0 {
			out[i].names = mergeNames(out[i].names, t.Names)
			continue
		}
		label := t.Image.ID
		if t.Image.Named() {
			label = t.Image.Name()
		}
		baseURL, repo, err := t.Image.blobSource()
		if err != nil {
			return nil, fmt.Errorf("oci: cannot save %s: %w", label, err)
		}
		dec, err := c.verifyRecord(t.Image.record)
		if err != nil {
			return nil, fmt.Errorf("oci: cannot save %s: %w", label, err)
		}
		for _, l := range dec.manifest.Layers {
			if err := checkLayerDescriptor(l, c.limits); err != nil {
				return nil, fmt.Errorf("oci: cannot save %s: %w", label, err)
			}
		}
		out = append(out, preparedSave{img: t.Image, dec: dec, names: slices.Clone(t.Names), baseURL: baseURL, repo: repo})
	}
	return out, nil
}

// archiveEpoch is the modification time of every archive member, so that the
// same images give the same archive.
var archiveEpoch = time.Unix(0, 0)

func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), Typeflag: tar.TypeReg, ModTime: archiveEpoch}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("oci: write archive member %s: %w", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		return fmt.Errorf("oci: write archive member %s: %w", name, err)
	}
	return nil
}

// copyRegistryBlob streams the layer blob l from the registry into the
// archive. The descriptor gives the size. The call verifies size and digest
// while it copies and returns ErrDigestMismatch on a difference.
func copyRegistryBlob(ctx context.Context, tw *tar.Writer, rc *registryClient, l Descriptor) error {
	body, err := rc.openBlob(ctx, l.Digest)
	if err != nil {
		return err
	}
	defer body.Close()

	hdr := &tar.Header{Name: saveBlobPath(l.Digest), Mode: 0o644, Size: l.Size, Typeflag: tar.TypeReg, ModTime: archiveEpoch}
	if err := tw.WriteHeader(hdr); err != nil {
		return fmt.Errorf("oci: write archive member %s: %w", hdr.Name, err)
	}
	h := sha256.New()
	if _, err := io.CopyN(io.MultiWriter(tw, h), body, l.Size); err != nil {
		if errors.Is(err, io.EOF) {
			return fmt.Errorf("%w: blob %s is shorter than the %d bytes of its descriptor", ErrDigestMismatch, l.Digest, l.Size)
		}
		return fmt.Errorf("oci: copy blob %s: %w", l.Digest, err)
	}
	var extra [1]byte
	if n, _ := body.Read(extra[:]); n > 0 {
		return fmt.Errorf("%w: blob %s is longer than the %d bytes of its descriptor", ErrDigestMismatch, l.Digest, l.Size)
	}
	want, err := parseDigest(l.Digest)
	if err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%w: blob sha256 is %s, want %s", ErrDigestMismatch, got, want)
	}
	return nil
}
