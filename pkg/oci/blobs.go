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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

const (
	blobsSubdir  = "blobs"
	sha256Subdir = "sha256"
)

func (c *LayerCache) blobsDir() string {
	return filepath.Join(c.dir, blobsSubdir, sha256Subdir)
}

// BlobPath returns the host path for a kept original blob under
// <cacheDir>/blobs/sha256/<hex>.
func (c *LayerCache) BlobPath(dgst string) (string, error) {
	hexStr := normalizeDigestHex(dgst)
	if hexStr == "" {
		return "", fmt.Errorf("oci: invalid blob digest %q", dgst)
	}
	return filepath.Join(c.blobsDir(), hexStr), nil
}

// HasBlob reports whether the kept original blob for dgst exists in the cache
// and matches its SHA-256 digest.
func (c *LayerCache) HasBlob(dgst string) (string, bool) {
	hexStr := normalizeDigestHex(dgst)
	if hexStr == "" {
		return "", false
	}
	f, _, err := c.openVerifiedBlob(digest.NewDigestFromEncoded(digest.SHA256, hexStr), -1)
	if err != nil {
		return "", false
	}
	if err := f.Close(); err != nil {
		return "", false
	}
	return filepath.Join(c.blobsDir(), hexStr), true
}

// hasBlobWithSize reports whether the kept blob for d exists on disk with the
// expected byte length and passes digest verification.
func (c *LayerCache) hasBlobWithSize(d digest.Digest, wantSize int64) bool {
	f, _, err := c.openVerifiedBlob(d, wantSize)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// openVerifiedBlob opens a kept blob read-only and verifies its size and
// SHA-256 digest, caching successful verification per process by (size, modTime).
// If the blob does not exist, the returned error wraps os.ErrNotExist.
func (c *LayerCache) openVerifiedBlob(d digest.Digest, wantSize int64) (*os.File, int64, error) {
	if err := validateSHA256(d); err != nil {
		return nil, 0, err
	}
	hexStr := d.Encoded()
	p := filepath.Join(c.blobsDir(), hexStr)
	f, err := openShared(p)
	if err != nil {
		return nil, 0, fmt.Errorf("oci: open cached blob %s: %w", d, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("oci: stat cached blob %s: %w", d, err)
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%w: cached blob %q is not a regular file", ErrDigestMismatch, p)
	}
	if wantSize >= 0 && info.Size() != wantSize {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%w: cached blob %s has %d bytes, want %d", ErrDigestMismatch, d, info.Size(), wantSize)
	}

	c.mu.Lock()
	v, ok := c.verifiedBlobs[hexStr]
	c.mu.Unlock()
	if ok && v.size == info.Size() && v.modTime.Equal(info.ModTime()) {
		return f, info.Size(), nil
	}

	digester := digest.SHA256.Digester()
	if _, err := io.Copy(digester.Hash(), io.NewSectionReader(f, 0, info.Size())); err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("oci: hash cached blob %s: %w", d, err)
	}
	if got := digester.Digest().Encoded(); got != hexStr {
		_ = f.Close()
		return nil, 0, fmt.Errorf("%w: cached blob %s has sha256 %s", ErrDigestMismatch, d, got)
	}
	c.recordVerifiedBlob(hexStr, info)
	return f, info.Size(), nil
}

func (c *LayerCache) recordVerifiedBlob(hexStr string, info os.FileInfo) {
	c.mu.Lock()
	c.verifiedBlobs[hexStr] = verifiedLayer{size: info.Size(), modTime: info.ModTime()}
	c.mu.Unlock()
}

// storeBlobFromReader streams src to a temporary file under blobs/sha256/,
// verifies size (when wantSize >= 0) and SHA-256 digest d, and publishes it
// atomically without replacing an already-valid blob.
func (c *LayerCache) storeBlobFromReader(d digest.Digest, wantSize int64, src io.Reader) (string, int64, error) {
	if err := validateSHA256(d); err != nil {
		return "", 0, err
	}
	hexStr := d.Encoded()
	if c.hasBlobWithSize(d, wantSize) {
		info, err := os.Stat(filepath.Join(c.blobsDir(), hexStr))
		if err == nil {
			return filepath.Join(c.blobsDir(), hexStr), info.Size(), nil
		}
	}
	blobDir := c.blobsDir()
	if err := os.MkdirAll(blobDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("oci: create blob cache dir %q: %w", blobDir, err)
	}
	tmp, err := os.CreateTemp(blobDir, tempPattern)
	if err != nil {
		return "", 0, fmt.Errorf("oci: create temp blob file for %s: %w", d, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	digester := digest.SHA256.Digester()
	bounded := newBoundedReader(src, fmt.Sprintf("blob %s size", d), c.limits.MaxBlobBytes, nil)
	n, err := io.Copy(io.MultiWriter(tmp, digester.Hash()), bounded)
	if err != nil {
		return "", 0, fmt.Errorf("oci: store blob %s: %w", d, err)
	}
	if wantSize >= 0 && n != wantSize {
		return "", 0, fmt.Errorf("%w: blob %s has %d bytes, descriptor says %d", ErrDigestMismatch, d, n, wantSize)
	}
	if got := digester.Digest().Encoded(); got != hexStr {
		return "", 0, fmt.Errorf("%w: blob sha256 is %s, want %s", ErrDigestMismatch, got, hexStr)
	}
	if err := tmp.Sync(); err != nil {
		return "", 0, fmt.Errorf("oci: sync blob %s: %w", d, err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("oci: stat blob %s: %w", d, err)
	}
	if err := tmp.Close(); err != nil {
		return "", 0, fmt.Errorf("oci: close blob %s: %w", d, err)
	}
	target, err := c.publishBlobFile(tmpPath, hexStr, info, &committed)
	if err != nil {
		return "", 0, err
	}
	return target, n, nil
}

func (c *LayerCache) publishBlobFile(tmpPath, hexKey string, tmpInfo os.FileInfo, committed *bool) (string, error) {
	target := filepath.Join(c.blobsDir(), hexKey)
	wantDigest := digest.NewDigestFromEncoded(digest.SHA256, hexKey)
	if c.hasBlobWithSize(wantDigest, tmpInfo.Size()) {
		return target, nil
	}
	if err := os.Link(tmpPath, target); err == nil {
		c.recordVerifiedBlob(hexKey, tmpInfo)
		return target, nil
	}
	if c.hasBlobWithSize(wantDigest, tmpInfo.Size()) {
		return target, nil
	}
	if err := replaceFile(tmpPath, target); err != nil {
		return "", fmt.Errorf("oci: publish cached blob %q: %w", target, err)
	}
	*committed = true
	c.recordVerifiedBlob(hexKey, tmpInfo)
	return target, nil
}

func (c *LayerCache) hasAllManifestBlobs(layers []ocispec.Descriptor) bool {
	for _, l := range layers {
		if !c.hasBlobWithSize(l.Digest, l.Size) {
			return false
		}
	}
	return true
}

func (c *LayerCache) hasAllLayerBlobsForRecord(baseURL, repository, dgst, arch string) bool {
	raw, err := readFileShared(c.imageRecordPath(baseURL, repository, dgst, arch))
	if err != nil {
		return false
	}
	_, dec, err := c.decodeRecord(raw, dgst, arch)
	if err != nil {
		return false
	}
	return c.hasAllManifestBlobs(dec.manifest.Layers)
}

// checkLocalBlobs verifies every kept layer blob that exists on disk and
// reports whether all manifest layers are available locally. A missing blob
// returns (false, nil). A corrupted blob on disk returns an error wrapping
// ErrDigestMismatch.
func (c *LayerCache) checkLocalBlobs(layers []ocispec.Descriptor) (bool, error) {
	allLocal := true
	for _, l := range layers {
		f, _, err := c.openVerifiedBlob(l.Digest, l.Size)
		if err == nil {
			_ = f.Close()
			continue
		}
		if errors.Is(err, os.ErrNotExist) {
			allLocal = false
			continue
		}
		return false, err
	}
	return allLocal, nil
}

// copyLocalBlob streams the kept blob for l into tw while verifying exact size
// and SHA-256 digest. It returns (false, nil) when the blob is not cached.
func (c *LayerCache) copyLocalBlob(tw *tar.Writer, l ocispec.Descriptor) (bool, error) {
	f, size, err := c.openVerifiedBlob(l.Digest, l.Size)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	defer f.Close()

	hdr := &tar.Header{
		Name:     saveBlobPath(l.Digest),
		Mode:     0o644,
		Size:     size,
		Typeflag: tar.TypeReg,
		ModTime:  archiveEpoch,
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return false, fmt.Errorf("oci: write archive member %s: %w", hdr.Name, err)
	}
	digester := digest.SHA256.Digester()
	if _, err := io.CopyN(io.MultiWriter(tw, digester.Hash()), io.NewSectionReader(f, 0, size), size); err != nil {
		return false, fmt.Errorf("oci: copy cached blob %s: %w", l.Digest, err)
	}
	if got := digester.Digest(); got != l.Digest {
		return false, fmt.Errorf("%w: cached blob %s has sha256 %s", ErrDigestMismatch, l.Digest, got.Encoded())
	}
	return true, nil
}

// usedBlobs returns the hex digests of all layer blobs referenced by any valid
// image record in the cache directory across all EROFS formats and architectures.
func (c *LayerCache) usedBlobs() (map[string]bool, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]bool{}, nil
		}
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
		var rec imageRecord
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Version != imageRecordVersion || len(rec.Manifests) == 0 {
			continue
		}
		dec, err := c.verifyRecord(rec)
		if err != nil {
			continue
		}
		for _, hexStr := range dec.layerHex {
			used[hexStr] = true
		}
	}
	return used, nil
}

// removeUnusedBlobs deletes kept blobs for candidates that no image record
// across any format or architecture references.
func (c *LayerCache) removeUnusedBlobs(candidates []string) error {
	if len(candidates) == 0 {
		return nil
	}
	blobDir := c.blobsDir()
	if _, err := os.Stat(blobDir); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	used, err := c.usedBlobs()
	if err != nil {
		return err
	}
	var errs []error
	for _, dgst := range candidates {
		hexStr := normalizeDigestHex(dgst)
		if hexStr == "" || used[hexStr] {
			continue
		}
		c.mu.Lock()
		delete(c.verifiedBlobs, hexStr)
		c.mu.Unlock()
		p := filepath.Join(blobDir, hexStr)
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Errorf("oci: remove unused blob %s: %w", hexStr, err))
		}
	}
	return errors.Join(errs...)
}

func (c *LayerCache) sweepOrphanedBlobs() error {
	blobDir := c.blobsDir()
	entries, err := os.ReadDir(blobDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("oci: list blob cache directory: %w", err)
	}
	used, err := c.usedBlobs()
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if digest.SHA256.Validate(name) != nil {
			continue
		}
		if !used[name] {
			c.mu.Lock()
			delete(c.verifiedBlobs, name)
			c.mu.Unlock()
			if rmErr := os.Remove(filepath.Join(blobDir, name)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("oci: remove orphaned blob %s: %w", name, rmErr))
			}
		}
	}
	return errors.Join(errs...)
}

func (c *LayerCache) blobCacheBytes() (int64, error) {
	entries, err := os.ReadDir(c.blobsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("oci: list blob cache directory: %w", err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || digest.SHA256.Validate(e.Name()) != nil {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total, nil
}

// activeBlobDigests returns the hex digests of blobs that cannot be reclaimed
// by PruneImages for the current format: every blob in activeCurrent plus every
// blob referenced by an image record belonging to another EROFS format.
func (c *LayerCache) activeBlobDigests(activeCurrent map[string]bool) (map[string]bool, error) {
	active := make(map[string]bool, len(activeCurrent))
	for k, v := range activeCurrent {
		if v {
			active[k] = true
		}
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return active, nil
		}
		return nil, fmt.Errorf("oci: list cache directory: %w", err)
	}
	curFmt := c.format()
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, imagePrefix) || !strings.HasSuffix(name, cacheJSONSuffix) {
			continue
		}
		raw, err := readFileShared(filepath.Join(c.dir, name))
		if err != nil {
			continue
		}
		var rec imageRecord
		if err := json.Unmarshal(raw, &rec); err != nil || rec.Version != imageRecordVersion || len(rec.Manifests) == 0 {
			continue
		}
		if rec.Format == curFmt {
			continue
		}
		dec, err := c.verifyRecord(rec)
		if err != nil {
			continue
		}
		for _, hexStr := range dec.layerHex {
			active[hexStr] = true
		}
	}
	return active, nil
}

func (c *LayerCache) blobDiskUsage(activeBlobs map[string]bool) (totalBytes, reclaimableBytes int64, err error) {
	entries, err := os.ReadDir(c.blobsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, 0, nil
		}
		return 0, 0, fmt.Errorf("oci: list blob cache directory: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || digest.SHA256.Validate(e.Name()) != nil {
			continue
		}
		info, statErr := e.Info()
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		sz := info.Size()
		totalBytes += sz
		if !activeBlobs[e.Name()] {
			reclaimableBytes += sz
		}
	}
	return totalBytes, reclaimableBytes, nil
}
