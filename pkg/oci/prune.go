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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// PruneOptions configures LayerCache.PruneImages.
type PruneOptions struct {
	// Arch selects the target Linux architecture (defaults to runtime.GOARCH).
	Arch string
	// All removes referenced images in addition to dangling images.
	All bool
}

// PruneReport summarizes records and disk space reclaimed by PruneImages.
type PruneReport struct {
	Untagged       []string
	Deleted        []string
	SpaceReclaimed int64
}

// CacheDiskUsage summarizes cached OCI images and EROFS layer storage.
type CacheDiskUsage struct {
	TotalImages      int
	ActiveImages     int
	TotalBytes       int64
	ReclaimableBytes int64
}

// PruneImages deletes dangling images (or all images when opts.All is true)
// for opts.Arch, sweeps orphaned tag, layer, sum, and temporary files, and
// reports the bytes reclaimed on disk.
func (c *LayerCache) PruneImages(opts PruneOptions) (PruneReport, error) {
	beforeBytes, err := c.cacheFileBytes()
	if err != nil {
		return PruneReport{}, err
	}
	images, err := c.ListImages(opts.Arch)
	if err != nil {
		return PruneReport{}, err
	}

	var report PruneReport
	var errs []error
	for _, img := range images {
		if !opts.All && img.Referenced() {
			continue
		}
		rep, err := c.Remove(img)
		for _, u := range rep.Untagged {
			if !slices.Contains(report.Untagged, u) {
				report.Untagged = append(report.Untagged, u)
			}
		}
		for _, d := range rep.Deleted {
			if !slices.Contains(report.Deleted, d) {
				report.Deleted = append(report.Deleted, d)
			}
		}
		if err != nil && !errors.Is(err, ErrNotCached) {
			errs = append(errs, err)
		}
	}

	if err := c.sweepOrphanedCacheFiles(); err != nil {
		errs = append(errs, err)
	}
	afterBytes, statErr := c.cacheFileBytes()
	if statErr == nil && beforeBytes > afterBytes {
		report.SpaceReclaimed = beforeBytes - afterBytes
	}
	return report, errors.Join(errs...)
}

func (c *LayerCache) sweepOrphanedCacheFiles() error {
	tags, err := c.readTagRecords()
	if err != nil {
		return err
	}
	var errs []error
	for _, t := range tags {
		if !t.rec.named() {
			continue
		}
		imgRec := c.imageRecordPath(t.rec.BaseURL, t.rec.Repository, t.rec.Digest, t.rec.Architecture)
		if _, statErr := os.Stat(imgRec); errors.Is(statErr, os.ErrNotExist) {
			if rmErr := os.Remove(t.path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("oci: remove orphaned tag record: %w", rmErr))
			}
		}
	}

	used, err := c.usedLayers()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("oci: list cache directory: %w", err))...)
	}
	layerSuffix := c.layerSuffix()
	sumSuffix := c.sumSuffix()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		switch {
		case strings.HasSuffix(name, sumSuffix):
			hexStr := strings.TrimSuffix(name, sumSuffix)
			if !used[hexStr] {
				if rmErr := os.Remove(filepath.Join(c.dir, name)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("oci: remove orphaned layer sum: %w", rmErr))
				}
			}
		case strings.HasSuffix(name, layerSuffix):
			hexStr := strings.TrimSuffix(name, layerSuffix)
			if !used[hexStr] {
				c.mu.Lock()
				delete(c.verified, hexStr)
				c.mu.Unlock()
				if rmErr := os.Remove(filepath.Join(c.dir, name)); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("oci: remove orphaned layer image: %w", rmErr))
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (c *LayerCache) isOwnedCacheFile(name string) bool {
	if strings.HasPrefix(name, imagePrefix) && strings.HasSuffix(name, cacheJSONSuffix) {
		return true
	}
	if strings.HasPrefix(name, tagPrefix) && strings.HasSuffix(name, cacheJSONSuffix) {
		return true
	}
	return strings.HasSuffix(name, c.layerSuffix()) || strings.HasSuffix(name, c.sumSuffix())
}

func (c *LayerCache) cacheFileBytes() (int64, error) {
	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("oci: list cache directory: %w", err)
	}
	var total int64
	for _, e := range entries {
		if e.IsDir() || !c.isOwnedCacheFile(e.Name()) {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
	}
	return total, nil
}

// DiskUsage computes total and reclaimable image and layer usage across
// cached amd64 and arm64 records.
func (c *LayerCache) DiskUsage() (CacheDiskUsage, error) {
	seenIDs := make(map[string]bool)
	activeIDs := make(map[string]bool)
	activeLayers := make(map[string]bool)
	activeRecordFiles := make(map[string]bool)

	for _, arch := range []string{"amd64", "arm64"} {
		imgs, err := c.ListImages(arch)
		if err != nil {
			return CacheDiskUsage{}, err
		}
		for _, img := range imgs {
			seenIDs[img.ID] = true
			if !img.Referenced() {
				continue
			}
			activeIDs[img.ID] = true
			activeRecordFiles[filepath.Base(c.imageRecordPath(img.BaseURL, img.Repository, img.Digest, img.Architecture))] = true
			for _, d := range img.LayerDigests {
				if hexStr := normalizeDigestHex(d); hexStr != "" {
					activeLayers[hexStr] = true
				}
			}
		}
	}

	tags, err := c.readTagRecords()
	if err != nil {
		return CacheDiskUsage{}, err
	}
	for _, t := range tags {
		if !t.rec.named() {
			activeRecordFiles[filepath.Base(t.path)] = true
			continue
		}
		imgRec := c.imageRecordPath(t.rec.BaseURL, t.rec.Repository, t.rec.Digest, t.rec.Architecture)
		if _, statErr := os.Stat(imgRec); statErr == nil {
			activeRecordFiles[filepath.Base(t.path)] = true
		}
	}

	entries, err := os.ReadDir(c.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return CacheDiskUsage{}, nil
		}
		return CacheDiskUsage{}, fmt.Errorf("oci: list cache directory: %w", err)
	}
	layerSuffix := c.layerSuffix()
	sumSuffix := c.sumSuffix()
	var totalBytes, reclaimableBytes int64
	for _, e := range entries {
		if e.IsDir() || !c.isOwnedCacheFile(e.Name()) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		sz := info.Size()
		totalBytes += sz
		name := e.Name()
		switch {
		case strings.HasSuffix(name, sumSuffix):
			if !activeLayers[strings.TrimSuffix(name, sumSuffix)] {
				reclaimableBytes += sz
			}
		case strings.HasSuffix(name, layerSuffix):
			if !activeLayers[strings.TrimSuffix(name, layerSuffix)] {
				reclaimableBytes += sz
			}
		default:
			if !activeRecordFiles[name] {
				reclaimableBytes += sz
			}
		}
	}

	return CacheDiskUsage{
		TotalImages:      len(seenIDs),
		ActiveImages:     len(activeIDs),
		TotalBytes:       totalBytes,
		ReclaimableBytes: reclaimableBytes,
	}, nil
}
