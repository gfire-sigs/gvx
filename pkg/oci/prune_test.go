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
	"os"
	"path/filepath"
	"testing"
)

func TestPruneImagesRemovesDanglingImagesAndPreservesSubdirectories(t *testing.T) {
	reg := newFakeRegistry(t)
	cache := newCache(t)

	shared := layerOf(t, "shared.txt", "shared")
	oldImg := newImageWithCreated(t, "V=1", "2025-01-01T00:00:00Z", shared, layerOf(t, "old.txt", "old-layer"))
	newImg := newImageWithCreated(t, "V=2", "2025-02-01T00:00:00Z", shared, layerOf(t, "new.txt", "new-layer"))

	pullTagged(t, reg, cache, oldImg, "latest")
	// Overwrite the "latest" tag so oldImg becomes dangling.
	pullTagged(t, reg, cache, newImg, "latest")

	// Place a sibling volumes directory inside cache.Dir() to ensure PruneImages
	// and DiskUsage ignore subdirectories.
	volSubdir := filepath.Join(cache.Dir(), "volumes")
	if err := os.MkdirAll(volSubdir, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinelFile := filepath.Join(volSubdir, "keep.ext4")
	if err := os.WriteFile(sentinelFile, []byte("volume-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}

	duBefore, err := cache.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage before prune: %v", err)
	}
	if duBefore.TotalImages != 2 || duBefore.ActiveImages != 1 {
		t.Fatalf("DiskUsage before = %+v, want TotalImages=2 ActiveImages=1", duBefore)
	}
	if duBefore.ReclaimableBytes <= 0 {
		t.Fatalf("DiskUsage ReclaimableBytes = %d, want > 0", duBefore.ReclaimableBytes)
	}

	report, err := cache.PruneImages(PruneOptions{Arch: storeArch, All: false})
	if err != nil {
		t.Fatalf("PruneImages(dangling): %v", err)
	}
	if len(report.Deleted) == 0 || report.SpaceReclaimed <= 0 {
		t.Fatalf("PruneImages(dangling) report = %+v, want deleted items and positive SpaceReclaimed", report)
	}

	remaining := listImages(t, cache)
	if len(remaining) != 1 || remaining[0].ID != sha256Digest(newImg.config) {
		t.Fatalf("remaining images = %+v, want only newImg", remaining)
	}
	if _, err := os.Stat(sentinelFile); err != nil {
		t.Fatalf("volumes subdirectory file removed by PruneImages: %v", err)
	}

	duAfter, err := cache.DiskUsage()
	if err != nil {
		t.Fatalf("DiskUsage after dangling prune: %v", err)
	}
	if duAfter.TotalImages != 1 || duAfter.ActiveImages != 1 || duAfter.ReclaimableBytes != 0 {
		t.Fatalf("DiskUsage after dangling prune = %+v, want Total=1 Active=1 Reclaimable=0", duAfter)
	}

	allReport, err := cache.PruneImages(PruneOptions{Arch: storeArch, All: true})
	if err != nil {
		t.Fatalf("PruneImages(all): %v", err)
	}
	if len(allReport.Untagged) == 0 || allReport.SpaceReclaimed <= 0 {
		t.Fatalf("PruneImages(all) report = %+v, want untagged items and positive SpaceReclaimed", allReport)
	}
	if got := listImages(t, cache); len(got) != 0 {
		t.Fatalf("listImages after PruneImages(all) = %+v, want empty", got)
	}
}
