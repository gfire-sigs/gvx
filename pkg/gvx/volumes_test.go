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

package gvx_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx"
	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
)

func TestVolumeLifecycleAndActiveLockProtection(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")

	if vols, err := gvx.ListVolumes(cacheDir); err != nil || len(vols) != 0 {
		t.Fatalf("ListVolumes on missing store = (%v, %v), want empty nil", vols, err)
	}

	extVol, err := gvx.CreateVolume(cacheDir, "app-data", gvx.DriverExt4lite)
	if err != nil {
		t.Fatalf("CreateVolume(ext4lite): %v", err)
	}
	if extVol.Name != "app-data" || extVol.Driver != gvx.DriverExt4lite || extVol.SizeBytes <= 0 || extVol.InUse {
		t.Fatalf("CreateVolume(ext4lite) = %+v", extVol)
	}

	hostVol, err := gvx.CreateVolume(cacheDir, "shared-dir", gvx.DriverHostfs)
	if err != nil {
		t.Fatalf("CreateVolume(hostfs): %v", err)
	}
	if err := os.WriteFile(filepath.Join(hostVol.Mountpoint, "hello.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	autoVol, err := gvx.CreateVolume(cacheDir, "", "")
	if err != nil {
		t.Fatalf("CreateVolume(anonymous): %v", err)
	}
	if len(autoVol.Name) != 64 || autoVol.Driver != gvx.DriverExt4lite {
		t.Fatalf("CreateVolume(anonymous) = %+v, want 64-hex ext4lite", autoVol)
	}

	// Driver mismatch on existing volume must fail with ErrInvalidConfig.
	if _, err := gvx.CreateVolume(cacheDir, "app-data", gvx.DriverHostfs); !errors.Is(err, gvx.ErrInvalidConfig) {
		t.Fatalf("CreateVolume(conflicting driver) = %v, want ErrInvalidConfig", err)
	}

	// Hold a real ext4lite exclusive lock on app-data to simulate an active sandbox.
	f, err := os.OpenFile(extVol.Mountpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	lockedVol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{})
	if err != nil {
		_ = f.Close()
		t.Fatalf("ext4lite.OpenVolume: %v", err)
	}
	closedLockedVol := false
	defer func() {
		if !closedLockedVol {
			_ = lockedVol.Close()
		}
	}()

	inspected, err := gvx.InspectVolume(cacheDir, "app-data")
	if err != nil {
		t.Fatalf("InspectVolume(app-data): %v", err)
	}
	if !inspected.InUse {
		t.Fatalf("InspectVolume(app-data).InUse = false while ext4lite.Volume is open")
	}

	du, err := gvx.ComputeVolumeDiskUsage(cacheDir)
	if err != nil {
		t.Fatalf("ComputeVolumeDiskUsage: %v", err)
	}
	if du.Total != 3 || du.Active != 1 {
		t.Fatalf("ComputeVolumeDiskUsage = %+v, want Total=3 Active=1", du)
	}

	if err := gvx.RemoveVolume(cacheDir, "app-data"); !errors.Is(err, gvx.ErrVolumeInUse) {
		t.Fatalf("RemoveVolume(locked) = %v, want ErrVolumeInUse", err)
	}

	pruneRep, err := gvx.PruneVolumes(cacheDir)
	if err != nil {
		t.Fatalf("PruneVolumes: %v", err)
	}
	if len(pruneRep.Deleted) != 2 {
		t.Fatalf("PruneVolumes Deleted = %v, want 2 unlocked volumes deleted", pruneRep.Deleted)
	}

	remaining, err := gvx.ListVolumes(cacheDir)
	if err != nil {
		t.Fatalf("ListVolumes after prune: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Name != "app-data" {
		t.Fatalf("ListVolumes after prune = %+v, want only locked app-data", remaining)
	}

	// Release the active volume lock and verify removal succeeds.
	closedLockedVol = true
	if err := lockedVol.Close(); err != nil {
		t.Fatalf("lockedVol.Close: %v", err)
	}
	if err := gvx.RemoveVolume(cacheDir, "app-data"); err != nil {
		t.Fatalf("RemoveVolume(unlocked app-data): %v", err)
	}
	if _, err := gvx.InspectVolume(cacheDir, "app-data"); !errors.Is(err, gvx.ErrVolumeNotFound) {
		t.Fatalf("InspectVolume(deleted) = %v, want ErrVolumeNotFound", err)
	}
}

func TestProbeSystemInfoReportsHostAndStoreCounts(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if _, err := gvx.CreateVolume(cacheDir, "v1", gvx.DriverExt4lite); err != nil {
		t.Fatal(err)
	}
	info, err := gvx.ProbeSystemInfo(cacheDir, tuning.Values{})
	if err != nil {
		t.Fatalf("ProbeSystemInfo: %v", err)
	}
	if info.OS == "" || info.Architecture == "" || info.NumCPU <= 0 || info.PageSize <= 0 {
		t.Fatalf("ProbeSystemInfo host fields incomplete: %+v", info)
	}
	if info.Volumes != 1 {
		t.Fatalf("ProbeSystemInfo.Volumes = %d, want 1", info.Volumes)
	}
}
