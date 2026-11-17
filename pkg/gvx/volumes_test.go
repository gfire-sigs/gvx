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

func TestConcurrentInspectVolumeNeverReportsFalseInUse(t *testing.T) {
	cacheDir := filepath.Join(t.TempDir(), "cache")
	if _, err := gvx.CreateVolume(cacheDir, "shared-probe", gvx.DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}
	errs := make(chan error, 8)
	for range 8 {
		go func() {
			for range 16 {
				vi, err := gvx.InspectVolume(cacheDir, "shared-probe")
				if err != nil {
					errs <- err
					return
				}
				if vi.InUse || vi.LockMode != "none" {
					errs <- errors.New("concurrent read-only InspectVolume reported non-none lock state")
					return
				}
			}
			errs <- nil
		}()
	}
	for range 8 {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestVolumeAllocatedBytesSparseVsDenseAndDiskUsage(t *testing.T) {
	// Property: VolumeInfo.AllocatedBytes measures physical disk allocation rather than
	// logical EOF size, and ComputeVolumeDiskUsage / PruneVolumes account physical bytes.
	// Seam: gvx.InspectVolume, gvx.ListVolumes, gvx.ComputeVolumeDiskUsage, gvx.PruneVolumes.
	// Fault: Reporting st_size as AllocatedBytes or summing logical SizeBytes in disk usage.
	cacheDir := filepath.Join(t.TempDir(), "cache")

	extVol, err := gvx.CreateVolume(cacheDir, "sparse-ext", gvx.DriverExt4lite)
	if err != nil {
		t.Fatalf("CreateVolume(ext4lite): %v", err)
	}
	const sparseLogical = int64(128 << 20)
	if err := os.Truncate(extVol.Mountpoint, sparseLogical); err != nil {
		t.Fatalf("Truncate(sparse-ext): %v", err)
	}

	hostVol, err := gvx.CreateVolume(cacheDir, "sparse-host", gvx.DriverHostfs)
	if err != nil {
		t.Fatalf("CreateVolume(hostfs): %v", err)
	}
	hostFile := filepath.Join(hostVol.Mountpoint, "hole.bin")
	hf, err := os.OpenFile(hostFile, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := hf.Truncate(64 << 20); err != nil {
		_ = hf.Close()
		t.Fatal(err)
	}
	if _, err := hf.WriteAt([]byte("tail"), (64<<20)-4); err != nil {
		_ = hf.Close()
		t.Fatal(err)
	}
	if err := hf.Close(); err != nil {
		t.Fatal(err)
	}

	extInspected, err := gvx.InspectVolume(cacheDir, "sparse-ext")
	if err != nil {
		t.Fatalf("InspectVolume(sparse-ext): %v", err)
	}
	if extInspected.SizeBytes != sparseLogical {
		t.Fatalf("sparse-ext SizeBytes = %d, want %d", extInspected.SizeBytes, sparseLogical)
	}
	if extInspected.AllocatedBytes <= 0 || extInspected.AllocatedBytes >= sparseLogical/2 {
		t.Fatalf("sparse-ext AllocatedBytes = %d, want > 0 and < %d", extInspected.AllocatedBytes, sparseLogical/2)
	}

	hostInspected, err := gvx.InspectVolume(cacheDir, "sparse-host")
	if err != nil {
		t.Fatalf("InspectVolume(sparse-host): %v", err)
	}
	if hostInspected.SizeBytes != 64<<20 {
		t.Fatalf("sparse-host SizeBytes = %d, want %d", hostInspected.SizeBytes, 64<<20)
	}
	if hostInspected.AllocatedBytes <= 0 || hostInspected.AllocatedBytes >= 32<<20 {
		t.Fatalf("sparse-host AllocatedBytes = %d, want > 0 and < %d", hostInspected.AllocatedBytes, 32<<20)
	}

	wantPhysical := extInspected.AllocatedBytes + hostInspected.AllocatedBytes
	du, err := gvx.ComputeVolumeDiskUsage(cacheDir)
	if err != nil {
		t.Fatalf("ComputeVolumeDiskUsage: %v", err)
	}
	if du.Total != 2 || du.Active != 0 || du.TotalBytes != wantPhysical || du.ReclaimableBytes != wantPhysical {
		t.Fatalf("ComputeVolumeDiskUsage = %+v, want Total=2 Active=0 TotalBytes=%d ReclaimableBytes=%d", du, wantPhysical, wantPhysical)
	}

	pruned, err := gvx.PruneVolumes(cacheDir)
	if err != nil {
		t.Fatalf("PruneVolumes: %v", err)
	}
	if pruned.SpaceReclaimed != wantPhysical {
		t.Fatalf("PruneVolumes SpaceReclaimed = %d, want physical %d", pruned.SpaceReclaimed, wantPhysical)
	}
}

func TestVolumeLockModeMatrixAndCompactVolume(t *testing.T) {
	// Property: LockMode distinguishes "none", "shared", and "exclusive" with InUse == (LockMode != "none"),
	// and CompactVolume refuses shared/exclusive/hostfs/missing volumes while compacting unlocked ext4lite volumes.
	// Seam: gvx.InspectVolume, gvx.CompactVolume.
	// Fault: Allowing compaction while LOCK_SH is held, misclassifying LOCK_SH as "none"/"exclusive", or failing to shrink tail.
	cacheDir := filepath.Join(t.TempDir(), "cache")

	if _, err := gvx.CompactVolume(cacheDir, "missing"); !errors.Is(err, gvx.ErrVolumeNotFound) {
		t.Fatalf("CompactVolume(missing) = %v, want ErrVolumeNotFound", err)
	}
	if _, err := gvx.CompactVolume(cacheDir, "../bad"); !errors.Is(err, gvx.ErrVolumeNotFound) {
		t.Fatalf("CompactVolume(invalid name) = %v, want ErrVolumeNotFound", err)
	}

	if _, err := gvx.CreateVolume(cacheDir, "dirvol", gvx.DriverHostfs); err != nil {
		t.Fatalf("CreateVolume(hostfs): %v", err)
	}
	if _, err := gvx.CompactVolume(cacheDir, "dirvol"); !errors.Is(err, gvx.ErrInvalidConfig) {
		t.Fatalf("CompactVolume(hostfs) = %v, want ErrInvalidConfig", err)
	}

	vol, err := gvx.CreateVolume(cacheDir, "branchable", gvx.DriverExt4lite)
	if err != nil {
		t.Fatalf("CreateVolume(ext4lite): %v", err)
	}
	initialSize := vol.SizeBytes
	if vol.LockMode != "none" || vol.InUse {
		t.Fatalf("initial LockMode=%q InUse=%v, want none/false", vol.LockMode, vol.InUse)
	}

	// Shared lock state: LockMode == "shared", InUse == true, CompactVolume and RemoveVolume fail with ErrVolumeInUse.
	releaseSH1 := holdSharedFileLock(t, vol.Mountpoint)
	releaseSH2 := holdSharedFileLock(t, vol.Mountpoint)
	sharedInfo, err := gvx.InspectVolume(cacheDir, "branchable")
	if err != nil {
		releaseSH2()
		releaseSH1()
		t.Fatalf("InspectVolume(shared): %v", err)
	}
	if sharedInfo.LockMode != "shared" || !sharedInfo.InUse {
		releaseSH2()
		releaseSH1()
		t.Fatalf("InspectVolume under LOCK_SH = (LockMode=%q, InUse=%v), want (\"shared\", true)", sharedInfo.LockMode, sharedInfo.InUse)
	}
	if _, err := gvx.CompactVolume(cacheDir, "branchable"); !errors.Is(err, gvx.ErrVolumeInUse) {
		releaseSH2()
		releaseSH1()
		t.Fatalf("CompactVolume under LOCK_SH = %v, want ErrVolumeInUse", err)
	}
	if err := gvx.RemoveVolume(cacheDir, "branchable"); !errors.Is(err, gvx.ErrVolumeInUse) {
		releaseSH2()
		releaseSH1()
		t.Fatalf("RemoveVolume under LOCK_SH = %v, want ErrVolumeInUse", err)
	}
	releaseSH2()
	releaseSH1()

	// Exclusive lock state: LockMode == "exclusive", InUse == true, CompactVolume fails with ErrVolumeInUse.
	rwFile, err := os.OpenFile(vol.Mountpoint, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	rwVol, err := ext4lite.OpenVolume(rwFile, ext4lite.VolumeOptions{ReadOnly: false})
	if err != nil {
		_ = rwFile.Close()
		t.Fatalf("OpenVolume(RW): %v", err)
	}
	exclInfo, err := gvx.InspectVolume(cacheDir, "branchable")
	if err != nil {
		_ = rwVol.Close()
		t.Fatalf("InspectVolume(exclusive): %v", err)
	}
	if exclInfo.LockMode != "exclusive" || !exclInfo.InUse {
		_ = rwVol.Close()
		t.Fatalf("InspectVolume under LOCK_EX = (LockMode=%q, InUse=%v), want (\"exclusive\", true)", exclInfo.LockMode, exclInfo.InUse)
	}
	if _, err := gvx.CompactVolume(cacheDir, "branchable"); !errors.Is(err, gvx.ErrVolumeInUse) {
		_ = rwVol.Close()
		t.Fatalf("CompactVolume under LOCK_EX = %v, want ErrVolumeInUse", err)
	}
	if err := rwVol.Close(); err != nil {
		t.Fatalf("rwVol.Close: %v", err)
	}

	// Over-extend image file beyond its group boundary, then CompactVolume must truncate and return clean VolumeInfo.
	bloatedSize := initialSize + (64 << 20)
	if err := os.Truncate(vol.Mountpoint, bloatedSize); err != nil {
		t.Fatalf("Truncate(bloated): %v", err)
	}
	compacted, err := gvx.CompactVolume(cacheDir, "branchable")
	if err != nil {
		t.Fatalf("CompactVolume(unlocked): %v", err)
	}
	if compacted.SizeBytes != initialSize || compacted.InUse || compacted.LockMode != "none" {
		t.Fatalf("CompactVolume result = %+v, want SizeBytes=%d InUse=false LockMode=none", compacted, initialSize)
	}
}
