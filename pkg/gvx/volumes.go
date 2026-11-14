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

package gvx

import (
	"cmp"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"z.gfire.dev/gvx/pkg/sentry/fsimpl/ext4lite"
)

var (
	// ErrVolumeNotFound reports that a named volume does not exist in the local store.
	ErrVolumeNotFound = errors.New("gvx: volume not found")
	// ErrVolumeInUse reports that another sandbox holds the exclusive lock on a volume.
	ErrVolumeInUse = ext4lite.ErrVolumeInUse
)

const ext4VolumeSuffix = ".ext4"

// VolumeInfo describes one named volume in the local gvx volume store.
type VolumeInfo struct {
	Name       string      `json:"Name"`
	Driver     MountDriver `json:"Driver"`
	Mountpoint string      `json:"Mountpoint"`
	CreatedAt  time.Time   `json:"CreatedAt"`
	SizeBytes  int64       `json:"SizeBytes"`
	InUse      bool        `json:"InUse"`
}

// VolumePruneReport summarizes volumes deleted by PruneVolumes.
type VolumePruneReport struct {
	Deleted        []string
	SpaceReclaimed int64
}

// VolumeDiskUsage summarizes local volume counts and byte consumption.
type VolumeDiskUsage struct {
	Total            int
	Active           int
	TotalBytes       int64
	ReclaimableBytes int64
}

// VolumeDir returns the host directory storing named volumes for cacheDir.
func VolumeDir(cacheDir string) (string, error) {
	return (Config{OCICacheDir: strings.TrimSpace(cacheDir)}).volumeRoot()
}

func randomVolumeName() (string, error) {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("gvx: generate volume name: %w", err)
	}
	return hex.EncodeToString(buf[:]), nil
}

// CreateVolume creates or opens an idempotent named volume under cacheDir.
// An empty name generates a 64-character hexadecimal identifier. An empty
// driver defaults to DriverExt4lite.
func CreateVolume(cacheDir, name string, driver MountDriver) (VolumeInfo, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		var err error
		name, err = randomVolumeName()
		if err != nil {
			return VolumeInfo{}, err
		}
	}
	if !volumeNamePattern.MatchString(name) {
		return VolumeInfo{}, fmt.Errorf("%w: invalid volume name %q", ErrInvalidConfig, name)
	}
	if driver == "" {
		driver = DriverExt4lite
	}
	if driver != DriverExt4lite && driver != DriverHostfs {
		return VolumeInfo{}, fmt.Errorf("%w: unsupported volume driver %q (want ext4lite or hostfs)", ErrInvalidConfig, driver)
	}

	root, err := VolumeDir(cacheDir)
	if err != nil {
		return VolumeInfo{}, err
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return VolumeInfo{}, fmt.Errorf("gvx: create volume directory: %w", err)
	}

	imgPath := filepath.Join(root, name+ext4VolumeSuffix)
	dirPath := filepath.Join(root, name)

	switch driver {
	case DriverExt4lite:
		if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
			return VolumeInfo{}, fmt.Errorf("%w: volume %q already exists with driver %q", ErrInvalidConfig, name, DriverHostfs)
		}
		if info, err := os.Stat(imgPath); err == nil {
			if !info.Mode().IsRegular() {
				return VolumeInfo{}, fmt.Errorf("gvx: volume %q path %q is not a regular file", name, imgPath)
			}
			return InspectVolume(cacheDir, name)
		}
		f, err := os.OpenFile(imgPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return VolumeInfo{}, fmt.Errorf("gvx: create volume %q: %w", name, err)
		}
		vol, err := ext4lite.OpenVolume(f, ext4lite.VolumeOptions{})
		if err != nil {
			_ = os.Remove(imgPath)
			return VolumeInfo{}, fmt.Errorf("gvx: format volume %q: %w", name, err)
		}
		if closeErr := vol.Close(); closeErr != nil {
			return VolumeInfo{}, fmt.Errorf("gvx: close formatted volume %q: %w", name, closeErr)
		}
		return InspectVolume(cacheDir, name)

	case DriverHostfs:
		if _, err := os.Stat(imgPath); err == nil {
			return VolumeInfo{}, fmt.Errorf("%w: volume %q already exists with driver %q", ErrInvalidConfig, name, DriverExt4lite)
		}
		if err := os.MkdirAll(dirPath, 0o700); err != nil {
			return VolumeInfo{}, fmt.Errorf("gvx: create hostfs volume %q: %w", name, err)
		}
		return InspectVolume(cacheDir, name)
	}
	return VolumeInfo{}, fmt.Errorf("%w: unsupported volume driver %q", ErrInvalidConfig, driver)
}

// InspectVolume returns metadata and lock state for one named volume.
func InspectVolume(cacheDir, name string) (VolumeInfo, error) {
	name = strings.TrimSpace(name)
	if !volumeNamePattern.MatchString(name) {
		return VolumeInfo{}, fmt.Errorf("%w: %s", ErrVolumeNotFound, name)
	}
	root, err := VolumeDir(cacheDir)
	if err != nil {
		return VolumeInfo{}, err
	}
	imgPath := filepath.Join(root, name+ext4VolumeSuffix)
	if info, err := os.Stat(imgPath); err == nil && info.Mode().IsRegular() {
		return buildExt4VolumeInfo(name, imgPath, info)
	}
	dirPath := filepath.Join(root, name)
	if info, err := os.Stat(dirPath); err == nil && info.IsDir() {
		return buildHostfsVolumeInfo(name, dirPath, info), nil
	}
	return VolumeInfo{}, fmt.Errorf("%w: %s", ErrVolumeNotFound, name)
}

// ListVolumes returns all named volumes under cacheDir sorted by name.
// Read-only calls on a non-existent store directory return an empty slice.
func ListVolumes(cacheDir string) ([]VolumeInfo, error) {
	root, err := VolumeDir(cacheDir)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("gvx: read volume directory: %w", err)
	}

	seenExt4 := make(map[string]bool)
	var vols []VolumeInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ext4VolumeSuffix) {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ext4VolumeSuffix)
		if !volumeNamePattern.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		vi, err := buildExt4VolumeInfo(name, filepath.Join(root, e.Name()), info)
		if err != nil {
			continue
		}
		seenExt4[name] = true
		vols = append(vols, vi)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		if seenExt4[name] || !volumeNamePattern.MatchString(name) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		vols = append(vols, buildHostfsVolumeInfo(name, filepath.Join(root, name), info))
	}
	slices.SortFunc(vols, func(a, b VolumeInfo) int {
		return cmp.Compare(a.Name, b.Name)
	})
	return vols, nil
}

// RemoveVolume deletes one named volume when it is not locked by a running sandbox.
func RemoveVolume(cacheDir, name string) error {
	vi, err := InspectVolume(cacheDir, name)
	if err != nil {
		return err
	}
	if vi.InUse {
		return fmt.Errorf("gvx: volume %q is in use: %w", vi.Name, ErrVolumeInUse)
	}
	switch vi.Driver {
	case DriverExt4lite:
		if err := os.Remove(vi.Mountpoint); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: %s", ErrVolumeNotFound, vi.Name)
			}
			return fmt.Errorf("gvx: remove volume %q: %w", vi.Name, err)
		}
	case DriverHostfs:
		if err := os.RemoveAll(vi.Mountpoint); err != nil {
			return fmt.Errorf("gvx: remove volume %q: %w", vi.Name, err)
		}
	}
	return nil
}

// PruneVolumes removes all local volumes that are not currently locked by a
// running sandbox.
func PruneVolumes(cacheDir string) (VolumePruneReport, error) {
	vols, err := ListVolumes(cacheDir)
	if err != nil {
		return VolumePruneReport{}, err
	}
	var report VolumePruneReport
	var errs []error
	for _, v := range vols {
		if v.InUse {
			continue
		}
		if err := RemoveVolume(cacheDir, v.Name); err != nil {
			if errors.Is(err, ErrVolumeInUse) || errors.Is(err, ErrVolumeNotFound) {
				continue
			}
			errs = append(errs, err)
			continue
		}
		report.Deleted = append(report.Deleted, v.Name)
		report.SpaceReclaimed += v.SizeBytes
	}
	return report, errors.Join(errs...)
}

// ComputeVolumeDiskUsage summarizes local volume counts and byte sizes.
func ComputeVolumeDiskUsage(cacheDir string) (VolumeDiskUsage, error) {
	vols, err := ListVolumes(cacheDir)
	if err != nil {
		return VolumeDiskUsage{}, err
	}
	var du VolumeDiskUsage
	du.Total = len(vols)
	for _, v := range vols {
		du.TotalBytes += v.SizeBytes
		if v.InUse {
			du.Active++
		} else {
			du.ReclaimableBytes += v.SizeBytes
		}
	}
	return du, nil
}

func buildExt4VolumeInfo(name, imgPath string, info os.FileInfo) (VolumeInfo, error) {
	abs, err := filepath.Abs(imgPath)
	if err == nil {
		imgPath = abs
	}
	inUse, err := ext4lite.ProbeVolumeInUse(imgPath)
	if err != nil {
		return VolumeInfo{}, fmt.Errorf("gvx: probe volume %q lock: %w", name, err)
	}
	return VolumeInfo{
		Name:       name,
		Driver:     DriverExt4lite,
		Mountpoint: imgPath,
		CreatedAt:  info.ModTime().UTC(),
		SizeBytes:  info.Size(),
		InUse:      inUse,
	}, nil
}

func buildHostfsVolumeInfo(name, dirPath string, info os.FileInfo) VolumeInfo {
	if abs, err := filepath.Abs(dirPath); err == nil {
		dirPath = abs
	}
	return VolumeInfo{
		Name:       name,
		Driver:     DriverHostfs,
		Mountpoint: dirPath,
		CreatedAt:  info.ModTime().UTC(),
		SizeBytes:  directorySizeBytes(dirPath),
	}
}

func directorySizeBytes(root string) int64 {
	var total int64
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, statErr := d.Info(); statErr == nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	return total
}
