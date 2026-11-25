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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"z.gfire.dev/gvx/pkg/oci"
)

// VolumeDirEnv names the environment variable that overrides the default
// directory of named volumes when neither Config.VolumeDir nor
// Config.OCICacheDir is set.
const VolumeDirEnv = "GVX_VOLUME_DIR"

// volumeRoot returns the directory that holds named volumes, migrating a
// legacy cache-adjacent directory on first default resolution. Precedence is
// Config.VolumeDir, Config.OCICacheDir ("<dir>/volumes"), VolumeDirEnv, and
// finally the platform user data directory of defaultVolumeDirFor.
func (c Config) volumeRoot() (string, error) {
	return c.volumeRootWithMigrate(true)
}

// volumeRootReadOnly resolves the directory that holds named volumes without
// moving or creating host directories. Config.normalize uses it so validation
// never mutates the host filesystem.
func (c Config) volumeRootReadOnly() (string, error) {
	return c.volumeRootWithMigrate(false)
}

func (c Config) volumeRootWithMigrate(migrate bool) (string, error) {
	if dir := strings.TrimSpace(c.VolumeDir); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("gvx: resolve VolumeDir %q: %w", dir, err)
		}
		return abs, nil
	}
	if dir := strings.TrimSpace(c.OCICacheDir); dir != "" {
		return filepath.Join(dir, "volumes"), nil
	}
	if dir := strings.TrimSpace(os.Getenv(VolumeDirEnv)); dir != "" {
		abs, err := filepath.Abs(dir)
		if err != nil {
			return "", fmt.Errorf("gvx: resolve %s %q: %w", VolumeDirEnv, dir, err)
		}
		return abs, nil
	}
	root, err := defaultVolumeDirFor(runtime.GOOS, os.Getenv, os.UserHomeDir)
	if err != nil {
		return "", err
	}
	layers, err := oci.DefaultCacheDir()
	if err != nil {
		return root, nil
	}
	legacy := filepath.Join(filepath.Dir(layers), "volumes")
	if !migrate {
		return existingVolumeRoot(legacy, root), nil
	}
	return migrateVolumeRoot(legacy, root), nil
}

// defaultVolumeDirFor returns the default directory of the named volumes on
// goos. On macOS and Linux it lies in the user data directory and not in the
// user cache directory, because a host can purge the cache directory. macOS
// deletes the content of ~/Library/Caches when the disk runs low on space.
// Windows does not purge %LOCALAPPDATA%, so the directory there stays beside
// the layer cache.
func defaultVolumeDirFor(goos string, getenv func(string) string, userHomeDir func() (string, error)) (string, error) {
	if goos == "windows" {
		localAppData := getenv("LOCALAPPDATA")
		if localAppData == "" {
			return "", errors.New("gvx: %LOCALAPPDATA% is not set, so the volume directory is unknown")
		}
		return filepath.Join(localAppData, "gvx", "cache", "volumes"), nil
	}
	if goos != "darwin" && goos != "ios" {
		if dataHome := getenv("XDG_DATA_HOME"); filepath.IsAbs(dataHome) {
			return filepath.Join(dataHome, "gvx", "volumes"), nil
		}
	}
	home, err := userHomeDir()
	if err != nil {
		return "", fmt.Errorf("gvx: locate the home directory for the volume directory: %w", err)
	}
	if goos == "darwin" || goos == "ios" {
		return filepath.Join(home, "Library", "Application Support", "gvx", "volumes"), nil
	}
	return filepath.Join(home, ".local", "share", "gvx", "volumes"), nil
}

// existingVolumeRoot reports where default named volumes currently reside
// without migrating legacy to root.
func existingVolumeRoot(legacy, root string) string {
	if legacy == root {
		return root
	}
	if _, err := os.Lstat(root); err == nil {
		return root
	}
	if st, err := os.Lstat(legacy); err == nil && st.IsDir() {
		return legacy
	}
	return root
}

// migrateVolumeRoot moves the volume directory of an earlier release, legacy,
// to root when root does not exist yet. It then leaves a symbolic link at
// legacy, so an earlier release that runs beside this one finds the same
// volumes and does not create empty ones. It returns the directory that holds
// the volumes: root, or legacy when the move fails. A failed move leaves the
// volumes where they were. Another process that moves the directory first
// makes the move fail, and root then exists.
func migrateVolumeRoot(legacy, root string) string {
	if legacy == root {
		return root
	}
	if _, err := os.Lstat(root); err == nil {
		return root
	}
	if st, err := os.Lstat(legacy); err != nil || !st.IsDir() {
		return root
	}
	if err := os.MkdirAll(filepath.Dir(root), 0o700); err == nil {
		if err := os.Rename(legacy, root); err == nil {
			// A missing link costs an earlier release the volumes, not this one.
			_ = os.Symlink(root, legacy)
			return root
		}
	}
	if _, err := os.Lstat(root); err == nil {
		return root
	}
	return legacy
}
