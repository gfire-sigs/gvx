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
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"z.gfire.dev/gvx/pkg/oci"
)

// isolateUserDirs points the user directories of every host at a fresh
// temporary home, so a test never reads or moves the volumes of the user.
func isolateUserDirs(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "AppData", "Local"))
	t.Setenv("XDG_CACHE_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv(VolumeDirEnv, "")
	return home
}

func TestDefaultVolumeDirForUsesTheDataDirectory(t *testing.T) {
	home := t.TempDir()
	dataHome := t.TempDir()
	localAppData := t.TempDir()
	homeDir := func() (string, error) { return home, nil }
	envOf := func(m map[string]string) func(string) string {
		return func(k string) string { return m[k] }
	}
	tests := []struct {
		goos string
		env  map[string]string
		want string
	}{
		{goos: "darwin", want: filepath.Join(home, "Library", "Application Support", "gvx", "volumes")},
		{goos: "darwin", env: map[string]string{"XDG_DATA_HOME": dataHome}, want: filepath.Join(home, "Library", "Application Support", "gvx", "volumes")},
		{goos: "linux", want: filepath.Join(home, ".local", "share", "gvx", "volumes")},
		{goos: "linux", env: map[string]string{"XDG_DATA_HOME": dataHome}, want: filepath.Join(dataHome, "gvx", "volumes")},
		{goos: "linux", env: map[string]string{"XDG_DATA_HOME": "relative"}, want: filepath.Join(home, ".local", "share", "gvx", "volumes")},
		{goos: "android", want: filepath.Join(home, ".local", "share", "gvx", "volumes")},
		{goos: "windows", env: map[string]string{"LOCALAPPDATA": localAppData}, want: filepath.Join(localAppData, "gvx", "cache", "volumes")},
	}
	for _, tc := range tests {
		got, err := defaultVolumeDirFor(tc.goos, envOf(tc.env), homeDir)
		if err != nil || got != tc.want {
			t.Errorf("defaultVolumeDirFor(%s, %v) = (%q, %v), want %q", tc.goos, tc.env, got, err, tc.want)
		}
	}

	if _, err := defaultVolumeDirFor("windows", envOf(nil), homeDir); err == nil {
		t.Error("defaultVolumeDirFor(windows) without LOCALAPPDATA succeeded")
	}
	noHome := func() (string, error) { return "", errors.New("no home") }
	if _, err := defaultVolumeDirFor("darwin", envOf(nil), noHome); err == nil {
		t.Error("defaultVolumeDirFor(darwin) without a home directory succeeded")
	}
}

func TestVolumeRootPrecedence(t *testing.T) {
	isolateUserDirs(t)
	def, err := defaultVolumeDirFor(runtime.GOOS, os.Getenv, os.UserHomeDir)
	if err != nil {
		t.Fatalf("defaultVolumeDirFor: %v", err)
	}
	if got, err := (Config{}).volumeRoot(); err != nil || got != def {
		t.Fatalf("volumeRoot() = (%q, %v), want the default %q", got, err, def)
	}

	cacheDir := t.TempDir()
	want := filepath.Join(cacheDir, "volumes")
	if got, err := (Config{OCICacheDir: cacheDir}).volumeRoot(); err != nil || got != want {
		t.Fatalf("volumeRoot() with OCICacheDir = (%q, %v), want %q", got, err, want)
	}

	envDir := t.TempDir()
	t.Setenv(VolumeDirEnv, envDir)
	if got, err := (Config{OCICacheDir: cacheDir}).volumeRoot(); err != nil || got != envDir {
		t.Fatalf("volumeRoot() with %s = (%q, %v), want %q", VolumeDirEnv, got, err, envDir)
	}
	if got, err := VolumeDir(cacheDir); err != nil || got != envDir {
		t.Fatalf("VolumeDir() with %s = (%q, %v), want %q", VolumeDirEnv, got, err, envDir)
	}
}

// TestVolumeRootMovesTheLegacyDirectory proves that the volumes of an earlier
// release, which lie beside the default layer cache, move to the new default
// directory on first use, and that the legacy path still reaches them.
func TestVolumeRootMovesTheLegacyDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows default stays beside the layer cache")
	}
	isolateUserDirs(t)
	layers, err := oci.DefaultCacheDir()
	if err != nil {
		t.Fatalf("oci.DefaultCacheDir: %v", err)
	}
	legacy := filepath.Join(filepath.Dir(layers), "volumes")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "data.ext4"), []byte("volume"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	root, err := (Config{}).volumeRoot()
	if err != nil {
		t.Fatalf("volumeRoot: %v", err)
	}
	if root == legacy {
		t.Fatalf("volumeRoot() = %q, want a directory outside the layer cache", root)
	}
	if got, err := os.ReadFile(filepath.Join(root, "data.ext4")); err != nil || string(got) != "volume" {
		t.Fatalf("moved volume = (%q, %v), want %q", got, err, "volume")
	}
	// An earlier release reads the legacy path, and the link sends it to the
	// moved volumes instead of an empty directory.
	if got, err := os.ReadFile(filepath.Join(legacy, "data.ext4")); err != nil || string(got) != "volume" {
		t.Fatalf("volume through the legacy path = (%q, %v), want %q", got, err, "volume")
	}
	if st, err := os.Lstat(legacy); err != nil || st.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("legacy path is not a symbolic link: mode %v, err %v", st.Mode(), err)
	}
	if again, err := (Config{}).volumeRoot(); err != nil || again != root {
		t.Fatalf("second volumeRoot() = (%q, %v), want %q", again, err, root)
	}
}

func TestMigrateVolumeRoot(t *testing.T) {
	t.Run("keeps a root that is the legacy directory", func(t *testing.T) {
		dir := t.TempDir()
		if got := migrateVolumeRoot(dir, dir); got != dir {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, dir)
		}
		if _, err := os.Lstat(dir); err != nil {
			t.Fatalf("directory changed: %v", err)
		}
	})
	t.Run("keeps an existing root", func(t *testing.T) {
		dir := t.TempDir()
		legacy, root := filepath.Join(dir, "legacy"), filepath.Join(dir, "root")
		for _, d := range []string{legacy, root} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if got := migrateVolumeRoot(legacy, root); got != root {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, root)
		}
		if _, err := os.Lstat(legacy); err != nil {
			t.Fatalf("legacy directory changed: %v", err)
		}
	})
	t.Run("creates nothing without a legacy directory", func(t *testing.T) {
		dir := t.TempDir()
		legacy, root := filepath.Join(dir, "legacy"), filepath.Join(dir, "parent", "root")
		if got := migrateVolumeRoot(legacy, root); got != root {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, root)
		}
		if _, err := os.Lstat(filepath.Dir(root)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("migrateVolumeRoot() created %s: %v", filepath.Dir(root), err)
		}
	})
	t.Run("ignores a legacy path that is not a directory", func(t *testing.T) {
		dir := t.TempDir()
		legacy, root := filepath.Join(dir, "legacy"), filepath.Join(dir, "root")
		if err := os.WriteFile(legacy, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := migrateVolumeRoot(legacy, root); got != root {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, root)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("migrateVolumeRoot() moved a regular file to %s", root)
		}
	})
	t.Run("keeps the legacy directory when the move fails", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory that the test user cannot write")
		}
		dir := t.TempDir()
		legacy := filepath.Join(dir, "legacy")
		parent := filepath.Join(dir, "parent")
		for _, d := range []string{legacy, parent} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		if got := migrateVolumeRoot(legacy, filepath.Join(parent, "root")); got != legacy {
			t.Fatalf("migrateVolumeRoot() = %q, want the legacy directory %q", got, legacy)
		}
	})
}
