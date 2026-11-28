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
	"sync"
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
		{goos: "windows", env: map[string]string{"LOCALAPPDATA": localAppData}, want: filepath.Join(localAppData, "gvx", "volumes")},
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

	envDir := t.TempDir()
	t.Setenv(VolumeDirEnv, envDir)
	if got, err := (Config{}).volumeRoot(); err != nil || got != envDir {
		t.Fatalf("volumeRoot() with %s = (%q, %v), want %q", VolumeDirEnv, got, err, envDir)
	}
	if got, err := VolumeDir(""); err != nil || got != envDir {
		t.Fatalf("VolumeDir(\"\") with %s = (%q, %v), want %q", VolumeDirEnv, got, err, envDir)
	}

	// An explicit OCICacheDir / cacheDir stays isolated from ambient GVX_VOLUME_DIR
	// so targeted commands (including volume prune) and tests never touch user volumes.
	cacheDir := t.TempDir()
	wantCache := filepath.Join(cacheDir, "volumes")
	if got, err := (Config{OCICacheDir: cacheDir}).volumeRoot(); err != nil || got != wantCache {
		t.Fatalf("volumeRoot() with OCICacheDir = (%q, %v), want %q", got, err, wantCache)
	}
	if got, err := VolumeDir(cacheDir); err != nil || got != wantCache {
		t.Fatalf("VolumeDir(cacheDir) with %s = (%q, %v), want %q", VolumeDirEnv, got, err, wantCache)
	}

	// Config.VolumeDir takes highest precedence over both OCICacheDir and GVX_VOLUME_DIR.
	volDir := t.TempDir()
	if got, err := (Config{OCICacheDir: cacheDir, VolumeDir: volDir}).volumeRoot(); err != nil || got != volDir {
		t.Fatalf("volumeRoot() with VolumeDir = (%q, %v), want %q", got, err, volDir)
	}
}

func TestPruneVolumesWithExplicitCacheDirDoesNotTouchVolumeDirEnv(t *testing.T) {
	isolateUserDirs(t)
	envDir := t.TempDir()
	t.Setenv(VolumeDirEnv, envDir)
	if _, err := CreateVolume("", "keep-me", DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume in %s: %v", VolumeDirEnv, err)
	}

	scratchCache := t.TempDir()
	if _, err := CreateVolume(scratchCache, "throwaway", DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume in scratch cache: %v", err)
	}
	report, err := PruneVolumes(scratchCache)
	if err != nil {
		t.Fatalf("PruneVolumes(scratchCache): %v", err)
	}
	if len(report.Deleted) != 1 || report.Deleted[0] != "throwaway" {
		t.Fatalf("PruneVolumes(scratchCache).Deleted = %v, want [throwaway]", report.Deleted)
	}
	if _, err := InspectVolume("", "keep-me"); err != nil {
		t.Fatalf("volume in %s was affected by PruneVolumes(scratchCache): %v", VolumeDirEnv, err)
	}
}

func isLegacyVolumeLink(st os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return st.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0
	}
	return st.Mode()&os.ModeSymlink != 0
}

func TestConfigNormalizeDoesNotMigrateLegacyVolumeDir(t *testing.T) {
	isolateUserDirs(t)
	layers, err := oci.DefaultCacheDir()
	if err != nil {
		t.Fatalf("oci.DefaultCacheDir: %v", err)
	}
	legacy := filepath.Join(filepath.Dir(layers), "volumes")
	if err := os.MkdirAll(legacy, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "keep.ext4"), []byte("volume"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg := Config{
		Mounts: []Mount{{Kind: MountVolume, VolumeName: "keep", GuestPath: "/data"}},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize(): %v", err)
	}
	st, err := os.Lstat(legacy)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", legacy, err)
	}
	if !st.IsDir() || isLegacyVolumeLink(st) {
		t.Fatalf("normalize() migrated legacy directory %q: mode %v", legacy, st.Mode())
	}
	root, err := defaultVolumeDirFor(runtime.GOOS, os.Getenv, os.UserHomeDir)
	if err != nil {
		t.Fatalf("defaultVolumeDirFor: %v", err)
	}
	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("normalize() created %q: %v", root, err)
	}
}

// TestVolumeRootMovesTheLegacyDirectory proves that the volumes of an earlier
// release, which lie beside the default layer cache, move to the new default
// directory on first use, and that the legacy path still reaches them.
func TestVolumeRootMovesTheLegacyDirectory(t *testing.T) {
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
	st, err := os.Lstat(legacy)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", legacy, err)
	}
	if !isLegacyVolumeLink(st) {
		t.Fatalf("legacy path is not a link or junction: mode %v", st.Mode())
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
	t.Run("keeps the legacy directory when root parent is unsearchable", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory that the test user cannot traverse")
		}
		dir := t.TempDir()
		legacy := filepath.Join(dir, "legacy")
		parent := filepath.Join(dir, "parent")
		for _, d := range []string{legacy, parent} {
			if err := os.Mkdir(d, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.Chmod(parent, 0o000); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
		if got := migrateVolumeRoot(legacy, filepath.Join(parent, "root")); got != legacy {
			t.Fatalf("migrateVolumeRoot() = %q, want the legacy directory %q", got, legacy)
		}
	})
	t.Run("concurrent callers all observe root after migration", func(t *testing.T) {
		dir := t.TempDir()
		legacy := filepath.Join(dir, "legacy")
		root := filepath.Join(dir, "data", "volumes")
		if err := os.Mkdir(legacy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, "shared.ext4"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}

		const workers = 8
		start := make(chan struct{})
		results := make([]string, workers)
		var wg sync.WaitGroup
		for i := range workers {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-start
				results[idx] = migrateVolumeRoot(legacy, root)
			}(i)
		}
		close(start)
		wg.Wait()

		for i, got := range results {
			if got != root {
				t.Errorf("worker %d got %q, want %q", i, got, root)
			}
		}
		if data, err := os.ReadFile(filepath.Join(root, "shared.ext4")); err != nil || string(data) != "ok" {
			t.Fatalf("migrated file = (%q, %v), want \"ok\"", data, err)
		}
		st, err := os.Lstat(legacy)
		if err != nil {
			t.Fatalf("Lstat(%q): %v", legacy, err)
		}
		if !isLegacyVolumeLink(st) {
			t.Fatalf("legacy path is not a link or junction after concurrent migration: mode %v", st.Mode())
		}
	})
	t.Run("switches to root when rename fails on an empty legacy directory", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory that the test user cannot modify")
		}
		dir := t.TempDir()
		legacyParent := filepath.Join(dir, "ro-parent")
		legacy := filepath.Join(legacyParent, "volumes")
		root := filepath.Join(dir, "data", "volumes")
		if err := os.MkdirAll(legacy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(legacyParent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(legacyParent, 0o700) })

		if got := migrateVolumeRoot(legacy, root); got != root {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, root)
		}
		if st, err := os.Lstat(root); err != nil || !st.IsDir() {
			t.Fatalf("root directory %q not created: st=%v err=%v", root, st, err)
		}
	})
	t.Run("keeps a non-empty legacy directory when rename fails", func(t *testing.T) {
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			t.Skip("needs a directory that the test user cannot modify")
		}
		dir := t.TempDir()
		legacyParent := filepath.Join(dir, "ro-parent")
		legacy := filepath.Join(legacyParent, "volumes")
		root := filepath.Join(dir, "data", "volumes")
		if err := os.MkdirAll(legacy, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(legacy, "keep.ext4"), []byte("data"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(legacyParent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(legacyParent, 0o700) })

		if got := migrateVolumeRoot(legacy, root); got != legacy {
			t.Fatalf("migrateVolumeRoot() = %q, want %q", got, legacy)
		}
		if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("migrateVolumeRoot() created %q while leaving volumes in %q: %v", root, legacy, err)
		}
	})
}

func TestVolumeRootRelativeAndWhitespaceInputs(t *testing.T) {
	isolateUserDirs(t)
	work := t.TempDir()
	t.Chdir(work)

	absWork, err := filepath.Abs(work)
	if err != nil {
		t.Fatalf("filepath.Abs(%q): %v", work, err)
	}

	gotCache, err := (Config{OCICacheDir: "rel-cache"}).volumeRoot()
	if err != nil {
		t.Fatalf("volumeRoot(rel-cache): %v", err)
	}
	wantCache := filepath.Join(absWork, "rel-cache", "volumes")
	if !filepath.IsAbs(gotCache) || gotCache != wantCache {
		t.Fatalf("volumeRoot(rel-cache) = %q, want %q", gotCache, wantCache)
	}

	gotVol, err := (Config{OCICacheDir: "rel-cache", VolumeDir: "rel-vols"}).volumeRoot()
	if err != nil {
		t.Fatalf("volumeRoot(rel-vols): %v", err)
	}
	wantVol := filepath.Join(absWork, "rel-vols")
	if !filepath.IsAbs(gotVol) || gotVol != wantVol {
		t.Fatalf("volumeRoot(rel-vols) = %q, want %q", gotVol, wantVol)
	}

	t.Setenv(VolumeDirEnv, "rel-env-vols")
	gotEnv, err := (Config{VolumeDir: "   ", OCICacheDir: "\t"}).volumeRoot()
	if err != nil {
		t.Fatalf("volumeRoot(whitespace + rel env): %v", err)
	}
	wantEnv := filepath.Join(absWork, "rel-env-vols")
	if !filepath.IsAbs(gotEnv) || gotEnv != wantEnv {
		t.Fatalf("volumeRoot(whitespace + rel env) = %q, want %q", gotEnv, wantEnv)
	}

	t.Setenv(VolumeDirEnv, "  \t ")
	def, err := defaultVolumeDirFor(runtime.GOOS, os.Getenv, os.UserHomeDir)
	if err != nil {
		t.Fatalf("defaultVolumeDirFor: %v", err)
	}
	if gotDef, err := (Config{}).volumeRoot(); err != nil || gotDef != def {
		t.Fatalf("volumeRoot(whitespace env) = (%q, %v), want %q", gotDef, err, def)
	}
}

func TestOpenMountsUsesExplicitVolumeDir(t *testing.T) {
	isolateUserDirs(t)
	canary := t.TempDir()
	t.Setenv(VolumeDirEnv, canary)

	cacheDir := t.TempDir()
	volDir := t.TempDir()

	cfg := Config{
		OCIImage:    "alpine:3.20",
		OCICacheDir: cacheDir,
		VolumeDir:   volDir,
		RootVolume:  "rvol",
		Mounts: []Mount{
			{Kind: MountVolume, VolumeName: "vext4", Driver: DriverExt4lite, GuestPath: "/data"},
			{Kind: MountVolume, VolumeName: "vhost", Driver: DriverHostfs, GuestPath: "/hostvol"},
		},
	}
	if err := NormalizeConfigForTest(&cfg); err != nil {
		t.Fatalf("NormalizeConfigForTest: %v", err)
	}
	sb := NewSandboxForMountTest(cfg)
	if err := OpenMountsForTest(sb); err != nil {
		t.Fatalf("OpenMountsForTest: %v", err)
	}
	t.Cleanup(func() {
		if err := CloseMountsForTest(sb); err != nil {
			t.Errorf("CloseMountsForTest: %v", err)
		}
	})

	for _, want := range []string{
		filepath.Join(volDir, "rvol.ext4"),
		filepath.Join(volDir, "vext4.ext4"),
		filepath.Join(volDir, "vhost"),
	} {
		if _, err := os.Stat(want); err != nil {
			t.Errorf("expected volume artifact %q: %v", want, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(cacheDir, "volumes")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("cacheDir/volumes should not exist when VolumeDir is set: %v", err)
	}
	if entries, err := os.ReadDir(canary); err != nil || len(entries) != 0 {
		t.Errorf("ambient %s directory modified: entries=%v err=%v", VolumeDirEnv, entries, err)
	}
}

func TestVolumeStoreAndSystemInfoVolumeDir(t *testing.T) {
	isolateUserDirs(t)
	canary := t.TempDir()
	t.Setenv(VolumeDirEnv, canary)
	if _, err := CreateVolume("", "canary", DriverExt4lite); err != nil {
		t.Fatalf("CreateVolume(canary): %v", err)
	}

	cacheDir := t.TempDir()
	volDir := t.TempDir()
	store := VolumeStore{OCICacheDir: cacheDir, VolumeDir: volDir}

	if gotDir, err := store.Dir(); err != nil || gotDir != volDir {
		t.Fatalf("store.Dir() = (%q, %v), want %q", gotDir, err, volDir)
	}
	v1, err := store.Create("v1", DriverExt4lite)
	if err != nil {
		t.Fatalf("store.Create(v1): %v", err)
	}
	if filepath.Dir(v1.Mountpoint) != volDir {
		t.Fatalf("v1.Mountpoint = %q, want under %q", v1.Mountpoint, volDir)
	}
	if _, err := store.Create("v2", DriverHostfs); err != nil {
		t.Fatalf("store.Create(v2): %v", err)
	}
	if got, err := store.Inspect("v1"); err != nil || got.Name != "v1" {
		t.Fatalf("store.Inspect(v1) = (%+v, %v)", got, err)
	}
	vols, err := store.List()
	if err != nil || len(vols) != 2 || vols[0].Name != "v1" || vols[1].Name != "v2" {
		t.Fatalf("store.List() = (%+v, %v), want [v1 v2]", vols, err)
	}
	if _, err := store.Compact("v1"); err != nil {
		t.Fatalf("store.Compact(v1): %v", err)
	}
	du, err := store.DiskUsage()
	if err != nil || du.Total != 2 {
		t.Fatalf("store.DiskUsage() = (%+v, %v), want Total=2", du, err)
	}

	si, err := ProbeSystemInfoWithOptions(SystemInfoOptions{
		CacheDir:  cacheDir,
		VolumeDir: volDir,
	})
	if err != nil {
		t.Fatalf("ProbeSystemInfoWithOptions: %v", err)
	}
	if si.VolumeDir != volDir || si.Volumes != 2 {
		t.Fatalf("SystemInfo = (VolumeDir=%q, Volumes=%d), want (%q, 2)", si.VolumeDir, si.Volumes, volDir)
	}

	if err := store.Remove("v2"); err != nil {
		t.Fatalf("store.Remove(v2): %v", err)
	}
	report, err := store.Prune()
	if err != nil {
		t.Fatalf("store.Prune(): %v", err)
	}
	if len(report.Deleted) != 1 || report.Deleted[0] != "v1" {
		t.Fatalf("store.Prune().Deleted = %v, want [v1]", report.Deleted)
	}
	if _, err := InspectVolume("", "canary"); err != nil {
		t.Fatalf("canary volume in %s was affected: %v", VolumeDirEnv, err)
	}
}
