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
	"os"
	"path/filepath"
	"testing"
)

func TestEphemeralVolumeRootPrecedenceAndVolumeListIsolation(t *testing.T) {
	base := t.TempDir()
	cacheDir := filepath.Join(base, "cache")
	volDir := filepath.Join(base, "vols")
	envVolDir := filepath.Join(base, "env-vols")

	t.Setenv(VolumeDirEnv, envVolDir)

	// VolumeDir takes precedence over OCICacheDir (matching volumeRoot so a
	// read-only shared cache can pair with a writable volume store), and its
	// hidden subdirectory must not appear in VolumeStore.List().
	got, err := (Config{OCICacheDir: cacheDir, VolumeDir: "  " + volDir + "  "}).ephemeralVolumeRoot()
	if err != nil {
		t.Fatalf("ephemeralVolumeRoot(VolumeDir) failed: %v", err)
	}
	wantVolEph := filepath.Join(volDir, "."+ephemeralVolumesDirName)
	if got != wantVolEph {
		t.Errorf("ephemeralVolumeRoot(VolumeDir) = %q, want %q", got, wantVolEph)
	}
	if err := os.MkdirAll(got, 0o700); err != nil {
		t.Fatalf("MkdirAll(%q) failed: %v", got, err)
	}
	vols, err := (VolumeStore{VolumeDir: volDir}).List()
	if err != nil {
		t.Fatalf("VolumeStore.List() failed: %v", err)
	}
	if len(vols) != 0 {
		t.Errorf("VolumeStore.List() = %+v, want empty (hidden ephemeral directory must not be listed)", vols)
	}

	// OCICacheDir is used when VolumeDir is blank and ignores surrounding whitespace.
	got, err = (Config{OCICacheDir: "  " + cacheDir + "  ", VolumeDir: "   "}).ephemeralVolumeRoot()
	if err != nil {
		t.Fatalf("ephemeralVolumeRoot(OCICacheDir) failed: %v", err)
	}
	if want := filepath.Join(cacheDir, ephemeralVolumesDirName); got != want {
		t.Errorf("ephemeralVolumeRoot(OCICacheDir) = %q, want %q", got, want)
	}

	// GVX_VOLUME_DIR is used when both VolumeDir and OCICacheDir are blank.
	got, err = (Config{}).ephemeralVolumeRoot()
	if err != nil {
		t.Fatalf("ephemeralVolumeRoot(env) failed: %v", err)
	}
	if want := filepath.Join(envVolDir, "."+ephemeralVolumesDirName); got != want {
		t.Errorf("ephemeralVolumeRoot(env) = %q, want %q", got, want)
	}
}
