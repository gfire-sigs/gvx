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
	"testing"
)

// symlinkOrSkip creates a symbolic link. Windows needs a privilege for that,
// so the test skips when the host refuses.
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("the host cannot create a symbolic link: %v", err)
	}
}

// TestCheckpointBundleRefusesLinkOnSave proves that a checkpoint does not
// write through a symbolic link that waits in the bundle directory.
func TestCheckpointBundleRefusesLinkOnSave(t *testing.T) {
	for _, name := range []string{checkpointManifestFileName, checkpointStateFileName, checkpointPagesMetaFileName, checkpointPagesFileName} {
		t.Run(name, func(t *testing.T) {
			victim := filepath.Join(t.TempDir(), "victim")
			if err := os.WriteFile(victim, []byte("host-data"), 0o600); err != nil {
				t.Fatalf("WriteFile: %v", err)
			}
			dir := t.TempDir()
			symlinkOrSkip(t, victim, filepath.Join(dir, name))

			files, err := openCheckpointBundleFiles(dir, nil)
			if err == nil {
				// The save path truncates each file before it writes.
				_ = files.rewindAndTruncate()
				_ = files.Close()
				t.Errorf("openCheckpointBundleFiles opened the link %s", name)
			}
			got, rErr := os.ReadFile(victim)
			if rErr != nil || string(got) != "host-data" {
				t.Errorf("file behind the link = %q, %v, want it unchanged", got, rErr)
			}
		})
	}
}

// TestCheckpointBundleOpensRegularFiles proves that a bundle directory with
// regular files, or with no files, still opens.
func TestCheckpointBundleOpensRegularFiles(t *testing.T) {
	dir := t.TempDir()
	for range 2 {
		files, err := openCheckpointBundleFiles(dir, nil)
		if err != nil {
			t.Fatalf("openCheckpointBundleFiles: %v", err)
		}
		if err := files.rewindAndTruncate(); err != nil {
			t.Fatalf("rewindAndTruncate: %v", err)
		}
		if err := files.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// TestRestoreRefusesLinkedBundleFiles proves that Restore reads no bundle
// file through a symbolic link.
func TestRestoreRefusesLinkedBundleFiles(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "outside.json")
	if err := os.WriteFile(outside, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	t.Run("manifest", func(t *testing.T) {
		dir := t.TempDir()
		symlinkOrSkip(t, outside, filepath.Join(dir, checkpointManifestFileName))
		if _, err := readAndParseManifest(dir); !errors.Is(err, ErrCheckpointManifest) {
			t.Fatalf("readAndParseManifest through a link = %v, want ErrCheckpointManifest", err)
		}
	})
	t.Run("regular manifest", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, checkpointManifestFileName), []byte(`{"version":1}`), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		if _, err := readAndParseManifest(dir); err != nil {
			t.Fatalf("readAndParseManifest of a regular file: %v", err)
		}
	})
	t.Run("state", func(t *testing.T) {
		dir := t.TempDir()
		symlinkOrSkip(t, outside, filepath.Join(dir, checkpointStateFileName))
		f, err := openTestBundleFile(t, dir, checkpointStateFileName)
		if err == nil {
			_ = f.Close()
			t.Fatal("openBundleFile opened a link")
		}
	})
	t.Run("link inside the bundle", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "other"), []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		symlinkOrSkip(t, "other", filepath.Join(dir, checkpointStateFileName))
		f, err := openTestBundleFile(t, dir, checkpointStateFileName)
		if err == nil {
			_ = f.Close()
			t.Fatal("openBundleFile opened a link to a file in the bundle")
		}
	})
}

func readAndParseManifest(dir string) (CheckpointManifest, error) {
	b, err := openBundleRoot(dir, false)
	if err != nil {
		return CheckpointManifest{}, errors.Join(ErrCheckpointManifest, err)
	}
	defer b.Close()
	return b.readAndParseManifest()
}

func openTestBundleFile(t *testing.T, dir, name string) (*os.File, error) {
	t.Helper()
	b, err := openBundleRoot(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	return b.openFile(name, os.O_RDONLY, 0)
}
