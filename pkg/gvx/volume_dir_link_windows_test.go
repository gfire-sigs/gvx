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

//go:build windows

package gvx

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCreateDirectoryJunctionAllowsUnprivilegedReadAndSafeRemoval(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "volumes")
	link := filepath.Join(base, "cache", "volumes")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "data.ext4"), []byte("persisted"), 0o600); err != nil {
		t.Fatal(err)
	}

	buf, err := buildMountPointReparseData(target)
	if err != nil {
		t.Fatalf("buildMountPointReparseData(%q): %v", target, err)
	}
	if got := binary.LittleEndian.Uint32(buf[0:4]); got != windows.IO_REPARSE_TAG_MOUNT_POINT {
		t.Fatalf("ReparseTag = %#x, want %#x", got, uint32(windows.IO_REPARSE_TAG_MOUNT_POINT))
	}
	if got := int(binary.LittleEndian.Uint16(buf[4:6])); got != len(buf)-8 {
		t.Fatalf("ReparseDataLength = %d, want %d", got, len(buf)-8)
	}

	if err := createDirectoryJunction(link, target); err != nil {
		t.Fatalf("createDirectoryJunction(%q, %q): %v", link, target, err)
	}
	// Publishing onto an existing path must fail cleanly without leaving temp dirs.
	if err := createDirectoryJunction(link, target); err == nil {
		t.Fatalf("second createDirectoryJunction(%q, %q) succeeded, want error", link, target)
	}
	if entries, err := os.ReadDir(filepath.Dir(link)); err != nil || len(entries) != 1 || entries[0].Name() != "volumes" {
		t.Fatalf("cache dir entries after collision = (%v, %v), want only [volumes]", entries, err)
	}

	for _, unc := range []string{`\\server\share\volumes`, `\\?\UNC\server\share\volumes`, `\\?\unc\server\share\volumes`} {
		if _, err := buildMountPointReparseData(unc); err == nil {
			t.Errorf("buildMountPointReparseData(%q) succeeded, want error for UNC target", unc)
		}
	}

	got, err := os.ReadFile(filepath.Join(link, "data.ext4"))
	if err != nil || string(got) != "persisted" {
		t.Fatalf("ReadFile via junction = (%q, %v), want %q", got, err, "persisted")
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatalf("Lstat(%q): %v", link, err)
	}
	if st.IsDir() || !isLegacyVolumeLink(st) {
		t.Fatalf("Lstat(junction) mode = %v, want non-dir link/reparse point", st.Mode())
	}

	// Removing the cache parent directory must remove the junction without
	// deleting files in the migrated target directory.
	if err := os.RemoveAll(filepath.Dir(link)); err != nil {
		t.Fatalf("RemoveAll(cache): %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(target, "data.ext4")); err != nil || string(got) != "persisted" {
		t.Fatalf("target file after removing junction parent = (%q, %v), want %q", got, err, "persisted")
	}
}
