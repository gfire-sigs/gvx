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
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
)

func TestReadAndParseManifestRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, checkpointManifestFileName)

	// A valid JSON document padded with spaces past the limit.
	big := append([]byte(`{"version":1}`), bytes.Repeat([]byte(" "), maxManifestBytes)...)
	if err := os.WriteFile(path, big, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readAndParseManifest(dir)
	if !errors.Is(err, ErrCheckpointManifest) || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("readAndParseManifest(%d bytes) = %v, want ErrCheckpointManifest with a size error", len(big), err)
	}

	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := readAndParseManifest(dir)
	if err != nil || m.Version != 1 {
		t.Fatalf("readAndParseManifest(small) = (%+v, %v), want version 1", m, err)
	}
}

func TestReadAndParseManifestRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, checkpointManifestFileName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := readAndParseManifest(dir); !errors.Is(err, ErrCheckpointManifest) {
		t.Fatalf("readAndParseManifest(directory) = %v, want ErrCheckpointManifest", err)
	}
}

func TestRestoreFileLimit(t *testing.T) {
	const gib = 1 << 30
	var tun tuning.Values
	for _, tc := range []struct {
		name       string
		configured int64
		hostRAM    uint64
		want       uint64
	}{
		{"configured limit wins", 4 * gib, 64 * gib, 9 * gib},
		{"host RAM without a limit", 0, 16 * gib, 33 * gib},
		{"nothing known", 0, 0, 0},
	} {
		if got := restoreFileLimit(tc.configured, tc.hostRAM, tun); got != tc.want {
			t.Errorf("%s: restoreFileLimit(%d, %d) = %d, want %d", tc.name, tc.configured, tc.hostRAM, got, tc.want)
		}
	}
}
