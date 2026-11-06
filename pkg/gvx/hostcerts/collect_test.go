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

package hostcerts

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestCollectReadsTheSystemRoots(t *testing.T) {
	roots, err := Collect(context.Background(), nil)
	if err != nil {
		t.Fatalf("Collect on %s: %v", runtime.GOOS, err)
	}
	if len(roots) < 5 {
		t.Fatalf("Collect returned %d roots, want the system roots of the host", len(roots))
	}
	for i, der := range roots {
		if !validDER(der) {
			t.Fatalf("root %d is not a certificate", i)
		}
	}
	if got := dedupe(roots); len(got) != len(roots) {
		t.Errorf("Collect returned %d roots and %d distinct roots", len(roots), len(got))
	}
}

// TestCollectAddsTheRootOfSSLCertFile is the hook of the end-to-end tests: a
// test CA that SSL_CERT_FILE names must reach the guest on every host OS.
func TestCollectAddsTheRootOfSSLCertFile(t *testing.T) {
	testRoot := makeRoot(t, "test CA")
	file := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(file, pemOf(testRoot), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", file)

	roots, err := Collect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(roots, func(der []byte) bool { return bytes.Equal(der, testRoot) }) {
		t.Errorf("Collect did not return the root of SSL_CERT_FILE among %d roots", len(roots))
	}
}

func TestCollectWarnsAboutAFailedSourceAndKeepsTheOthers(t *testing.T) {
	t.Setenv("SSL_CERT_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	var warnings strings.Builder
	roots, err := Collect(context.Background(), &warnings)
	if runtime.GOOS == "linux" {
		// An explicit file that is missing does not stop Go from reading the
		// system directories; a minimal container has none.
		if err != nil {
			t.Skipf("the host has no certificate directory: %v", err)
		}
	} else if err != nil {
		t.Fatal(err)
	}
	if len(roots) == 0 || !strings.Contains(warnings.String(), "missing.pem") {
		t.Errorf("Collect = %d roots, warnings %q; want roots and a warning that names the file", len(roots), warnings.String())
	}
}

func TestCollectFailsWhenNoSourceHasACertificate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("macOS and Windows always have system roots")
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "empty.pem")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", file)
	t.Setenv("SSL_CERT_DIR", dir)
	if _, err := Collect(context.Background(), nil); err == nil {
		t.Fatal("Collect returned no error although no source has a certificate")
	}
}
