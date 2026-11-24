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

package gpurender

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeExecFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestLocateSearchOrder(t *testing.T) {
	root := t.TempDir()
	exePath := filepath.Join(root, "usr", "bin", "rungv")
	explicitPath := filepath.Join(root, "explicit", "gvx-gpu-renderer")
	envPath := filepath.Join(root, "env", "gvx-gpu-renderer")
	siblingPath := filepath.Join(root, "usr", "bin", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")
	libexecPath := filepath.Join(root, "usr", "libexec", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")

	tests := []struct {
		name     string
		create   []string
		explicit string
		env      string
		want     string
	}{
		{
			name:     "explicit wins over env and bundles",
			create:   []string{explicitPath, envPath, siblingPath, libexecPath},
			explicit: explicitPath,
			env:      envPath,
			want:     explicitPath,
		},
		{
			name:   "env wins over bundles",
			create: []string{envPath, siblingPath, libexecPath},
			env:    envPath,
			want:   envPath,
		},
		{
			name:   "sibling bundle wins over libexec bundle",
			create: []string{siblingPath, libexecPath},
			want:   siblingPath,
		},
		{
			name:   "libexec bundle found alone",
			create: []string{libexecPath},
			want:   libexecPath,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			caseRoot := t.TempDir()
			remap := func(p string) string {
				if p == "" {
					return ""
				}
				rel, err := filepath.Rel(root, p)
				if err != nil {
					t.Fatalf("rel %s: %v", p, err)
				}
				return filepath.Join(caseRoot, rel)
			}
			for _, p := range tc.create {
				writeExecFile(t, remap(p))
			}

			got, _, err := locate(remap(tc.explicit), remap(tc.env), remap(exePath), isRegularExecutable)
			if err != nil {
				t.Fatalf("locate() error = %v, want %s", err, remap(tc.want))
			}
			if want := remap(tc.want); got != want {
				t.Fatalf("locate() = %q, want %q", got, want)
			}
		})
	}
}

func TestLocateNamesSearchedPaths(t *testing.T) {
	root := t.TempDir()
	exePath := filepath.Join(root, "usr", "bin", "rungv")

	t.Run("missing explicit searches only explicit", func(t *testing.T) {
		missing := filepath.Join(root, "absent-explicit")
		_, searched, err := locate(missing, filepath.Join(root, "ignored-env"), exePath, isRegularExecutable)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("locate() error = %v, want ErrNotFound", err)
		}
		if len(searched) != 1 || searched[0] != missing {
			t.Fatalf("searched = %v, want [%s]", searched, missing)
		}
		if !strings.Contains(err.Error(), missing) {
			t.Fatalf("error %q does not name %q", err.Error(), missing)
		}
	})

	t.Run("missing env does not fall through to bundles", func(t *testing.T) {
		caseRoot := t.TempDir()
		caseExe := filepath.Join(caseRoot, "usr", "bin", "rungv")
		siblingPath := filepath.Join(caseRoot, "usr", "bin", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")
		writeExecFile(t, siblingPath)
		missingEnv := filepath.Join(caseRoot, "absent-env-renderer")

		_, searched, err := locate("", missingEnv, caseExe, isRegularExecutable)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("locate() error = %v, want ErrNotFound", err)
		}
		if len(searched) != 1 || searched[0] != missingEnv {
			t.Fatalf("searched = %v, want [%s]", searched, missingEnv)
		}
		if !strings.Contains(err.Error(), missingEnv) {
			t.Fatalf("error %q does not name %q", err.Error(), missingEnv)
		}
	})

	t.Run("relative explicit and env paths resolve to absolute", func(t *testing.T) {
		caseRoot := t.TempDir()
		rel := filepath.Join("rel", "gvx-gpu-renderer")
		absTarget := filepath.Join(caseRoot, rel)
		writeExecFile(t, absTarget)
		t.Chdir(caseRoot)

		wantAbs, err := filepath.Abs(rel)
		if err != nil {
			t.Fatalf("Abs(%q): %v", rel, err)
		}

		gotExplicit, _, err := locate(rel, "", exePath, isRegularExecutable)
		if err != nil {
			t.Fatalf("locate(explicit=%q): %v", rel, err)
		}
		if !filepath.IsAbs(gotExplicit) || gotExplicit != wantAbs {
			t.Fatalf("locate(explicit=%q) = %q, want %q", rel, gotExplicit, wantAbs)
		}

		gotEnv, _, err := locate("", rel, exePath, isRegularExecutable)
		if err != nil {
			t.Fatalf("locate(env=%q): %v", rel, err)
		}
		if !filepath.IsAbs(gotEnv) || gotEnv != wantAbs {
			t.Fatalf("locate(env=%q) = %q, want %q", rel, gotEnv, wantAbs)
		}
	})

	t.Run("nothing set searches two executable-relative paths", func(t *testing.T) {
		want1 := filepath.Join(root, "usr", "bin", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")
		want2 := filepath.Join(root, "usr", "libexec", "gvx-gpu-renderer", "bin", "gvx-gpu-renderer")
		_, searched, err := locate("", "", exePath, isRegularExecutable)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("locate() error = %v, want ErrNotFound", err)
		}
		if len(searched) != 2 || searched[0] != want1 || searched[1] != want2 {
			t.Fatalf("searched = %v, want [%s %s]", searched, want1, want2)
		}
		if !strings.Contains(err.Error(), want1) || !strings.Contains(err.Error(), want2) {
			t.Fatalf("error %q does not name both %q and %q", err.Error(), want1, want2)
		}
	})

	t.Run("directory at searched path is not a match", func(t *testing.T) {
		dirPath := filepath.Join(root, "dir-not-file")
		if err := os.MkdirAll(dirPath, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dirPath, err)
		}
		_, searched, err := locate(dirPath, "", exePath, isRegularExecutable)
		if !errors.Is(err, ErrNotFound) {
			t.Fatalf("locate(dir) error = %v, want ErrNotFound", err)
		}
		if len(searched) != 1 || searched[0] != dirPath {
			t.Fatalf("searched = %v, want [%s]", searched, dirPath)
		}
	})

	if runtime.GOOS != "windows" {
		t.Run("non-executable regular file is not a match", func(t *testing.T) {
			plain := filepath.Join(root, "plain-file")
			if err := os.WriteFile(plain, []byte("data"), 0o644); err != nil {
				t.Fatalf("write %s: %v", plain, err)
			}
			_, _, err := locate(plain, "", exePath, isRegularExecutable)
			if !errors.Is(err, ErrNotFound) {
				t.Fatalf("locate(non-exec) error = %v, want ErrNotFound", err)
			}
		})
	}
}
