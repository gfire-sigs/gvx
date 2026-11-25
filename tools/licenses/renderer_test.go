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

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func seedRendererTree(t *testing.T) string {
	t.Helper()
	repoRoot := filepath.Join("..", "..")
	root := t.TempDir()
	for _, rel := range []string{
		rendererLockRelPath,
		rendererComponentsRelPath,
		rendererVenusRelPath,
	} {
		src := filepath.Join(repoRoot, filepath.FromSlash(rel))
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatalf("read %s: %v", src, err)
		}
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}
	return root
}

func TestCheckRenderer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mutate  func(t *testing.T, root string)
		wantErr string
	}{
		{
			name:   "current inputs pass",
			mutate: func(t *testing.T, root string) {},
		},
		{
			name: "CRLF manifest and lock pass",
			mutate: func(t *testing.T, root string) {
				for _, rel := range []string{rendererComponentsRelPath, rendererLockRelPath} {
					p := filepath.Join(root, filepath.FromSlash(rel))
					data, err := os.ReadFile(p)
					if err != nil {
						t.Fatalf("read %s: %v", rel, err)
					}
					crlf := strings.ReplaceAll(lfOnly(string(data)), "\n", "\r\n")
					if err := os.WriteFile(p, []byte(crlf), 0o644); err != nil {
						t.Fatalf("write %s: %v", rel, err)
					}
				}
			},
		},
		{
			name: "missing libepoxy line fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				const target = "libepoxy|MIT|libepoxy.txt|pinned,mesa-source\n"
				normalized := lfOnly(string(data))
				updated := strings.Replace(normalized, target, "", 1)
				if updated == normalized {
					t.Fatal("failed to remove libepoxy line")
				}
				if err := os.WriteFile(p, []byte(updated), 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `missing component "libepoxy"`,
		},
		{
			name: "new bottle formula without manifest line fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererLockRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read lock: %v", err)
				}
				data = append(data, []byte("\nBOTTLE.foo.version=1.2.3\n")...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
			wantErr: `missing component "foo"`,
		},
		{
			name: "manifest line for formula absent from lock fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				data = append(data, []byte("\norphan-lib|MIT|orphan-lib.txt|pinned\n")...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `unexpected component "orphan-lib"`,
		},
		{
			name: "bad SPDX expression fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				updated := strings.Replace(string(data), "virglrenderer|MIT|", "virglrenderer|MIT AND (|", 1)
				if updated == string(data) {
					t.Fatal("failed to replace virglrenderer SPDX line")
				}
				if err := os.WriteFile(p, []byte(updated), 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `invalid SPDX expression`,
		},
		{
			name: "missing venus-protocol.txt fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererVenusRelPath))
				if err := os.Remove(p); err != nil {
					t.Fatalf("remove venus-protocol.txt: %v", err)
				}
			},
			wantErr: rendererVenusRelPath,
		},
		{
			name: "empty venus-protocol.txt fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererVenusRelPath))
				if err := os.WriteFile(p, nil, 0o644); err != nil {
					t.Fatalf("truncate venus-protocol.txt: %v", err)
				}
			},
			wantErr: `must be a non-empty regular file`,
		},
		{
			name: "duplicate component fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				data = append(data, []byte("\nvirglrenderer|MIT|virglrenderer.txt|pinned\n")...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `duplicate component "virglrenderer"`,
		},
		{
			name: "unknown bundle kind fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				updated := strings.Replace(string(data), "virglrenderer|MIT|virglrenderer.txt|pinned,mesa-source", "virglrenderer|MIT|virglrenderer.txt|homebrew", 1)
				if err := os.WriteFile(p, []byte(updated), 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `unknown bundle kind "homebrew"`,
		},
		{
			name: "mismatched license file name fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererComponentsRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read manifest: %v", err)
				}
				updated := strings.Replace(string(data), "virglrenderer|MIT|virglrenderer.txt|", "virglrenderer|MIT|INDEX.txt|", 1)
				if updated == string(data) {
					t.Fatal("failed to replace virglrenderer license file")
				}
				if err := os.WriteFile(p, []byte(updated), 0o644); err != nil {
					t.Fatalf("write manifest: %v", err)
				}
			},
			wantErr: `want "virglrenderer.txt"`,
		},
		{
			name: "malformed bottle lock key fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererLockRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read lock: %v", err)
				}
				data = append(data, []byte("\nBOTTLE.badkey=1\n")...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
			wantErr: `malformed BOTTLE key`,
		},
		{
			name: "malformed toolchain lock key fails",
			mutate: func(t *testing.T, root string) {
				p := filepath.Join(root, filepath.FromSlash(rendererLockRelPath))
				data, err := os.ReadFile(p)
				if err != nil {
					t.Fatalf("read lock: %v", err)
				}
				data = append(data, []byte("\nTOOLCHAIN.badkey=1\n")...)
				if err := os.WriteFile(p, data, 0o644); err != nil {
					t.Fatalf("write lock: %v", err)
				}
			},
			wantErr: `malformed TOOLCHAIN key`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := seedRendererTree(t)
			tc.mutate(t, root)
			err := checkRenderer(root)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("checkRenderer() = %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("checkRenderer() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("checkRenderer() = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestParseSPDXExpression(t *testing.T) {
	for _, tc := range []struct {
		expr    string
		wantErr bool
	}{
		{expr: "MIT"},
		{expr: "Apache-2.0"},
		{expr: "GPL-2.0+"},
		{expr: "MIT AND (Apache-2.0 OR MIT)"},
		{expr: "GPL-2.0-only WITH Linux-syscall-note"},
		{expr: "LicenseRef-Homebrew-public-domain"},
		{expr: "DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2"},
		{expr: "MIT AND (GPL-1.0-or-later WITH Linux-syscall-note)"},
		{expr: "", wantErr: true},
		{expr: "   ", wantErr: true},
		{expr: "MIT AND", wantErr: true},
		{expr: "AND MIT", wantErr: true},
		{expr: "MIT OR OR Apache-2.0", wantErr: true},
		{expr: "(MIT", wantErr: true},
		{expr: "MIT)", wantErr: true},
		{expr: "()", wantErr: true},
		{expr: "MIT Apache-2.0", wantErr: true},
		{expr: "MIT / Apache-2.0", wantErr: true},
		{expr: "(MIT OR Apache-2.0) WITH Linux-syscall-note", wantErr: true},
		{expr: "MIT WITH", wantErr: true},
		{expr: "MIT WITH LicenseRef-foo", wantErr: true},
		{expr: "LicenseRef-", wantErr: true},
		{expr: "LicenseRef-foo+", wantErr: true},
		{expr: "NOASSERTION", wantErr: true},
		{expr: "NONE", wantErr: true},
	} {
		t.Run(tc.expr, func(t *testing.T) {
			err := parseSPDXExpression(tc.expr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseSPDXExpression(%q) error = %v, wantErr = %v", tc.expr, err, tc.wantErr)
			}
		})
	}
}

func TestRepoSourceFilesSkipsBuildAndGPURenderer(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"build/gpu/cache/virglrenderer/vkr.c",
		"build/gpu/cache/venus-protocol/vk.h",
		"ext/workers/gpu-renderer/src/main.c",
		"ext/workers/gpu-renderer/gvx_gpu_protocol.h",
		"internal/xsys/unix/syscall.go",
		"third_party/vendored/lib.go",
		".hidden/ignored.go",
		"pkg/gvx/sandbox.go",
		"cmd/rungv/main.go",
	} {
		dst := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(dst), err)
		}
		if err := os.WriteFile(dst, []byte("// synthetic\n"), 0o644); err != nil {
			t.Fatalf("write %s: %v", dst, err)
		}
	}

	files, err := repoSourceFiles(root)
	if err != nil {
		t.Fatalf("repoSourceFiles() error: %v", err)
	}
	var got []string
	for _, f := range files {
		got = append(got, f.label)
	}
	want := []string{"cmd/rungv/main.go", "pkg/gvx/sandbox.go"}
	if !slices.Equal(got, want) {
		t.Fatalf("repoSourceFiles() = %v, want %v", got, want)
	}
}
