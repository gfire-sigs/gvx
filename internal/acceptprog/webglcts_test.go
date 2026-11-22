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

package acceptprog

import (
	"archive/tar"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractTarGzSubtreeSkipsOutsideMembersAndLinks(t *testing.T) {
	archive := writeTestTarGz(t,
		archiveMember{name: "repo/README.md", mode: 0o644, body: "readme"},
		archiveMember{name: "repo/specs/1.0", typeflag: tar.TypeSymlink, linkname: "latest/1.0"},
		archiveMember{name: "repo/specs/hard", typeflag: tar.TypeLink, linkname: "repo/README.md"},
		archiveMember{name: "repo/sdk/tests", mode: 0o755, typeflag: tar.TypeDir},
		archiveMember{name: "repo/sdk/tests/00_test_list.txt", mode: 0o644, body: "a.html\n"},
		archiveMember{name: "repo/sdk/tests/sub/a.html", mode: 0o644, body: "<html/>"},
		archiveMember{name: "repo/sdk/tests-extra/b.html", mode: 0o644, body: "outside"},
	)
	dst := t.TempDir()
	limits := subtreeLimits{
		maxScanned:    16,
		extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
	}
	if err := extractTarGzSubtree(archive, dst, "repo/sdk/tests", limits); err != nil {
		t.Fatalf("extractTarGzSubtree() = %v, want nil", err)
	}
	requireFile(t, filepath.Join(dst, "00_test_list.txt"), "a.html\n", false)
	requireFile(t, filepath.Join(dst, "sub", "a.html"), "<html/>", false)
	for _, absent := range []string{"README.md", "specs", "tests-extra"} {
		if _, err := os.Lstat(filepath.Join(dst, absent)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("outside path %s exists (stat err: %v)", absent, err)
		}
	}
}

func TestExtractTarGzSubtreeRefusesInsideLinks(t *testing.T) {
	cases := []struct {
		name   string
		member archiveMember
	}{
		{name: "symlink", member: archiveMember{name: "repo/sdk/tests/link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
		{name: "hardlink", member: archiveMember{name: "repo/sdk/tests/hard", typeflag: tar.TypeLink, linkname: "repo/sdk/tests/a.html"}},
		{name: "char_device", member: archiveMember{name: "repo/sdk/tests/null", mode: 0o666, typeflag: tar.TypeChar}},
	}
	limits := subtreeLimits{
		maxScanned:    16,
		extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			archive := writeTestTarGz(t,
				archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: "ok"},
				tc.member,
			)
			dst := t.TempDir()
			if err := extractTarGzSubtree(archive, dst, "repo/sdk/tests", limits); err == nil {
				t.Fatalf("extractTarGzSubtree() of %s = nil, want an error", tc.name)
			}
		})
	}
}

func TestExtractTarGzSubtreeRefusesUnsafeOutsidePath(t *testing.T) {
	limits := subtreeLimits{
		maxScanned:    16,
		extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
	}
	for _, bad := range []string{"../escape", "/abs/outside", `outside\backslash`} {
		t.Run(bad, func(t *testing.T) {
			archive := writeTestTarGz(t,
				archiveMember{name: bad, mode: 0o644, body: "x"},
				archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: "ok"},
			)
			if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); err == nil {
				t.Fatalf("extractTarGzSubtree() with outside member %q = nil, want an error", bad)
			}
		})
	}
}

func TestExtractTarGzSubtreeEnforcesScannedAndKeptLimits(t *testing.T) {
	t.Run("scanned_limit", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "outside/1", mode: 0o644, body: "a"},
			archiveMember{name: "outside/2", mode: 0o644, body: "b"},
			archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: "c"},
		)
		limits := subtreeLimits{
			maxScanned:    2,
			extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
		}
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errTooManyMembers) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errTooManyMembers)
		}
	})

	t.Run("kept_limit", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "outside/1", mode: 0o644, body: "a"},
			archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: "b"},
			archiveMember{name: "repo/sdk/tests/b.html", mode: 0o644, body: "c"},
		)
		limits := subtreeLimits{
			maxScanned:    16,
			extractLimits: extractLimits{maxMembers: 1, maxMemberBytes: 1024, maxTotalBytes: 4096},
		}
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errTooManyMembers) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errTooManyMembers)
		}
	})
}

func TestExtractTarGzSubtreeEnforcesByteLimits(t *testing.T) {
	t.Run("single_member", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "outside/big", mode: 0o644, body: strings.Repeat("z", 100)},
			archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: strings.Repeat("a", 9)},
		)
		limits := subtreeLimits{
			maxScanned:    16,
			extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 8, maxTotalBytes: 1024},
		}
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errExtractedTooLarge) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errExtractedTooLarge)
		}
	})

	t.Run("total_bytes", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "outside/big", mode: 0o644, body: strings.Repeat("z", 100)},
			archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: strings.Repeat("a", 8)},
			archiveMember{name: "repo/sdk/tests/b.html", mode: 0o644, body: strings.Repeat("b", 8)},
		)
		limits := subtreeLimits{
			maxScanned:    16,
			extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 10, maxTotalBytes: 12},
		}
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errExtractedTooLarge) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errExtractedTooLarge)
		}
	})

	t.Run("decompressed_limit", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "outside/bomb", mode: 0o644, body: strings.Repeat("z", 8192)},
			archiveMember{name: "repo/sdk/tests/a.html", mode: 0o644, body: "ok"},
		)
		limits := subtreeLimits{
			maxScanned:           16,
			maxDecompressedBytes: 2048,
			extractLimits:        extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
		}
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errExtractedTooLarge) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errExtractedTooLarge)
		}
	})
}

func TestExtractTarGzSubtreeRejectsEmptySubtree(t *testing.T) {
	limits := subtreeLimits{
		maxScanned:    16,
		extractLimits: extractLimits{maxMembers: 8, maxMemberBytes: 1024, maxTotalBytes: 4096},
	}
	t.Run("no_matching_member", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "repo/README.md", mode: 0o644, body: "readme"},
		)
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errEmptySubtree) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errEmptySubtree)
		}
	})
	t.Run("only_strip_root_dir", func(t *testing.T) {
		archive := writeTestTarGz(t,
			archiveMember{name: "repo/sdk/tests", mode: 0o755, typeflag: tar.TypeDir},
		)
		if err := extractTarGzSubtree(archive, t.TempDir(), "repo/sdk/tests", limits); !errors.Is(err, errEmptySubtree) {
			t.Fatalf("extractTarGzSubtree() = %v, want %v", err, errEmptySubtree)
		}
	})
}

func TestWebGLCTSArchiveStripMatchesCommit(t *testing.T) {
	want := "WebGL-" + WebGLCTSCommit + "/sdk/tests"
	if webglCTSArchive.strip != want {
		t.Fatalf("webglCTSArchive.strip = %q, want %q", webglCTSArchive.strip, want)
	}
}
