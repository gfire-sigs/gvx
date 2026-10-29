package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestReadUpstreamArchiveSkipsHeadersAndKeepsRegularFiles(t *testing.T) {
	t.Parallel()

	tree, err := ReadUpstreamArchive(bytes.NewReader(buildTestTarGz(t, map[string]string{
		"pkg/a.go":    "package a\n",
		"go.mod":      "module gvisor.dev/gvisor\n",
		"empty/.keep": "",
	})), testSHA)
	if err != nil {
		t.Fatalf("ReadUpstreamArchive: %v", err)
	}
	if len(tree.Files) != 3 || string(tree.Files["pkg/a.go"]) != "package a\n" {
		t.Fatalf("unexpected tree: %v", tree.Files)
	}
	if got, ok := tree.pristine("pkg/a.go"); !ok || string(got) != "package a\n" {
		t.Fatalf("pristine(pkg/a.go) = %q, %v", got, ok)
	}
	if got, _ := tree.pristine("go.mod"); !strings.Contains(string(got), "gvisor.dev/gvisor") {
		t.Fatalf("go.mod must keep the upstream module path, got %q", got)
	}
	if _, ok := tree.pristine("missing.go"); ok {
		t.Fatal("pristine reported a missing file")
	}
}

func TestReadUpstreamArchiveRewritesModulePathInPristine(t *testing.T) {
	t.Parallel()

	tree, err := ReadUpstreamArchive(bytes.NewReader(buildTestTarGz(t, map[string]string{
		"pkg/a.go": "package a\n\nimport _ \"gvisor.dev/gvisor/pkg/b\"\n",
	})), testSHA)
	if err != nil {
		t.Fatalf("ReadUpstreamArchive: %v", err)
	}
	got, _ := tree.pristine("pkg/a.go")
	if !strings.Contains(string(got), `"z.gfire.dev/gvx/pkg/b"`) {
		t.Fatalf("pristine = %q", got)
	}
}

func TestReadUpstreamArchiveRejectsWrongCommitAndBadInput(t *testing.T) {
	t.Parallel()

	other := strings.Repeat("b", 40)
	if _, err := ReadUpstreamArchive(bytes.NewReader(buildTestTarGzSHA(t, other, map[string]string{"a.go": "package a\n"})), testSHA); !errors.Is(err, errArchiveCommit) {
		t.Fatalf("wrong root err = %v, want %v", err, errArchiveCommit)
	}
	if _, err := ReadUpstreamArchive(strings.NewReader("not gzip"), testSHA); err == nil {
		t.Fatal("non-gzip input must fail")
	}
	if _, err := ReadUpstreamArchive(bytes.NewReader(buildTestTarGz(t, nil)), testSHA); !errors.Is(err, errArchiveEmpty) {
		t.Fatalf("empty archive err = %v, want %v", err, errArchiveEmpty)
	}
	if _, err := ReadUpstreamArchive(bytes.NewReader(buildTestTarGz(t, map[string]string{"../escape.go": "package a\n"})), testSHA); !errors.Is(err, errUnsafeArchivePath) {
		t.Fatalf("traversal err = %v, want %v", err, errUnsafeArchivePath)
	}
}

func TestArchiveSourceLoadOrder(t *testing.T) {
	t.Parallel()

	files := map[string]string{"pkg/a.go": "package a\n"}
	body := buildTestTarGz(t, files)

	t.Run("explicit archive path wins over cache", func(t *testing.T) {
		t.Parallel()
		cache := t.TempDir()
		if err := os.WriteFile(filepath.Join(cache, testSHA+".tar.gz"), buildTestTarGz(t, map[string]string{"pkg/cached.go": "package c\n"}), 0o644); err != nil {
			t.Fatal(err)
		}
		explicit := writeArchiveFile(t, files)
		tree, err := ArchiveSource{ArchivePath: explicit, CacheDir: cache, Offline: true}.Load(context.Background(), testSHA)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if _, ok := tree.Files["pkg/a.go"]; !ok || len(tree.Files) != 1 {
			t.Fatalf("explicit archive ignored: %v", tree.Files)
		}
	})

	t.Run("cache hit needs no network", func(t *testing.T) {
		t.Parallel()
		cache := t.TempDir()
		if err := os.WriteFile(filepath.Join(cache, testSHA+".tar.gz"), body, 0o644); err != nil {
			t.Fatal(err)
		}
		tree, err := ArchiveSource{CacheDir: cache, Offline: true}.Load(context.Background(), testSHA)
		if err != nil || len(tree.Files) != 1 {
			t.Fatalf("Load = %v, %v", tree, err)
		}
	})

	t.Run("offline miss fails with an actionable error", func(t *testing.T) {
		t.Parallel()
		cache := t.TempDir()
		_, err := ArchiveSource{CacheDir: cache, Offline: true}.Load(context.Background(), testSHA)
		if !errors.Is(err, errArchiveMissing) {
			t.Fatalf("Load err = %v, want %v", err, errArchiveMissing)
		}
		if !strings.Contains(err.Error(), filepath.Join(cache, testSHA+".tar.gz")) || !strings.Contains(err.Error(), "-offline") {
			t.Fatalf("error does not name the cache file and the flag: %v", err)
		}
	})

	t.Run("download fills the cache once", func(t *testing.T) {
		t.Parallel()
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if !strings.HasSuffix(r.URL.Path, "/"+testSHA) {
				http.NotFound(w, r)
				return
			}
			_, _ = w.Write(body)
		}))
		defer srv.Close()

		cache := t.TempDir()
		src := ArchiveSource{CacheDir: cache, BaseURL: srv.URL + "/tar.gz", HTTPClient: srv.Client()}
		for range 2 {
			tree, err := src.Load(context.Background(), testSHA)
			if err != nil || len(tree.Files) != 1 {
				t.Fatalf("Load = %v, %v", tree, err)
			}
		}
		if hits.Load() != 1 {
			t.Fatalf("server hit %d times, want 1 (second load must use the cache)", hits.Load())
		}
		if _, err := os.Stat(filepath.Join(cache, testSHA+".tar.gz")); err != nil {
			t.Fatalf("cache file missing: %v", err)
		}
	})

	t.Run("download failure leaves no cache file", func(t *testing.T) {
		t.Parallel()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		cache := t.TempDir()
		_, err := ArchiveSource{CacheDir: cache, BaseURL: srv.URL, HTTPClient: srv.Client()}.Load(context.Background(), testSHA)
		if !errors.Is(err, errHTTPStatus) {
			t.Fatalf("Load err = %v, want %v", err, errHTTPStatus)
		}
		entries, readErr := os.ReadDir(cache)
		if readErr != nil || len(entries) != 0 {
			t.Fatalf("cache directory not empty after failure: %v, %v", entries, readErr)
		}
	})

	t.Run("cached archive for another commit is rejected", func(t *testing.T) {
		t.Parallel()
		cache := t.TempDir()
		other := strings.Repeat("c", 40)
		if err := os.WriteFile(filepath.Join(cache, testSHA+".tar.gz"), buildTestTarGzSHA(t, other, files), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := (ArchiveSource{CacheDir: cache, Offline: true}).Load(context.Background(), testSHA); !errors.Is(err, errArchiveCommit) {
			t.Fatalf("Load err = %v, want %v", err, errArchiveCommit)
		}
	})

	t.Run("malformed SHA", func(t *testing.T) {
		t.Parallel()
		if _, err := (ArchiveSource{Offline: true}).Load(context.Background(), "xyz"); !errors.Is(err, errInvalidCommitSHA) {
			t.Fatalf("Load err = %v, want %v", err, errInvalidCommitSHA)
		}
	})
}

func TestUpstreamGoFilesAppliesMask(t *testing.T) {
	t.Parallel()

	tree := &UpstreamTree{SHA: testSHA, Files: map[string][]byte{
		"pkg/a.go":      nil,
		"pkg/a_amd64.s": nil,
		"pkg/BUILD":     nil,
		"runsc/m.go":    nil,
		"README.md":     nil,
	}}
	mask, err := ParseFileMaskReader(strings.NewReader("EXCLUDE runsc/**\nINCLUDE pkg/**\n"))
	if err != nil {
		t.Fatal(err)
	}
	included, excluded := tree.UpstreamGoFiles(mask)
	if len(included) != 2 || excluded != 1 {
		t.Fatalf("included=%v excluded=%d, want 2 files and 1 excluded", included, excluded)
	}
}

func TestRewriteModulePathPointsXSysUnixAtTheEmbeddedCopy(t *testing.T) {
	src := []byte("import (\n\t\"golang.org/x/sys/unix\"\n\t\"golang.org/x/sys/windows\"\n\t\"gvisor.dev/gvisor/pkg/abi/linux\"\n)\n")
	got := string(rewriteModulePath(src))
	for _, want := range []string{
		`"z.gfire.dev/gvx/third_party/x_sys/unix"`,
		`"golang.org/x/sys/windows"`,
		`"z.gfire.dev/gvx/pkg/abi/linux"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("rewritten source lacks %s:\n%s", want, got)
		}
	}
	if strings.Contains(got, `"golang.org/x/sys/unix"`) {
		t.Errorf("rewritten source still imports the upstream unix package:\n%s", got)
	}
}
