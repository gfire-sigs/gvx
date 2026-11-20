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
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// archiveMember is one member of a test archive.
type archiveMember struct {
	name     string
	mode     os.FileMode
	typeflag byte // When non-zero, overrides the tar header typeflag.
	linkname string
	body     string
}

func writeTestTarGz(t *testing.T, members ...archiveMember) string {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, m := range members {
		hdr := &tar.Header{Name: m.name, Mode: int64(m.mode.Perm()), Size: int64(len(m.body)), Typeflag: tar.TypeReg}
		if m.typeflag != 0 {
			hdr.Typeflag = m.typeflag
			hdr.Linkname = m.linkname
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("write tar header %s: %v", m.name, err)
		}
		if hdr.Typeflag == tar.TypeReg {
			if _, err := tw.Write([]byte(m.body)); err != nil {
				t.Fatalf("write tar body %s: %v", m.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar writer: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip writer: %v", err)
	}
	p := filepath.Join(t.TempDir(), "a.tgz")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return p
}

func writeTestZip(t *testing.T, members ...archiveMember) string {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, m := range members {
		fh := &zip.FileHeader{Name: m.name, Method: zip.Deflate}
		mode, body := m.mode, m.body
		if m.typeflag == tar.TypeSymlink {
			mode, body = os.ModeSymlink|0o777, m.linkname
		}
		fh.SetMode(mode)
		w, err := zw.CreateHeader(fh)
		if err != nil {
			t.Fatalf("create zip member %s: %v", m.name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip member %s: %v", m.name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip writer: %v", err)
	}
	p := filepath.Join(t.TempDir(), "a.zip")
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	return p
}

func requireFile(t *testing.T, path, wantBody string, wantExec bool) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read extracted %s: %v", path, err)
	}
	if string(got) != wantBody {
		t.Errorf("extracted %s = %q, want %q", path, got, wantBody)
	}
	if runtime.GOOS == "windows" {
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat extracted %s: %v", path, err)
	}
	if isExec := info.Mode().Perm()&0o100 != 0; isExec != wantExec {
		t.Errorf("extracted %s mode = %v, want owner execute %v", path, info.Mode(), wantExec)
	}
}

func TestExtractTarGzStripsPackagePrefix(t *testing.T) {
	archive := writeTestTarGz(t,
		archiveMember{name: "package/package.json", mode: 0o644, body: `{"name":"x"}`},
		archiveMember{name: "package/lib/cli.js", mode: 0o755, body: "cli"},
	)
	dst := t.TempDir()
	if err := extractTarGz(archive, dst, "package"); err != nil {
		t.Fatalf("extractTarGz() = %v, want nil", err)
	}
	requireFile(t, filepath.Join(dst, "package.json"), `{"name":"x"}`, false)
	requireFile(t, filepath.Join(dst, "lib", "cli.js"), "cli", true)
}

func TestExtractZipKeepsExecutableBit(t *testing.T) {
	archive := writeTestZip(t,
		archiveMember{name: "electron", mode: 0o755, body: "ELF"},
		archiveMember{name: "locales/en-US.pak", mode: 0o644, body: "pak"},
	)
	dst := t.TempDir()
	if err := extractZip(archive, dst, ""); err != nil {
		t.Fatalf("extractZip() = %v, want nil", err)
	}
	requireFile(t, filepath.Join(dst, "electron"), "ELF", true)
	requireFile(t, filepath.Join(dst, "locales", "en-US.pak"), "pak", false)
}

func TestExtractRejectsUnsafeMemberPaths(t *testing.T) {
	cases := []struct {
		name      string
		member    string
		checkPath string // optional path relative to parent dir that must not exist
	}{
		{name: "dotdot", member: "../escape", checkPath: "escape"},
		{name: "absolute", member: "/abs/path"},
		{name: "backslash_escape", member: `..\escape`, checkPath: "escape"},
		{name: "backslash_nested", member: `sub\file`},
	}
	for _, tc := range cases {
		m := archiveMember{name: tc.member, mode: 0o644, body: "x"}
		for format, run := range map[string]func(dst string) error{
			"tar.gz": func(dst string) error { return extractTarGz(writeTestTarGz(t, m), dst, "") },
			"zip":    func(dst string) error { return extractZip(writeTestZip(t, m), dst, "") },
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				parent := t.TempDir()
				dst := filepath.Join(parent, "dst")
				if err := os.Mkdir(dst, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := run(dst); err == nil {
					t.Fatalf("extract of member %q = nil, want an error", m.name)
				}
				if tc.checkPath != "" {
					if _, err := os.Stat(filepath.Join(parent, tc.checkPath)); err == nil {
						t.Errorf("member %q was written outside the extraction directory", m.name)
					}
				}
			})
		}
	}
}

func TestExtractRejectsUnsupportedMemberTypes(t *testing.T) {
	tarCases := []struct {
		name   string
		member archiveMember
	}{
		{name: "symlink", member: archiveMember{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
		{name: "hardlink", member: archiveMember{name: "hard", typeflag: tar.TypeLink, linkname: "target"}},
		{name: "char_device", member: archiveMember{name: "null", mode: 0o666, typeflag: tar.TypeChar}},
		{name: "block_device", member: archiveMember{name: "blk", mode: 0o660, typeflag: tar.TypeBlock}},
	}
	for _, tc := range tarCases {
		t.Run("tar.gz/"+tc.name, func(t *testing.T) {
			dst := t.TempDir()
			if err := extractTarGz(writeTestTarGz(t, tc.member), dst, ""); err == nil {
				t.Fatalf("extractTarGz of %s = nil, want an error", tc.name)
			}
			if _, err := os.Lstat(filepath.Join(dst, tc.member.name)); err == nil {
				t.Errorf("%s member was created", tc.name)
			}
		})
	}

	zipCases := []struct {
		name   string
		member archiveMember
	}{
		{name: "symlink", member: archiveMember{name: "link", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"}},
		{name: "char_device", member: archiveMember{name: "null", mode: os.ModeDevice | os.ModeCharDevice | 0o666}},
		{name: "fifo", member: archiveMember{name: "pipe", mode: os.ModeNamedPipe | 0o644}},
	}
	for _, tc := range zipCases {
		t.Run("zip/"+tc.name, func(t *testing.T) {
			dst := t.TempDir()
			if err := extractZip(writeTestZip(t, tc.member), dst, ""); err == nil {
				t.Fatalf("extractZip of %s = nil, want an error", tc.name)
			}
			if _, err := os.Lstat(filepath.Join(dst, tc.member.name)); err == nil {
				t.Errorf("%s member was created", tc.name)
			}
		})
	}
}

func TestExtractTarGzRejectsMemberOutsideStripPrefix(t *testing.T) {
	archive := writeTestTarGz(t, archiveMember{name: "other/file", mode: 0o644, body: "x"})
	if err := extractTarGz(archive, t.TempDir(), "package"); err == nil {
		t.Fatalf("extractTarGz() of member outside %q = nil, want an error", "package")
	}
}

func TestExtractEnforcesMemberCountCap(t *testing.T) {
	limits := extractLimits{maxMembers: 2, maxMemberBytes: 1024, maxTotalBytes: 4096}
	two := []archiveMember{
		{name: "a", mode: 0o644, body: "1"},
		{name: "b", mode: 0o644, body: "2"},
	}
	three := append(append([]archiveMember(nil), two...), archiveMember{name: "c", mode: 0o644, body: "3"})
	for format, run := range map[string]func(members []archiveMember) error{
		"tar.gz": func(members []archiveMember) error {
			return extractTarGzWithLimits(writeTestTarGz(t, members...), t.TempDir(), "", limits)
		},
		"zip": func(members []archiveMember) error {
			return extractZipWithLimits(writeTestZip(t, members...), t.TempDir(), "", limits)
		},
	} {
		t.Run(format, func(t *testing.T) {
			if err := run(two); err != nil {
				t.Fatalf("extract at exact member cap (%d) = %v, want nil", limits.maxMembers, err)
			}
			if err := run(three); !errors.Is(err, errTooManyMembers) {
				t.Fatalf("extract above member cap = %v, want %v", err, errTooManyMembers)
			}
		})
	}
}

func TestExtractEnforcesByteCaps(t *testing.T) {
	cases := []struct {
		name    string
		limits  extractLimits
		okSet   []archiveMember
		overSet []archiveMember
	}{
		{
			name:   "single_member",
			limits: extractLimits{maxMembers: 10, maxMemberBytes: 8, maxTotalBytes: 1024},
			okSet:  []archiveMember{{name: "a", mode: 0o644, body: strings.Repeat("a", 8)}},
			overSet: []archiveMember{
				{name: "a", mode: 0o644, body: strings.Repeat("a", 9)},
			},
		},
		{
			name:   "cumulative_total",
			limits: extractLimits{maxMembers: 10, maxMemberBytes: 10, maxTotalBytes: 12},
			okSet: []archiveMember{
				{name: "a", mode: 0o644, body: strings.Repeat("a", 6)},
				{name: "b", mode: 0o644, body: strings.Repeat("b", 6)},
			},
			overSet: []archiveMember{
				{name: "a", mode: 0o644, body: strings.Repeat("a", 8)},
				{name: "b", mode: 0o644, body: strings.Repeat("b", 8)},
			},
		},
	}
	for _, tc := range cases {
		for format, run := range map[string]func(members []archiveMember) error{
			"tar.gz": func(members []archiveMember) error {
				return extractTarGzWithLimits(writeTestTarGz(t, members...), t.TempDir(), "", tc.limits)
			},
			"zip": func(members []archiveMember) error {
				return extractZipWithLimits(writeTestZip(t, members...), t.TempDir(), "", tc.limits)
			},
		} {
			t.Run(format+"/"+tc.name, func(t *testing.T) {
				if err := run(tc.okSet); err != nil {
					t.Fatalf("extract at cap = %v, want nil", err)
				}
				if err := run(tc.overSet); !errors.Is(err, errExtractedTooLarge) {
					t.Fatalf("extract above cap = %v, want %v", err, errExtractedTooLarge)
				}
			})
		}
	}
}

func TestDownloadArchiveEnforcesSizeAndDigest(t *testing.T) {
	payload := []byte("bounded-archive-payload")
	sum := sha256.Sum256(payload)
	wantDigest := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ok":
			_, _ = w.Write(payload)
		case "/large-known":
			body := bytes.Repeat([]byte("x"), 64)
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			_, _ = w.Write(body)
		case "/large-chunked":
			flusher, ok := w.(http.Flusher)
			chunk := bytes.Repeat([]byte("y"), 16)
			for range 8 {
				_, _ = w.Write(chunk)
				if ok {
					flusher.Flush()
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	t.Run("valid", func(t *testing.T) {
		dir := t.TempDir()
		dst := filepath.Join(dir, "archive.tgz")
		if err := downloadArchive(srv.Client(), srv.URL+"/ok", dst, wantDigest, int64(len(payload))); err != nil {
			t.Fatalf("downloadArchive() = %v, want nil", err)
		}
		got, err := os.ReadFile(dst)
		if err != nil {
			t.Fatalf("read downloaded file: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("downloaded bytes = %q, want %q", got, payload)
		}
	})

	for _, tc := range []struct {
		name    string
		path    string
		digest  string
		maxSize int64
		wantErr error
	}{
		{name: "oversized_content_length", path: "/large-known", digest: wantDigest, maxSize: 32, wantErr: errArchiveTooLarge},
		{name: "oversized_chunked", path: "/large-chunked", digest: wantDigest, maxSize: 32, wantErr: errArchiveTooLarge},
		{name: "digest_mismatch", path: "/ok", digest: strings.Repeat("0", 64), maxSize: 64, wantErr: errDigestMismatch},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dst := filepath.Join(dir, "archive.tgz")
			err := downloadArchive(srv.Client(), srv.URL+tc.path, dst, tc.digest, tc.maxSize)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("downloadArchive() = %v, want %v", err, tc.wantErr)
			}
			entries, readErr := os.ReadDir(dir)
			if readErr != nil {
				t.Fatalf("read cache dir: %v", readErr)
			}
			if len(entries) != 0 {
				t.Errorf("failed download left files in %s: %v", dir, entries)
			}
		})
	}
}
