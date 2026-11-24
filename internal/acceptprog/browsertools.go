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
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// browserArchive is one release archive of a browser tool. The digest is the
// SHA-256 of the archive file. strip is the leading path component that the
// extraction removes from every member, or "" to keep the names. maxBytes caps
// the HTTP response body before verification.
type browserArchive struct {
	url      string
	sha256   string
	strip    string
	maxBytes int64
}

const (
	// PlaywrightCoreVersion is the playwright-core release that FetchPlaywrightCore
	// returns. It must match the Playwright version of the browser gate image.
	PlaywrightCoreVersion = "1.65.1"

	// ElectronVersion is the Electron release that FetchElectron returns.
	ElectronVersion = "45.4.1"

	// Download and extraction ceilings bound disk use against oversized HTTP
	// responses and decompression bombs.
	maxPlaywrightDownloadBytes int64 = 32 << 20
	maxElectronDownloadBytes   int64 = 256 << 20
	maxArchiveMembers                = 4096
	maxMemberBytes             int64 = 384 << 20
	maxExtractedBytes          int64 = 512 << 20
)

var (
	errArchiveTooLarge = errors.New("archive download exceeds size limit")
	errDigestMismatch  = errors.New("archive digest mismatch")
	// errDownloadTransport marks a download that the network stopped: the
	// request got no response, or the response body ended with an error.
	errDownloadTransport = errors.New("download transport error")
	errTreeIncomplete    = errors.New("cached tree is incomplete")
	errTooManyMembers    = errors.New("archive exceeds member count limit")
	errExtractedTooLarge = errors.New("archive exceeds extracted byte limit")
)

type extractLimits struct {
	maxMembers     int
	maxMemberBytes int64
	maxTotalBytes  int64
}

var defaultExtractLimits = extractLimits{
	maxMembers:     maxArchiveMembers,
	maxMemberBytes: maxMemberBytes,
	maxTotalBytes:  maxExtractedBytes,
}

// playwrightCoreArchive is the npm tarball of playwright-core. The package
// has no dependencies, so the guest needs no npm install step. The digest is
// the SHA-256 of the tarball; the npm integrity field is
// sha512-hqPpz7blSMPxWVdoeE1yiBSzXsKiVOd2k+kjCvmUywD2GPO2Dd9HfcWnq9NN0GHbNZDFgZ9JfBFr+X5/BLo0qw==.
var playwrightCoreArchive = browserArchive{
	url:      "https://registry.npmjs.org/playwright-core/-/playwright-core-" + PlaywrightCoreVersion + ".tgz",
	sha256:   "6f5a60be62a4fddfbe7d10c448d8fbd54547da3358f2f8a04211440471ee863e",
	strip:    "package",
	maxBytes: maxPlaywrightDownloadBytes,
}

// electronArchives maps a Linux architecture to the Electron release zip. The
// digests come from SHASUMS256.txt of the release.
var electronArchives = map[string]browserArchive{
	"amd64": {
		url:      "https://github.com/electron/electron/releases/download/v" + ElectronVersion + "/electron-v" + ElectronVersion + "-linux-x64.zip",
		sha256:   "e1d077c7a087d7e344350ea0c5cd2b7dc5af3d9bf7979474f38e0fc1a560b875",
		maxBytes: maxElectronDownloadBytes,
	},
	"arm64": {
		url:      "https://github.com/electron/electron/releases/download/v" + ElectronVersion + "/electron-v" + ElectronVersion + "-linux-arm64.zip",
		sha256:   "3da04c450fa682e3b80961e92a918a1c2a1a10796527a7e63dec7b8e466b6334",
		maxBytes: maxElectronDownloadBytes,
	},
}

// FetchPlaywrightCore returns a host directory that holds the playwright-core
// package (package.json at its top). Mount it read-only in the guest and load
// it with require. See fetchBrowserArchive for the download rules.
func FetchPlaywrightCore(tb testing.TB) string {
	tb.Helper()
	return fetchBrowserArchive(tb, "playwright-core", playwrightCoreArchive, extractTarGz)
}

// FetchElectron returns a host directory that holds the Electron release for
// the Linux architecture goarch, with the electron executable at its top. See
// fetchBrowserArchive for the download rules.
func FetchElectron(tb testing.TB, goarch string) string {
	tb.Helper()
	archive, ok := electronArchives[goarch]
	if !ok {
		tb.Fatalf("no Electron release for linux/%s", goarch)
	}
	return fetchBrowserArchive(tb, "electron", archive, extractZip)
}

// treeManifestName is the file at the top of a cached tree that lists the
// regular files of the tree with their sizes. installTree writes it before the
// tree gets its final name, so a tree with a manifest was complete at that time.
const treeManifestName = ".gvx-tree-manifest"

// writeTreeManifest writes the manifest of the tree at dir.
func writeTreeManifest(dir string) error {
	var b strings.Builder
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%d\t%s\n", info.Size(), filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	if b.Len() == 0 {
		return fmt.Errorf("%w: %s has no regular file", errTreeIncomplete, dir)
	}
	return os.WriteFile(filepath.Join(dir, treeManifestName), []byte(b.String()), 0o644)
}

// verifyTree compares the tree at dir with its manifest. It returns an error
// that wraps errTreeIncomplete when the manifest is absent or empty, or when a
// listed file is absent, is not a regular file, or has a different size. The
// host can remove old files of a temporary directory and keep the directory.
func verifyTree(dir string) error {
	data, err := os.ReadFile(filepath.Join(dir, treeManifestName))
	if err != nil {
		return fmt.Errorf("%w: %w", errTreeIncomplete, err)
	}
	lines := strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
	if len(data) == 0 {
		return fmt.Errorf("%w: empty manifest in %s", errTreeIncomplete, dir)
	}
	for _, line := range lines {
		sizeText, rel, ok := strings.Cut(line, "\t")
		size, perr := strconv.ParseInt(sizeText, 10, 64)
		if !ok || perr != nil || !filepath.IsLocal(filepath.FromSlash(rel)) {
			return fmt.Errorf("%w: manifest line %q", errTreeIncomplete, line)
		}
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return fmt.Errorf("%w: %w", errTreeIncomplete, err)
		}
		if !info.Mode().IsRegular() || info.Size() != size {
			return fmt.Errorf("%w: %s has mode %s and %d bytes, want a regular file of %d bytes", errTreeIncomplete, rel, info.Mode(), info.Size(), size)
		}
	}
	return nil
}

// reuseTree reports whether the cached tree is complete. It removes a tree
// that is not complete, so the caller can install a new one under that name.
func reuseTree(tree string) (bool, error) {
	if _, err := os.Lstat(tree); errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err := verifyTree(tree); err == nil {
		return true, nil
	}
	if err := os.RemoveAll(tree); err != nil {
		return false, err
	}
	return false, nil
}

// installTree writes the manifest of the new tree at tmp and renames tmp to
// tree. A concurrent test process can win the rename; installTree then
// verifies the tree of that process.
func installTree(tmp, tree string) error {
	if err := writeTreeManifest(tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, tree); err != nil {
		if verr := verifyTree(tree); verr != nil {
			return errors.Join(err, verr)
		}
	}
	return nil
}

// downloadFailureSkips reports whether a test skips after the download error
// err. Only a transport error skips, and only when GVX_E2E_REQUIRE_NETWORK is
// empty. An HTTP status other than 200, a size above the limit, a digest
// mismatch, and a local file error always fail: a pinned asset that the server
// removed or refused must not show as a skip.
func downloadFailureSkips(err error, requireNetwork bool) bool {
	return errors.Is(err, errDownloadTransport) && !requireNetwork
}

// failOrSkipDownload ends the test after the download error err with the rule
// of downloadFailureSkips.
func failOrSkipDownload(tb testing.TB, name string, err error) {
	tb.Helper()
	if downloadFailureSkips(err, os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "") {
		tb.Skipf("download %s: %v", name, err)
	}
	tb.Fatalf("download %s: %v", name, err)
}

// fetchBrowserArchive downloads the archive on the host, verifies its SHA-256
// digest, and extracts it into a cache directory that later runs reuse. A
// later run reuses the tree only when it matches its manifest. It skips the
// test when GVX_E2E_OFFLINE is 1. It also skips when a transport error stops
// the download and GVX_E2E_REQUIRE_NETWORK is empty. Every other download
// error fails the test.
func fetchBrowserArchive(tb testing.TB, name string, a browserArchive, extract func(archive, dst, strip string) error) string {
	tb.Helper()
	dir := filepath.Join(os.TempDir(), "gvx-acceptprog-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("create the %s cache directory: %v", name, err)
	}
	tree := filepath.Join(dir, a.sha256+"-"+name)
	ok, err := reuseTree(tree)
	if err != nil {
		tb.Fatalf("remove the incomplete %s tree: %v", name, err)
	}
	if ok {
		return tree
	}
	archive := filepath.Join(dir, a.sha256+path.Ext(a.url))
	if fileDigest(archive) != a.sha256 {
		if os.Getenv("GVX_E2E_OFFLINE") == "1" {
			tb.Skipf("%s download is off (GVX_E2E_OFFLINE=1)", name)
		}
		if err := downloadArchive(nil, a.url, archive, a.sha256, a.maxBytes); err != nil {
			failOrSkipDownload(tb, name, err)
		}
	}
	tmp, err := os.MkdirTemp(dir, name+"-extract-*")
	if err != nil {
		tb.Fatalf("create the %s extraction directory: %v", name, err)
	}
	defer os.RemoveAll(tmp)
	if err := extract(archive, tmp, a.strip); err != nil {
		tb.Fatalf("extract %s from %s: %v", name, archive, err)
	}
	if err := installTree(tmp, tree); err != nil {
		tb.Fatalf("install the %s tree: %v", name, err)
	}
	return tree
}

// transportReader marks every read error of r, except io.EOF, as a transport
// error.
type transportReader struct{ r io.Reader }

func (t transportReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("%w: %w", errDownloadTransport, err)
	}
	return n, err
}

// downloadArchive streams url into a temporary file beside dst while hashing
// its SHA-256 digest, aborts if the body exceeds maxBytes, and renames the
// file to dst only after the digest matches wantSHA256. An error of the
// request or of a body read wraps errDownloadTransport.
func downloadArchive(client *http.Client, url, dst, wantSHA256 string, maxBytes int64) error {
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Minute}
	}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("%w: %w", errDownloadTransport, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	if maxBytes > 0 && resp.ContentLength > maxBytes {
		return fmt.Errorf("GET %s: content length %d exceeds limit %d: %w", url, resp.ContentLength, maxBytes, errArchiveTooLarge)
	}
	tmp, err := os.CreateTemp(filepath.Dir(dst), "download-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	h := sha256.New()
	var body io.Reader = transportReader{resp.Body}
	if maxBytes > 0 {
		body = io.LimitReader(body, maxBytes+1)
	}
	n, copyErr := io.Copy(io.MultiWriter(tmp, h), body)
	closeErr := tmp.Close()
	if copyErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if maxBytes > 0 && n > maxBytes {
		return fmt.Errorf("GET %s: body exceeds limit %d: %w", url, maxBytes, errArchiveTooLarge)
	}
	if wantSHA256 != "" {
		if got := hex.EncodeToString(h.Sum(nil)); got != wantSHA256 {
			return fmt.Errorf("GET %s: digest = %s, want %s: %w", url, got, wantSHA256, errDigestMismatch)
		}
	}
	return os.Rename(tmpName, dst)
}

// memberName returns the cleaned slash-separated member name with the strip
// prefix removed. It returns "" for the strip directory itself. It rejects
// backslashes, absolute names, and names that leave the extraction directory.
func memberName(name, strip string) (string, error) {
	if strings.Contains(name, "\\") {
		return "", fmt.Errorf("member %q contains a backslash", name)
	}
	clean := path.Clean(strings.TrimPrefix(name, "./"))
	if path.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("member %q leaves the extraction directory", name)
	}
	if strip == "" {
		if clean == "." {
			return "", nil
		}
		return clean, nil
	}
	if clean == strip {
		return "", nil
	}
	rest, ok := strings.CutPrefix(clean, strip+"/")
	if !ok {
		return "", fmt.Errorf("member %q is not below %q", name, strip)
	}
	return rest, nil
}

// writeMember copies at most min(*remaining, maxMember) bytes from r to name
// below root with the permission bits of mode. os.Root rejects a name that
// resolves outside root.
func writeMember(root *os.Root, name string, mode fs.FileMode, r io.Reader, remaining *int64, maxMember int64) (err error) {
	if dir := path.Dir(name); dir != "." {
		if err := root.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode.Perm()|0o200)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, f.Close())
	}()
	limit := min(*remaining, maxMember)
	n, copyErr := io.Copy(f, io.LimitReader(r, limit+1))
	if copyErr != nil {
		return copyErr
	}
	if n > limit {
		return fmt.Errorf("member %q exceeds cap of %d bytes: %w", name, limit, errExtractedTooLarge)
	}
	*remaining -= n
	return nil
}

// extractTarGz extracts the directories and regular files of a tar.gz
// archive into dst. It refuses links and other member types.
func extractTarGz(archive, dst, strip string) error {
	return extractTarGzWithLimits(archive, dst, strip, defaultExtractLimits)
}

func extractTarGzWithLimits(archive, dst, strip string, limits extractLimits) error {
	f, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	tr := tar.NewReader(gz)
	members := 0
	remaining := limits.maxTotalBytes
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		members++
		if members > limits.maxMembers {
			return fmt.Errorf("archive exceeds %d members: %w", limits.maxMembers, errTooManyMembers)
		}
		name, err := memberName(hdr.Name, strip)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if name != "" {
				if err := root.MkdirAll(name, 0o755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			if name == "" {
				return fmt.Errorf("member %q has no name below %q", hdr.Name, strip)
			}
			if err := writeMember(root, name, fs.FileMode(hdr.Mode), tr, &remaining, limits.maxMemberBytes); err != nil {
				return fmt.Errorf("extract %s: %w", hdr.Name, err)
			}
		default:
			return fmt.Errorf("member %q has unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
}

// extractZip extracts the directories and regular files of a zip archive into
// dst. It keeps the Unix permission bits, so executables stay executable. It
// refuses symbolic links and other member types.
func extractZip(archive, dst, strip string) error {
	return extractZipWithLimits(archive, dst, strip, defaultExtractLimits)
}

func extractZipWithLimits(archive, dst, strip string, limits extractLimits) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	if len(zr.File) > limits.maxMembers {
		return fmt.Errorf("archive has %d members, cap is %d: %w", len(zr.File), limits.maxMembers, errTooManyMembers)
	}
	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer root.Close()
	remaining := limits.maxTotalBytes
	for _, zf := range zr.File {
		name, err := memberName(zf.Name, strip)
		if err != nil {
			return err
		}
		mode := zf.Mode()
		switch {
		case mode.IsDir():
			if name != "" {
				if err := root.MkdirAll(name, 0o755); err != nil {
					return err
				}
			}
		case mode.IsRegular():
			if name == "" {
				return fmt.Errorf("member %q has no name below %q", zf.Name, strip)
			}
			rc, err := zf.Open()
			if err != nil {
				return err
			}
			err = writeMember(root, name, mode, rc, &remaining, limits.maxMemberBytes)
			err = errors.Join(err, rc.Close())
			if err != nil {
				return fmt.Errorf("extract %s: %w", zf.Name, err)
			}
		default:
			return fmt.Errorf("member %q has unsupported mode %v", zf.Name, mode)
		}
	}
	return nil
}
