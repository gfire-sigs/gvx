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
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"
	"testing"
)

const (
	// WebGLCTSCommit is the KhronosGroup/WebGL commit that FetchWebGLCTS
	// returns. It is the commit that Chromium 159 pins in DEPS
	// (src/third_party/webgl/src), so the tests match the browser of the
	// Playwright gate image.
	WebGLCTSCommit = "714857a28445e8f5d8d6ae1c78498578009534d8"

	// WebGLCTSSHA256 is the SHA-256 digest of the pinned source tarball.
	WebGLCTSSHA256 = "c966cbce41d22fdf29c7a146fe0981016f9a57b247e80c4fa6beecf448b68bab"

	maxWebGLCTSDownloadBytes int64 = 32 << 20
)

var errEmptySubtree = errors.New("archive subtree matched no members")

// webglCTSArchive is the GitHub source tarball of WebGLCTSCommit.
var webglCTSArchive = browserArchive{
	url:      "https://codeload.github.com/KhronosGroup/WebGL/tar.gz/" + WebGLCTSCommit,
	sha256:   WebGLCTSSHA256,
	strip:    "WebGL-" + WebGLCTSCommit + "/sdk/tests",
	maxBytes: maxWebGLCTSDownloadBytes,
}

// subtreeLimits bound the extraction of a tar subtree. maxScanned counts every
// tar header in the archive, maxDecompressedBytes caps the total uncompressed
// bytes read from the gzip stream, and extractLimits.maxMembers counts members
// strictly below the strip prefix.
type subtreeLimits struct {
	maxScanned           int
	maxDecompressedBytes int64
	extractLimits
}

var webglCTSLimits = subtreeLimits{
	maxScanned:           32768,
	maxDecompressedBytes: 128 << 20,
	extractLimits:        extractLimits{maxMembers: 8192, maxMemberBytes: 4 << 20, maxTotalBytes: 64 << 20},
}

// limitedDecompressReader caps total bytes read from r and returns
// errExtractedTooLarge once reads exceed limit.
type limitedDecompressReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (l *limitedDecompressReader) Read(p []byte) (int, error) {
	if l.limit <= 0 {
		return l.r.Read(p)
	}
	rem := l.limit - l.read
	if rem <= 0 {
		var probe [1]byte
		n, err := l.r.Read(probe[:])
		if n > 0 {
			return 0, fmt.Errorf("decompressed archive exceeds %d bytes: %w", l.limit, errExtractedTooLarge)
		}
		if err != nil {
			return 0, err
		}
		return 0, nil
	}
	if int64(len(p)) > rem {
		p = p[:rem]
	}
	n, err := l.r.Read(p)
	l.read += int64(n)
	return n, err
}

// FetchWebGLCTS returns a host directory that holds the sdk/tests tree of the
// WebGL conformance suite (00_test_list.txt at its top). Mount it read-only in
// the guest. See fetchBrowserArchive for the download rules.
func FetchWebGLCTS(tb testing.TB) string {
	tb.Helper()
	return fetchBrowserArchive(tb, "webgl-cts", webglCTSArchive, extractWebGLCTS)
}

func extractWebGLCTS(archive, dst, strip string) error {
	return extractTarGzSubtree(archive, dst, strip, webglCTSLimits)
}

// extractTarGzSubtree extracts only directories and regular files below strip
// from archive into dst. It validates every member path against traversal,
// skips members of any type outside strip, refuses links or special files
// inside strip, and fails when no member matches strip.
func extractTarGzSubtree(archive, dst, strip string, limits subtreeLimits) error {
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

	cleanStrip := ""
	if strip != "" {
		cleanStrip = path.Clean(strip)
	}
	tr := tar.NewReader(&limitedDecompressReader{r: gz, limit: limits.maxDecompressedBytes})
	scanned := 0
	kept := 0
	remaining := limits.maxTotalBytes
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			if kept == 0 {
				return fmt.Errorf("subtree %q: %w", strip, errEmptySubtree)
			}
			return nil
		}
		if err != nil {
			return err
		}
		scanned++
		if scanned > limits.maxScanned {
			return fmt.Errorf("archive exceeds %d scanned members: %w", limits.maxScanned, errTooManyMembers)
		}
		clean, err := memberName(hdr.Name, "")
		if err != nil {
			return err
		}
		rel := clean
		if cleanStrip != "" {
			if clean == cleanStrip {
				rel = ""
			} else if rest, ok := strings.CutPrefix(clean, cleanStrip+"/"); ok {
				rel = rest
			} else {
				continue
			}
		}
		if rel != "" {
			kept++
			if kept > limits.maxMembers {
				return fmt.Errorf("subtree %q exceeds %d members: %w", strip, limits.maxMembers, errTooManyMembers)
			}
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if rel != "" {
				if err := root.MkdirAll(rel, 0o755); err != nil {
					return err
				}
			}
		case tar.TypeReg:
			if rel == "" {
				return fmt.Errorf("member %q has no name below %q", hdr.Name, strip)
			}
			if err := writeMember(root, rel, fs.FileMode(hdr.Mode), tr, &remaining, limits.maxMemberBytes); err != nil {
				return fmt.Errorf("extract %s: %w", hdr.Name, err)
			}
		default:
			return fmt.Errorf("member %q has unsupported type %q", hdr.Name, hdr.Typeflag)
		}
	}
}
