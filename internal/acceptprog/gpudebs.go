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
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// debPackage is one Ubuntu package file and the SHA-256 digest of the file.
type debPackage struct {
	file   string
	sha256 string
}

// launchpadFiles is the download prefix of the Launchpad librarian. It keeps
// every published build, also after the Ubuntu archive drops the version.
const launchpadFiles = "https://launchpad.net/ubuntu/+archive/primary/+files/"

// gpuGuestDebs maps a Linux architecture to the Ubuntu 24.04 packages that
// add the Mesa Vulkan drivers (with venus) and vulkaninfo to the browser gate
// image. The Mesa version must equal the mesa-libgallium version of that
// image (25.2.8-0ubuntu0.24.04.4 in playwright:v1.65.1-noble); a new image
// needs new entries. Only arm64 exists, because -gpu=venus needs an Apple
// silicon host.
var gpuGuestDebs = map[string][]debPackage{
	"arm64": {
		{"mesa-vulkan-drivers_25.2.8-0ubuntu0.24.04.4_arm64.deb", "f79fedc658ca9c399462241a6751eb05c6868911ec6ba0fa025741c26ef43f07"},
		{"vulkan-tools_1.3.275.0+dfsg1-1_arm64.deb", "0f94baf8ce7d3eb401d9343e8119b8e59f16c4c0339647db2d6f4bd6a71e2df9"},
	},
}

// FetchGPUGuestDebs returns a host directory that holds the package files of
// gpuGuestDebs for goarch under their Ubuntu file names. Mount it read-only
// and install the files with dpkg -i; the guest needs no network. The
// download rules are those of fetchBrowserArchive.
func FetchGPUGuestDebs(tb testing.TB, goarch string) string {
	tb.Helper()
	debs, ok := gpuGuestDebs[goarch]
	if !ok {
		tb.Fatalf("no GPU guest packages for linux/%s", goarch)
	}
	dir := filepath.Join(os.TempDir(), "gvx-acceptprog-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("create the package cache directory: %v", err)
	}
	set := sha256.New()
	for _, d := range debs {
		io.WriteString(set, d.sha256)
	}
	tree := filepath.Join(dir, "gpu-debs-"+goarch+"-"+hex.EncodeToString(set.Sum(nil))[:16])
	if info, err := os.Stat(tree); err == nil && info.IsDir() {
		return tree
	}
	tmp, err := os.MkdirTemp(dir, "gpu-debs-*")
	if err != nil {
		tb.Fatalf("create the package directory: %v", err)
	}
	defer os.RemoveAll(tmp)
	for _, d := range debs {
		cached := filepath.Join(dir, d.sha256+".deb")
		if fileDigest(cached) != d.sha256 {
			if os.Getenv("GVX_E2E_OFFLINE") == "1" {
				tb.Skipf("%s download is off (GVX_E2E_OFFLINE=1)", d.file)
			}
			if err := download(launchpadFiles+d.file, cached); err != nil {
				if os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "" {
					tb.Fatalf("download %s: %v", d.file, err)
				}
				tb.Skipf("download %s: %v", d.file, err)
			}
			if got := fileDigest(cached); got != d.sha256 {
				_ = os.Remove(cached)
				tb.Fatalf("%s digest = %s, want %s", d.file, got, d.sha256)
			}
		}
		if strings.ContainsAny(d.file, `/\`) {
			tb.Fatalf("package file name %q has a path separator", d.file)
		}
		if err := copyRegular(cached, filepath.Join(tmp, d.file)); err != nil {
			tb.Fatalf("copy %s: %v", d.file, err)
		}
	}
	if err := os.Rename(tmp, tree); err != nil {
		// A concurrent test process can win the rename. Its tree is complete.
		if info, statErr := os.Stat(tree); statErr != nil || !info.IsDir() {
			tb.Fatalf("install the package directory: %v", err)
		}
	}
	return tree
}

// copyRegular copies the regular file src to the new file dst.
func copyRegular(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
