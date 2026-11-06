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
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"testing"
)

// releaseTool is one executable inside a release archive. The digest is the
// SHA-256 of the archive that the release page publishes.
type releaseTool struct {
	url    string
	sha256 string
	member string
}

// etcdctlAssets and sonobuoyAssets map a Linux architecture to the release
// archive. etcd 3.5.16 is the version that k3s v1.31.4 embeds.
var (
	etcdctlAssets = map[string]releaseTool{
		"amd64": {"https://github.com/etcd-io/etcd/releases/download/v3.5.16/etcd-v3.5.16-linux-amd64.tar.gz",
			"b414b27a5ad05f7cb01395c447c85d3227e3fb1c176e51757a283b817f645ccc", "etcd-v3.5.16-linux-amd64/etcdctl"},
		"arm64": {"https://github.com/etcd-io/etcd/releases/download/v3.5.16/etcd-v3.5.16-linux-arm64.tar.gz",
			"8e68c55e6d72b791a9e98591c755af36f6f55aa9eca63767822cd8a3817fdb23", "etcd-v3.5.16-linux-arm64/etcdctl"},
	}
	sonobuoyAssets = map[string]releaseTool{
		"amd64": {"https://github.com/vmware-tanzu/sonobuoy/releases/download/v0.57.3/sonobuoy_0.57.3_linux_amd64.tar.gz",
			"6728e04f62068465c56e2d317f4a5392520bf00c836aeaba970ae913f943718c", "sonobuoy"},
		"arm64": {"https://github.com/vmware-tanzu/sonobuoy/releases/download/v0.57.3/sonobuoy_0.57.3_linux_arm64.tar.gz",
			"958edd774ff6a23f8eaefc2ea2c361b05caa8d7980ab8443e552e7f7bf100ab1", "sonobuoy"},
	}
)

// FetchEtcdctl returns the path of the etcdctl 3.5.16 executable for the
// Linux architecture goarch. See fetchReleaseTool for the download rules.
func FetchEtcdctl(tb testing.TB, goarch string) string {
	tb.Helper()
	return fetchReleaseTool(tb, "etcdctl", etcdctlAssets, goarch)
}

// FetchSonobuoy returns the path of the sonobuoy 0.57.3 executable for the
// Linux architecture goarch. See fetchReleaseTool for the download rules.
func FetchSonobuoy(tb testing.TB, goarch string) string {
	tb.Helper()
	return fetchReleaseTool(tb, "sonobuoy", sonobuoyAssets, goarch)
}

// fetchReleaseTool downloads the release archive on the host, verifies its
// SHA-256 digest, and extracts one executable into a cache directory. The
// host downloads the file, so the guest needs no TLS client. It skips the
// test when GVX_E2E_OFFLINE is 1. It also skips when the download fails and
// GVX_E2E_REQUIRE_NETWORK is empty.
func fetchReleaseTool(tb testing.TB, name string, assets map[string]releaseTool, goarch string) string {
	tb.Helper()
	asset, ok := assets[goarch]
	if !ok {
		tb.Fatalf("no %s release for linux/%s", name, goarch)
	}
	dir := filepath.Join(os.TempDir(), "gvx-acceptprog-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("create the %s cache directory: %v", name, err)
	}
	exe := filepath.Join(dir, asset.sha256+"-"+name)
	if _, err := os.Stat(exe); err == nil {
		return exe
	}
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		tb.Skipf("%s download is off (GVX_E2E_OFFLINE=1)", name)
	}
	archive := filepath.Join(dir, asset.sha256+".tar.gz")
	if fileDigest(archive) != asset.sha256 {
		if err := download(asset.url, archive); err != nil {
			if os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "" {
				tb.Fatalf("download %s: %v", name, err)
			}
			tb.Skipf("download %s: %v", name, err)
		}
		if got := fileDigest(archive); got != asset.sha256 {
			_ = os.Remove(archive)
			tb.Fatalf("%s archive digest = %s, want %s", name, got, asset.sha256)
		}
	}
	if err := extractMember(archive, asset.member, exe); err != nil {
		tb.Fatalf("extract %s from %s: %v", asset.member, archive, err)
	}
	return exe
}

// extractMember copies the regular file member of the tar.gz archive to dst
// through a temporary file, so a failed extraction leaves no partial file.
func extractMember(archive, member, dst string) error {
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
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return fmt.Errorf("member %s not found", member)
		}
		if err != nil {
			return err
		}
		if hdr.Typeflag != tar.TypeReg || path.Clean(hdr.Name) != member {
			continue
		}
		tmp, err := os.CreateTemp(filepath.Dir(dst), "extract-*")
		if err != nil {
			return err
		}
		defer os.Remove(tmp.Name())
		if _, err := io.Copy(tmp, tr); err != nil {
			tmp.Close()
			return err
		}
		if err := tmp.Close(); err != nil {
			return err
		}
		if err := os.Chmod(tmp.Name(), 0o755); err != nil {
			return err
		}
		return os.Rename(tmp.Name(), dst)
	}
}

// calicoVXLANManifest is the manifest of Calico 3.28.2 for VXLAN without BIRD.
// The digest is the SHA-256 of the file that the project publishes at the tag.
var calicoVXLANManifest = struct{ url, sha256 string }{
	"https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico-vxlan.yaml",
	"41ccdbcbc13e5d79be2693df878faef1c11806bad04f779907ab71fcc474c83a",
}

// FetchCalicoVXLANManifest returns the path of the Calico 3.28.2 VXLAN
// manifest. The host downloads the file, because the guest needs no TLS
// client. It verifies the SHA-256 digest. The test skips when GVX_E2E_OFFLINE is
// 1, or when the download fails and GVX_E2E_REQUIRE_NETWORK is empty.
func FetchCalicoVXLANManifest(tb testing.TB) string {
	tb.Helper()
	dir := filepath.Join(os.TempDir(), "gvx-acceptprog-cache")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		tb.Fatalf("create the manifest cache directory: %v", err)
	}
	file := filepath.Join(dir, calicoVXLANManifest.sha256+"-calico-vxlan.yaml")
	if fileDigest(file) == calicoVXLANManifest.sha256 {
		return file
	}
	if os.Getenv("GVX_E2E_OFFLINE") == "1" {
		tb.Skip("Calico manifest download is off (GVX_E2E_OFFLINE=1)")
	}
	if err := download(calicoVXLANManifest.url, file); err != nil {
		if os.Getenv("GVX_E2E_REQUIRE_NETWORK") != "" {
			tb.Fatalf("download the Calico manifest: %v", err)
		}
		tb.Skipf("download the Calico manifest: %v", err)
	}
	if got := fileDigest(file); got != calicoVXLANManifest.sha256 {
		_ = os.Remove(file)
		tb.Fatalf("Calico manifest digest = %s, want %s", got, calicoVXLANManifest.sha256)
	}
	return file
}
