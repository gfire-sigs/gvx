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

package oci

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"z.gfire.dev/gvx/pkg/abi/linux"
)

// archiveMemberSpec is one member of a test image archive.
type archiveMemberSpec struct {
	name string
	data []byte
}

func writeArchive(t testing.TB, members []archiveMemberSpec) []byte {
	t.Helper()
	entries := make([]tarEntry, 0, len(members))
	for _, m := range members {
		entries = append(entries, fileEntry(m.name, string(m.data)))
	}
	return buildTar(t, entries...)
}

// ociLayoutMembers returns the members of an OCI image layout that holds the
// given images, one manifest per architecture in index.json.
func ociLayoutMembers(t testing.TB, imgs ...*testImage) []archiveMemberSpec {
	t.Helper()
	members := []archiveMemberSpec{{name: ocispec.ImageLayoutFile, data: []byte(`{"imageLayoutVersion":"1.0.0"}`)}}
	index := ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex}
	for _, img := range imgs {
		index.Manifests = append(index.Manifests, ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest, Digest: digest.Digest(img.digest()), Size: int64(len(img.manifest)),
			Platform: &ocispec.Platform{OS: "linux", Architecture: img.arch},
		})
		members = append(members, blobMember(img.manifest), blobMember(img.config))
		for _, b := range img.blobs {
			members = append(members, blobMember(b))
		}
	}
	raw, err := json.Marshal(index)
	if err != nil {
		t.Fatal(err)
	}
	return append(members, archiveMemberSpec{name: "index.json", data: raw})
}

func blobMember(b []byte) archiveMemberSpec {
	return archiveMemberSpec{name: "blobs/sha256/" + strings.TrimPrefix(sha256Digest(b), "sha256:"), data: b}
}

func replaceMember(members []archiveMemberSpec, name string, data []byte) []archiveMemberSpec {
	out := append([]archiveMemberSpec(nil), members...)
	for i := range out {
		if out[i].name == name {
			out[i].data = data
		}
	}
	return out
}

func writeFile(t testing.TB, dir, name string, data []byte) *os.File {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func TestLoadArchiveTarReadsOCILayouts(t *testing.T) {
	amd, arm := twoLayerImage(t, "amd64", "A=amd"), twoLayerImage(t, "arm64", "A=arm")
	archiveTar := writeArchive(t, ociLayoutMembers(t, amd, arm))

	inputs := map[string]func(t *testing.T) any{
		"file":       func(t *testing.T) any { return writeFile(t, t.TempDir(), "img.tar", archiveTar) },
		"reader":     func(t *testing.T) any { return bytes.NewReader(archiveTar) },
		"gzip file":  func(t *testing.T) any { return writeFile(t, t.TempDir(), "img.tar.gz", gzipBytes(t, archiveTar)) },
		"zstd file":  func(t *testing.T) any { return writeFile(t, t.TempDir(), "img.tar.zst", zstdBytes(t, archiveTar)) },
		"gzip bytes": func(t *testing.T) any { return bytes.NewReader(gzipBytes(t, archiveTar)) },
	}
	for name, open := range inputs {
		for arch, want := range map[string]string{"amd64": "base-amd64", "arm64": "base-arm64"} {
			t.Run(name+"/"+arch, func(t *testing.T) {
				cache := newCache(t)
				img, err := LoadArchiveTar(open(t).(interface{ Read([]byte) (int, error) }), cache, arch)
				if err != nil {
					t.Fatalf("LoadArchiveTar: %v", err)
				}
				defer img.Close()
				if len(img.LayerFiles) != 2 || len(img.LayerPaths) != 2 {
					t.Fatalf("image has %d handles and %d paths", len(img.LayerFiles), len(img.LayerPaths))
				}
				if got := string(readImage(t, img.LayerPaths[0])["/etc/os-release"].content); got != want {
					t.Errorf("base layer holds %q, want %q", got, want)
				}
				if img.Config.WorkingDir != "/w" || img.Architecture != arch {
					t.Errorf("config = %+v arch %q", img.Config, img.Architecture)
				}
				assertNoTempFiles(t, cache.Dir())
			})
		}
	}
}

func TestLoadArchiveTarVerifiesDigests(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")
	members := ociLayoutMembers(t, img)
	evil := gzipBytes(t, buildTar(t, fileEntry("evil", "x")))
	otherConfig := []byte(strings.Replace(string(img.config), "A=1", "A=2", 1))
	otherManifest := twoLayerImage(t, "amd64", "A=other").manifest

	for name, tampered := range map[string][]archiveMemberSpec{
		"layer":    replaceMember(members, blobMember(img.blobs[1]).name, evil),
		"config":   replaceMember(members, blobMember(img.config).name, otherConfig),
		"manifest": replaceMember(members, blobMember(img.manifest).name, otherManifest),
	} {
		t.Run(name, func(t *testing.T) {
			cache := newCache(t)
			_, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, tampered)), cache, "amd64")
			if !errors.Is(err, ErrDigestMismatch) {
				t.Errorf("err = %v, want ErrDigestMismatch", err)
			}
			assertNoTempFiles(t, cache.Dir())
		})
	}

	t.Run("missing layer", func(t *testing.T) {
		var kept []archiveMemberSpec
		for _, m := range members {
			if m.name != blobMember(img.blobs[0]).name {
				kept = append(kept, m)
			}
		}
		_, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, kept)), newCache(t), "amd64")
		if err == nil || !strings.Contains(err.Error(), "missing") {
			t.Errorf("err = %v, want a missing blob error", err)
		}
	})
	t.Run("other architecture", func(t *testing.T) {
		_, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, members)), newCache(t), "arm64")
		if err == nil || !strings.Contains(err.Error(), "no linux/arm64 manifest") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("oci-layout with an unusable index", func(t *testing.T) {
		broken := replaceMember(members, "index.json", []byte(`{"manifests":[]}`))
		if _, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, broken)), newCache(t), "amd64"); err == nil {
			t.Error("an OCI layout without manifests loaded")
		}
	})
}

func dockerSaveMembers(t testing.TB, img *testImage) []archiveMemberSpec {
	t.Helper()
	cfgName := strings.TrimPrefix(sha256Digest(img.config), "sha256:") + ".json"
	members := []archiveMemberSpec{{name: cfgName, data: img.config}}
	var layers []string
	for i, raw := range img.rawLayers {
		name := "layer" + string(rune('0'+i)) + "/layer.tar"
		layers = append(layers, name)
		members = append(members, archiveMemberSpec{name: name, data: raw})
	}
	manifest, err := json.Marshal([]dockerSaveEntry{{Config: cfgName, RepoTags: []string{"app:latest"}, Layers: layers}})
	if err != nil {
		t.Fatal(err)
	}
	return append(members, archiveMemberSpec{name: "manifest.json", data: manifest})
}

func TestLoadArchiveTarReadsDockerSaveArchives(t *testing.T) {
	img := twoLayerImage(t, "amd64", "A=1")
	members := dockerSaveMembers(t, img)

	cache := newCache(t)
	got, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, members)), cache, "amd64")
	if err != nil {
		t.Fatalf("LoadArchiveTar: %v", err)
	}
	defer got.Close()
	if string(readImage(t, got.LayerPaths[1])["/app"].content) != "app-amd64" || got.Config.WorkingDir != "/w" {
		t.Errorf("image = %+v", got.Config)
	}
	// Layers are named by their diff IDs.
	wantDigest := strings.TrimPrefix(sha256Digest(img.rawLayers[0]), "sha256:")
	if got.LayerDigests[0] != wantDigest {
		t.Errorf("layer 0 digest = %s, want the diff ID %s", got.LayerDigests[0], wantDigest)
	}

	tampered := replaceMember(members, "layer1/layer.tar", buildTar(t, fileEntry("evil", "x")))
	if _, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, tampered)), newCache(t), "amd64"); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("tampered layer: err = %v, want ErrDigestMismatch", err)
	}
	if _, err := LoadArchiveTar(bytes.NewReader(writeArchive(t, members)), newCache(t), "arm64"); err == nil {
		t.Error("an amd64 docker save archive loaded for arm64")
	}
}

func TestLoadArchiveTarStreamsRootfsTarballsThroughTheCompiler(t *testing.T) {
	secret := tarEntry{hdr: tar.Header{Name: "root/secret", Typeflag: tar.TypeReg, Mode: 0o600, Uid: 1234, Gid: 4321, Size: 1, ModTime: epoch}, data: []byte("s")}
	// The two orders differ in where whiteouts, devices, and directories sit,
	// but keep each hardlink after its target as tar requires.
	orderA := []tarEntry{
		dirEntry("bin/"), fileEntry("bin/sh", "#!"), symlinkEntry("bin/ash", "sh"), linkEntry("bin/sh2", "bin/sh"),
		dirEntry("dev/"), deviceEntry("dev/null", tar.TypeChar, 1, 3), secret,
		fileEntry("var/.wh.cache", ""), fileEntry("opt/.wh..wh..opq", ""), fileEntry("opt/!first", "f"),
	}
	orderB := []tarEntry{
		fileEntry("opt/!first", "f"), fileEntry("var/.wh.cache", ""), secret, fileEntry("opt/.wh..wh..opq", ""),
		deviceEntry("dev/null", tar.TypeChar, 1, 3), fileEntry("bin/sh", "#!"), linkEntry("bin/sh2", "bin/sh"),
		symlinkEntry("bin/ash", "sh"), dirEntry("dev/"), dirEntry("bin/"),
	}
	a, b := buildTar(t, orderA...), buildTar(t, orderB...)

	var summaries []map[string]string
	for name, input := range map[string][]byte{"plain a": a, "plain b": b, "gzip": gzipBytes(t, a), "zstd": zstdBytes(t, b)} {
		cache := newCache(t)
		img, err := LoadArchiveTar(bytes.NewReader(input), cache, "arm64")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		defer img.Close()
		if len(img.LayerFiles) != 1 || img.Config.WorkingDir != "/" || img.Architecture != "arm64" {
			t.Fatalf("%s: image = %+v", name, img)
		}
		tree := readImage(t, img.LayerPaths[0])
		summaries = append(summaries, treeSummary(tree))
		if n := tree["/bin/ash"]; n.target != "sh" {
			t.Errorf("%s: symlink = %q", name, n.target)
		}
		if tree["/bin/sh"].nid != tree["/bin/sh2"].nid || tree["/bin/sh"].nlink != 2 {
			t.Errorf("%s: hardlink was not kept", name)
		}
		if n := tree["/dev/null"]; n.mode != linux.S_IFCHR|0o600 || n.major != 1 || n.minor != 3 {
			t.Errorf("%s: device = %+v", name, n)
		}
		if n := tree["/root/secret"]; n.mode != linux.S_IFREG|0o600 || n.uid != 1234 || n.gid != 4321 {
			t.Errorf("%s: owner/mode = %o %d:%d", name, n.mode, n.uid, n.gid)
		}
		if n := tree["/var/cache"]; n == nil || n.mode != linux.S_IFCHR {
			t.Errorf("%s: whiteout = %+v", name, n)
		}
		if n := tree["/opt"]; n.xattrs[OpaqueXattrName] != "y" || tree["/opt/!first"] == nil {
			t.Errorf("%s: opaque dir = %+v", name, n)
		}
		assertNoTempFiles(t, cache.Dir())
	}
	for _, s := range summaries[1:] {
		if !maps.Equal(s, summaries[0]) {
			t.Error("the same layer content compiled to different trees")
			break
		}
	}
}

func TestLoadArchiveTarRejectsBrokenArchives(t *testing.T) {
	good := writeArchive(t, ociLayoutMembers(t, twoLayerImage(t, "amd64", "A=1")))
	for name, input := range map[string][]byte{
		"truncated in a blob": good[:len(good)/2],
		"garbage":             bytes.Repeat([]byte{0xA5}, 4096),
		"empty":               {},
	} {
		t.Run(name, func(t *testing.T) {
			cache := newCache(t)
			img, err := LoadArchiveTar(bytes.NewReader(input), cache, "amd64")
			if name == "empty" {
				// An empty archive is an empty root filesystem, not an error.
				if err != nil {
					t.Fatalf("empty archive: %v", err)
				}
				img.Close()
				return
			}
			if err == nil {
				img.Close()
				t.Fatal("LoadArchiveTar succeeded, want an error")
			}
			assertNoTempFiles(t, cache.Dir())
		})
	}
}

func TestLoadArchiveTarBoundsArchiveSizeAndMemberCount(t *testing.T) {
	bomb := gzipBytes(t, buildTar(t, fileEntry("zeros", string(make([]byte, 16<<20)))))
	cache := newCache(t)
	lim := DefaultLimits()
	lim.MaxImageBytes = 1 << 20
	if err := cache.SetLimits(lim); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadArchiveTar(bytes.NewReader(bomb), cache, "amd64"); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("archive bomb: err = %v, want ErrLimitExceeded", err)
	}
	assertNoTempFiles(t, cache.Dir())

	cache = newCache(t)
	lim = DefaultLimits()
	lim.MaxArchiveEntries = 2
	if err := cache.SetLimits(lim); err != nil {
		t.Fatal(err)
	}
	many := buildTar(t, fileEntry("a", ""), fileEntry("b", ""), fileEntry("c", ""))
	if _, err := LoadArchiveTar(bytes.NewReader(many), cache, "amd64"); !errors.Is(err, ErrLimitExceeded) {
		t.Errorf("member count: err = %v, want ErrLimitExceeded", err)
	}
}
