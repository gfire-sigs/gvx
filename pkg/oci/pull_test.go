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
	"bytes"
	"context"
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"github.com/opencontainers/go-digest"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestParseRuntimeConfigExposedPorts(t *testing.T) {
	cfg, err := ParseRuntimeConfig([]byte(`{"config":{"ExposedPorts":{
		"8080/tcp":{}, "53/udp":{}, "443":{}, "80/tcp":{}, "0/tcp":{}, "70000/tcp":{}, "9/sctp":{}, "x/tcp":{}}}}`))
	if err != nil {
		t.Fatalf("ParseRuntimeConfig: %v", err)
	}
	want := []ExposedPort{
		{Port: 53, Protocol: "udp"},
		{Port: 80, Protocol: "tcp"},
		{Port: 443, Protocol: "tcp"},
		{Port: 8080, Protocol: "tcp"},
	}
	if got := cfg.ExposedPortList(); !reflect.DeepEqual(got, want) {
		t.Errorf("ExposedPortList() = %v, want %v (ordered by port, a key without protocol is tcp, invalid keys skipped)", got, want)
	}
}

func TestExposedPortListEmptyWithoutDeclaration(t *testing.T) {
	cfg, err := ParseRuntimeConfig([]byte(`{"config":{}}`))
	if err != nil {
		t.Fatalf("ParseRuntimeConfig: %v", err)
	}
	if got := cfg.ExposedPortList(); len(got) != 0 {
		t.Errorf("ExposedPortList() = %v, want none", got)
	}
}

func TestParseRuntimeConfigLabels(t *testing.T) {
	t.Run("populated", func(t *testing.T) {
		raw := []byte(`{"config":{"Labels":{"org.opencontainers.image.source":"https://example.com/repo","dev.gfire.role":"worker"}}}`)
		cfg, err := ParseRuntimeConfig(raw)
		if err != nil {
			t.Fatalf("ParseRuntimeConfig: %v", err)
		}
		want := map[string]string{
			"org.opencontainers.image.source": "https://example.com/repo",
			"dev.gfire.role":                  "worker",
		}
		if !maps.Equal(cfg.Labels, want) {
			t.Fatalf("Labels = %v, want %v", cfg.Labels, want)
		}
	})

	for name, raw := range map[string]string{
		"absent": `{"config":{}}`,
		"null":   `{"config":{"Labels":null}}`,
		"empty":  `{"config":{"Labels":{}}}`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := ParseRuntimeConfig([]byte(raw))
			if err != nil {
				t.Fatalf("ParseRuntimeConfig: %v", err)
			}
			if cfg.Labels != nil {
				t.Errorf("Labels = %#v, want nil", cfg.Labels)
			}
		})
	}
}

func newLabeledTestImage(t testing.TB, arch string, labels map[string]string) *testImage {
	t.Helper()
	rawLayer := buildTar(t, dirEntry("etc/"), fileEntry("etc/os-release", "labeled-"+arch))
	blob := gzipBytes(t, rawLayer)
	img := &testImage{
		arch:      arch,
		rawLayers: [][]byte{rawLayer},
		blobs:     [][]byte{blob},
	}
	cfgObj := map[string]any{
		"architecture": arch,
		"os":           "linux",
		"config": map[string]any{
			"Cmd":        []string{"/bin/true"},
			"WorkingDir": "/app",
			"Labels":     labels,
		},
		"rootfs": map[string]any{
			"type":     "layers",
			"diff_ids": []string{sha256Digest(rawLayer)},
		},
	}
	var err error
	if img.config, err = json.Marshal(cfgObj); err != nil {
		t.Fatal(err)
	}
	img.manifest, err = json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    digest.FromBytes(img.config),
			Size:      int64(len(img.config)),
		},
		Layers: []ocispec.Descriptor{{
			MediaType: ocispec.MediaTypeImageLayerGzip,
			Digest:    digest.FromBytes(blob),
			Size:      int64(len(blob)),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestResolvedImageExposesLabelsAndConfigDigestAcrossPaths(t *testing.T) {
	wantLabels := map[string]string{
		"org.opencontainers.image.title": "demo",
		"com.example.tier":               "edge",
	}
	testImg := newLabeledTestImage(t, "amd64", wantLabels)
	wantConfigDigest := sha256Digest(testImg.config)

	assertMeta := func(t *testing.T, img *ResolvedImage) {
		t.Helper()
		if img.ConfigDigest != wantConfigDigest {
			t.Errorf("ConfigDigest = %q, want %q", img.ConfigDigest, wantConfigDigest)
		}
		if !maps.Equal(img.Config.Labels, wantLabels) {
			t.Errorf("Config.Labels = %v, want %v", img.Config.Labels, wantLabels)
		}
	}

	t.Run("registry pull, cache load, import, and inspect", func(t *testing.T) {
		reg := newFakeRegistry(t)
		reg.tag("v1", reg.addImage(testImg))
		base, repo := pullArgs(reg)

		cache := newCache(t)
		pulled, err := PullRegistryImage(context.Background(), nil, base, repo, "v1", "amd64", cache)
		if err != nil {
			t.Fatalf("PullRegistryImage: %v", err)
		}
		defer pulled.Close()
		assertMeta(t, pulled)

		cached, err := cache.LoadCachedImage(base, repo, "v1", "amd64")
		if err != nil {
			t.Fatalf("LoadCachedImage: %v", err)
		}
		defer cached.Close()
		assertMeta(t, cached)

		dstCache := newCache(t)
		imported, err := dstCache.ImportCachedImage(cache, base, repo, "v1", "amd64")
		if err != nil {
			t.Fatalf("ImportCachedImage: %v", err)
		}
		defer imported.Close()
		assertMeta(t, imported)

		listed, err := cache.ListImages("amd64")
		if err != nil {
			t.Fatalf("ListImages: %v", err)
		}
		if len(listed) != 1 {
			t.Fatalf("ListImages returned %d images, want 1", len(listed))
		}
		if listed[0].ID != pulled.ConfigDigest {
			t.Errorf("Image.ID = %q, want ConfigDigest %q", listed[0].ID, pulled.ConfigDigest)
		}
		if !maps.Equal(listed[0].Config.Labels, wantLabels) {
			t.Errorf("Image.Config.Labels = %v, want %v", listed[0].Config.Labels, wantLabels)
		}
	})

	t.Run("oci layout archive", func(t *testing.T) {
		archiveBytes := writeArchive(t, ociLayoutMembers(t, testImg))
		img, err := LoadArchiveTar(bytes.NewReader(archiveBytes), newCache(t), "amd64")
		if err != nil {
			t.Fatalf("LoadArchiveTar(oci-layout): %v", err)
		}
		defer img.Close()
		assertMeta(t, img)
	})

	t.Run("docker save archive", func(t *testing.T) {
		archiveBytes := writeArchive(t, dockerSaveMembers(t, testImg))
		img, err := LoadArchiveTar(bytes.NewReader(archiveBytes), newCache(t), "amd64")
		if err != nil {
			t.Fatalf("LoadArchiveTar(docker-save): %v", err)
		}
		defer img.Close()
		assertMeta(t, img)
	})

	t.Run("plain rootfs tarball", func(t *testing.T) {
		rootfs := buildTar(t, fileEntry("hello", "world"))
		img, err := LoadArchiveTar(bytes.NewReader(rootfs), newCache(t), "amd64")
		if err != nil {
			t.Fatalf("LoadArchiveTar(rootfs): %v", err)
		}
		defer img.Close()
		if img.ConfigDigest != "" {
			t.Errorf("ConfigDigest = %q, want empty for plain rootfs", img.ConfigDigest)
		}
		if img.Config.Labels != nil {
			t.Errorf("Config.Labels = %#v, want nil for plain rootfs", img.Config.Labels)
		}
	})
}
