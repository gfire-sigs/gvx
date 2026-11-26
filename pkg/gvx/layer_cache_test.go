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

package gvx

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"z.gfire.dev/gvx/pkg/gvx/tuning"
	"z.gfire.dev/gvx/pkg/hostarch"
	"z.gfire.dev/gvx/pkg/oci"
)

func buildMinimalLayerTar(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(body)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestConfigNormalizeLayerCacheValidation(t *testing.T) {
	dir := t.TempDir()
	cache, err := NewLayerCacheWithOptions(dir, oci.CacheOptions{
		KeepBlobs:    true,
		AlwaysVerify: true,
	}, tuning.Values{})
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions: %v", err)
	}
	if cache.BlockSize() != int(hostarch.PageSize) {
		t.Errorf("BlockSize = %d, want %d", cache.BlockSize(), hostarch.PageSize)
	}
	if !cache.KeepBlobs() || !cache.AlwaysVerify() {
		t.Errorf("KeepBlobs=%v AlwaysVerify=%v, want both true", cache.KeepBlobs(), cache.AlwaysVerify())
	}

	ociTuned, err := tuning.Values{}.Set("oci.max_blob_bytes", "64MiB")
	if err != nil {
		t.Fatal(err)
	}
	netTuned, err := tuning.Values{}.Set("net.nat.mtu", "1400")
	if err != nil {
		t.Fatal(err)
	}

	bad := []struct {
		name string
		cfg  Config
	}{
		{"zero LayerCache", Config{LayerCache: &oci.LayerCache{}}},
		{"LayerCache with OCICacheDir", Config{LayerCache: cache, OCICacheDir: dir}},
		{"LayerCache with OCIKeepBlobs", Config{LayerCache: cache, OCIKeepBlobs: true}},
		{"LayerCache with oci.* Tuning", Config{LayerCache: cache, Tuning: ociTuned}},
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("normalize() = %v, want ErrInvalidConfig", err)
			}
		})
	}

	// Non-oci.* tunables combine cleanly with LayerCache.
	good := Config{LayerCache: cache, Tuning: netTuned}
	if err := good.normalize(); err != nil {
		t.Fatalf("normalize() with LayerCache and net.* tuning: %v", err)
	}
	// VolumeDir must NOT inherit LayerCache.Dir() (shared cache may be read-only).
	volDir, err := good.volumeRootWithMigrate(false)
	if err != nil {
		t.Fatalf("volumeRootWithMigrate(false): %v", err)
	}
	if volDir == filepath.Join(cache.Dir(), "volumes") {
		t.Errorf("volumeRootWithMigrate(false) = %q inherited LayerCache.Dir()", volDir)
	}

	// On hosts where Sentry page size exceeds oci.MinBlockSize (such as 16 KiB
	// darwin/arm64), normalize() rejects a misaligned LayerCache block size.
	if int(hostarch.PageSize) > oci.MinBlockSize {
		smallCache, err := oci.NewLayerCacheWithOptions(t.TempDir(), oci.CacheOptions{BlockSize: oci.MinBlockSize})
		if err != nil {
			t.Fatal(err)
		}
		badBS := Config{LayerCache: smallCache}
		if err := badBS.normalize(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("misaligned BlockSize normalize() = %v, want ErrInvalidConfig", err)
		}
	}

	// Verify NewLayerCacheWithOptions derives Limits from oci.* tunables when
	// opts.Limits is zero, and honors explicit opts.Limits over tuning.
	tinyTuned, err := tuning.Values{}.WithSize(tuning.OCIMaxBlobBytes, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	tunedCache, err := NewLayerCacheWithOptions(t.TempDir(), oci.CacheOptions{}, tinyTuned)
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions with tuning: %v", err)
	}
	bigBlob := bytes.Repeat([]byte{0}, (1<<20)+1024)
	if _, _, err := tunedCache.CompileAndStore("", bytes.NewReader(bigBlob)); !errors.Is(err, oci.ErrLimitExceeded) {
		t.Errorf("tunedCache over MaxBlobBytes: err = %v, want ErrLimitExceeded", err)
	}
	explicitLimits := oci.DefaultLimits()
	explicitLimits.MaxBlobBytes = 256
	overrideCache, err := NewLayerCacheWithOptions(t.TempDir(), oci.CacheOptions{Limits: explicitLimits}, tinyTuned)
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions with explicit Limits: %v", err)
	}
	if _, _, err := overrideCache.CompileAndStore("", bytes.NewReader(buildMinimalLayerTar(t, "x", "hello"))); !errors.Is(err, oci.ErrLimitExceeded) {
		t.Errorf("overrideCache over explicit MaxBlobBytes: err = %v, want ErrLimitExceeded", err)
	}

	// Regression: cold-cache loadCachedReference with a valid non-default
	// BlockSize (e.g., 2 * PageSize) returns oci.ErrNotCached instead of a
	// block-size mismatch error when probing the default host cache.
	altBS := 2 * int(hostarch.PageSize)
	if altBS <= oci.MaxBlockSize {
		altCache, err := NewLayerCacheWithOptions(t.TempDir(), oci.CacheOptions{BlockSize: altBS}, tuning.Values{})
		if err != nil {
			t.Fatalf("NewLayerCacheWithOptions(BlockSize=%d): %v", altBS, err)
		}
		_, err = loadCachedReference(altCache, registryRequest{
			baseURL: "https://registry-1.docker.io",
			repo:    "library/nonexistent-gvx-test-image",
			tag:     "missing",
			arch:    "amd64",
		})
		if !errors.Is(err, oci.ErrNotCached) {
			t.Errorf("loadCachedReference with BlockSize=%d: err = %v, want oci.ErrNotCached", altBS, err)
		}
	}
}

func TestSharedLayerCacheConcurrentSandboxesAndRestore(t *testing.T) {
	cacheDir := t.TempDir()
	cache, err := NewLayerCacheWithOptions(cacheDir, oci.CacheOptions{}, tuning.Values{})
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions: %v", err)
	}

	layerA := buildMinimalLayerTar(t, "a.txt", "layer-alpha")
	layerB := buildMinimalLayerTar(t, "b.txt", "layer-beta")
	_, statsA, err := cache.CompileAndStore("", bytes.NewReader(layerA))
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	errs := make(chan error, 3)

	runInit := func(tarBytes []byte) {
		defer wg.Done()
		cfg := Config{
			LayerCache:   cache,
			OCILayerTars: [][]byte{tarBytes},
		}
		if err := cfg.normalize(); err != nil {
			errs <- err
			return
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.initOCILayers(context.Background()); err != nil {
			errs <- err
			return
		}
		if len(sb.layerHandles) != 1 {
			_ = sb.Close()
			errs <- errors.New("expected 1 opened layer handle")
			return
		}
		if err := sb.Close(); err != nil {
			errs <- err
		}
	}

	runRestoreManifest := func() {
		defer wg.Done()
		cfg := Config{LayerCache: cache}
		if err := cfg.normalizeWithMode(true); err != nil {
			errs <- err
			return
		}
		sb := &Sandbox{cfg: cfg}
		if err := sb.openManifestLayers([]string{statsA.SHA256Hex}); err != nil {
			errs <- err
			return
		}
		if len(sb.layerHandles) != 1 || sb.layerDigests[0] != statsA.SHA256Hex {
			_ = sb.Close()
			errs <- errors.New("openManifestLayers did not open manifest layer from Config.LayerCache")
			return
		}
		if err := sb.Close(); err != nil {
			errs <- err
		}
	}

	wg.Add(3)
	go runInit(layerA)
	go runInit(layerB)
	go runRestoreManifest()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent shared LayerCache usage failed: %v", err)
	}

	// Verify caller-owned LayerCache remains healthy and unmutated after sandboxes close.
	if _, ok := cache.HasLayer(statsA.SHA256Hex); !ok {
		t.Error("shared LayerCache lost layer after sandboxes closed")
	}
}
