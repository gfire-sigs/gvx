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
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCompileAndStoreVerifiesAndRecordsIntegrity(t *testing.T) {
	raw := buildTar(t, dirEntry("d/"), fileEntry("d/f", "payload"))
	blob := gzipBytes(t, raw)
	digest := sha256Digest(blob)
	cache := newCache(t)

	path, stats, err := cache.CompileAndStore(digest, bytes.NewReader(blob))
	if err != nil {
		t.Fatalf("CompileAndStore: %v", err)
	}
	want, _ := cache.LayerPath(digest)
	if path != want {
		t.Errorf("path = %q, want %q", path, want)
	}
	hexStr := strings.TrimPrefix(digest, "sha256:")
	record, err := os.ReadFile(filepath.Join(cache.Dir(), hexStr+cache.sumSuffix()))
	if err != nil {
		t.Fatalf("integrity record: %v", err)
	}
	if size, sum, err := cache.parseSumRecord(record); err != nil || size != stats.TotalBytes || sum != stats.SHA256Hex {
		t.Errorf("record = %q (size %d sum %s err %v), stats %+v", record, size, sum, err, stats)
	}
	if p, ok := cache.HasLayer(digest); !ok || p != path {
		t.Errorf("HasLayer = %q, %v", p, ok)
	}
	handles, err := cache.OpenLayerHandles([]string{digest, hexStr})
	if err != nil {
		t.Fatalf("OpenLayerHandles: %v", err)
	}
	if err := CloseLayerFiles(handles); err != nil {
		t.Fatal(err)
	}
	if string(readImage(t, path)["/d/f"].content) != "payload" {
		t.Error("cached image content differs")
	}
	assertNoTempFiles(t, cache.Dir())
}

func TestCompileAndStoreRejectsWrongDigestsWithoutStoringAnything(t *testing.T) {
	raw := buildTar(t, fileEntry("f", "payload"))
	cache := newCache(t)
	wrong := sha256Digest([]byte("something else"))

	if _, _, err := cache.CompileAndStore(wrong, bytes.NewReader(raw)); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("wrong digest: err = %v, want ErrDigestMismatch", err)
	}
	// Bytes after the end of the tar archive are part of the digest.
	good := sha256Digest(raw)
	if _, _, err := cache.CompileAndStore(good, bytes.NewReader(append(raw, "trailing"...))); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("trailing bytes: err = %v, want ErrDigestMismatch", err)
	}
	for _, bad := range []string{"sha256:xyz", "sha256:abcd", "../../etc/passwd"} {
		if _, _, err := cache.CompileAndStore(bad, bytes.NewReader(raw)); err == nil {
			t.Errorf("CompileAndStore accepted the digest %q", bad)
		}
	}
	entries, err := os.ReadDir(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("failed stores left %d files in the cache", len(entries))
	}
}

func TestCompileAndStoreNamesUnlabeledLayersByImageDigest(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, fileEntry("f", "x"))
	path, stats, err := cache.CompileAndStore("", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(path) != stats.SHA256Hex+cache.layerSuffix() {
		t.Errorf("path %q is not named by the image digest %s", path, stats.SHA256Hex)
	}
	if _, ok := cache.HasLayer(stats.SHA256Hex); !ok {
		t.Error("the unlabeled layer is not found by its image digest")
	}
}

func TestLayerCacheVerifiesOnFirstReusePerProcess(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, fileEntry("f", strings.Repeat("x", 9000)))
	_, stats, err := cache.CompileAndStore("", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	hexStr := stats.SHA256Hex
	p, _ := cache.LayerPath(hexStr)

	// Same size, different content, as a bit flip would be.
	flip := func() {
		f, err := os.OpenFile(p, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		var b [1]byte
		if _, err := f.ReadAt(b[:], 1500); err != nil {
			t.Fatal(err)
		}
		b[0] ^= 0xFF
		if _, err := f.WriteAt(b[:], 1500); err != nil {
			t.Fatal(err)
		}
	}
	flip()
	if err := os.Chtimes(p, time.Now(), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	if _, ok := cache.HasLayer(hexStr); ok {
		t.Error("the same process kept trusting a layer whose file changed")
	}
	fresh, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HasLayer(hexStr); ok {
		t.Error("a new process trusted a bit-flipped layer")
	}
	if _, err := fresh.OpenLayerHandles([]string{hexStr}); !errors.Is(err, ErrCacheCorrupt) {
		t.Errorf("OpenLayerHandles err = %v, want ErrCacheCorrupt", err)
	}

	// Truncation and garbage records are caught too.
	flip()
	if err := os.Truncate(p, 100); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HasLayer(hexStr); ok {
		t.Error("a truncated layer was trusted")
	}
	if err := os.WriteFile(filepath.Join(cache.Dir(), hexStr+cache.sumSuffix()), []byte("garbage\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HasLayer(hexStr); ok {
		t.Error("a layer with a garbage integrity record was trusted")
	}

	// Compiling again repairs the entry.
	if _, _, err := fresh.CompileAndStore(hexStr, bytes.NewReader(raw)); err == nil {
		t.Error("compiling with the image digest as the stream digest should fail")
	}
	if _, _, err := fresh.CompileAndStore("", bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HasLayer(hexStr); !ok {
		t.Error("recompiling did not repair the layer")
	}
}

func TestLayerCacheIgnoresRecordsOfOtherCompilerVersions(t *testing.T) {
	cache := newCache(t)
	_, stats, err := cache.CompileAndStore("", bytes.NewReader(buildTar(t, fileEntry("f", "x"))))
	if err != nil {
		t.Fatal(err)
	}
	record := strings.Replace(string(cache.formatSumRecord(stats.TotalBytes, stats.SHA256Hex)), cache.format(), "gvx-erofs-v1", 1)
	if err := os.WriteFile(filepath.Join(cache.Dir(), stats.SHA256Hex+cache.sumSuffix()), []byte(record), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, _ := newCacheAt(cache.Dir())
	if _, ok := fresh.HasLayer(stats.SHA256Hex); ok {
		t.Error("a layer from another compiler version was reused")
	}
}

func TestLayerCacheToleratesConcurrentCompiles(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, dirEntry("d/"), fileEntry("d/f", strings.Repeat("c", 20000)))
	blob := gzipBytes(t, raw)
	digest := sha256Digest(blob)

	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := newCacheAt(cache.Dir())
			if err != nil {
				errs <- err
				return
			}
			p, _, err := c.CompileAndStore(digest, bytes.NewReader(blob))
			if err != nil {
				errs <- err
				return
			}
			files, err := c.OpenLayerHandles([]string{digest})
			if err != nil {
				errs <- err
				return
			}
			defer func() {
				_ = CloseLayerFiles(files)
			}()
			openedInfo, err := files[0].Stat()
			if err != nil {
				errs <- err
				return
			}
			pathInfo, err := os.Stat(p)
			if err != nil {
				errs <- err
				return
			}
			if !os.SameFile(openedInfo, pathInfo) {
				errs <- errors.New("layer file identity changed between OpenLayerHandles and Stat")
				return
			}
			errs <- nil
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent CompileAndStore: %v", err)
		}
	}
	fresh, _ := newCacheAt(cache.Dir())
	if _, ok := fresh.HasLayer(digest); !ok {
		t.Error("the layer is not valid after concurrent compiles")
	}
	assertNoTempFiles(t, cache.Dir())
}

func TestSetLimitsRejectsNonPositiveBudgets(t *testing.T) {
	cache := newCache(t)
	lim := DefaultLimits()
	lim.MaxLayerBytes = 0
	if err := cache.SetLimits(lim); err == nil {
		t.Error("SetLimits accepted a zero budget")
	}
	if err := cache.SetLimits(DefaultLimits()); err != nil {
		t.Errorf("SetLimits(DefaultLimits()) = %v", err)
	}
}

func TestLayerCacheNeverReadsOrReplacesOtherFormatsFiles(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, fileEntry("f", "x"))
	blob := gzipBytes(t, raw)
	digest := sha256Digest(blob)
	hexStr := strings.TrimPrefix(digest, "sha256:")

	// An older tree left a layer under the unversioned name, without a record.
	old := filepath.Join(cache.Dir(), hexStr+".erofs")
	oldContent := bytes.Repeat([]byte{0x5A}, 2*testBlockSize)
	if err := os.WriteFile(old, oldContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := cache.HasLayer(digest); ok {
		t.Error("a layer in the older unversioned format was reused")
	}
	path, _, err := cache.CompileAndStore(digest, bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	if path == old {
		t.Fatal("the new layer replaced the older tree's file")
	}
	if got, err := os.ReadFile(old); err != nil || !bytes.Equal(got, oldContent) {
		t.Errorf("the older tree's file changed (err %v)", err)
	}
	if _, ok := cache.HasLayer(digest); !ok {
		t.Error("the recompiled layer is not served")
	}
}
