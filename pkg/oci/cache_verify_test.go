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
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSiblingIDSidecarKeepsThreeFieldSumAndFastPathVsAlwaysVerify(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, dirEntry("d/"), fileEntry("d/f", strings.Repeat("payload", 2000)))
	path, stats, err := cache.CompileAndStore("", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("CompileAndStore: %v", err)
	}
	hexStr := stats.SHA256Hex

	// Verify .sum stays strictly 3-field for v0.24 backward compatibility.
	sumRaw, err := os.ReadFile(cache.sumPath(hexStr))
	if err != nil {
		t.Fatalf("read .sum: %v", err)
	}
	if fields := strings.Fields(string(sumRaw)); len(fields) != 3 {
		t.Fatalf(".sum has %d fields (%q), want strictly 3", len(fields), string(sumRaw))
	}

	// Verify sibling .id sidecar exists and matches the real open file identity.
	f, err := openShared(path)
	if err != nil {
		t.Fatalf("openShared: %v", err)
	}
	realID, hasID := fileIdentity(f)
	_ = f.Close()
	if !hasID {
		t.Skip("filesystem does not expose stable file identity")
	}
	idRaw, err := os.ReadFile(cache.idPath(hexStr))
	if err != nil {
		t.Fatalf("read .id: %v", err)
	}
	idSize, idSum, idToken, err := cache.parseIDRecord(idRaw)
	if err != nil {
		t.Fatalf("parseIDRecord(%q): %v", string(idRaw), err)
	}
	if idSize != stats.TotalBytes || idSum != stats.SHA256Hex || idToken != realID.token {
		t.Fatalf(".id = (%d, %s, %s), want (%d, %s, %s)", idSize, idSum, idToken, stats.TotalBytes, stats.SHA256Hex, realID.token)
	}

	// Falsifiable proof that default fresh cache trusts matching (.sum, .id)
	// without hashing payload bytes, while AlwaysVerify: true hashes in full:
	// point both .sum and .id at a different valid SHA-256 while preserving the
	// real file's identity token.
	fakeSum := strings.Repeat("a", 64)
	if fakeSum == stats.SHA256Hex {
		fakeSum = strings.Repeat("b", 64)
	}
	if err := os.WriteFile(cache.sumPath(hexStr), cache.formatSumRecord(stats.TotalBytes, fakeSum), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.idPath(hexStr), cache.formatIDRecord(stats.TotalBytes, fakeSum, realID.token), 0o644); err != nil {
		t.Fatal(err)
	}

	if realID.trustableAt(time.Now()) {
		fastCache, err := NewLayerCacheWithOptions(cache.Dir(), CacheOptions{BlockSize: cache.BlockSize()})
		if err != nil {
			t.Fatal(err)
		}
		files, err := fastCache.OpenLayerHandles([]string{hexStr})
		if err != nil {
			t.Fatalf("default LayerCache did not use .id fast path: %v", err)
		}
		_ = CloseLayerFiles(files)
	}

	strictCache, err := NewLayerCacheWithOptions(cache.Dir(), CacheOptions{
		BlockSize:    cache.BlockSize(),
		AlwaysVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strictCache.AlwaysVerify() {
		t.Error("AlwaysVerify() = false, want true")
	}
	if _, err := strictCache.OpenLayerHandles([]string{hexStr}); !errors.Is(err, ErrCacheCorrupt) {
		t.Fatalf("AlwaysVerify LayerCache err = %v, want ErrCacheCorrupt", err)
	}
}

func TestSiblingIDSidecarInvalidationLazyUpgradeAndReadOnlyCache(t *testing.T) {
	cache := newCache(t)
	raw := buildTar(t, fileEntry("f", strings.Repeat("z", 10000)))
	p, stats, err := cache.CompileAndStore("", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	hexStr := stats.SHA256Hex

	// 1. Missing .id (v0.24 cache) falls back to full SHA-256 and lazily creates .id.
	if err := os.Remove(cache.idPath(hexStr)); err != nil {
		t.Fatal(err)
	}
	fresh, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh.HasLayer(hexStr); !ok {
		t.Fatal("HasLayer failed without .id sidecar")
	}
	if _, err := os.Stat(cache.idPath(hexStr)); err != nil {
		t.Errorf("lazy .id upgrade did not recreate sidecar: %v", err)
	}

	// 2. Malformed .id and well-formed stale .id (wrong token or wrong digest)
	// fall back to full SHA-256 and self-repair .id.
	for _, tc := range []struct {
		name string
		raw  []byte
	}{
		{"malformed", []byte("corrupt-id\n")},
		{"stale token", cache.formatIDRecord(stats.TotalBytes, stats.SHA256Hex, "u1:999:999:1:1:1:1")},
		{"stale digest", cache.formatIDRecord(stats.TotalBytes, strings.Repeat("d", 64), "u1:1:1:1:1:1:1")},
	} {
		if err := os.WriteFile(cache.idPath(hexStr), tc.raw, 0o644); err != nil {
			t.Fatal(err)
		}
		freshRepair, err := newCacheAt(cache.Dir())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := freshRepair.HasLayer(hexStr); !ok {
			t.Fatalf("HasLayer failed with %s .id sidecar", tc.name)
		}
		if rawID, err := os.ReadFile(cache.idPath(hexStr)); err != nil {
			t.Fatal(err)
		} else if _, gotSum, gotTok, perr := freshRepair.parseIDRecord(rawID); perr != nil || gotSum != stats.SHA256Hex || gotTok == "u1:999:999:1:1:1:1" {
			t.Errorf("repaired .id after %s = (%q, err=%v)", tc.name, string(rawID), perr)
		}
	}

	// 2b. Missing .sum with a valid .id present must still fail with ErrCacheCorrupt.
	sumBackup, err := os.ReadFile(cache.sumPath(hexStr))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cache.sumPath(hexStr)); err != nil {
		t.Fatal(err)
	}
	noSumCache, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noSumCache.OpenLayerHandles([]string{hexStr}); !errors.Is(err, ErrCacheCorrupt) {
		t.Errorf("missing .sum with valid .id: err = %v, want ErrCacheCorrupt", err)
	}
	if err := os.WriteFile(cache.sumPath(hexStr), sumBackup, 0o644); err != nil {
		t.Fatal(err)
	}

	// 3. Same-size bit flip with mtime restored to original still changes ctime
	// on Unix and ChangeTime on Windows, so both same-process and fresh caches
	// reject it and evict c.verified.
	fresh2, err := newCacheAt(cache.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := fresh2.HasLayer(hexStr); !ok {
		t.Fatal("HasLayer failed before tamper check")
	}
	beforeFile, err := openShared(p)
	if err != nil {
		t.Fatal(err)
	}
	beforeID, hasID := fileIdentity(beforeFile)
	_ = beforeFile.Close()
	if hasID {
		origInfo, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		origMod := origInfo.ModTime()
		if f, err := os.OpenFile(p, os.O_RDWR, 0); err != nil {
			t.Fatal(err)
		} else {
			var b [1]byte
			if _, err := f.ReadAt(b[:], 512); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			b[0] ^= 0xFF
			if _, err := f.WriteAt(b[:], 512); err != nil {
				_ = f.Close()
				t.Fatal(err)
			}
			_ = f.Close()
		}
		// Advance past coarse kernel clock ticks (e.g., Linux CONFIG_HZ=250 4ms
		// jiffy or Windows 15.625ms tick) while keeping mtime equal to origMod.
		var ctimeAdvanced bool
		for range 50 {
			if err := os.Chtimes(p, origMod, origMod); err != nil {
				t.Fatal(err)
			}
			probe, err := openShared(p)
			if err != nil {
				t.Fatal(err)
			}
			afterID, ok := fileIdentity(probe)
			_ = probe.Close()
			if ok && afterID.token != beforeID.token {
				ctimeAdvanced = true
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		if !ctimeAdvanced {
			t.Fatal("ctime/ChangeTime did not advance after in-place write and Chtimes")
		}
		if _, err := fresh2.OpenLayerHandles([]string{hexStr}); !errors.Is(err, ErrCacheCorrupt) {
			t.Errorf("same-process tampered layer with restored mtime: err = %v, want ErrCacheCorrupt", err)
		}
		fresh2.mu.Lock()
		_, stillCached := fresh2.verified[hexStr]
		fresh2.mu.Unlock()
		if stillCached {
			t.Error("corrupt layer was not evicted from c.verified")
		}
		fresh3, err := newCacheAt(cache.Dir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh3.OpenLayerHandles([]string{hexStr}); !errors.Is(err, ErrCacheCorrupt) {
			t.Errorf("fresh-process tampered layer with restored mtime: err = %v, want ErrCacheCorrupt", err)
		}

		// Repair the layer for read-only cache dir check.
		if _, _, err := fresh3.CompileAndStore("", bytes.NewReader(raw)); err != nil {
			t.Fatal(err)
		}
	}

	// 4. Read-only cache directory (Unix non-root): missing .id verifies cleanly
	// without failing on sidecar write.
	if runtime.GOOS != "windows" && os.Geteuid() != 0 {
		if err := os.Remove(cache.idPath(hexStr)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(cache.Dir(), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(cache.Dir(), 0o755) })
		roCache, err := newCacheAt(cache.Dir())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := roCache.HasLayer(hexStr); !ok {
			t.Error("HasLayer failed on read-only cache directory when .id is absent")
		}
		assertNoTempFiles(t, cache.Dir())
	}
}

func TestFileIDCoarseRacyCleanGuard(t *testing.T) {
	now := time.Unix(1_700_000_100, 500_000_000)

	if (fileID{}).trustableAt(now) {
		t.Error("empty fileID trusted")
	}
	subsec := fileID{token: "u1:1:2:1:1:1:1", coarse: false, changeTime: now}
	if !subsec.trustableAt(now) {
		t.Error("sub-second fileID rejected at current instant")
	}
	coarseRecent := fileID{token: "u1:1:2:1:0:1:0", coarse: true, changeTime: now.Add(-time.Second)}
	if coarseRecent.trustableAt(now) {
		t.Error("coarse fileID within 2s past window was trusted")
	}
	coarseFuture := fileID{token: "u1:1:2:1:0:1:0", coarse: true, changeTime: now.Add(time.Second)}
	if coarseFuture.trustableAt(now) {
		t.Error("coarse fileID within 2s future skew window was trusted")
	}
	coarseOld := fileID{token: "u1:1:2:1:0:1:0", coarse: true, changeTime: now.Add(-3 * time.Second)}
	if !coarseOld.trustableAt(now) {
		t.Error("coarse fileID older than 2s was rejected")
	}
}

func TestImportLayerStampsOwnIDAndPruneRemovesIDSidecars(t *testing.T) {
	reg := newFakeRegistry(t)
	img := twoLayerImage(t, "amd64", "A=1")
	reg.tag("v1", reg.addImage(img))
	src := newCache(t)
	mustPull(t, reg, src, "v1", "amd64")
	base, repo := pullArgs(reg)

	dst := newCache(t)
	got, err := dst.ImportCachedImage(src, base, repo, "v1", "amd64")
	if err != nil {
		t.Fatalf("ImportCachedImage: %v", err)
	}
	_ = got.Close()

	for _, hexStr := range got.LayerDigests {
		srcIDRaw, err := os.ReadFile(src.idPath(hexStr))
		if err != nil {
			t.Fatalf("src .id missing for %s: %v", hexStr, err)
		}
		dstIDRaw, err := os.ReadFile(dst.idPath(hexStr))
		if err != nil {
			t.Fatalf("dst .id missing for %s: %v", hexStr, err)
		}
		_, _, srcTok, err := src.parseIDRecord(srcIDRaw)
		if err != nil {
			t.Fatalf("parse src .id: %v", err)
		}
		_, _, dstTok, err := dst.parseIDRecord(dstIDRaw)
		if err != nil {
			t.Fatalf("parse dst .id: %v", err)
		}
		if srcTok == dstTok {
			t.Errorf("imported layer %s copied src .id token %q instead of stamping dst file", hexStr, dstTok)
		}
	}

	// Active image whose .erofs was deleted while .id remains: DiskUsage counts
	// the orphaned .id as reclaimable and PruneImages removes it even without All.
	missingLayerHex := got.LayerDigests[0]
	missingLayerPath, err := dst.LayerPath(missingLayerHex)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(missingLayerPath); err != nil {
		t.Fatal(err)
	}
	duMissing, err := dst.DiskUsage()
	if err != nil {
		t.Fatal(err)
	}
	if duMissing.ReclaimableBytes <= 0 {
		t.Errorf("DiskUsage.ReclaimableBytes with orphaned active .id = %d, want > 0", duMissing.ReclaimableBytes)
	}
	if _, err := dst.PruneImages(PruneOptions{Arch: "amd64"}); err != nil {
		t.Fatalf("PruneImages(dangling): %v", err)
	}
	if _, err := os.Stat(dst.idPath(missingLayerHex)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("PruneImages left .id behind when sibling .erofs was missing (err=%v)", err)
	}

	// Removing the image deletes remaining .erofs, .sum, and .id sidecars.
	images, err := dst.ListImages("amd64")
	if err != nil || len(images) != 1 {
		t.Fatalf("ListImages = %d, err %v", len(images), err)
	}
	if _, err := dst.Remove(images[0]); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	for _, hexStr := range got.LayerDigests {
		if _, err := os.Stat(dst.idPath(hexStr)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Remove left .id sidecar %s behind (err=%v)", dst.idPath(hexStr), err)
		}
	}

	// PruneImages sweeps orphaned .id files and DiskUsage accounts for them.
	orphanID := filepath.Join(dst.Dir(), strings.Repeat("c", 64)+dst.idSuffix())
	if err := os.WriteFile(orphanID, []byte("orphan\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	du, err := dst.DiskUsage()
	if err != nil {
		t.Fatal(err)
	}
	if du.ReclaimableBytes < int64(len("orphan\n")) {
		t.Errorf("DiskUsage.ReclaimableBytes = %d, want >= %d", du.ReclaimableBytes, len("orphan\n"))
	}
	if _, err := dst.PruneImages(PruneOptions{Arch: "amd64", All: true}); err != nil {
		t.Fatalf("PruneImages: %v", err)
	}
	if _, err := os.Stat(orphanID); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("PruneImages left orphaned .id file behind (err=%v)", err)
	}
}

func TestCacheOptionsValidationConcurrentSafetyAndBoundedMaps(t *testing.T) {
	dir := t.TempDir()
	// Non-zero partial Limits must fail validation in NewLayerCacheWithOptions.
	if _, err := NewLayerCacheWithOptions(dir, CacheOptions{
		Limits: Limits{MaxBlobBytes: 1024},
	}); err == nil {
		t.Fatal("NewLayerCacheWithOptions accepted invalid partial Limits")
	}

	dns := []netip.AddrPort{netip.MustParseAddrPort("1.1.1.1:53")}
	cache, err := NewLayerCacheWithOptions(dir, CacheOptions{
		BlockSize:  testBlockSize,
		KeepBlobs:  true,
		Limits:     DefaultLimits(),
		DNSServers: dns,
	})
	if err != nil {
		t.Fatalf("NewLayerCacheWithOptions: %v", err)
	}
	if got := cache.getDNSServers(); len(got) != 1 || got[0] != dns[0] {
		t.Errorf("getDNSServers = %v, want %v", got, dns)
	}

	// Concurrent readers/writers on one shared LayerCache must be race-free.
	raw := buildTar(t, fileEntry("hello", "world"))
	_, stats, err := cache.CompileAndStore("", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 12)
	for i := range 6 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for range 10 {
				if err := cache.SetLimits(DefaultLimits()); err != nil {
					errs <- err
					return
				}
				cache.SetDNSServers(dns)
				cache.SetKeepBlobs(i%2 == 0)
			}
		}(i)
		go func() {
			defer wg.Done()
			for range 10 {
				files, err := cache.OpenLayerHandles([]string{stats.SHA256Hex})
				if err != nil {
					errs <- err
					return
				}
				_ = CloseLayerFiles(files)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent shared LayerCache failed: %v", err)
	}

	// Verify in-memory maps stay bounded at maxVerifiedCacheEntries.
	sampleInfo, err := os.Stat(filepath.Join(cache.Dir(), stats.SHA256Hex+cache.layerSuffix()))
	if err != nil {
		t.Fatal(err)
	}
	for i := range maxVerifiedCacheEntries + 32 {
		key := strconv.Itoa(i)
		cache.recordVerified(key, 4096, time.Now(), fileID{token: "t" + key})
		cache.recordVerifiedBlob(key, sampleInfo)
	}
	cache.mu.Lock()
	nLayers := len(cache.verified)
	nBlobs := len(cache.verifiedBlobs)
	cache.mu.Unlock()
	if nLayers > maxVerifiedCacheEntries {
		t.Errorf("len(cache.verified) = %d, want <= %d", nLayers, maxVerifiedCacheEntries)
	}
	if nBlobs > maxVerifiedCacheEntries {
		t.Errorf("len(cache.verifiedBlobs) = %d, want <= %d", nBlobs, maxVerifiedCacheEntries)
	}
}
