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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// compilerVersion names the EROFS output format. A cached layer is valid only
// if its integrity record carries the same version, so a compiler change
// invalidates every layer that an older compiler wrote.
const compilerVersion = "gvx-erofs-v3"

// Cache file names. Layers are <hex>.<format>.erofs with a .sum integrity
// record, where <format> is the compiler version and the block size, for
// example gvx-erofs-v3-b16384. The format in the name keeps trees with other
// compiler versions or block sizes from reading or overwriting these files.
// Image records are image-<key>.json and tag-<key>.json, and their keys also
// cover the format.
const (
	imagePrefix     = "image-"
	tagPrefix       = "tag-"
	cacheJSONSuffix = ".json"
	tempPattern     = "*.tmp"
)

var (
	// ErrNotCached reports that the cache holds no image for a reference.
	ErrNotCached = errors.New("oci: image is not in the layer cache")
	// ErrCacheCorrupt reports that a cached file failed its integrity verification.
	ErrCacheCorrupt = errors.New("oci: cached layer failed its integrity check")
)

// LayerCache stores compiled <sha256>.erofs layer images in a non-TCC host
// cache directory.
type LayerCache struct {
	dir       string
	limits    Limits
	blockSize int

	mu       sync.Mutex
	verified map[string]verifiedLayer
}

// verifiedLayer records a layer that passed its integrity verification in this
// process. The recorded size and modification time detect later replacement.
type verifiedLayer struct {
	size    int64
	modTime time.Time
}

// DefaultCacheDir returns the platform-native non-TCC layer cache directory:
// %LOCALAPPDATA%\gvx\cache\layers on Windows and ~/Library/Caches/gvx/layers on macOS.
func DefaultCacheDir() (string, error) {
	return defaultCacheDirFor(runtime.GOOS, os.Getenv, os.UserCacheDir)
}

// defaultCacheDirFor computes DefaultCacheDir for goos. Windows needs
// %LOCALAPPDATA% and never falls back to a temporary directory.
func defaultCacheDirFor(goos string, getenv func(string) string, userCacheDir func() (string, error)) (string, error) {
	if goos == "windows" {
		localAppData := getenv("LOCALAPPDATA")
		if localAppData == "" {
			return "", errors.New("oci: %LOCALAPPDATA% is not set, so the layer cache directory is unknown")
		}
		return filepath.Join(localAppData, "gvx", "cache", "layers"), nil
	}
	base, err := userCacheDir()
	if err != nil {
		return "", fmt.Errorf("oci: locate the user cache directory: %w", err)
	}
	return filepath.Join(base, "gvx", "layers"), nil
}

// CacheOptions configures a LayerCache. Zero fields select the defaults.
type CacheOptions struct {
	// BlockSize is the EROFS block size of the layers that the cache compiles
	// and serves. It must be a power of two from MinBlockSize to MaxBlockSize.
	// The sentry refuses images whose block size is not a multiple of its page
	// size, so a caller passes at least hostarch.PageSize. Caches with other
	// block sizes keep separate files in the same directory.
	BlockSize int
}

// NewLayerCache creates or opens a LayerCache at dir (or DefaultCacheDir when
// dir is empty). Layers use DefaultBlockSize.
func NewLayerCache(dir string) (*LayerCache, error) {
	return NewLayerCacheWithOptions(dir, CacheOptions{})
}

// NewLayerCacheWithOptions is NewLayerCache with explicit options.
func NewLayerCacheWithOptions(dir string, opts CacheOptions) (*LayerCache, error) {
	bs, err := resolveBlockSize(opts.BlockSize)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(dir) == "" {
		var err error
		dir, err = DefaultCacheDir()
		if err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("oci: create layer cache dir %q: %w", dir, err)
	}
	return &LayerCache{dir: dir, limits: DefaultLimits(), blockSize: bs, verified: make(map[string]verifiedLayer)}, nil
}

// BlockSize returns the EROFS block size of the layers in this cache.
func (c *LayerCache) BlockSize() int {
	return c.blockSize
}

// format names the on-disk format of this cache's layers.
func (c *LayerCache) format() string {
	return compilerVersion + "-b" + strconv.Itoa(c.blockSize)
}

func (c *LayerCache) layerSuffix() string { return "." + c.format() + ".erofs" }
func (c *LayerCache) sumSuffix() string   { return c.layerSuffix() + ".sum" }

// SetLimits replaces the size budgets that the cache applies to pulls and
// layer compilation.
func (c *LayerCache) SetLimits(l Limits) error {
	if err := l.validate(); err != nil {
		return err
	}
	c.limits = l
	return nil
}

// Dir returns the backing directory path of the LayerCache.
func (c *LayerCache) Dir() string {
	return c.dir
}

// LayerPath returns the absolute host path for a cached <digestHex>.erofs file.
func (c *LayerCache) LayerPath(digest string) (string, error) {
	hexStr := normalizeDigestHex(digest)
	if hexStr == "" {
		return "", fmt.Errorf("oci: invalid layer digest %q", digest)
	}
	return filepath.Join(c.dir, hexStr+c.layerSuffix()), nil
}

func (c *LayerCache) sumPath(hexStr string) string {
	return filepath.Join(c.dir, hexStr+c.sumSuffix())
}

// HasLayer reports whether the compiled <digestHex>.erofs layer exists in the
// cache directory and matches its integrity record. The first verification of a
// layer in each process hashes the whole file.
func (c *LayerCache) HasLayer(digest string) (string, bool) {
	p, err := c.LayerPath(digest)
	if err != nil {
		return "", false
	}
	f, err := c.openVerifiedLayer(normalizeDigestHex(digest))
	if err != nil {
		return "", false
	}
	if err := f.Close(); err != nil {
		return "", false
	}
	return p, true
}

// openVerifiedLayer opens a cached layer read-only and verifies it against its
// integrity record, unless this process already verified the same file.
func (c *LayerCache) openVerifiedLayer(hexStr string) (*os.File, error) {
	p := filepath.Join(c.dir, hexStr+c.layerSuffix())
	f, err := openShared(p)
	if err != nil {
		return nil, fmt.Errorf("oci: open cached EROFS layer %q: %w", p, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("oci: stat cached EROFS layer %q: %w", p, err)
	}
	if !info.Mode().IsRegular() || info.Size() < int64(c.blockSize) {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q is not a layer image", ErrCacheCorrupt, p)
	}

	c.mu.Lock()
	v, ok := c.verified[hexStr]
	c.mu.Unlock()
	if ok && v.size == info.Size() && v.modTime.Equal(info.ModTime()) {
		return f, nil
	}

	record, err := readFileShared(c.sumPath(hexStr))
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: read integrity record of %q: %w", ErrCacheCorrupt, p, err)
	}
	wantSize, wantSum, err := c.parseSumRecord(record)
	if err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q: %w", ErrCacheCorrupt, p, err)
	}
	if wantSize != info.Size() {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q has %d bytes, want %d", ErrCacheCorrupt, p, info.Size(), wantSize)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(f, 0, info.Size())); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("oci: hash cached EROFS layer %q: %w", p, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != wantSum {
		_ = f.Close()
		return nil, fmt.Errorf("%w: %q has sha256 %s, want %s", ErrCacheCorrupt, p, got, wantSum)
	}
	c.mu.Lock()
	c.verified[hexStr] = verifiedLayer{size: info.Size(), modTime: info.ModTime()}
	c.mu.Unlock()
	return f, nil
}

func (c *LayerCache) formatSumRecord(size int64, sum string) []byte {
	return []byte(c.format() + " " + strconv.FormatInt(size, 10) + " " + sum + "\n")
}

func (c *LayerCache) parseSumRecord(raw []byte) (size int64, sum string, err error) {
	fields := strings.Fields(string(raw))
	if len(fields) != 3 || fields[0] != c.format() {
		return 0, "", fmt.Errorf("integrity record is not in format %s", c.format())
	}
	size, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 {
		return 0, "", errors.New("integrity record has an invalid size")
	}
	if len(fields[2]) != sha256.Size*2 || normalizeDigestHex(fields[2]) != fields[2] {
		return 0, "", errors.New("integrity record has an invalid digest")
	}
	return size, fields[2], nil
}

// CompileAndStore compiles a layer stream into an EROFS image and atomically
// stores it under <digest>.erofs inside the cache directory. The stream can be
// raw, gzip, or zstd compressed tar. A non-empty digest is the sha256 of the
// stream bytes. A mismatch fails the call and stores nothing. An empty digest
// names the image by the sha256 of the compiled image.
func (c *LayerCache) CompileAndStore(digest string, tarStream io.Reader) (string, CompileStats, error) {
	var hexKey string
	if strings.TrimSpace(digest) != "" {
		if hexKey = normalizeDigestHex(digest); len(hexKey) != sha256.Size*2 {
			return "", CompileStats{}, fmt.Errorf("oci: invalid layer digest %q", digest)
		}
	}
	return c.compileAndStore(layerSpec{key: hexKey, blobHex: hexKey, blobSize: -1}, tarStream)
}

// hashingReader hashes and counts the bytes that pass through it.
type hashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
	}
	return n, err
}

// layerSpec describes what a layer stream must satisfy and how to name its image.
type layerSpec struct {
	// key names the cached image. Empty names it by the sha256 of the image.
	key string
	// blobHex is the expected sha256 of the stream bytes, or empty.
	blobHex string
	// blobSize is the expected stream length, or -1.
	blobSize int64
	// diffID is the expected sha256 of the decompressed tar, or empty.
	diffID string
	// image accumulates the decompressed bytes of all layers of an image.
	image *byteBudget
}

// compileAndStore compiles src into the cache and verifies it against spec.
func (c *LayerCache) compileAndStore(spec layerSpec, src io.Reader) (string, CompileStats, error) {
	hexKey := spec.key
	tmp, err := os.CreateTemp(c.dir, tempPattern)
	if err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: create temp layer file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	// The hash covers every byte that the compiler and the final drain read,
	// so it equals the hash of the whole stream.
	in := &hashingReader{r: newBoundedReader(src, "compressed layer size", c.limits.MaxBlobBytes, nil), h: sha256.New()}
	var diff *diffVerifier
	if spec.diffID != "" {
		diff = newDiffVerifier(spec.diffID)
	}
	stats, err := compileLayer(in, tmp, c.limits, c.blockSize, spec.image, diff)
	if err != nil {
		return "", CompileStats{}, err
	}
	if _, err := io.Copy(io.Discard, in); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: read layer trailer: %w", err)
	}
	if spec.blobSize >= 0 && in.n != spec.blobSize {
		return "", CompileStats{}, fmt.Errorf("%w: layer has %d bytes, descriptor says %d", ErrDigestMismatch, in.n, spec.blobSize)
	}
	if got := hex.EncodeToString(in.h.Sum(nil)); spec.blobHex != "" && got != spec.blobHex {
		return "", CompileStats{}, fmt.Errorf("%w: layer sha256 is %s, want %s", ErrDigestMismatch, got, spec.blobHex)
	}
	if hexKey == "" {
		hexKey = stats.SHA256Hex
	}

	if err := tmp.Sync(); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: sync layer file: %w", err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: stat layer file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: close layer file: %w", err)
	}

	// Write the integrity record first, so that a published image always has one.
	if err := writeFileAtomic(c.dir, hexKey+c.sumSuffix(), c.formatSumRecord(stats.TotalBytes, stats.SHA256Hex)); err != nil {
		return "", CompileStats{}, err
	}
	target := filepath.Join(c.dir, hexKey+c.layerSuffix())
	if err := replaceFile(tmpPath, target); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: rename cached layer %q: %w", target, err)
	}
	committed = true
	c.mu.Lock()
	c.verified[hexKey] = verifiedLayer{size: info.Size(), modTime: info.ModTime()}
	c.mu.Unlock()
	return target, stats, nil
}

// writeFileAtomic writes data to dir/name through a synced temporary file.
func writeFileAtomic(dir, name string, data []byte) error {
	tmp, err := os.CreateTemp(dir, tempPattern)
	if err != nil {
		return fmt.Errorf("oci: create temp file for %q: %w", name, err)
	}
	tmpPath := tmp.Name()
	fail := func(op string, err error) error {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("oci: %s %q: %w", op, name, err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail("write", err)
	}
	if err := tmp.Sync(); err != nil {
		return fail("sync", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("oci: close %q: %w", name, err)
	}
	if err := replaceFile(tmpPath, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("oci: publish %q: %w", name, err)
	}
	return nil
}

// OpenLayerHandles opens read-only *os.File handles for all ordered layer
// digests prior to hostlockdown.Apply(). It fails if a layer is missing or
// fails its integrity verification.
func (c *LayerCache) OpenLayerHandles(digests []string) ([]*os.File, error) {
	files := make([]*os.File, 0, len(digests))
	for _, d := range digests {
		hexStr := normalizeDigestHex(d)
		if hexStr == "" {
			closeAllFiles(files)
			return nil, fmt.Errorf("oci: invalid layer digest %q", d)
		}
		f, err := c.openVerifiedLayer(hexStr)
		if err != nil {
			closeAllFiles(files)
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func closeAllFiles(files []*os.File) {
	for _, f := range files {
		if f != nil {
			_ = f.Close()
		}
	}
}

func normalizeDigestHex(digest string) string {
	digest = strings.TrimSpace(digest)
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) == 0 {
		return ""
	}
	for i := range len(digest) {
		ch := digest[i]
		isHex := (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')
		if !isHex {
			return ""
		}
	}
	return strings.ToLower(digest)
}

// CloseLayerFiles closes a slice of pre-opened *os.File handles.
func CloseLayerFiles(files []*os.File) error {
	var errs []error
	for _, f := range files {
		if f != nil {
			if err := f.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// imageRecord is the on-disk form of a resolved image. It keeps the verbatim
// manifest chain and config, so loading re-verifies every digest.
type imageRecord struct {
	Version      int    `json:"version"`
	BaseURL      string `json:"baseURL"`
	Repository   string `json:"repository"`
	Digest       string `json:"digest"`
	Architecture string `json:"architecture"`
	// Format is the layer format that the image's layers use.
	Format    string   `json:"format"`
	Manifests [][]byte `json:"manifests"`
	Config    []byte   `json:"config"`
	// Source is sourceArchive for an image that came from an archive. Other
	// records came from a registry. Records written before the field existed
	// have none, which means a registry.
	Source string `json:"source,omitempty"`
	// OriginBaseURL and OriginRepository name the registry that holds the
	// original blobs when a tag copied the record to another name.
	OriginBaseURL    string `json:"originBaseURL,omitempty"`
	OriginRepository string `json:"originRepository,omitempty"`
}

const (
	imageRecordVersion = 2
	// sourceArchive marks an image whose original layer blobs are not in any registry.
	sourceArchive = "archive"
)

func cacheKey(format string, parts ...string) string {
	parts = append([]string{format}, parts...)
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

func (c *LayerCache) imageRecordPath(baseURL, repository, digest, arch string) string {
	return filepath.Join(c.dir, imagePrefix+cacheKey(c.format(), strings.ToLower(baseURL), repository, digest, arch)+cacheJSONSuffix)
}

func (c *LayerCache) tagRecordPath(baseURL, repository, tag, arch string) string {
	return filepath.Join(c.dir, tagPrefix+cacheKey(c.format(), strings.ToLower(baseURL), repository, tag, arch)+cacheJSONSuffix)
}

// tagRecord maps a tag, or a digest reference, to a manifest digest. Records
// from before tagRecordVersion 2 hold only the digest. The fields that name
// the reference make the record listable, and every later write adds them.
type tagRecord struct {
	Digest string `json:"digest"`

	Version      int    `json:"version,omitempty"`
	BaseURL      string `json:"baseURL,omitempty"`
	Repository   string `json:"repository,omitempty"`
	Architecture string `json:"architecture,omitempty"`
	// Tag is the tag. A reference by digest stores the digest here.
	Tag string `json:"tag,omitempty"`
}

const tagRecordVersion = 2

// named reports whether the record carries the names of its reference.
func (r tagRecord) named() bool {
	return r.Version >= tagRecordVersion && r.Repository != "" && r.Tag != "" && isDigestRef(r.Digest)
}

// storeImage records a resolved image under its manifest digest.
func (c *LayerCache) storeImage(rec imageRecord) error {
	rec.Version = imageRecordVersion
	rec.Format = c.format()
	raw, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("oci: encode image record: %w", err)
	}
	p := c.imageRecordPath(rec.BaseURL, rec.Repository, rec.Digest, rec.Architecture)
	return writeFileAtomic(filepath.Dir(p), filepath.Base(p), raw)
}

// storeTag records the manifest digest that a tag pointed to. A digest
// reference passes the digest as tag.
func (c *LayerCache) storeTag(baseURL, repository, tag, arch, digest string) error {
	raw, err := json.Marshal(tagRecord{
		Digest: digest, Version: tagRecordVersion,
		BaseURL: baseURL, Repository: repository, Tag: tag, Architecture: arch,
	})
	if err != nil {
		return fmt.Errorf("oci: encode tag record: %w", err)
	}
	p := c.tagRecordPath(baseURL, repository, tag, arch)
	return writeFileAtomic(filepath.Dir(p), filepath.Base(p), raw)
}

// LoadCachedImage returns the image that an earlier pull stored for reference,
// without any network access. A tag resolves to the digest that the last
// successful pull saw, which allows offline runs. A digest reference is exact.
// It returns ErrNotCached if the image or any of its layers is missing.
func (c *LayerCache) LoadCachedImage(baseURL, repository, reference, targetArch string) (*ResolvedImage, error) {
	baseURL, repository, reference, targetArch = normalizePullArgs(baseURL, repository, reference, targetArch)
	digest := reference
	if !isDigestRef(reference) {
		raw, err := readFileShared(c.tagRecordPath(baseURL, repository, reference, targetArch))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, ErrNotCached
			}
			return nil, fmt.Errorf("oci: read tag record: %w", err)
		}
		var tr tagRecord
		if err := json.Unmarshal(raw, &tr); err != nil || !isDigestRef(tr.Digest) {
			return nil, ErrNotCached
		}
		digest = tr.Digest
	}
	img, err := c.loadImageByDigest(baseURL, repository, digest, targetArch)
	if err != nil {
		return nil, err
	}
	return img, nil
}

// decodedRecord is the verified content of an image record.
type decodedRecord struct {
	manifest ImageManifest
	// manifestBody is the verbatim body of the image manifest.
	manifestBody []byte
	config       []byte
	cfg          RuntimeConfig
	// layerHex lists the cache keys of the layers, from the lowest up.
	layerHex []string
}

// decodeRecord parses an image record and re-derives the image from its
// verbatim blobs. A non-empty digest or arch must equal the one in the
// record. It returns ErrNotCached for a record that is stale, belongs to
// another format, or fails verification.
func (c *LayerCache) decodeRecord(raw []byte, digest, arch string) (imageRecord, *decodedRecord, error) {
	var rec imageRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Version != imageRecordVersion || len(rec.Manifests) == 0 ||
		(digest != "" && rec.Digest != digest) || (arch != "" && rec.Architecture != arch) || rec.Format != c.format() {
		return imageRecord{}, nil, ErrNotCached
	}
	dec, err := c.verifyRecord(rec)
	if err != nil {
		return imageRecord{}, nil, err
	}
	return rec, dec, nil
}

// verifyRecord re-derives the image from the verbatim blobs of rec. A record
// that was edited after it was written no longer matches the digest that
// names it.
func (c *LayerCache) verifyRecord(rec imageRecord) (*decodedRecord, error) {
	digest, arch := rec.Digest, rec.Architecture
	byDigest := make(map[string][]byte, len(rec.Manifests))
	for _, m := range rec.Manifests {
		sum := sha256.Sum256(m)
		byDigest["sha256:"+hex.EncodeToString(sum[:])] = m
	}
	top, ok := byDigest[digest]
	if !ok {
		return nil, ErrNotCached
	}
	res, err := resolveManifestChain(top, arch, func(d Descriptor) ([]byte, error) {
		b, ok := byDigest[d.Digest]
		if !ok {
			return nil, ErrNotCached
		}
		return b, nil
	})
	if err != nil {
		if errors.Is(err, ErrNotCached) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("oci: cached image record is invalid: %w", err)
	}
	if err := verifyBody(res.Manifest.Config, rec.Config); err != nil {
		return nil, ErrNotCached
	}
	cfg, err := parseImageConfig(rec.Config, arch, len(res.Manifest.Layers))
	if err != nil {
		return nil, fmt.Errorf("oci: cached image record is invalid: %w", err)
	}
	layerHex := make([]string, 0, len(res.Manifest.Layers))
	for _, l := range res.Manifest.Layers {
		hexStr, err := parseDigest(l.Digest)
		if err != nil {
			return nil, fmt.Errorf("oci: cached image record is invalid: %w", err)
		}
		layerHex = append(layerHex, hexStr)
	}
	return &decodedRecord{
		manifest: res.Manifest, manifestBody: res.Chain[len(res.Chain)-1],
		config: rec.Config, cfg: cfg, layerHex: layerHex,
	}, nil
}

// loadImageByDigest loads and re-verifies the record of a manifest digest.
func (c *LayerCache) loadImageByDigest(baseURL, repository, digest, arch string) (*ResolvedImage, error) {
	raw, err := readFileShared(c.imageRecordPath(baseURL, repository, digest, arch))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("oci: read image record: %w", err)
	}
	_, dec, err := c.decodeRecord(raw, digest, arch)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(dec.layerHex))
	for _, hexStr := range dec.layerHex {
		p, ok := c.HasLayer(hexStr)
		if !ok {
			return nil, ErrNotCached
		}
		paths = append(paths, p)
	}
	handles, err := c.OpenLayerHandles(dec.layerHex)
	if err != nil {
		return nil, ErrNotCached
	}
	return &ResolvedImage{
		Architecture:   arch,
		Config:         dec.cfg,
		ManifestDigest: digest,
		LayerDigests:   dec.layerHex,
		LayerPaths:     paths,
		LayerFiles:     handles,
	}, nil
}

// ImportCachedImage copies the cached image of reference from src into this
// cache and returns it. It copies layer images together with their integrity
// records and verifies each source layer before it publishes the copy.
func (c *LayerCache) ImportCachedImage(src *LayerCache, baseURL, repository, reference, targetArch string) (*ResolvedImage, error) {
	if src.blockSize != c.blockSize {
		return nil, fmt.Errorf("oci: cannot import layers with block size %d into a cache with block size %d", src.blockSize, c.blockSize)
	}
	baseURL, repository, reference, targetArch = normalizePullArgs(baseURL, repository, reference, targetArch)
	img, err := src.LoadCachedImage(baseURL, repository, reference, targetArch)
	if err != nil {
		return nil, err
	}
	defer img.Close()

	for _, d := range img.LayerDigests {
		if _, ok := c.HasLayer(d); ok {
			continue
		}
		if err := c.importLayer(src, d); err != nil {
			return nil, err
		}
	}

	rawRec, err := readFileShared(src.imageRecordPath(baseURL, repository, img.ManifestDigest, targetArch))
	if err != nil {
		return nil, fmt.Errorf("oci: read source image record: %w", err)
	}
	p := c.imageRecordPath(baseURL, repository, img.ManifestDigest, targetArch)
	if err := writeFileAtomic(filepath.Dir(p), filepath.Base(p), rawRec); err != nil {
		return nil, err
	}
	if err := c.storeTag(baseURL, repository, reference, targetArch, img.ManifestDigest); err != nil {
		return nil, err
	}
	return c.LoadCachedImage(baseURL, repository, reference, targetArch)
}

// importLayer copies one verified layer image and its integrity record.
func (c *LayerCache) importLayer(src *LayerCache, hexStr string) error {
	in, err := src.openVerifiedLayer(hexStr)
	if err != nil {
		return err
	}
	defer in.Close()
	record, err := readFileShared(src.sumPath(hexStr))
	if err != nil {
		return fmt.Errorf("oci: read integrity record of %s: %w", hexStr, err)
	}
	size, sum, err := c.parseSumRecord(record)
	if err != nil {
		return fmt.Errorf("oci: integrity record of %s: %w", hexStr, err)
	}

	tmp, err := os.CreateTemp(c.dir, tempPattern)
	if err != nil {
		return fmt.Errorf("oci: create temp layer file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(tmp, h), io.NewSectionReader(in, 0, size)); err != nil {
		return fmt.Errorf("oci: copy layer %s: %w", hexStr, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sum {
		return fmt.Errorf("%w: layer %s changed while it was copied", ErrCacheCorrupt, hexStr)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("oci: sync layer file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("oci: close layer file: %w", err)
	}
	if err := writeFileAtomic(c.dir, hexStr+c.sumSuffix(), record); err != nil {
		return err
	}
	if err := replaceFile(tmpPath, filepath.Join(c.dir, hexStr+c.layerSuffix())); err != nil {
		return fmt.Errorf("oci: publish layer %s: %w", hexStr, err)
	}
	committed = true
	return nil
}
