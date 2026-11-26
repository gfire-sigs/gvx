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
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
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
// cache directory. A LayerCache is safe for concurrent use by multiple
// goroutines and sandboxes.
type LayerCache struct {
	dir          string
	blockSize    int
	alwaysVerify bool

	mu        sync.Mutex
	limits    Limits
	keepBlobs bool
	// dnsServers are the resolvers of the registry requests that a pull or a
	// save sends with its default HTTP client. Empty selects the host resolver.
	dnsServers    []netip.AddrPort
	verified      map[string]verifiedLayer
	verifiedBlobs map[string]verifiedLayer
}

const (
	// maxVerifiedCacheEntries bounds the in-memory verification maps in
	// long-lived processes.
	maxVerifiedCacheEntries = 4096

	// racyCleanWindow prevents trusting whole-second coarse filesystem
	// timestamps that were modified within the current wall-clock window.
	racyCleanWindow = 2 * time.Second
)

// fileID holds platform-specific metadata that identifies an open regular file
// and detects in-place modification, replacement, or metadata changes.
type fileID struct {
	token      string
	handleKey  string
	writeStamp string
	coarse     bool
	changeTime time.Time
}

func (id fileID) trustableAt(now time.Time) bool {
	if id.token == "" {
		return false
	}
	if !id.coarse {
		return true
	}
	diff := now.Sub(id.changeTime)
	if diff < 0 {
		diff = -diff
	}
	return diff >= racyCleanWindow
}

// verifiedLayer records a layer or blob that passed integrity verification in
// this LayerCache instance.
type verifiedLayer struct {
	size    int64
	modTime time.Time
	idToken string
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
	// KeepBlobs retains original compressed/uncompressed layer blobs under
	// <cacheDir>/blobs/sha256/<hex> during pulls and archive loads so offline
	// SaveImages and PushImage work with original digests.
	KeepBlobs bool
	// AlwaysVerify disables the cross-process file-identity sidecar fast path
	// in openVerifiedLayer and hashes each unverified layer file in full once
	// per LayerCache instance.
	AlwaysVerify bool
	// Limits sets optional parsing and decompression caps. Zero selects
	// DefaultLimits().
	Limits Limits
	// DNSServers sets optional custom DNS resolvers for registry requests.
	DNSServers []netip.AddrPort
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
	limits := DefaultLimits()
	if opts.Limits != (Limits{}) {
		if err := opts.Limits.validate(); err != nil {
			return nil, err
		}
		limits = opts.Limits
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
	return &LayerCache{
		dir:           dir,
		limits:        limits,
		blockSize:     bs,
		keepBlobs:     opts.KeepBlobs,
		alwaysVerify:  opts.AlwaysVerify,
		dnsServers:    slices.Clone(opts.DNSServers),
		verified:      make(map[string]verifiedLayer),
		verifiedBlobs: make(map[string]verifiedLayer),
	}, nil
}

// KeepBlobs reports whether this cache retains original layer blobs during
// pulls and archive loads.
func (c *LayerCache) KeepBlobs() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.keepBlobs
}

// AlwaysVerify reports whether this cache disables the cross-process
// file-identity fast path and hashes each layer once per LayerCache instance.
func (c *LayerCache) AlwaysVerify() bool {
	return c.alwaysVerify
}

// SetKeepBlobs enables or disables keeping original layer blobs under
// <cacheDir>/blobs/sha256/<hex> during pulls and archive loads.
func (c *LayerCache) SetKeepBlobs(keep bool) {
	c.mu.Lock()
	c.keepBlobs = keep
	c.mu.Unlock()
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
func (c *LayerCache) idSuffix() string    { return c.layerSuffix() + ".id" }

// SetLimits replaces the size budgets that the cache applies to pulls and
// layer compilation.
func (c *LayerCache) SetLimits(l Limits) error {
	if err := l.validate(); err != nil {
		return err
	}
	c.mu.Lock()
	c.limits = l
	c.mu.Unlock()
	return nil
}

func (c *LayerCache) getLimits() Limits {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limits
}

// SetDNSServers makes the registry requests of this cache resolve names
// through servers, in place of the resolver of the host. It applies to a pull
// or a save that gets no HTTP client from its caller. A host without a
// resolver configuration, such as Android, needs it. Empty servers select the
// resolver of the host again.
func (c *LayerCache) SetDNSServers(servers []netip.AddrPort) {
	cp := slices.Clone(servers)
	c.mu.Lock()
	c.dnsServers = cp
	c.mu.Unlock()
}

func (c *LayerCache) getDNSServers() []netip.AddrPort {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.dnsServers)
}

// Dir returns the backing directory path of the LayerCache.
func (c *LayerCache) Dir() string {
	return c.dir
}

// LayerPath returns the absolute host path for a cached <digestHex>.erofs file.
func (c *LayerCache) LayerPath(dgst string) (string, error) {
	hexStr := normalizeDigestHex(dgst)
	if hexStr == "" {
		return "", fmt.Errorf("oci: invalid layer digest %q", dgst)
	}
	return filepath.Join(c.dir, hexStr+c.layerSuffix()), nil
}

func (c *LayerCache) sumPath(hexStr string) string {
	return filepath.Join(c.dir, hexStr+c.sumSuffix())
}

func (c *LayerCache) idPath(hexStr string) string {
	return filepath.Join(c.dir, hexStr+c.idSuffix())
}

// HasLayer reports whether the compiled <digestHex>.erofs layer exists in the
// cache directory and matches its integrity record.
func (c *LayerCache) HasLayer(dgst string) (string, bool) {
	p, err := c.LayerPath(dgst)
	if err != nil {
		return "", false
	}
	f, err := c.openVerifiedLayer(normalizeDigestHex(dgst))
	if err != nil {
		return "", false
	}
	if err := f.Close(); err != nil {
		return "", false
	}
	return p, true
}

// openVerifiedLayer opens a cached layer read-only and verifies it against its
// integrity record, using the in-memory verification cache and the sibling .id
// file-identity sidecar (unless AlwaysVerify is set) to skip redundant full
// SHA-256 hashing of unchanged files.
func (c *LayerCache) openVerifiedLayer(hexStr string) (*os.File, error) {
	p := filepath.Join(c.dir, hexStr+c.layerSuffix())
	f, err := openShared(p)
	if err != nil {
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("oci: open cached EROFS layer %q: %w", p, err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("oci: stat cached EROFS layer %q: %w", p, err)
	}
	if !info.Mode().IsRegular() || info.Size() < int64(c.blockSize) {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("%w: %q is not a layer image", ErrCacheCorrupt, p)
	}

	id, hasID := fileIdentity(f)
	now := time.Now()

	c.mu.Lock()
	v, ok := c.verified[hexStr]
	c.mu.Unlock()
	if ok && v.size == info.Size() {
		if hasID && v.idToken != "" {
			if v.idToken == id.token && id.trustableAt(now) {
				return f, nil
			}
		} else if !hasID && v.idToken == "" && v.modTime.Equal(info.ModTime()) {
			return f, nil
		}
	}

	record, err := readFileShared(c.sumPath(hexStr))
	if err != nil {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("%w: read integrity record of %q: %w", ErrCacheCorrupt, p, err)
	}
	wantSize, wantSum, err := c.parseSumRecord(record)
	if err != nil {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("%w: %q: %w", ErrCacheCorrupt, p, err)
	}
	if wantSize != info.Size() {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("%w: %q has %d bytes, want %d", ErrCacheCorrupt, p, info.Size(), wantSize)
	}

	if !c.alwaysVerify && hasID && id.trustableAt(now) {
		if idRaw, idErr := readFileShared(c.idPath(hexStr)); idErr == nil {
			if idSize, idSum, idToken, parseErr := c.parseIDRecord(idRaw); parseErr == nil &&
				idSize == wantSize && idSum == wantSum && idToken == id.token {
				c.recordVerified(hexStr, info.Size(), info.ModTime(), id)
				return f, nil
			}
		}
	}

	digester := digest.SHA256.Digester()
	if _, err := io.Copy(digester.Hash(), io.NewSectionReader(f, 0, info.Size())); err != nil {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("oci: hash cached EROFS layer %q: %w", p, err)
	}
	if got := digester.Digest().Encoded(); got != wantSum {
		_ = f.Close()
		c.forgetVerified(hexStr)
		return nil, fmt.Errorf("%w: %q has sha256 %s, want %s", ErrCacheCorrupt, p, got, wantSum)
	}
	c.recordVerified(hexStr, info.Size(), info.ModTime(), id)
	if hasID {
		c.writeIDBestEffort(hexStr, info.Size(), wantSum, id)
	}
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
	if digest.SHA256.Validate(fields[2]) != nil {
		return 0, "", errors.New("integrity record has an invalid digest")
	}
	return size, fields[2], nil
}

func (c *LayerCache) formatIDRecord(size int64, sum, token string) []byte {
	return []byte(c.format() + " " + strconv.FormatInt(size, 10) + " " + sum + " " + token + "\n")
}

func (c *LayerCache) parseIDRecord(raw []byte) (size int64, sum, token string, err error) {
	fields := strings.Fields(string(raw))
	if len(fields) != 4 || fields[0] != c.format() {
		return 0, "", "", fmt.Errorf("identity record is not in format %s", c.format())
	}
	size, err = strconv.ParseInt(fields[1], 10, 64)
	if err != nil || size < 0 {
		return 0, "", "", errors.New("identity record has an invalid size")
	}
	if digest.SHA256.Validate(fields[2]) != nil {
		return 0, "", "", errors.New("identity record has an invalid digest")
	}
	if fields[3] == "" {
		return 0, "", "", errors.New("identity record has an empty token")
	}
	return size, fields[2], fields[3], nil
}

func (c *LayerCache) writeIDBestEffort(hexKey string, size int64, sum string, id fileID) {
	if id.token == "" {
		return
	}
	_ = writeFileAtomic(c.dir, hexKey+c.idSuffix(), c.formatIDRecord(size, sum, id.token))
}

// CompileAndStore compiles a layer stream into an EROFS image and atomically
// stores it under <digest>.erofs inside the cache directory. The stream can be
// raw, gzip, or zstd compressed tar. A non-empty digest is the sha256 of the
// stream bytes. A mismatch fails the call and stores nothing. An empty digest
// names the image by the sha256 of the compiled image.
func (c *LayerCache) CompileAndStore(dgst string, tarStream io.Reader) (string, CompileStats, error) {
	var hexKey string
	if strings.TrimSpace(dgst) != "" {
		if hexKey = normalizeDigestHex(dgst); hexKey == "" {
			return "", CompileStats{}, fmt.Errorf("oci: invalid layer digest %q", dgst)
		}
	}
	return c.compileAndStore(layerSpec{key: hexKey, blobHex: hexKey, blobSize: -1}, tarStream)
}

// hashingReader hashes, counts, and optionally tees the bytes that pass through it.
type hashingReader struct {
	r io.Reader
	h hash.Hash
	w io.Writer
	n int64
}

func (h *hashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	if n > 0 {
		h.h.Write(p[:n])
		h.n += int64(n)
		if h.w != nil {
			if _, wErr := h.w.Write(p[:n]); wErr != nil {
				return n, wErr
			}
		}
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
	// keepBlob tees the raw stream into blobs/sha256/<sha256> after verification.
	keepBlob bool
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
		if tmp != nil {
			_ = tmp.Close()
		}
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()

	var (
		blobTmp       *os.File
		blobTmpPath   string
		blobCommitted bool
	)
	if spec.keepBlob {
		blobDir := c.blobsDir()
		if err := os.MkdirAll(blobDir, 0o755); err != nil {
			return "", CompileStats{}, fmt.Errorf("oci: create blob cache dir %q: %w", blobDir, err)
		}
		blobTmp, err = os.CreateTemp(blobDir, tempPattern)
		if err != nil {
			return "", CompileStats{}, fmt.Errorf("oci: create temp blob file: %w", err)
		}
		blobTmpPath = blobTmp.Name()
		defer func() {
			if !blobCommitted {
				_ = blobTmp.Close()
				_ = os.Remove(blobTmpPath)
			}
		}()
	}

	// The hash covers every byte that the compiler and the final drain read,
	// so it equals the hash of the whole stream.
	limits := c.getLimits()
	digester := digest.SHA256.Digester()
	var tee io.Writer
	if blobTmp != nil {
		tee = blobTmp
	}
	in := &hashingReader{r: newBoundedReader(src, "compressed layer size", limits.MaxBlobBytes, nil), h: digester.Hash(), w: tee}
	var diff *diffVerifier
	if spec.diffID != "" {
		diff = newDiffVerifier(spec.diffID)
	}
	stats, err := compileLayer(in, tmp, limits, c.blockSize, spec.image, diff)
	if err != nil {
		return "", CompileStats{}, err
	}
	if _, err := io.Copy(io.Discard, in); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: read layer trailer: %w", err)
	}
	if spec.blobSize >= 0 && in.n != spec.blobSize {
		return "", CompileStats{}, fmt.Errorf("%w: layer has %d bytes, descriptor says %d", ErrDigestMismatch, in.n, spec.blobSize)
	}
	gotBlobHex := digester.Digest().Encoded()
	if spec.blobHex != "" && gotBlobHex != spec.blobHex {
		return "", CompileStats{}, fmt.Errorf("%w: layer sha256 is %s, want %s", ErrDigestMismatch, gotBlobHex, spec.blobHex)
	}
	if hexKey == "" {
		hexKey = stats.SHA256Hex
	}

	if blobTmp != nil {
		if err := blobTmp.Sync(); err != nil {
			return "", CompileStats{}, fmt.Errorf("oci: sync blob file: %w", err)
		}
		blobInfo, err := blobTmp.Stat()
		if err != nil {
			return "", CompileStats{}, fmt.Errorf("oci: stat blob file: %w", err)
		}
		if err := blobTmp.Close(); err != nil {
			return "", CompileStats{}, fmt.Errorf("oci: close blob file: %w", err)
		}
		if _, err := c.publishBlobFile(blobTmpPath, gotBlobHex, blobInfo, &blobCommitted); err != nil {
			return "", CompileStats{}, err
		}
	}

	if err := tmp.Sync(); err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: sync layer file: %w", err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return "", CompileStats{}, fmt.Errorf("oci: stat layer file: %w", err)
	}

	// Publish the compiled image without replacing a valid layer file that a
	// concurrent writer already published at target.
	target, err := c.publishCompiledLayer(&tmp, tmpPath, hexKey, info, stats.TotalBytes, stats.SHA256Hex, &committed)
	if err != nil {
		return "", CompileStats{}, err
	}
	return target, stats, nil
}

// publishCompiledLayer publishes tmpPath at the cache path for hexKey while
// preserving the file identity of an already-valid cached layer so concurrent
// openers never observe an inode swap between verification and HostHandle open.
// On Unix, tmp stays open across link/unlink or rename so the post-publish .id
// sidecar stamps the exact verified inode with zero TOCTOU. On Windows, tmp is
// closed before link/rename and target is verified against the pre-close file
// ID and write timestamp before stamping .id.
func (c *LayerCache) publishCompiledLayer(tmpPtr **os.File, tmpPath, hexKey string, tmpInfo os.FileInfo, wantSize int64, wantSum string, committed *bool) (string, error) {
	target := filepath.Join(c.dir, hexKey+c.layerSuffix())
	if existingInfo, existingID, ok := c.verifyLayerOnDisk(hexKey, wantSize, wantSum); ok {
		c.recordVerified(hexKey, existingInfo.Size(), existingInfo.ModTime(), existingID)
		c.writeIDBestEffort(hexKey, existingInfo.Size(), wantSum, existingID)
		return target, nil
	}

	preID, preHasID := fileIdentity(*tmpPtr)
	if !publishViaOpenTempHandle {
		if err := (*tmpPtr).Close(); err != nil {
			*tmpPtr = nil
			return "", fmt.Errorf("oci: close layer file: %w", err)
		}
		*tmpPtr = nil
	}

	// Write the 3-field integrity record first, so a published image always has one.
	if err := writeFileAtomic(c.dir, hexKey+c.sumSuffix(), c.formatSumRecord(wantSize, wantSum)); err != nil {
		return "", err
	}

	finishPublished := func() (string, error) {
		if publishViaOpenTempHandle {
			f := *tmpPtr
			*tmpPtr = nil
			postInfo, statErr := f.Stat()
			postID, postOK := fileIdentity(f)
			if closeErr := f.Close(); closeErr != nil {
				return "", fmt.Errorf("oci: close layer file: %w", closeErr)
			}
			if statErr == nil && postInfo.Mode().IsRegular() && postInfo.Size() == wantSize {
				if postOK {
					if preHasID && postID.handleKey == preID.handleKey && postID.writeStamp == preID.writeStamp {
						c.recordVerified(hexKey, postInfo.Size(), postInfo.ModTime(), postID)
						c.writeIDBestEffort(hexKey, postInfo.Size(), wantSum, postID)
					}
				} else if !preHasID && postInfo.ModTime().Equal(tmpInfo.ModTime()) {
					c.recordVerified(hexKey, postInfo.Size(), postInfo.ModTime(), fileID{})
				}
			}
			return target, nil
		}
		c.stampPublishedTarget(target, hexKey, wantSize, wantSum, preID, preHasID)
		return target, nil
	}

	if err := os.Link(tmpPath, target); err == nil {
		_ = os.Remove(tmpPath)
		*committed = true
		return finishPublished()
	}
	if existingInfo, existingID, ok := c.verifyLayerOnDisk(hexKey, wantSize, wantSum); ok {
		c.recordVerified(hexKey, existingInfo.Size(), existingInfo.ModTime(), existingID)
		c.writeIDBestEffort(hexKey, existingInfo.Size(), wantSum, existingID)
		return target, nil
	}

	if err := replaceFile(tmpPath, target); err != nil {
		return "", fmt.Errorf("oci: rename cached layer %q: %w", target, err)
	}
	*committed = true
	return finishPublished()
}

func (c *LayerCache) stampPublishedTarget(target, hexKey string, wantSize int64, wantSum string, preID fileID, preHasID bool) {
	if !preHasID {
		return
	}
	f, err := openShared(target)
	if err != nil {
		return
	}
	postInfo, statErr := f.Stat()
	postID, postOK := fileIdentity(f)
	_ = f.Close()
	if statErr != nil || !postOK || !postInfo.Mode().IsRegular() || postInfo.Size() != wantSize {
		return
	}
	if postID.handleKey != preID.handleKey || postID.writeStamp != preID.writeStamp {
		return
	}
	c.recordVerified(hexKey, postInfo.Size(), postInfo.ModTime(), postID)
	c.writeIDBestEffort(hexKey, postInfo.Size(), wantSum, postID)
}

func (c *LayerCache) recordVerified(hexKey string, size int64, modTime time.Time, id fileID) {
	c.mu.Lock()
	if len(c.verified) >= maxVerifiedCacheEntries {
		clear(c.verified)
	}
	c.verified[hexKey] = verifiedLayer{size: size, modTime: modTime, idToken: id.token}
	c.mu.Unlock()
}

func (c *LayerCache) forgetVerified(hexKey string) {
	c.mu.Lock()
	delete(c.verified, hexKey)
	c.mu.Unlock()
}

// verifyLayerOnDisk checks whether the on-disk layer and integrity record for
// hexKey already exist and match wantSize and wantSum.
func (c *LayerCache) verifyLayerOnDisk(hexKey string, wantSize int64, wantSum string) (os.FileInfo, fileID, bool) {
	record, err := readFileShared(c.sumPath(hexKey))
	if err != nil {
		return nil, fileID{}, false
	}
	recSize, recSum, err := c.parseSumRecord(record)
	if err != nil || recSize != wantSize || recSum != wantSum {
		return nil, fileID{}, false
	}
	p := filepath.Join(c.dir, hexKey+c.layerSuffix())
	f, err := openShared(p)
	if err != nil {
		return nil, fileID{}, false
	}
	defer func() {
		_ = f.Close()
	}()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != wantSize {
		return nil, fileID{}, false
	}
	// Capture file identity before hashing so a concurrent in-place write
	// during io.Copy cannot pair post-tamper timestamps with the old digest.
	id, _ := fileIdentity(f)
	digester := digest.SHA256.Digester()
	if _, err := io.Copy(digester.Hash(), io.NewSectionReader(f, 0, info.Size())); err != nil {
		return nil, fileID{}, false
	}
	if digester.Digest().Encoded() != wantSum {
		return nil, fileID{}, false
	}
	return info, id, true
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
			_ = CloseLayerFiles(files)
			return nil, fmt.Errorf("oci: invalid layer digest %q", d)
		}
		f, err := c.openVerifiedLayer(hexStr)
		if err != nil {
			_ = CloseLayerFiles(files)
			return nil, err
		}
		files = append(files, f)
	}
	return files, nil
}

func normalizeDigestHex(s string) string {
	s = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(s), "sha256:"))
	if digest.SHA256.Validate(s) != nil {
		return ""
	}
	return s
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
	digester := digest.SHA256.Digester()
	h := digester.Hash()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return digester.Digest().Encoded()[:32]
}

func (c *LayerCache) imageRecordPath(baseURL, repository, dgst, arch string) string {
	return filepath.Join(c.dir, imagePrefix+cacheKey(c.format(), strings.ToLower(baseURL), repository, dgst, arch)+cacheJSONSuffix)
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
func (c *LayerCache) storeTag(baseURL, repository, tag, arch, dgst string) error {
	raw, err := json.Marshal(tagRecord{
		Digest: dgst, Version: tagRecordVersion,
		BaseURL: baseURL, Repository: repository, Tag: tag, Architecture: arch,
	})
	if err != nil {
		return fmt.Errorf("oci: encode tag record: %w", err)
	}
	p := c.tagRecordPath(baseURL, repository, tag, arch)
	return writeFileAtomic(filepath.Dir(p), filepath.Base(p), raw)
}

func (c *LayerCache) resolveTagDigest(baseURL, repository, reference, arch string) (string, error) {
	if isDigestRef(reference) {
		return reference, nil
	}
	raw, err := readFileShared(c.tagRecordPath(baseURL, repository, reference, arch))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", ErrNotCached
		}
		return "", fmt.Errorf("oci: read tag record: %w", err)
	}
	var tr tagRecord
	if err := json.Unmarshal(raw, &tr); err != nil || !isDigestRef(tr.Digest) {
		return "", ErrNotCached
	}
	return tr.Digest, nil
}

// LoadCachedImage returns the image that an earlier pull stored for reference,
// without any network access. A tag resolves to the digest that the last
// successful pull saw, which allows offline runs. A digest reference is exact.
// It returns ErrNotCached if the image or any of its layers is missing.
func (c *LayerCache) LoadCachedImage(baseURL, repository, reference, targetArch string) (*ResolvedImage, error) {
	baseURL, repository, reference, targetArch = normalizePullArgs(baseURL, repository, reference, targetArch)
	dgst, err := c.resolveTagDigest(baseURL, repository, reference, targetArch)
	if err != nil {
		return nil, err
	}
	return c.loadImageByDigest(baseURL, repository, dgst, targetArch)
}

// decodedRecord is the verified content of an image record.
type decodedRecord struct {
	manifest ocispec.Manifest
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
func (c *LayerCache) decodeRecord(raw []byte, dgst, arch string) (imageRecord, *decodedRecord, error) {
	var rec imageRecord
	if err := json.Unmarshal(raw, &rec); err != nil || rec.Version != imageRecordVersion || len(rec.Manifests) == 0 ||
		(dgst != "" && rec.Digest != dgst) || (arch != "" && rec.Architecture != arch) || rec.Format != c.format() {
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
	dgst, arch := digest.Digest(rec.Digest), rec.Architecture
	byDigest := make(map[digest.Digest][]byte, len(rec.Manifests))
	for _, m := range rec.Manifests {
		byDigest[digest.FromBytes(m)] = m
	}
	top, ok := byDigest[dgst]
	if !ok {
		return nil, ErrNotCached
	}
	res, err := resolveManifestChain(top, arch, func(d ocispec.Descriptor) ([]byte, error) {
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
		if err := validateSHA256(l.Digest); err != nil {
			return nil, fmt.Errorf("oci: cached image record is invalid: %w", err)
		}
		layerHex = append(layerHex, l.Digest.Encoded())
	}
	return &decodedRecord{
		manifest: res.Manifest, manifestBody: res.Chain[len(res.Chain)-1],
		config: rec.Config, cfg: cfg, layerHex: layerHex,
	}, nil
}

// loadImageByDigest loads and re-verifies the record of a manifest digest.
func (c *LayerCache) loadImageByDigest(baseURL, repository, dgst, arch string) (*ResolvedImage, error) {
	raw, err := readFileShared(c.imageRecordPath(baseURL, repository, dgst, arch))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotCached
		}
		return nil, fmt.Errorf("oci: read image record: %w", err)
	}
	_, dec, err := c.decodeRecord(raw, dgst, arch)
	if err != nil {
		return nil, err
	}

	img, err := c.finishImage(arch, dec.cfg, dgst, dec.manifest.Config.Digest.String(), dec.layerHex)
	if err != nil {
		return nil, ErrNotCached
	}
	return img, nil
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
		if _, ok := c.HasLayer(d); !ok {
			if err := c.importLayer(src, d); err != nil {
				return nil, err
			}
		}
		if c.KeepBlobs() {
			dgst := digest.NewDigestFromEncoded(digest.SHA256, d)
			f, sz, bErr := src.openVerifiedBlob(dgst, -1)
			if bErr == nil {
				_, _, sErr := c.storeBlobFromReader(dgst, sz, io.NewSectionReader(f, 0, sz))
				_ = f.Close()
				if sErr != nil {
					return nil, sErr
				}
			} else if !errors.Is(bErr, os.ErrNotExist) {
				return nil, bErr
			}
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

// importLayer copies one verified layer image and publishes a fresh integrity
// record and sibling .id sidecar for this cache's published file.
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
		if tmp != nil {
			_ = tmp.Close()
		}
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	digester := digest.SHA256.Digester()
	n, err := io.Copy(io.MultiWriter(tmp, digester.Hash()), io.NewSectionReader(in, 0, size))
	if err != nil {
		return fmt.Errorf("oci: copy layer %s: %w", hexStr, err)
	}
	if n != size || digester.Digest().Encoded() != sum {
		return fmt.Errorf("%w: layer %s changed while it was copied", ErrCacheCorrupt, hexStr)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("oci: sync layer file: %w", err)
	}
	info, err := tmp.Stat()
	if err != nil {
		return fmt.Errorf("oci: stat layer file: %w", err)
	}
	if _, err := c.publishCompiledLayer(&tmp, tmpPath, hexStr, info, size, sum, &committed); err != nil {
		return fmt.Errorf("oci: publish layer %s: %w", hexStr, err)
	}
	return nil
}
