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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

// DefaultRegistryBaseURL is the default OCI v2 registry endpoint (Docker Hub).
const DefaultRegistryBaseURL = "https://registry-1.docker.io"

// Media types of the manifest formats that the runner understands.
const (
	mediaTypeOCIIndex       = "application/vnd.oci.image.index.v1+json"
	mediaTypeDockerList     = "application/vnd.docker.distribution.manifest.list.v2+json"
	mediaTypeOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	mediaTypeDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	mediaTypeDockerV1Prefix = "application/vnd.docker.distribution.manifest.v1"
	mediaTypeOCIConfig      = "application/vnd.oci.image.config.v1+json"
	mediaTypeDockerConfig   = "application/vnd.docker.container.image.v1+json"

	// maxIndexDepth bounds nested image indexes.
	maxIndexDepth = 4
)

// ErrDigestMismatch reports that content does not match its descriptor.
var ErrDigestMismatch = errors.New("oci: content digest mismatch")

// PlatformSpec identifies the OS and CPU architecture of an OCI manifest.
type PlatformSpec struct {
	OS           string `json:"os"`
	Architecture string `json:"architecture"`
	Variant      string `json:"variant,omitempty"`
}

// Descriptor describes a content-addressable blob in an OCI Image Index or Manifest.
type Descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	URLs        []string          `json:"urls,omitempty"`
	Platform    *PlatformSpec     `json:"platform,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// ImageIndex represents an OCI Image Index or Docker Manifest List.
type ImageIndex struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Manifests     []Descriptor `json:"manifests"`
}

// ImageManifest represents a single-architecture OCI Image Manifest.
type ImageManifest struct {
	SchemaVersion int          `json:"schemaVersion"`
	MediaType     string       `json:"mediaType,omitempty"`
	Config        Descriptor   `json:"config"`
	Layers        []Descriptor `json:"layers"`
}

// RuntimeConfig holds the container execution metadata parsed from an OCI
// Image Configuration JSON blob.
type RuntimeConfig struct {
	Entrypoint []string `json:"Entrypoint"`
	Cmd        []string `json:"Cmd"`
	Env        []string `json:"Env"`
	WorkingDir string   `json:"WorkingDir"`
	User       string   `json:"User"`
	// ExposedPorts holds the keys of the image ExposedPorts map, such as
	// "80/tcp". ExposedPortList parses them.
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
}

// ExposedPort is one port that an image declares with EXPOSE.
type ExposedPort struct {
	Port     uint16
	Protocol string // "tcp" or "udp"
}

// ExposedPortList returns the ports that the image declares, ordered by port
// number and then by protocol. A key without a protocol means tcp. The call
// skips a key that is not a port number from 1 to 65535 with tcp or udp.
func (c RuntimeConfig) ExposedPortList() []ExposedPort {
	var ports []ExposedPort
	for key := range c.ExposedPorts {
		num, proto, _ := strings.Cut(key, "/")
		if proto == "" {
			proto = "tcp"
		}
		n, err := strconv.ParseUint(num, 10, 16)
		if err != nil || n == 0 || (proto != "tcp" && proto != "udp") {
			continue
		}
		ports = append(ports, ExposedPort{Port: uint16(n), Protocol: proto})
	}
	sort.Slice(ports, func(i, j int) bool {
		if ports[i].Port != ports[j].Port {
			return ports[i].Port < ports[j].Port
		}
		return ports[i].Protocol < ports[j].Protocol
	})
	return ports
}

type imageConfigFile struct {
	Architecture string        `json:"architecture"`
	OS           string        `json:"os"`
	Created      string        `json:"created"`
	Config       RuntimeConfig `json:"config"`
	RootFS       struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// ResolvedImage holds the resolved runtime metadata, cached .erofs layer paths,
// and pre-opened read-only *os.File handles ready for VFS2 overlay mounting.
type ResolvedImage struct {
	Architecture string
	Config       RuntimeConfig
	// ManifestDigest is the digest of the manifest or index that named the
	// image. It is empty for images that come from an archive without one.
	ManifestDigest string
	LayerDigests   []string
	LayerPaths     []string
	LayerFiles     []*os.File
}

// Close closes all pre-opened .erofs layer file handles.
func (r *ResolvedImage) Close() error {
	if r == nil {
		return nil
	}
	err := CloseLayerFiles(r.LayerFiles)
	r.LayerFiles = nil
	return err
}

// CommandVector returns the combined Entrypoint + Cmd argv slice for the image,
// overriding Cmd when userArgs is non-empty.
func (c RuntimeConfig) CommandVector(userArgs []string) []string {
	var argv []string
	argv = append(argv, c.Entrypoint...)
	if len(userArgs) > 0 {
		argv = append(argv, userArgs...)
	} else {
		argv = append(argv, c.Cmd...)
	}
	return argv
}

// SelectManifestForArch selects the linux/<targetArch> manifest descriptor from
// an OCI ImageIndex. When targetArch is empty, runtime.GOARCH is used.
func SelectManifestForArch(index ImageIndex, targetArch string) (Descriptor, error) {
	if targetArch == "" {
		targetArch = runtime.GOARCH
	}
	targetArch = normalizeArch(targetArch)

	for _, m := range index.Manifests {
		if m.Platform == nil {
			continue
		}
		if strings.EqualFold(m.Platform.OS, "linux") && normalizeArch(m.Platform.Architecture) == targetArch {
			return m, nil
		}
	}
	return Descriptor{}, fmt.Errorf("oci: no linux/%s manifest found in image index", targetArch)
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

// ParseRuntimeConfig parses Entrypoint, Cmd, Env, WorkingDir, and User from an
// OCI Image Configuration JSON payload.
func ParseRuntimeConfig(configJSON []byte) (RuntimeConfig, error) {
	var parsed imageConfigFile
	if err := json.Unmarshal(configJSON, &parsed); err != nil {
		return RuntimeConfig{}, fmt.Errorf("oci: unmarshal image config JSON: %w", err)
	}
	if parsed.Config.WorkingDir == "" {
		parsed.Config.WorkingDir = "/"
	}
	return parsed.Config, nil
}

// parseImageConfig parses an image config and rejects an image for another OS
// or architecture, or a config that disagrees with the manifest layer count.
func parseImageConfig(raw []byte, arch string, layers int) (RuntimeConfig, error) {
	var parsed imageConfigFile
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return RuntimeConfig{}, fmt.Errorf("oci: unmarshal image config JSON: %w", err)
	}
	if parsed.OS != "" && !strings.EqualFold(parsed.OS, "linux") {
		return RuntimeConfig{}, fmt.Errorf("oci: image targets OS %q, want linux", parsed.OS)
	}
	if parsed.Architecture != "" && normalizeArch(parsed.Architecture) != arch {
		return RuntimeConfig{}, fmt.Errorf("oci: image targets architecture %q, want %s", parsed.Architecture, arch)
	}
	if n := len(parsed.RootFS.DiffIDs); n != 0 && n != layers {
		return RuntimeConfig{}, fmt.Errorf("oci: image config lists %d diff IDs for %d layers", n, layers)
	}
	if parsed.Config.WorkingDir == "" {
		parsed.Config.WorkingDir = "/"
	}
	return parsed.Config, nil
}

// parseDigest returns the lowercase hex of a "sha256:<hex>" digest.
func parseDigest(digest string) (string, error) {
	hexStr, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexStr) != sha256.Size*2 || normalizeDigestHex(hexStr) != hexStr {
		return "", fmt.Errorf("oci: unsupported or malformed digest %q", digest)
	}
	return hexStr, nil
}

func isDigestRef(ref string) bool {
	_, err := parseDigest(ref)
	return err == nil
}

// verifyDigest compares body against a sha256 digest string.
func verifyDigest(digest string, body []byte) error {
	want, err := parseDigest(digest)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != want {
		return fmt.Errorf("%w: sha256 is %s, want %s", ErrDigestMismatch, got, want)
	}
	return nil
}

// verifyBody compares body against the digest and size of its descriptor.
func verifyBody(desc Descriptor, body []byte) error {
	if int64(len(body)) != desc.Size {
		return fmt.Errorf("%w: %s has %d bytes, descriptor says %d", ErrDigestMismatch, desc.Digest, len(body), desc.Size)
	}
	return verifyDigest(desc.Digest, body)
}

// resolvedManifest is the manifest of one image and the blobs that led to it.
type resolvedManifest struct {
	// Chain holds the verbatim bodies from the top-level index or manifest
	// down to the image manifest.
	Chain    [][]byte
	Manifest ImageManifest
}

// resolveManifestChain walks from a verified top-level body to the image
// manifest for arch. fetch returns the body of a descriptor. Every body that
// fetch returns is verified against its descriptor.
func resolveManifestChain(top []byte, arch string, fetch func(Descriptor) ([]byte, error)) (*resolvedManifest, error) {
	res := &resolvedManifest{}
	body := top
	for range maxIndexDepth {
		res.Chain = append(res.Chain, body)
		var probe struct {
			SchemaVersion int          `json:"schemaVersion"`
			MediaType     string       `json:"mediaType"`
			Manifests     []Descriptor `json:"manifests"`
			Layers        []Descriptor `json:"layers"`
			Config        *Descriptor  `json:"config"`
		}
		if err := json.Unmarshal(body, &probe); err != nil {
			return nil, fmt.Errorf("oci: decode manifest: %w", err)
		}
		if probe.SchemaVersion == 1 || strings.HasPrefix(probe.MediaType, mediaTypeDockerV1Prefix) {
			return nil, errors.New("oci: Docker image manifest schema 1 is not supported")
		}
		isIndex := probe.MediaType == mediaTypeOCIIndex || probe.MediaType == mediaTypeDockerList ||
			(probe.MediaType == "" && probe.Config == nil && len(probe.Manifests) > 0)
		if !isIndex {
			if err := json.Unmarshal(body, &res.Manifest); err != nil {
				return nil, fmt.Errorf("oci: decode image manifest: %w", err)
			}
			if res.Manifest.Config.Digest == "" {
				return nil, errors.New("oci: image manifest has no config descriptor")
			}
			if mt := res.Manifest.Config.MediaType; mt != "" && mt != mediaTypeOCIConfig && mt != mediaTypeDockerConfig {
				return nil, fmt.Errorf("oci: config media type %q is not a container image", mt)
			}
			return res, nil
		}

		desc, err := SelectManifestForArch(ImageIndex{Manifests: probe.Manifests}, arch)
		if err != nil {
			if len(probe.Manifests) != 1 || probe.Manifests[0].Platform != nil {
				return nil, err
			}
			desc = probe.Manifests[0]
		}
		if body, err = fetch(desc); err != nil {
			return nil, err
		}
		if err := verifyBody(desc, body); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("oci: image index nesting is too deep")
}

// checkLayerDescriptor rejects layers that the runner cannot compile.
func checkLayerDescriptor(l Descriptor, lim Limits) error {
	if len(l.URLs) > 0 || strings.Contains(l.MediaType, "foreign") {
		return fmt.Errorf("oci: layer %s is a foreign layer, which is not supported", l.Digest)
	}
	if mt := l.MediaType; mt != "" &&
		!strings.HasPrefix(mt, "application/vnd.oci.image.layer.") &&
		!strings.HasPrefix(mt, "application/vnd.docker.image.rootfs.diff.tar") {
		return fmt.Errorf("oci: layer %s has unsupported media type %q", l.Digest, mt)
	}
	if l.Size < 0 || l.Size > lim.MaxBlobBytes {
		return &LimitError{What: fmt.Sprintf("size of layer %s", l.Digest), Limit: lim.MaxBlobBytes}
	}
	return nil
}

// normalizePullArgs applies the defaults that every entry point shares.
func normalizePullArgs(baseURL, repository, reference, targetArch string) (string, string, string, string) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		baseURL = DefaultRegistryBaseURL
	}
	repository = NormalizeRegistryRepo(baseURL, repository)
	if reference == "" {
		reference = "latest"
	}
	if targetArch == "" {
		targetArch = runtime.GOARCH
	}
	return baseURL, repository, reference, normalizeArch(targetArch)
}

// NormalizeRegistryRepo returns the repository name that the registry and the
// layer cache use. Docker Hub stores single-name images under "library/".
func NormalizeRegistryRepo(baseURL, repo string) string {
	repo = strings.Trim(repo, "/")
	if !strings.Contains(repo, "/") {
		lowerBase := strings.ToLower(baseURL)
		if strings.Contains(lowerBase, "docker.io") {
			return "library/" + repo
		}
	}
	return repo
}

// PullRegistryImage fetches a multi-arch OCI image from an HTTP/HTTPS registry
// endpoint, compiles its layers into cached <sha256>.erofs files, and opens
// read-only handles prior to hostlockdown.Apply().
//
// A tag reference asks the registry for the current manifest digest on every
// call, so a moved tag is observed. A digest reference, and a tag whose digest
// is already cached, need no further network access. The call verifies the
// manifest, the config, and every layer against their digests.
func PullRegistryImage(ctx context.Context, client *http.Client, baseURL, repository, reference, targetArch string, cache *LayerCache) (*ResolvedImage, error) {
	if cache == nil {
		var err error
		cache, err = NewLayerCache("")
		if err != nil {
			return nil, err
		}
	}
	baseURL, repository, reference, targetArch = normalizePullArgs(baseURL, repository, reference, targetArch)

	// A digest names immutable content, so a cached image needs no network.
	if isDigestRef(reference) {
		img, err := cache.loadImageByDigest(baseURL, repository, reference, targetArch)
		switch {
		case err == nil:
			if err := cache.storeTag(baseURL, repository, reference, targetArch, reference); err != nil {
				_ = img.Close()
				return nil, err
			}
			return img, nil
		case !errors.Is(err, ErrNotCached):
			return nil, err
		}
	}

	rc, err := newRegistryClient(client, baseURL, repository, cache.limits)
	if err != nil {
		return nil, err
	}
	defer rc.close()

	digest := reference
	var topBody []byte
	if !isDigestRef(reference) {
		if digest, topBody, err = rc.resolveTag(ctx, reference); err != nil {
			return nil, fmt.Errorf("oci: resolve tag %q: %w", reference, err)
		}
		img, err := cache.loadImageByDigest(baseURL, repository, digest, targetArch)
		switch {
		case err == nil:
			if err := cache.storeTag(baseURL, repository, reference, targetArch, digest); err != nil {
				_ = img.Close()
				return nil, err
			}
			return img, nil
		case !errors.Is(err, ErrNotCached):
			return nil, err
		}
	}
	if topBody == nil {
		if topBody, err = rc.getManifest(ctx, digest); err != nil {
			return nil, err
		}
	}
	if err := verifyDigest(digest, topBody); err != nil {
		return nil, fmt.Errorf("oci: manifest %s: %w", digest, err)
	}

	res, err := resolveManifestChain(topBody, targetArch, func(d Descriptor) ([]byte, error) {
		return rc.getManifest(ctx, d.Digest)
	})
	if err != nil {
		return nil, err
	}
	cfgBytes, err := rc.getBlobBytes(ctx, res.Manifest.Config)
	if err != nil {
		return nil, err
	}
	cfg, err := parseImageConfig(cfgBytes, targetArch, len(res.Manifest.Layers))
	if err != nil {
		return nil, err
	}

	image := newByteBudget("decompressed image size", cache.limits.MaxImageBytes)
	digests := make([]string, 0, len(res.Manifest.Layers))
	for _, l := range res.Manifest.Layers {
		hexStr, err := parseDigest(l.Digest)
		if err != nil {
			return nil, err
		}
		if err := checkLayerDescriptor(l, cache.limits); err != nil {
			return nil, err
		}
		if _, ok := cache.HasLayer(hexStr); !ok {
			body, err := rc.openBlob(ctx, l.Digest)
			if err != nil {
				return nil, err
			}
			_, _, err = cache.compileAndStore(layerSpec{key: hexStr, blobHex: hexStr, blobSize: l.Size, image: image}, body)
			closeErr := body.Close()
			if err != nil {
				return nil, fmt.Errorf("oci: compile layer %s: %w", l.Digest, err)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("oci: close layer %s: %w", l.Digest, closeErr)
			}
		}
		digests = append(digests, hexStr)
	}

	if err := cache.storeImage(imageRecord{
		BaseURL:      baseURL,
		Repository:   repository,
		Digest:       digest,
		Architecture: targetArch,
		Manifests:    res.Chain,
		Config:       cfgBytes,
	}); err != nil {
		return nil, err
	}
	if err := cache.storeTag(baseURL, repository, reference, targetArch, digest); err != nil {
		return nil, err
	}
	return cache.finishImage(targetArch, cfg, digest, digests)
}

// finishImage opens the verified layer handles of a finished image.
func (c *LayerCache) finishImage(arch string, cfg RuntimeConfig, manifestDigest string, digests []string) (*ResolvedImage, error) {
	paths := make([]string, len(digests))
	for i, d := range digests {
		p, err := c.LayerPath(d)
		if err != nil {
			return nil, err
		}
		paths[i] = p
	}
	handles, err := c.OpenLayerHandles(digests)
	if err != nil {
		return nil, err
	}
	return &ResolvedImage{
		Architecture:   arch,
		Config:         cfg,
		ManifestDigest: manifestDigest,
		LayerDigests:   digests,
		LayerPaths:     paths,
		LayerFiles:     handles,
	}, nil
}
