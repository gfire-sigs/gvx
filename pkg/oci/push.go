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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// PushOptions configures LayerCache.PushImage.
type PushOptions struct {
	// Client is the HTTP client for target and fallback source registry requests.
	// A nil client selects a default HTTP client.
	Client *http.Client
	// BaseURL overrides target.BaseURL() when non-empty (for example from
	// -registry-url).
	BaseURL string
	// Credentials overrides Store for the target registry when non-nil.
	Credentials *Credentials
	// SourceCredentials overrides Store when fetching unkept layer blobs from the
	// image's source registry as a fallback.
	SourceCredentials *Credentials
	// Store is the Docker credential store used when Credentials is nil.
	Store CredentialStore
	// Progress receives per-blob and manifest upload events when non-nil.
	Progress func(PushEvent)
}

// PushEvent describes one completed step of PushImage.
type PushEvent struct {
	// Kind is "layer", "config", or "manifest".
	Kind string
	// Digest is the SHA-256 digest of the blob or manifest.
	Digest string
	// Size is the byte length of the blob or manifest.
	Size int64
	// Status is "exists", "mounted", or "pushed".
	Status string
}

// PushResult summarizes the outcome of PushImage.
type PushResult struct {
	// Digest is the SHA-256 digest of the pushed manifest.
	Digest string
	// ConfigDigest is the SHA-256 digest of the pushed image config.
	ConfigDigest string
	// PushedBlobs is the number of layer and config blobs uploaded via PUT.
	PushedBlobs int
	// MountedBlobs is the number of blobs satisfied via cross-repository mount.
	MountedBlobs int
	// SkippedBlobs is the number of blobs already present on the target registry.
	SkippedBlobs int
	// UploadedBytes is the sum of byte lengths uploaded via PUT for blobs.
	UploadedBytes int64
}

// ParseAuthConfig parses Docker X-Registry-Auth credentials from raw JSON or
// base64-encoded JSON (standard or URL-safe, with or without padding).
// Supported JSON fields match Docker's AuthConfig: username, password,
// identitytoken, and auth (base64 "username:password").
func ParseAuthConfig(raw []byte) (Credentials, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return Credentials{}, errors.New("oci: registry auth payload is empty")
	}
	payload := trimmed
	if payload[0] != '{' {
		decoded, err := decodeBase64Flexible(string(trimmed))
		if err != nil {
			return Credentials{}, fmt.Errorf("oci: decode registry auth payload: %w", err)
		}
		payload = bytes.TrimSpace(decoded)
	}
	var entry authEntry
	if err := json.Unmarshal(payload, &entry); err != nil {
		return Credentials{}, fmt.Errorf("oci: parse registry auth JSON: %w", err)
	}
	if entry.Username != "" || entry.Password != "" {
		return Credentials{
			Username:      entry.Username,
			Password:      entry.Password,
			IdentityToken: entry.IdentityToken,
		}, nil
	}
	if entry.Auth != "" {
		decoded, err := decodeBase64Flexible(strings.TrimSpace(entry.Auth))
		if err != nil {
			return Credentials{}, fmt.Errorf("oci: decode auth field in registry auth JSON: %w", err)
		}
		user, pass, found := strings.Cut(string(decoded), ":")
		if !found {
			return Credentials{}, errors.New("oci: auth field in registry auth JSON must decode to username:password")
		}
		return Credentials{
			Username:      user,
			Password:      pass,
			IdentityToken: entry.IdentityToken,
		}, nil
	}
	if entry.IdentityToken != "" {
		return Credentials{IdentityToken: entry.IdentityToken}, nil
	}
	return Credentials{}, errors.New("oci: registry auth JSON contains no username, password, auth, or identitytoken")
}

func decodeBase64Flexible(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.RawURLEncoding,
	} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, nil
		}
	}
	return nil, errors.New("invalid base64 data")
}

func (rc *registryClient) uploadStartURL() string {
	return fmt.Sprintf("%s/v2/%s/blobs/uploads/", strings.TrimRight(rc.baseURL.String(), "/"), rc.repo)
}

func (rc *registryClient) blobExists(ctx context.Context, d digest.Digest) (bool, error) {
	u := rc.blobURL(d.String())
	resp, err := rc.doRequest(ctx, http.MethodHead, u, nil, nil)
	if err != nil {
		return false, fmt.Errorf("oci: check blob %s at %s: %w", d, u, err)
	}
	status := resp.StatusCode
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if closeErr := resp.Body.Close(); closeErr != nil {
		return false, fmt.Errorf("oci: close HEAD response for %s: %w", u, closeErr)
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, &StatusError{URL: u, StatusCode: status}
	}
}

func resolveUploadLocation(baseRaw, locHeader string) (string, error) {
	locHeader = strings.TrimSpace(locHeader)
	if locHeader == "" {
		return "", errors.New("oci: registry upload response omitted Location header")
	}
	baseURL, err := url.Parse(baseRaw)
	if err != nil {
		return "", fmt.Errorf("oci: parse upload base URL: %w", err)
	}
	locURL, err := url.Parse(locHeader)
	if err != nil {
		return "", fmt.Errorf("oci: parse upload Location %q: %w", locHeader, err)
	}
	resolved := baseURL.ResolveReference(locURL)
	if baseURL.Scheme == "https" && resolved.Scheme != "https" {
		return "", fmt.Errorf("oci: upload Location %s downgrades https", resolved.Redacted())
	}
	if (resolved.Scheme != "https" && resolved.Scheme != "http") || resolved.Host == "" {
		return "", fmt.Errorf("oci: invalid upload Location %q", resolved.Redacted())
	}
	return resolved.String(), nil
}

func appendDigestQuery(rawURL string, d digest.Digest) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("oci: parse upload URL: %w", err)
	}
	q := u.Query()
	q.Set("digest", d.String())
	u.RawQuery = q.Encode()
	return u.String(), nil
}

func sameRegistry(baseA, baseB string) bool {
	uA, errA := url.Parse(baseA)
	uB, errB := url.Parse(baseB)
	if errA != nil || errB != nil {
		return false
	}
	return strings.EqualFold(uA.Scheme, uB.Scheme) && canonicalHost(uA) == canonicalHost(uB)
}

// startOrMountUpload initiates a blob upload session or performs a
// cross-repository mount when fromRepo is non-empty. On mount success it
// returns (mounted=true, location="", nil). Otherwise it returns an upload
// Location URL for monolithic PUT.
func (rc *registryClient) startOrMountUpload(ctx context.Context, d digest.Digest, fromRepo string) (mounted bool, location string, err error) {
	startBase := rc.uploadStartURL()
	if fromRepo != "" {
		q := url.Values{}
		q.Set("mount", d.String())
		q.Set("from", fromRepo)
		mountURL := startBase + "?" + q.Encode()
		resp, err := rc.doRequest(ctx, http.MethodPost, mountURL, nil, &requestBody{contentLength: 0})
		if err != nil {
			return false, "", fmt.Errorf("oci: mount blob %s from %s: %w", d, fromRepo, err)
		}
		status := resp.StatusCode
		locHeader := resp.Header.Get("Location")
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		if closeErr := resp.Body.Close(); closeErr != nil {
			return false, "", fmt.Errorf("oci: close mount response for %s: %w", d, closeErr)
		}
		switch status {
		case http.StatusCreated:
			return true, "", nil
		case http.StatusAccepted:
			loc, locErr := resolveUploadLocation(mountURL, locHeader)
			if locErr != nil {
				return false, "", locErr
			}
			return false, loc, nil
		case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed:
			// Fall back to a plain upload session if the registry rejects mount params.
		default:
			return false, "", &StatusError{URL: mountURL, StatusCode: status}
		}
	}

	resp, err := rc.doRequest(ctx, http.MethodPost, startBase, nil, &requestBody{contentLength: 0})
	if err != nil {
		return false, "", fmt.Errorf("oci: start upload for blob %s: %w", d, err)
	}
	status := resp.StatusCode
	locHeader := resp.Header.Get("Location")
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if closeErr := resp.Body.Close(); closeErr != nil {
		return false, "", fmt.Errorf("oci: close upload start response for %s: %w", d, closeErr)
	}
	if status != http.StatusAccepted {
		return false, "", &StatusError{URL: startBase, StatusCode: status}
	}
	loc, err := resolveUploadLocation(startBase, locHeader)
	if err != nil {
		return false, "", err
	}
	return false, loc, nil
}

func (rc *registryClient) putBlob(ctx context.Context, uploadLocation string, d digest.Digest, size int64, open func() (io.ReadCloser, error)) error {
	putURL, err := appendDigestQuery(uploadLocation, d)
	if err != nil {
		return err
	}
	resp, err := rc.doRequest(ctx, http.MethodPut, putURL, nil, &requestBody{
		contentLength: size,
		contentType:   "application/octet-stream",
		open:          open,
	})
	if err != nil {
		return fmt.Errorf("oci: upload blob %s: %w", d, err)
	}
	status := resp.StatusCode
	gotDigest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if closeErr := resp.Body.Close(); closeErr != nil {
		return fmt.Errorf("oci: close upload response for blob %s: %w", d, closeErr)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return &StatusError{URL: putURL, StatusCode: status}
	}
	if gotDigest != "" && gotDigest != d.String() {
		return fmt.Errorf("%w: registry reported blob digest %s, want %s", ErrDigestMismatch, gotDigest, d)
	}
	return nil
}

func (rc *registryClient) putManifest(ctx context.Context, ref, mediaType string, body []byte, wantDigest digest.Digest) error {
	u := rc.manifestURL(ref)
	resp, err := rc.doRequest(ctx, http.MethodPut, u, nil, &requestBody{
		contentLength: int64(len(body)),
		contentType:   mediaType,
		open: func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(body)), nil
		},
	})
	if err != nil {
		return fmt.Errorf("oci: push manifest %s: %w", u, err)
	}
	status := resp.StatusCode
	gotDigest := strings.TrimSpace(resp.Header.Get("Docker-Content-Digest"))
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if closeErr := resp.Body.Close(); closeErr != nil {
		return fmt.Errorf("oci: close manifest push response for %s: %w", u, closeErr)
	}
	if status != http.StatusCreated && status != http.StatusOK {
		return &StatusError{URL: u, StatusCode: status}
	}
	if gotDigest != "" && gotDigest != wantDigest.String() {
		return fmt.Errorf("%w: registry reported manifest digest %s, want %s", ErrDigestMismatch, gotDigest, wantDigest)
	}
	return nil
}

// spoolSourceBlob downloads a missing layer blob from srcRC into a temporary
// file under c.dir while verifying exact size and SHA-256 digest. The caller
// closes and removes the returned file via cleanup.
func (c *LayerCache) spoolSourceBlob(ctx context.Context, srcRC *registryClient, l ocispec.Descriptor) (path string, cleanup func(), err error) {
	if err := validateSHA256(l.Digest); err != nil {
		return "", nil, err
	}
	body, err := srcRC.openBlob(ctx, l.Digest.String())
	if err != nil {
		return "", nil, err
	}
	defer body.Close()

	tmp, err := os.CreateTemp(c.dir, tempPattern)
	if err != nil {
		return "", nil, fmt.Errorf("oci: create temp upload spool for %s: %w", l.Digest, err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	digester := digest.SHA256.Digester()
	if _, err := io.CopyN(io.MultiWriter(tmp, digester.Hash()), body, l.Size); err != nil {
		if errors.Is(err, io.EOF) {
			return "", nil, fmt.Errorf("%w: blob %s is shorter than the %d bytes of its descriptor", ErrDigestMismatch, l.Digest, l.Size)
		}
		return "", nil, fmt.Errorf("oci: read source blob %s: %w", l.Digest, err)
	}
	var extra [1]byte
	if n, _ := body.Read(extra[:]); n > 0 {
		return "", nil, fmt.Errorf("%w: blob %s is longer than the %d bytes of its descriptor", ErrDigestMismatch, l.Digest, l.Size)
	}
	if got := digester.Digest(); got != l.Digest {
		return "", nil, fmt.Errorf("%w: source blob sha256 is %s, want %s", ErrDigestMismatch, got.Encoded(), l.Digest.Encoded())
	}
	if err := tmp.Close(); err != nil {
		return "", nil, fmt.Errorf("oci: close temp upload spool for %s: %w", l.Digest, err)
	}
	ok = true
	return tmpPath, func() { _ = os.Remove(tmpPath) }, nil
}

// PushImage uploads img to target using the OCI Distribution Spec v1.1.
//
// PushImage checks each layer blob and the config blob with HEAD and skips any
// blob the target registry already has. When the image originates from another
// repository on the same registry, PushImage attempts a cross-repository mount
// before uploading bytes. Layer bytes come from the kept-blob cache first; for
// unkept blobs, PushImage falls back to fetching from the image's source
// registry when available. If an image has unkept blobs and no registry source,
// PushImage fails before uploading with an error wrapping ErrNoRegistrySource.
func (c *LayerCache) PushImage(ctx context.Context, img Image, target Reference, opts PushOptions) (PushResult, error) {
	if target.Repository == "" {
		return PushResult{}, fmt.Errorf("%w: push target must name a repository", ErrInvalidReference)
	}
	manifestRef := target.ManifestReference()
	if manifestRef == "" {
		return PushResult{}, fmt.Errorf("%w: push target must have a tag or digest", ErrInvalidReference)
	}
	label := img.ID
	if img.Named() {
		label = img.Name()
	}

	dec, err := c.verifyRecord(img.record)
	if err != nil {
		return PushResult{}, fmt.Errorf("oci: cannot push %s: %w", label, err)
	}
	for _, l := range dec.manifest.Layers {
		if err := checkLayerDescriptor(l, c.limits); err != nil {
			return PushResult{}, fmt.Errorf("oci: cannot push %s: %w", label, err)
		}
	}
	if err := validateSHA256(dec.manifest.Config.Digest); err != nil {
		return PushResult{}, fmt.Errorf("oci: cannot push %s: invalid config digest: %w", label, err)
	}
	if int64(len(dec.config)) != dec.manifest.Config.Size {
		return PushResult{}, fmt.Errorf("oci: cannot push %s: %w: config size is %d, descriptor says %d", label, ErrDigestMismatch, len(dec.config), dec.manifest.Config.Size)
	}

	manifestDigest := digest.FromBytes(dec.manifestBody)
	if target.Digest != "" && target.Digest != manifestDigest.String() {
		return PushResult{}, fmt.Errorf("oci: cannot push %s to %s: target digest does not match manifest digest %s", label, target.Familiar(), manifestDigest)
	}

	allLocal, err := c.checkLocalBlobs(dec.manifest.Layers)
	if err != nil {
		return PushResult{}, fmt.Errorf("oci: cannot push %s: %w", label, err)
	}
	srcBaseURL, srcRepo, srcErr := img.blobSource()
	if !allLocal && srcErr != nil {
		return PushResult{}, fmt.Errorf("oci: cannot push %s: original layer blobs are not kept in the cache (pull or load with -keep-blobs): %w", label, srcErr)
	}

	targetBaseURL := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	if targetBaseURL == "" {
		targetBaseURL = target.BaseURL()
	}
	dstRC, err := newRegistryClient(opts.Client, targetBaseURL, target.Repository, c.limits, c.dnsServers)
	if err != nil {
		return PushResult{}, err
	}
	defer dstRC.close()
	dstRC.store = opts.Store
	dstRC.fixed = opts.Credentials

	var srcRC *registryClient
	defer func() {
		if srcRC != nil {
			srcRC.close()
		}
	}()
	getSourceClient := func() (*registryClient, error) {
		if srcRC != nil {
			return srcRC, nil
		}
		if srcErr != nil {
			return nil, fmt.Errorf("oci: cannot push %s: %w", label, srcErr)
		}
		rc, err := newRegistryClient(opts.Client, srcBaseURL, srcRepo, c.limits, c.dnsServers)
		if err != nil {
			return nil, err
		}
		rc.store = opts.Store
		rc.fixed = opts.SourceCredentials
		srcRC = rc
		return srcRC, nil
	}

	mountFrom := ""
	if srcErr == nil && sameRegistry(targetBaseURL, srcBaseURL) && srcRepo != "" && srcRepo != target.Repository {
		mountFrom = srcRepo
	}

	emit := func(ev PushEvent) {
		if opts.Progress != nil {
			opts.Progress(ev)
		}
	}

	res := PushResult{
		Digest:       manifestDigest.String(),
		ConfigDigest: dec.manifest.Config.Digest.String(),
	}
	done := make(map[digest.Digest]bool)

	pushBlob := func(kind string, desc ocispec.Descriptor, openLocal func() (func() (io.ReadCloser, error), func(), bool, error)) error {
		if done[desc.Digest] {
			return nil
		}
		exists, err := dstRC.blobExists(ctx, desc.Digest)
		if err != nil {
			return err
		}
		if exists {
			done[desc.Digest] = true
			res.SkippedBlobs++
			emit(PushEvent{Kind: kind, Digest: desc.Digest.String(), Size: desc.Size, Status: "exists"})
			return nil
		}
		mounted, location, err := dstRC.startOrMountUpload(ctx, desc.Digest, mountFrom)
		if err != nil {
			return err
		}
		if mounted {
			done[desc.Digest] = true
			res.MountedBlobs++
			emit(PushEvent{Kind: kind, Digest: desc.Digest.String(), Size: desc.Size, Status: "mounted"})
			return nil
		}

		openFn, cleanup, haveLocal, err := openLocal()
		if err != nil {
			return err
		}
		if cleanup != nil {
			defer cleanup()
		}
		if !haveLocal {
			rc, err := getSourceClient()
			if err != nil {
				return err
			}
			spoolPath, spoolCleanup, err := c.spoolSourceBlob(ctx, rc, desc)
			if err != nil {
				return err
			}
			defer spoolCleanup()
			openFn = func() (io.ReadCloser, error) {
				return openShared(spoolPath)
			}
		}

		if err := dstRC.putBlob(ctx, location, desc.Digest, desc.Size, openFn); err != nil {
			return err
		}
		done[desc.Digest] = true
		res.PushedBlobs++
		res.UploadedBytes += desc.Size
		emit(PushEvent{Kind: kind, Digest: desc.Digest.String(), Size: desc.Size, Status: "pushed"})
		return nil
	}

	for _, l := range dec.manifest.Layers {
		layerDesc := l
		err := pushBlob("layer", layerDesc, func() (func() (io.ReadCloser, error), func(), bool, error) {
			f, _, openErr := c.openVerifiedBlob(layerDesc.Digest, layerDesc.Size)
			if openErr != nil {
				if errors.Is(openErr, os.ErrNotExist) {
					return nil, nil, false, nil
				}
				return nil, nil, false, openErr
			}
			_ = f.Close()
			blobPath := ""
			blobPath, openErr = c.BlobPath(layerDesc.Digest.String())
			if openErr != nil {
				return nil, nil, false, openErr
			}
			return func() (io.ReadCloser, error) {
				return openShared(blobPath)
			}, nil, true, nil
		})
		if err != nil {
			return PushResult{}, err
		}
	}

	cfgDesc := dec.manifest.Config
	if err := pushBlob("config", cfgDesc, func() (func() (io.ReadCloser, error), func(), bool, error) {
		return func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(dec.config)), nil
		}, nil, true, nil
	}); err != nil {
		return PushResult{}, err
	}

	mediaType := dec.manifest.MediaType
	if mediaType == "" {
		mediaType = ocispec.MediaTypeImageManifest
	}
	if err := dstRC.putManifest(ctx, manifestRef, mediaType, dec.manifestBody, manifestDigest); err != nil {
		return PushResult{}, err
	}
	emit(PushEvent{Kind: "manifest", Digest: manifestDigest.String(), Size: int64(len(dec.manifestBody)), Status: "pushed"})
	return res, nil
}
