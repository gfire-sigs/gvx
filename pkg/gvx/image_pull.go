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
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"z.gfire.dev/gvx/pkg/oci"
)

// PullPolicy selects when the image of a run comes from its registry. The
// values match the Docker flag --pull.
type PullPolicy string

const (
	// PullAlways asks the registry first, so a tag that moved gives the new
	// image. It uses the cached image when the registry is unreachable. It
	// also uses the cached image when the registry denies access to the
	// reference or does not know it.
	PullAlways PullPolicy = "always"

	// PullMissing uses the cached image and asks the registry only when the
	// cache has no record of the reference. This is the default, as in Docker.
	PullMissing PullPolicy = "missing"

	// PullNever uses the cached image only. A missing image is an error.
	PullNever PullPolicy = "never"
)

// ParsePullPolicy converts the text of a --pull flag into a PullPolicy. Case
// and outer spaces do not matter. Empty text selects PullMissing.
func ParsePullPolicy(text string) (PullPolicy, error) {
	switch p := PullPolicy(strings.ToLower(strings.TrimSpace(text))); p {
	case "":
		return PullMissing, nil
	case PullAlways, PullMissing, PullNever:
		return p, nil
	}
	return "", fmt.Errorf("%w: pull policy %q must be always, missing, or never", ErrInvalidConfig, text)
}

// pullOrder tells resolveImage how to pick between the cache and a registry.
type pullOrder struct {
	policy PullPolicy
	// useCacheWhenDenied makes PullAlways use the cache when the registry
	// answers 401, 403, or 404.
	useCacheWhenDenied bool
	// warnings receives the line about a denied registry. Nil discards it.
	warnings io.Writer
}

// registryRequest names one image on one registry.
type registryRequest struct {
	baseURL string
	// explicitRegistry reports that the caller overrode the registry.
	explicitRegistry bool
	repo, tag, arch  string
	// image is the text that the caller gave, for messages.
	image string
}

// registryPuller fetches one image from a registry into cache.
type registryPuller func(ctx context.Context, client *http.Client, baseURL, repo, tag, arch string, cache *oci.LayerCache) (*oci.ResolvedImage, error)

// resolveRegistryImage picks the image of one reference as order says.
func resolveRegistryImage(ctx context.Context, cache *oci.LayerCache, req registryRequest, order pullOrder, pull registryPuller) (*oci.ResolvedImage, error) {
	switch order.policy {
	case PullNever:
		img, err := loadCachedReference(cache, req)
		if errors.Is(err, oci.ErrNotCached) {
			return nil, fmt.Errorf("gvx: image %q is not in the local cache and the pull policy is %q: %w", req.image, PullNever, err)
		}
		return img, err
	case PullMissing:
		img, err := loadCachedReference(cache, req)
		if !errors.Is(err, oci.ErrNotCached) {
			return img, err
		}
	case PullAlways:
	}

	img, pullErr := pull(ctx, nil, req.baseURL, req.repo, req.tag, req.arch, cache)
	if pullErr == nil {
		return img, nil
	}
	if ctx.Err() != nil {
		return nil, pullErr
	}
	denied := order.useCacheWhenDenied && isRegistryDenied(pullErr)
	if !isNetworkError(pullErr) && !denied {
		return nil, pullErr
	}

	cached, cacheErr := loadCachedReference(cache, req)
	switch {
	case cacheErr == nil:
		if denied && order.warnings != nil {
			_, _ = fmt.Fprintf(order.warnings, "gvx: warning: the registry did not give access to %s (%v); using the cached image\n", req.image, pullErr)
		}
		return cached, nil
	case errors.Is(cacheErr, oci.ErrNotCached):
		return nil, pullErr
	}
	return nil, errors.Join(pullErr, cacheErr)
}

// loadCachedReference returns the cached image of a reference without network
// access. It looks in cache first. Without a registry override, it then
// imports the image from the default host layer cache. It returns
// oci.ErrNotCached when neither holds the image.
func loadCachedReference(cache *oci.LayerCache, req registryRequest) (*oci.ResolvedImage, error) {
	cached, err := cache.LoadCachedImage(req.baseURL, req.repo, req.tag, req.arch)
	if !errors.Is(err, oci.ErrNotCached) || req.explicitRegistry {
		return cached, err
	}
	defaultCache, err := NewLayerCache("")
	if err != nil {
		return nil, err
	}
	if defaultCache.Dir() == cache.Dir() {
		return nil, oci.ErrNotCached
	}
	return cache.ImportCachedImage(defaultCache, req.baseURL, req.repo, req.tag, req.arch)
}

// isRegistryDenied reports whether the registry answered that the caller has
// no access to the reference, or that it does not know the reference.
func isRegistryDenied(err error) bool {
	if errors.Is(err, oci.ErrAuthRequired) {
		return true
	}
	var status *oci.StatusError
	if !errors.As(err, &status) {
		return false
	}
	switch status.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound:
		return true
	}
	return false
}
