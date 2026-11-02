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
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"z.gfire.dev/gvx/pkg/oci"
)

const pullPolicyRepo = "gvx/ref"

// pullPolicyFixture is a registry that a test can switch from serving to
// failing, and a cache that holds the image from the serving phase.
type pullPolicyFixture struct {
	baseURL string
	cache   *oci.LayerCache
	digest  string
}

// newPullPolicyFixture pulls gvx/ref:v1 into a new cache. When withCache is
// false, the cache stays empty.
func newPullPolicyFixture(t *testing.T, withCache bool) pullPolicyFixture {
	t.Helper()
	reg, _ := referenceRegistry(t)
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}
	f := pullPolicyFixture{baseURL: reg.URL, cache: cache}
	if !withCache {
		return f
	}
	img, err := oci.PullRegistryImage(context.Background(), nil, reg.URL, pullPolicyRepo, "v1", runtime.GOARCH, cache)
	if err != nil {
		t.Fatalf("seed pull failed: %v", err)
	}
	f.digest = img.ManifestDigest
	if err := img.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	return f
}

func (f pullPolicyFixture) request() registryRequest {
	return registryRequest{
		baseURL: f.baseURL, explicitRegistry: true, repo: pullPolicyRepo, tag: "v1",
		arch: runtime.GOARCH, image: "gvx/ref:v1",
	}
}

func TestResolveRegistryImageFollowsThePullPolicy(t *testing.T) {
	networkErr := fmt.Errorf("oci: resolve tag: %w", &net.OpError{Op: "dial", Err: errors.New("connection refused")})
	statusErr := func(code int) error {
		return fmt.Errorf("oci: resolve tag: %w", &oci.StatusError{URL: "https://registry.example/v2/x", StatusCode: code})
	}
	authErr := fmt.Errorf("oci: resolve tag: %w", oci.ErrAuthRequired)

	tests := []struct {
		name      string
		policy    PullPolicy
		denied    bool // useCacheWhenDenied
		cached    bool
		pullErr   error // nil means the pull succeeds
		wantFetch bool
		wantErr   func(error) bool // nil means success
		wantWarn  bool
	}{
		{name: "always fetches and succeeds", policy: PullAlways, denied: true, cached: true, wantFetch: true},
		{name: "always with a network error uses the cache", policy: PullAlways, denied: true, cached: true, pullErr: networkErr, wantFetch: true},
		{name: "always with a network error and no cache fails", policy: PullAlways, denied: true, pullErr: networkErr, wantFetch: true,
			wantErr: func(err error) bool { var ne net.Error; return errors.As(err, &ne) }},
		{name: "always with 401 uses the cache and warns", policy: PullAlways, denied: true, cached: true, pullErr: statusErr(401), wantFetch: true, wantWarn: true},
		{name: "always with 403 uses the cache and warns", policy: PullAlways, denied: true, cached: true, pullErr: statusErr(403), wantFetch: true, wantWarn: true},
		{name: "always with 404 uses the cache and warns", policy: PullAlways, denied: true, cached: true, pullErr: statusErr(404), wantFetch: true, wantWarn: true},
		{name: "always with missing credentials uses the cache and warns", policy: PullAlways, denied: true, cached: true, pullErr: authErr, wantFetch: true, wantWarn: true},
		{name: "always with 401 and no cache returns the registry error", policy: PullAlways, denied: true, pullErr: statusErr(401), wantFetch: true,
			wantErr: func(err error) bool {
				var se *oci.StatusError
				return errors.As(err, &se) && se.StatusCode == 401
			}},
		{name: "always with 500 does not use the cache", policy: PullAlways, denied: true, cached: true, pullErr: statusErr(500), wantFetch: true,
			wantErr: func(err error) bool {
				var se *oci.StatusError
				return errors.As(err, &se) && se.StatusCode == 500
			}},
		{name: "always for rungv pull does not use the cache after 401", policy: PullAlways, cached: true, pullErr: statusErr(401), wantFetch: true,
			wantErr: func(err error) bool {
				var se *oci.StatusError
				return errors.As(err, &se) && se.StatusCode == 401
			}},
		{name: "missing with a cache does not fetch", policy: PullMissing, denied: true, cached: true, pullErr: statusErr(401)},
		{name: "missing without a cache fetches", policy: PullMissing, denied: true, wantFetch: true},
		{name: "missing without a cache reports a failed fetch", policy: PullMissing, denied: true, pullErr: statusErr(401), wantFetch: true,
			wantErr: func(err error) bool { return isRegistryDenied(err) }},
		{name: "never with a cache does not fetch", policy: PullNever, denied: true, cached: true, pullErr: statusErr(401)},
		{name: "never without a cache fails and does not fetch", policy: PullNever, denied: true,
			wantErr: func(err error) bool {
				return errors.Is(err, oci.ErrNotCached) && strings.Contains(err.Error(), `"gvx/ref:v1"`) && strings.Contains(err.Error(), "never")
			}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPullPolicyFixture(t, tt.cached)
			var fetches int
			pull := func(ctx context.Context, client *http.Client, baseURL, repo, tag, arch string, cache *oci.LayerCache) (*oci.ResolvedImage, error) {
				fetches++
				if tt.pullErr != nil {
					return nil, tt.pullErr
				}
				return oci.PullRegistryImage(ctx, client, baseURL, repo, tag, arch, cache)
			}
			var warnings bytes.Buffer
			order := pullOrder{policy: tt.policy, useCacheWhenDenied: tt.denied, warnings: &warnings}

			img, err := resolveRegistryImage(context.Background(), f.cache, f.request(), order, pull)
			if img != nil {
				t.Cleanup(func() { _ = img.Close() })
			}
			if (fetches > 0) != tt.wantFetch {
				t.Errorf("fetches = %d, want a fetch: %v", fetches, tt.wantFetch)
			}
			if tt.wantErr != nil {
				if err == nil || !tt.wantErr(err) {
					t.Fatalf("error = %v, want the expected failure", err)
				}
			} else if err != nil {
				t.Fatalf("resolveRegistryImage failed: %v", err)
			} else if tt.cached && tt.pullErr != nil && img.ManifestDigest != f.digest {
				t.Errorf("digest = %q, want the cached %q", img.ManifestDigest, f.digest)
			}
			lines := strings.Count(warnings.String(), "\n")
			if tt.wantWarn && (lines != 1 || !strings.Contains(warnings.String(), "using the cached image")) {
				t.Errorf("warnings = %q, want one line about the cached image", warnings.String())
			}
			if !tt.wantWarn && lines != 0 {
				t.Errorf("warnings = %q, want none", warnings.String())
			}
		})
	}
}

func TestResolveRegistryImageKeepsContextErrors(t *testing.T) {
	f := newPullPolicyFixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	pull := func(context.Context, *http.Client, string, string, string, string, *oci.LayerCache) (*oci.ResolvedImage, error) {
		cancel()
		return nil, &oci.StatusError{URL: "u", StatusCode: 401}
	}
	_, err := resolveRegistryImage(ctx, f.cache, f.request(), pullOrder{policy: PullAlways, useCacheWhenDenied: true}, pull)
	var se *oci.StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want the registry error, not the cache", err)
	}
}

// gatedRegistry forwards to a registry until deny is set. Then it answers
// every request with status.
func gatedRegistry(t *testing.T, target string, status int, challenge string) (baseURL string, deny *atomic.Bool) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(u)
	deny = new(atomic.Bool)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deny.Load() {
			if challenge != "" {
				w.Header().Set("Www-Authenticate", challenge)
			}
			w.WriteHeader(status)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv.URL, deny
}

func TestResolveImageWithPolicyUsesALoadedImageWhenTheRegistryDeniesIt(t *testing.T) {
	t.Setenv("DOCKER_CONFIG", t.TempDir())
	for _, tt := range []struct {
		name      string
		status    int
		challenge string
	}{
		{"unauthorized with a basic challenge", http.StatusUnauthorized, `Basic realm="registry"`},
		{"not found", http.StatusNotFound, ""},
		{"forbidden", http.StatusForbidden, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reg, _ := referenceRegistry(t)
			baseURL, deny := gatedRegistry(t, reg.URL, tt.status, tt.challenge)
			cache, err := NewLayerCache(t.TempDir())
			if err != nil {
				t.Fatalf("NewLayerCache failed: %v", err)
			}
			image := pullPolicyRepo + ":v1"
			seed, err := ResolveImage(context.Background(), cache, baseURL, image, runtime.GOARCH)
			if err != nil {
				t.Fatalf("seed ResolveImage failed: %v", err)
			}
			want := seed.ManifestDigest
			_ = seed.Close()
			deny.Store(true)

			var warnings bytes.Buffer
			img, err := ResolveImageWithPolicy(context.Background(), cache, baseURL, image, runtime.GOARCH, PullAlways, &warnings)
			if err != nil {
				t.Fatalf("ResolveImageWithPolicy failed: %v", err)
			}
			defer img.Close()
			if img.ManifestDigest != want {
				t.Errorf("digest = %q, want the cached %q", img.ManifestDigest, want)
			}
			if got := warnings.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "using the cached image") {
				t.Errorf("warnings = %q, want one line", got)
			}

			if _, err := ResolveImage(context.Background(), cache, baseURL, image, runtime.GOARCH); err == nil {
				t.Errorf("ResolveImage with a denying registry succeeded, want the registry error for rungv pull")
			}
			uncached, err := NewLayerCache(t.TempDir())
			if err != nil {
				t.Fatalf("NewLayerCache failed: %v", err)
			}
			if _, err := ResolveImageWithPolicy(context.Background(), uncached, baseURL, image, runtime.GOARCH, PullAlways, nil); err == nil {
				t.Errorf("ResolveImageWithPolicy without a cached image succeeded, want an error")
			}
		})
	}
}

func TestResolveImageWithPolicyRejectsAnUnknownPolicy(t *testing.T) {
	cache, err := NewLayerCache(t.TempDir())
	if err != nil {
		t.Fatalf("NewLayerCache failed: %v", err)
	}
	_, err = ResolveImageWithPolicy(context.Background(), cache, "", "alpine:3.20", runtime.GOARCH, "sometimes", nil)
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("error = %v, want ErrInvalidConfig", err)
	}
}

func TestParsePullPolicy(t *testing.T) {
	for in, want := range map[string]PullPolicy{
		"": PullMissing, "always": PullAlways, " Missing ": PullMissing, "NEVER": PullNever,
	} {
		got, err := ParsePullPolicy(in)
		if err != nil || got != want {
			t.Errorf("ParsePullPolicy(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	if _, err := ParsePullPolicy("if-not-present"); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("ParsePullPolicy(\"if-not-present\") error = %v, want ErrInvalidConfig", err)
	}
}

func TestConfigNormalizeValidatesThePullPolicy(t *testing.T) {
	cfg := Config{PullPolicy: "sometimes"}
	if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize with an unknown pull policy = %v, want ErrInvalidConfig", err)
	}
	cfg = Config{}
	if err := cfg.normalize(); err != nil || cfg.PullPolicy != PullMissing {
		t.Fatalf("normalize of the zero config = %v with policy %q, want PullMissing", err, cfg.PullPolicy)
	}
}
