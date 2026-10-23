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
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	// maxRedirects bounds the redirect chain of one request.
	maxRedirects = 10
	// maxTokenBytes bounds a bearer token response.
	maxTokenBytes = 1 << 20
	// defaultIdleTimeout is how long a registry request may go without
	// receiving a byte before it fails.
	defaultIdleTimeout = 60 * time.Second
	userAgent          = "gvx-oci"
)

var manifestAccept = strings.Join([]string{
	mediaTypeOCIIndex,
	mediaTypeDockerList,
	mediaTypeOCIManifest,
	mediaTypeDockerManifest,
}, ", ")

// StatusError reports an unexpected HTTP status from a registry.
type StatusError struct {
	URL        string
	StatusCode int
}

// Error implements error.
func (e *StatusError) Error() string {
	return fmt.Sprintf("oci: request %s returned HTTP %d", e.URL, e.StatusCode)
}

// registryClient talks to one repository of one registry.
type registryClient struct {
	http    *http.Client
	owned   bool
	baseURL *url.URL
	repo    string
	lim     Limits
	idle    time.Duration
	// authz is the Authorization header value that the last challenge produced.
	authz string
	// store supplies the credentials of the registry.
	store CredentialStore
	// fixed replaces the store when set. Login uses it to test credentials
	// that are not stored yet.
	fixed       *Credentials
	credsLoaded bool
	cred        Credentials
	haveCred    bool
	credErr     error
}

func newRegistryClient(client *http.Client, baseURL, repo string, lim Limits) (*registryClient, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("oci: parse registry URL %q: %w", baseURL, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("oci: registry URL %q must be an http or https URL with a host", baseURL)
	}
	rc := &registryClient{baseURL: u, repo: repo, lim: lim, idle: defaultIdleTimeout}
	if client == nil {
		client = newDefaultHTTPClient()
		rc.owned = true
	}
	clone := *client
	orig := client.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("oci: stopped after %d redirects", maxRedirects)
		}
		prev := via[len(via)-1]
		if prev.URL.Scheme == "https" && req.URL.Scheme != "https" {
			return fmt.Errorf("oci: redirect from %s to %s downgrades https", prev.URL.Redacted(), req.URL.Redacted())
		}
		// Go keeps credentials for other ports of the same host. A registry
		// token must reach only the host that issued the request.
		if canonicalHost(req.URL) != canonicalHost(prev.URL) {
			req.Header.Del("Authorization")
		}
		if orig != nil {
			return orig(req, via)
		}
		return nil
	}
	rc.http = &clone
	return rc, nil
}

func newDefaultHTTPClient() *http.Client {
	return &http.Client{Transport: &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   30 * time.Second,
		ExpectContinueTimeout: time.Second,
	}}
}

// close releases idle connections of a client that this call created.
func (rc *registryClient) close() {
	if rc.owned {
		rc.http.CloseIdleConnections()
	}
}

// canonicalHost returns the lowercase host of u without a default port.
func canonicalHost(u *url.URL) string {
	host := strings.ToLower(u.Host)
	switch u.Scheme {
	case "https":
		host = strings.TrimSuffix(host, ":443")
	case "http":
		host = strings.TrimSuffix(host, ":80")
	}
	return host
}

// idleBody cancels its request when no byte arrives within the idle timeout.
type idleBody struct {
	rc     io.ReadCloser
	timer  *time.Timer
	idle   time.Duration
	cancel context.CancelFunc
	parent context.Context
}

func (b *idleBody) Read(p []byte) (int, error) {
	n, err := b.rc.Read(p)
	if n > 0 {
		b.timer.Reset(b.idle)
	}
	if err != nil && !errors.Is(err, io.EOF) && b.parent.Err() == nil {
		return n, fmt.Errorf("oci: registry transfer stalled or failed: %w", err)
	}
	return n, err
}

func (b *idleBody) Close() error {
	b.timer.Stop()
	err := b.rc.Close()
	b.cancel()
	return err
}

// once sends one request with the current credentials.
func (rc *registryClient) once(ctx context.Context, method, rawURL, accept string) (*http.Response, error) {
	reqCtx, cancel := context.WithCancel(ctx)
	timer := time.AfterFunc(rc.idle, cancel)
	req, err := http.NewRequestWithContext(reqCtx, method, rawURL, nil)
	if err != nil {
		timer.Stop()
		cancel()
		return nil, fmt.Errorf("oci: build request %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if rc.authz != "" {
		req.Header.Set("Authorization", rc.authz)
	}
	resp, err := rc.http.Do(req)
	if err != nil {
		timer.Stop()
		// Only the idle timer cancels reqCtx before this call does.
		stalled := ctx.Err() == nil && reqCtx.Err() != nil
		cancel()
		if stalled {
			return nil, fmt.Errorf("oci: request %s received no data for %s", rawURL, rc.idle)
		}
		return nil, fmt.Errorf("oci: request %s: %w", rawURL, err)
	}
	timer.Reset(rc.idle)
	resp.Body = &idleBody{rc: resp.Body, timer: timer, idle: rc.idle, cancel: cancel, parent: ctx}
	return resp, nil
}

// do sends a request and answers one authentication challenge.
func (rc *registryClient) do(ctx context.Context, method, rawURL, accept string) (*http.Response, error) {
	resp, err := rc.once(ctx, method, rawURL, accept)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}
	challenge := resp.Header.Get("Www-Authenticate")
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("oci: close response of %s: %w", rawURL, err)
	}
	if err := rc.authorize(ctx, challenge); err != nil {
		return nil, err
	}
	return rc.once(ctx, method, rawURL, accept)
}

// get sends a GET request and returns the body of a 200 response.
func (rc *registryClient) get(ctx context.Context, rawURL, accept string) (*http.Response, error) {
	resp, err := rc.do(ctx, http.MethodGet, rawURL, accept)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &StatusError{URL: rawURL, StatusCode: resp.StatusCode}
	}
	return resp, nil
}

func (rc *registryClient) manifestURL(ref string) string {
	return fmt.Sprintf("%s/v2/%s/manifests/%s", strings.TrimRight(rc.baseURL.String(), "/"), rc.repo, ref)
}

func (rc *registryClient) blobURL(digest string) string {
	return fmt.Sprintf("%s/v2/%s/blobs/%s", strings.TrimRight(rc.baseURL.String(), "/"), rc.repo, digest)
}

// getManifest returns the body of a manifest or index.
func (rc *registryClient) getManifest(ctx context.Context, ref string) ([]byte, error) {
	u := rc.manifestURL(ref)
	resp, err := rc.get(ctx, u, manifestAccept)
	if err != nil {
		return nil, fmt.Errorf("oci: fetch manifest %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, err := readAllBounded(resp.Body, "manifest size", rc.lim.MaxJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("oci: read manifest %s: %w", u, err)
	}
	return body, nil
}

// resolveTag returns the manifest digest that tag names right now. When the
// registry answers a HEAD request without a digest header, it fetches the
// manifest and also returns the body.
func (rc *registryClient) resolveTag(ctx context.Context, tag string) (digest string, body []byte, err error) {
	u := rc.manifestURL(tag)
	resp, err := rc.do(ctx, http.MethodHead, u, manifestAccept)
	if err != nil {
		return "", nil, err
	}
	status := resp.StatusCode
	header := resp.Header.Get("Docker-Content-Digest")
	if err := resp.Body.Close(); err != nil {
		return "", nil, fmt.Errorf("oci: close response of %s: %w", u, err)
	}
	switch {
	case status == http.StatusOK && isDigestRef(header):
		return header, nil, nil
	case status == http.StatusOK || status == http.StatusMethodNotAllowed || status == http.StatusNotImplemented:
		if body, err = rc.getManifest(ctx, tag); err != nil {
			return "", nil, err
		}
		sum := sha256.Sum256(body)
		return "sha256:" + hex.EncodeToString(sum[:]), body, nil
	default:
		return "", nil, &StatusError{URL: u, StatusCode: status}
	}
}

// getBlobBytes fetches a small blob such as an image config and verifies it.
func (rc *registryClient) getBlobBytes(ctx context.Context, desc Descriptor) ([]byte, error) {
	if desc.Size < 0 || desc.Size > rc.lim.MaxJSONBytes {
		return nil, &LimitError{What: fmt.Sprintf("size of blob %s", desc.Digest), Limit: rc.lim.MaxJSONBytes}
	}
	if _, err := parseDigest(desc.Digest); err != nil {
		return nil, err
	}
	u := rc.blobURL(desc.Digest)
	resp, err := rc.get(ctx, u, "")
	if err != nil {
		return nil, fmt.Errorf("oci: fetch blob %s: %w", u, err)
	}
	defer resp.Body.Close()
	body, err := readAllBounded(resp.Body, "blob size", rc.lim.MaxJSONBytes)
	if err != nil {
		return nil, fmt.Errorf("oci: read blob %s: %w", u, err)
	}
	if err := verifyBody(desc, body); err != nil {
		return nil, fmt.Errorf("oci: blob %s: %w", desc.Digest, err)
	}
	return body, nil
}

// openBlob streams a blob. The caller verifies the digest while it reads.
func (rc *registryClient) openBlob(ctx context.Context, digest string) (io.ReadCloser, error) {
	u := rc.blobURL(digest)
	resp, err := rc.get(ctx, u, "")
	if err != nil {
		return nil, fmt.Errorf("oci: fetch blob %s: %w", u, err)
	}
	return resp.Body, nil
}

// challenge is a parsed WWW-Authenticate header.
type challenge struct {
	scheme string
	params map[string]string
}

// parseChallenge parses `Scheme key="value", key=value`. Quoted values can
// contain commas, as Docker scopes do.
func parseChallenge(h string) challenge {
	h = strings.TrimSpace(h)
	scheme, rest, _ := strings.Cut(h, " ")
	c := challenge{scheme: strings.ToLower(scheme), params: make(map[string]string)}
	for rest = strings.TrimSpace(rest); rest != ""; {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			break
		}
		key := strings.ToLower(strings.TrimSpace(rest[:eq]))
		rest = strings.TrimSpace(rest[eq+1:])
		var value string
		if strings.HasPrefix(rest, `"`) {
			var sb strings.Builder
			i := 1
			for ; i < len(rest) && rest[i] != '"'; i++ {
				if rest[i] == '\\' && i+1 < len(rest) {
					i++
				}
				sb.WriteByte(rest[i])
			}
			value = sb.String()
			rest = rest[min(i+1, len(rest)):]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				end = len(rest)
			}
			value = strings.TrimSpace(rest[:end])
			rest = rest[end:]
		}
		c.params[key] = value
		rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ","))
	}
	return c
}

// dockerHubHosts are the host names of Docker Hub's registry and its token
// service. Docker Hub issues tokens for registry-1.docker.io from
// auth.docker.io, so credentials for the registry may go to that realm.
var dockerHubHosts = map[string]bool{
	"registry-1.docker.io": true,
	"index.docker.io":      true,
	"registry.docker.io":   true,
	"docker.io":            true,
	"auth.docker.io":       true,
}

// realmMayReceiveCredentials reports whether stored credentials for the
// registry may be sent to the token realm. They may go to the registry's own
// host, or between Docker Hub's hosts, and never over a downgraded scheme.
func realmMayReceiveCredentials(registry, realm *url.URL) bool {
	if registry.Scheme == "https" && realm.Scheme != "https" {
		return false
	}
	if canonicalHost(registry) == canonicalHost(realm) {
		return true
	}
	return dockerHubHosts[strings.ToLower(registry.Hostname())] && dockerHubHosts[strings.ToLower(realm.Hostname())]
}

type bearerTokenResponse struct {
	Token       string `json:"token"`
	AccessToken string `json:"access_token"`
}

// credentials returns the stored credentials for the registry. It asks the
// store once and keeps the answer, so a retry does not run a helper again.
func (rc *registryClient) credentials(ctx context.Context) (Credentials, bool, error) {
	if rc.fixed != nil {
		return *rc.fixed, true, nil
	}
	if !rc.credsLoaded {
		rc.cred, rc.haveCred, rc.credErr = rc.store.Lookup(ctx, rc.baseURL.String())
		rc.credsLoaded = true
	}
	return rc.cred, rc.haveCred, rc.credErr
}

// authorize answers a 401 challenge and stores the resulting credentials.
func (rc *registryClient) authorize(ctx context.Context, header string) error {
	ch := parseChallenge(header)
	cred, haveCred, err := rc.credentials(ctx)
	if err != nil {
		return err
	}
	switch ch.scheme {
	case "basic":
		if !haveCred || (cred.Username == "" && cred.Password == "") {
			return fmt.Errorf("oci: basic authentication required by %s but no credentials found in docker config", rc.baseURL.Host)
		}
		rc.authz = "Basic " + base64.StdEncoding.EncodeToString([]byte(cred.Username+":"+cred.Password))
		return nil
	case "bearer":
		token, err := rc.fetchBearerToken(ctx, ch, cred, haveCred)
		if err != nil {
			return err
		}
		rc.authz = "Bearer " + token
		return nil
	default:
		return fmt.Errorf("oci: unsupported WWW-Authenticate challenge %q", header)
	}
}

func (rc *registryClient) fetchBearerToken(ctx context.Context, ch challenge, cred Credentials, haveCred bool) (string, error) {
	realm := ch.params["realm"]
	if realm == "" {
		return "", errors.New("oci: missing realm in WWW-Authenticate challenge")
	}
	u, err := url.Parse(realm)
	if err != nil {
		return "", fmt.Errorf("oci: parse auth realm %q: %w", realm, err)
	}
	if (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return "", fmt.Errorf("oci: auth realm %q must be an http or https URL", realm)
	}
	// Stored credentials go only to a realm that belongs to the registry.
	// Any other realm receives an anonymous request.
	useCred := haveCred && realmMayReceiveCredentials(rc.baseURL, u)

	var req *http.Request
	if useCred && cred.Username == "" && cred.Password == "" && cred.IdentityToken != "" {
		form := url.Values{
			"grant_type":    {"refresh_token"},
			"refresh_token": {cred.IdentityToken},
			"client_id":     {userAgent},
		}
		if s := ch.params["service"]; s != "" {
			form.Set("service", s)
		}
		if s := ch.params["scope"]; s != "" {
			form.Set("scope", s)
		}
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, u.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return "", fmt.Errorf("oci: build token request: %w", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		q := u.Query()
		if s := ch.params["service"]; s != "" {
			q.Set("service", s)
		}
		if s := ch.params["scope"]; s != "" {
			q.Set("scope", s)
		}
		u.RawQuery = q.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return "", fmt.Errorf("oci: build token request: %w", err)
		}
		if useCred && (cred.Username != "" || cred.Password != "") {
			req.SetBasicAuth(cred.Username, cred.Password)
		}
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := rc.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("oci: fetch bearer token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", &StatusError{URL: u.Redacted(), StatusCode: resp.StatusCode}
	}
	body, err := readAllBounded(resp.Body, "token response size", maxTokenBytes)
	if err != nil {
		return "", fmt.Errorf("oci: read bearer token: %w", err)
	}
	var tok bearerTokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return "", fmt.Errorf("oci: decode bearer token JSON: %w", err)
	}
	switch {
	case tok.Token != "":
		return tok.Token, nil
	case tok.AccessToken != "":
		return tok.AccessToken, nil
	default:
		return "", errors.New("oci: empty bearer token in auth response")
	}
}
