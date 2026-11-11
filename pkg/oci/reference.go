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
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"
)

// ErrInvalidReference reports an image reference that breaks the Docker
// reference grammar. The error text names the broken part.
var ErrInvalidReference = errors.New("oci: invalid image reference")

var anchoredDomainRegexp = regexp.MustCompile("^" + reference.DomainRegexp.String() + "$")

const (
	// DockerHubRegistry is the canonical registry name of Docker Hub.
	DockerHubRegistry = "docker.io"
	// hubRepositoryRoot prefixes a Docker Hub repository of one component.
	hubRepositoryRoot   = "library/"
	placeholderRegistry = "registry.invalid"
)

// Reference names an image in a registry. Registry is the canonical host
// with an optional port. Docker Hub is always "docker.io". Repository is the
// path inside the registry, and a Docker Hub path with one component has the
// "library/" prefix. A reference without a tag and a digest has the tag
// "latest". A reference can carry both: the digest then selects the content.
type Reference struct {
	Registry   string
	Repository string
	Tag        string
	Digest     string
}

// ParseReference parses a Docker image reference such as "alpine:3.20",
// "ghcr.io/org/img:v1", or "name@sha256:<64 hex digits>". The first path
// component names a registry only if it contains "." or ":" or equals
// "localhost". Other names live on Docker Hub.
func ParseReference(s string) (Reference, error) {
	if s == "" {
		return Reference{}, fmt.Errorf("%w: reference is empty", ErrInvalidReference)
	}
	input := s
	if first, rest, ok := strings.Cut(s, "/"); ok {
		host := strings.ToLower(first)
		switch {
		case dockerHubHosts[host]:
			input = DockerHubRegistry + "/" + rest
		case isRegistryComponent(first):
			if err := validateRegistryHost(host); err != nil {
				return Reference{}, invalidReference(s, "%v", err)
			}
			input = host + "/" + rest
		default:
			input = DockerHubRegistry + "/" + s
		}
	}
	named, err := parseNamed(s, input)
	if err != nil {
		return Reference{}, err
	}
	domain := strings.ToLower(reference.Domain(named))
	if err := validateRegistryHost(domain); err != nil {
		return Reference{}, invalidReference(s, "%v", err)
	}
	tag, dgst := extractTagAndDigest(named)
	return Reference{
		Registry:   domain,
		Repository: reference.Path(named),
		Tag:        tag,
		Digest:     dgst,
	}, nil
}

// ParseReferenceAt parses s for an explicit registry base URL, such as the
// -registry-url flag. A registry host in s is dropped and baseURL names the
// registry. The repository path stays as written, except that a Docker Hub
// base URL adds "library/" to a one-component name.
func ParseReferenceAt(s, baseURL string) (Reference, error) {
	if s == "" {
		return Reference{}, fmt.Errorf("%w: reference is empty", ErrInvalidReference)
	}
	pathSpec := s
	if first, rest, ok := strings.Cut(s, "/"); ok && isRegistryComponent(first) {
		if err := validateRegistryHost(strings.ToLower(first)); err != nil {
			return Reference{}, invalidReference(s, "%v", err)
		}
		pathSpec = rest
	}
	named, err := parseNamed(s, placeholderRegistry+"/"+pathSpec)
	if err != nil {
		return Reference{}, err
	}
	tag, dgst := extractTagAndDigest(named)
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	return Reference{
		Registry:   registryOfBaseURL(baseURL),
		Repository: NormalizeRegistryRepo(baseURL, reference.Path(named)),
		Tag:        tag,
		Digest:     dgst,
	}, nil
}

func invalidReference(s, format string, args ...any) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidReference, s, fmt.Sprintf(format, args...))
}

func parseNamed(raw, input string) (reference.Named, error) {
	if namePart, digestPart, hasAt := strings.Cut(raw, "@"); hasAt && namePart != "" {
		d, err := digest.Parse(digestPart)
		if err != nil {
			return nil, invalidReference(raw, "invalid digest %q: %v", digestPart, err)
		}
		if d.Algorithm() != digest.SHA256 {
			return nil, invalidReference(raw, "unsupported digest algorithm %q", d.Algorithm())
		}
	}
	named, err := reference.ParseNormalizedNamed(input)
	if err != nil {
		if errors.Is(err, reference.ErrNameContainsUppercase) || strings.Contains(err.Error(), "must be lowercase") {
			return nil, invalidReference(raw, "%v (uppercase characters are not allowed)", err)
		}
		return nil, invalidReference(raw, "%v", err)
	}
	return named, nil
}

func extractTagAndDigest(named reference.Named) (tag, dgst string) {
	if tagged, ok := named.(reference.NamedTagged); ok {
		tag = tagged.Tag()
	}
	if digested, ok := named.(reference.Digested); ok {
		dgst = digested.Digest().String()
	}
	if tag == "" && dgst == "" {
		if tagged, ok := reference.TagNameOnly(named).(reference.NamedTagged); ok {
			tag = tagged.Tag()
		}
	}
	return tag, dgst
}

// isRegistryComponent applies the Docker rule for the first path component.
func isRegistryComponent(c string) bool {
	return strings.ContainsAny(c, ".:") || c == "localhost"
}

func validateRegistryHost(host string) error {
	if host == "" || host != strings.ToLower(host) || !anchoredDomainRegexp.MatchString(host) {
		return fmt.Errorf("invalid reference format: invalid registry host %q", host)
	}
	hostname, port := host, ""
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		hostname, port = host[1:end], strings.TrimPrefix(host[end+1:], ":")
		if _, err := netip.ParseAddr(hostname); err != nil {
			return fmt.Errorf("registry host %q has an invalid IPv6 address", host)
		}
	} else if i := strings.IndexByte(host, ':'); i >= 0 {
		port = host[i+1:]
	}
	if port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("registry host %q has an invalid port", host)
		}
	}
	return nil
}

// registryOfBaseURL returns the registry name that a stored base URL denotes.
func registryOfBaseURL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.EqualFold(trimmed, DefaultRegistryBaseURL) {
		return DockerHubRegistry
	}
	if u, err := url.Parse(trimmed); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	return strings.ToLower(trimmed)
}

// referenceOf builds the reference of a stored image record.
func referenceOf(baseURL, repository string) Reference {
	return Reference{Registry: registryOfBaseURL(baseURL), Repository: repository}
}

// BaseURL returns the registry endpoint of the reference. Docker Hub maps to
// its registry host. Other registries use https, except localhost,
// 127.0.0.0/8, and [::1], which use http.
func (r Reference) BaseURL() string {
	if r.Registry == DockerHubRegistry {
		return DefaultRegistryBaseURL
	}
	scheme := "https"
	if isLoopbackRegistry(r.Registry) {
		scheme = "http"
	}
	return scheme + "://" + r.Registry
}

func isLoopbackRegistry(registry string) bool {
	host := registry
	if strings.HasPrefix(host, "[") {
		if end := strings.IndexByte(host, ']'); end > 0 {
			host = host[1:end]
		}
	} else if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

// ManifestReference returns the value that a registry takes after
// /manifests/. A digest wins over a tag.
func (r Reference) ManifestReference() string {
	if r.Digest != "" {
		return r.Digest
	}
	return r.Tag
}

// Name returns the canonical repository name without tag and digest, such as
// "docker.io/library/alpine".
func (r Reference) Name() string {
	return r.Registry + "/" + r.Repository
}

// String returns the canonical form, such as "docker.io/library/alpine:3.20".
func (r Reference) String() string {
	return r.Name() + r.suffix()
}

func (r Reference) suffix() string {
	var sb strings.Builder
	if r.Tag != "" {
		sb.WriteString(":" + r.Tag)
	}
	if r.Digest != "" {
		sb.WriteString("@" + r.Digest)
	}
	return sb.String()
}

// FamiliarName returns the repository name as users write it. Docker Hub
// drops the host and drops "library/", so "docker.io/library/alpine" becomes
// "alpine" and "docker.io/me/app" becomes "me/app".
func (r Reference) FamiliarName() string {
	if named, err := reference.WithName(r.Name()); err == nil {
		return reference.FamiliarName(named)
	}
	if r.Registry != DockerHubRegistry {
		return r.Name()
	}
	if rest, ok := strings.CutPrefix(r.Repository, hubRepositoryRoot); ok && !strings.Contains(rest, "/") {
		return rest
	}
	return r.Repository
}

// Familiar returns the display form with tag and digest, such as
// "alpine:3.20" or "ghcr.io/org/img:v1".
func (r Reference) Familiar() string {
	return r.FamiliarName() + r.suffix()
}
