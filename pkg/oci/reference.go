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
)

// ErrInvalidReference reports an image reference that breaks the Docker
// reference grammar. The error text names the broken part.
var ErrInvalidReference = errors.New("oci: invalid image reference")

const (
	// DockerHubRegistry is the canonical registry name of Docker Hub.
	DockerHubRegistry = "docker.io"
	defaultTag        = "latest"
	maxRepositoryLen  = 255
	// hubRepositoryRoot prefixes a Docker Hub repository of one component.
	hubRepositoryRoot = "library/"
)

var (
	tagPattern       = regexp.MustCompile(`^[0-9A-Za-z_][0-9A-Za-z_.-]{0,127}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repoPartPattern  = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	hostLabelPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
	dockerHubAliases = map[string]bool{"docker.io": true, "index.docker.io": true, "registry-1.docker.io": true}
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

// rawReference is the result of the grammar step, before Docker Hub defaults.
type rawReference struct {
	// registry is the host as written, lowercase, or empty.
	registry string
	// path is the repository path as written.
	path   string
	tag    string
	digest string
}

// ParseReference parses a Docker image reference such as "alpine:3.20",
// "ghcr.io/org/img:v1", or "name@sha256:<64 hex digits>". The first path
// component names a registry only if it contains "." or ":" or equals
// "localhost". Other names live on Docker Hub.
func ParseReference(s string) (Reference, error) {
	raw, err := splitReference(s)
	if err != nil {
		return Reference{}, err
	}
	registry := raw.registry
	if registry == "" || dockerHubAliases[registry] {
		registry = DockerHubRegistry
	}
	repo := raw.path
	if registry == DockerHubRegistry && !strings.Contains(repo, "/") {
		repo = hubRepositoryRoot + repo
	}
	if len(repo) > maxRepositoryLen {
		return Reference{}, invalidReference(s, "repository name is longer than %d characters", maxRepositoryLen)
	}
	ref := Reference{Registry: registry, Repository: repo, Tag: raw.tag, Digest: raw.digest}
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = defaultTag
	}
	return ref, nil
}

// ParseReferenceAt parses s for an explicit registry base URL, such as the
// -registry-url flag. A registry host in s is dropped and baseURL names the
// registry. The repository path stays as written, except that a Docker Hub
// base URL adds "library/" to a one-component name.
func ParseReferenceAt(s, baseURL string) (Reference, error) {
	raw, err := splitReference(s)
	if err != nil {
		return Reference{}, err
	}
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	ref := Reference{
		Registry:   registryOfBaseURL(baseURL),
		Repository: NormalizeRegistryRepo(baseURL, raw.path),
		Tag:        raw.tag,
		Digest:     raw.digest,
	}
	if ref.Tag == "" && ref.Digest == "" {
		ref.Tag = defaultTag
	}
	return ref, nil
}

func invalidReference(s, format string, args ...any) error {
	return fmt.Errorf("%w %q: %s", ErrInvalidReference, s, fmt.Sprintf(format, args...))
}

// outsideBrackets returns s without a leading "[...]" IPv6 host. An unclosed
// bracket returns an empty string, and host validation reports it.
func outsideBrackets(s string) string {
	if !strings.HasPrefix(s, "[") {
		return s
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return ""
	}
	return s[end+1:]
}

// splitReference applies the reference grammar and leaves the defaults of
// Docker Hub to the caller.
func splitReference(s string) (rawReference, error) {
	switch {
	case s == "":
		return rawReference{}, fmt.Errorf("%w: the reference is empty", ErrInvalidReference)
	case strings.ContainsFunc(s, func(r rune) bool { return r <= ' ' || r == 0x7f }):
		return rawReference{}, invalidReference(s, "it contains a space or control character")
	case strings.Contains(outsideBrackets(s), "::"):
		return rawReference{}, invalidReference(s, "it contains a double colon")
	case strings.HasSuffix(s, "/"):
		return rawReference{}, invalidReference(s, "it ends with a slash")
	case strings.HasPrefix(s, "/"):
		return rawReference{}, invalidReference(s, "it starts with a slash")
	}

	var raw rawReference
	name := s
	if at := strings.IndexByte(name, '@'); at >= 0 {
		name, raw.digest = name[:at], name[at+1:]
		if !digestPattern.MatchString(raw.digest) {
			return rawReference{}, invalidReference(s, "digest %q must be sha256: followed by 64 lowercase hex digits", raw.digest)
		}
	}
	if name == "" {
		return rawReference{}, invalidReference(s, "the image name is empty")
	}

	slash := strings.LastIndexByte(name, '/')
	if colon := strings.LastIndexByte(name[slash+1:], ':'); colon >= 0 {
		colon += slash + 1
		name, raw.tag = name[:colon], name[colon+1:]
		if raw.tag == "" {
			return rawReference{}, invalidReference(s, "the tag after the colon is empty")
		}
		if !tagPattern.MatchString(raw.tag) {
			return rawReference{}, invalidReference(s, "tag %q must match [\\w][\\w.-]{0,127}", raw.tag)
		}
	}
	if name == "" {
		return rawReference{}, invalidReference(s, "the image name is empty")
	}

	raw.path = name
	if first, rest, ok := strings.Cut(name, "/"); ok && isRegistryComponent(first) {
		host := strings.ToLower(first)
		if err := validateRegistryHost(host); err != nil {
			return rawReference{}, invalidReference(s, "%v", err)
		}
		raw.registry, raw.path = host, rest
	}
	if err := validateRepositoryPath(raw.path); err != nil {
		return rawReference{}, invalidReference(s, "%v", err)
	}
	return raw, nil
}

// isRegistryComponent applies the Docker rule for the first path component.
func isRegistryComponent(c string) bool {
	return strings.ContainsAny(c, ".:") || c == "localhost"
}

func validateRepositoryPath(path string) error {
	for part := range strings.SplitSeq(path, "/") {
		switch {
		case part == "":
			return errors.New("the repository path has an empty component")
		case part != strings.ToLower(part):
			return fmt.Errorf("repository component %q has uppercase letters, which Docker rejects", part)
		case !repoPartPattern.MatchString(part):
			return fmt.Errorf("repository component %q must use lowercase letters, digits, and the separators . _ -", part)
		}
	}
	return nil
}

func validateRegistryHost(host string) error {
	hostname, port := host, ""
	if strings.HasPrefix(host, "[") {
		end := strings.IndexByte(host, ']')
		if end < 0 {
			return fmt.Errorf("registry host %q has an unclosed bracket", host)
		}
		hostname, port = host[1:end], host[end+1:]
		if _, err := netip.ParseAddr(hostname); err != nil {
			return fmt.Errorf("registry host %q has an invalid IPv6 address", host)
		}
		if port != "" {
			if port[0] != ':' {
				return fmt.Errorf("registry host %q has text after the bracket", host)
			}
			port = port[1:]
			if port == "" {
				return fmt.Errorf("registry host %q has an empty port", host)
			}
		}
	} else if i := strings.IndexByte(host, ':'); i >= 0 {
		hostname, port = host[:i], host[i+1:]
		if port == "" {
			return fmt.Errorf("registry host %q has an empty port", host)
		}
		hostname = strings.TrimSuffix(hostname, ".")
	}
	if port != "" {
		if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
			return fmt.Errorf("registry host %q has an invalid port", host)
		}
	}
	if strings.HasPrefix(host, "[") {
		return nil
	}
	for label := range strings.SplitSeq(hostname, ".") {
		if !hostLabelPattern.MatchString(label) {
			return fmt.Errorf("registry host %q has an invalid name", host)
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
