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
	"strings"
	"testing"
)

const refTestDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseReferenceAcceptsDockerForms(t *testing.T) {
	for _, tc := range []struct {
		name         string
		in           string
		want         Reference
		wantBaseURL  string
		wantManifest string
		wantString   string
		wantFamiliar string
	}{
		{
			name:         "bare name gets library and latest",
			in:           "alpine",
			want:         Reference{Registry: "docker.io", Repository: "library/alpine", Tag: "latest"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "latest",
			wantString:   "docker.io/library/alpine:latest",
			wantFamiliar: "alpine:latest",
		},
		{
			name:         "hub name with tag",
			in:           "alpine:3.20",
			want:         Reference{Registry: "docker.io", Repository: "library/alpine", Tag: "3.20"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "3.20",
			wantString:   "docker.io/library/alpine:3.20",
			wantFamiliar: "alpine:3.20",
		},
		{
			name:         "hub user repository keeps its path",
			in:           "me/app:v2",
			want:         Reference{Registry: "docker.io", Repository: "me/app", Tag: "v2"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "v2",
			wantString:   "docker.io/me/app:v2",
			wantFamiliar: "me/app:v2",
		},
		{
			name:         "explicit library prefix",
			in:           "docker.io/library/alpine:3",
			want:         Reference{Registry: "docker.io", Repository: "library/alpine", Tag: "3"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "3",
			wantString:   "docker.io/library/alpine:3",
			wantFamiliar: "alpine:3",
		},
		{
			name:         "index.docker.io alias",
			in:           "index.docker.io/me/app",
			want:         Reference{Registry: "docker.io", Repository: "me/app", Tag: "latest"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "latest",
			wantString:   "docker.io/me/app:latest",
			wantFamiliar: "me/app:latest",
		},
		{
			name:         "registry-1.docker.io alias with one component",
			in:           "registry-1.docker.io/busybox:1.36",
			want:         Reference{Registry: "docker.io", Repository: "library/busybox", Tag: "1.36"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "1.36",
			wantString:   "docker.io/library/busybox:1.36",
			wantFamiliar: "busybox:1.36",
		},
		{
			name:         "ghcr registry",
			in:           "ghcr.io/org/img:v1",
			want:         Reference{Registry: "ghcr.io", Repository: "org/img", Tag: "v1"},
			wantBaseURL:  "https://ghcr.io",
			wantManifest: "v1",
			wantString:   "ghcr.io/org/img:v1",
			wantFamiliar: "ghcr.io/org/img:v1",
		},
		{
			name:         "registry with a one-component repository does not get library",
			in:           "quay.io/tool",
			want:         Reference{Registry: "quay.io", Repository: "tool", Tag: "latest"},
			wantBaseURL:  "https://quay.io",
			wantManifest: "latest",
			wantString:   "quay.io/tool:latest",
			wantFamiliar: "quay.io/tool:latest",
		},
		{
			name:         "uppercase registry host is lowercased",
			in:           "GHCR.io/org/img",
			want:         Reference{Registry: "ghcr.io", Repository: "org/img", Tag: "latest"},
			wantBaseURL:  "https://ghcr.io",
			wantManifest: "latest",
			wantString:   "ghcr.io/org/img:latest",
			wantFamiliar: "ghcr.io/org/img:latest",
		},
		{
			name:         "localhost registry uses http",
			in:           "localhost:5000/team/app:dev",
			want:         Reference{Registry: "localhost:5000", Repository: "team/app", Tag: "dev"},
			wantBaseURL:  "http://localhost:5000",
			wantManifest: "dev",
			wantString:   "localhost:5000/team/app:dev",
			wantFamiliar: "localhost:5000/team/app:dev",
		},
		{
			name:         "localhost without a port",
			in:           "localhost/app",
			want:         Reference{Registry: "localhost", Repository: "app", Tag: "latest"},
			wantBaseURL:  "http://localhost",
			wantManifest: "latest",
			wantString:   "localhost/app:latest",
			wantFamiliar: "localhost/app:latest",
		},
		{
			name:         "loopback IPv4 registry uses http",
			in:           "127.0.0.1:41234/gvx/x:v1",
			want:         Reference{Registry: "127.0.0.1:41234", Repository: "gvx/x", Tag: "v1"},
			wantBaseURL:  "http://127.0.0.1:41234",
			wantManifest: "v1",
			wantString:   "127.0.0.1:41234/gvx/x:v1",
			wantFamiliar: "127.0.0.1:41234/gvx/x:v1",
		},
		{
			name:         "other 127 address uses http",
			in:           "127.8.9.10/app",
			want:         Reference{Registry: "127.8.9.10", Repository: "app", Tag: "latest"},
			wantBaseURL:  "http://127.8.9.10",
			wantManifest: "latest",
			wantString:   "127.8.9.10/app:latest",
			wantFamiliar: "127.8.9.10/app:latest",
		},
		{
			name:         "loopback IPv6 registry uses http",
			in:           "[::1]:5000/app:v1",
			want:         Reference{Registry: "[::1]:5000", Repository: "app", Tag: "v1"},
			wantBaseURL:  "http://[::1]:5000",
			wantManifest: "v1",
			wantString:   "[::1]:5000/app:v1",
			wantFamiliar: "[::1]:5000/app:v1",
		},
		{
			name:         "private network address uses https",
			in:           "10.0.0.5:5000/app",
			want:         Reference{Registry: "10.0.0.5:5000", Repository: "app", Tag: "latest"},
			wantBaseURL:  "https://10.0.0.5:5000",
			wantManifest: "latest",
			wantString:   "10.0.0.5:5000/app:latest",
			wantFamiliar: "10.0.0.5:5000/app:latest",
		},
		{
			name:         "digest without tag",
			in:           "alpine@" + refTestDigest,
			want:         Reference{Registry: "docker.io", Repository: "library/alpine", Digest: refTestDigest},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: refTestDigest,
			wantString:   "docker.io/library/alpine@" + refTestDigest,
			wantFamiliar: "alpine@" + refTestDigest,
		},
		{
			name:         "tag and digest select the digest",
			in:           "ghcr.io/org/img:v1@" + refTestDigest,
			want:         Reference{Registry: "ghcr.io", Repository: "org/img", Tag: "v1", Digest: refTestDigest},
			wantBaseURL:  "https://ghcr.io",
			wantManifest: refTestDigest,
			wantString:   "ghcr.io/org/img:v1@" + refTestDigest,
			wantFamiliar: "ghcr.io/org/img:v1@" + refTestDigest,
		},
		{
			name:         "separators inside repository components",
			in:           "org/my-app_v2.core--x:1.0-rc_1",
			want:         Reference{Registry: "docker.io", Repository: "org/my-app_v2.core--x", Tag: "1.0-rc_1"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "1.0-rc_1",
			wantString:   "docker.io/org/my-app_v2.core--x:1.0-rc_1",
			wantFamiliar: "org/my-app_v2.core--x:1.0-rc_1",
		},
		{
			name:         "tag of 128 characters",
			in:           "app:" + strings.Repeat("a", 128),
			want:         Reference{Registry: "docker.io", Repository: "library/app", Tag: strings.Repeat("a", 128)},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: strings.Repeat("a", 128),
			wantString:   "docker.io/library/app:" + strings.Repeat("a", 128),
			wantFamiliar: "app:" + strings.Repeat("a", 128),
		},
		{
			name:         "uppercase tag is legal",
			in:           "app:V1_Final",
			want:         Reference{Registry: "docker.io", Repository: "library/app", Tag: "V1_Final"},
			wantBaseURL:  "https://registry-1.docker.io",
			wantManifest: "V1_Final",
			wantString:   "docker.io/library/app:V1_Final",
			wantFamiliar: "app:V1_Final",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReference(tc.in)
			if err != nil {
				t.Fatalf("ParseReference(%q) failed: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseReference(%q) = %+v, want %+v", tc.in, got, tc.want)
			}
			if got.BaseURL() != tc.wantBaseURL {
				t.Errorf("BaseURL() = %q, want %q", got.BaseURL(), tc.wantBaseURL)
			}
			if got.ManifestReference() != tc.wantManifest {
				t.Errorf("ManifestReference() = %q, want %q", got.ManifestReference(), tc.wantManifest)
			}
			if got.String() != tc.wantString {
				t.Errorf("String() = %q, want %q", got.String(), tc.wantString)
			}
			if got.Familiar() != tc.wantFamiliar {
				t.Errorf("Familiar() = %q, want %q", got.Familiar(), tc.wantFamiliar)
			}
			again, err := ParseReference(got.String())
			if err != nil || again != got {
				t.Errorf("ParseReference(%q) = %+v, %v, want the same reference again", got.String(), again, err)
			}
		})
	}
}

func TestParseReferenceRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", "empty"},
		{"uppercase repository", "Alpine", "uppercase"},
		{"uppercase path component", "me/MyApp:v1", "uppercase"},
		{"uppercase component that looks like a user", "Foo/bar", "uppercase"},
		{"trailing slash", "alpine/", "slash"},
		{"leading slash", "/alpine", "slash"},
		{"double slash", "me//app", "empty component"},
		{"double colon", "alpine::3.20", "double colon"},
		{"empty tag", "alpine:", "tag"},
		{"tag starts with a dash", "alpine:-1", "tag"},
		{"tag starts with a dot", "alpine:.1", "tag"},
		{"tag with a slash", "alpine:a/b", "port"},
		{"tag longer than 128 characters", "alpine:" + strings.Repeat("a", 129), "tag"},
		{"tag with a space", "alpine: 1", "space"},
		{"short digest", "alpine@sha256:abc", "digest"},
		{"digest with uppercase hex", "alpine@sha256:" + strings.ToUpper(strings.Repeat("ab", 32)), "digest"},
		{"digest of another algorithm", "alpine@sha512:" + strings.Repeat("a", 64), "digest"},
		{"digest without algorithm", "alpine@" + strings.Repeat("a", 64), "digest"},
		{"empty digest", "alpine@", "digest"},
		{"two digests", "alpine@" + refTestDigest + "@" + refTestDigest, "digest"},
		{"name missing before digest", "@" + refTestDigest, "name is empty"},
		{"name missing before tag", ":3.20", "name is empty"},
		{"repository with an underscore pair edge", "app_", "lowercase letters"},
		{"repository with a leading dash", "-app", "lowercase letters"},
		{"repository with a plus", "my+app", "lowercase letters"},
		{"registry with an empty port", "localhost:/app", "port"},
		{"registry with a bad port", "localhost:99999/app", "port"},
		{"registry with a bad label", "bad_host.io/app", "invalid name"},
		{"registry with an unclosed bracket", "[::1/app", "bracket"},
		{"repository longer than 255 characters", strings.Repeat("a", 256), "255"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReference(tc.in)
			if err == nil {
				t.Fatalf("ParseReference(%q) = %+v, want an error mentioning %q", tc.in, got, tc.want)
			}
			if !errors.Is(err, ErrInvalidReference) {
				t.Errorf("ParseReference(%q) error %v does not wrap ErrInvalidReference", tc.in, err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("ParseReference(%q) error = %q, want it to mention %q", tc.in, err, tc.want)
			}
		})
	}
}

func TestParseReferenceAtKeepsThePathAsWritten(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      string
		baseURL string
		want    Reference
	}{
		{
			name: "plain name on a custom registry", in: "gvx/app:v1", baseURL: "http://127.0.0.1:5000",
			want: Reference{Registry: "127.0.0.1:5000", Repository: "gvx/app", Tag: "v1"},
		},
		{
			name: "one component stays one component", in: "alpine", baseURL: "http://127.0.0.1:5000/",
			want: Reference{Registry: "127.0.0.1:5000", Repository: "alpine", Tag: "latest"},
		},
		{
			name: "explicit library prefix survives", in: "library/alpine:3", baseURL: "http://127.0.0.1:5000",
			want: Reference{Registry: "127.0.0.1:5000", Repository: "library/alpine", Tag: "3"},
		},
		{
			name: "registry host in the name is dropped", in: "ghcr.io/org/img:v1", baseURL: "http://127.0.0.1:5000",
			want: Reference{Registry: "127.0.0.1:5000", Repository: "org/img", Tag: "v1"},
		},
		{
			name: "docker hub base URL adds library", in: "alpine:3", baseURL: DefaultRegistryBaseURL,
			want: Reference{Registry: "docker.io", Repository: "library/alpine", Tag: "3"},
		},
		{
			name: "digest only", in: "app@" + refTestDigest, baseURL: "https://reg.example",
			want: Reference{Registry: "reg.example", Repository: "app", Digest: refTestDigest},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseReferenceAt(tc.in, tc.baseURL)
			if err != nil {
				t.Fatalf("ParseReferenceAt(%q, %q) failed: %v", tc.in, tc.baseURL, err)
			}
			if got != tc.want {
				t.Errorf("ParseReferenceAt(%q, %q) = %+v, want %+v", tc.in, tc.baseURL, got, tc.want)
			}
		})
	}
	if _, err := ParseReferenceAt("Bad", "http://127.0.0.1:5000"); err == nil {
		t.Errorf("ParseReferenceAt accepted an uppercase repository")
	}
}
