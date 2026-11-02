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
	"errors"
	"net/http"
	"testing"
)

// schema1Payload is the unsigned part of a Docker schema 1 manifest.
const schema1Payload = `{"schemaVersion":1,"name":"app","tag":"latest","architecture":"amd64","fsLayers":[{"blobSum":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"history":[{"v1Compatibility":"{}"}]`

func TestPullNamesSchema1ManifestsInsteadOfADigestMismatch(t *testing.T) {
	// A registry reports the digest of the unsigned payload for a signed
	// schema 1 manifest, so the digest of the served body never matches.
	payloadDigest := sha256Digest([]byte(schema1Payload + "}"))
	signed := schema1Payload + `,"signatures":[{"header":{"alg":"ES256"},"signature":"AAAA","protected":"BBBB"}]}`
	tests := []struct {
		name        string
		contentType string
		body        string
	}{
		{"signed prettyjws", "application/vnd.docker.distribution.manifest.v1+prettyjws", signed},
		{"plain v1+json", "application/vnd.docker.distribution.manifest.v1+json", schema1Payload + "}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := newFakeRegistry(t)
			reg.onManifest = func(w http.ResponseWriter, r *http.Request, ref string) bool {
				w.Header().Set("Content-Type", tt.contentType)
				w.Header().Set("Docker-Content-Digest", payloadDigest)
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(tt.body))
				}
				return true
			}
			base, repo := pullArgs(reg)
			_, err := PullRegistryImage(context.Background(), nil, base, repo, "latest", "amd64", newCache(t))
			if !errors.Is(err, ErrSchema1Unsupported) {
				t.Fatalf("err = %v, want ErrSchema1Unsupported", err)
			}
			if errors.Is(err, ErrDigestMismatch) {
				t.Errorf("err = %v, must not report a digest mismatch", err)
			}
		})
	}
}

func TestRejectSchema1LeavesOtherBodiesToLaterSteps(t *testing.T) {
	for name, body := range map[string]string{
		"oci manifest": `{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`,
		"not json":     `not json`,
		"empty":        ``,
	} {
		if err := rejectSchema1([]byte(body)); err != nil {
			t.Errorf("rejectSchema1(%s) = %v, want nil", name, err)
		}
	}
}
