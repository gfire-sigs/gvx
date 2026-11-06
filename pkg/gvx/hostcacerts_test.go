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

import "testing"

func TestCoveredByMountMatchesThePointAndEverythingBelowIt(t *testing.T) {
	covered := coveredByMount([]Mount{
		{GuestPath: "/etc/ssl/certs"},
		{GuestPath: "/etc/ssl/cert.pem"},
		{GuestPath: "/data/"},
	})
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/etc/ssl/certs", true},
		{"/etc/ssl/certs/ca-certificates.crt", true},
		{"/etc/ssl/cert.pem", true},
		{"/etc/ssl/certs-extra/ca.crt", false},
		{"/etc/ssl", false},
		{"/etc/ssl/cert.pem.bak", false},
		{"/data/x", true},
		{"/usr/local/share/ca-certificates/gvx-host-1.crt", false},
	} {
		if got := covered(tc.path); got != tc.want {
			t.Errorf("covered(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestCoveredByMountWithoutMountsCoversNothing(t *testing.T) {
	if coveredByMount(nil)("/etc/ssl/certs/ca-certificates.crt") {
		t.Error("a sandbox without mounts covers a path")
	}
}
