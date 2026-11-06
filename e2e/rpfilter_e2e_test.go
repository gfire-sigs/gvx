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

//go:build darwin || windows || linux

package e2e

import "testing"

// TestE2ERPFilterSysctl checks the files conf/{all,default,<link>}/rp_filter.
// They hold any integer, start at 0, follow the rules of net/ipv4/devinet.c for
// the default and the links, and belong to one network namespace. Calico reads
// conf/default/rp_filter at start. The guest is the program nodeprobe, so the
// test needs no registry.
func TestE2ERPFilterSysctl(t *testing.T) {
	forEachNodeBackend(t, func(t *testing.T, b gateBackend, bin string) {
		code, out := runNodeProbe(t, b, bin, nil, "rpfilter")
		requireNodeChecks(t, code, out,
			"rpfilter-starts-at-zero", "rpfilter-keeps-any-integer", "rpfilter-all-changes-no-link",
			"rpfilter-new-link-starts-with-the-default", "rpfilter-default-reaches-links-without-a-value",
			"rpfilter-link-keeps-the-value-that-the-guest-wrote", "rpfilter-removed-link-loses-its-value",
			"rpfilter-new-namespace-inherits-all-and-default", "rpfilter-namespaces-are-independent",
			"rpfilter-ordinary-user-reads-but-cannot-write")
	})
}
