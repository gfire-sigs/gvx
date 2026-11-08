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

package main

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"z.gfire.dev/gvx/internal/testdns"
)

// hostDNSTestName is a name that no resolver of the host knows. Only the test
// DNS server maps it.
const hostDNSTestName = "registry.gvx-dns-test"

func TestRunFlagsHostDNSIsRepeatableAndAcceptsCommas(t *testing.T) {
	rc, _, done, stderr := parse(t, "--host-dns", "10.0.2.3", "-host-dns=8.8.8.8,[2001:db8::1]:5353", "-image=x")
	if done {
		t.Fatalf("parseRunArgs ended the command: %s", stderr)
	}
	want := []string{"10.0.2.3", "8.8.8.8", "[2001:db8::1]:5353"}
	if !slices.Equal(rc.cfg.HostDNSServers, want) {
		t.Errorf("HostDNSServers = %q, want %q", rc.cfg.HostDNSServers, want)
	}
}

func TestRunFlagsHostDNSRejectsAHostName(t *testing.T) {
	_, code, done, stderr := parse(t, "--host-dns", "dns.example.test", "-image=x")
	if !done || code != 2 || !strings.Contains(stderr, "--host-dns") {
		t.Errorf("parseRunArgs = (done %v, code %d, %q), want a usage error that names --host-dns", done, code, stderr)
	}
}

func TestPullResolvesTheRegistryThroughTheHostDNSFlag(t *testing.T) {
	reg := startRegistry(t, twoFiles()...)
	dns := testdns.Start(t, map[string]netip.Addr{hostDNSTestName: netip.MustParseAddr("127.0.0.1")})
	_, port, _ := strings.Cut(reg.Host, ":")
	env := newCLIEnv(t)

	out := env.run("pull", "--host-dns", dns.AddrPort().String(),
		"-registry-url", "http://"+hostDNSTestName+":"+port, "gvx/app:v1").mustSucceed(t, "pull by name")
	if !strings.Contains(out.stdout, "Digest: sha256:") {
		t.Errorf("pull output has no digest:\n%s", out.stdout)
	}
	if dns.Queries() == 0 {
		t.Errorf("the DNS server %s received no query for %s", dns.AddrPort(), hostDNSTestName)
	}
}

func TestPullRejectsAHostDNSHostName(t *testing.T) {
	env := newCLIEnv(t)
	res := env.run("pull", "--host-dns", "dns.example.test", "gvx/app:v1")
	if res.code == 0 || !strings.Contains(res.stderr, "--host-dns") {
		t.Errorf("pull with a host name as DNS server = (%d, %q), want a failure that names --host-dns", res.code, res.stderr)
	}
}
