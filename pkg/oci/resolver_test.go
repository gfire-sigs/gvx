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
	"bytes"
	"context"
	"net"
	"net/netip"
	"testing"
)

// registryName is a name that no resolver of the host knows. Only the test DNS
// server maps it, to the loopback address of the fake registry.
const registryName = "registry.gvx-dns-test"

// namedRegistry starts a fake registry and a DNS server that maps registryName
// to it. It returns the base URL of the registry by name.
func namedRegistry(t *testing.T) (reg *fakeRegistry, dns *testDNS, baseURL string) {
	t.Helper()
	reg = newFakeRegistry(t)
	dns = startTestDNS(t, map[string]netip.Addr{registryName: netip.MustParseAddr("127.0.0.1")})
	_, port, err := net.SplitHostPort(reg.srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return reg, dns, "http://" + net.JoinHostPort(registryName, port)
}

func TestPullResolvesTheRegistryNameThroughTheConfiguredDNSServers(t *testing.T) {
	reg, dns, baseURL := namedRegistry(t)
	digest := reg.addImage(twoLayerImage(t, storeArch, "A=1"))
	reg.tag("v1", digest)
	cache := newCache(t)
	cache.SetDNSServers([]netip.AddrPort{dns.AddrPort()})

	img, err := PullRegistryImage(context.Background(), nil, baseURL, testRepo, "v1", storeArch, cache)
	if err != nil {
		t.Fatalf("PullRegistryImage(%s) with the DNS server %s: %v", baseURL, dns.AddrPort(), err)
	}
	defer img.Close()
	if img.ManifestDigest != digest {
		t.Errorf("pulled manifest %s, want %s", img.ManifestDigest, digest)
	}
	if dns.Queries() == 0 {
		t.Errorf("the DNS server %s received no query for %s", dns.AddrPort(), registryName)
	}
}

func TestSaveImagesResolvesTheRegistryNameThroughTheConfiguredDNSServers(t *testing.T) {
	reg, dns, baseURL := namedRegistry(t)
	reg.tag("v1", reg.addImage(twoLayerImage(t, storeArch, "A=1")))
	cache := newCache(t)
	cache.SetDNSServers([]netip.AddrPort{dns.AddrPort()})
	img, err := PullRegistryImage(context.Background(), nil, baseURL, testRepo, "v1", storeArch, cache)
	if err != nil {
		t.Fatalf("PullRegistryImage: %v", err)
	}
	defer img.Close()
	id := listImages(t, cache)[0].ID
	queriesAfterPull := dns.Queries()

	var archive bytes.Buffer
	if err := saveByName(t, cache, &archive, id); err != nil {
		t.Fatalf("SaveImages with the DNS server %s: %v", dns.AddrPort(), err)
	}
	if dns.Queries() <= queriesAfterPull {
		t.Errorf("SaveImages sent no query to the DNS server %s after the pull", dns.AddrPort())
	}
}

func TestResolverTriesTheNextServerWhenTheFirstIsDown(t *testing.T) {
	dns := startTestDNS(t, map[string]netip.Addr{registryName: netip.MustParseAddr("127.0.0.1")})
	// A closed UDP port answers with ICMP unreachable on loopback, so the read fails.
	dead, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := dead.LocalAddr().(*net.UDPAddr).AddrPort()
	if err := dead.Close(); err != nil {
		t.Fatal(err)
	}

	resolver := newServerResolver([]netip.AddrPort{deadAddr, dns.AddrPort()})
	addrs, err := resolver.LookupNetIP(context.Background(), "ip4", registryName)
	if err != nil {
		t.Fatalf("lookup with the servers %s and %s: %v", deadAddr, dns.AddrPort(), err)
	}
	if len(addrs) != 1 || addrs[0] != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("addresses = %v, want [127.0.0.1]", addrs)
	}
}
