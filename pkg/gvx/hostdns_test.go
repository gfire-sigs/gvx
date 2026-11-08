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
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"runtime"
	"slices"
	"testing"
	"time"

	"z.gfire.dev/gvx/internal/testdns"
	"z.gfire.dev/gvx/internal/testimage"
	"z.gfire.dev/gvx/pkg/netbackend"
	"z.gfire.dev/gvx/pkg/tcpip"
	"z.gfire.dev/gvx/pkg/tcpip/adapters/gonet"
	"z.gfire.dev/gvx/pkg/tcpip/network/ipv4"
)

// hostDNSTestName is a name that no resolver of the host knows. Only the test
// DNS server maps it.
const hostDNSTestName = "registry.gvx-dns-test"

func TestHostDNSServersNormalizeToCanonicalAddresses(t *testing.T) {
	cfg := Config{HostDNSServers: []string{" 10.0.2.3 ", "", "[2001:db8::1]:5353"}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if want := []string{"10.0.2.3:53", "[2001:db8::1]:5353"}; !slices.Equal(cfg.HostDNSServers, want) {
		t.Errorf("HostDNSServers = %v, want %v", cfg.HostDNSServers, want)
	}
}

func TestHostDNSServersRejectAHostName(t *testing.T) {
	cfg := Config{HostDNSServers: []string{"dns.example.test"}}
	if err := cfg.normalize(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("normalize with a host name as DNS server = %v, want ErrInvalidConfig", err)
	}
}

// The guest asks the relay at 10.0.2.3:53 for a name. The relay must send the
// query to the server of Config.HostDNSServers, because an Android host has no
// resolver configuration to discover.
func TestNATGuestRelayForwardsToConfiguredHostDNSServers(t *testing.T) {
	dns := testdns.Start(t, map[string]netip.Addr{hostDNSTestName: netip.MustParseAddr("192.0.2.77")})
	cfg := Config{NetworkMode: NetModeNAT, HostDNSServers: []string{dns.AddrPort().String()}}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	s := &Sandbox{cfg: cfg}
	if err := s.initNetstack(); err != nil {
		t.Fatalf("initNetstack: %v", err)
	}
	t.Cleanup(func() {
		_ = s.natForwarder.Close()
		s.netStack.Close()
	})

	relay := tcpip.FullAddress{NIC: netbackend.Eth0NICID, Addr: tcpip.AddrFrom4([4]byte{10, 0, 2, 3}), Port: netbackend.DefaultDNSPort}
	conn, err := gonet.DialUDP(s.netStack, nil, &relay, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatalf("dial the relay: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(aQuery(0x5151, hostDNSTestName)); err != nil {
		t.Fatalf("send the query: %v", err)
	}
	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp := make([]byte, 512)
	n, err := conn.Read(resp)
	if err != nil {
		t.Fatalf("read the answer of the relay: %v", err)
	}
	if rcode := resp[3] & 0x0f; rcode != 0 || n < 4 {
		t.Fatalf("relay answered rcode %d in %d bytes, want NOERROR from the server %s", rcode, n, dns.AddrPort())
	}
	if got := netip.AddrFrom4([4]byte(resp[n-4 : n])); got != netip.MustParseAddr("192.0.2.77") {
		t.Errorf("relay answered %s, want 192.0.2.77", got)
	}
	if dns.Queries() == 0 {
		t.Errorf("the DNS server %s received no query", dns.AddrPort())
	}
}

// aQuery returns a standard DNS query of type A with recursion desired.
func aQuery(id uint16, name string) []byte {
	q := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			q = append(q, byte(i-start))
			q = append(q, name[start:i]...)
			start = i + 1
		}
	}
	return append(q, 0x00, 0x00, 0x01, 0x00, 0x01)
}

// The image pull of a Sandbox reaches the registry by name. Its resolver must
// use Config.HostDNSServers, because the Go resolver on Android has no
// resolver configuration and queries [::1]:53.
func TestSandboxImagePullResolvesTheRegistryThroughHostDNSServers(t *testing.T) {
	layer, err := testimage.Tar(testimage.File{Name: "marker", Data: []byte("pulled\n")})
	if err != nil {
		t.Fatalf("testimage.Tar: %v", err)
	}
	registry := testimage.NewRegistryServer(t, "gvx/hostdns", "v1",
		testimage.Image{Arch: runtime.GOARCH, Layers: [][]byte{layer}, Cmd: []string{"/marker"}})
	registryURL, err := url.Parse(registry.URL)
	if err != nil {
		t.Fatal(err)
	}
	baseURL := "http://" + net.JoinHostPort(hostDNSTestName, registryURL.Port())
	dns := testdns.Start(t, map[string]netip.Addr{hostDNSTestName: netip.MustParseAddr("127.0.0.1")})

	cfg := Config{
		OCIImage:        "gvx/hostdns:v1",
		OCICacheDir:     t.TempDir(),
		RegistryBaseURL: baseURL,
		Architecture:    runtime.GOARCH,
		HostDNSServers:  []string{dns.AddrPort().String()},
	}
	if err := cfg.normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	s := &Sandbox{cfg: cfg}
	t.Cleanup(func() {
		for _, h := range s.layerHandles {
			_ = h.Close()
		}
	})
	if err := s.initOCILayers(context.Background()); err != nil {
		t.Fatalf("initOCILayers with the DNS server %s: %v", dns.AddrPort(), err)
	}
	if s.resolvedImg == nil || len(s.resolvedImg.LayerDigests) != 1 {
		t.Fatalf("resolved image = %+v, want one layer", s.resolvedImg)
	}
	t.Cleanup(func() { _ = s.resolvedImg.Close() })
	if dns.Queries() == 0 {
		t.Errorf("the DNS server %s received no query for %s", dns.AddrPort(), hostDNSTestName)
	}
}
