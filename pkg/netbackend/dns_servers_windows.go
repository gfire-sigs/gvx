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

//go:build windows

package netbackend

import (
	"errors"
	"net"
	"net/netip"
	"runtime"
	"strconv"
	"unsafe"

	"golang.org/x/sys/windows"
)

// discoverHostDNSConfig returns deduplicated DNS servers and adapter DNS search
// suffixes from operational non-loopback Windows network adapters.
func discoverHostDNSConfig() hostDNSConfig {
	cfg, err := adapterDNSConfig()
	if err != nil {
		return hostDNSConfig{}
	}
	return cfg
}

// adapterDNSConfig reads the DNS servers and search suffixes with
// GetAdaptersAddresses. It skips adapters that are down and loopback adapters.
// It also skips the site-local IPv6 placeholder addresses that Windows lists
// when no IPv6 DNS server exists.
func adapterDNSConfig() (hostDNSConfig, error) {
	const flags = windows.GAA_FLAG_SKIP_UNICAST | windows.GAA_FLAG_SKIP_ANYCAST |
		windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_FRIENDLY_NAME

	// The required buffer size can grow between two calls, so retry on overflow.
	size := uint32(15 * 1024)
	var buf []byte
	for range 8 {
		if size == 0 {
			return hostDNSConfig{}, windows.ERROR_BUFFER_OVERFLOW
		}
		buf = make([]byte, size)
		first := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, flags, 0, first, &size)
		if err == nil {
			break
		}
		if !errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			return hostDNSConfig{}, err
		}
		buf = nil
	}
	if len(buf) == 0 {
		return hostDNSConfig{}, windows.ERROR_BUFFER_OVERFLOW
	}

	var cfg hostDNSConfig
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		if aa.OperStatus != windows.IfOperStatusUp || aa.IfType == windows.IF_TYPE_SOFTWARE_LOOPBACK {
			continue
		}
		if aa.DnsSuffix != nil {
			if d, ok := sanitizeSearchDomain(windows.UTF16PtrToString(aa.DnsSuffix)); ok {
				cfg.search = append(cfg.search, d)
			}
		}
		for dns := aa.FirstDnsServerAddress; dns != nil; dns = dns.Next {
			ip := dns.Address.IP()
			if ip == nil {
				continue
			}
			addr, ok := netip.AddrFromSlice(ip)
			if !ok {
				continue
			}
			addr = addr.Unmap()
			if addr.IsUnspecified() || isSiteLocalDNSPlaceholder(addr) {
				continue
			}
			if addr.Is6() && addr.IsLinkLocalUnicast() {
				// A link-local server is reachable only through its interface.
				addr = addr.WithZone(strconv.FormatUint(uint64(aa.Ipv6IfIndex), 10))
			}
			cfg.servers = append(cfg.servers, net.JoinHostPort(addr.String(), "53"))
		}
	}
	runtime.KeepAlive(buf)
	cfg.servers = dedupeStrings(cfg.servers)
	cfg.search = capSearchDomains(dedupeStrings(cfg.search))
	return cfg, nil
}

// isSiteLocalDNSPlaceholder reports fec0:0:0:ffff::1, ::2, and ::3. Windows
// lists them as IPv6 DNS servers when the adapter has no real IPv6 server.
func isSiteLocalDNSPlaceholder(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	return addr.As16()[0] == 0xfe && addr.As16()[1] == 0xc0
}
