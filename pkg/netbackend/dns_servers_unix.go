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

//go:build !windows

package netbackend

import (
	"net"
	"net/netip"
	"os"
	"strings"
)

const (
	// resolvConfPath is the macOS and Unix resolver configuration file.
	resolvConfPath = "/etc/resolv.conf"

	// systemdResolvConfPath holds the upstream resolvers behind the
	// systemd-resolved loopback stub (127.0.0.53) on Linux hosts.
	systemdResolvConfPath = "/run/systemd/resolve/resolv.conf"
)

// discoverHostDNSServers returns the "host:port" address of each nameserver
// in /etc/resolv.conf. It runs before hostlockdown.Apply, because lockdown
// denies reads outside the workspace. It returns nil when the file is missing
// or lists no valid nameserver, so the relay then answers SERVFAIL.
func discoverHostDNSServers() []string {
	return discoverHostDNSConfig().servers
}

// discoverHostDNSConfig reads nameservers, search domains, and resolver options
// from /etc/resolv.conf before hostlockdown.Apply. When /etc/resolv.conf lists
// only the systemd-resolved stub (127.0.0.53), it appends any non-loopback
// upstream servers from /run/systemd/resolve/resolv.conf as fallback.
func discoverHostDNSConfig() hostDNSConfig {
	raw, err := os.ReadFile(resolvConfPath)
	if err != nil {
		return hostDNSConfig{}
	}
	cfg := parseResolvConfConfig(string(raw))
	if isOnlySystemdStub(cfg.servers) {
		if fallbackRaw, err := os.ReadFile(systemdResolvConfPath); err == nil {
			fallback := parseResolvConfConfig(string(fallbackRaw))
			cfg = mergeSystemdFallback(cfg, fallback)
		}
	}
	return cfg
}

func isOnlySystemdStub(servers []string) bool {
	return len(servers) == 1 && servers[0] == "127.0.0.53:53"
}

func mergeSystemdFallback(primary, fallback hostDNSConfig) hostDNSConfig {
	merged := primary
	for _, s := range fallback.servers {
		ap, err := netip.ParseAddrPort(s)
		if err != nil || ap.Addr().IsLoopback() {
			continue
		}
		merged.servers = append(merged.servers, s)
	}
	merged.servers = dedupeStrings(merged.servers)
	if len(merged.search) == 0 {
		merged.search = fallback.search
	}
	if len(merged.options) == 0 {
		merged.options = fallback.options
	}
	return merged
}

// parseResolvConf extracts the nameserver addresses of a resolv.conf file.
func parseResolvConf(text string) []string {
	return parseResolvConfConfig(text).servers
}

// parseResolvConfConfig extracts nameservers, search domains, and safe options
// from a resolv.conf file. Per resolv.conf(5), the last search or domain
// directive wins.
func parseResolvConfConfig(text string) hostDNSConfig {
	var cfg hostDNSConfig
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "nameserver":
			addr, err := netip.ParseAddr(fields[1])
			if err != nil || addr.IsUnspecified() {
				continue
			}
			cfg.servers = append(cfg.servers, net.JoinHostPort(addr.String(), "53"))
		case "search":
			var domains []string
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "#") || strings.HasPrefix(f, ";") {
					break
				}
				if d, ok := sanitizeSearchDomain(f); ok {
					domains = append(domains, d)
				}
			}
			if len(domains) > 0 {
				cfg.search = dedupeStrings(domains)
			}
		case "domain":
			if d, ok := sanitizeSearchDomain(fields[1]); ok {
				cfg.search = []string{d}
			}
		case "options":
			for _, f := range fields[1:] {
				if strings.HasPrefix(f, "#") || strings.HasPrefix(f, ";") {
					break
				}
				if opt, ok := sanitizeResolvOption(f); ok {
					cfg.options = append(cfg.options, opt)
				}
			}
		}
	}
	cfg.servers = dedupeStrings(cfg.servers)
	cfg.search = capSearchDomains(cfg.search)
	cfg.options = dedupeStrings(cfg.options)
	return cfg
}
