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

package hostlockdown

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
)

// DialContext dials an outbound host network connection. On Windows after Apply
// with Options.AllowOutboundNet enabled, TCP and UDP dials execute on the
// Low-integrity socket broker so sandbox threads keep NULL_SID restriction.
func DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return dialHostContext(ctx, network, address)
}

// AcceptListener accepts one inbound connection from a pre-bound listener. On
// Windows, AcceptEx allocates a new acceptor socket handle, so locked-down NAT
// sandboxes run the accept on the Low-integrity socket broker.
func AcceptListener(ln net.Listener) (net.Conn, error) {
	return acceptHostListener(ln)
}

// ListenLoopback binds a TCP listener on a host loopback address (127.0.0.1 or
// ::1). After Apply, it requires Options.AllowOutboundNet and
// Options.AllowLoopbackBind.
func ListenLoopback(network, address string) (net.Listener, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("hostlockdown: ListenLoopback rejects network %q", network)
	}
	if err := validateLoopbackBind(address); err != nil {
		return nil, err
	}
	if IsLockedDown() && !loopbackBindAllowed.Load() {
		return nil, errors.New("hostlockdown: loopback bind is disabled")
	}
	return listenHostLoopback(network, address)
}

// ListenPacketLoopback binds a UDP packet socket on a host loopback address
// (127.0.0.1 or ::1). After Apply, it requires Options.AllowOutboundNet and
// Options.AllowLoopbackBind.
func ListenPacketLoopback(network, address string) (net.PacketConn, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("hostlockdown: ListenPacketLoopback rejects network %q", network)
	}
	if err := validateLoopbackBind(address); err != nil {
		return nil, err
	}
	if IsLockedDown() && !loopbackBindAllowed.Load() {
		return nil, errors.New("hostlockdown: loopback bind is disabled")
	}
	return listenHostPacketLoopback(network, address)
}

// ListenAllowed binds a TCP listener on a host IP address authorized by
// Options.AllowLoopbackBind or Options.AllowedBindAddrs. Unlisted addresses
// and non-TCP networks are rejected. Generic "tcp" is narrowed to "tcp4" or
// "tcp6" from the IP literal so an IPv4 wildcard never opens a dual-stack IPv6
// listener (or vice versa).
func ListenAllowed(network, address string) (net.Listener, error) {
	narrowNet, canonAddr, addr, err := parseAndNarrowBind("tcp", network, address)
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: ListenAllowed: %w", err)
	}
	if !isBindAddrAllowed(addr) {
		return nil, fmt.Errorf("hostlockdown: bind address %q is not allowed under host lockdown", addr.String())
	}
	return listenHostAllowed(narrowNet, canonAddr)
}

// ListenPacketAllowed binds a UDP packet socket on a host IP address
// authorized by Options.AllowLoopbackBind or Options.AllowedBindAddrs.
// Unlisted addresses and non-UDP networks are rejected. Generic "udp" is
// narrowed to "udp4" or "udp6" from the IP literal.
func ListenPacketAllowed(network, address string) (net.PacketConn, error) {
	narrowNet, canonAddr, addr, err := parseAndNarrowBind("udp", network, address)
	if err != nil {
		return nil, fmt.Errorf("hostlockdown: ListenPacketAllowed: %w", err)
	}
	if !isBindAddrAllowed(addr) {
		return nil, fmt.Errorf("hostlockdown: bind address %q is not allowed under host lockdown", addr.String())
	}
	return listenHostPacketAllowed(narrowNet, canonAddr)
}

func parseAndNarrowBind(base, network, address string) (narrowNet, canonAddr string, addr netip.Addr, err error) {
	v4Net, v6Net := base+"4", base+"6"
	switch network {
	case base, v4Net, v6Net:
	default:
		return "", "", netip.Addr{}, fmt.Errorf("rejects network %q", network)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return "", "", netip.Addr{}, fmt.Errorf("invalid bind address %q: %w", address, err)
	}
	parsed, err := netip.ParseAddr(host)
	if err != nil || parsed.Zone() != "" {
		return "", "", netip.Addr{}, fmt.Errorf("bind address %q must use a bare IP literal", address)
	}
	addr = parsed.Unmap()
	wantNet := v4Net
	if addr.Is6() {
		wantNet = v6Net
	}
	if network != base && network != wantNet {
		return "", "", netip.Addr{}, fmt.Errorf("network %q does not match address family of %q", network, addr.String())
	}
	return wantNet, net.JoinHostPort(addr.String(), port), addr, nil
}

func parseBindHostAddr(address string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("hostlockdown: invalid bind address %q: %w", address, err)
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("hostlockdown: bind address %q must use a bare IP literal", address)
	}
	return addr.Unmap(), nil
}

func validateLoopbackBind(address string) error {
	addr, err := parseBindHostAddr(address)
	if err != nil {
		return err
	}
	if !addr.IsLoopback() {
		return fmt.Errorf("hostlockdown: bind address %q is not a loopback IP", address)
	}
	return nil
}
